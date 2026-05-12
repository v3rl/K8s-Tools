#!/usr/bin/env bash
# =============================================================================
# k8s_hardening_scan.sh
# Kubernetes Pod & Container Security Hardening Scanner
# Supports: Online (live cluster) and Offline (pods.yaml) modes
# Output: CSV with issue details
# Author: Security Scanner | yq v3 compatible
# =============================================================================

set -euo pipefail

# ─── Colour codes ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ─── Defaults ─────────────────────────────────────────────────────────────────
MODE="online"
INPUT_FILE=""
OUTPUT_CSV="k8s_hardening_report_$(date +%Y%m%d_%H%M%S).csv"
FINDINGS=0
FINDINGS_FILE=""
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# ─── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
cat <<'EOF'
╔══════════════════════════════════════════════════════════════════╗
║     K8s Pod & Container Security Hardening Scanner               ║
║     Detects: CIS Benchmark | NSA/CISA | OWASP K8s Top 10        ║
╚══════════════════════════════════════════════════════════════════╝
EOF
}

# ─── Usage ────────────────────────────────────────────────────────────────────
usage() {
  echo -e "${BOLD}Usage:${NC}"
  echo "  $0 [OPTIONS]"
  echo ""
  echo "  -m, --mode      online | offline  (default: online)"
  echo "  -f, --file      Path to pods.yaml (required for offline mode)"
  echo "  -o, --output    Output CSV file   (default: auto-named)"
  echo "  -h, --help      Show this help"
  echo ""
  echo "  Examples:"
  echo "    $0 --mode online"
  echo "    $0 --mode offline --file pods.yaml"
  exit 0
}

# ─── Argument Parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case $1 in
    -m|--mode)   MODE="$2";        shift 2 ;;
    -f|--file)   INPUT_FILE="$2";  shift 2 ;;
    -o|--output) OUTPUT_CSV="$2";  shift 2 ;;
    -h|--help)   usage ;;
    *) echo "Unknown option: $1"; usage ;;
  esac
done

# ─── Dependency Checker & Installer ───────────────────────────────────────────
check_and_install_deps() {
  echo -e "\n${CYAN}[*] Checking required dependencies...${NC}"

  # ── kubectl ──
  if ! command -v kubectl &>/dev/null; then
    echo -e "${YELLOW}[!] kubectl not found. Installing...${NC}"
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
    [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
    K8S_VER=$(curl -sL https://dl.k8s.io/release/stable.txt 2>/dev/null || echo "v1.29.0")
    curl -sLo "$TMP_DIR/kubectl" \
      "https://dl.k8s.io/release/${K8S_VER}/bin/${OS}/${ARCH}/kubectl"
    chmod +x "$TMP_DIR/kubectl"
    sudo mv "$TMP_DIR/kubectl" /usr/local/bin/kubectl || \
      { export PATH="$TMP_DIR:$PATH"; cp "$TMP_DIR/kubectl" "$TMP_DIR/kubectl"; }
    echo -e "${GREEN}[+] kubectl installed.${NC}"
  else
    echo -e "${GREEN}[+] kubectl found: $(kubectl version --client --short 2>/dev/null | head -1)${NC}"
  fi

  # ── jq ──
  if ! command -v jq &>/dev/null; then
    echo -e "${YELLOW}[!] jq not found. Installing...${NC}"
    if command -v apt-get &>/dev/null; then
      sudo apt-get install -y jq &>/dev/null
    elif command -v yum &>/dev/null; then
      sudo yum install -y jq &>/dev/null
    elif command -v brew &>/dev/null; then
      brew install jq &>/dev/null
    else
      OS=$(uname -s | tr '[:upper:]' '[:lower:]')
      ARCH=$(uname -m)
      [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
      curl -sLo /usr/local/bin/jq \
        "https://github.com/jqlang/jq/releases/download/jq-1.7.1/jq-${OS}-${ARCH}"
      chmod +x /usr/local/bin/jq
    fi
    echo -e "${GREEN}[+] jq installed.${NC}"
  else
    echo -e "${GREEN}[+] jq found: $(jq --version)${NC}"
  fi

  # ── yq v3 ──
  if command -v yq &>/dev/null; then
    YQ_VER=$(yq --version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    YQ_MAJOR=$(echo "$YQ_VER" | cut -d. -f1)
    if [[ "$YQ_MAJOR" -eq 3 ]]; then
      echo -e "${GREEN}[+] yq v3 found: $(yq --version 2>&1)${NC}"
    else
      echo -e "${YELLOW}[!] yq found but not v3 (found v${YQ_VER}). Installing yq v3 as yq3...${NC}"
      _install_yq3
    fi
  else
    echo -e "${YELLOW}[!] yq not found. Installing yq v3...${NC}"
    _install_yq3
  fi

  # ── python3 (fallback yaml→json) ──
  if ! command -v python3 &>/dev/null; then
    echo -e "${YELLOW}[!] python3 not found. Attempting install...${NC}"
    if command -v apt-get &>/dev/null; then
      sudo apt-get install -y python3 &>/dev/null
    elif command -v yum &>/dev/null; then
      sudo yum install -y python3 &>/dev/null
    fi
  else
    echo -e "${GREEN}[+] python3 found: $(python3 --version 2>&1)${NC}"
  fi

  # ── curl ──
  if ! command -v curl &>/dev/null; then
    echo -e "${YELLOW}[!] curl not found. Installing...${NC}"
    if command -v apt-get &>/dev/null; then sudo apt-get install -y curl &>/dev/null
    elif command -v yum &>/dev/null; then sudo yum install -y curl &>/dev/null
    fi
  fi

  echo -e "${GREEN}[+] All dependency checks complete.${NC}\n"
}

_install_yq3() {
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  [[ "$ARCH" == "x86_64" ]] && ARCH="amd64"
  [[ "$ARCH" == "aarch64" ]] && ARCH="arm64"
  YQ3_URL="https://github.com/mikefarah/yq/releases/download/3.4.1/yq_${OS}_${ARCH}"
  TARGET="/usr/local/bin/yq3"
  if curl -sLo "$TARGET" "$YQ3_URL" 2>/dev/null; then
    chmod +x "$TARGET"
    echo -e "${GREEN}[+] yq v3 installed as 'yq3'.${NC}"
    YQ_CMD="yq3"
  else
    echo -e "${RED}[-] Could not download yq v3. Will use python3 YAML→JSON fallback.${NC}"
    YQ_CMD=""
  fi
}

# Set YQ_CMD global
YQ_CMD="yq"

# ─── YAML → JSON converter (uses yq3 or python3 fallback) ────────────────────
yaml_to_json() {
  local yaml_file="$1"
  local json_out="$TMP_DIR/pods.json"

  if [[ -n "$YQ_CMD" ]] && command -v "$YQ_CMD" &>/dev/null; then
    # yq v3: convert multi-doc YAML to JSON array
    "$YQ_CMD" r -j "$yaml_file" 2>/dev/null > "$json_out" || \
      python3 -c "
import sys, json, yaml
docs = list(yaml.safe_load_all(open('$yaml_file')))
# If it's a List kind, expand items; else wrap
result = []
for d in docs:
    if d and d.get('kind') == 'List':
        result.extend(d.get('items', []))
    elif d:
        result.append(d)
print(json.dumps(result))
" > "$json_out"
  else
    python3 -c "
import sys, json, yaml
docs = list(yaml.safe_load_all(open('$yaml_file')))
result = []
for d in docs:
    if d and d.get('kind') == 'List':
        result.extend(d.get('items', []))
    elif d:
        result.append(d)
print(json.dumps(result))
" > "$json_out"
  fi

  echo "$json_out"
}

# ─── CSV helpers ──────────────────────────────────────────────────────────────
init_csv() {
  echo "Issue Name,Controller Type,Pod Name,Container Name,Namespace,Severity,Issue Details,Risk / Impact" \
    > "$OUTPUT_CSV"
  FINDINGS_FILE="$TMP_DIR/findings.count"
  echo "0" > "$FINDINGS_FILE"
}

# Escape a field for CSV (wrap in quotes, escape inner quotes)
csv_field() {
  local v="$1"
  v="${v//\"/\"\"}"
  echo "\"$v\""
}

write_finding() {
  local issue="$1" ctrl="$2" pod="$3" container="$4" ns="$5"
  local severity="$6" detail="$7" risk="$8"
  printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$(csv_field "$issue")" \
    "$(csv_field "$ctrl")" \
    "$(csv_field "$pod")" \
    "$(csv_field "$container")" \
    "$(csv_field "$ns")" \
    "$(csv_field "$severity")" \
    "$(csv_field "$detail")" \
    "$(csv_field "$risk")" \
    >> "$OUTPUT_CSV"
  local _fc
  _fc=$(cat "$FINDINGS_FILE" 2>/dev/null || echo 0)
  echo $((_fc + 1)) > "$FINDINGS_FILE"
  FINDINGS=$(cat "$FINDINGS_FILE")
  local color=$NC
  case "$severity" in
    CRITICAL) color=$RED ;;
    HIGH)     color=$RED ;;
    MEDIUM)   color=$YELLOW ;;
    LOW)      color=$CYAN ;;
  esac
  echo -e "  ${color}[${severity}]${NC} ${pod}/${container} → ${issue}"
}

# ─── Linux Capabilities Reference ────────────────────────────────────────────
# Severity rationale:
#   CRITICAL — direct kernel/host compromise or container escape path
#   HIGH     — significant privilege abuse, network control, or process introspection
#   MEDIUM   — expands attack surface, enables privilege abuse with other conditions
#   LOW      — minimal direct security impact, flag for awareness
#
# Notes:
#   - SYS_PACCT  → HIGH  (process accounting manipulation; defence evasion, not direct escape)
#   - LINUX_IMMUTABLE → HIGH (makes files undeletable; persistence risk, not kernel access)
#   - NET_BROADCAST removed (not a real Linux kernel capability)
#   - BPF added CRITICAL (eBPF kernel program loading; used in real container escapes)
#   - PERFMON added HIGH (kernel/process memory side-channel via perf subsystem)
#   - CHECKPOINT_RESTORE added HIGH (read/write process memory of other processes)
CAP_CRITICAL="SYS_ADMIN NET_ADMIN SYS_PTRACE SYS_MODULE SYS_RAWIO SYS_BOOT BPF"
CAP_HIGH="NET_RAW SYS_CHROOT SYS_TIME MKNOD SYS_TTY_CONFIG SYS_NICE SYS_RESOURCE IPC_LOCK IPC_OWNER SYS_PACCT LINUX_IMMUTABLE PERFMON CHECKPOINT_RESTORE"
CAP_MEDIUM="AUDIT_CONTROL AUDIT_READ AUDIT_WRITE SETUID SETGID SETFCAP SETPCAP DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL"
CAP_LOW="NET_BIND_SERVICE CHOWN LEASE SYSLOG WAKE_ALARM"

cap_severity() {
  # Normalise: uppercase and strip CAP_ prefix (some manifests use CAP_SYS_ADMIN form)
  local cap="${1^^}"
  cap="${cap#CAP_}"
  for c in $CAP_CRITICAL; do [[ "$c" == "$cap" ]] && echo "CRITICAL" && return; done
  for c in $CAP_HIGH;     do [[ "$c" == "$cap" ]] && echo "HIGH"     && return; done
  for c in $CAP_MEDIUM;   do [[ "$c" == "$cap" ]] && echo "MEDIUM"   && return; done
  echo "LOW"
}

# ─── Core Scanner ─────────────────────────────────────────────────────────────
scan_pods_json() {
  local json_file="$1"

  # Validate JSON
  if ! jq empty "$json_file" 2>/dev/null; then
    echo -e "${RED}[!] Invalid JSON in $json_file${NC}"; return 1
  fi

  # Total pod count
  local total
  total=$(jq 'if type=="array" then length else 1 end' "$json_file")
  echo -e "${CYAN}[*] Scanning ${total} pod(s)...${NC}\n"

  # Iterate pods — handle both array and single-object JSON
  jq -c 'if type=="array" then .[] else . end' "$json_file" | while IFS= read -r pod_json; do

    # ── Pod metadata ──
    local pod_name ns ctrl_type ctrl_name
    pod_name=$(echo "$pod_json" | jq -r '.metadata.name // "unknown"')
    ns=$(echo "$pod_json"       | jq -r '.metadata.namespace // "default"')

    # Determine controller type from ownerReferences
    ctrl_type=$(echo "$pod_json" | jq -r '
      .metadata.ownerReferences // [] |
      map(select(.controller==true)) |
      first | .kind // "Pod"' 2>/dev/null || echo "Pod")
    ctrl_name=$(echo "$pod_json" | jq -r '
      .metadata.ownerReferences // [] |
      map(select(.controller==true)) |
      first | .name // ""' 2>/dev/null || echo "")
    [[ -z "$ctrl_name" ]] && ctrl_name="$pod_name"

    echo -e "${BOLD}  Pod:${NC} ${ns}/${pod_name} (${ctrl_type})"

    local spec
    spec=$(echo "$pod_json" | jq -c '.spec // {}')

    # ── Pod-level security context ──
    local pod_sc
    pod_sc=$(echo "$spec" | jq -c '.securityContext // {}')

    # ── P1: hostPID ──
    if echo "$spec" | jq -e '.hostPID == true' &>/dev/null; then
      write_finding "Host PID Namespace Shared" "$ctrl_type" "$pod_name" "N/A" "$ns" \
        "HIGH" "spec.hostPID=true — pod shares host PID namespace" \
        "Attacker can view/signal all host processes, enabling privilege escalation"
    fi

    # ── P2: hostIPC ──
    if echo "$spec" | jq -e '.hostIPC == true' &>/dev/null; then
      write_finding "Host IPC Namespace Shared" "$ctrl_type" "$pod_name" "N/A" "$ns" \
        "HIGH" "spec.hostIPC=true — pod shares host IPC namespace" \
        "Allows access to shared memory of host processes; data leakage and privilege escalation"
    fi

    # ── P3: hostNetwork ──
    if echo "$spec" | jq -e '.hostNetwork == true' &>/dev/null; then
      write_finding "Host Network Namespace Shared" "$ctrl_type" "$pod_name" "N/A" "$ns" \
        "HIGH" "spec.hostNetwork=true — pod uses host network stack" \
        "Container can sniff host network traffic and bypass network policies"
    fi

    # ── P4: automountServiceAccountToken (pod-level) ──
    local pod_automount
    pod_automount=$(echo "$spec" | jq -r '.automountServiceAccountToken // "not_set"')
    if [[ "$pod_automount" == "true" ]] || [[ "$pod_automount" == "not_set" ]]; then
      write_finding "Service Account Token Auto-Mounted" "$ctrl_type" "$pod_name" "N/A" "$ns" \
        "MEDIUM" "automountServiceAccountToken not explicitly false; SA token mounted by default" \
        "Any compromised process can use the SA token to query/modify cluster API"
    fi

    # ── P5: Pod-level runAsNonRoot ──
    local pod_nonroot
    pod_nonroot=$(echo "$pod_sc" | jq -r '.runAsNonRoot // "not_set"')

    # ── P6: Pod-level seccomp ──
    local pod_seccomp
    pod_seccomp=$(echo "$pod_sc" | \
      jq -r '.seccompProfile.type // "not_set"' 2>/dev/null || echo "not_set")
    # Also check legacy annotation
    local legacy_seccomp
    legacy_seccomp=$(echo "$pod_json" | \
      jq -r '.metadata.annotations["seccomp.security.alpha.kubernetes.io/pod"] // ""')

    # ── P7: AppArmor annotation ──
    local aa_annotation
    aa_annotation=$(echo "$pod_json" | \
      jq -r '.metadata.annotations // {} | to_entries |
        map(select(.key | startswith("container.apparmor.security.beta.kubernetes.io/"))) |
        map(.key + "=" + .value) | join("; ")' 2>/dev/null || echo "")

    # ── P8: hostPath volumes (check all volumes) ──
    # Severity tiers:
    #   CRITICAL — container runtime sockets, root fs, kernel interfaces (/proc /sys)
    #              → direct node compromise / container escape
    #   HIGH     — kubelet, etcd, k8s config, system credentials, binary dirs
    #              → cluster takeover or credential theft
    #   MEDIUM   — logs, home dirs, boot — sensitive but indirect
    #   LOW      — any other hostPath (still flagged for audit visibility)
    echo "$spec" | jq -c '.volumes // [] | .[]' 2>/dev/null | while IFS= read -r vol; do
      local vol_name vol_path
      vol_name=$(echo "$vol" | jq -r '.name // "unknown"')
      vol_path=$(echo "$vol" | jq -r '.hostPath.path // ""')
      if [[ -n "$vol_path" ]]; then
        local sev="" risk_txt=""

        # ── CRITICAL: runtime sockets, root, kernel virtual filesystems ──
        case "$vol_path" in
          /|/proc|/proc/*|/sys|/sys/*| \
          /var/run/docker.sock|/run/docker.sock| \
          /var/run/crio.sock|/run/crio.sock| \
          /run/containerd*|/var/run/containerd*)
            sev="CRITICAL"
            risk_txt="hostPath='${vol_path}' — runtime socket or kernel interface; enables full container escape and node compromise"
            ;;
        esac

        # ── HIGH: cluster internals, credentials, system binaries ──
        if [[ -z "$sev" ]]; then
          case "$vol_path" in
            /etc|/etc/*| \
            /var/lib/kubelet|/var/lib/kubelet/*| \
            /var/lib/etcd|/var/lib/etcd/*| \
            /usr|/usr/*|/bin|/bin/*|/sbin|/sbin/*| \
            /lib|/lib/*|/lib64|/lib64/*)
              sev="HIGH"
              risk_txt="hostPath='${vol_path}' — system credentials, cluster config, or binary dirs; enables credential theft or binary replacement"
              ;;
          esac
        fi

        # ── MEDIUM: logs, home dirs, boot ──
        if [[ -z "$sev" ]]; then
          case "$vol_path" in
            /var/log|/var/log/*| \
            /root|/root/*|/home|/home/*| \
            /boot|/boot/*)
              sev="MEDIUM"
              risk_txt="hostPath='${vol_path}' — sensitive data exposure; logs may contain secrets, home/boot dirs enable persistence"
              ;;
          esac
        fi

        # ── LOW: any other hostPath — flag for audit, unknown risk ──
        if [[ -z "$sev" ]]; then
          sev="LOW"
          risk_txt="hostPath='${vol_path}' — non-standard host path mounted; review if access to this host location is necessary"
        fi

        write_finding "Dangerous HostPath Volume" "$ctrl_type" "$pod_name" "N/A (volume: $vol_name)" "$ns" \
          "$sev" "volume '$vol_name' mounts hostPath='$vol_path'" "$risk_txt"
      fi
    done

    # ── P8b: hostPath volume type — Socket/BlockDevice/CharDevice escalation ──
    echo "$spec" | jq -c '.volumes // [] | .[]' 2>/dev/null | while IFS= read -r vol; do
      local vhp_type vhp_name
      vhp_name=$(echo "$vol" | jq -r '.name // "unknown"')
      vhp_type=$(echo "$vol" | jq -r '.hostPath.type // ""')
      case "$vhp_type" in
        Socket)
          write_finding "HostPath Volume Type: Socket" "$ctrl_type" "$pod_name" "N/A (volume: $vhp_name)" "$ns" \
            "CRITICAL" "volume '$vhp_name' hostPath.type=Socket — mounts a host Unix socket directly" \
            "Direct socket access (e.g. container runtime) enables full container escape and node compromise"
          ;;
        BlockDevice)
          write_finding "HostPath Volume Type: BlockDevice" "$ctrl_type" "$pod_name" "N/A (volume: $vhp_name)" "$ns" \
            "CRITICAL" "volume '$vhp_name' hostPath.type=BlockDevice — mounts raw block device from host" \
            "Raw block device access allows reading/writing host disk including other containers filesystems"
          ;;
        CharDevice)
          write_finding "HostPath Volume Type: CharDevice" "$ctrl_type" "$pod_name" "N/A (volume: $vhp_name)" "$ns" \
            "HIGH" "volume '$vhp_name' hostPath.type=CharDevice — mounts a character device from host" \
            "Character device access can expose kernel interfaces like /dev/mem or enable terminal hijacking"
          ;;
      esac
    done

    # ── P8c: Projected SA token volume (bypasses automountServiceAccountToken=false) ──
    echo "$spec" | jq -c '.volumes // [] | .[]' 2>/dev/null | while IFS= read -r vol; do
      local proj_has_sa vol_name_proj
      vol_name_proj=$(echo "$vol" | jq -r '.name // "unknown"')
      proj_has_sa=$(echo "$vol" | jq -r '.projected.sources // [] | map(select(has("serviceAccountToken"))) | length')
      if [[ "$proj_has_sa" -gt 0 ]]; then
        local tok_exp
        tok_exp=$(echo "$vol" | jq -r '
          .projected.sources[] | select(has("serviceAccountToken")) |
          .serviceAccountToken.expirationSeconds // 3600' | head -1)
        write_finding "SA Token Manually Projected (Bypasses automount=false)" "$ctrl_type" "$pod_name" "N/A (volume: $vol_name_proj)" "$ns" \
          "MEDIUM" "Projected volume '$vol_name_proj' manually mounts serviceAccountToken (expirationSeconds=${tok_exp})" \
          "automountServiceAccountToken=false is bypassed; SA token still accessible to all containers in the pod"
      fi
    done

    # ── P9: Default service account used ──
    local sa_name
    sa_name=$(echo "$spec" | jq -r '.serviceAccountName // "default"')
    if [[ "$sa_name" == "default" ]]; then
      write_finding "Default Service Account Used" "$ctrl_type" "$pod_name" "N/A" "$ns" \
        "LOW" "serviceAccountName=default — no dedicated SA assigned" \
        "Default SA may have unintended RBAC permissions; use dedicated least-privilege SAs"
    fi

    # ─────────────────────────────────────────────────────────────────────────
    # Container-level checks (init + ephemeral + regular containers)
    # ─────────────────────────────────────────────────────────────────────────
    local all_containers
    all_containers=$(echo "$spec" | jq -c '
      [
        (.containers // [] | map(. + {_ctype: "container"})),
        (.initContainers // [] | map(. + {_ctype: "initContainer"})),
        (.ephemeralContainers // [] | map(. + {_ctype: "ephemeralContainer"}))
      ] | add // []
      | .[]')

    echo "$all_containers" | while IFS= read -r ctr_json; do
      local ctr_name ctr_type image
      ctr_name=$(echo "$ctr_json" | jq -r '.name // "unknown"')
      ctr_type=$(echo "$ctr_json" | jq -r '._ctype // "container"')
      image=$(echo "$ctr_json"    | jq -r '.image // "unknown"')

      local csc
      csc=$(echo "$ctr_json" | jq -c '.securityContext // {}')

      # ── C1: privileged mode ──
      if echo "$csc" | jq -e '.privileged == true' &>/dev/null; then
        write_finding "Privileged Container" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "CRITICAL" "securityContext.privileged=true" \
          "Full host kernel access; equivalent to root on the node; trivial container escape"
      fi

      # ── C2: runAsRoot / runAsUser=0 ──
      local run_as_user run_as_nr
      run_as_user=$(echo "$csc" | jq -r '.runAsUser // "not_set"')
      run_as_nr=$(echo "$csc"   | jq -r '.runAsNonRoot // "not_set"')

      if [[ "$run_as_user" == "0" ]]; then
        write_finding "Container Runs as Root (UID 0)" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "HIGH" "securityContext.runAsUser=0 — container explicitly runs as root" \
          "Root in container = broad privilege; if container escapes, attacker has root on node"
      elif [[ "$run_as_nr" == "false" ]]; then
        write_finding "runAsNonRoot Disabled" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "HIGH" "securityContext.runAsNonRoot=false — container may run as root" \
          "Increases blast radius if process is compromised"
      elif [[ "$run_as_nr" == "not_set" && "$pod_nonroot" != "true" && "$run_as_user" == "not_set" ]]; then
        write_finding "No runAsNonRoot Enforcement" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "MEDIUM" "Neither runAsNonRoot nor runAsUser set at container or pod level" \
          "Container image entrypoint may run as root by default"
      fi

      # ── C3: allowPrivilegeEscalation ──
      local allow_pe
      allow_pe=$(echo "$csc" | jq -r '.allowPrivilegeEscalation // "not_set"')
      if [[ "$allow_pe" != "false" ]]; then
        write_finding "Privilege Escalation Allowed" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "HIGH" "allowPrivilegeEscalation not set to false (value: ${allow_pe})" \
          "Process can gain more privileges than parent; enables setuid binary abuse"
      fi

      # ── C4: readOnlyRootFilesystem ──
      local ro_fs
      ro_fs=$(echo "$csc" | jq -r '.readOnlyRootFilesystem // "not_set"')
      if [[ "$ro_fs" != "true" ]]; then
        write_finding "Writable Root Filesystem" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "MEDIUM" "readOnlyRootFilesystem not set to true (value: ${ro_fs})" \
          "Attacker can write malicious files/backdoors to container filesystem"
      fi

      # ── C4b: runAsGroup = 0 (root GID) ──
      local run_as_group
      run_as_group=$(echo "$csc" | jq -r '.runAsGroup // "not_set"')
      if [[ "$run_as_group" == "0" ]]; then
        write_finding "Container Runs with Root GID (GID 0)" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "MEDIUM" "securityContext.runAsGroup=0 — container process has root group membership" \
          "Root GID grants access to group-owned root files; use a non-zero GID"
      fi

      # ── C4c: procMount = Unmasked ──
      local proc_mount
      proc_mount=$(echo "$csc" | jq -r '.procMount // "Default"')
      if [[ "${proc_mount,,}" == "unmasked" ]]; then
        write_finding "procMount Set to Unmasked" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "CRITICAL" "securityContext.procMount=Unmasked — full /proc tree exposed inside container" \
          "Exposes masked proc paths (/proc/kcore, /proc/latency_stats) enabling container escape and kernel memory access"
      fi

      # ── C5: Linux Capabilities ──
      local caps_add caps_drop
      caps_add=$(echo "$csc"  | jq -r '.capabilities.add // [] | join(",")' 2>/dev/null || echo "")
      caps_drop=$(echo "$csc" | jq -r '.capabilities.drop // [] | join(",")' 2>/dev/null || echo "")

      # Check if ALL capabilities are dropped
      local drop_all=false
      if echo "$caps_drop" | grep -qiP '(password|passwd|secret|token|api_key|apikey|private_key|access_key|credential|\bkey\b|\bauth\b)'; then
        drop_all=true
      fi

      # Skip drop-ALL check when already privileged — privileged supersedes all capability controls
      local is_privileged
      is_privileged=$(echo "$csc" | jq -r '.privileged // false')
      if [[ "$drop_all" == "false" && "$is_privileged" != "true" ]]; then
        local drop_detail="capabilities.drop=[${caps_drop:-<none>}] — ALL not present"
        write_finding "Capabilities Not Dropped (drop ALL missing)" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "MEDIUM" "$drop_detail" \
          "Container retains default kernel capabilities; increases attack surface"
      fi

      # Check explicitly added capabilities
      if [[ -n "$caps_add" ]]; then
        local worst_sev="LOW"
        local cap_detail_parts=""   # e.g. SYS_ADMIN(CRITICAL); NET_RAW(HIGH)
        local cap_risk_parts=""     # concatenated per-cap risk one-liners
        IFS=',' read -ra added_caps <<< "$caps_add"
        for cap in "${added_caps[@]}"; do
          cap=$(echo "$cap" | tr -d '[:space:]' | tr '[:lower:]' '[:upper:]')
          cap="${cap#CAP_}"  # strip CAP_ prefix if present (e.g. CAP_SYS_ADMIN → SYS_ADMIN)
          [[ -z "$cap" ]] && continue
          local csev cap_desc
          csev=$(cap_severity "$cap")

          # Per-capability specific risk description
          case "$cap" in
            SYS_ADMIN)          cap_desc="SYS_ADMIN(CRITICAL): broadest Linux capability; enables mount, keyctl, namespace creation, cgroup writes — primary container escape vector" ;;
            NET_ADMIN)          cap_desc="NET_ADMIN(CRITICAL): configure interfaces, firewall rules, routing, VLANs — full host network stack control" ;;
            SYS_PTRACE)         cap_desc="SYS_PTRACE(CRITICAL): attach to and read/write memory of any process in the namespace — secret/credential extraction" ;;
            SYS_MODULE)         cap_desc="SYS_MODULE(CRITICAL): load/unload kernel modules — arbitrary kernel code execution, rootkit installation" ;;
            SYS_RAWIO)          cap_desc="SYS_RAWIO(CRITICAL): raw I/O port access and /dev/mem — read/write physical memory, full host compromise" ;;
            SYS_BOOT)           cap_desc="SYS_BOOT(CRITICAL): reboot or kexec the host — node availability destruction" ;;
            BPF)                cap_desc="BPF(CRITICAL): load eBPF programs into kernel — used in real container escapes, kernel memory inspection, traffic interception" ;;
            NET_RAW)            cap_desc="NET_RAW(HIGH): raw/packet sockets — ARP/DNS spoofing, network sniffing, MITM attacks" ;;
            SYS_CHROOT)         cap_desc="SYS_CHROOT(HIGH): change filesystem root — can escape restricted environments when combined with other caps" ;;
            SYS_TIME)           cap_desc="SYS_TIME(HIGH): set system clock — breaks time-based auth (Kerberos, TLS cert validity, audit timestamps)" ;;
            MKNOD)              cap_desc="MKNOD(HIGH): create device files — can create block/char devices to access host storage or interact with kernel drivers" ;;
            SYS_TTY_CONFIG)     cap_desc="SYS_TTY_CONFIG(HIGH): vhangup and TTY configuration — can hijack terminal sessions" ;;
            SYS_NICE)           cap_desc="SYS_NICE(HIGH): set process priorities and scheduling — can starve other processes, enabling DoS" ;;
            SYS_RESOURCE)       cap_desc="SYS_RESOURCE(HIGH): override resource limits — bypass ulimits set by the container runtime" ;;
            IPC_LOCK)           cap_desc="IPC_LOCK(HIGH): lock memory pages — bypass memory limits, contribute to host OOM conditions" ;;
            IPC_OWNER)          cap_desc="IPC_OWNER(HIGH): bypass IPC permission checks — access shared memory segments of other processes" ;;
            SYS_PACCT)          cap_desc="SYS_PACCT(HIGH): enable/disable process accounting — attacker can suppress accounting logs for defence evasion" ;;
            LINUX_IMMUTABLE)    cap_desc="LINUX_IMMUTABLE(HIGH): set immutable/append-only file flags — malicious files made undeletable, enables persistent backdoors" ;;
            PERFMON)            cap_desc="PERFMON(HIGH): access perf subsystem — kernel and process memory side-channel leakage (Spectre-class attacks)" ;;
            CHECKPOINT_RESTORE) cap_desc="CHECKPOINT_RESTORE(HIGH): checkpoint/restore processes — read/write memory of other processes, extract secrets" ;;
            AUDIT_CONTROL)      cap_desc="AUDIT_CONTROL(MEDIUM): enable/disable kernel auditing and change audit rules — attacker can blind audit subsystem" ;;
            AUDIT_READ)         cap_desc="AUDIT_READ(MEDIUM): read audit log via multicast netlink — exposes security-sensitive audit trail" ;;
            AUDIT_WRITE)        cap_desc="AUDIT_WRITE(MEDIUM): write to kernel audit log — inject false audit records, corrupt audit trail" ;;
            SETUID)             cap_desc="SETUID(MEDIUM): make arbitrary UID changes — escalate to root via setuid binaries inside container" ;;
            SETGID)             cap_desc="SETGID(MEDIUM): make arbitrary GID changes — access files/resources of other groups" ;;
            SETFCAP)            cap_desc="SETFCAP(MEDIUM): set file capabilities — grant dangerous caps to arbitrary executables inside container" ;;
            SETPCAP)            cap_desc="SETPCAP(MEDIUM): transfer/remove capabilities from own set — can be used to grant caps to child processes" ;;
            DAC_OVERRIDE)       cap_desc="DAC_OVERRIDE(MEDIUM): bypass file read/write/execute permission checks — access any file regardless of ownership" ;;
            DAC_READ_SEARCH)    cap_desc="DAC_READ_SEARCH(MEDIUM): bypass file read and directory search permissions — read any file on accessible filesystems" ;;
            FOWNER)             cap_desc="FOWNER(MEDIUM): bypass permission checks for operations requiring file ownership — modify any file's permissions" ;;
            FSETID)             cap_desc="FSETID(MEDIUM): retain setuid/setgid bits on modified files — enables privilege escalation via file manipulation" ;;
            KILL)               cap_desc="KILL(MEDIUM): send signals to any process — can kill processes outside own UID, enabling DoS" ;;
            NET_BIND_SERVICE)   cap_desc="NET_BIND_SERVICE(LOW): bind to privileged ports (<1024) — low risk but unnecessary for most workloads" ;;
            CHOWN)              cap_desc="CHOWN(LOW): change file ownership arbitrarily — limited risk within container but violates least-privilege" ;;
            LEASE)              cap_desc="LEASE(LOW): establish leases on files — minor risk, signals on file access" ;;
            SYSLOG)             cap_desc="SYSLOG(LOW): privileged syslog operations — can read kernel log buffer, minor info disclosure" ;;
            WAKE_ALARM)         cap_desc="WAKE_ALARM(LOW): set CLOCK_REALTIME_ALARM — can wake system from suspend, minimal security impact" ;;
            *)                  cap_desc="${cap}(LOW): unrecognised capability — review whether this capability is necessary" ;;
          esac

          cap_detail_parts="${cap_detail_parts}${cap}(${csev}); "
          cap_risk_parts="${cap_risk_parts}${cap_desc} | "

          # Track worst severity
          case "$csev" in
            CRITICAL) worst_sev="CRITICAL" ;;
            HIGH)     [[ "$worst_sev" != "CRITICAL" ]] && worst_sev="HIGH" ;;
            MEDIUM)   [[ "$worst_sev" == "LOW" ]] && worst_sev="MEDIUM" ;;
          esac
        done

        # Trim trailing separators
        cap_detail_parts="${cap_detail_parts%%; }"
        cap_risk_parts="${cap_risk_parts%% | }"

        write_finding "Dangerous Linux Capabilities Added" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "$worst_sev" \
          "Highest severity: ${worst_sev} | drop=[${caps_drop:-<none>}] | caps: ${cap_detail_parts}" \
          "${cap_risk_parts}"
      fi

      # ── C6: seccompProfile ──
      local ctr_seccomp pod_seccomp_type
      ctr_seccomp=$(echo "$csc" | jq -r '.seccompProfile.type // "not_set"' 2>/dev/null || echo "not_set")
      pod_seccomp_type=$(echo "$pod_sc" | jq -r '.seccompProfile.type // "not_set"' 2>/dev/null || echo "not_set")
      if [[ "${ctr_seccomp,,}" == "unconfined" || "${pod_seccomp_type,,}" == "unconfined" ]]; then
        write_finding "Seccomp Explicitly Unconfined" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "CRITICAL" "seccompProfile.type=Unconfined — seccomp explicitly disabled; all syscalls permitted" \
          "Actively removes syscall filtering; worse than absent; enables kernel exploits via unrestricted syscalls"
      elif [[ "$ctr_seccomp" == "not_set" && "$pod_seccomp" == "not_set" && -z "$legacy_seccomp" ]]; then
        write_finding "No Seccomp Profile" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "MEDIUM" "No seccompProfile at container or pod level; kernel syscalls unrestricted" \
          "Without seccomp, container can make any syscall; expands kernel attack surface significantly"
      fi

      # ── C7: AppArmor ──
      local aa_key="container.apparmor.security.beta.kubernetes.io/${ctr_name}"
      local aa_val
      aa_val=$(echo "$pod_json" | jq -r --arg k "$aa_key" '.metadata.annotations[$k] // ""')
      local ctr_aa_sc
      ctr_aa_sc=$(echo "$csc" | jq -r '.appArmorProfile.type // ""' 2>/dev/null || echo "")
      if [[ "${aa_val,,}" == "unconfined" || "${ctr_aa_sc,,}" == "unconfined" ]]; then
        write_finding "AppArmor Explicitly Unconfined" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "HIGH" "AppArmor profile=unconfined — MAC policy explicitly disabled for container" \
          "Explicitly disabling AppArmor removes all mandatory access controls; maximum exposure if container is compromised"
      elif [[ -z "$aa_val" && -z "$ctr_aa_sc" ]]; then
        write_finding "No AppArmor Profile" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "LOW" "No AppArmor annotation or securityContext.appArmorProfile set for container" \
          "Without AppArmor, container has no MAC policy; increases exploit impact"
      fi

      # ── C8: Image using 'latest' tag or no tag ──
      # Strip registry+port prefix before extracting tag to avoid :port false matches
      local img_tag img_name_part
      img_name_part=$(echo "$image" | sed 's|.*/||')
      img_tag=$(echo "$img_name_part" | grep -oE ':[^:@]+$' | sed 's/^://' || echo "")
      if echo "$image" | grep -q '@sha256:'; then img_tag="digest"; fi
      if [[ -z "$img_tag" || "$img_tag" == "latest" ]]; then
        write_finding "Image Uses 'latest' or No Tag" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "MEDIUM" "image='${image}' — mutable or absent tag; image content can change without notice" \
          "Supply-chain risk: image may silently change; no pinned digest verification"
      fi

      # ── C9: Image uses digest (best practice check - informational if missing) ──
      if ! echo "$image" | grep -q '@sha256:'; then
        write_finding "Image Not Pinned to Digest" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "LOW" "image='${image}' does not use @sha256 digest pinning" \
          "Without digest pinning, image can be silently swapped (supply chain attack)"
      fi

      # ── C10: Resource limits missing (DoS / noisy-neighbour attack surface) ──
      local cpu_lim mem_lim
      cpu_lim=$(echo "$ctr_json" | jq -r '.resources.limits.cpu // ""')
      mem_lim=$(echo "$ctr_json" | jq -r '.resources.limits.memory // ""')

      if [[ -z "$cpu_lim" || -z "$mem_lim" ]]; then
        write_finding "No Resource Limits Set" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
          "LOW" "limits: cpu=${cpu_lim:-<none>}, memory=${mem_lim:-<none>}" \
          "No limits allow unbounded resource consumption; enables DoS against co-located workloads on the node"
      fi

      # ── C11: Environment variables with sensitive patterns ──
      # Keyword match rules:
      #   - Full-word match for short/noisy terms (key, auth) via \b word boundaries
      #     to avoid false positives like MONKEY, AUTHOR, CACHE_KEY_PREFIX
      #   - Substring match is fine for unambiguous terms (password, secret, token, etc.)
      #   - Unified keyword list applied consistently across all three sub-checks
      echo "$ctr_json" | jq -c '.env // [] | .[]' 2>/dev/null | while IFS= read -r env_entry; do
        local env_name env_val val_from_type
        env_name=$(echo "$env_entry" | jq -r '.name // ""')
        env_val=$(echo "$env_entry"  | jq -r '.value // ""')

        # Unified sensitive name pattern — word boundaries on short/ambiguous terms
        local sensitive_name=false
        if echo "$env_name" | grep -qiE           '(password|passwd|secret|token|api_key|apikey|private_key|access_key|credential|key|auth)'; then
          sensitive_name=true
        fi

        # Classify the source of the env var value
        val_from_type=$(echo "$env_entry" | jq -r '
          if .valueFrom then
            if .valueFrom.secretKeyRef      then "secretKeyRef"
            elif .valueFrom.configMapKeyRef then "configMapKeyRef"
            elif .valueFrom.fieldRef        then "fieldRef"
            elif .valueFrom.resourceFieldRef then "resourceFieldRef"
            else "unknownRef"
            end
          elif (.value != null and .value != "") then "plaintext"
          else "empty"
          end')

        if [[ "$sensitive_name" == "true" ]]; then
          case "$val_from_type" in
            plaintext)
              # Literal value hardcoded in pod spec
              write_finding "Sensitive Data in Plaintext Env Var" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
                "HIGH" "env var '${env_name}' has a hardcoded plaintext value in pod spec" \
                "Plaintext secrets in pod spec are stored unencrypted in etcd and visible to anyone who can read the pod; use secretKeyRef"
              ;;
            configMapKeyRef)
              # Pulled from a ConfigMap — not encrypted at rest by default
              write_finding "Sensitive Data Sourced from ConfigMap" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
                "HIGH" "env var '${env_name}' loaded via valueFrom.configMapKeyRef — ConfigMaps are not encrypted at rest" \
                "ConfigMaps store data in plaintext in etcd; sensitive values must use Secrets with encryption at rest enabled"
              ;;
            fieldRef|resourceFieldRef)
              # Pulled from pod metadata or resource fields — not a Secret
              write_finding "Sensitive Env Var Sourced from Pod Field (Not Secret)" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
                "MEDIUM" "env var '${env_name}' loaded via valueFrom.${val_from_type} — pod/resource metadata, not a Secret" \
                "Using pod field references for sensitive variable names suggests a misconfiguration; value is not protected as a Secret"
              ;;
            unknownRef)
              # valueFrom present but type unrecognised
              write_finding "Sensitive Env Var with Unknown Value Source" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
                "MEDIUM" "env var '${env_name}' uses valueFrom with unrecognised source type" \
                "Review the value source; ensure sensitive values are always sourced from Kubernetes Secrets"
              ;;
            secretKeyRef|empty)
              # secretKeyRef is correct practice — no finding; empty value is not a risk
              ;;
          esac
        fi
      done

      # ── C12: Volume mounts with sensitive paths / writable ──
      echo "$ctr_json" | jq -c '.volumeMounts // [] | .[]' 2>/dev/null | while IFS= read -r vm; do
        local vm_name vm_path vm_ro
        vm_name=$(echo "$vm" | jq -r '.name // ""')
        vm_path=$(echo "$vm" | jq -r '.mountPath // ""')
        vm_ro=$(echo "$vm"   | jq -r '.readOnly // false')

        case "$vm_path" in
          /etc/passwd|/etc/shadow|/etc/hosts|/etc/cni*|/var/run/secrets/kubernetes.io*)
            write_finding "Sensitive Path Mounted in Container" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
              "HIGH" "volumeMount '${vm_name}' at '${vm_path}' (readOnly=${vm_ro})" \
              "Mounting sensitive system paths can expose credentials or enable persistence"
            ;;
        esac

        if [[ "$vm_ro" == "false" || "$vm_ro" == "null" ]]; then
          # Only flag if path looks like it should be RO
          if echo "$vm_path" | grep -qE '^/(etc|usr|bin|sbin|lib|var/run/secrets)'; then
            write_finding "Sensitive Mount Not Read-Only" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
              "MEDIUM" "volumeMount '${vm_name}' at '${vm_path}' mounted read-write" \
              "Writable mount at sensitive path allows modification of system/config files"
          fi
        fi
      done

      # ── C13: hostPort binding — actually binds on the node network interface ──
      # containerPort is documentation-only; hostPort is the real enforcement point
      echo "$ctr_json" | jq -c '.ports // [] | .[]' 2>/dev/null | while IFS= read -r port_entry; do
        local hport cport pprot
        hport=$(echo "$port_entry" | jq -r '.hostPort // 0')
        cport=$(echo "$port_entry" | jq -r '.containerPort // 0')
        pprot=$(echo "$port_entry" | jq -r '.protocol // "TCP"')
        if [[ "$hport" -gt 0 ]]; then
          write_finding "hostPort Binding on Node" "$ctrl_type" "$pod_name" "$ctr_name ($ctr_type)" "$ns" \
            "HIGH" "hostPort=${hport} bound to node interface (containerPort=${cport}/${pprot})" \
            "hostPort bypasses NetworkPolicy, binds directly on node IP, exposes service on every node the pod lands on"
        fi
      done

    done  # end container loop

    # ── P11: Tolerations allowing scheduling on master/control-plane ──
    local taint_master
    taint_master=$(echo "$spec" | jq -r '
      .tolerations // [] |
      map(select(
        (.key == "node-role.kubernetes.io/master" or
         .key == "node-role.kubernetes.io/control-plane") and
        .effect == "NoSchedule"
      )) | length')
    if [[ "$taint_master" -gt 0 ]]; then
      write_finding "Tolerates Control-Plane Taint" "$ctrl_type" "$pod_name" "N/A" "$ns" \
        "HIGH" "Pod tolerates master/control-plane NoSchedule taint — can land on control-plane nodes" \
        "Workloads on control-plane nodes have access to cluster management components"
    fi

    # ── P12: shareProcessNamespace ──
    if echo "$spec" | jq -e '.shareProcessNamespace == true' &>/dev/null; then
      write_finding "Shared Process Namespace Between Containers" "$ctrl_type" "$pod_name" "N/A" "$ns" \
        "MEDIUM" "spec.shareProcessNamespace=true — all containers share PID namespace" \
        "One container can inspect/signal processes in other containers; credential scraping risk"
    fi

    # ── P13: Priority class — privileged/system classes on user workloads ──
    local prio_class
    prio_class=$(echo "$spec" | jq -r '.priorityClassName // ""')
    if echo "$prio_class" | grep -qiE '(system-cluster-critical|system-node-critical)'; then
      if [[ "$ns" != "kube-system" ]]; then
        write_finding "Workload Uses System-Critical Priority Class" "$ctrl_type" "$pod_name" "N/A" "$ns" \
          "HIGH" "priorityClassName='${prio_class}' used in non-kube-system namespace '${ns}'" \
          "Hijacking system priority classes can cause eviction of critical system pods (DoS)"
      fi
    fi

  done  # end pod loop
}

# ─── Online Mode — fetch from live cluster ────────────────────────────────────
run_online() {
  echo -e "\n${CYAN}[*] Online mode — querying live cluster via kubectl...${NC}"

  if ! kubectl cluster-info &>/dev/null; then
    echo -e "${RED}[!] Cannot connect to cluster. Check KUBECONFIG or cluster connectivity.${NC}"
    exit 1
  fi

  local live_json="$TMP_DIR/live_pods.json"

  echo -e "${CYAN}[*] Fetching all pods from all namespaces...${NC}"
  # Use JSON output directly for accuracy
  kubectl get pods -A -o json 2>/dev/null | jq '[.items[]]' > "$live_json"

  local count
  count=$(jq 'length' "$live_json")
  echo -e "${GREEN}[+] Retrieved ${count} pods from cluster.${NC}"

  scan_pods_json "$live_json"
}

# ─── Offline Mode — parse local YAML file ─────────────────────────────────────
run_offline() {
  echo -e "\n${CYAN}[*] Offline mode — parsing file: ${INPUT_FILE}${NC}"

  if [[ ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}[!] File not found: ${INPUT_FILE}${NC}"; exit 1
  fi

  echo -e "${CYAN}[*] Converting YAML → JSON...${NC}"
  local json_file
  json_file=$(yaml_to_json "$INPUT_FILE")

  # Handle kubectl output wrapper (kind: List)
  local pod_count
  pod_count=$(jq '
    if type=="array" then
      map(select(.kind == "Pod")) | length
    elif .kind == "List" then
      [.items[] | select(.kind == "Pod")] | length
    elif .kind == "Pod" then 1
    else 0 end
  ' "$json_file" 2>/dev/null || echo 0)

  if [[ "$pod_count" -eq 0 ]]; then
    echo -e "${YELLOW}[!] No Pod objects found. Trying to extract from List...${NC}"
    # Normalise: extract items from List
    jq '
      if type=="array" then
        if .[0].kind == "List" then [.[0].items[]] else . end
      elif .kind == "List" then [.items[]]
      else [.] end
    ' "$json_file" > "$TMP_DIR/norm_pods.json"
    mv "$TMP_DIR/norm_pods.json" "$json_file"
  else
    # Filter only Pods from possibly mixed manifest
    jq '
      if type=="array" then
        map(select(.kind == "Pod"))
      elif .kind == "List" then
        [.items[] | select(.kind == "Pod")]
      elif .kind == "Pod" then [.]
      else [] end
    ' "$json_file" > "$TMP_DIR/pods_only.json"
    mv "$TMP_DIR/pods_only.json" "$json_file"
  fi

  scan_pods_json "$json_file"
}

# ─── Summary ──────────────────────────────────────────────────────────────────
print_summary() {
  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════${NC}"
  echo -e "${BOLD}  SCAN COMPLETE${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════${NC}"
  FINDINGS=$(cat "$FINDINGS_FILE" 2>/dev/null || echo 0)
  echo -e "  Total Findings : ${RED}${FINDINGS}${NC}"
  echo -e "  Output CSV     : ${GREEN}${OUTPUT_CSV}${NC}"

  # Severity breakdown from CSV (skip header)
  if [[ -f "$OUTPUT_CSV" ]]; then
    local crit high med low
    crit=$(tail -n +2 "$OUTPUT_CSV" | awk -F',' '{print $6}' | tr -d '"' | grep -c "CRITICAL" || true)
    high=$(tail -n +2 "$OUTPUT_CSV" | awk -F',' '{print $6}' | tr -d '"' | grep -c "HIGH"     || true)
    med=$(tail -n +2  "$OUTPUT_CSV" | awk -F',' '{print $6}' | tr -d '"' | grep -c "MEDIUM"   || true)
    low=$(tail -n +2  "$OUTPUT_CSV" | awk -F',' '{print $6}' | tr -d '"' | grep -c "LOW"      || true)
    echo ""
    echo -e "  ${RED}CRITICAL: ${crit}${NC}"
    echo -e "  ${RED}HIGH    : ${high}${NC}"
    echo -e "  ${YELLOW}MEDIUM  : ${med}${NC}"
    echo -e "  ${CYAN}LOW     : ${low}${NC}"
  fi
  echo -e "${BOLD}═══════════════════════════════════════════${NC}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  print_banner

  # Validate mode
  if [[ "$MODE" != "online" && "$MODE" != "offline" ]]; then
    echo -e "${RED}[!] Invalid mode: $MODE. Use 'online' or 'offline'.${NC}"; exit 1
  fi

  if [[ "$MODE" == "offline" && -z "$INPUT_FILE" ]]; then
    echo -e "${RED}[!] Offline mode requires --file <path_to_pods.yaml>${NC}"; exit 1
  fi

  check_and_install_deps
  init_csv

  # Re-detect yq after potential install
  if command -v yq3 &>/dev/null; then
    YQ_CMD="yq3"
  elif command -v yq &>/dev/null; then
    YQ_VER=$(yq --version 2>&1 | grep -oE '[0-9]+' | head -1)
    if [[ "$YQ_VER" == "3" ]]; then
      YQ_CMD="yq"
    else
      YQ_CMD=""
    fi
  else
    YQ_CMD=""
  fi

  case "$MODE" in
    online)  run_online ;;
    offline) run_offline ;;
  esac

  print_summary
}

main "$@"
