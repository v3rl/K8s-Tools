# Kubernetes RBAC Security Auditor

A shell script that audits Kubernetes RBAC configurations for security misconfigurations, dangerous permission grants, and cloud-specific risks. Works against live clusters (online) or kubectl YAML dumps (offline). Outputs a detailed CSV report with severity ratings and plain-English risk descriptions.

---

## Features

- **32 security checks** covering RBAC, pod security, and cloud-specific risks
- **Works online** (live cluster via kubectl) or **offline** (8 kubectl YAML dump files)
- **Cloud-aware** — dedicated checks for AKS, EKS, and GKE
- **Smart allowlists** — suppresses known-safe system/infra components by default (CNI, CSI, ArgoCD, Flux, Prometheus, Istio, cert-manager, and 100+ more)
- **CSV output** with 11 columns including a **Risk Description** column explaining the concrete attack impact of each finding
- **Exception report** — optionally write suppressed findings to a separate CSV for audit trail

---

## Requirements

| Mode | Tools needed |
|---|---|
| Online | `kubectl` (configured and connected) + `jq` |
| Offline | `jq` + `yq` (kislyuk/yq — `pip install yq`) |

### Install dependencies

```bash
# jq
brew install jq           # macOS
apt-get install jq        # Debian/Ubuntu

# yq (kislyuk/yq) — jq wrapper that reads YAML
pip install yq

# Verify
yq --version   # e.g. yq 3.4.3
```


---

## Quick Start

```bash
# Make the script executable
chmod +x k8s_rbac_audit.sh

# Run against your current cluster
./k8s_rbac_audit.sh --mode online --output report.csv

# Step 1 — dump resources from the cluster
mkdir dump
kubectl get roles               -A -o yaml > dump/roles.yaml
kubectl get clusterroles           -o yaml > dump/clusterroles.yaml
kubectl get rolebindings        -A -o yaml > dump/rolebindings.yaml
kubectl get clusterrolebindings    -o yaml > dump/clusterrolebindings.yaml
kubectl get pods                -A -o yaml > dump/pods.yaml
kubectl get serviceaccounts     -A -o yaml > dump/serviceaccounts.yaml
kubectl get services            -A -o yaml > dump/services.yaml
kubectl get namespaces             -o yaml > dump/namespaces.yaml

# Step 2 — run the audit
./k8s_rbac_audit.sh --mode offline --dir ./dump --output report.csv
```

---

## All Options

```
Usage:
  k8s_rbac_audit.sh --mode online  [OPTIONS]
  k8s_rbac_audit.sh --mode offline --dir <path> [OPTIONS]
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--mode` | Yes | — | `online` (live cluster) or `offline` (manifests) |
| `--dir` | offline only | — | Directory containing the 8 kubectl YAML dump files |
| `--kubeconfig` | no | `$KUBECONFIG` | Path to a specific kubeconfig file |
| `--context` | no | current context | kubeconfig context name to use |
| `--cloud` | no | `auto` | Cloud provider: `auto`, `aks`, `eks`, `gke`, `vanilla` |
| `--output` | no | `rbac_audit_<timestamp>.csv` | Output CSV file path |
| `--no-exceptions` | no | off | Disable allowlists — report all findings including system components |
| `--exception-report` | no | — | Write suppressed findings to this CSV path |
| `--help` | no | — | Show usage and exit |

---

## Usage Examples

### Online mode

```bash
# Basic run — auto-detects cloud provider
./k8s_rbac_audit.sh --mode online --output report.csv

# Specific kubeconfig and context
./k8s_rbac_audit.sh --mode online \
  --kubeconfig ~/.kube/prod-config \
  --context prod-eu-west \
  --output prod-report.csv

# Force EKS mode (skips auto-detection)
./k8s_rbac_audit.sh --mode online --cloud eks --output eks-report.csv

# Full audit — disable allowlists to see every finding including system components
./k8s_rbac_audit.sh --mode online --no-exceptions --output full-report.csv

# Audit with separate file for suppressed findings
./k8s_rbac_audit.sh --mode online \
  --output findings.csv \
  --exception-report suppressed.csv
```

### Offline mode

Offline mode requires exactly 8 YAML files, each produced by `kubectl get ... -o yaml`.

```bash
# Step 1 — dump the required resources from the cluster
mkdir ./dump

kubectl get roles               -A -o yaml > ./dump/roles.yaml
kubectl get clusterroles           -o yaml > ./dump/clusterroles.yaml
kubectl get rolebindings        -A -o yaml > ./dump/rolebindings.yaml
kubectl get clusterrolebindings    -o yaml > ./dump/clusterrolebindings.yaml
kubectl get pods                -A -o yaml > ./dump/pods.yaml
kubectl get serviceaccounts     -A -o yaml > ./dump/serviceaccounts.yaml
kubectl get services            -A -o yaml > ./dump/services.yaml
kubectl get namespaces             -o yaml > ./dump/namespaces.yaml

# Step 2 — run the audit
./k8s_rbac_audit.sh --mode offline --dir ./dump --output findings.csv

# With exception report
./k8s_rbac_audit.sh --mode offline --dir ./dump \
  --output findings.csv --exception-report suppressed.csv

# With cloud-specific checks (auto-detection not available offline)
./k8s_rbac_audit.sh --mode offline --dir ./dump --cloud eks --output eks.csv
```

> The cloud provider cannot be auto-detected in offline mode. It defaults to `vanilla`. Pass `--cloud aks|eks|gke` explicitly to enable cloud-specific checks.

---

## Output CSV Columns

Each finding in the CSV contains the following columns:

| Column | Description |
|---|---|
| **Issue** | Short description of the security problem found |
| **Dangerous Verbs or Resources** | The specific verbs and/or resources involved |
| **Role or ClusterRole** | The role that grants the problematic permission |
| **Binding** | The RoleBinding or ClusterRoleBinding that attaches the role |
| **Namespace** | Namespace where the binding applies |
| **Service Account** | The ServiceAccount subject of the binding |
| **Pod Using SA** | Any running pod that uses this ServiceAccount |
| **Service Backed by Pod** | Kubernetes Service fronting that pod (if any) |
| **Pod Namespace** | Namespace of the pod |
| **Severity** | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| **Risk Description** | Plain-English explanation of the concrete attack impact |

### Severity guide

| Severity | Meaning |
|---|---|
| **CRITICAL** | Direct path to cluster takeover, credential theft, or node compromise. Fix immediately. |
| **HIGH** | Significant privilege — enables lateral movement, namespace escape, or sensitive data access. |
| **MEDIUM** | Weakens defence-in-depth — not directly exploitable but increases blast radius of other issues. |
| **LOW** | Latent or theoretical risk — orphaned roles, informational misconfigurations. |
| **INFO** | Informational — no direct vulnerability but warrants manual review. |

---

## Security Checks

### Core RBAC (C01–C25)

| ID | Check | Severity |
|---|---|---|
| C01 | Wildcard verb or resource (`*`) in a role | CRITICAL |
| C02 | `cluster-admin` ClusterRole bound to a ServiceAccount | CRITICAL |
| C03 | Dangerous verb+resource combos (secrets, exec, webhook, CSR, nodes, RBAC objects…) | CRITICAL / HIGH / MEDIUM |
| C04 | `bind` or `escalate` verb on roles — privilege escalation path | CRITICAL |
| C05 | `impersonate` verb — act as any user/group/SA | CRITICAL |
| C06 | Non-trivial role bound to the `default` ServiceAccount | HIGH |
| C07 | `automountServiceAccountToken` not disabled (pod and SA level) | MEDIUM |
| C08 | Cross-namespace RoleBinding — SA in a different namespace | HIGH |
| C09 | Powerful ClusterRole (`admin`/`edit`/`cluster-admin`) via namespace RoleBinding | HIGH |
| C10 | SA subject in ClusterRoleBinding has no namespace field | MEDIUM |
| C11 | Read access to Secrets (`get`/`list`/`watch`) | HIGH |
| C12 | Write access to Webhook configurations — API request interception | CRITICAL |
| C13 | Write access to CRDs or APIServices — API extension attack | HIGH |
| C14 | Access to `nodes/proxy` subresource — bypasses RBAC and NetworkPolicies | CRITICAL |
| C15 | Dangerous ClusterRole exists but has no binding (orphaned) | LOW |
| C16 | Pod running as root with SA token auto-mounted | HIGH |
| C17 | Pod with `hostPath` volume mount — node filesystem exposure | HIGH |
| C18 | Privileged container (`privileged: true`) with SA token — kernel + API access | CRITICAL |
| C19 | Write access to RBAC objects — self-escalation loop | CRITICAL |
| C20 | `serviceaccounts/token` create — mint arbitrary-lifetime tokens | CRITICAL |
| C21 | Built-in `admin` ClusterRole bound to a ServiceAccount via RoleBinding | HIGH |
| C22 | `system:masters` group bound — bypasses all RBAC authorisation | CRITICAL |
| C23 | `system:anonymous` or `system:unauthenticated` has an RBAC binding | CRITICAL |
| C24 | Role bound to `system:authenticated` — affects every valid token holder | HIGH |
| C25 | `pods/exec` create access (CRITICAL in prod namespaces) | HIGH / CRITICAL |

### Extended checks (C26–C33)

| ID | Check | Severity |
|---|---|---|
| C26 | `system:serviceaccounts` group binding — all SAs inherit role cluster-wide or per-namespace | CRITICAL / HIGH |
| C27 | SubjectAccessReview/SelfSubjectAccessReview create — RBAC reconnaissance | HIGH |
| C28 | Dangerous Linux capabilities (`SYS_ADMIN`, `NET_ADMIN`, `NET_RAW`…) or `allowPrivilegeEscalation: true` | CRITICAL / HIGH / MEDIUM |
| C30 | `tokenreviews` create permission — auth-delegation / token validation abuse | HIGH |
| C31 | CSR `approve`/`sign` permission — can forge cluster-trusted TLS certificates | CRITICAL |
| C32 | Write access to Secrets — inject or overwrite credentials and TLS certs | CRITICAL |
| C33 | `deletecollection` verb — mass-delete any resource type in one call | HIGH |

### Cloud-specific checks

#### AKS (Azure Kubernetes Service)
| Check | Severity |
|---|---|
| AzureIdentityBinding exposes managed identity to pods | HIGH |
| AzureIdentityBinding with no pod selector (matches ALL pods) | CRITICAL |
| AAD Group granted ClusterRoleBinding | HIGH |
| Agentpool MSI ServiceAccount with cluster-level binding | HIGH |
| ServiceAccount with Workload Identity annotation | MEDIUM |

#### EKS (Amazon Elastic Kubernetes Service)
| Check | Severity |
|---|---|
| IRSA ServiceAccount with IAM Role annotation | MEDIUM |
| `aws-auth` ConfigMap grants `system:masters` to IAM Role | CRITICAL |
| `aws-auth` ConfigMap grants `system:masters` to IAM User | CRITICAL |
| Node in managed nodegroup — EC2 instance profile review | INFO |
| AWS system SA with ClusterRoleBinding | MEDIUM |

#### GKE (Google Kubernetes Engine)
| Check | Severity |
|---|---|
| Workload Identity SA with GCP Service Account annotation | MEDIUM |
| Pod on GKE node — metadata server exposure | INFO |
| GCP Service Account as direct K8s RBAC subject | HIGH |
| Namespace with Binary Authorization excluded | HIGH |

---

## Allowlist Behaviour

By default the script suppresses findings from known-safe infrastructure components so you can focus on real issues. All entries are **pinned to specific SA names, namespaces, and role patterns** — no blanket namespace wildcards.

| Group | Suppressed components |
|---|---|
| **K8s control-plane** | kube-apiserver, scheduler, controller-manager, kube-proxy, all `system:controller:*` SAs, CoreDNS |
| **CNI plugins** | Calico, Cilium, Flannel, WeaveNet, OVN-Kubernetes, Multus, Whereabouts |
| **CSI drivers** | AWS EBS, GCE PD, Azure Disk/File, NFS, Rook-Ceph CSI, Longhorn CSI, OpenEBS CSI, TopoLVM, SMB *(kube-system only)* |
| **Storage operators** | Kadalu operator+CSI, Rook-Ceph named SAs, Longhorn operator, OpenEBS Maya operator, local-path-provisioner, NFS provisioner |
| **Autoscalers** | KEDA operator+metrics-server, cluster-autoscaler *(kube-system only)*, VPA admission/recommender/updater, Descheduler |
| **GitOps** | ArgoCD app-controller, server, repo-server, notifications, applicationset-controller; all 6 Flux controllers |
| **Metrics** | metrics-server, kube-state-metrics, Prometheus+operator+Alertmanager, Thanos, Loki, OpenTelemetry operator |
| **Logging** | Fluentd, Fluent Bit *(pinned SA names only)* |
| **Ingress** | NGINX Ingress *(ingress-nginx ns)*, Traefik *(traefik ns)*, Contour, HAProxy, Kong, Emissary |
| **Service mesh** | Istiod + gateways, Linkerd control plane *(3 named SAs)*, Consul Connect injector, Kuma control plane |
| **Security tools** | cert-manager *(3 named SAs)*, external-secrets, Vault+injector, OPA Gatekeeper, Kyverno, Falco, Trivy, Sealed Secrets |
| **AKS** | aad-pod-identity, azure-policy, azure-npm, konnectivity, omsagent, ama-logs, Azure Disk/File CSI, cloud-node-manager, CCM |
| **EKS** | aws-node, kube-proxy, ALB controller *(kube-system)*, EBS/EFS CSI, ACM PCA issuer, vpc-admission-webhook, CloudWatch agent, CCM |
| **GKE** | config-connector, gke-metadata-server, anthos-connect-agent, policy-controller, stackdriver-agent, fluentbit-gke, Filestore/PD CSI, CCM |
| **Vanilla add-ons** | MetalLB, CoreDNS, kube-dns, node-local-dns |

**Intentionally NOT suppressed** (will always generate findings if they have unusual RBAC):
- Grafana, Datadog, Filebeat, Promtail, Logstash, Vector — these tools need minimal or no cluster RBAC
- ArgoCD Dex, ArgoCD Redis — OIDC provider and cache with no K8s API needs
- Linkerd Viz, Traefik in kube-system — dashboard/UI or misconfigured namespace
- Kubernetes Dashboard — well-known source of cluster-admin misconfigurations
- Cluster Autoscaler outside kube-system — non-standard deployment worth flagging

Use `--no-exceptions` to disable all suppression and see every finding. Use `--exception-report` to get a second CSV listing everything that was suppressed, for compliance audit trails.

---

## How It Works

```
k8s_rbac_audit.sh
│
├── load_online()        kubectl get roles, bindings, pods, services, SAs
│   └── load_offline()   yq . <file> | jq . converts each of 8 YAML dumps to JSON
│
├── 33 check functions   Each emits findings via add_finding_filtered()
│   │
│   └── add_finding_filtered()
│       ├── is_excepted()   Match against allowlist patterns (SA / NS / role)
│       ├── → suppressed    Written to EXCEPTION_ROWS (if --exception-report set)
│       └── → flagged       Written to CSV_ROWS via add_finding()
│
└── write_csv()          Writes main CSV + optional exception CSV
```

**Offline YAML parsing — one file per resource kind:**
Each of the 8 kubectl dump files is converted directly to JSON with `yq . <file> | jq . > <dest>`.
`yq` (kislyuk/yq) reads the YAML and passes it through `jq`, producing the same JSON that
`kubectl get ... -o json` would return. The resulting JSON files are used directly by all 32 checks —
no file discovery, no document splitting, no intermediate stream.

---

## Contributing

The allowlist patterns live in `build_allowlists()`. To add a new suppression entry add a line in the format:

```bash
"GROUP_NAME|SA_PATTERN|NAMESPACE_PATTERN|ROLE_PATTERN|REASON"
```

Patterns are ERE (bash `=~`). An empty field matches everything (`.*`).

To add a new check, write a `check_<name>()` function that calls `emit_for_role` or `add_finding_filtered`, then add it to the call list in `main()`. All checks query the per-kind JSON files (`$ROLES_JSON`, `$PODS_JSON`, etc.) using plain `jq` — no YAML parsing needed inside check functions.


# K8s Pod & Container Security Hardening Scanner

A pure Bash shell script that audits Kubernetes pods and containers for security hardening misconfigurations. Works against a live cluster (online) or a saved `kubectl` YAML export (offline). All findings are written to a structured CSV report.

Aligned with:
- **CIS Kubernetes Benchmark**
- **NSA/CISA Kubernetes Hardening Guide**
- **OWASP Kubernetes Top 10**

---

## Features

- **Online mode** — queries a live cluster via `kubectl` in real time
- **Offline mode** — parses a locally saved `kubectl get pods -A -o yaml` file
- **Auto dependency installation** — installs `kubectl`, `jq`, `yq v3`, `python3` if missing
- **CSV output** — one row per finding with full context
- **Severity classification** — CRITICAL / HIGH / MEDIUM / LOW
- **Covers all container types** — regular containers, init containers, ephemeral containers
- **Linux capability intelligence** — per-capability risk descriptions with worst-severity rollup
- **Zero external scoring tools required** — pure Bash + jq + yq

---

## Requirements

The script auto-installs missing tools on first run. Manual requirements if running in an air-gapped environment:

| Tool | Version | Purpose |
|---|---|---|
| `bash` | ≥ 4.0 | Script runtime |
| `kubectl` | any | Live cluster queries (online mode only) |
| `jq` | ≥ 1.6 | JSON processing |
| `yq` | **v3.x** | YAML → JSON conversion (offline mode) |
| `python3` | ≥ 3.6 | Fallback YAML → JSON if yq unavailable |
| `curl` | any | Dependency downloads |

> `yq` v3 is installed as `yq3` if a different version is already present.  
> If `yq` cannot be downloaded, `python3` with the `PyYAML` library is used as a fallback.

---

## Installation

```bash
git clone <repo>
cd <repo>
chmod +x k8s_hardening_scan.sh
```

---

## Usage

```
./k8s_hardening_scan.sh [OPTIONS]

Options:
  -m, --mode      online | offline  (default: online)
  -f, --file      Path to pods.yaml (required for offline mode)
  -o, --output    Output CSV file   (default: k8s_hardening_report_<timestamp>.csv)
  -h, --help      Show help
```

### Online Mode — Live Cluster

Ensure `KUBECONFIG` is set and you have cluster read access.

```bash
./k8s_hardening_scan.sh --mode online
```

```bash
./k8s_hardening_scan.sh --mode online --output my_report.csv
```

### Offline Mode — Saved YAML

First export the pod manifest from your cluster:

```bash
kubectl get pods -A -o yaml > pods.yaml
```

Then run the scanner against it:

```bash
./k8s_hardening_scan.sh --mode offline --file pods.yaml
```

```bash
./k8s_hardening_scan.sh --mode offline --file pods.yaml --output my_report.csv
```

---

## Output

### Terminal

Progress and findings are printed to stdout with colour-coded severity:

```
╔══════════════════════════════════════════════════════════════════╗
║     K8s Pod & Container Security Hardening Scanner               ║
║     Detects: CIS Benchmark | NSA/CISA | OWASP K8s Top 10        ║
╚══════════════════════════════════════════════════════════════════╝

[*] Scanning 12 pod(s)...

  Pod: production/api-server-7f9d (Deployment)
  [CRITICAL] api-server-7f9d/web → Privileged Container
  [HIGH]     api-server-7f9d/web → Container Runs as Root (UID 0)
  [HIGH]     api-server-7f9d/web → Dangerous Linux Capabilities Added
  [MEDIUM]   api-server-7f9d/web → Writable Root Filesystem
  ...

═══════════════════════════════════════════════════════
  SCAN COMPLETE
═══════════════════════════════════════════════════════
  Total Findings : 47

  CRITICAL: 3
  HIGH    : 14
  MEDIUM  : 18
  LOW     : 12
═══════════════════════════════════════════════════════
```

### CSV Report

Each row in the CSV contains:

| Column | Description |
|---|---|
| **Issue Name** | Short name of the finding |
| **Controller Type** | Pod / Deployment / DaemonSet / StatefulSet / ReplicaSet / Job / CronJob |
| **Pod Name** | Name of the affected pod |
| **Container Name** | Container name and type (container / initContainer / ephemeralContainer), or N/A for pod-level findings |
| **Namespace** | Kubernetes namespace |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **Issue Details** | One-liner describing exactly what was detected (field name, value) |
| **Risk / Impact** | Explanation of the security impact and attack scenario |

#### Example Rows

```csv
"Privileged Container","Deployment","api-pod","web (container)","production","CRITICAL","securityContext.privileged=true","Full host kernel access; equivalent to root on the node; trivial container escape"

"Dangerous Linux Capabilities Added","Deployment","api-pod","web (container)","production","CRITICAL","Highest severity: CRITICAL | drop=[<none>] | caps: SYS_ADMIN(CRITICAL); NET_RAW(HIGH); SETUID(MEDIUM)","SYS_ADMIN(CRITICAL): broadest Linux capability; enables mount, keyctl, namespace creation — primary escape vector | NET_RAW(HIGH): raw/packet sockets — ARP/DNS spoofing, MITM attacks | SETUID(MEDIUM): arbitrary UID changes — escalate via setuid binaries"

"Dangerous HostPath Volume","DaemonSet","log-collector","N/A (volume: docker-sock)","kube-system","CRITICAL","volume 'docker-sock' mounts hostPath='/var/run/docker.sock'","hostPath='/var/run/docker.sock' — runtime socket or kernel interface; enables full container escape and node compromise"
```

---

## Security Checks Reference

### Pod-Level Checks

| ID | Check | Severity | Field |
|---|---|---|---|
| P1 | Host PID Namespace Shared | HIGH | `spec.hostPID` |
| P2 | Host IPC Namespace Shared | HIGH | `spec.hostIPC` |
| P3 | Host Network Namespace Shared | HIGH | `spec.hostNetwork` |
| P4 | Service Account Token Auto-Mounted | MEDIUM | `spec.automountServiceAccountToken` |
| P5 | Dangerous HostPath Volume | CRITICAL–LOW | `spec.volumes[].hostPath.path` |
| P6 | HostPath Volume Type: Socket | CRITICAL | `spec.volumes[].hostPath.type=Socket` |
| P7 | HostPath Volume Type: BlockDevice | CRITICAL | `spec.volumes[].hostPath.type=BlockDevice` |
| P8 | HostPath Volume Type: CharDevice | HIGH | `spec.volumes[].hostPath.type=CharDevice` |
| P9 | SA Token Manually Projected (Bypasses automount=false) | MEDIUM | `spec.volumes[].projected.sources[].serviceAccountToken` |
| P10 | Default Service Account Used | LOW | `spec.serviceAccountName` |
| P11 | Tolerates Control-Plane Taint | HIGH | `spec.tolerations` |
| P12 | Shared Process Namespace Between Containers | MEDIUM | `spec.shareProcessNamespace` |
| P13 | Workload Uses System-Critical Priority Class | HIGH | `spec.priorityClassName` |

#### HostPath Volume Severity Tiers

| Tier | Paths | Rationale |
|---|---|---|
| CRITICAL | `/`, `/proc`, `/sys`, `/var/run/docker.sock`, `/run/docker.sock`, `/var/run/crio.sock`, `/run/containerd*` | Runtime sockets and kernel interfaces — direct container escape |
| HIGH | `/etc`, `/var/lib/kubelet`, `/var/lib/etcd`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64` | Cluster config, credentials, system binaries — credential theft or binary replacement |
| MEDIUM | `/var/log`, `/root`, `/home`, `/boot` | Sensitive data exposure or persistence paths |
| LOW | All other hostPath mounts | Unknown risk — flagged for audit visibility |

---

### Container-Level Checks

Applies to regular containers, init containers, and ephemeral containers.

| ID | Check | Severity | Field |
|---|---|---|---|
| C1 | Privileged Container | CRITICAL | `securityContext.privileged` |
| C2 | Container Runs as Root (UID 0) | HIGH | `securityContext.runAsUser=0` |
| C2 | runAsNonRoot Disabled | HIGH | `securityContext.runAsNonRoot=false` |
| C2 | No runAsNonRoot Enforcement | MEDIUM | Neither `runAsUser` nor `runAsNonRoot` set |
| C3 | Privilege Escalation Allowed | HIGH | `securityContext.allowPrivilegeEscalation` not false |
| C4 | Writable Root Filesystem | MEDIUM | `securityContext.readOnlyRootFilesystem` not true |
| C4b | Container Runs with Root GID (GID 0) | MEDIUM | `securityContext.runAsGroup=0` |
| C4c | procMount Set to Unmasked | CRITICAL | `securityContext.procMount=Unmasked` |
| C5 | Capabilities Not Dropped (drop ALL missing) | MEDIUM | `securityContext.capabilities.drop` missing ALL |
| C5 | Dangerous Linux Capabilities Added | CRITICAL–LOW | `securityContext.capabilities.add` |
| C6 | Seccomp Explicitly Unconfined | CRITICAL | `securityContext.seccompProfile.type=Unconfined` |
| C6 | No Seccomp Profile | MEDIUM | No `seccompProfile` at container or pod level |
| C7 | AppArmor Explicitly Unconfined | HIGH | AppArmor annotation or profile = `unconfined` |
| C7 | No AppArmor Profile | LOW | No AppArmor annotation or `appArmorProfile` |
| C8 | Image Uses 'latest' or No Tag | MEDIUM | Image tag absent or `latest` |
| C9 | Image Not Pinned to Digest | LOW | Image missing `@sha256:` digest |
| C10 | No Resource Limits Set | LOW | `resources.limits.cpu` or `.memory` absent |
| C11 | Sensitive Data in Plaintext Env Var | HIGH | Env var with sensitive name has hardcoded `.value` |
| C11 | Sensitive Data Sourced from ConfigMap | HIGH | Sensitive env var via `valueFrom.configMapKeyRef` |
| C11 | Sensitive Env Var Sourced from Pod Field | MEDIUM | Sensitive env var via `valueFrom.fieldRef` |
| C11 | Sensitive Env Var with Unknown Value Source | MEDIUM | Sensitive env var with unrecognised `valueFrom` type |
| C12 | Sensitive Path Mounted in Container | HIGH | volumeMount at `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, `/etc/cni*`, `/var/run/secrets/kubernetes.io*` |
| C12 | Sensitive Mount Not Read-Only | MEDIUM | Mount at sensitive path without `readOnly: true` |
| C13 | hostPort Binding on Node | HIGH | `ports[].hostPort > 0` |

---

### Linux Capabilities — Severity Classification

Each capability added via `securityContext.capabilities.add` is individually classified. The finding uses the highest severity across all detected capabilities, with all individual assessments concatenated in the Risk column.

| Capability | Tier | Risk |
|---|---|---|
| `SYS_ADMIN` | CRITICAL | Broadest capability; mount, keyctl, namespace, cgroup — primary container escape vector |
| `NET_ADMIN` | CRITICAL | Full host network stack control — interfaces, firewall, routing |
| `SYS_PTRACE` | CRITICAL | Read/write memory of any process — secret and credential extraction |
| `SYS_MODULE` | CRITICAL | Load/unload kernel modules — arbitrary kernel code execution, rootkit installation |
| `SYS_RAWIO` | CRITICAL | Raw I/O port and `/dev/mem` access — read/write physical memory |
| `SYS_BOOT` | CRITICAL | Reboot or kexec the host — node destruction |
| `BPF` | CRITICAL | Load eBPF programs — kernel escape, memory inspection, traffic interception |
| `NET_RAW` | HIGH | Raw/packet sockets — ARP/DNS spoofing, sniffing, MITM |
| `SYS_CHROOT` | HIGH | Change filesystem root — escape restricted environments |
| `SYS_TIME` | HIGH | Set system clock — breaks Kerberos, TLS cert validity, audit timestamps |
| `MKNOD` | HIGH | Create device files — access host storage via block/char devices |
| `SYS_TTY_CONFIG` | HIGH | TTY manipulation — hijack terminal sessions |
| `SYS_NICE` | HIGH | Set process priorities — starve other processes (DoS) |
| `SYS_RESOURCE` | HIGH | Override resource limits — bypass container runtime ulimits |
| `IPC_LOCK` | HIGH | Lock memory pages — bypass memory limits, contribute to host OOM |
| `IPC_OWNER` | HIGH | Bypass IPC permission checks — access shared memory of other processes |
| `SYS_PACCT` | HIGH | Enable/disable process accounting — suppress audit logs (defence evasion) |
| `LINUX_IMMUTABLE` | HIGH | Set immutable file flags — make backdoors undeletable |
| `PERFMON` | HIGH | Access perf subsystem — kernel/process memory side-channel (Spectre-class) |
| `CHECKPOINT_RESTORE` | HIGH | Checkpoint/restore processes — read/write other process memory |
| `AUDIT_CONTROL` | MEDIUM | Disable kernel auditing — blind the audit subsystem |
| `AUDIT_READ` | MEDIUM | Read audit log — expose security-sensitive audit trail |
| `AUDIT_WRITE` | MEDIUM | Write audit log — inject false records, corrupt audit trail |
| `SETUID` | MEDIUM | Arbitrary UID changes — escalate via setuid binaries |
| `SETGID` | MEDIUM | Arbitrary GID changes — access other groups' files |
| `SETFCAP` | MEDIUM | Set file capabilities — grant dangerous caps to arbitrary executables |
| `SETPCAP` | MEDIUM | Transfer capabilities — grant caps to child processes |
| `DAC_OVERRIDE` | MEDIUM | Bypass file permission checks — access any file |
| `DAC_READ_SEARCH` | MEDIUM | Bypass read/search permissions — read any file on accessible filesystems |
| `FOWNER` | MEDIUM | Bypass ownership checks — modify any file's permissions |
| `FSETID` | MEDIUM | Retain setuid/setgid bits — privilege escalation via file manipulation |
| `KILL` | MEDIUM | Send signals to any process — kill processes outside own UID (DoS) |
| `NET_BIND_SERVICE` | LOW | Bind to privileged ports (<1024) — low risk, violates least-privilege |
| `CHOWN` | LOW | Change file ownership — violates least-privilege |
| `LEASE` | LOW | Establish file leases — signals on file access |
| `SYSLOG` | LOW | Privileged syslog ops — read kernel log buffer |
| `WAKE_ALARM` | LOW | Set system-wide alarms — minimal security impact |

> `CAP_` prefix is automatically stripped — `CAP_SYS_ADMIN` and `SYS_ADMIN` are treated identically.  
> Unknown capabilities are classified as LOW with a note to review.

---

### Sensitive Environment Variable Detection

The scanner detects env vars with sensitive-sounding names that are not sourced from a Kubernetes Secret. Keyword matching uses Perl-compatible regex with word boundaries on short/ambiguous terms to minimise false positives.

**Matched keywords:** `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `private_key`, `access_key`, `credential`, `\bkey\b`, `\bauth\b`

**Excluded from false positives:** `AUTHOR`, `AUTHORIZATION_ENDPOINT`, `CACHE_KEY_PREFIX`, `MONKEY`, `DONKEY`, `JAVA_AUTH_OPTS` (word boundaries prevent these from matching)

| Source Type | Finding | Severity |
|---|---|---|
| Hardcoded `.value` | Sensitive Data in Plaintext Env Var | HIGH |
| `valueFrom.configMapKeyRef` | Sensitive Data Sourced from ConfigMap | HIGH |
| `valueFrom.fieldRef` / `resourceFieldRef` | Sensitive Env Var Sourced from Pod Field | MEDIUM |
| Unknown `valueFrom` type | Sensitive Env Var with Unknown Value Source | MEDIUM |
| `valueFrom.secretKeyRef` | No finding — correct practice | — |
| Empty value | No finding | — |

---

## Limitations

- **Static analysis only** — the script analyses manifest configuration; it does not connect to containers or inspect running processes.
- **No RBAC analysis** — ServiceAccount RBAC bindings and ClusterRoles are not evaluated (only the SA name and automount flag).
- **No NetworkPolicy analysis** — the script does not audit NetworkPolicy coverage per pod.
- **No image scanning** — image vulnerability scanning (CVEs) is out of scope; use Trivy or Grype for that.
- **Pods only** — the script processes Pod objects. Workload objects (Deployment, DaemonSet, etc.) are only referenced via `ownerReferences`; their own specs are not separately parsed.
- **`grep -qiP`** — the env var keyword check uses Perl-compatible regex (`-P`). On systems where `grep` is not compiled with PCRE (rare on macOS), this may fall back silently. Test with `grep -P '' /dev/null` to verify.

---

## Examples

### Run Against Live Cluster, Custom Output

```bash
./k8s_hardening_scan.sh --mode online --output cluster_audit_$(date +%F).csv
```

### Run Against Specific Namespace Export

```bash
kubectl get pods -n production -o yaml > prod_pods.yaml
./k8s_hardening_scan.sh --mode offline --file prod_pods.yaml --output prod_audit.csv
```

### Filter CSV for Critical Findings Only

```bash
awk -F',' '$6 == "\"CRITICAL\""' k8s_hardening_report_*.csv
```

### Count Findings by Severity

```bash
tail -n +2 k8s_hardening_report_*.csv \
  | awk -F',' '{print $6}' \
  | tr -d '"' \
  | sort | uniq -c | sort -rn
```

### Get All Findings for a Specific Namespace

```bash
grep '"production"' k8s_hardening_report_*.csv
```

---

## File Structure

```
.
├── k8s_hardening_scan.sh    # Main scanner script
└── README.md                # This file
```

Output files are created in the current working directory:

```
k8s_hardening_report_20250512_143022.csv    # Auto-named by default
```

---

## Severity Definitions

| Severity | Meaning |
|---|---|
| **CRITICAL** | Direct path to container escape, kernel compromise, or full node takeover. Remediate immediately. |
| **HIGH** | Significant privilege abuse, credential exposure, or host network/process access. Remediate urgently. |
| **MEDIUM** | Expands attack surface or enables abuse under additional conditions. Remediate as part of normal hardening cycle. |
| **LOW** | Violates least-privilege or best practice. Low direct impact. Address in next hardening review. |
