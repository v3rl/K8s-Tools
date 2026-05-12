#!/usr/bin/env bash
# =============================================================================
# k8s_rbac_audit.sh — Kubernetes RBAC Security Auditor
# =============================================================================
# Detects RBAC misconfigurations across vanilla K8s and cloud-managed clusters
# (AKS, EKS, GKE). Supports online (live cluster) and offline (manifest dir)
# modes. Outputs a detailed CSV report.
#
# Requirements (online):  kubectl, jq
# Requirements (offline): jq  +  yq (kislyuk/yq, the jq wrapper)
#   yq install : pip install yq
#   - yq converts YAML files to JSON first; all analysis runs pure jq
#   - If yq is absent, only .json files are processed (.yaml/.yml skipped)
#
# =============================================================================
# SECURITY ISSUES DETECTED BY THIS SCRIPT
# =============================================================================
#
# ── CORE RBAC CHECKS (C01 – C25) ─────────────────────────────────────────────
#
#  C01  Wildcard verb or resource in role                    [CRITICAL]
#       Role grants '*' on verbs or resources → unrestricted API access.
#
#  C02  cluster-admin ClusterRole bound to ServiceAccount    [CRITICAL]
#       Most privileged built-in role attached to a workload SA; any pod
#       using that SA has full cluster control.
#
#  C03  Dangerous verb on sensitive resource                 [CRITICAL/HIGH/MEDIUM]
#       Specific verb+resource combinations that enable attacks:
#         secrets + get/list/watch/delete        → credential theft
#         pods/exec + create                     → remote code execution
#         pods/attach + create                   → process injection
#         pods/portforward + create              → covert tunnel
#         serviceaccounts/token + create         → token impersonation
#         clusterroles + escalate/bind           → privilege escalation
#         clusterrolebindings + create/update    → self-grant admin
#         webhookconfigurations + create/update  → API request interception
#         namespaces + create/delete             → isolation escape
#         deployments/daemonsets/statefulsets    → workload hijack
#         configmaps + create/update             → config injection
#         networkpolicies + create/update        → policy bypass
#         podsecuritypolicies + use              → PSP abuse
#         customresourcedefinitions + create     → API extension attack
#         storageclasses + create/update         → storage manipulation
#         persistentvolumes + create/delete      → data exfiltration
#         nodes + *                              → node compromise
#
#  C04  Privilege escalation via bind/escalate verb          [CRITICAL]
#       Role grants 'bind' or 'escalate' on roles/clusterroles, allowing
#       the holder to create bindings to higher-privilege roles.
#
#  C05  Impersonation rights granted                         [CRITICAL]
#       'impersonate' verb on users/groups/serviceaccounts lets a principal
#       act as any other identity, bypassing audit trails.
#
#  C06  Non-trivial role bound to 'default' ServiceAccount   [HIGH]
#       The implicit 'default' SA in every namespace has a meaningful role;
#       any pod without an explicit SA inherits these rights.
#
#  C07  automountServiceAccountToken not disabled on pod     [MEDIUM]
#       Pod does not set automountServiceAccountToken: false; SA token is
#       mounted at /var/run/secrets and readable by any container process.
#
#  C08  Cross-namespace RoleBinding                          [HIGH]
#       RoleBinding grants permissions to a SA in a different namespace,
#       violating namespace isolation boundaries.
#
#  C09  Powerful ClusterRole via namespace-scoped RoleBinding [HIGH]
#       ClusterRole (admin, edit, cluster-admin, system:node) applied via a
#       namespace RoleBinding; broad permissions unusual in a single ns.
#
#  C10  Missing namespace on SA subject in ClusterRoleBinding [MEDIUM]
#       ClusterRoleBinding SA subject has no namespace field; may resolve
#       to an unintended namespace at runtime.
#
#  C11  Read access to Secrets                               [HIGH]
#       Role grants get/list/watch on secrets, exposing all credentials,
#       SA tokens, and TLS certificates in the namespace or cluster.
#
#  C12  Write access to Webhook configurations               [CRITICAL]
#       Creating or patching ValidatingWebhookConfigurations or
#       MutatingWebhookConfigurations can intercept every API request,
#       inject fields, or silently bypass security policies.
#
#  C13  Write access to CRDs or APIServices                  [HIGH]
#       Modifying CRDs or APIServices lets an attacker extend the API,
#       override schemas, or redirect API groups to rogue servers.
#
#  C14  Access to nodes/proxy subresource                    [CRITICAL]
#       nodes/proxy lets a client send arbitrary HTTP to the kubelet,
#       bypassing RBAC, NetworkPolicies, and audit logging entirely.
#
#  C15  Dangerous ClusterRole exists but is unbound          [LOW]
#       Orphaned ClusterRole with wildcard/escalate/bind/impersonate.
#       No current binding but can be activated later or from a backup.
#
#  C16  Pod running as root with SA token auto-mounted       [HIGH]
#       runAsUser=0 combined with token mount: container compromise
#       gives both root filesystem access and API server access.
#
#  C17  Pod with hostPath volume mount                       [HIGH]
#       hostPath volumes expose node filesystem to containers.
#       Paths like /etc, /var/lib/kubelet allow credential theft or
#       container escape.
#
#  C18  Privileged container with SA token mounted           [CRITICAL]
#       privileged: true disables most container isolation; combined
#       with a mounted token the attacker has kernel access + API access.
#
#  C19  Write access to RBAC objects (self-escalation)       [CRITICAL]
#       create/update/patch/delete on roles or bindings lets the holder
#       create new bindings granting themselves any permission.
#
#  C20  Can create ServiceAccount tokens                     [CRITICAL]
#       serviceaccounts/token + create allows minting arbitrary-lifetime
#       tokens for any SA, enabling long-lived credential abuse.
#
#  C21  Namespace admin ClusterRole bound to ServiceAccount  [HIGH]
#       Built-in 'admin' ClusterRole via RoleBinding gives workload SA
#       full namespace admin rights including creating further bindings.
#
#  C22  system:masters group explicitly bound                [CRITICAL]
#       system:masters bypasses ALL RBAC authorisation checks; principals
#       in this group have unconditional cluster-admin access.
#
#  C23  Anonymous/unauthenticated user has RBAC binding      [CRITICAL]
#       system:anonymous or system:unauthenticated has a role binding;
#       unauthenticated HTTP requests can perform API operations.
#
#  C24  Role bound to system:authenticated group             [HIGH]
#       Any valid-token holder (including low-privilege users and SAs)
#       inherits these permissions cluster-wide.
#
#  C25  pods/exec create access in namespace                 [HIGH / CRITICAL]
#       Grants interactive shell access into running pods.
#       Severity is escalated to CRITICAL in production namespaces.
#
#  C26  system:serviceaccounts group risky bindings           [CRITICAL / HIGH]
#       Any binding whose subject is system:serviceaccounts (all SAs cluster-wide)
#       or system:serviceaccounts:<ns> (all SAs in a namespace) grants permissions
#       to every current and future workload in that scope. Wildcard or admin-level
#       permissions are CRITICAL; all others are HIGH.
#
#  C27  SubjectAccessReview / SelfSubjectAccessReview permission [HIGH]
#       A role grants create on subjectaccessreviews, selfsubjectaccessreviews,
#       localsubjectaccessreviews, or selfsubjectrulesreviews.
#       Enables RBAC reconnaissance: holder can discover what any identity can do,
#       mapping privilege gaps to plan escalation paths.
#
#  C28  Dangerous Linux capabilities or allowPrivilegeEscalation [CRITICAL/HIGH/MEDIUM]
#       Containers with SYS_ADMIN, NET_ADMIN, NET_RAW, SYS_PTRACE, SYS_MODULE,
#       DAC_READ_SEARCH or similar caps, or allowPrivilegeEscalation: true.
#       SYS_ADMIN is near-equivalent to node root; NET_RAW enables ARP spoofing;
#       allowPrivilegeEscalation lets a setuid binary gain root inside container.
#
#  C30  TokenReview create permission                              [HIGH]
#       Lets a principal validate arbitrary tokens against the API server,
#       confirming validity and identity — reconnaissance for lateral movement.
#
#  C31  CertificateSigningRequest approve/sign permission          [CRITICAL]
#       Holder can approve CSRs for any identity including system:masters,
#       forging cluster-trusted TLS certificates that bypass all RBAC checks.
#
#  C32  Write access to Secrets (create/update/patch/delete)       [CRITICAL]
#       Holder can inject malicious credentials, replace TLS certificates with
#       attacker-controlled ones, or poison SA tokens used by other workloads.
#
#  C33  deletecollection verb (mass-delete any resource type)      [HIGH]
#       One API call deletes all resources of a type cluster-wide — wipes Pods,
#       Secrets, ConfigMaps, or PVCs. Effective denial-of-service or evidence
#       destruction.
#
# ── CLOUD-SPECIFIC CHECKS ─────────────────────────────────────────────────────
#
#  AKS  AzureIdentityBinding exposes managed identity to pods    [HIGH]
#       aad-pod-identity binding grants Azure IAM to pods beyond K8s RBAC.
#
#  AKS  AzureIdentityBinding with no pod selector               [CRITICAL]
#       Empty selector matches ALL pods in the namespace.
#
#  AKS  AAD Group granted ClusterRoleBinding                     [HIGH]
#       AAD group membership changes directly affect cluster access.
#
#  AKS  Agentpool MSI ServiceAccount with cluster binding        [HIGH]
#       SA matching node identity naming patterns has cluster-level bindings.
#
#  AKS  ServiceAccount with Workload Identity annotation         [MEDIUM]
#       azure.workload.identity/client-id federates SA to Azure AD app;
#       verify IAM permissions on that application.
#
#  EKS  IRSA ServiceAccount with IAM Role annotation             [MEDIUM]
#       eks.amazonaws.com/role-arn federates SA to AWS IAM role;
#       review IAM policies for over-permission.
#
#  EKS  aws-auth ConfigMap grants system:masters to IAM Role/User [CRITICAL]
#       Direct IAM-to-system:masters mapping bypasses all K8s RBAC.
#
#  EKS  Node in managed nodegroup (instance profile review)      [INFO]
#       Reminder to verify EC2 instance profile follows least-privilege.
#
#  EKS  AWS system SA with ClusterRoleBinding                    [MEDIUM]
#       aws-node/vpc-admission/eks-* SAs with cluster bindings; confirm
#       necessity of each permission.
#
#  GKE  Workload Identity SA with GCP Service Account binding    [MEDIUM]
#       iam.gke.io/gcp-service-account federates SA to GCP SA;
#       verify GCP IAM permissions on that account.
#
#  GKE  Pod on GKE node metadata server exposure                 [INFO]
#       Without metadata concealment, pods can reach GCE metadata endpoint
#       and obtain node service account tokens.
#
#  GKE  GCP Service Account as K8s RBAC subject                  [HIGH]
#       GCP SA email as direct RBAC subject; GCP IAM changes affect access.
#
#  GKE  Namespace with Binary Authorization excluded              [HIGH]
#       Namespace bypasses binary auth or sigstore policy; unsigned images
#       can run without verification.
#
# ── OFFLINE YAML/JSON PARSING ────────────────────────────────────────────────
#
#  Uses yq (kislyuk/yq v3.x — the jq wrapper, installed via pip install yq).
#  Strategy: convert ALL YAML/JSON files to JSON on disk first, then run
#  all analysis using pure jq against the converted JSON.
#
#  Step 1 — convert_to_json_dir:
#    • YAML files: split on --- boundaries, convert each document with "yq ."
#    • JSON files: copied as-is into the conversion temp directory
#  Step 2 — parse_json_to_ndjson:
#    • Each JSON file is parsed by jq to extract K8s resource objects
#    • Handles plain objects, JSON arrays, List kind (.items[] unwrap)
#  Step 3 — extract per-kind List files for all downstream jq checks.
#
#  Fallback: if yq is absent, .yaml/.yml are skipped; .json files only.
#
# ── ALLOWLIST / EXCEPTION ENGINE ─────────────────────────────────────────────
#
#  Suppresses known-safe RBAC for infrastructure components. Groups:
#    K8s control-plane, CNI (Calico/Cilium/Flannel/WeaveNet/OVN/Multus),
#    CSI (EBS/GCE/Azure/NFS/Rook/Longhorn/OpenEBS/TopoLVM/SMB),
#    Storage (Kadalu/Rook-Ceph/Longhorn/OpenEBS/local-path/NFS-provisioner),
#    Autoscalers (KEDA/cluster-autoscaler/VPA/Descheduler),
#    GitOps (ArgoCD all 7 SAs / Flux all 6 controllers),
#    Metrics (Prometheus stack/metrics-server/kube-state-metrics/
#             Thanos/Loki/OpenTelemetry/Datadog),
#    Logging (Fluentd/Fluent-Bit/Filebeat/Promtail/Logstash/Vector),
#    Ingress (nginx/Traefik/Contour/HAProxy/Kong/Emissary),
#    Service Mesh (Istio/Linkerd/Consul/Kuma),
#    Security tools (cert-manager/external-secrets/Vault/OPA-Gatekeeper/
#                    Kyverno/Falco/Trivy/Sealed-Secrets),
#    Cloud: AKS (aad-pod-identity/azure-policy/azure-npm/OMS/AMA/CSI/CCM),
#           EKS (aws-node/ALB/EBS-CSI/EFS-CSI/CloudWatch/ADOT),
#           GKE (config-connector/Anthos/metadata-server/Stackdriver/GMP).
#  Use --no-exceptions to audit ALL components with no suppression.
#
# =============================================================================
set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
fatal()   { error "$*"; exit 1; }

# ── Defaults ──────────────────────────────────────────────────────────────────
MODE=""
MANIFEST_DIR=""
OUTPUT_CSV="rbac_audit_$(date +%Y%m%d_%H%M%S).csv"
KUBECONFIG_PATH="${KUBECONFIG:-}"
KUBE_CONTEXT=""
CLOUD_PROVIDER="auto"   # auto | aks | eks | gke | vanilla
SKIP_EXCEPTIONS=false   # --no-exceptions disables all allowlists
EXCEPTION_CSV=""        # optional path for suppressed-findings CSV
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

# ── CSV state ─────────────────────────────────────────────────────────────────
CSV_ROWS=()
EXCEPTION_ROWS=()   # populated when --exception-report is used

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
cat <<'USAGE_EOF'
Kubernetes RBAC Security Auditor

Usage:
  k8s_rbac_audit.sh --mode online  [OPTIONS]
  k8s_rbac_audit.sh --mode offline --dir <manifest-directory> [OPTIONS]

Options:
  --mode              online | offline  (required)
  --dir               Path to directory with YAML/JSON manifests (offline mode)
  --kubeconfig        Path to kubeconfig (online mode, default: $KUBECONFIG)
  --context           Kubeconfig context (online mode)
  --cloud             auto|aks|eks|gke|vanilla  (default: auto)
  --output            CSV output filename (default: rbac_audit_<timestamp>.csv)
  --no-exceptions     Disable built-in allowlists; report ALL findings including
                      system/infra components (CNI, CSI, ArgoCD, KEDA, etc.)
  --exception-report  Path to write a second CSV of suppressed findings
  --help              Show this help

Allowlist behaviour (ON by default):
  Suppresses known-safe RBAC for K8s control-plane, CNI plugins, CSI drivers,
  storage add-ons (Kadalu/Rook/Longhorn/OpenEBS), autoscalers (KEDA/CA/VPA),
  GitOps (ArgoCD/Flux), metrics/logging, ingress, service mesh, security tools,
  and cloud add-ons (AKS/EKS/GKE platform components).

Examples:
  ./k8s_rbac_audit.sh --mode online --output report.csv
  ./k8s_rbac_audit.sh --mode online --no-exceptions --output full.csv
  ./k8s_rbac_audit.sh --mode offline --dir ./manifests \
      --output findings.csv --exception-report suppressed.csv
  ./k8s_rbac_audit.sh --mode online --cloud eks --output eks.csv
USAGE_EOF
exit 0
}

# ── Argument parsing ──────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && usage
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)              MODE="$2";            shift 2 ;;
    --dir)               MANIFEST_DIR="$2";    shift 2 ;;
    --kubeconfig)        KUBECONFIG_PATH="$2"; shift 2 ;;
    --context)           KUBE_CONTEXT="$2";    shift 2 ;;
    --cloud)             CLOUD_PROVIDER="$2";  shift 2 ;;
    --output)            OUTPUT_CSV="$2";      shift 2 ;;
    --no-exceptions)     SKIP_EXCEPTIONS=true; shift   ;;
    --exception-report)  EXCEPTION_CSV="$2";   shift 2 ;;
    --help|-h)           usage ;;
    *) fatal "Unknown argument: $1" ;;
  esac
done

[[ -z "$MODE" ]]                                   && fatal "--mode is required (online|offline)"
[[ "$MODE" == "offline" && -z "$MANIFEST_DIR" ]]   && fatal "--dir is required for offline mode"
[[ "$MODE" == "offline" && ! -d "$MANIFEST_DIR" ]] && fatal "Directory not found: $MANIFEST_DIR"

# ══════════════════════════════════════════════════════════════════════════════
# EXCEPTION / ALLOWLIST ENGINE
# ══════════════════════════════════════════════════════════════════════════════
# Each entry: "GROUP|SA_PATTERN|NS_PATTERN|ROLE_PATTERN|REASON"
# Patterns are ERE (bash =~).  Empty field = match-all (.*).
ALLOWLIST=()

build_allowlists() {
  # ── K8s Control-Plane ──────────────────────────────────────────────────────
  ALLOWLIST+=(
    "control-plane|system:kube-apiserver|kube-system|.*|K8s API Server"
    "control-plane|system:kube-scheduler|kube-system|system:kube-scheduler.*|K8s Scheduler"
    "control-plane|system:kube-controller-manager|kube-system|system:kube-controller-manager.*|K8s Controller Manager"
    "control-plane|system:node-proxier|kube-system|system:node-proxier.*|kube-proxy"
    "control-plane|kube-proxy|kube-system|system:node-proxier.*|kube-proxy SA"
    "control-plane|daemon-set-controller|kube-system|system:controller:daemon-set-controller|DaemonSet Controller"
    "control-plane|deployment-controller|kube-system|system:controller:deployment-controller|Deployment Controller"
    "control-plane|replicaset-controller|kube-system|system:controller:replicaset-controller|ReplicaSet Controller"
    "control-plane|replication-controller|kube-system|system:controller:replication-controller|RC Controller"
    "control-plane|statefulset-controller|kube-system|system:controller:statefulset-controller|StatefulSet Controller"
    "control-plane|job-controller|kube-system|system:controller:job-controller|Job Controller"
    "control-plane|cronjob-controller|kube-system|system:controller:cronjob-controller|CronJob Controller"
    "control-plane|node-controller|kube-system|system:controller:node-controller|Node Controller"
    "control-plane|endpoint-controller|kube-system|system:controller:endpoint-controller|Endpoint Controller"
    "control-plane|endpointslice-controller|kube-system|system:controller:endpointslice-controller|EndpointSlice Controller"
    "control-plane|service-controller|kube-system|system:controller:service-controller|Service Controller"
    "control-plane|service-account-controller|kube-system|system:controller:service-account-controller|SA Controller"
    "control-plane|namespace-controller|kube-system|system:controller:namespace-controller|Namespace Controller"
    "control-plane|persistent-volume-binder|kube-system|system:controller:persistent-volume-binder|PV Binder"
    "control-plane|pvc-protection-controller|kube-system|system:controller:pvc-protection-controller|PVC Protection"
    "control-plane|resourcequota-controller|kube-system|system:controller:resourcequota-controller|ResourceQuota"
    "control-plane|clusterrole-aggregation-controller|kube-system|system:controller:clusterrole-aggregation-controller|CR Aggregation"
    "control-plane|expand-controller|kube-system|system:controller:expand-controller|Volume Expand"
    "control-plane|horizontal-pod-autoscaler|kube-system|system:controller:horizontal-pod-autoscaler|HPA"
    "control-plane|certificate-controller|kube-system|system:controller:certificate-controller|Certificate"
    "control-plane|ttl-controller|kube-system|system:controller:ttl-controller|TTL Controller"
    "control-plane|generic-garbage-collector|kube-system|system:controller:generic-garbage-collector|GC"
    "control-plane|attachdetach-controller|kube-system|system:controller:attachdetach-controller|AttachDetach"
    "control-plane|disruption-controller|kube-system|system:controller:disruption-controller|PDB Controller"
    "control-plane|token-cleaner|kube-system|system:controller:token-cleaner|Token Cleaner"
    "control-plane|route-controller|kube-system|system:controller:route-controller|Route Controller"
    "control-plane|cloud-node-controller|kube-system|system:controller:cloud-node-controller|Cloud Node"
    "control-plane|cloud-provider|kube-system|system:cloud-provider|Cloud Provider"
    "control-plane|coredns|kube-system|system:coredns|CoreDNS"
    "control-plane|coredns|kube-system|.*coredns.*|CoreDNS SA"
  )

  # ── CNI Plugins ────────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "cni-calico|calico-node|kube-system|calico-node.*|Calico node daemonset"
    "cni-calico|calico-kube-controllers|kube-system|calico-kube-controllers.*|Calico controllers"
    "cni-calico|calico-cni-plugin|kube-system|calico.*|Calico CNI plugin"
    "cni-calico|.*|calico-system|calico.*|Calico (calico-system ns)"
    "cni-calico|.*|tigera-operator|tigera.*|Tigera Operator"
    "cni-cilium|cilium|kube-system|cilium.*|Cilium agent"
    "cni-cilium|cilium-operator|kube-system|cilium.*|Cilium operator"
    "cni-cilium|.*|cilium|cilium.*|Cilium (cilium ns)"
    "cni-flannel|flannel|kube-system|flannel.*|Flannel CNI"
    "cni-flannel|kube-flannel|kube-flannel|.*|Flannel (kube-flannel ns)"
    "cni-weave|weave-net|kube-system|weave-net.*|WeaveNet CNI"
    "cni-ovn|ovn-kubernetes|ovn-kubernetes|.*ovn.*|OVN-Kubernetes"
    "cni-ovn|ovn-controller|kube-system|.*ovn.*|OVN controller"
    "cni-multus|multus|kube-system|multus.*|Multus meta-CNI"
    "cni-whereabouts|whereabouts|kube-system|whereabouts.*|Whereabouts IPAM"
  )

  # ── CSI Drivers ────────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "csi|.*csi.*|kube-system|.*csi.*|CSI driver (kube-system)"
    "csi-aws-ebs|ebs-csi-controller-sa|kube-system|.*ebs.*|AWS EBS CSI controller"
    "csi-aws-ebs|ebs-csi-node-sa|kube-system|.*ebs.*|AWS EBS CSI node"
    "csi-gce-pd|csi-gce-pd-controller-sa|kube-system|.*gce-pd.*|GCE PD CSI"
    "csi-azure|csi-azuredisk-controller-sa|kube-system|.*azuredisk.*|Azure Disk CSI"
    "csi-azure|csi-azurefile-controller-sa|kube-system|.*azurefile.*|Azure File CSI"
    "csi-nfs|csi-nfs-controller-sa|kube-system|.*nfs.*|NFS CSI"
    "csi-rook|rook-csi-.*|rook-ceph|.*rook.*ceph.*|Rook-Ceph CSI"
    "csi-longhorn|longhorn-service-account|longhorn-system|.*longhorn.*|Longhorn CSI"
    "csi-openebs|openebs-cstor-csi-controller-sa|openebs|.*openebs.*|OpenEBS CSI"
    "csi-openebs|openebs-cstor-csi-node-sa|openebs|.*openebs.*|OpenEBS CSI node"
    "csi-topolvm|topolvm-controller|topolvm-system|.*topolvm.*|TopoLVM CSI"
    "csi-topolvm|topolvm-node|topolvm-system|.*topolvm.*|TopoLVM CSI node"
    "csi-smb|csi-smb-controller-sa|kube-system|.*smb.*|SMB CSI"
  )

  # ── Storage Add-ons ────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "storage-kadalu|kadalu-operator|kadalu|.*kadalu.*|Kadalu operator"
    "storage-kadalu|kadalu-csi-nodeplugin|kadalu|.*kadalu.*|Kadalu CSI node"
    "storage-kadalu|kadalu-csi-provisioner|kadalu|.*kadalu.*|Kadalu CSI provisioner"
    "storage-rook|rook-ceph-system|rook-ceph|.*rook.*|Rook-Ceph system SA"
    "storage-rook|rook-ceph-osd|rook-ceph|.*rook.*|Rook OSD"
    "storage-rook|rook-ceph-mgr|rook-ceph|.*rook.*|Rook Manager"
    "storage-rook|rook-ceph-cmd-reporter|rook-ceph|.*rook.*|Rook cmd reporter"
    "storage-longhorn|longhorn-service-account|longhorn-system|.*longhorn.*|Longhorn"
    "storage-openebs|openebs-maya-operator|openebs|.*openebs.*|OpenEBS Maya"
    "storage-local-path|local-path-provisioner-service-account|local-path-storage|.*local-path.*|Local Path Provisioner"
    "storage-nfs|nfs-client-provisioner|.*|.*nfs.*provisioner.*|NFS provisioner"
  )

  # ── Autoscalers ────────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "autoscaler-keda|keda-operator|keda|.*keda.*|KEDA operator"
    "autoscaler-keda|keda-operator-metrics-apiserver|keda|.*keda.*|KEDA metrics server"
    "autoscaler-ca|cluster-autoscaler|kube-system|.*autoscaler.*|Cluster Autoscaler"
    "autoscaler-vpa|vpa-admission-controller|kube-system|.*vpa.*|VPA Admission"
    "autoscaler-vpa|vpa-recommender|kube-system|.*vpa.*|VPA Recommender"
    "autoscaler-vpa|vpa-updater|kube-system|.*vpa.*|VPA Updater"
    "autoscaler-descheduler|descheduler|kube-system|.*descheduler.*|Descheduler"
  )

  # ── GitOps ─────────────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "gitops-argocd|argocd-application-controller|argocd|.*argocd.*|ArgoCD app controller"
    "gitops-argocd|argocd-server|argocd|.*argocd.*|ArgoCD server"
    "gitops-argocd|argocd-repo-server|argocd|.*argocd.*|ArgoCD repo server"
    "gitops-argocd|argocd-notifications-controller|argocd|.*argocd.*|ArgoCD notifications"
    "gitops-argocd|argocd-applicationset-controller|argocd|.*argocd.*|ArgoCD AppSet"
    "gitops-flux|kustomize-controller|flux-system|.*flux.*|Flux kustomize"
    "gitops-flux|helm-controller|flux-system|.*flux.*|Flux helm"
    "gitops-flux|source-controller|flux-system|.*flux.*|Flux source"
    "gitops-flux|notification-controller|flux-system|.*flux.*|Flux notification"
    "gitops-flux|image-reflector-controller|flux-system|.*flux.*|Flux image reflector"
    "gitops-flux|image-automation-controller|flux-system|.*flux.*|Flux image automation"
  )

  # ── Metrics & Observability ────────────────────────────────────────────────
  ALLOWLIST+=(
    "metrics-server|metrics-server|kube-system|system:metrics-server|metrics-server"
    "metrics-server|metrics-server|.*|.*metrics-server.*|metrics-server (any ns)"
    "metrics-ksm|kube-state-metrics|kube-system|.*kube-state-metrics.*|kube-state-metrics"
    "metrics-ksm|kube-state-metrics|monitoring|.*kube-state-metrics.*|kube-state-metrics"
    "metrics-prometheus|prometheus-k8s|monitoring|.*prometheus.*|Prometheus"
    "metrics-prometheus|prometheus-operator|.*|.*prometheus.*operator.*|Prometheus Operator"
    "metrics-prometheus|alertmanager-main|monitoring|.*alertmanager.*|Alertmanager"
    "metrics-thanos|thanos-.*|monitoring|.*thanos.*|Thanos"
    "metrics-loki|loki|logging|.*loki.*|Loki"
    "metrics-loki|loki|monitoring|.*loki.*|Loki (monitoring)"
    "metrics-otel|opentelemetry-operator|.*|.*opentelemetry.*|OpenTelemetry operator"
  )

  # ── Logging Agents ─────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "logging-fluentd|fluentd|.*|.*fluentd.*|Fluentd"
    "logging-fluentd|fluentbit|.*|.*fluentbit.*|Fluent Bit"
    "logging-fluentd|fluent-bit|logging|.*fluent.*|Fluent Bit (logging ns)"
  )

  # ── Ingress Controllers ────────────────────────────────────────────────────
  ALLOWLIST+=(
    "ingress-nginx|ingress-nginx|ingress-nginx|.*ingress.*nginx.*|NGINX Ingress"
    "ingress-traefik|traefik|traefik|.*traefik.*|Traefik Ingress"
    "ingress-contour|contour|projectcontour|.*contour.*|Contour Ingress"
    "ingress-contour|envoy|projectcontour|.*contour.*|Contour Envoy"
    "ingress-haproxy|haproxy-ingress|.*|.*haproxy.*|HAProxy Ingress"
    "ingress-kong|kong-serviceaccount|.*|.*kong.*|Kong Ingress"
    "ingress-emissary|traffic-manager|ambassador|.*emissary.*|Emissary Ingress"
  )

  # ── Service Mesh ───────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "mesh-istio|istiod|istio-system|.*istio.*|Istio control plane"
    "mesh-istio|istio-ingressgateway|istio-system|.*istio.*|Istio ingress gateway"
    "mesh-istio|istio-egressgateway|istio-system|.*istio.*|Istio egress gateway"
    "mesh-linkerd|linkerd-destination|linkerd|.*linkerd.*|Linkerd destination"
    "mesh-linkerd|linkerd-identity|linkerd|.*linkerd.*|Linkerd identity"
    "mesh-linkerd|linkerd-proxy-injector|linkerd|.*linkerd.*|Linkerd proxy injector"
    "mesh-consul|consul-connect-injector|consul|.*consul.*|Consul Connect"
    "mesh-kuma|kuma-control-plane|kuma-system|.*kuma.*|Kuma control plane"
  )

  # ── Security Tools ─────────────────────────────────────────────────────────
  ALLOWLIST+=(
    "security-certmanager|cert-manager|cert-manager|.*cert-manager.*|cert-manager controller"
    "security-certmanager|cert-manager-cainjector|cert-manager|.*cert-manager.*|cert-manager CA injector"
    "security-certmanager|cert-manager-webhook|cert-manager|.*cert-manager.*|cert-manager webhook"
    "security-external-secrets|external-secrets|external-secrets|.*external.*secrets.*|External Secrets"
    "security-vault|vault|vault|.*vault.*|Vault"
    "security-vault|vault-agent-injector|vault|.*vault.*|Vault Agent Injector"
    "security-opa|gatekeeper-admin|gatekeeper-system|.*gatekeeper.*|OPA Gatekeeper"
    "security-kyverno|kyverno-service-account|kyverno|.*kyverno.*|Kyverno"
    "security-falco|falco|falco|.*falco.*|Falco runtime security"
    "security-trivy|trivy-operator|trivy-system|.*trivy.*|Trivy Operator"
    "security-sealed-secrets|sealed-secrets-controller|kube-system|.*sealed-secrets.*|Sealed Secrets"
  )

  # ── Cloud-specific: AKS ────────────────────────────────────────────────────
  if [[ "$CLOUD_PROVIDER" == "aks" || "$CLOUD_PROVIDER" == "auto" ]]; then
    ALLOWLIST+=(
      "cloud-aks|aad-pod-identity|kube-system|.*aad-pod-identity.*|AKS AAD Pod Identity"
      "cloud-aks|nmi|kube-system|.*aad-pod-identity.*|AKS NMI"
      "cloud-aks|azure-policy|kube-system|.*azure-policy.*|AKS Azure Policy"
      "cloud-aks|azure-policy-webhook|kube-system|.*azure-policy.*|AKS Policy webhook"
      "cloud-aks|azure-npm|kube-system|.*azure-npm.*|AKS Network Policy Manager"
      "cloud-aks|konnectivity-agent|kube-system|.*konnectivity.*|AKS Konnectivity"
      "cloud-aks|omsagent|kube-system|.*omsagent.*|AKS OMS Agent"
      "cloud-aks|ama-logs|kube-system|.*ama-logs.*|AKS Azure Monitor Agent"
      "cloud-aks|azuredisk-csi-driver|kube-system|.*azuredisk.*|AKS Azure Disk CSI"
      "cloud-aks|azurefile-csi-driver|kube-system|.*azurefile.*|AKS Azure File CSI"
      "cloud-aks|cloud-node-manager|kube-system|.*cloud-node.*|AKS Cloud Node Manager"
        "cloud-aks|.*|kube-system|system:cloud-controller-manager|AKS CCM"
    )
  fi

  # ── Cloud-specific: EKS ────────────────────────────────────────────────────
  if [[ "$CLOUD_PROVIDER" == "eks" || "$CLOUD_PROVIDER" == "auto" ]]; then
    ALLOWLIST+=(
      "cloud-eks|aws-node|kube-system|aws-node.*|EKS VPC CNI (aws-node)"
      "cloud-eks|kube-proxy|kube-system|.*kube-proxy.*|EKS kube-proxy"
      "cloud-eks|aws-load-balancer-controller|kube-system|.*aws-load-balancer.*|EKS ALB controller"
          "cloud-eks|ebs-csi-controller-sa|kube-system|.*ebs.*csi.*|EKS EBS CSI controller"
      "cloud-eks|ebs-csi-node-sa|kube-system|.*ebs.*csi.*|EKS EBS CSI node"
      "cloud-eks|efs-csi-controller-sa|kube-system|.*efs.*csi.*|EKS EFS CSI controller"
      "cloud-eks|efs-csi-node-sa|kube-system|.*efs.*csi.*|EKS EFS CSI node"
      "cloud-eks|aws-privateca-issuer|.*|.*aws-pca.*|EKS ACM PCA Issuer"
      "cloud-eks|vpc-admission-webhook|kube-system|.*vpc-admission.*|EKS VPC Admission"
      "cloud-eks|amazon-cloudwatch-observability|amazon-cloudwatch|.*cloudwatch.*|EKS CloudWatch agent"
        "cloud-eks|.*|kube-system|system:cloud-controller-manager|EKS CCM"
    )
  fi

  # ── Cloud-specific: GKE ────────────────────────────────────────────────────
  if [[ "$CLOUD_PROVIDER" == "gke" || "$CLOUD_PROVIDER" == "auto" ]]; then
    ALLOWLIST+=(
      "cloud-gke|config-connector-manager|cnrm-system|.*config-connector.*|GKE Config Connector"
      "cloud-gke|cnrm-controller-manager|cnrm-system|.*cnrm.*|GKE Config Connector CM"
        "cloud-gke|gke-metadata-server|kube-system|.*metadata-server.*|GKE Metadata Server"
      "cloud-gke|anthos-connect-agent|.*|.*anthos.*|GKE Anthos Connect"
      "cloud-gke|policy-controller|.*|.*policy-controller.*|GKE Policy Controller"
      "cloud-gke|stackdriver-metadata-agent|kube-system|.*stackdriver.*|GKE Stackdriver"
      "cloud-gke|fluentbit-gke|kube-system|.*fluentbit-gke.*|GKE Fluent Bit"
      "cloud-gke|gke-managed-filestorecsi|kube-system|.*filestore.*|GKE Filestore CSI"
      "cloud-gke|pdcsi-node-sa|kube-system|.*pdcsi.*|GKE PD CSI node"
      "cloud-gke|.*|kube-system|system:cloud-controller-manager|GKE CCM"
      )
  fi

  # ── Vanilla K8s add-ons ────────────────────────────────────────────────────
  ALLOWLIST+=(
    "addon-metallb|controller|metallb-system|.*metallb.*|MetalLB controller"
    "addon-metallb|speaker|metallb-system|.*metallb.*|MetalLB speaker"
    "addon-coredns|coredns|kube-system|.*coredns.*|CoreDNS"
    "addon-dnsmasq|kube-dns|kube-system|.*dns.*|kube-dns"
    "addon-local-dns|node-local-dns|kube-system|.*node-local-dns.*|Node Local DNS"
  )
}

# ── is_excepted ───────────────────────────────────────────────────────────────
is_excepted() {
  $SKIP_EXCEPTIONS && return 1
  local sa="$1" ns="$2" role="$3"
  local _group sa_pat ns_pat role_pat _reason
  for entry in "${ALLOWLIST[@]}"; do
    IFS='|' read -r _group sa_pat ns_pat role_pat _reason <<< "$entry"
    if [[ "$sa"   =~ ^(${sa_pat:-.*})$   ]] &&
       [[ "$ns"   =~ ^(${ns_pat:-.*})$   ]] &&
       [[ "$role" =~ ^(${role_pat:-.*})$ ]]; then
      return 0
    fi
  done
  return 1
}

# ── add_finding_filtered ──────────────────────────────────────────────────────
add_finding_filtered() {
  local issue="$1"     verbs_res="$2"  role="$3"    binding="$4" \
        namespace="$5" sa="$6"         pod="$7"     svc="$8" \
        pod_ns="$9"    severity="${10}" risk_desc="${11:-}"
  local bare_role="${role##*/}"
  if is_excepted "$sa" "$namespace" "$bare_role"; then
    if [[ -n "$EXCEPTION_CSV" ]]; then
      EXCEPTION_ROWS+=("$(csv_escape "$issue"),$(csv_escape "$verbs_res"),$(csv_escape "$role"),$(csv_escape "$binding"),$(csv_escape "$namespace"),$(csv_escape "$sa"),$(csv_escape "$pod"),$(csv_escape "$svc"),$(csv_escape "$pod_ns"),$(csv_escape "$severity"),$(csv_escape "$risk_desc"),$(csv_escape "SUPPRESSED-ALLOWLIST")")
    fi
    return
  fi
  add_finding "$issue" "$verbs_res" "$role" "$binding" \
              "$namespace" "$sa" "$pod" "$svc" "$pod_ns" "$severity" "$risk_desc"
}

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
  command -v jq &>/dev/null || fatal "jq is required but not installed."
  if [[ "$MODE" == "online" ]]; then
    command -v kubectl &>/dev/null || fatal "kubectl is required for online mode."
  fi
  if [[ "$MODE" == "offline" ]]; then
    if ! command -v yq &>/dev/null; then
      warn "yq not found — YAML files will be skipped. Only .json manifests will be audited."
      warn "Install yq (kislyuk/yq):  pip install yq"
    fi
  fi
}

# ── kubectl wrapper ───────────────────────────────────────────────────────────
KC_ARGS=()
[[ -n "$KUBECONFIG_PATH" ]] && KC_ARGS+=(--kubeconfig "$KUBECONFIG_PATH")
[[ -n "$KUBE_CONTEXT"    ]] && KC_ARGS+=(--context    "$KUBE_CONTEXT")
kc() { kubectl "${KC_ARGS[@]}" "$@" 2>/dev/null; }

# ── Cloud provider auto-detection ─────────────────────────────────────────────
detect_cloud() {
  if [[ "$CLOUD_PROVIDER" != "auto" ]]; then return; fi
  local server
  server=$(kc config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null || true)
  if   echo "$server" | grep -qi "azmk8s.io\|aks";                then CLOUD_PROVIDER="aks"
  elif echo "$server" | grep -qi "eks.amazonaws.com\|eks";         then CLOUD_PROVIDER="eks"
  elif echo "$server" | grep -qi "container.googleapis.com\|gke";  then CLOUD_PROVIDER="gke"
  else
    local nodes
    nodes=$(kc get nodes -o jsonpath='{.items[*].metadata.labels}' 2>/dev/null || echo "{}")
    if   echo "$nodes" | grep -qi "eks.amazonaws.com";   then CLOUD_PROVIDER="eks"
    elif echo "$nodes" | grep -qi "cloud.google.com";    then CLOUD_PROVIDER="gke"
    elif echo "$nodes" | grep -qi "kubernetes.azure.com"; then CLOUD_PROVIDER="aks"
    else CLOUD_PROVIDER="vanilla"
    fi
  fi
  info "Detected cloud provider: ${BOLD}${CLOUD_PROVIDER}${RESET}"
}

# ── CSV helpers ───────────────────────────────────────────────────────────────
csv_escape() { local v="${1//\"/\"\"}"; echo "\"$v\""; }

add_finding() {
  local issue="$1" verbs_res="$2" role="$3" binding="$4" \
        namespace="$5" sa="$6" pod="$7" svc="$8" pod_ns="$9" severity="${10}" \
        risk_desc="${11:-}"
  CSV_ROWS+=("$(csv_escape "$issue"),$(csv_escape "$verbs_res"),$(csv_escape "$role"),$(csv_escape "$binding"),$(csv_escape "$namespace"),$(csv_escape "$sa"),$(csv_escape "$pod"),$(csv_escape "$svc"),$(csv_escape "$pod_ns"),$(csv_escape "$severity"),$(csv_escape "$risk_desc")")
}

write_csv() {
  {
    echo "Issue,Dangerous Verbs or Resources,Role or ClusterRole,Binding,Namespace,Service Account,Pod Using SA,Service Backed by Pod,Pod Namespace,Severity,Risk Description"
    for row in "${CSV_ROWS[@]+"${CSV_ROWS[@]}"}"; do echo "$row"; done
  } > "$OUTPUT_CSV"
  if [[ -n "$EXCEPTION_CSV" && ${#EXCEPTION_ROWS[@]} -gt 0 ]]; then
    {
      echo "Issue,Dangerous Verbs or Resources,Role or ClusterRole,Binding,Namespace,Service Account,Pod Using SA,Service Backed by Pod,Pod Namespace,Severity,Risk Description,Status"
      for row in "${EXCEPTION_ROWS[@]}"; do echo "$row"; done
    } > "$EXCEPTION_CSV"
  fi
}

# ── Data file paths ───────────────────────────────────────────────────────────
ROLES_JSON="$TEMP_DIR/roles.json"
CLUSTER_ROLES_JSON="$TEMP_DIR/clusterroles.json"
ROLE_BINDINGS_JSON="$TEMP_DIR/rolebindings.json"
CLUSTER_ROLE_BINDINGS_JSON="$TEMP_DIR/clusterrolebindings.json"
PODS_JSON="$TEMP_DIR/pods.json"
SERVICES_JSON="$TEMP_DIR/services.json"
NAMESPACES_JSON="$TEMP_DIR/namespaces.json"
SA_JSON="$TEMP_DIR/serviceaccounts.json"

# ── Online loader ─────────────────────────────────────────────────────────────
load_online() {
  info "Loading RBAC data from live cluster..."
  kc get roles           --all-namespaces -o json > "$ROLES_JSON"
  kc get clusterroles                     -o json > "$CLUSTER_ROLES_JSON"
  kc get rolebindings    --all-namespaces -o json > "$ROLE_BINDINGS_JSON"
  kc get clusterrolebindings              -o json > "$CLUSTER_ROLE_BINDINGS_JSON"
  kc get pods            --all-namespaces -o json > "$PODS_JSON"
  kc get services        --all-namespaces -o json > "$SERVICES_JSON"
  kc get namespaces                       -o json > "$NAMESPACES_JSON"
  kc get serviceaccounts --all-namespaces -o json > "$SA_JSON"
  success "Data loaded."
}

# ══════════════════════════════════════════════════════════════════════════════
# OFFLINE YAML/JSON PARSER
# ══════════════════════════════════════════════════════════════════════════════
#
# Strategy:
#   yq (kislyuk/yq v3.x) is a jq wrapper for YAML. It converts YAML to JSON
#   and pipes it through jq. We exploit this by using it to convert each file
#   to a JSON file on disk first, then all analysis runs pure jq against JSON.
#
#   Step 1: convert_to_json_dir — walk the manifest directory, convert every
#           .yaml/.yml file to JSON using "yq . file.yaml > file.json" and
#           copy existing .json files as-is. All JSON lands in $JSON_DIR.
#   Step 2: parse_json_to_ndjson — for each JSON file in $JSON_DIR, extract
#           individual K8s resource objects into an NDJSON stream using jq.
#           Handles: plain objects, JSON arrays, multi-doc (split by ---
#           before yq conversion), and List kind (unwraps .items[]).
#
# Fallback: if yq is absent, .yaml/.yml files are skipped and only .json
#           files in the source directory are processed by jq directly.
#
# ─────────────────────────────────────────────────────────────────────────────

YQ_AVAILABLE=false
JSON_DIR=""   # temp dir holding all converted JSON files

# ── probe_yaml_parser ─────────────────────────────────────────────────────────
probe_yaml_parser() {
  if command -v yq &>/dev/null; then
    local yq_ver
    yq_ver=$(yq --version 2>&1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    YQ_AVAILABLE=true
    info "YAML parser : yq ${yq_ver} (kislyuk/yq jq-wrapper) — converting YAML to JSON first"
  else
    YQ_AVAILABLE=false
    warn "yq not found — .yaml/.yml files will be SKIPPED."
    warn "Install: pip install yq  (kislyuk/yq, wraps jq)"
  fi
}

# ── yaml_file_to_json ─────────────────────────────────────────────────────────
# Converts a single YAML file to one or more JSON files in $JSON_DIR.
# Multi-document YAML (--- separator) is split into individual files.
# Each output file is: $JSON_DIR/<basename>_<n>.json
yaml_file_to_json() {
  local src="$1"
  local base; base=$(basename "$src" | sed 's/\.[^.]*$//')
  local idx=0

  # Split on --- boundaries, convert each document with yq
  # yq . converts YAML to JSON; null documents (empty ---) are skipped
  local doc=""
  local in_doc=false

  flush_doc() {
    if [[ -n "${doc// /}" ]]; then
      local out="$JSON_DIR/${base}_${idx}.json"
      echo "$doc" | yq . 2>/dev/null > "$out"
      # Drop empty or null-only outputs
      if [[ -s "$out" ]] && jq -e 'type == "object" or type == "array"' "$out" &>/dev/null; then
        (( idx++ )) || true
      else
        rm -f "$out"
      fi
    fi
    doc=""
  }

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == "---" ]]; then
      flush_doc
    else
      doc+="$line"$'\n'
    fi
  done < "$src"
  flush_doc
}

# ── convert_to_json_dir ───────────────────────────────────────────────────────
# Walk $MANIFEST_DIR recursively; convert all YAML files to JSON and
# copy all JSON files into $JSON_DIR. Returns counts via global vars.
CONV_TOTAL=0
CONV_OK=0
CONV_ERRORS=0

convert_to_json_dir() {
  JSON_DIR="$TEMP_DIR/json_converted"
  mkdir -p "$JSON_DIR"

  while IFS= read -r -d '' file; do
    local ext="${file##*.}"; ext="${ext,,}"
    (( CONV_TOTAL++ )) || true

    case "$ext" in
      yaml|yml)
        if $YQ_AVAILABLE; then
          if yaml_file_to_json "$file" 2>/dev/null; then
            (( CONV_OK++ )) || true
          else
            (( CONV_ERRORS++ )) || true
            warn "yq conversion failed: $(basename "$file")"
          fi
        fi
        ;;
      json)
        local dest="$JSON_DIR/$(basename "$file")"
        # Avoid collisions from files with same name in different subdirs
        [[ -e "$dest" ]] && dest="$JSON_DIR/$$.$(basename "$file")"
        cp "$file" "$dest" 2>/dev/null && (( CONV_OK++ )) || (( CONV_ERRORS++ )) || true
        ;;
    esac
  done < <(find "$MANIFEST_DIR" -follow -type f \
              \( -name "*.yaml" -o -name "*.yml" -o -name "*.json" \) \
              -print0 2>/dev/null)

  local json_count
  json_count=$(find "$JSON_DIR" -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
  info "Converted/copied ${CONV_OK}/${CONV_TOTAL} files → ${json_count} JSON file(s) in conversion dir"
  [[ $CONV_ERRORS -gt 0 ]] && warn "${CONV_ERRORS} file(s) failed conversion"
}

# ── parse_json_to_ndjson ──────────────────────────────────────────────────────
# Reads a single JSON file and emits one compact JSON object per K8s resource.
# Handles: plain object, JSON array of objects, List kind (unwraps .items[]).
parse_json_to_ndjson() {
  local file="$1"
  jq -c '
    def unwrap:
      if type == "object" then
        if .kind == "List" then
          (.items // [])[] | select(. != null and .kind != null) | unwrap
        elif .kind != null then .
        else empty
        end
      elif type == "array" then
        .[] | select(type == "object") | unwrap
      else empty
      end;
    unwrap
  ' "$file" 2>/dev/null || true
}
# ── Offline loader ────────────────────────────────────────────────────────────
load_offline() {
  info "Loading RBAC data from manifests in: $MANIFEST_DIR"
  probe_yaml_parser

  # Step 1: convert all YAML/JSON files to JSON in a temp directory
  convert_to_json_dir

  if [[ "$CONV_OK" -eq 0 ]]; then
    warn "No files could be converted. Check manifest directory and yq installation."
    for f in "$ROLES_JSON" "$CLUSTER_ROLES_JSON" "$ROLE_BINDINGS_JSON" \
              "$CLUSTER_ROLE_BINDINGS_JSON" "$PODS_JSON" "$SERVICES_JSON" \
              "$NAMESPACES_JSON" "$SA_JSON"; do
      echo '{"apiVersion":"v1","kind":"List","items":[]}' > "$f"
    done
    return
  fi

  # Step 2: parse all JSON files into a single NDJSON stream
  local all_items="$TEMP_DIR/all_items.ndjson"
  > "$all_items"

  local parsed_ok=0 parse_errors=0
  while IFS= read -r json_file; do
    local before after
    before=$(wc -l < "$all_items" 2>/dev/null || echo 0)
    parse_json_to_ndjson "$json_file" >> "$all_items" 2>/dev/null || true
    after=$(wc -l < "$all_items" 2>/dev/null || echo 0)
    if (( after > before )); then
      (( parsed_ok++ )) || true
    else
      (( parse_errors++ )) || true
    fi
  done < <(find "$JSON_DIR" -name "*.json" -type f 2>/dev/null)

  local total_docs
  total_docs=$(wc -l < "$all_items" 2>/dev/null | tr -d ' ')
  info "Extracted ${total_docs} K8s object(s) from ${parsed_ok} JSON file(s)"
  [[ $parse_errors -gt 0 ]] && warn "${parse_errors} JSON file(s) yielded no objects"

  if [[ "${total_docs:-0}" -eq 0 ]]; then
    warn "No K8s objects found. Verify manifest contents."
    for f in "$ROLES_JSON" "$CLUSTER_ROLES_JSON" "$ROLE_BINDINGS_JSON" \
              "$CLUSTER_ROLE_BINDINGS_JSON" "$PODS_JSON" "$SERVICES_JSON" \
              "$NAMESPACES_JSON" "$SA_JSON"; do
      echo '{"apiVersion":"v1","kind":"List","items":[]}' > "$f"
    done
    return
  fi

  # Step 3: slice NDJSON into per-kind List JSON files (all downstream jq runs against these)
  info "Building per-kind indices..."
  local all_as_array="$TEMP_DIR/all_items_array.json"
  jq -s '.' "$all_items" > "$all_as_array" 2>/dev/null || echo '[]' > "$all_as_array"

  extract_kind() {
    local kind="$1" outfile="$2"
    jq --arg k "$kind" \
      '[.[] | select(.kind == $k)] | {apiVersion:"v1",kind:"List",items:.}' \
      "$all_as_array" > "$outfile" 2>/dev/null \
      || echo '{"apiVersion":"v1","kind":"List","items":[]}' > "$outfile"
    local count; count=$(jq '.items | length' "$outfile" 2>/dev/null || echo 0)
    info "  ${kind}: ${count} object(s)"
  }

  extract_kind "Role"               "$ROLES_JSON"
  extract_kind "ClusterRole"        "$CLUSTER_ROLES_JSON"
  extract_kind "RoleBinding"        "$ROLE_BINDINGS_JSON"
  extract_kind "ClusterRoleBinding" "$CLUSTER_ROLE_BINDINGS_JSON"
  extract_kind "Pod"                "$PODS_JSON"
  extract_kind "Service"            "$SERVICES_JSON"
  extract_kind "Namespace"          "$NAMESPACES_JSON"
  extract_kind "ServiceAccount"     "$SA_JSON"

  rm -f "$all_items" "$all_as_array"
  success "Offline manifests loaded."
}
# ── Helper: pods using a ServiceAccount ──────────────────────────────────────
pods_for_sa() {
  local sa_name="$1" sa_namespace="$2"
  jq -r --arg sa "$sa_name" --arg ns "$sa_namespace" '
    .items[] |
    select(
      (.spec.serviceAccountName // "default") == $sa
      and (if $ns != "" then .metadata.namespace == $ns else true end)
    ) |
    "\(.metadata.name)|\(.metadata.namespace)"
  ' "$PODS_JSON" 2>/dev/null || true
}

# ── Helper: service backing a pod ────────────────────────────────────────────
service_for_pod() {
  local pod_name="$1" pod_ns="$2"
  local pod_labels
  pod_labels=$(jq -r --arg p "$pod_name" --arg n "$pod_ns" '
    .items[] | select(.metadata.name==$p and .metadata.namespace==$n)
    | .metadata.labels // {} | to_entries | map("\(.key)=\(.value)") | join(",")
  ' "$PODS_JSON" 2>/dev/null || true)
  [[ -z "$pod_labels" ]] && echo "" && return
  jq -r --arg ns "$pod_ns" --arg labels "$pod_labels" '
    .items[] | select(.metadata.namespace == $ns) |
    . as $svc |
    ($svc.spec.selector // {}) | to_entries |
    map("\(.key)=\(.value)") | join(",") as $sel |
    if $sel != "" and ($labels | contains($sel)) then $svc.metadata.name else empty end
  ' "$SERVICES_JSON" 2>/dev/null | head -1 || true
}

# ── Helper: bindings for a role ──────────────────────────────────────────────
bindings_for_role() {
  local role_name="$1" role_kind="$2"
  jq -r --arg rn "$role_name" --arg rk "$role_kind" '
    .items[] |
    select(.roleRef.name == $rn and .roleRef.kind == $rk) |
    . as $b |
    ($b.subjects // [])[] |
    select(.kind == "ServiceAccount") |
    "\(.name)|\(.namespace // $b.metadata.namespace)|\($b.metadata.name)|\($b.metadata.namespace)"
  ' "$ROLE_BINDINGS_JSON" 2>/dev/null || true

  if [[ "$role_kind" == "ClusterRole" ]]; then
    jq -r --arg rn "$role_name" '
      .items[] |
      select(.roleRef.name == $rn and .roleRef.kind == "ClusterRole") |
      . as $b |
      ($b.subjects // [])[] |
      select(.kind == "ServiceAccount") |
      "\(.name)|\(.namespace // "")|\($b.metadata.name)|cluster-wide"
    ' "$CLUSTER_ROLE_BINDINGS_JSON" 2>/dev/null || true
  fi
}

# ── emit_for_role ─────────────────────────────────────────────────────────────
emit_for_role() {
  local issue="$1" verbs_res="$2" role_name="$3" role_kind="$4" \
        role_ns="$5" severity="$6" risk_desc="${7:-}"
  local display_role="${role_kind}/${role_name}"
  local found_any=false

  while IFS='|' read -r sa_name sa_ns binding_name binding_ns; do
    [[ -z "$sa_name" ]] && continue
    found_any=true
    local effective_ns="${sa_ns:-${role_ns}}"
    local pod_found=false

    while IFS='|' read -r pod_name pod_ns; do
      [[ -z "$pod_name" ]] && continue
      local svc; svc=$(service_for_pod "$pod_name" "$pod_ns")
      add_finding_filtered "$issue" "$verbs_res" "$display_role" "$binding_name" \
        "$effective_ns" "$sa_name" "$pod_name" "${svc:-N/A}" "$pod_ns" "$severity" "$risk_desc" \
          "Elevated RBAC privilege beyond least-privilege baseline. Review binding necessity and apply minimal scope."
      pod_found=true
    done < <(pods_for_sa "$sa_name" "$effective_ns")

    if ! $pod_found; then
      add_finding_filtered "$issue" "$verbs_res" "$display_role" "$binding_name" \
        "$effective_ns" "$sa_name" "N/A" "N/A" "N/A" "$severity" "$risk_desc" \
          "Elevated RBAC privilege beyond least-privilege baseline. Review binding necessity and apply minimal scope."
    fi
  done < <(bindings_for_role "$role_name" "$role_kind")

  if ! $found_any; then
    add_finding_filtered "$issue" "$verbs_res" "$display_role" "N/A (unbound)" \
      "$role_ns" "N/A" "N/A" "N/A" "N/A" "$severity" "$risk_desc" \
        "Elevated RBAC privilege beyond least-privilege baseline. Review binding necessity and apply minimal scope."
  fi
}

# ══════════════════════════════════════════════════════════════════════════════
# CHECK FUNCTIONS  C01 – C25
# ══════════════════════════════════════════════════════════════════════════════

check_wildcard() {
  info "C01 — Wildcard verbs/resources"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.verbs // [] | contains(["*"])) or (.resources // [] | contains(["*"]))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Wildcard verb or resource in role" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL" \
        "Equivalent to cluster-admin for this resource scope: any API operation permitted. No lateral movement needed to escalate further."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_cluster_admin() {
  info "C02 — cluster-admin ClusterRole bound to ServiceAccounts"
  jq -r '
    .items[] | select(.roleRef.name == "cluster-admin") | . as $b |
    ($b.subjects // [])[] | select(.kind == "ServiceAccount") |
    "\(.name)|\(.namespace // "")|\($b.metadata.name)"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r sa_name sa_ns binding_name; do
    local effective_ns="${sa_ns:-cluster-wide}"
    local pod_found=false
    while IFS='|' read -r pod_name pod_ns; do
      local svc; svc=$(service_for_pod "$pod_name" "$pod_ns")
      add_finding_filtered "cluster-admin bound to ServiceAccount" \
        "ALL verbs on ALL resources" "ClusterRole/cluster-admin" "$binding_name" \
        "$effective_ns" "$sa_name" "$pod_name" "${svc:-N/A}" "$pod_ns" "CRITICAL" \
          "Any compromised pod using this SA has full cluster control: read all Secrets, exec into any pod, delete workloads, rewrite RBAC."
      pod_found=true
    done < <(pods_for_sa "$sa_name" "$sa_ns")
    if ! $pod_found; then
      add_finding_filtered "cluster-admin bound to ServiceAccount" \
        "ALL verbs on ALL resources" "ClusterRole/cluster-admin" "$binding_name" \
        "$effective_ns" "$sa_name" "N/A" "N/A" "N/A" "CRITICAL" \
          "Any compromised pod using this SA has full cluster control: read all Secrets, exec into any pod, delete workloads, rewrite RBAC."
    fi
  done
}

check_dangerous_verbs() {
  info "C03 — Dangerous verbs on sensitive resources"
  declare -A DC=(
    # Secrets — read OR write
    ["secrets|get,list,watch"]="CRITICAL"
    ["secrets|create,update,patch,delete"]="CRITICAL"
    ["secrets|*"]="CRITICAL"
    # Pod exec/attach/portforward
    ["pods/exec|create"]="CRITICAL"
    ["pods/attach|create"]="HIGH"
    ["pods/portforward|create"]="HIGH"
    # Ephemeral containers — same risk as exec
    ["pods/ephemeralcontainers|patch,update"]="HIGH"
    # SA token minting
    ["serviceaccounts/token|create"]="CRITICAL"
    # Nodes — broad and specific dangerous subresources
    ["nodes|*"]="HIGH"
    ["nodes/log|get,list"]="HIGH"
    ["nodes/stats|get,list"]="MEDIUM"
    # TokenReview — auth-delegation abuse / token validation bypass
    ["tokenreviews|create"]="HIGH"
    # CSR approve/sign — allows forging cluster certificates
    ["certificatesigningrequests|approve,sign"]="CRITICAL"
    # Mass delete
    ["*|deletecollection"]="HIGH"
    # PersistentVolumes
    ["persistentvolumes|create,delete,patch"]="HIGH"
    # ConfigMaps write
    ["configmaps|create,update,patch,delete"]="HIGH"
    # Workload write
    ["deployments|create,update,patch,delete"]="HIGH"
    ["daemonsets|create,update,patch,delete"]="HIGH"
    ["statefulsets|create,update,patch,delete"]="HIGH"
    ["replicasets|create,update,patch,delete"]="MEDIUM"
    ["jobs|create,update,patch,delete"]="MEDIUM"
    ["cronjobs|create,update,patch,delete"]="MEDIUM"
    # RBAC objects
    ["clusterroles|escalate,bind"]="CRITICAL"
    ["clusterrolebindings|create,update,patch,delete"]="CRITICAL"
    ["rolebindings|create,update,patch,delete"]="HIGH"
    ["roles|escalate,bind"]="HIGH"
    # Namespace isolation
    ["namespaces|create,delete"]="HIGH"
    # Admission control
    ["validatingwebhookconfigurations|create,update,patch,delete"]="CRITICAL"
    ["mutatingwebhookconfigurations|create,update,patch,delete"]="CRITICAL"
    ["networkpolicies|create,update,patch,delete"]="HIGH"
    ["podsecuritypolicies|use"]="HIGH"
    # API extension
    ["storageclasses|create,update,patch,delete"]="MEDIUM"
    ["customresourcedefinitions|create,update,patch,delete"]="HIGH"
  )
  local f='
    .items[] | . as $r | ($r.rules // [])[] | . as $rule |
    ($rule.resources // [])[] as $res | ($rule.verbs // [])[] as $verb |
    "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\($verb)|\($res)"'
  while IFS='|' read -r rn rk rns verb resource; do
    for combo in "${!DC[@]}"; do
      local cr="${combo%%|*}" cv="${combo##*|}" sev="${DC[$combo]}"
      if [[ "$resource" == "$cr" || "$resource" == "*" ]]; then
        if [[ "$cv" == "*" && "$verb" == "*" ]] || \
           echo "$cv" | tr ',' '\n' | grep -qx "$verb" || [[ "$verb" == "*" ]]; then
          emit_for_role "Dangerous verb on sensitive resource" \
            "verb=${verb} resource=${resource}" "$rn" "$rk" "$rns" "$sev" \
              "Specific dangerous capability granted. Impact: Secrets->credential theft, exec->RCE, webhooks->API interception, RBAC->self-escalation."
          break
        fi
      fi
    done
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_privilege_escalation() {
  info "C04 — Privilege escalation (bind/escalate verbs)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if (.verbs // [] | (contains(["bind"]) or contains(["escalate"]))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Privilege escalation via bind/escalate verb" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL" \
        "Holder can bind themselves to any role including cluster-admin without owning it — unrestricted privilege escalation with a single API call."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_impersonation() {
  info "C05 — Impersonation rights (impersonate verb)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if (.verbs // [] | contains(["impersonate"])) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Impersonation rights granted" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL" \
        "Holder can act as any user, group, or SA — bypasses audit trails and inherits the target identity full permission set."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_default_sa() {
  info "C06 — Non-trivial roles bound to 'default' ServiceAccount"
  jq -r '
    .items[] | . as $b | ($b.subjects // [])[] |
    select(.kind == "ServiceAccount" and .name == "default") |
    "\($b.roleRef.name)|\($b.roleRef.kind)|\(.namespace // $b.metadata.namespace)|\($b.metadata.name)"
  ' "$ROLE_BINDINGS_JSON" "$CLUSTER_ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r rn rk rns bn; do
    add_finding_filtered "'default' ServiceAccount has non-trivial role binding" \
      "Inherited from ${rk}/${rn}" "${rk}/${rn}" "$bn" "$rns" "default" "N/A" "N/A" "N/A" "HIGH" \
        "Any pod without an explicit serviceAccountName inherits this role. A single misconfigured Deployment can compromise the entire namespace."
  done
}

check_automount() {
  info "C07 — automountServiceAccountToken not disabled on pods"
  # Pod-level automount not disabled
  jq -r '
    .items[] |
    select((.spec.automountServiceAccountToken // true) == true and
           ((.spec.serviceAccountName // "default") != "")) |
    "\(.metadata.name)|\(.metadata.namespace)|\(.spec.serviceAccountName // "default")"
  ' "$PODS_JSON" 2>/dev/null | \
  while IFS='|' read -r pod pod_ns sa; do
    local svc; svc=$(service_for_pod "$pod" "$pod_ns")
    add_finding_filtered "automountServiceAccountToken not disabled on pod" \
      "Token auto-mounted into pod filesystem" \
      "N/A" "N/A" "$pod_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "MEDIUM" \
        "SA token mounted at /var/run/secrets/kubernetes.io/serviceaccount/token. Any RCE in the container exposes this token to an attacker."
  done
  # ServiceAccount-level automount not disabled (applies to all pods using this SA
  # unless the pod itself overrides it)
  jq -r '
    .items[] |
    select((.automountServiceAccountToken // true) == true) |
    "\(.metadata.name)|\(.metadata.namespace)"
  ' "$SA_JSON" 2>/dev/null | \
  while IFS='|' read -r sa sa_ns; do
    # Skip default SA — already flagged separately if it has risky bindings
    [[ "$sa" == "default" ]] && continue
    add_finding_filtered "ServiceAccount has automountServiceAccountToken not disabled" \
      "All pods using this SA auto-mount the token unless pod overrides it" \
      "N/A" "N/A" "$sa_ns" "$sa" "N/A" "N/A" "N/A" "MEDIUM" \
        "Any pod using this SA will auto-mount the token. Disabling at SA level is the defence-in-depth default; rely on pod-level override is error-prone."
  done
}

check_cross_namespace_binding() {
  info "C08 — Cross-namespace RoleBinding (SA in different namespace)"
  jq -r '
    .items[] | . as $b | ($b.subjects // [])[] |
    select(.kind == "ServiceAccount") |
    select((.namespace // $b.metadata.namespace) != $b.metadata.namespace) |
    "\(.name)|\(.namespace)|\($b.metadata.namespace)|\($b.metadata.name)|\($b.roleRef.name)|\($b.roleRef.kind)"
  ' "$ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r sa sa_ns bns bn rn rk; do
    add_finding_filtered "Cross-namespace RoleBinding (SA from different namespace)" \
      "SA ${sa_ns}/${sa} bound in namespace ${bns}" \
      "${rk}/${rn}" "$bn" "$bns" "$sa" "N/A" "N/A" "$sa_ns" "HIGH" \
        "Namespace isolation broken: compromising a pod in namespace A yields RBAC rights in namespace B, enabling multi-tenant escape."
  done
}

check_clusterrole_via_rolebinding() {
  info "C09 — Powerful ClusterRole via namespace-scoped RoleBinding"
  for cr in "cluster-admin" "admin" "edit" "system:node" "system:masters"; do
    jq -r --arg cr "$cr" '
      .items[] |
      select(.roleRef.kind == "ClusterRole" and .roleRef.name == $cr) |
      . as $b | ($b.subjects // [])[] | select(.kind == "ServiceAccount") |
      "\(.name)|\(.namespace // $b.metadata.namespace)|\($b.metadata.name)|\($b.metadata.namespace)"
    ' "$ROLE_BINDINGS_JSON" 2>/dev/null | \
    while IFS='|' read -r sa sa_ns bn bns; do
      local pod_found=false
      while IFS='|' read -r pod pod_ns; do
        local svc; svc=$(service_for_pod "$pod" "$pod_ns")
        add_finding_filtered "Powerful ClusterRole '${cr}' via namespace-scoped RoleBinding" \
          "ClusterRole=${cr}" "ClusterRole/${cr}" "$bn" \
          "$bns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "HIGH" \
            "Broad cluster permissions scoped to one namespace. Roles like admin include creating further RoleBindings — namespace takeover is one step away."
        pod_found=true
      done < <(pods_for_sa "$sa" "$sa_ns")
      if ! $pod_found; then
        add_finding_filtered "Powerful ClusterRole '${cr}' via namespace-scoped RoleBinding" \
          "ClusterRole=${cr}" "ClusterRole/${cr}" "$bn" \
          "$bns" "$sa" "N/A" "N/A" "N/A" "HIGH" \
            "Broad cluster permissions scoped to one namespace. Roles like admin include creating further RoleBindings — namespace takeover is one step away."
      fi
    done
  done
}

check_missing_namespace_in_crb() {
  info "C10 — Missing namespace on SA subject in ClusterRoleBinding"
  jq -r '
    .items[] | . as $b | ($b.subjects // [])[] |
    select(.kind == "ServiceAccount" and (.namespace == null or .namespace == "")) |
    "\($b.metadata.name)|\($b.roleRef.name)|\($b.roleRef.kind)"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r bn rn rk; do
    add_finding_filtered "ClusterRoleBinding SA subject has no namespace set" \
      "May default to unexpected namespace" \
      "${rk}/${rn}" "$bn" "cluster-wide" "N/A" "N/A" "N/A" "N/A" "MEDIUM" \
        "Kubernetes may default the SA to an unintended namespace, silently granting cluster-wide permissions to the wrong workload."
  done
}

check_secret_read() {
  info "C11 — Roles with read access to Secrets"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["secrets"]) or contains(["*"])))
        and (.verbs // [] | (contains(["get"]) or contains(["list"]) or contains(["watch"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Read access to Secrets" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "HIGH" \
        "All Secrets in scope readable: DB passwords, API keys, TLS private keys, SA tokens for other workloads. One read = full credential harvest."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_webhook_manipulation() {
  info "C12 — Write access to webhook configurations"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["validatingwebhookconfigurations"]) or contains(["mutatingwebhookconfigurations"]) or contains(["*"])))
        and (.verbs // [] | (contains(["create"]) or contains(["update"]) or contains(["patch"]) or contains(["delete"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Write access to Webhook configurations (potential interception)" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL" \
        "Holder can intercept, mutate, or reject every API request cluster-wide via a rogue webhook — silent data exfiltration or security bypass."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_crd_manipulation() {
  info "C13 — Write access to CRDs or APIServices"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["customresourcedefinitions"]) or contains(["apiservices"]) or contains(["*"])))
        and (.verbs // [] | (contains(["create"]) or contains(["update"]) or contains(["patch"]) or contains(["delete"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Write access to CRDs or APIServices (API extension attack)" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "HIGH" \
        "Holder can introduce new API endpoints or redirect existing groups to attacker-controlled servers — persistent API-level backdoors."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_node_proxy() {
  info "C14 — Access to nodes/proxy subresource"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["nodes/proxy"]) or contains(["nodes/*"]) or contains(["*"])))
        and (.verbs // [] | (contains(["get"]) or contains(["create"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|nodes/proxy"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Access to nodes/proxy (bypasses network policies)" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL" \
        "Proxying through the kubelet bypasses Kubernetes RBAC and NetworkPolicies — reach any pod on the node and read node-level credentials."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_unused_clusterroles() {
  info "C15 — Dangerous ClusterRoles that exist but are unbound"
  jq -r --argjson dv '["*","escalate","bind","impersonate"]' '
    .items[] | . as $cr |
    select(.metadata.name | startswith("system:") | not) |
    ($cr.rules // [])[] |
    if (.verbs // [] | any(. as $v | $dv[] | . == $v)) then $cr.metadata.name
    else empty end
  ' "$CLUSTER_ROLES_JSON" 2>/dev/null | sort -u | \
  while read -r rname; do
    local has_binding
    has_binding=$(jq -r --arg rn "$rname" '
      .items[] | select(.roleRef.name == $rn) | .metadata.name
    ' "$CLUSTER_ROLE_BINDINGS_JSON" "$ROLE_BINDINGS_JSON" 2>/dev/null | head -1)
    if [[ -z "$has_binding" ]]; then
      add_finding_filtered "Dangerous ClusterRole exists but is unbound (orphaned risk)" \
        "Contains wildcard/escalate/bind/impersonate verbs" \
        "ClusterRole/${rname}" "N/A (unbound)" \
        "cluster-wide" "N/A" "N/A" "N/A" "N/A" "LOW" \
          "Latent risk: one kubectl create clusterrolebinding activates it. Also signals configuration drift or forgotten privileged access."
    fi
  done
}

check_root_pods_with_token() {
  info "C16 — Pods running as root with SA token auto-mounted (pod or initContainer level)"
  jq -r '
    .items[] |
    select(
      (.spec.automountServiceAccountToken // true) == true and
      ((.spec.securityContext.runAsUser // 0) == 0 or
       (.spec.securityContext.runAsNonRoot // false) == false)
    ) |
    "\(.metadata.name)|\(.metadata.namespace)|\(.spec.serviceAccountName // "default")"
  ' "$PODS_JSON" 2>/dev/null | \
  while IFS='|' read -r pod pod_ns sa; do
    local svc; svc=$(service_for_pod "$pod" "$pod_ns")
    add_finding_filtered "Pod running as root with SA token auto-mounted" \
      "runAsRoot + automountServiceAccountToken=true" \
      "N/A" "N/A" "$pod_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "HIGH" \
        "Container breakout grants both root filesystem access and API server access via the mounted token — combined node and cluster escalation."
  done
}

check_hostpath_volumes() {
  info "C17 — Pods with hostPath volumes (potential node escape)"
  jq -r '
    .items[] | select(.spec.volumes != null) | . as $pod |
    ($pod.spec.volumes // [])[] | select(.hostPath != null) |
    "\($pod.metadata.name)|\($pod.metadata.namespace)|\($pod.spec.serviceAccountName // "default")|\(.hostPath.path)"
  ' "$PODS_JSON" 2>/dev/null | \
  while IFS='|' read -r pod pod_ns sa hp; do
    local svc; svc=$(service_for_pod "$pod" "$pod_ns")
    add_finding_filtered "Pod with hostPath volume mount (node filesystem access)" \
      "hostPath=${hp}" "N/A" "N/A" "$pod_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "HIGH" \
        "Direct node filesystem access. Paths like /etc/kubernetes expose kubeconfigs and credentials enabling node-level compromise."
  done
}

check_privileged_containers() {
  info "C18 — Privileged containers with SA token mounted (containers + initContainers + ephemeralContainers)"
  jq -r '
    .items[] | select(.spec.automountServiceAccountToken // true) | . as $pod |
    (($pod.spec.containers // []) + ($pod.spec.initContainers // []) + ($pod.spec.ephemeralContainers // []))[] |
    select(.securityContext.privileged == true) |
    "\($pod.metadata.name)|\($pod.metadata.namespace)|\($pod.spec.serviceAccountName // "default")|\(.name)"
  ' "$PODS_JSON" 2>/dev/null | \
  while IFS='|' read -r pod pod_ns sa cname; do
    local svc; svc=$(service_for_pod "$pod" "$pod_ns")
    add_finding_filtered "Privileged container with SA token mounted" \
      "container=${cname} privileged=true" \
      "N/A" "N/A" "$pod_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "CRITICAL" \
        "privileged:true disables seccomp, AppArmor, and namespace isolation. With token: kernel-level access plus full API server control."
  done
}

check_rbac_write() {
  info "C19 — Write access to RBAC objects (self-escalation risk)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["roles"]) or contains(["clusterroles"]) or contains(["rolebindings"]) or contains(["clusterrolebindings"]) or contains(["*"])))
        and (.verbs // [] | (contains(["create"]) or contains(["update"]) or contains(["patch"]) or contains(["delete"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Write access to RBAC objects (self-escalation risk)" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL" \
        "Holder can create new ClusterRoleBindings granting cluster-admin — classic privilege escalation loop requiring no other vulnerabilities."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_sa_token_secret_access() {
  info "C20 — serviceaccounts/token create permission"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["serviceaccounts/token"]) or contains(["*"])))
        and (.verbs // [] | (contains(["create"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|serviceaccounts/token"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role "Can create ServiceAccount tokens (token theft risk)" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL" \
        "Holder can mint non-expiring tokens for any SA — persistent access surviving pod restarts, SA rotation, and secret deletion."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}

check_namespace_admin_misuse() {
  info "C21 — Namespace 'admin' ClusterRole bound to ServiceAccounts"
  jq -r '
    .items[] | select(.roleRef.name == "admin" and .roleRef.kind == "ClusterRole") |
    . as $b | ($b.subjects // [])[] | select(.kind == "ServiceAccount") |
    "\(.name)|\(.namespace // $b.metadata.namespace)|\($b.metadata.name)|\($b.metadata.namespace)"
  ' "$ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r sa sa_ns bn bns; do
    local pod_found=false
    while IFS='|' read -r pod pod_ns; do
      local svc; svc=$(service_for_pod "$pod" "$pod_ns")
      add_finding_filtered "Namespace admin ClusterRole bound to ServiceAccount" \
        "ClusterRole=admin (full namespace control)" \
        "ClusterRole/admin" "$bn" "$bns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "HIGH" \
          "Full namespace admin: read all Secrets, exec into pods, create new RoleBindings, deploy arbitrary workloads."
      pod_found=true
    done < <(pods_for_sa "$sa" "$sa_ns")
    if ! $pod_found; then
      add_finding_filtered "Namespace admin ClusterRole bound to ServiceAccount" \
        "ClusterRole=admin (full namespace control)" \
        "ClusterRole/admin" "$bn" "$bns" "$sa" "N/A" "N/A" "N/A" "HIGH" \
          "Full namespace admin: read all Secrets, exec into pods, create new RoleBindings, deploy arbitrary workloads."
    fi
  done
}

check_system_masters_group() {
  info "C22 — system:masters group binding (bypasses all RBAC)"
  jq -r '
    .items[] | . as $b | ($b.subjects // [])[] |
    select(.kind == "Group" and .name == "system:masters") |
    "\($b.roleRef.name)|\($b.metadata.name)"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r rn bn; do
    add_finding_filtered \
      "system:masters group explicitly bound — bypasses all RBAC authorizers" \
      "Group=system:masters has superuser access" \
      "ClusterRole/${rn}" "$bn" \
      "cluster-wide" "N/A (system:masters group)" "N/A" "N/A" "N/A" "CRITICAL"
  done
}

check_anonymous_access() {
  info "C23 — RBAC bindings for anonymous/unauthenticated users"
  jq -r '
    .items[] | . as $b | ($b.subjects // [])[] |
    select(
      .name == "system:anonymous" or .name == "system:unauthenticated" or
      (.kind == "Group" and .name == "system:unauthenticated")
    ) |
    "\(.name)|\($b.roleRef.name)|\($b.metadata.name)"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" "$ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r subj rn bn; do
    add_finding_filtered "Anonymous/unauthenticated user has RBAC binding" \
      "Subject=${subj} (no authentication required)" \
      "ClusterRole/${rn}" "$bn" \
      "cluster-wide" "N/A (${subj})" "N/A" "N/A" "N/A" "CRITICAL" \
        "Unauthenticated HTTP requests gain these permissions. No credential needed — exploitable from any network with API server access."
  done
}

check_all_authenticated_users() {
  info "C24 — Roles bound to system:authenticated group"
  jq -r '
    .items[] | . as $b | ($b.subjects // [])[] |
    select(.kind == "Group" and .name == "system:authenticated") |
    "\($b.roleRef.name)|\($b.roleRef.kind)|\($b.metadata.name)"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" "$ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r rn rk bn; do
    add_finding_filtered "Role bound to system:authenticated (all cluster users)" \
      "Group=system:authenticated (any valid token holder)" \
      "${rk}/${rn}" "$bn" \
      "cluster-wide" "N/A (all authenticated)" "N/A" "N/A" "N/A" "HIGH" \
        "Every valid-token holder inherits these permissions. Any token compromise has cluster-wide blast radius."
  done
}

check_pod_exec_in_prod() {
  info "C25 — pods/exec create access (severity raised in prod namespaces)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["pods/exec"]) or contains(["pods/*"]) or contains(["*"])))
        and (.verbs // [] | (contains(["create"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|pods/exec"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    local sev="HIGH"
    echo "$rns" | grep -qiE "^(prod|production|staging|live|prd)" && sev="CRITICAL"
    emit_for_role "pods/exec create access (remote shell into running pods)" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "$sev" \
        "Interactive shell into any in-scope running pod. Equivalent to SSH with the pod SA token, filesystem access, and network position."
  done < <(jq -r "$f" "$ROLES_JSON" 2>/dev/null; jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null)
}


# ── C26: system:serviceaccounts group risky bindings ─────────────────────────
check_sa_group_bindings() {
  info "C26 — system:serviceaccounts group risky bindings"

  # system:serviceaccounts = ALL SAs cluster-wide
  jq -r '
    .items[] | . as $b |
    ($b.subjects // [])[] |
    select(.kind == "Group" and .name == "system:serviceaccounts") |
    "\($b.roleRef.name)|\($b.roleRef.kind)|\($b.metadata.name)|cluster-wide"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" "$ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r rn rk bn bns; do
    local sev="HIGH"
    echo "$rn" | grep -qE "^(cluster-admin|admin)$" && sev="CRITICAL"
    # Also escalate if the role contains wildcards
    jq -r --arg rn "$rn" --arg rk "$rk" '
      .items[] | select(.metadata.name == $rn and .kind == $rk) |
      (.rules // [])[] |
      if (.verbs // [] | contains(["*"])) or (.resources // [] | contains(["*"])) then
        "wildcard"
      else empty end
    ' "$CLUSTER_ROLES_JSON" "$ROLES_JSON" 2>/dev/null | grep -q "wildcard" && sev="CRITICAL"
    add_finding_filtered \
      "system:serviceaccounts group binding (ALL SAs cluster-wide inherit this role)" \
      "Group=system:serviceaccounts role=${rk}/${rn}" \
      "${rk}/${rn}" "$bn" \
      "cluster-wide" "N/A (system:serviceaccounts)" "N/A" "N/A" "N/A" "$sev" \
      "Permissions granted to EVERY service account in the cluster — current and future workloads. Single binding = blast radius of entire SA population."
  done

  # system:serviceaccounts:<ns> = all SAs in a specific namespace
  jq -r '
    .items[] | . as $b |
    ($b.subjects // [])[] |
    select(.kind == "Group" and (.name | startswith("system:serviceaccounts:"))) |
    "\($b.roleRef.name)|\($b.roleRef.kind)|\($b.metadata.name)|\($b.metadata.namespace // "cluster-wide")|\(.name)"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" "$ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r rn rk bn bns grp; do
    local sev="HIGH"
    echo "$rn" | grep -qE "^(cluster-admin|admin)$" && sev="CRITICAL"
    add_finding_filtered \
      "system:serviceaccounts:<ns> group binding (all SAs in namespace inherit this role)" \
      "Group=${grp} role=${rk}/${rn}" \
      "${rk}/${rn}" "$bn" \
      "$bns" "N/A (${grp})" "N/A" "N/A" "N/A" "$sev" \
      "Every current and future SA in the target namespace inherits this role. Compromising any pod in that namespace yields these permissions."
  done
}

# ── C27: SubjectAccessReview / SelfSubjectAccessReview permissions ────────────
check_subject_access_review() {
  info "C27 — SubjectAccessReview create permission (RBAC reconnaissance)"
  local jq_filter='
    .items[] | . as $r |
    ($r.rules // [])[] |
    if ((.resources // [] | (
          contains(["subjectaccessreviews"]) or
          contains(["selfsubjectaccessreviews"]) or
          contains(["localsubjectaccessreviews"]) or
          contains(["selfsubjectrulesreviews"]) or
          contains(["*"])
        ))
        and (.verbs // [] | (contains(["create"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end
  '
  while IFS='|' read -r rn rk rns v res; do
    # Skip built-in system:auth-delegator and similar expected roles
    echo "$rn" | grep -qE "^system:" && continue
    emit_for_role \
      "SubjectAccessReview permission granted (RBAC reconnaissance capability)" \
      "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "HIGH" \
      "Holder can query the authoriser to discover what any identity can do — reconnaissance for mapping RBAC gaps and planning privilege escalation paths."
  done < <(
    jq -r "$jq_filter" "$ROLES_JSON"         2>/dev/null
    jq -r "$jq_filter" "$CLUSTER_ROLES_JSON" 2>/dev/null
  )
}


# ── C28: Dangerous Linux capabilities ────────────────────────────────────────
check_dangerous_capabilities() {
  info "C28 — Dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, allowPrivilegeEscalation)"
  local DANGEROUS_CAPS=("SYS_ADMIN" "NET_ADMIN" "NET_RAW" "SYS_PTRACE" "SYS_MODULE" "DAC_READ_SEARCH" "DAC_OVERRIDE" "SETUID" "SETGID" "CHOWN" "FOWNER")

  jq -r '
    .items[] | . as $pod |
    (($pod.spec.containers // []) + ($pod.spec.initContainers // []) + ($pod.spec.ephemeralContainers // []))[] | . as $c |
    {
      pod: $pod.metadata.name,
      ns:  $pod.metadata.namespace,
      sa:  ($pod.spec.serviceAccountName // "default"),
      container: $c.name,
      caps: ($c.securityContext.capabilities.add // []),
      privEsc: ($c.securityContext.allowPrivilegeEscalation // true)
    } |
    if (.privEsc == true) then
      "\(.pod)|\(.ns)|\(.sa)|\(.container)|allowPrivilegeEscalation=true|MEDIUM"
    else empty end,
    if (.caps | length) > 0 then
      "\(.pod)|\(.ns)|\(.sa)|\(.container)|caps=\(.caps | join(","))|HIGH"
    else empty end
  ' "$PODS_JSON" 2>/dev/null |   while IFS='|' read -r pod pod_ns sa cname detail sev; do
    # For cap lines, check if any cap is in the dangerous list
    if echo "$detail" | grep -q "^caps="; then
      local cap_list="${detail#caps=}"
      local is_dangerous=false
      for cap in SYS_ADMIN NET_ADMIN NET_RAW SYS_PTRACE SYS_MODULE DAC_READ_SEARCH DAC_OVERRIDE SETUID SETGID CHOWN FOWNER; do
        echo "$cap_list" | grep -qw "$cap" && is_dangerous=true && break
      done
      $is_dangerous || continue
      [[ "$cap_list" == *"SYS_ADMIN"* || "$cap_list" == *"NET_ADMIN"* ]] && sev="CRITICAL"
    fi
    local svc; svc=$(service_for_pod "$pod" "$pod_ns")
    add_finding_filtered "Dangerous Linux capability or privilege escalation in container"       "container=${cname} ${detail}"       "N/A" "N/A" "$pod_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "$sev"       "SYS_ADMIN is near-equivalent to root on the node. NET_ADMIN enables ARP spoofing and traffic interception. allowPrivilegeEscalation=true lets a setuid binary gain root."
  done
}


# ── C30: TokenReview create permission (auth-delegation abuse) ────────────────
check_token_review_permission() {
  info "C30 — TokenReview create permission (auth-delegation / token validation)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["tokenreviews"]) or contains(["*"])))
        and (.verbs // [] | (contains(["create"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    echo "$rn" | grep -qE "^system:" && continue
    emit_for_role       "TokenReview create permission (token validation / auth-delegation abuse)"       "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "HIGH"       "Holder can validate arbitrary tokens against the API server, confirming which tokens are valid and what identities they represent — useful for lateral movement planning."
  done < <(
    jq -r "$f" "$ROLES_JSON"         2>/dev/null
    jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null
  )
}

# ── C31: CertificateSigningRequest approve/sign (cluster PKI compromise) ──────
check_csr_permissions() {
  info "C31 — CSR approve or sign permission (cluster PKI compromise)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["certificatesigningrequests"]) or contains(["certificatesigningrequests/approval"]) or contains(["signers"]) or contains(["*"])))
        and (.verbs // [] | (contains(["approve"]) or contains(["sign"]) or contains(["update"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    echo "$rn" | grep -qE "^system:" && continue
    emit_for_role       "CSR approve/sign permission (cluster PKI compromise)"       "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL"       "Holder can approve certificate signing requests for any identity including system:masters, forging cluster-trusted TLS certificates and bypassing RBAC entirely."
  done < <(
    jq -r "$f" "$ROLES_JSON"         2>/dev/null
    jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null
  )
}

# ── C32: Secrets write access (create/update/patch/delete) ───────────────────
check_secret_write() {
  info "C32 — Write access to Secrets (create/update/patch/delete)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if ((.resources // [] | (contains(["secrets"]) or contains(["*"])))
        and (.verbs // [] | (contains(["create"]) or contains(["update"]) or contains(["patch"]) or contains(["delete"]) or contains(["*"])))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role       "Write access to Secrets (inject or overwrite credentials)"       "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "CRITICAL"       "Holder can create or overwrite Secrets — injecting malicious credentials, replacing TLS certs with attacker-controlled ones, or poisoning SA tokens used by other workloads."
  done < <(
    jq -r "$f" "$ROLES_JSON"         2>/dev/null
    jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null
  )
}

# ── C33: deletecollection verb (mass-delete any resource) ────────────────────
check_delete_collection() {
  info "C33 — deletecollection verb (mass-delete resources)"
  local f='
    .items[] | . as $r | ($r.rules // [])[] |
    if (.verbs // [] | (contains(["deletecollection"]) or contains(["*"]))) then
      "\($r.metadata.name)|\($r.kind)|\($r.metadata.namespace // "")|\((.verbs//[]) | join(","))|\((.resources//[]) | join(","))"
    else empty end'
  while IFS='|' read -r rn rk rns v res; do
    emit_for_role       "deletecollection verb granted (mass-delete any resource type)"       "verbs=[${v}] resources=[${res}]" "$rn" "$rk" "$rns" "HIGH"       "Holder can delete all resources of a type in one API call — wipe all Pods, Secrets, ConfigMaps, or PVCs cluster-wide. Effective denial-of-service or evidence destruction."
  done < <(
    jq -r "$f" "$ROLES_JSON"         2>/dev/null
    jq -r "$f" "$CLUSTER_ROLES_JSON" 2>/dev/null
  )
}

# ══════════════════════════════════════════════════════════════════════════════
# CLOUD-SPECIFIC CHECKS
# ══════════════════════════════════════════════════════════════════════════════

check_aks() {
  info "AKS — Azure-specific RBAC checks"
  if [[ "$MODE" == "online" ]]; then
    local aad_pods
    aad_pods=$(kc get azureidentitybindings --all-namespaces -o json 2>/dev/null || echo '{"items":[]}')
    echo "$aad_pods" | jq -r '
      .items[] |
      "\(.metadata.name)|\(.metadata.namespace)|\(.spec.azureIdentityRef // "unknown")|\(.spec.selector // "all")"
    ' 2>/dev/null | \
    while IFS='|' read -r bn bns iref sel; do
      add_finding_filtered "AKS: AzureIdentityBinding may expose Azure managed identity to pods" \
        "selector=${sel} identity=${iref}" "AzureIdentity/MSI" "$bn" \
        "$bns" "N/A" "N/A" "N/A" "N/A" "HIGH" \
          "Pods can request Azure managed identity tokens. Stolen tokens grant Azure IAM permissions outside Kubernetes RBAC scope."
    done
    echo "$aad_pods" | jq -r '
      .items[] | select(.spec.selector == "" or .spec.selector == null) |
      "\(.metadata.name)|\(.metadata.namespace)"
    ' 2>/dev/null | \
    while IFS='|' read -r bn bns; do
      add_finding_filtered "AKS: AzureIdentityBinding has no pod selector (matches ALL pods)" \
        "selector=* (matches all pods in namespace)" "AzureIdentity/MSI" "$bn" \
        "$bns" "N/A" "N/A" "N/A" "N/A" "CRITICAL" \
          "Every pod in the namespace can request the managed identity token — including attacker-deployed pods. No containment boundary."
    done
    jq -r '
      .items[] | . as $b | ($b.subjects // [])[] |
      select(.kind == "Group" and (.name | startswith("system:masters") | not)) |
      "\(.name)|\($b.roleRef.name)|\($b.metadata.name)"
    ' "$CLUSTER_ROLE_BINDINGS_JSON" 2>/dev/null | \
    while IFS='|' read -r grp rn bn; do
      add_finding_filtered "AKS: AAD Group granted ClusterRoleBinding (verify group membership)" \
        "AAD Group=${grp}" "ClusterRole/${rn}" "$bn" \
        "cluster-wide" "N/A (AAD Group)" "N/A" "N/A" "N/A" "HIGH" \
          "AAD group membership managed in Azure Portal. Adding a user to the group silently grants cluster access without any kubectl change."
    done
    jq -r '
      .items[] | . as $b | ($b.subjects // [])[] |
      select(.kind == "ServiceAccount" and (.name | test("agentpool|aks-|azure-"))) |
      "\(.name)|\(.namespace // $b.metadata.namespace)|\($b.roleRef.name)|\($b.metadata.name)"
    ' "$CLUSTER_ROLE_BINDINGS_JSON" "$ROLE_BINDINGS_JSON" 2>/dev/null | \
    while IFS='|' read -r sa sa_ns rn bn; do
      add_finding_filtered "AKS: Potential AKS node MSI ServiceAccount with cluster binding" \
        "SA=${sa} may represent node managed identity" "ClusterRole/${rn}" "$bn" \
        "$sa_ns" "$sa" "N/A" "N/A" "N/A" "HIGH" \
          "SA may inherit node-level Azure IAM and Kubernetes permissions if it shares node identity naming patterns."
    done
  fi
  jq -r '
    .items[] |
    select(.metadata.annotations["azure.workload.identity/client-id"] != null or
           .metadata.annotations["azure.workload.identity/tenant-id"] != null) |
    "\(.metadata.name)|\(.metadata.namespace)|\(.metadata.annotations["azure.workload.identity/client-id"] // "unknown")"
  ' "$SA_JSON" 2>/dev/null | \
  while IFS='|' read -r sa sa_ns cid; do
    add_finding_filtered "AKS: ServiceAccount with Workload Identity annotation (verify Azure RBAC)" \
      "azure.workload.identity/client-id=${cid}" "AzureWorkloadIdentity" "N/A" \
      "$sa_ns" "$sa" "N/A" "N/A" "N/A" "MEDIUM" \
        "Federated identity: SA exchanges K8s token for cloud credentials. Verify the mapped cloud identity has least-privilege IAM roles."
  done
}

check_eks() {
  info "EKS — AWS-specific RBAC checks"
  jq -r '
    .items[] | select(.metadata.annotations["eks.amazonaws.com/role-arn"] != null) |
    "\(.metadata.name)|\(.metadata.namespace)|\(.metadata.annotations["eks.amazonaws.com/role-arn"])"
  ' "$SA_JSON" 2>/dev/null | \
  while IFS='|' read -r sa sa_ns arn; do
    local pod_found=false
    while IFS='|' read -r pod pod_ns; do
      local svc; svc=$(service_for_pod "$pod" "$pod_ns")
      add_finding_filtered "EKS: IRSA ServiceAccount with IAM Role annotation (verify IAM permissions)" \
        "eks.amazonaws.com/role-arn=${arn}" "AWS IAM Role via IRSA" "N/A" \
        "$sa_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "MEDIUM" \
          "IRSA federated identity: SA exchanges OIDC token for AWS credentials. Over-permissive IAM role enables AWS-side lateral movement."
      pod_found=true
    done < <(pods_for_sa "$sa" "$sa_ns")
    if ! $pod_found; then
      add_finding_filtered "EKS: IRSA ServiceAccount with IAM Role annotation (verify IAM permissions)" \
        "eks.amazonaws.com/role-arn=${arn}" "AWS IAM Role via IRSA" "N/A" \
        "$sa_ns" "$sa" "N/A" "N/A" "N/A" "MEDIUM" \
          "IRSA federated identity: SA exchanges OIDC token for AWS credentials. Over-permissive IAM role enables AWS-side lateral movement."
    fi
  done

  if [[ "$MODE" == "online" ]]; then
    local aws_auth
    aws_auth=$(kc get configmap aws-auth -n kube-system -o json 2>/dev/null || echo '{}')
    if [[ "$aws_auth" != "{}" ]]; then
      echo "$aws_auth" | jq -r '
        .data.mapRoles // "" | fromjson? // [] |
        .[] | select(.groups != null and (.groups | contains(["system:masters"]))) |
        "\(.rolearn // "unknown")|\(.username // "unknown")"
      ' 2>/dev/null | \
      while IFS='|' read -r rarn uname; do
        add_finding_filtered "EKS: aws-auth ConfigMap grants system:masters to IAM Role" \
          "IAM Role=${rarn} username=${uname} groups=[system:masters]" \
          "ClusterRole/cluster-admin (via aws-auth)" "aws-auth ConfigMap" \
          "kube-system" "N/A (IAM)" "N/A" "N/A" "N/A" "CRITICAL" \
            "Direct IAM Role to system:masters mapping: anyone who can assume this AWS role has unconditional cluster-admin with no K8s RBAC controls."
      done
      echo "$aws_auth" | jq -r '
        .data.mapUsers // "" | fromjson? // [] |
        .[] | select(.groups != null and (.groups | contains(["system:masters"]))) |
        "\(.userarn // "unknown")|\(.username // "unknown")"
      ' 2>/dev/null | \
      while IFS='|' read -r uarn uname; do
        add_finding_filtered "EKS: aws-auth ConfigMap grants system:masters to IAM User" \
          "IAM User=${uarn} username=${uname}" \
          "ClusterRole/cluster-admin (via aws-auth)" "aws-auth ConfigMap" \
          "kube-system" "N/A (IAM)" "N/A" "N/A" "N/A" "CRITICAL" \
            "Direct IAM User to system:masters mapping: unconditional cluster-admin with no K8s RBAC controls."
      done
    fi
    kc get nodes -o json 2>/dev/null | jq -r '
      .items[] | select(.metadata.labels["eks.amazonaws.com/nodegroup"] != null) |
      "\(.metadata.name)|\(.metadata.labels["eks.amazonaws.com/nodegroup"])"
    ' 2>/dev/null | head -5 | \
    while IFS='|' read -r node ng; do
      add_finding_filtered "EKS: Node in managed nodegroup — verify EC2 instance profile has least privilege" \
        "nodegroup=${ng}" "N/A (IAM instance profile)" "N/A" \
        "kube-system" "N/A (Node: ${node})" "N/A" "N/A" "N/A" "INFO" \
          "Over-permissive EC2 instance profile enables node-to-AWS-API lateral movement. Verify minimal IAM policies for the nodegroup."
    done
  fi

  jq -r '
    .items[] | . as $b | ($b.subjects // [])[] |
    select(.kind == "ServiceAccount" and (.name | test("aws-node|vpc-admission|eks-"))) |
    "\(.name)|\(.namespace // "kube-system")|\($b.roleRef.name)|\($b.metadata.name)"
  ' "$CLUSTER_ROLE_BINDINGS_JSON" 2>/dev/null | \
  while IFS='|' read -r sa sa_ns rn bn; do
    add_finding_filtered "EKS: AWS system component SA with ClusterRoleBinding (validate necessity)" \
      "SA=${sa} may have excessive permissions" "ClusterRole/${rn}" "$bn" \
      "$sa_ns" "$sa" "N/A" "N/A" "N/A" "MEDIUM" \
        "Broad permissions on AWS DaemonSet components can be exploited if the pod is compromised — verify necessity of each permission."
  done
}

check_gke() {
  info "GKE — Google Cloud-specific RBAC checks"
  jq -r '
    .items[] | select(.metadata.annotations["iam.gke.io/gcp-service-account"] != null) |
    "\(.metadata.name)|\(.metadata.namespace)|\(.metadata.annotations["iam.gke.io/gcp-service-account"])"
  ' "$SA_JSON" 2>/dev/null | \
  while IFS='|' read -r sa sa_ns gcp_sa; do
    local pod_found=false
    while IFS='|' read -r pod pod_ns; do
      local svc; svc=$(service_for_pod "$pod" "$pod_ns")
      add_finding_filtered "GKE: Workload Identity SA with GCP Service Account binding (verify GCP IAM)" \
        "iam.gke.io/gcp-service-account=${gcp_sa}" \
        "GCP Service Account via Workload Identity" "N/A" \
        "$sa_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "MEDIUM" \
          "Federated identity: compromised pod obtains GCP credentials and can access GCS, BigQuery, Pub/Sub beyond Kubernetes RBAC scope."
      pod_found=true
    done < <(pods_for_sa "$sa" "$sa_ns")
    if ! $pod_found; then
      add_finding_filtered "GKE: Workload Identity SA with GCP Service Account binding (verify GCP IAM)" \
        "iam.gke.io/gcp-service-account=${gcp_sa}" \
        "GCP Service Account via Workload Identity" "N/A" \
        "$sa_ns" "$sa" "N/A" "N/A" "N/A" "MEDIUM" \
          "Federated identity: compromised pod obtains GCP credentials and can access GCS, BigQuery, Pub/Sub beyond Kubernetes RBAC scope."
    fi
  done

  if [[ "$MODE" == "online" ]]; then
    jq -r '
      .items[] |
      select((.metadata.annotations["cloud.google.com/load-balancer-type"] // "") != "" or
             (.metadata.labels["cloud.google.com/gke-nodepool"] // "") != "") |
      "\(.metadata.name)|\(.metadata.namespace)|\(.spec.serviceAccountName // "default")"
    ' "$PODS_JSON" 2>/dev/null | head -10 | \
    while IFS='|' read -r pod pod_ns sa; do
      local svc; svc=$(service_for_pod "$pod" "$pod_ns")
      add_finding_filtered "GKE: Pod on GKE node — verify metadata server access is restricted" \
        "Pod may access GCE metadata endpoint (169.254.169.254)" \
        "N/A" "N/A" "$pod_ns" "$sa" "$pod" "${svc:-N/A}" "$pod_ns" "INFO" \
          "Without metadata concealment pods can query http://169.254.169.254 for the node GCP SA token, bypassing Workload Identity controls."
    done
    jq -r '
      .items[] | . as $b | ($b.subjects // [])[] |
      select(.kind == "User" and (.name | test("@.*\\.gserviceaccount\\.com"))) |
      "\(.name)|\($b.roleRef.name)|\($b.roleRef.kind)|\($b.metadata.name)"
    ' "$CLUSTER_ROLE_BINDINGS_JSON" "$ROLE_BINDINGS_JSON" 2>/dev/null | \
    while IFS='|' read -r gsa rn rk bn; do
      add_finding_filtered "GKE: GCP Service Account bound directly as K8s RBAC subject" \
        "GCP SA=${gsa} (verify GCP IAM -> K8s RBAC chain)" \
        "${rk}/${rn}" "$bn" "cluster-wide" "N/A (GCP SA)" "N/A" "N/A" "N/A" "HIGH" \
          "GCP IAM changes silently grant K8s cluster access. Audit trail is split between GCP IAM and K8s audit logs — hard to correlate."
    done
  fi

  jq -r '
    .items[] |
    select(.metadata.labels["policy.kubernetes.io/engine"] == "none" or
           .metadata.annotations["policy.sigstore.dev/exclude"] == "true") |
    "\(.metadata.name)"
  ' "$NAMESPACES_JSON" 2>/dev/null | \
  while read -r ns_name; do
    add_finding_filtered "GKE: Namespace has Binary Authorization or policy enforcement excluded" \
      "policy.kubernetes.io/engine=none or sigstore exclusion" \
      "N/A" "N/A" "$ns_name" "N/A" "N/A" "N/A" "N/A" "HIGH" \
        "Unsigned or policy-violating images can run, removing supply-chain integrity controls against tampered container images."
  done
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}   Kubernetes RBAC Security Auditor                        ${RESET}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
  echo ""

  check_deps
  build_allowlists

  if [[ "$MODE" == "online" ]]; then
    detect_cloud
    load_online
  else
    CLOUD_PROVIDER="${CLOUD_PROVIDER:-vanilla}"
    load_offline
  fi

  echo ""
  info "Running security checks..."
  echo ""

  # Core RBAC checks
  check_wildcard
  check_cluster_admin
  check_dangerous_verbs
  check_privilege_escalation
  check_impersonation
  check_default_sa
  check_automount
  check_cross_namespace_binding
  check_clusterrole_via_rolebinding
  check_missing_namespace_in_crb
  check_secret_read
  check_webhook_manipulation
  check_crd_manipulation
  check_node_proxy
  check_unused_clusterroles
  check_root_pods_with_token
  check_hostpath_volumes
  check_privileged_containers
  check_rbac_write
  check_sa_token_secret_access
  check_namespace_admin_misuse
  check_system_masters_group
  check_anonymous_access
  check_all_authenticated_users
  check_pod_exec_in_prod
  check_sa_group_bindings
  check_subject_access_review
  check_dangerous_capabilities
  check_token_review_permission
  check_csr_permissions
  check_secret_write
  check_delete_collection

  # Cloud-specific checks
  case "$CLOUD_PROVIDER" in
    aks)     check_aks ;;
    eks)     check_eks ;;
    gke)     check_gke ;;
    vanilla) info "Skipping cloud-specific checks (vanilla K8s)" ;;
    *)       check_aks; check_eks; check_gke ;;
  esac

  echo ""
  write_csv

  # Summary
  local total="${#CSV_ROWS[@]}"
  local critical=0 high=0 medium=0 low=0 info_count=0
  if [[ $total -gt 0 ]]; then
    critical=$(printf '%s\n' "${CSV_ROWS[@]}" | grep -c '"CRITICAL"' || true)
    high=$(printf '%s\n'     "${CSV_ROWS[@]}" | grep -c '"HIGH"'     || true)
    medium=$(printf '%s\n'   "${CSV_ROWS[@]}" | grep -c '"MEDIUM"'   || true)
    low=$(printf '%s\n'      "${CSV_ROWS[@]}" | grep -c '"LOW"'      || true)
    info_count=$(printf '%s\n' "${CSV_ROWS[@]}" | grep -c '"INFO"'   || true)
  fi

  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}   Audit Summary${RESET}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${RESET}"
  echo -e "  Total findings : ${BOLD}${total}${RESET}"
  echo -e "  ${RED}CRITICAL${RESET}       : ${critical}"
  echo -e "  ${YELLOW}HIGH${RESET}           : ${high}"
  echo -e "  ${CYAN}MEDIUM${RESET}         : ${medium}"
  echo -e "  LOW            : ${low}"
  echo -e "  INFO           : ${info_count}"
  echo ""
  success "Report written to: ${BOLD}${OUTPUT_CSV}${RESET}"

  if [[ -n "$EXCEPTION_CSV" ]]; then
    info "Suppressed findings : ${#EXCEPTION_ROWS[@]} (written to ${EXCEPTION_CSV})"
  elif $SKIP_EXCEPTIONS; then
    warn "All allowlists DISABLED — no findings were suppressed"
  else
    info "Suppressed by allowlist : ${#EXCEPTION_ROWS[@]} infra/system findings (use --no-exceptions to see all)"
  fi
  echo ""
}

main
