#!/usr/bin/env python3
import sys
from kubernetes import client, config
import pandas as pd

# ---------------------------------------------------------------------------
# Cluster connection — tries local kubeconfig first, falls back to in-cluster
# service account credentials when running as a pod.
# ---------------------------------------------------------------------------
try:
    config.load_kube_config()
except Exception:
    config.load_incluster_config()

v1 = client.CoreV1Api()
rbac_v1 = client.RbacAuthorizationV1Api()

# ---------------------------------------------------------------------------
# Verbs and resources considered dangerous for RBAC evaluation.
# dangerous_resources is used inside check_rbac_rules to decide whether a
# read-verb rule is worth flagging (only secrets, or wildcard resources).
# ---------------------------------------------------------------------------
dangerous_verbs = {
    'create', 'update', 'patch', 'delete',
    'impersonate', 'escalate', 'bind',
    'get', 'list', 'watch'
}
dangerous_resources = {'secrets'}  # read verbs are only flagged for these (or wildcard)


def check_rbac_rules(rules):
    """
    Return True if any rule in the list is considered dangerous.

    Write verbs (create/update/patch/delete/impersonate/escalate/bind) are
    always dangerous regardless of resource.

    Read verbs (get/list/watch) are only dangerous when the resource is
    'secrets' or a wildcard '*'.

    These two checks are intentionally independent so that a rule carrying
    BOTH a write verb and a read verb (e.g. {create, get} on pods) is still
    correctly caught by the write-verb path.

    Guards against None fields on rule objects to avoid AttributeErrors.
    """
    write_verbs = dangerous_verbs - {'get', 'list', 'watch'}
    read_verbs  = {'get', 'list', 'watch'}

    for rule in (rules or []):
        verbs     = set(getattr(rule, "verbs",     None) or [])
        resources = set(getattr(rule, "resources", None) or [])
        is_wildcard = "*" in resources

        if not verbs:
            continue

        # Write verbs are dangerous regardless of resource
        if verbs & write_verbs:
            return True

        # Read verbs are only dangerous on secrets or wildcard resources
        if verbs & read_verbs:
            if dangerous_resources & resources or is_wildcard:
                return True

    return False


# ---------------------------------------------------------------------------
# Pre-fetch all ClusterRoleBindings once before the pod loop.
# Fetching inside the loop would cause O(n_pods) identical API calls.
# Falls back to an empty list and emits a warning on any non-404 error.
# ---------------------------------------------------------------------------
try:
    all_crbs = rbac_v1.list_cluster_role_binding().items
except client.exceptions.ApiException as e:
    print(
        f"Warning: could not list ClusterRoleBindings (status={e.status}). "
        "ClusterRoleBinding results will be empty.",
        file=sys.stderr
    )
    all_crbs = []

# ---------------------------------------------------------------------------
# Main audit loop — iterate every pod across all namespaces.
# For each pod, resolve the ServiceAccount, find all Role/ClusterRole bindings
# that reference it, collect their rules, and evaluate for dangerous permissions.
# ---------------------------------------------------------------------------
pods = v1.list_pod_for_all_namespaces().items
data = []

for pod in pods:
    pod_name  = pod.metadata.name
    namespace = pod.metadata.namespace
    sa_name   = pod.spec.service_account_name or 'default'

    roles = []  # role/clusterrole names bound to this SA
    rules = []  # accumulated policy rules from all bound roles

    # -----------------------------------------------------------------------
    # RoleBindings — namespace-scoped bindings that may reference a Role or
    # a ClusterRole (ClusterRole used within a single namespace).
    # -----------------------------------------------------------------------
    try:
        rbs = rbac_v1.list_namespaced_role_binding(namespace=namespace).items
    except client.exceptions.ApiException as e:
        if e.status != 404:
            print(
                f"Warning: could not list RoleBindings in {namespace} "
                f"(status={e.status})",
                file=sys.stderr
            )
        rbs = []

    for rb in rbs:
        for subject in (getattr(rb, "subjects", None) or []):
            if (
                getattr(subject, "kind",  None) == 'ServiceAccount'
                and getattr(subject, "name", None) == sa_name
            ):
                role_ref = getattr(rb, "role_ref", None)
                if not role_ref:
                    continue
                roles.append(role_ref.name)

                # Fetch rules from the referenced Role or ClusterRole
                if role_ref.kind == 'Role':
                    try:
                        role = rbac_v1.read_namespaced_role(role_ref.name, namespace)
                        rules.extend(role.rules or [])
                    except client.exceptions.ApiException as e:
                        if e.status != 404:
                            print(
                                f"Warning: could not read Role {role_ref.name} "
                                f"in {namespace} (status={e.status})",
                                file=sys.stderr
                            )
                elif role_ref.kind == 'ClusterRole':
                    try:
                        cluster_role = rbac_v1.read_cluster_role(role_ref.name)
                        rules.extend(cluster_role.rules or [])
                    except client.exceptions.ApiException as e:
                        if e.status != 404:
                            print(
                                f"Warning: could not read ClusterRole {role_ref.name} "
                                f"(status={e.status})",
                                file=sys.stderr
                            )

    # -----------------------------------------------------------------------
    # ClusterRoleBindings — cluster-scoped bindings; must match on namespace
    # as well as name so we don't attribute another namespace's SA permissions
    # to this pod. Uses the pre-fetched list to avoid repeated API calls.
    # -----------------------------------------------------------------------
    for crb in all_crbs:
        for subject in (getattr(crb, "subjects", None) or []):
            if (
                getattr(subject, "kind",      None) == 'ServiceAccount'
                and getattr(subject, "name",      None) == sa_name
                and getattr(subject, "namespace", None) == namespace
            ):
                role_ref = getattr(crb, "role_ref", None)
                if not role_ref:
                    continue
                roles.append(role_ref.name)

                # A CRB normally references a ClusterRole, but handle the rare
                # case of a CRB pointing to a namespaced Role gracefully.
                if role_ref.kind == 'ClusterRole':
                    try:
                        cluster_role = rbac_v1.read_cluster_role(role_ref.name)
                        rules.extend(cluster_role.rules or [])
                    except client.exceptions.ApiException as e:
                        if e.status != 404:
                            print(
                                f"Warning: could not read ClusterRole {role_ref.name} "
                                f"(status={e.status})",
                                file=sys.stderr
                            )
                elif role_ref.kind == 'Role':
                    try:
                        role = rbac_v1.read_namespaced_role(role_ref.name, namespace)
                        rules.extend(role.rules or [])
                    except client.exceptions.ApiException as e:
                        if e.status != 404:
                            print(
                                f"Warning: could not read Role {role_ref.name} "
                                f"in {namespace} (status={e.status})",
                                file=sys.stderr
                            )

    # Evaluate all accumulated rules for dangerous permissions
    rbac_issue = check_rbac_rules(rules)

    data.append({
        'Pod':               pod_name,
        'Namespace':         namespace,
        'ServiceAccount':    sa_name,
        'Roles/ClusterRoles': ','.join(roles),
        'RBAC Issue':        rbac_issue
    })

# ---------------------------------------------------------------------------
# Write results to CSV
# ---------------------------------------------------------------------------
df = pd.DataFrame(data)
df.to_csv('k8s_rbac_audit.csv', index=False)
print(f"RBAC audit report saved to k8s_rbac_audit.csv (rows={len(df)})")
