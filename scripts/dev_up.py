#!/usr/bin/env python3
"""
dev_up.py — Start LightweightAuth control plane + 1 data-plane instance for local testing.

Prerequisites:
  - Docker Desktop running
  - kind CLI installed
  - kubectl CLI installed
  - helm CLI installed

Usage:
  python scripts/dev_up.py          # Full build + deploy
  python scripts/dev_up.py --skip-build   # Skip Docker builds (use existing images)
  python scripts/dev_up.py --teardown     # Delete the Kind cluster
"""

import argparse
import subprocess
import sys
import time
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLUSTER_NAME = "lwauth-dev"
NAMESPACE = "lwauth-system"
CP_IMAGE = "lwauth-controlplane:dev"
DP_IMAGE = "lightweightauth:dev"
CP_RELEASE = "lwauth-cp"
DP_RELEASE = "lwauth-tenant-a"


def run(cmd: list[str], check=True, capture=False, **kwargs):
    """Run a subprocess command, printing it first."""
    print(f"  $ {' '.join(cmd)}")
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True, **kwargs)
        if check and result.returncode != 0:
            print(f"    FAILED (exit {result.returncode}): {result.stderr.strip()}")
            sys.exit(1)
        return result
    return subprocess.run(cmd, check=check, **kwargs)


def cluster_exists() -> bool:
    result = run(["kind", "get", "clusters"], capture=True, check=False)
    return CLUSTER_NAME in result.stdout.split()


def ensure_cluster():
    """Create Kind cluster if it doesn't exist."""
    if cluster_exists():
        print(f"✓ Kind cluster '{CLUSTER_NAME}' already exists")
        return

    print(f"→ Creating Kind cluster '{CLUSTER_NAME}'...")
    run(["kind", "create", "cluster", "--name", CLUSTER_NAME])
    run(["kubectl", "create", "namespace", NAMESPACE])


def build_images():
    """Build Docker images for control plane and data plane."""
    print("\n→ Building control plane image...")
    run(["docker", "build", "-t", CP_IMAGE, "-f", "Dockerfile.controlplane", "."], cwd=ROOT)

    print("\n→ Building data-plane image...")
    run(["docker", "build", "-t", DP_IMAGE, "-f", "Dockerfile", "."], cwd=ROOT)


def load_images():
    """Load images into Kind cluster."""
    print("\n→ Loading images into Kind...")
    run(["kind", "load", "docker-image", CP_IMAGE, "--name", CLUSTER_NAME])
    run(["kind", "load", "docker-image", DP_IMAGE, "--name", CLUSTER_NAME])


def deploy_control_plane():
    """Deploy control plane via Helm."""
    print("\n→ Deploying control plane...")
    chart = str(ROOT / "deploy" / "helm" / "lightweightauth-controlplane")
    run([
        "helm", "upgrade", "--install", CP_RELEASE, chart,
        "--namespace", NAMESPACE,
        "--create-namespace",
        "--set", "image.repository=lwauth-controlplane",
        "--set", "image.tag=dev",
        "--set", "image.pullPolicy=Never",
        "--set", "replicaCount=1",
        "--set", "leaderElection.enabled=false",
        "--set", "service.type=ClusterIP",
    ])


def deploy_data_plane():
    """Deploy one lwauth data-plane instance via Helm."""
    print("\n→ Deploying data-plane instance (tenant-a)...")
    chart = str(ROOT / "deploy" / "helm" / "lightweightauth")
    values_file = str(ROOT / "deploy" / "values-tenant-a.yaml")
    run([
        "helm", "upgrade", "--install", DP_RELEASE, chart,
        "--namespace", NAMESPACE,
        "--create-namespace",
        "-f", values_file,
    ])


def wait_for_pods():
    """Wait for all pods in namespace to be ready."""
    print("\n→ Waiting for pods to be ready...")
    for _ in range(60):
        result = run(
            ["kubectl", "get", "pods", "-n", NAMESPACE, "-o", "json"],
            capture=True, check=False,
        )
        if result.returncode != 0:
            time.sleep(2)
            continue

        pods = json.loads(result.stdout)
        items = pods.get("items", [])
        if not items:
            time.sleep(2)
            continue

        all_ready = all(
            any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in pod.get("status", {}).get("conditions", [])
            )
            for pod in items
        )
        if all_ready:
            print(f"✓ All {len(items)} pod(s) ready")
            return

        time.sleep(2)

    print("✗ Timed out waiting for pods")
    run(["kubectl", "get", "pods", "-n", NAMESPACE])
    sys.exit(1)


def setup_port_forward():
    """Start port-forward for the control plane (background process)."""
    print("\n→ Setting up port-forward (localhost:8443 → control plane)...")

    # Kill any existing port-forward on 8443 (Windows)
    kill_result = run(
        ["powershell", "-Command",
         "Get-NetTCPConnection -LocalPort 8443 -ErrorAction SilentlyContinue | "
         "ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }"],
        check=False, capture=True,
    )
    time.sleep(1)

    # Start port-forward as a background subprocess
    proc = subprocess.Popen(
        ["kubectl", "port-forward", "-n", NAMESPACE,
         f"svc/{CP_RELEASE}-lightweightauth-controlplane", "8443:8443"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(3)

    if proc.poll() is not None:
        print("  ⚠ Port-forward exited early — port may already be forwarded")
    else:
        print("  ✓ Port-forward started (pid: {})".format(proc.pid))

    return proc


def register_instance():
    """Register the data-plane instance with the control plane."""
    print("\n→ Registering tenant-a with control plane...")
    time.sleep(3)  # Give port-forward time to connect

    import urllib.request
    import urllib.error

    url = "http://localhost:8443/v1/controlplane/instances/register"
    body = json.dumps({
        "name": "lwauth-tenant-a",
        "cluster": "local",
        "adminUrl": f"http://{DP_RELEASE}.{NAMESPACE}.svc.cluster.local:8080",
    }).encode()

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")

    for attempt in range(10):
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                print(f"✓ Registered: {data.get('name')} in cluster '{data.get('cluster')}'")
                return
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            if attempt < 9:
                time.sleep(2)
            else:
                print(f"✗ Failed to register instance: {e}")


def print_status():
    """Print final status and access info."""
    print("\n" + "=" * 60)
    print("  LightweightAuth Dev Environment Ready")
    print("=" * 60)
    print(f"""
  Control Plane UI:   http://localhost:8443
  API Base:           http://localhost:8443/v1/controlplane/
  Health Check:       http://localhost:8443/healthz

  Instances:
    • lwauth-tenant-a (local cluster)

  Useful commands:
    kubectl get pods -n {NAMESPACE}
    kubectl logs -n {NAMESPACE} -l app.kubernetes.io/instance={DP_RELEASE} -f
    curl http://localhost:8443/v1/controlplane/instances
    curl http://localhost:8443/v1/controlplane/health

  To tear down:
    python scripts/dev_up.py --teardown
""")


def teardown():
    """Delete the Kind cluster."""
    print(f"→ Deleting Kind cluster '{CLUSTER_NAME}'...")
    run(["kind", "delete", "cluster", "--name", CLUSTER_NAME])
    print("✓ Cluster deleted")


def main():
    parser = argparse.ArgumentParser(description="Start LightweightAuth dev environment")
    parser.add_argument("--skip-build", action="store_true", help="Skip Docker image builds")
    parser.add_argument("--teardown", action="store_true", help="Delete the Kind cluster")
    parser.add_argument("--no-port-forward", action="store_true", help="Skip port-forward (useful in CI)")
    args = parser.parse_args()

    if args.teardown:
        teardown()
        return

    print("=" * 60)
    print("  LightweightAuth Dev Environment Setup")
    print("=" * 60)

    ensure_cluster()

    if not args.skip_build:
        build_images()

    load_images()
    deploy_control_plane()
    deploy_data_plane()
    wait_for_pods()

    if not args.no_port_forward:
        pf_proc = setup_port_forward()
        register_instance()

    print_status()

    if not args.no_port_forward:
        print("  Port-forward is running. Press Ctrl+C to stop.\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n→ Shutting down port-forward...")
            if pf_proc and pf_proc.poll() is None:
                pf_proc.terminate()


if __name__ == "__main__":
    main()
