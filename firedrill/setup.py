"""Write the Firedrill descriptor and local plan for Guardian on this machine.

    python3 firedrill/setup.py          -> firedrill/local/descriptor.json and firedrill/local/plan.json

Both are machine-specific (the plan names this checkout's real path and its directory identity), so they
are written to firedrill/local/, which git ignores. Rerun after moving the checkout or changing
agent/drill.py. The descriptor digest is computed by the installed Firedrill CLI's own code, so it always
matches what `firedrill register` and `firedrill run` compute.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUT = os.path.join(ROOT, "firedrill", "local")

# Synthetic services Guardian uses, the variable each address goes in, and the operations it may call.
DEPENDENCIES = [
    ("gmail", "GUARDIAN_GMAIL_URL", ["messages.list", "messages.get", "messages.modify", "labels.list", "labels.create"]),
    ("stripe", "GUARDIAN_STRIPE_URL", ["charges.list"]),
    ("slack", "GUARDIAN_SLACK_URL", ["conversations.list", "chat.postMessage"]),
]


def root_identity(path):
    """firedrill.root-identity.v1: sha256 of the prefix, the real path, NUL, and <device>:<inode>."""
    st = os.stat(path)
    h = hashlib.sha256(b"firedrill.root-identity.v1\0" + path.encode() + b"\0")
    h.update(("%d:%d" % (st.st_dev, st.st_ino)).encode())
    return h.hexdigest()


def file_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def descriptor(identity):
    return {
        "schema": "firedrill.local-descriptor.v1",
        "source_roots": [{"alias": "guardian", "identity_sha256": identity}],
        "services": [{"alias": "guardian", "root_alias": "guardian", "role": "agent", "depends_on": [],
                      "configuration": [{"name": env, "phase": "runtime", "secret": False, "required": True}
                                        for _, env, _ in DEPENDENCIES]
                      + [{"name": "GUARDIAN_FAMILY_CHANNEL", "phase": "runtime", "secret": False, "required": False}]}],
        "entry_service": "guardian",
        "driver": {"profile": "jsonl-process.v1", "adapter_sha256": file_sha256(os.path.join(ROOT, "agent", "drill.py")),
                   "authentication": "anonymous", "state_domains": ["proc"]},
        # Guardian keeps its store, runs and outbox in a temp folder per process, so a new process is a clean slate.
        "state_domains": [{"alias": "proc", "service_alias": "guardian", "kind": "process", "location": "local",
                           "reset": "fresh-process", "concurrency": "independent", "hook_sha256": None}],
        "dependencies": [{"alias": alias, "service_alias": "guardian", "protocol": "http", "mode": "synthetic",
                          "operations": ops} for alias, _, ops in DEPENDENCIES],
    }


def descriptor_digest(path):
    """Ask the installed CLI's canonical.js for the digest, so it can never drift from Firedrill's own."""
    npm_root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True, check=True).stdout.strip()
    canonical = os.path.join(npm_root, "firedrill-run", "dist", "cli", "src", "native", "canonical.js")
    script = ("import {normalizeDescriptor} from %s; import {readFileSync} from 'node:fs';"
              "process.stdout.write(normalizeDescriptor(JSON.parse(readFileSync(%s,'utf8'))).descriptor_sha256)"
              % (json.dumps("file://" + canonical), json.dumps(path)))
    return subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True,
                          check=True).stdout.strip()


def plan(identity, digest):
    python = shutil.which("python3") or sys.executable
    return {
        "version": 1,
        "descriptor_sha256": digest,
        "roots": [{"alias": "guardian", "path": ROOT, "identity_sha256": identity}],
        "services": [{
            "alias": "guardian", "root_alias": "guardian", "mode": "launch",
            "command": {"executable": os.path.realpath(python), "args": ["-I", "agent/drill.py"]},
            "cwd": ".", "env_passthrough": [], "env_static": {"GUARDIAN_FAMILY_CHANNEL": "family"},
            "readiness": {"kind": "stdout", "pattern": "guardian-drill-ready"}, "readiness_timeout_ms": 30000,
            "stop_timeout_ms": 5000, "per_drill": True, "port_env": None,
            "dependency_env": [{"alias": alias, "name": env, "url": "invoke"} for alias, env, _ in DEPENDENCIES],
        }],
        "driver": {"profile": "jsonl-process.v1", "service_alias": "guardian"},
        "state_hooks": [],
        "max_parallel_drills": 1,
    }


def main():
    os.makedirs(OUT, exist_ok=True)
    identity = root_identity(ROOT)
    d_path = os.path.join(OUT, "descriptor.json")
    with open(d_path, "w") as f:
        json.dump(descriptor(identity), f, indent=2)
    digest = descriptor_digest(d_path)
    with open(os.path.join(OUT, "plan.json"), "w") as f:
        json.dump(plan(identity, digest), f, indent=2)
    print("wrote %s and plan.json (descriptor %s)" % (d_path, digest[:12]))


if __name__ == "__main__":
    main()
