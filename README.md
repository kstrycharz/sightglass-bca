# Sightglass

**Scan the artifacts you are about to ship.**

Everyone scans their source code. Almost nobody looks at the binary that comes
out the other end — and the build pipeline leaks. CI environment variables get
baked into strings tables. Debug builds ship PDB paths that expose internal
directory trees, developer usernames, and unreleased project codenames.
Embedded vendors hardcode provisioning credentials and update-server API keys
because the device has no other way to bootstrap. An installer bundles a
`config.default.json` with a real staging token in it.

Sightglass takes the installers, executables, firmware images, and update
bundles you are about to release, unpacks them inside disposable sandboxes,
reverse engineers them with standard open-source tooling, and reports on
**secrets exposure, sensitive data leakage, and unintended IP disclosure**
before the artifact reaches a customer.

It is self-hosted and air-gap capable. Your artifacts do not leave your network.

---

## What it is not

Sightglass is a pre-release supply-chain hygiene tool. It is **not** a malware
analysis platform, a competitor-teardown tool, or an exploit development
environment.

- It optimises for finding secrets in *cooperative* artifacts — the ones you
  built. It does not defeat commercial protectors, bypass license checks, or
  circumvent DRM.
- It never produces exploits or weaponised output. Findings describe exposure
  and remediation.
- Every upload requires an authorization attestation: you own the artifact, or
  you are contractually authorized to test it. That attestation is recorded in
  the audit log and stamped into every report.

See [SECURITY.md](SECURITY.md) for the third-party-artifact (due diligence)
case.

## Deterministic spine, AI enhancement layer

This is the design constraint everything else defers to.

**Every finding is produced by a deterministic rule.** Same artifact, same rule
pack, same tool versions ⇒ byte-identical findings, enforced by a CI test that
runs the corpus twice and diffs the output. Every run records a manifest —
artifact hash, rule-pack hash, analyzer image digests, tool versions — and the
report prints it. Finding IDs are content-derived, so they are stable across
re-runs and comparable across releases.

**The whole pipeline runs with `--no-llm` and still produces a complete,
useful report.** That is the CI default. If your model is down, your release
gate still works.

**The LLM sits strictly on top.** It triages (collapsing the false positives
that make binary secret scanning unusable), explains, suggests remediation, and
can run a bounded, fully-cited deep investigation. It cannot invent a finding
that no rule anchored, and it cannot change a finding's severity, offsets, or
locations. The UI attributes every AI-derived field and has a
"deterministic view only" toggle. You can always answer *"would this finding
exist without the AI?"*

Bring your own model: Ollama and vLLM locally, or OpenAI, Anthropic, Google,
Azure, and Bedrock. Egress is denied by default and enforced at the HTTP-client
layer, not by convention.

## Status

**Milestone M0 — foundation.** The sandbox boundary, the deployment stack, and
CI. Artifact ingestion and static scanning land in M1.

What works today:

```bash
./make.ps1 sandbox-check     # Windows
make sandbox-check           # Linux/macOS
```

That builds the reference analyzer image, runs it through the real driver in a
locked-down container, and asserts — from *inside* the container — that the
rootfs is read-only, the input mount is read-only, there is no network, and the
process is not root.

See [CLAUDE.md](CLAUDE.md) for current status, the architecture decision log,
and what is next.

## Quick start

Requires Docker, [uv](https://docs.astral.sh/uv/), and Node 22.

```bash
cp .env.example .env
```

`SIGHTGLASS_RUN_ROOT` **must be an absolute host path** — the worker spawns
analyzer containers as siblings through the Docker socket, and the daemon
resolves their bind mounts on the host. See the comment at the top of
[docker-compose.yml](docker-compose.yml).

```bash
make install      # Python dependencies
make images       # analyzer images
make dev          # the full stack: Postgres, Redis, MinIO, API, workers, web
```

Then open <http://localhost:3000> for the dashboard and
<http://localhost:8000/docs> for the API.

Verification:

```bash
make check              # lint, type-check, unit tests — no Docker needed
make test-integration   # sandbox isolation tests — needs Docker
```

On Windows, substitute `./make.ps1 <target>` for `make <target>`; the targets
are identical.

## Architecture

```
upload ──▶ API ──▶ orchestrator ──▶ one disposable container per analyzer
                                     unpack │ static │ ghidra │ dynamic
                                              │
                                    normalized evidence
                                              │
                                        correlator  ── dedupe, entropy, scoring
                                              │
                                     LLM layer (optional, advisory)
                                              │
                                    PDF · HTML · SARIF · CycloneDX · JSON
```

Analyzer containers never touch the network, never see the Docker socket, and
never hold provider API keys. The orchestrator is the only component with
egress, and it sends only redacted, size-bounded evidence.

Full detail in [ARCHITECTURE.md](ARCHITECTURE.md) and
[THREAT_MODEL.md](THREAT_MODEL.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [CLAUDE.md](CLAUDE.md) | Current status, ADR log, progress, next steps |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, pipeline stages, data model |
| [SECURITY.md](SECURITY.md) | Reporting vulnerabilities, responsible use |
| [THREAT_MODEL.md](THREAT_MODEL.md) | What the sandbox defends against, and what it does not |

## Licence

Apache-2.0.
