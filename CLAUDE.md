# CLAUDE.md — Sightglass working document

The contract between sessions. Update at the end of every working session.
Keep under ~500 lines; compress old progress entries rather than letting them
sprawl.

---

## 1. Project overview

Sightglass is a self-hosted, air-gap-capable analysis platform for the binaries
a company is about to ship — installers, executables, DLLs, firmware images,
ELF binaries, embedded-device update bundles. It detonates them inside
disposable Docker sandboxes, reverse engineers them with standard open-source
tooling, and reports on secrets exposure, sensitive data leakage, and
unintended IP disclosure before the artifact reaches a customer. It fills the
gap between source-code scanning, which everyone does, and what is actually
embedded in the compiled output, which almost nobody checks.

The design premise is that the build pipeline leaks: CI environment variables
end up in strings tables, debug builds ship PDB paths exposing internal
directory trees and developer usernames, embedded vendors hardcode provisioning
credentials because the device has no other way to bootstrap, and installers
bundle config defaults with real staging tokens. The governing architectural
constraint is **deterministic spine, AI enhancement layer** (§2.5 of the
brief): every finding comes from a deterministic rule and the whole pipeline
runs usefully with the LLM disabled. The model triages, explains, and
investigates on top of that spine — it never invents a finding.

---

## 2. Current status

**Milestone: M0 — Foundation. Complete.**

What runs today, end to end, from a clean clone:

```bash
make install && make sandbox-check     # ./make.ps1 on Windows
```

- `SandboxSpec` / `SandboxDriver` / `DockerDriver` / watchdog / reaper are
  implemented, typed, and tested.
- The `sightglass/hello:dev` analyzer image builds and runs through the real
  driver inside a locked-down container.
- The isolation boundary is verified **from inside the container**: not root,
  read-only rootfs, read-only input mount, no TCP, no DNS, writable scratch and
  results.
- The watchdog kills a container that ignores SIGTERM; a memory hog is stopped
  and diagnosed as OOM rather than as a timeout.
- `docker compose` brings up Postgres, Redis, MinIO, API, two worker lanes,
  beat, and web. `/readyz` reports per-dependency health.
- CI runs lint, mypy strict, unit tests, the isolation suite, a gitleaks scan,
  the web build, and a stack-boots check.

Verified this session: 64 unit tests, 17 integration tests, `mypy --strict`
clean on `core/`, `ruff check` and `ruff format --check` clean.

Not yet started: ingestion, analyzers, correlation, rules, LLM layer,
reporting, MCP servers. The `web` dashboard is a single status page.

**Next milestone: M1 — Ingest & static core.**

---

## 3. Architecture decisions (ADR log)

Append-only. Supersede rather than edit.

### ADR-0001 — Stack is fixed by the brief (2026-08-17)
Python 3.12, FastAPI + Pydantic v2, Celery + Redis, PostgreSQL 16, MinIO, uv,
Next.js 15, Docker sandboxes.
**Rationale:** every serious binary-analysis library is Python-native or
Python-first (LIEF, pefile, pyelftools, capa, yara-python, binwalk, angr,
pyghidra). Rewriting that ecosystem elsewhere is the single biggest way to fail
this project.
**Rejected:** Go/Rust backend — would mean shelling out to Python for every
analyzer, losing type safety at exactly the boundary that matters.

### ADR-0002 — Sandbox interface before any analyzer (2026-08-17)
`SandboxDriver` was written and tested before a single analyzer existed.
**Rationale:** every analyzer will depend on this boundary, and retrofitting an
abstraction under N analyzers means rewriting all N. Podman (rootless, required
by many enterprises) and gVisor must drop in without touching analyzer code.
**Alternatives rejected:** calling docker-py directly from analyzers, "we'll
abstract it later".

### ADR-0003 — The driver removes containers; Docker `--rm` is never used (2026-08-17)
`SandboxSpec.auto_remove` means *the driver* removes the container after
collecting output. The Docker `AutoRemove` flag is explicitly set to `False`.
**Rationale:** `--rm` races log collection — the daemon can reap the container
before we read its output, producing an empty analyzer result with no error.
The reaper covers what a crash leaks.
**Rejected:** `--rm` plus a log-streaming attach, which is more moving parts
for the same guarantee.

### ADR-0004 — Seccomp is an allowlist, applied via inlined JSON (2026-08-17)
`sandbox/profiles/analyzer.json` denies by default (EPERM) and names the
permitted syscalls. The driver reads the file and passes its *contents* in
`security_opt`.
**Rationale:** a denylist silently admits every syscall a future kernel adds.
And the Docker CLI reads profile files client-side while the API expects the
JSON contents — passing a path through the API yields no profile at all, with
no error, which is the worst possible failure for a security control.
Socket syscalls are permitted because network isolation is enforced by the
netns and blocking them breaks libc and the JVM for no gain. `clone3` returns
ENOSYS rather than EPERM so glibc falls back to `clone`.
**Follow-up:** the profile is validated against every new analyzer image; Ghidra
and Wine are the likely sources of surprises.

### ADR-0005 — Tmpfs mounts carry explicit uid/gid/mode (2026-08-17)
Scratch tmpfs mounts specify `uid=10001,gid=10001,mode=0770`.
**Rationale:** found by the M0 acceptance check on its first run. A tmpfs masks
whatever the image did to the underlying directory and is created root-owned
0755, so an image that carefully chowns `/work` still yields a scratch
directory the analyzer cannot write to. It presents as a broken analyzer rather
than a broken mount, which is a bad afternoon.
**Rejected:** `mode=1777` — world-writable buys nothing in a single-user
container and reads badly in an audit.

### ADR-0006 — Windows is a first-class development environment (2026-08-17)
`make.ps1` mirrors every Makefile target.
**Rationale:** most artifacts Sightglass analyses are Windows binaries, so a
Windows dev box is not an afterthought, and GNU make is not present by default
there. The Makefile stays canonical for CI and Linux.
**Cost:** two files to keep in sync; every new target needs an entry in both.

### ADR-0007 — Run root is mounted at the same absolute path on host and worker (2026-08-17)
`${SIGHTGLASS_RUN_ROOT}:${SIGHTGLASS_RUN_ROOT}` rather than a named volume.
**Rationale:** the worker spawns analyzer containers as *siblings* through the
host Docker socket, and the daemon resolves their bind mounts on the host. A
path that exists only inside the worker yields analyzers with empty input
directories and no error at all.
**Rejected:** running the daemon inside the worker (docker-in-docker) — needs
`--privileged`, which is a far worse trade than a documented socket mount.

### ADR-0008 — Degraded analyzers return results; they do not raise (2026-08-17)
`SandboxDriver.run()` returns a `SandboxResult` with a degraded status for
timeouts, OOMs, and start failures. It raises only for an invalid spec, which
is programmer error.
**Rationale:** Ghidra will hang and OOM on real artifacts. That must cost one
degraded analyzer, not the user's whole scan. The report says which analyzers
degraded rather than silently reporting "no findings".

---

## 4. Progress log

Reverse-chronological.

### 2026-08-17 — M0 complete
**Built:** repo skeleton (§12 layout); `core/sandbox/` in full — `SandboxSpec`
with isolation guards, `SandboxDriver` ABC, `DockerDriver`, driver-agnostic
watchdog, reaper, `NotImplementedError` stubs for Podman/gVisor; seccomp
allowlist; `sightglass/hello:dev` reference analyzer doubling as an isolation
probe; FastAPI app with `/healthz` and `/readyz`; Celery app with six queues
and a beat-scheduled reaper sweep; Typer CLI (`sandbox health`,
`sandbox hello`); compose stack + dev overlay; Makefile + `make.ps1`; GitHub
Actions CI with six jobs; Next.js status page; README and this file.

**Verified:** 64 unit tests, 17 integration tests, mypy strict clean, ruff
clean. `sightglass sandbox hello` confirms the boundary from inside the
container. The watchdog kills a SIGTERM-ignoring container within its deadline.
A memory hog is stopped rather than swapping the host.

**Broke, then fixed:** the acceptance check failed on its first run —
`write_work_tmpfs` returned `PermissionError`. Docker creates tmpfs mounts
root-owned 0755 regardless of what the image did to the directory underneath.
Fixed by making ownership explicit in `TmpfsMount` (ADR-0005). This is exactly
the class of bug the from-inside probe exists to catch, and it would have been
invisible to a test that only inspected the container's declared config.

---

## 5. Next steps

Top of the queue for M1 — Ingest & static core.

1. **Data model and migrations.** SQLAlchemy models for `runs`,
   `run_manifests`, `artifacts` (self-referencing tree via `parent_id`),
   `evidence`, `findings`, `finding_locations`, `audit_log`. Alembic baseline.
   Finding IDs are content-derived from `hash(rule_id + value_hash +
   artifact_path + offset)` from the first commit — retrofitting stable IDs
   after findings exist is painful.
2. **Upload API with the attestation gate.** `POST /api/runs` taking the
   artifact plus attesting identity, timestamp, and free-text authorization
   reference. Recorded immutably in `audit_log`, carried into the run manifest.
   Reject the upload without it; this is a real gate, not a checkbox.
3. **S0 ingest + S1 identify.** Hash (SHA-256, SSDEEP, TLSH), store in MinIO,
   dedupe by hash against prior runs. Then LIEF/pefile/pyelftools parsing,
   architecture, packer/compiler ID, and build metadata — PE Rich header, Go
   build info, .NET assembly attributes, debug directory and PDB path,
   code-signing chain and expiry.
4. **S3 strings + rule scanning.** ASCII *and* UTF-16LE with offset
   preservation — Windows binaries hide half their secrets in wide strings and
   a surprising number of tools forget this. Then the YAML rule loader, a first
   detection pack (AWS keys, private keys, PDB paths), and YARA integration.
5. **Analyzer protocol.** A uniform `Analyzer` interface over the sandbox
   driver: build a spec, run, parse `/output/result.json`, emit `Evidence`
   rows. The hello analyzer becomes its first conformance test.

Then the minimal findings-list UI, closing M1's acceptance: upload a corpus
`.exe`, see a real hardcoded-key finding with correct offsets.

---

## 6. Known issues & tech debt

| Severity | Item |
| --- | --- |
| Medium | `PodmanDriver` and `GvisorDriver` raise `NotImplementedError`. Scheduled M6. Rootless Podman is a hard requirement for some enterprises. |
| Medium | `NetworkMode.SINKHOLE` raises in `DockerDriver._build_create_kwargs`. Dynamic analysis lands M5. Failing loudly is deliberate — a silent fallback to a bridge would hand an artifact real egress. |
| Medium | The seccomp allowlist has only been exercised against a slim Python image. Ghidra (JVM) and Wine are likely to need additions. Validate per image as they are built; do not weaken the profile globally in response to one failure. |
| Medium | `_active_run_ids()` in `core/orchestrator/tasks.py` returns `None` until the `runs` table exists, degrading the reaper to age-based cleanup. Wire it in M1. |
| Low | `make corpus` and `make airgap-bundle` exit 1 with a pointer to their milestone (M2, M6). |
| Low | Base image digests are pinned inline in Dockerfiles. `make refresh-digests` prints current values but does not rewrite them. |
| Low | No `docker-compose` healthcheck on the workers; a wedged worker is only visible in logs. |
| Low | The web dashboard is one status page. No shadcn/ui, TanStack Query, or SSE yet — those arrive with M1's findings list and M4's explorer. |

---

## 7. Dev environment

Requires Docker, [uv](https://docs.astral.sh/uv/), and Node 22.
Windows: use `./make.ps1 <target>` — same target names.

```bash
make install            # sync Python deps into .venv
make images             # build analyzer images
make check              # lint + mypy + unit tests; no Docker needed
make test-integration   # sandbox isolation suite; needs Docker
make sandbox-check      # M0 acceptance: probe through the real sandbox
make dev                # full stack with reload
make down / make clean  # stop / stop and delete volumes
```

Non-obvious things worth knowing:

- **`SIGHTGLASS_RUN_ROOT` must be an absolute host path.** The worker spawns
  analyzer containers as siblings via the Docker socket; the daemon resolves
  their bind mounts on the *host*. Mismatch it and analyzers silently get empty
  input directories. See ADR-0007.
- **The isolation probe is the real test.** `sightglass sandbox hello` reports
  what the container observed from the inside. Inspecting the daemon's view of
  a container's config proves nothing about whether the config took effect.
- **A single analyzer test run:**
  `uv run pytest tests/integration -k probe -v`.
- **Seccomp failures look like mysterious `EPERM`s** in an analyzer, usually
  during process start. Reproduce with `seccomp_profile=None` on the spec to
  confirm the profile is the cause before editing it.
- **Windows bind mounts** work through Docker Desktop but do not carry POSIX
  ownership, so `_make_writable()` is a no-op there and the container sees a
  permissive mount. On Linux the results directory is chowned to uid 10001.

---

## 8. Conventions

- **Commits:** Conventional Commits. Small and atomic. Feature branches; never
  commit directly to `main`.
- **Tests:** every non-trivial module gets tests in the same commit. Unit tests
  must not require Docker. Integration tests are marked `@pytest.mark.integration`
  and skip cleanly when Docker is absent.
- **Types:** `mypy --strict` on `core/`. New modules go under `core/` unless
  they are genuinely API, CLI, or reporting concerns.
- **Style:** ruff with line length 100. Comments explain *why*, especially
  where the obvious implementation is wrong (see the `--rm` and tmpfs notes).
- **Dependencies:** prefer boring and well-supported. Pin exactly. Justify every
  new one in the ADR log.
- **Placeholders raise.** Nothing is silently stubbed. A placeholder raises
  `NotImplementedError` naming its milestone, and appears in §6.
- **Determinism:** sort orders explicit everywhere. Finding IDs are
  content-derived, never sequence numbers. Parallelism must not affect output.

---

## 9. Do not do

Product guardrails, from §2 and §14 of the brief:

- **No offensive capability.** No exploit generation, no PoCs, no
  anti-anti-debug, no unpacking of commercial protectors, no license-check
  bypass, no DRM circumvention. Findings describe exposure and remediation,
  full stop. If a prompt to the LLM layer asks for any of it, the system prompt
  refuses.
- **No finding without a deterministic anchor.** The LLM may suppress, demote,
  rank, explain, and investigate. It may never create a finding, change a
  `value_hash`, offsets, or locations, or lower severity below a rule's floor
  for critical items.
- **Never require the LLM.** `--no-llm` must always produce a complete, valid,
  useful report. That is the CI default.
- **Never send candidate secret plaintext to a remote provider.** Shape,
  entropy, rule name, masked context, offsets only. Local providers may receive
  plaintext solely under a distinct, explicit opt-in.
- **Analyzers get no network, no Docker socket, no API keys.** The orchestrator
  is the only component with egress.
- **No attestation, no ingestion.** It is recorded in the audit log and printed
  in every report.
- **Never store discovered secrets in plaintext by default.** Hashed and masked
  unless plaintext retention is explicitly enabled per run, encrypted at rest,
  with a TTL and auto-purge.
- **Never commit a real credential to this repo.** Corpus fixtures use
  provably-invalid shapes (`AKIAIOSFODNN7EXAMPLE`). gitleaks runs in CI.

Engineering dead ends already explored, so they are not re-explored:

- Docker `--rm` for analyzer containers — races log collection (ADR-0003).
- Passing a seccomp *path* through the Docker API — silently applies no
  profile (ADR-0004).
- Relying on an image's `chown` for tmpfs scratch directories — the mount masks
  it (ADR-0005).
- A named volume for the run root — sibling containers resolve bind paths on
  the host (ADR-0007).
