# CLAUDE.md — Sightglass working document

The contract between sessions. Update at the end of every working session.
Keep under ~500 lines; compress old progress entries rather than letting them
sprawl. The ADR log lives in [docs/ADR.md](docs/ADR.md) because it is
append-only and would otherwise consume this budget on its own.

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

**Milestone: M1 — Ingest & static core. Complete. Plus an early slice of M3
(the Ollama provider and triage) and the M4 release gate, both pulled forward
so the product is usable in a pipeline.**

Working end to end today: upload an artifact through the dashboard or the CLI,
it is scanned in a locked-down container, and deterministic findings appear
with offsets, encoding, and remediation. Optional AI triage classifies them.
A release policy turns those findings into a ship / do-not-ship decision with
a meaningful exit code, so Sightglass is a build-pipeline stage gate and not
only a dashboard.

```bash
make images && make corpus && make dev
uv run python scripts/demo.py

# as a release gate
uv run sightglass policy init
uv run sightglass scan dist/installer.exe --sarif sightglass.sarif
```

See [docs/CICD.md](docs/CICD.md) for the pipeline integration design and
working workflows for GitHub Actions, GitLab, Azure DevOps, and Jenkins.

See [docs/SETUP.md](docs/SETUP.md) for the full walkthrough.

**Previously: M0 — Foundation. Complete.**

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

Verified: 269 unit tests, 19 integration tests, `mypy --strict` clean on
`core/`, `ruff` clean, the frontend builds.

Not yet started: Ghidra and dynamic analysis (M5), PDF/CycloneDX reporting
(M4), cloud LLM adapters (M3), MCP servers (M5), API authentication.

**Next milestone: M4 — reporting (PDF, CycloneDX) on top of the SARIF and
gate work already landed.**

---

## 3. Architecture decisions

The full log, with rationale and rejected alternatives, is in [docs/ADR.md](docs/ADR.md).
Append-only; supersede rather than edit.

- **ADR-0001** — Stack is fixed by the brief (2026-08-17)
- **ADR-0002** — Sandbox interface before any analyzer (2026-08-17)
- **ADR-0003** — The driver removes containers; Docker `--rm` is never used (2026-08-17)
- **ADR-0004** — Seccomp is an allowlist, applied via inlined JSON (2026-08-17)
- **ADR-0005** — Tmpfs mounts carry explicit uid/gid/mode (2026-08-17)
- **ADR-0006** — Windows is a first-class development environment (2026-08-17)
- **ADR-0007** — Run root is mounted at the same absolute path on host and worker (2026-08-17)
- **ADR-0008** — Degraded analyzers return results; they do not raise (2026-08-17)
- **ADR-0009** — The driver translates host paths; it does not require identical mounts (2026-08-17)
- **ADR-0010** — Findings use a composite primary key (id, run_id) (2026-08-17)
- **ADR-0011** — The detection engine has no heavy dependencies (2026-08-17)
- **ADR-0012** — Triage cannot dismiss a finding at or above high severity (2026-08-17)
- **ADR-0013** — The dashboard proxies the API at runtime, not via a rewrite (2026-08-17)
- **ADR-0014** — Durations are measured with a monotonic clock (2026-08-17)
- **ADR-0015** — The release gate is a product surface, not a script (2026-08-18)
- **ADR-0016** — The gate fails on what the build introduced, not what it inherited (2026-08-18)
- **ADR-0017** — A model may not open the release gate (2026-08-18)
- **ADR-0018** — An incomplete scan is INCONCLUSIVE, never a pass (2026-08-18)
- **ADR-0019** — The policy travels to the server; findings do not travel to CI (2026-08-18)
- **ADR-0020** — click is pinned below 8.2 (2026-08-18)
- **ADR-0021** — Rules carry an explicit exclusion list, not negative lookaheads (2026-08-19)
- **ADR-0022** — The static analyzer parallelises inside one container (2026-08-19)
- **ADR-0023** — The API authenticates by default, with two scopes (2026-08-24)
- **ADR-0024** — Schema changes ship as migrations; start-up refuses a stale schema (2026-08-25)
- **ADR-0025** — A run is claimed with a conditional UPDATE, committed immediately (2026-08-25)
- **ADR-0026** — Response models are constructed, not validated from ORM objects (2026-08-25)

---

## 4. Progress log

Reverse-chronological.

### 2026-08-25 — migrations; a failed analyzer can no longer look clean
**The failure that set the agenda.** Adding a `components` column to
`RunManifest` and redeploying broke the stack: `create_all()` reported success
because the *table* existed, and it is structurally blind to a missing
*column*. Every run read returned 500, and a 213 MB scan died at the manifest
write with the artifact already uploaded, unpacked and scanned. No test could
have caught it — every test builds its schema from the current models, so the
two agree by construction. Only a pre-existing database disagrees.

**Built:** Alembic, properly (ADR-0024). `alembic.ini`, an `env.py` that
borrows the application's own connection so the migrated schema is necessarily
the one the process will query, a `0001_baseline` describing the schema as it
stood *before* migrations existed, and `0002_manifest_components`.
`upgrade_schema()` handles all three states a deployment can be in — empty,
created by the old bootstrap (stamped at the baseline, then upgraded), or
already at head. `create_all()` is now tests-only, and a failed migration
aborts the boot instead of logging a warning and serving anyway.

**Verified against the live populated database**, not a scratch one: the API
container stamped `0001_baseline`, applied `0002`, logged `api.schema_current`,
and all 18 existing manifests survived. That is the adoption path every
existing deployment will take, exercised once, for real.

**Then the same scan found a worse bug.** The static analyzer exited 1 in 0.97s
— the image had never been given `core/composition/` — and the run recorded
`status=completed, findings=0`. A clean bill of health for a 213 MB installer
nobody had looked inside. The **gate caught it** and returned INCONCLUSIVE with
"static (failed) did not finish", exit 3, exactly as ADR-0018 requires; the
control worked. But the run, the API and the dashboard all said *completed*,
and only the gate disagreed.

Fixed by making the run status honest: `RunStatus.DEGRADED`, set from the
stages themselves. "Which stages are degraded" now has one definition in
`core/pipeline/stages.py` that both the run status and the gate read, because
deriving that answer twice is what let them diverge.

**Also fixed:** a read that stalls after the response headers arrive raises a
bare `TimeoutError`, which is not a `URLError` and matched no handler — so a
build agent got a forty-line Python traceback instead of a sentence and an exit
code. Both `urlopen` call sites now name the remedy (`--timeout`).

**Then two more, both caught by running the scan rather than by reading it.**

*A run being scanned looked abandoned.* The whole scan runs in one transaction,
so the RUNNING transition was flushed but never committed — for eight minutes
every other connection read the run as `queued`, including the orphan sweep,
whose grace period is five. It requeued a run at `age_s=399` while its original
task was still inside the static analyzer, and a second `scan_run` was
dispatched for the same 213 MB artifact. Watched it happen live. The transition
is now committed, and the claim is a conditional UPDATE rather than a
read-then-write, because Celery is at-least-once and a duplicate delivery must
lose the race rather than join it.

*The run detail endpoint took 58 seconds.* `ArtifactOut.children` and
`Artifact.children` share a name, so `model_validate` on an ORM object made
Pydantic read the relationship and lazy-load each node's entire subtree from
the database — recursively, per node, and discarded on the next line. The
endpoint the CLI polls every 20 seconds. Building the node field by field, and
capping the tree at 500 nodes (68 976 artifacts is not a thing a browser
renders), took it to **0.096s**.

**Verified end to end on the NVIDIA AI Workbench installer** (213 MB, 68 976
artifacts): both stages completed, 45 findings, run detail in 0.096s, a
CycloneDX 1.5 SBOM with **1 003 components** — 811 npm and 192 Go modules read
from `Go buildinfo` — 705 carrying a declared licence, and a PDF release record.
Four of those 1 003 declared `./LICENSE.md` as their licence; a path is not an
SPDX expression, and a licence field a tool cannot evaluate is worse than an
absent one, so file pointers are now dropped.

**Verified:** 473 unit tests (29 new), mypy strict, ruff clean, `tsc` clean.
The migration tests assert the thing that actually failed — that every column
the ORM will select exists after migrating — rather than that the migration ran.


### 2026-08-24 — API authentication; `sightglass gate`
**Built:** `core/auth.py` (token minting, hashing, scope rules — stdlib only,
no database); the `api_tokens` table; `core/pipeline/tokens.py` for the
lifecycle; `api/deps.py` with the `get_caller` / `require_scope` dependencies;
`sightglass token create|list|revoke`; startup bootstrap that mints and prints
a first admin token so secure-by-default does not brick a fresh stack. The
dashboard authenticates as itself through the proxy route, server-side, and the
proxy now strips any `Authorization` the browser sends so a page script cannot
smuggle its own.

**Also built:** `sightglass gate <run-id>` — re-evaluate a stored run under a
different policy without re-uploading. The verdict was always a separate call
for exactly this (ADR-0015); only the CLI verb was missing. `scan` and `gate`
share one output path so they cannot disagree about a verdict.

**Verified:** 372 unit tests (83 new), mypy strict, ruff clean. The enforcement
tests enumerate every protected route and assert 401 for anonymous and 403 for
a `ci` token on the corpus — the failure this feature actually has is "we wrote
an auth module and forgot to attach it to a router", and only a per-route
assertion catches that.

**Broke, then fixed:** `parse_bearer("Bearer ")` returned the literal string
`"Bearer"` as the presented credential, which then failed verification and
landed in the audit log as though somebody had tried it as a token; the
"already revoked" error was unreachable because the lookup filtered to active
tokens first. Both found by the tests, both trivial, both the kind of thing
that makes an audit trail lie. Enabling auth also broke the nine gate API
tests, which is the control working — they now mint and present a real
CI-scoped token, which makes them more realistic than they were.

**Verified over real HTTP.** Docker Desktop would not start this session, so
instead of settling for TestClient the API was run under uvicorn against
SQLite and driven with curl and the real CLI: bootstrap banner on first start,
`/healthz` open, 401 for anonymous and for an unknown token on every `/api`
route, 200 for the admin token, 200 for a CI token on `/api/runs` and
`/api/runs/{id}/sarif`, **403** for that same CI token on `/findings` and
`/settings` with a message naming the scope it lacked, the `X-Sightglass-Token`
fallback header, revocation taking effect immediately, and the audit log
holding the whole sequence.

**That run found the bug worth finding.** `ensure_bootstrap_token` was logging
the full plaintext token into the *structured* log as well as the console
banner — shipping a live admin credential to whatever aggregates those logs,
where it is indexed and retained. The banner is the intended one-time
disclosure; the log line now carries only the prefix, and two tests assert no
minting path ever puts a plaintext token into logging output. Exactly the
class of leak this product exists to find in other people's artifacts.

**Then Docker came back and the compose path was verified too.** The bootstrap
banner appears in `docker compose logs api` exactly as documented; a CI token
submits and gates but gets 403 on `/findings` and `/settings`; the dashboard
proxy returns 401 with no token wired and 200 once `SIGHTGLASS_TOKEN` is set,
and discards a browser-supplied `Authorization` rather than forwarding it. A
full gated scan ran with a CI token, and `sightglass gate` re-evaluated that
run under a stricter `mode: all` policy — exit 1, five violations, no
re-upload. No plaintext token appears anywhere in the service logs.

**And it found a second real bug.** `docker compose exec api sightglass token
create ...` — the documented way to bootstrap credentials, in both
`docs/CICD.md` and `.env.example` — failed with "executable file not found in
$PATH". `deploy/Dockerfile.backend` installs what `pyproject.toml` *requires*
but never the project itself, so the console script it declares never existed;
`PYTHONPATH=/app` is why the API ran anyway and why nothing caught it. Fixed
with a shim on PATH rather than `pip install .`, which would put a second copy
of the source in site-packages and make "which one is running?" a question.

**Housekeeping:** the ADR log moved to [docs/ADR.md](docs/ADR.md). It is
append-only by design and had grown to 320 lines, pushing this file to 709 —
40% past its own stated limit, with no amount of progress-entry compression
able to fix it. Nothing was edited in the move; §3 keeps a one-line index.

### 2026-08-19 — validated through the real stack; analyzer parallelised
**Ran the whole thing for real,** which the previous session had not: compose
stack healthy, artifacts uploaded through the API, scanned in the sandbox,
gated by the CLI. The M0 isolation probe still passes from inside the container.

**The gate works end to end.** A real ripgrep release gives PASS, exit 0. A
planted binary with fabricated credentials gives BLOCKED, exit 1, five
violations, with the public GitHub URL correctly excluded. SARIF 2.1.0
validates, byte offsets are present, fingerprints match the gate's finding ids,
and no plaintext reaches the file.

**The data is verified against the bytes.** ripgrep findings at offsets
3072616, 3200336, 3200488 each land exactly on a
`C:\Users\runneradmin\.cargo\registry\...` path — a release build carrying the
CI runner's account name. 91 distinct values collapse into one finding with 91
locations. The in-process field harness and the sandboxed pipeline agree rule
for rule (27 findings on the PowerShell tree), validating both.

**Found by running it:** the API container was serving an image built before
`api/routers/gate.py` existed, so every `POST .../gate` returned 404 while the
scan itself succeeded — invisible to any test, obvious on first deploy.

**Performance.** Profiling contradicted the obvious assumption: container
spinup is ~0.5s across two containers, ~1s of a 35s job. The cost was a
sequential per-file loop. Now parallel (ADR-0022): 35.4s to 13.1s at 4 CPUs,
10.7s at 8, byte-identical output. Recon's extraction is split too (9.0s to
2.2s) while its rarity sweep stays central.

**Also confirmed:** pointing `SIGHTGLASS_RUN_ROOT` at a Windows path without
`SIGHTGLASS_RUN_ROOT_HOST` gives the analyzer an empty `/input`. It exits 2
with "no artifacts found" rather than reporting a clean scan — the right
failure.


### 2026-08-19 — detection fixes from the field corpus
**Built:** `scripts/field_test.py`, which runs the production components
in-process (`Extractor` → `scan_file` → `correlate` → gate `evaluate`) over a
directory of real artifacts and reports findings, verdicts, throughput and a
rule-by-hit table for false-positive triage.

**Corpus:** 7 released artifacts, 105 MB downloaded / 349 MB scanned after
unpacking — Tari 5.6.0 (Rust/Win), PowerShell 7.6.5 (.NET), syncthing 2.1.3
(Go), gh 2.97.0 (MSI), ripgrep, fd, jq.

**What it caught that review had not.** Two of seven were **blocked**, both on
`scm-url` at high, and both were false positives: `git://github.com/dotnet/
runtime` from .NET `RepositoryUrl` metadata, and a public GitHub API URL from a
Go binary. A public forge is not internal-infrastructure disclosure, and a gate
that blocks ordinary clean software on it is one a team switches off. Fixed via
ADR-0021 with the observed strings as negative fixtures. `private-ip-address`
also matched `10.00.000.0` — `\d{1,3}` accepts non-octets; now validated.
A positive control (fabricated but structurally valid credentials in a
synthetic PE) still yields 3 critical, 3 high and BLOCKED, so the narrowing did
not hollow the rules out.

**Also fixed:** `.sightglass/` was in `.gitignore`, contradicting ADR-0019 —
the policy is a committed, reviewed artifact whose git history is the audit
trail.

### 2026-08-18 — the release gate: Sightglass as a CI/CD stage gate
**Built:** `core/policy/`, a dependency-light deterministic gate engine
(severity floor, blocked rules/categories, budgets, baseline comparison,
expiring waivers, degraded posture) with a shared wire codec;
`core/pipeline/gate.py`, the ORM bridge and baseline resolver; `POST
/api/runs/{id}/gate` and `GET /api/runs/{id}/sarif`; `reporting/sarif.py`
(SARIF 2.1.0, `security-severity`, stable `partialFingerprints`, masked values
only); `sightglass scan` and `sightglass policy init|validate|explain`; a
stdlib-only streaming API client so a build agent needs no dependency tree;
text/JSON/Markdown renderers with GitHub job-summary output; `docs/CICD.md` and
workflows for GitHub Actions, GitLab, Azure DevOps, and Jenkins.

**Verified:** 269 unit tests (104 new), mypy strict, ruff clean. Tested at four
levels because each hides the others' failures: the engine alone, the ORM
bridge against a real schema in SQLite, the endpoints through the real FastAPI
app, and the CLI end to end over real HTTP against a stub server.

**The three decisions that make it adoptable** are ADR-0016 (fail on what the
build introduced), ADR-0017 (a model may not open the gate), and ADR-0018 (an
incomplete scan is INCONCLUSIVE, never a pass).

**Broke, then fixed:** every `--help` in the CLI died on
`make_metavar() missing 1 required positional argument` — click 8.4.2 against
typer 0.15.1, predating these commands and surviving because the commands
themselves run (→ pinned, ADR-0020); the gate joined `finding_locations` to
`artifacts` for a path that the location already denormalises, so the join was
both wrong and unnecessary (caught by the SQLite test, exactly what a mocked
session hides); the API tests all failed "no such table" because each session
opened its own in-memory SQLite (→ `StaticPool`, and the lifespan is skipped in
tests where it was dialling a real Postgres).

### 2026-08-17 — M0 and M1 complete, plus the Ollama slice of M3
**M0 built:** `core/sandbox/` in full — `SandboxSpec`, the `SandboxDriver` ABC,
`DockerDriver`, watchdog, reaper, Podman/gVisor stubs; the seccomp allowlist;
the `sightglass/hello:dev` probe; FastAPI health probes; Celery with six
queues; the compose stack; Makefile + `make.ps1`; CI with six jobs.

**M1 built:** the SQLAlchemy schema; ingest with the attestation gate;
content-addressed MinIO storage; the detection engine (`core/rules/`) with
ASCII + UTF-16LE extraction, entropy and masking, a 17-rule seed pack and a
44-entry false-positive corpus; the `sightglass/static` analyzer image; the
correlator; the scan pipeline and Celery tasks; the REST API; the Next.js
dashboard; the Ollama provider with egress enforcement; LLM triage with the
severity floor.

**Verified:** 102 unit tests, 17 integration tests, mypy strict, ruff clean.
Upload → sandboxed scan → 9 findings from 10 evidence rows → triage on
qwen2.5-coder:14b in 21.4s; three of the nine were UTF-16LE only. The severity
floor was *demonstrated*: the model called a shipped private key a false
positive and was overruled into `needs_review` (ADR-0012).

**Broke, then fixed:** a tmpfs mount is created root-owned 0755 and masks
whatever the image did underneath, so the very first acceptance run failed
(ADR-0005) — the class of bug the from-inside probe exists to catch;
`Finding.id` as a sole primary key died on any re-scan (→ composite key,
ADR-0010); a false-positive corpus entry silently disabled a critical rule by
matching its structural marker rather than a credential value; `core.rules`
transitively imported SQLAlchemy, which would have forced an ORM into the
analyzer image (→ `core/vocab.py`, ADR-0011).

---

## 5. Next steps

The gate is landed but not yet deployable to a hostile network, and that is the
gap that matters most.

1. **API authentication.** `sightglass scan --token` already sends a bearer
   token; nothing verifies it. Until it does, the deployment must sit inside a
   perimeter — and a release gate that anyone on the network can query, or
   whose verdict anyone can request, is not a control. Highest priority.
2. **Gate the gate in this repo's own CI.** Sightglass should scan its own
   built artifacts on every release tag. Dogfooding is the fastest way to find
   out which parts of `docs/CICD.md` are wrong.
3. **A `sightglass gate` subcommand** for re-evaluating an existing run under a
   changed policy without re-uploading. The API supports it (that is why the
   verdict is a separate call from the scan, ADR-0015); only the CLI verb is
   missing.
4. **Waiver ergonomics.** The CI output prints finding ids; there is no
   `sightglass waive <id> --reason ... --expires ...` to append a well-formed
   entry. Hand-editing YAML under time pressure is where waivers acquire
   missing owners and absent expiries.
5. **M4 reporting proper.** PDF for the release record and CycloneDX for the
   SBOM story. SARIF is done and is what feeds code scanning.

Then: the run-comparison view in the dashboard, which is the same baseline
computation the gate already does, surfaced for a human rather than a pipeline.

---

## 6. Known issues & tech debt

| Severity | Item |
| --- | --- |
| Medium | `PodmanDriver` and `GvisorDriver` raise `NotImplementedError`. Scheduled M6. Rootless Podman is a hard requirement for some enterprises. |
| Medium | `NetworkMode.SINKHOLE` raises in `DockerDriver._build_create_kwargs`. Dynamic analysis lands M5. Failing loudly is deliberate — a silent fallback to a bridge would hand an artifact real egress. |
| Medium | The seccomp allowlist has only been exercised against a slim Python image. Ghidra (JVM) and Wine are likely to need additions. Validate per image as they are built; do not weaken the profile globally in response to one failure. |
| Medium | `_active_run_ids()` in `core/orchestrator/tasks.py` returns `None` until the `runs` table exists, degrading the reaper to age-based cleanup. Wire it in M1. |
| Medium | The artifact tree in the run detail response is capped at 500 nodes. The count stays exact and every artifact is still scanned, but there is no way to page through the rest — a real explorer needs its own paginated endpoint. |
| Low | `ManifestOut` exposes neither `recon` nor `components`; both are reachable only through their own endpoints. Fine for now, surprising if you read the schema. |
| Low | `make corpus` and `make airgap-bundle` exit 1 with a pointer to their milestone (M2, M6). |
| Low | Base image digests are pinned inline in Dockerfiles. `make refresh-digests` prints current values but does not rewrite them. |
| Low | No `docker-compose` healthcheck on the workers; a wedged worker is only visible in logs. |
| Medium | Go binaries store strings in one contiguous blob with no separators, so the printable-run extractor merges adjacent unrelated strings and a regex can match across the seam. Observed: `…per_page=30reflect:` and `dllsecur32.dllshell32.dlluserenv.dlltime`. Affects every rule on Go artifacts; needs a Go-aware string splitter, not a per-rule fix. |
| Medium | `internal-hostname` matches Go package paths — `eq.internal`, `hash.internal`, `x509.local` — because `internal` is a reserved Go package name. 46 hits in one binary, all noise. Medium severity so it does not block, but it pads the report. |
| Medium | The release gate has no native GitHub Action or GitLab component; `docs/CICD.md` calls the CLI directly, which works everywhere but is more wiring than a marketplace action. |
| Medium | `first_seen_run_id` on `Finding` is never populated. The gate computes "is new" from the baseline run's id set instead, which is correct but means the column is dead weight. |
| Low | `click` is pinned to 8.1.8 to work around typer 0.15.1 (ADR-0020). Revisit when typer supports click 8.2+. |
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
