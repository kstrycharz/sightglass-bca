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

**Milestone: M1 — Ingest & static core. Complete. Plus most of M3 (BYOLLM:
local and cloud providers, triage, explain, summarize, discovery) and the M4
release gate, both pulled forward so the product is usable in a pipeline.**

Working end to end today: upload an artifact through the dashboard or the CLI,
it is scanned in a locked-down container, and deterministic findings appear
with offsets, encoding, and remediation. Optional AI triage classifies them,
explains individual findings, and summarises a run. A release policy turns
those findings into a ship / do-not-ship decision with a meaningful exit code,
so Sightglass is a build-pipeline stage gate and not only a dashboard.

Deployment is two commands and no file editing — the dashboard's first-run
wizard mints the API token and optionally connects a model:

```bash
docker compose build
docker compose up -d          # then open http://localhost:3000
```

```bash
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

Verified: 536 unit tests, 19 integration tests, `mypy --strict` clean on
`core/`, `ruff` clean, `next build` clean.

Not yet started: Ghidra and dynamic analysis (M5), MCP servers (M5), the
`remediate` role, and a Bedrock adapter (SigV4, unlike every other provider).

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
- **ADR-0027** — LiteLLM is the transport; the air gap is enforced above it (2026-08-26)

---

## 4. Progress log

Reverse-chronological.

### 2026-08-26 (4) — LiteLLM replaces the hand-written cloud adapters
**Why:** breadth, from something maintained. Three hand-written adapters
covered OpenAI-compatible, Anthropic, and Google; LiteLLM covers those and a
hundred more, and tracking every vendor's wire format is not this project's
job. The catalog went from 8 providers to 17 by adding rows, not code.

**The part that needed care: LiteLLM has no single egress choke point.**
Measured rather than assumed, and both obvious mechanisms failed:
`litellm.client_session` with an httpx request hook fires for the OpenAI family
and *nothing else* — Anthropic, Gemini, and Groq use their own handlers — and
an explicit `api_base` is honoured by Anthropic but silently ignored by Gemini.
Either would have looked like enforcement while quietly permitting egress from
an air-gapped deployment.

So the guarantee moved up a level, where it is absolute: **a non-local provider
is never constructed under a deny policy** (ADR-0027). `build_provider` refuses
it and `load_config` refuses the whole config at start-up, so there is no
request for LiteLLM to route. Locality comes from the base URL when there is
one — a config claiming `is_local: true` for `api.openai.com` is still refused —
and otherwise from what the catalog declared, defaulting to hosted. Seven tests
hold that line, including the two "must be refused" cases and the URL-wins case.

**Ollama stays on its own adapter.** LiteLLM speaks Ollama, but the native one
has `warm()` (a cold 9 GB model takes 20+ seconds to page in, and without an
explicit warm-up that lands on the first candidate and looks like a slow model)
and a health check that lists pulled models and says `ollama pull X` when one is
missing. Losing either would be a real regression for the local path, which is
also the one that needs no vendor breadth.

**What LiteLLM gives back beyond breadth:** typed exceptions. "The API key was
rejected" and "the model was not found for this key" are different problems
with different fixes, and every vendor words them differently. `_explain_failure`
turns them into one sentence an operator can act on, with the key scrubbed.

**Verified end to end**, not just unit-tested: 17 providers listed, a hosted
provider refused under `egress: deny` in the deployed container, a bad OpenAI
key rejected with a readable message and rolled back out of the key store, and
a real `explain` call routed through LiteLLM returning grounded prose in 2.8s.

**Verified:** 543 unit tests, mypy strict, ruff clean, `next build` clean.


### 2026-08-26 (3) — the AI layer that was configurable but never called
**The finding that set the agenda.** `grep 'role="'` across the codebase
returned two hits. `config/llm.yaml` routed five roles and the settings page
described each one confidently, but only `triage` and `discover` had a caller —
`explain`, `remediate`, and `summarize` were dead config. An operator could
point a model at "summarize", be told it was healthy, and never see output,
because nothing invoked it. That is the whole of "the AI summaries aren't clear
where they are or what they're doing": there were no summaries.

**Built:** `core/llm/explain.py` — the `explain` and `summarize` roles, with
`explain_finding_task` / `summarize_run_task`, `POST
/api/runs/{id}/findings/{fid}/explain` and `POST /api/runs/{id}/summarize`,
migration `0003` for the columns to live in, and UI for both. Explain is
per-finding on request, not per-run: it routes to a reasoning model by default
and running it over 45 findings would cost more than the scan. Every AI panel
now names its role, its model, and when it ran.

`llm_explanation` is deliberately not `llm_reasoning`. Reasoning is triage's
justification for a status change and part of that audit trail; reusing the
column would mean asking for an explanation destroyed the record of why a
finding was dismissed. A test pins it.

**The token-budget bug, diagnosed.** Triage caps output at 300 tokens, which is
right for a one-line JSON verdict from a fast model and catastrophic for a
reasoning model, which spends the whole budget thinking and returns nothing.
The new roles ask for 4000 and, when a model still returns empty with a
`thinking` field, say *which* failure it was and how to fix it. Separately,
`config/llm.yaml` pointed at `glm-4.7-flash:bf16`, which was never pulled on
the Ollama host — `q4_K_M` was. Health said so plainly; nothing had read it.

**Cloud providers, and the wizard step for them.** `openai_compatible.py`
(OpenAI, Groq, OpenRouter, Together, vLLM, LM Studio, Azure), `anthropic.py`,
and `google.py`, wired into `build_provider`, plus `core/llm/catalog.py`
driving a second wizard step with a prominent skip — a model is genuinely
optional. The connection is tested *before* anything is written, so "connected"
means it; a rejected key is rolled back out of the store rather than left
behind. Verified against a live Ollama host and a deliberately-bad OpenAI key
(401 → refused, key store left `{}`).

**Keys never touch `config/llm.yaml`.** That file is committed, and a provider
key in it is a credential in the repository — the exact failure this product
exists to find in other people's artifacts. Keys resolve from an env var first,
then a 0600 runtime store (`core/llm/secrets.py`). Adapter error strings are
scrubbed of the key before they reach a log or the settings page.

**Then the bug that made all of it pointless.** The wizard wrote to
`config/llm.yaml` under `repo_root` — which is baked into the image, so every
`docker compose build` silently discarded whatever the operator had configured,
and `/app/data` had no volume mounted on the backend at all, so the key store
did not survive a container recreate either. The live config and keys now live
in a `backend-data` volume shared by the API and both workers, seeded from the
packaged default on first use. **Verified by doing it:** configured a provider,
rebuilt the image, recreated the container, confirmed it was still there.

**Also fixed:** the wizard's "Continue to dashboard" did nothing. Middleware had
redirected `/` → `/setup` and Next's client router cached that redirect, so
`router.push("/")` replayed it and landed back on the same page. It now leaves
with a full page load, which is correct rather than a workaround — completing
setup changes the server state the entire cache was built under. Reopening
`/setup` on a configured deployment used to 409 and strand you; it now advances
to the model step.

**Caught by building, not by type-checking.** Wiring the persisted token into
`lib/api.ts` pulled `node:fs` into the client bundle twice, because that module
is imported by client components. `tsc --noEmit` passes; only `next build`
fails. The rule is now written down in the file itself: `api` is server-only,
client components use a bare `fetch` through the proxy.

**Verified:** 536 unit tests (21 new), mypy strict, ruff clean, a real
`next build`, and a live `explain` call returning grounded prose in 33s.


### 2026-08-26 (2) — a fresh deployment could not start; setup moved into the dashboard
**The failure that set the agenda.** Destroying the compose volumes to verify
a clean bring-up crash-looped the API on the very first migration:
`relation "runs" does not exist` while creating `artifacts`. `0001_baseline`
created `artifacts` (which references `runs`) eleven tables before it created
`runs` — a real cycle, not just the wrong order, since `runs.root_artifact_id`
points back at `artifacts`. Every deployment so far had reached this migration
either via the old `create_all()` bootstrap (stamped at baseline, never
replayed) or already past it, so a truly empty database was the first thing
ever to run this path for real. Fixed by creating `runs` first, without that
one column's constraint, and closing it with `op.batch_alter_table` once
`artifacts` exists — batch mode because Postgres runs that as a plain ALTER
but SQLite has no ALTER-ADD-CONSTRAINT at all, only the recreate-and-copy batch
mode performs.

**The unit suite could not have caught it, structurally.** It migrates SQLite
by design (no Docker, portable), and SQLite accepts a `CREATE TABLE` whose
foreign key targets a table that does not exist yet — it validates FK targets
lazily, never at DDL time. Postgres validates immediately. Added
`TestForeignKeyOrdering` in `tests/unit/test_migrations.py`: it renders every
migration's DDL for the **postgresql dialect** via Alembic's own `--sql`
offline mode — real SQL text, no database — and replays the ordering rule
Postgres actually enforces, both directions. Confirmed against the original
file (`git stash`) that both new tests fail on the bug and pass on the fix.

**Then the deploy-simplicity gap.** Getting the stack running again needed a
manually-minted token, because the only other admin token had been minted by
an earlier crash-loop retry and its one-time console banner had already
scrolled past — unrecoverable by design (ADR-0024's era), just at an
inconvenient moment. That prompted the actual ask: remove the `.env`-and-CLI
onboarding step entirely. `ensure_bootstrap_token`'s automatic call at startup
is gone; `POST /api/setup/bootstrap` (`api/routers/setup.py`) exposes the same
one-shot mint over HTTP instead — unauthenticated by construction, but safe,
because the guard is "no token exists yet," the same fact the console version
already gated on. The dashboard's `middleware.ts` checks `GET
/api/setup/status` ahead of every page and redirects a deployment with no
tokens to `/setup`, a one-step wizard that mints, shows the token once, and
hands the user back to a dashboard that already works.

**"Already works" needed its own fix.** Server components fetch the API
directly rather than through the Next.js proxy (`lib/api.ts`), and that path
read `SIGHTGLASS_TOKEN` from the environment only — so the wizard could mint a
token and the very next page load would still say "a valid API token is
required." `lib/runtime-token.ts` now resolves the token from the env var
first, falling back to a file the wizard persists to a new `web-data` volume,
so a container *restart* does not ask again. Wiring it into `lib/api.ts`
broke the client production build outright — `node:fs` doesn't resolve in a
browser bundle, and that file is imported by client components for its types.
The fix was `npm run build`, not `tsc --noEmit`: type-checking alone never
sees a bundler resolve failure. Traced it to one non-type import
(`SEVERITY_ORDER`, used by the client-side findings explorer) pulling the
whole module graph in; split it into `lib/severity.ts`, which has no
server-only dependency, and the client build is clean again.

**Verified against a real clean-slate deploy**, the scenario that started
this: `docker compose down --volumes`, rebuild every image, `up`. Migration
ran to head on the first try. Dashboard opened on `/setup` automatically,
minted a token, and every page — the proxy path and the direct server-render
path — worked immediately after, including across a full `docker compose
restart web`, without touching `.env`.

**Verified:** 500 unit tests (9 new), mypy strict, ruff clean, `tsc` clean, a
real `next build` (which is what actually caught the bundling break).


### 2026-08-26 — a progress bar that reports work, not time
**Built:** live scan progress. Five phases derived from stage rows — queued,
unpack, index, scan, report — a determinate bar, a live elapsed timer, the
artifact count as it climbs, and, where the same artifact has been scanned
before, that run's duration as an estimate. The bar never interpolates inside a
phase: nothing is known about progress within one, and a bar advancing on a
clock is inventing the only thing the operator opened the page for.

**The feature was mostly a bug hunt.** Two of the five phases (`index`,
`report`) have no analyzer of their own — they are the pipeline writing 69 000
artifact rows, then correlating evidence — and they are exactly the windows
that looked like a hang.

*Every phase was invisible.* Stage rows and artifacts are written inside the
scan's single long transaction, so nothing outside it saw them until the run
finished. The panel could only ever show `queued`, then the finished report
seven minutes later. The pipeline now commits at each phase boundary, which
also means a scan killed mid-flight leaves behind what it actually completed.

*Then the phase was wrong.* `RunStage.status` defaults to PENDING and the row
is committed before its container starts, so "row exists" was read as "stage
finished" — the panel reported `report` for the whole six-minute static scan,
sitting one phase from the end while the work had barely begun. Stages now
start RUNNING, and `_phase` treats PENDING as unfinished so the default cannot
lie again.

*And the widget hung on degraded runs.* It treated only `completed`/`failed` as
terminal, so `RunStatus.DEGRADED` — added the day before — would have streamed
for ever and never shown the report.

**Also fixed:** `duration()` rounded the seconds remainder rather than the
total, so 419.6s rendered as "6m 60s". Pre-existing, on every duration in the
dashboard.

**Verified against a live scan**, which is the only place any of this was
visible: Unpack at 20% with `unpack running`, Index at 40%, Scan at 60% with
`68,976 artifacts found` and `unpack completed 19.5s`, then the terminal
refresh into the report.

**Verified:** 491 unit tests (18 new), mypy strict, ruff clean, `tsc` clean.


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
**Built:** `core/auth.py` (minting, hashing, scope rules; stdlib only), the
`api_tokens` table, `api/deps.py` with `get_caller` / `require_scope`,
`sightglass token create|list|revoke`, a startup bootstrap so secure-by-default
does not brick a fresh stack, and `sightglass gate <run-id>` to re-evaluate a
stored run under a different policy without re-uploading. The dashboard
authenticates as itself server-side, and the proxy strips any `Authorization`
the browser sends so a page script cannot smuggle its own (ADR-0023).

**Verified over real HTTP**, not TestClient: 401 anonymous and for an unknown
token on every `/api` route, 200 for admin, **403** for a CI token on
`/findings` and `/settings` naming the scope it lacked, revocation effective
immediately, and the audit log holding the sequence. 372 unit tests (83 new).

**That run found the bug worth finding.** `ensure_bootstrap_token` logged the
full plaintext token into the *structured* log as well as the console banner —
shipping a live admin credential to whatever aggregates those logs. The banner
is the intended one-time disclosure; the log line now carries only the prefix,
and two tests assert no minting path puts plaintext into logging output.
Exactly the class of leak this product exists to find.

**And a second real one:** `docker compose exec api sightglass token create` —
the documented bootstrap path — failed with "executable file not found".
`Dockerfile.backend` installed what `pyproject.toml` requires but never the
project, so its console script never existed; `PYTHONPATH=/app` is why the API
ran anyway and nothing caught it. Fixed with a shim rather than `pip install .`,
which would put a second copy of the source in site-packages.

**Housekeeping:** the ADR log moved to [docs/ADR.md](docs/ADR.md); §3 keeps a
one-line index.

### 2026-08-19 — validated through the real stack; analyzer parallelised
**Ran the whole thing for real**, which the previous session had not: compose
stack healthy, artifacts uploaded through the API, scanned in the sandbox,
gated by the CLI. A real ripgrep release gives PASS/0; a planted binary gives
BLOCKED/1 with five violations and the public GitHub URL correctly excluded.
SARIF 2.1.0 validates, byte offsets present, fingerprints match, no plaintext
reaches the file.

**Data verified against the bytes:** ripgrep findings at offsets 3072616,
3200336, 3200488 each land on a cargo registry path under the CI runner's own
home directory — a release build carrying the runner's account name. 91
distinct values collapse into one finding with 91 locations.

**Found by running it:** the API container was serving an image built before
`api/routers/gate.py` existed, so every `POST .../gate` returned 404 while the
scan succeeded — invisible to any test, obvious on first deploy.

**Performance.** Profiling contradicted the obvious assumption: container
spinup is ~1s of a 35s job; the cost was a sequential per-file loop. Now
parallel (ADR-0022): 35.4s to 13.1s at 4 CPUs, 10.7s at 8, byte-identical
output.

**Detection fixes from a field corpus** of 7 released artifacts (105 MB
downloaded, 349 MB scanned): two of seven were **blocked** on `scm-url` at
high, both false positives — a `git://` URL from .NET repository metadata and a
public GitHub API URL from a Go binary. A public forge is not
internal-infrastructure disclosure, and a gate that blocks ordinary clean
software is one a team switches off. Fixed via ADR-0021 with the observed
strings as negative fixtures. `private-ip-address` also matched `10.00.000.0`;
octets are now validated. A positive control still yields BLOCKED, so the
narrowing did not hollow the rules out.

### 2026-08-18 — the release gate: Sightglass as a CI/CD stage gate
**Built:** `core/policy/` (severity floor, blocked rules/categories, budgets,
baseline comparison, expiring waivers, degraded posture); `core/pipeline/gate.py`;
`POST /api/runs/{id}/gate` and `GET /api/runs/{id}/sarif`; `reporting/sarif.py`
(SARIF 2.1.0, stable `partialFingerprints`, masked values only); `sightglass
scan` and `policy init|validate|explain`; a stdlib-only streaming API client so
a build agent needs no dependency tree; `docs/CICD.md` and workflows for GitHub
Actions, GitLab, Azure DevOps, and Jenkins.

**Verified:** 269 unit tests (104 new). Tested at four levels because each
hides the others' failures: the engine alone, the ORM bridge against a real
schema, the endpoints through the real app, and the CLI over real HTTP.

**The three decisions that make it adoptable** are ADR-0016 (fail on what the
build introduced), ADR-0017 (a model may not open the gate), and ADR-0018 (an
incomplete scan is INCONCLUSIVE, never a pass).

**Broke, then fixed:** every `--help` died on `make_metavar()` — click 8.4.2
against typer 0.15.1 (→ pinned, ADR-0020); the gate joined `finding_locations`
to `artifacts` for a path the location already denormalises, so the join was
both wrong and unnecessary (caught by the SQLite test, exactly what a mocked
session hides); the API tests all failed "no such table" because each session
opened its own in-memory SQLite (→ `StaticPool`).

### 2026-08-17 — M0 and M1 complete, plus the Ollama slice of M3
**M0:** the sandbox stack in full (`SandboxSpec`, `DockerDriver`, watchdog,
reaper, seccomp allowlist, the `hello:dev` probe), health probes, six-queue
Celery, the compose stack, `make.ps1`, six-job CI. **M1:** the schema; ingest
with the attestation gate; content-addressed MinIO storage; the detection
engine (ASCII + UTF-16LE, entropy/masking, 17 rules, a 44-entry FP corpus);
the static analyzer image; the correlator; the scan pipeline; the REST API and
Next.js dashboard; the Ollama provider with egress enforcement; LLM triage
with the severity floor.

**Verified:** 102 unit / 17 integration tests, mypy strict, ruff clean. Upload
→ sandboxed scan → 9 findings from 10 evidence rows → triage in 21.4s; three
findings were UTF-16LE only. The severity floor was demonstrated: the model
called a shipped private key a false positive and was overruled into
`needs_review` (ADR-0012).

**Broke, then fixed:** a tmpfs mount is root-owned 0755 and masks the image's
own chown underneath it, failing the first acceptance run (ADR-0005);
`Finding.id` alone as a primary key died on any re-scan (→ composite key,
ADR-0010); a FP-corpus entry matched a rule's structural marker instead of a
credential value, silently disabling it; `core.rules` transitively imported
SQLAlchemy, which would have forced an ORM into the analyzer image (→
`core/vocab.py`, ADR-0011).

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
| Medium | Plaintext retention has no TTL and no auto-purge, and nothing encrypts it at rest. A run scanned with "Retain full plaintext values" leaves real secrets in Postgres indefinitely. The UI says so at the point of choosing, but §9 promises a TTL that does not exist yet. |
| Medium | The `remediate` role is routable and described in the settings UI as not-yet-wired, but nothing calls it. Either wire it or drop it from `EDITABLE_ROLES`. |
| Low | `explain` and `summarize` have no cache: asking twice costs two calls. Triage caches by prompt hash within a pass; these do not, because they are user-initiated and low-volume. |
| Low | Cloud provider adapters are unit-tested against their wire shapes but only OpenAI has been exercised against the live API (a deliberate 401). Anthropic and Google are untested end to end. |

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
