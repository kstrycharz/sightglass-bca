# Architecture decision log

Append-only. Supersede rather than edit — a decision that was wrong is part of
the record, and the reasoning that led to it usually recurs.

Split out of [CLAUDE.md](../CLAUDE.md) on 2026-08-24: the log had grown past the
300-line mark and was crowding the working contract out of its own file. Nothing
was edited in the move.

---

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
*(Superseded by ADR-0009.)*
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

### ADR-0009 — The driver translates host paths; it does not require identical mounts (2026-08-17)
*Supersedes ADR-0007.* The driver holds two views of the run root — `run_root`
(as the orchestrator sees it) and `host_run_root` (as the daemon sees it) — and
rewrites bind sources between them.
**Rationale:** the same-path approach in ADR-0007 is impossible on Windows,
where a host path is `C:\...` and cannot also be a container path. Docker
rejects it outright with "too many colons". Translation is more general and
removes the footgun rather than documenting around it.
**Rejected:** a named volume, which has no host path the daemon can be given.

### ADR-0010 — Findings use a composite primary key (id, run_id) (2026-08-17)
`Finding.id` stays content-derived and excludes `run_id`; the table's primary
key is the pair.
**Rationale:** content-derived IDs are what make "what is new since the last
release" a set difference rather than a fuzzy match, so the same secret must
carry the same id in every release that ships it. That means re-scanning an
artifact legitimately produces the same id again — a different row, same
finding. With `id` alone as the primary key the second scan of any artifact
dies on a unique violation. Finding routes became run-scoped as a consequence,
which is more correct REST anyway.
**Rejected:** hashing `run_id` into the id, which would destroy cross-run
comparability; a surrogate key with a separate `fingerprint` column, which
leaves the user-visible id meaningless.

### ADR-0011 — The detection engine has no heavy dependencies (2026-08-17)
`core/rules/` imports only PyYAML and the standard library. `Severity` lives in
a dependency-free `core/vocab.py`, and `core/__init__.py` is empty of imports.
**Rationale:** the static analyzer image shares `core.rules` with the host, so
the scanner that produces findings in production is the exact source the unit
tests exercise — not a reimplementation that drifts. That only works if the
import does not drag SQLAlchemy and Pydantic into a sandboxed container.
**Cost:** one extra module and a re-export; worth it to keep the analyzer image
at one third-party package.

### ADR-0012 — Triage cannot dismiss a finding at or above high severity (2026-08-17)
A model verdict of `false_positive` on a `critical` or `high` finding sets
status to `needs_review`, not `false_positive`.
**Rationale:** demonstrated in the first live run — the model called a shipped
private key a false positive, reasoning from a marker in the surrounding text.
A model is allowed to be wrong; it is not allowed to be wrong in a way that
hides a shipped private key. Below the floor the model is trusted to reduce
noise, which is where the value is anyway.
**Rejected:** trusting verdicts uniformly; requiring human confirmation for
every verdict, which would defeat the purpose of triage.
### ADR-0013 — The dashboard proxies the API at runtime, not via a rewrite (2026-08-17)
Browser calls go through `web/app/api/[...path]/route.ts`, a Route Handler
using `node:http`. `next.config.ts` declares no `rewrites()`.
**Rationale:** two failures, both found only by using the UI. Next resolves
`rewrites()` at *build* time and bakes the result into the routes manifest, so
an image built without `SIGHTGLASS_API_URL` proxies to `localhost:8000`
forever — and since server components read the env at runtime, every page
renders fine and only uploads, triage, and status changes fail with a 500.
Then `fetch` proved unusable for the proxy itself: Next patches global fetch
and drops `duplex: "half"`, so a streamed request body fails with a bare
"fetch failed" while the identical stream works through plain Node.
`node:http` also pipes uploads instead of buffering them, so a 2 GB installer
never has to fit in the dashboard's memory.
**Rejected:** passing the API URL as a build arg (couples the image to one
deployment topology); calling the API cross-origin with CORS (a findings page
is a list of a company's exposed secrets).

### ADR-0014 — Durations are measured with a monotonic clock (2026-08-17)
`SandboxResult.duration_s` is a stored field fed by `time.monotonic()`, not
`finished_at - started_at`.
**Rationale:** observed in a real run — Docker Desktop's VM corrected its clock
mid-scan and a completed stage reported **-42.4 seconds**. Wall clock jumps
backwards on NTP correction and VM suspend/resume. The timestamps remain for
display and audit; the number a human reads comes from a clock that only moves
forward.

### ADR-0015 — The release gate is a product surface, not a script (2026-08-18)
`core/policy/` is a dependency-light engine (stdlib + PyYAML), `sightglass
scan` is the CI entry point, and the verdict has four distinct exit codes:
0 pass, 1 blocked, 2 tool error, 3 inconclusive.
**Rationale:** a scanner that can only be driven by a human uploading a file
catches secrets after the decision to ship has already been made. The gate is
where the product's value is realised, so it gets a real engine with its own
tests rather than a wrapper script around the API. Exit code 2 is kept strictly
apart from 1 because "the scanner was down" and "your installer ships an AWS
key" demand different responses; a tool that returns the same code for both
teaches people to re-run until it goes green.
**Rejected:** a shell wrapper around `curl` and `jq` (no way to test the
decision logic); folding the gate into the API's response to the upload
(couples the decision to the scan, so re-gating under a changed policy would
mean re-scanning a 2 GB installer).

### ADR-0016 — The gate fails on what the build introduced, not what it inherited (2026-08-18)
`baseline.mode: new_only` is the default. Findings present in the previous run
of a same-named artifact are reported and counted but do not block.
**Rationale:** this is the difference between a gate a team turns on and a gate
a team turns off. A product with 200 pre-existing findings cannot adopt a tool
that fails every build on day one. It can adopt one that stops the bleeding
today and lets the backlog burn down on a schedule somebody owns. Content-
derived finding IDs (ADR-0010) are what make this a set difference rather than
a fuzzy match, which is exactly the property they were introduced for.
**Cost:** a genuinely bad artifact whose secrets all predate the baseline
passes. Mitigated by reporting inherited findings prominently in every verdict
and by `mode: all` for release branches.
**Rejected:** blocking on everything by default — correct in principle, and the
reason most such gates end up disabled or wrapped in `|| true`.

### ADR-0017 — A model may not open the release gate (2026-08-18)
`trust_llm_dismissals` defaults to false. A finding triage called a false
positive still blocks the release; the gate reopens it.
**Rationale:** ADR-0012's severity floor stops the model dismissing a critical
finding in the database. This is the same principle one layer out, and it has
to be stronger: below that floor the model is trusted to reduce noise for a
human reviewer, but "reduce noise in a queue" and "authorise a release" are
different acts. A human disposition (`accepted_risk`, `fixed`) is trusted,
because a person is accountable for it. Teams that want the model's judgement
to count can opt in per policy.
**Rejected:** honouring triage uniformly, which would make the LLM load-bearing
for a release decision and violate "never require the LLM" in spirit.

### ADR-0018 — An incomplete scan is INCONCLUSIVE, never a pass (2026-08-18)
Degraded stages (timeout, OOM, failure) produce a third verdict with its own
exit code, considered *before* findings are evaluated.
**Rationale:** ADR-0008 made degraded analyzers return results rather than
raise, so a scan finishes with a partial view of the artifact. Reporting that
as "clean" is the failure mode that makes a gate worse than no gate — the
pipeline goes green and everyone believes the artifact was examined. A separate
verdict also stops "we found a problem" and "we could not finish looking" from
collapsing into one red build, which is what teaches people to retry until it
passes.
**Rejected:** treating degradation as a blocking violation (indistinguishable
from a real finding); treating it as a warning (the default nobody reads).

### ADR-0019 — The policy travels to the server; findings do not travel to CI (2026-08-18)
`POST /api/runs/{id}/gate` takes the policy as YAML text and returns a verdict.
The runner never receives the findings list.
**Rationale:** a findings list is a company's exposed secrets in one document.
Shipping it to every build agent would spread it into CI logs, artifact stores,
and whatever retains those — re-leaking exactly what the product exists to
catch (§14). Sending the policy *as the committed bytes* also means one parser
and one set of error messages, instead of a JSON projection that can drift from
the document a reviewer approved. The server additionally holds the baseline,
so "is this new" is a set difference it can answer directly.
**Rejected:** `GET /findings` in CI plus local evaluation (leaks the corpus);
storing policies server-side (takes ownership of "shippable" away from the team
that owns the binary, and loses the git history that is the audit trail).

### ADR-0020 — click is pinned below 8.2 (2026-08-18)
`click==8.1.8` is an explicit direct dependency although only typer uses it.
**Rationale:** click 8.2 changed `Parameter.make_metavar()` to require a `ctx`
argument, which typer 0.15.1 does not pass. The resolver happily picks a newer
click, and the result is that *every* `--help` in the CLI dies with a
`TypeError` while the commands themselves run fine — so it survives a smoke
test and fails the first person who asks the tool what its flags are. Found
while building `sightglass scan`; it was already broken for `sandbox hello`.
**Follow-up:** remove the pin when typer supports click 8.2+.

### ADR-0021 — Rules carry an explicit exclusion list, not negative lookaheads (2026-08-19)
`Rule.rejects_matching` is a list of regexes; a captured value matching any of
them is dropped in `accepts()`.
**Rationale:** almost every "internal infrastructure" rule needs to say *…but
not the public equivalent*, and the alternative is a negative lookahead
repeated inside each of the rule's patterns, which makes them unreadable and
drifts as patterns are added. Found in the field, not in review: `scm-url`
fired at **high** on `git://github.com/dotnet/runtime` inside a shipped .NET
assembly and on a public GitHub API URL inside a Go binary — both ordinary
build provenance — and blocked two of seven real-world release artifacts. The
rule already declared `https://github.com/example/project` as a negative test,
so its own stated intent was right and only its patterns leaked.
**Rejected:** per-pattern lookaheads (unreadable, repeated); the false-positive
corpus, which is for published literal values (`AKIAIOSFODNN7EXAMPLE`), not for
structural host classes.

### ADR-0022 — The static analyzer parallelises inside one container (2026-08-19)
The scan and the recon extraction run across a `ProcessPoolExecutor` sized from
the container's *cgroup* CPU quota, not the host core count. `sweep` stays in
the parent. `Settings.analyzer_cpus` (default 4) is the quota.
**Rationale:** measured, not assumed. Container spinup is ~0.5s and a scan
spawns exactly two containers (unpack, static), so lifecycle overhead is ~1s
and irrelevant; the cost is rule matching, which is CPU-bound regex work over
independent files. On a 502-file, 64 MB .NET tree in the real sandbox the
production configuration went 35.4s to 13.1s at 4 CPUs and 10.7s at 8, with
byte-identical output. Sizing from `os.cpu_count()` would read 28 on this host
and spawn 28 workers to share a 2-CPU quota, which is slower than one.
**Determinism:** `Executor.map` yields in submission order, so output does not
depend on scheduling (§2.5). Asserted at the unit level and again end to end by
`scripts/bench_analyzer.py`, which fingerprints the whole result document.
**Why `sweep` is not parallelised:** it ranks by rarity *across the corpus* —
the interesting string appears once, `System.Runtime` appears three thousand
times — so per-file sweeps would change its meaning. Only the extraction ahead
of it is split (9.0s to 2.2s across 8 workers).
**Fallback:** a pool that cannot start logs and runs sequentially. Seccomp
profiles, pids limits and a missing /dev/shm all vary by deployment, and a
slower scan beats a lost one — ADR-0008's posture one level down.
**Rejected:** a container per extracted file (400 starts for one installer);
raising `nano_cpus` without reading the cgroup (workers fight over the quota);
warm container pools (complexity for ~1s on a 13s job).

### ADR-0023 — The API authenticates by default, with two scopes (2026-08-24)
`Settings.auth_required` defaults to true. Tokens are 256-bit random strings
stored only as a SHA-256 hash; scopes are `ci` and `admin`.
**Rationale:** a release gate whose verdict anyone on the network can request,
and whose findings anyone can read, is not a control. Defaulting the check off
means every deployment that never set the variable is open, so the default is
on and a fresh stack bootstraps itself: with no tokens present the API mints one
admin token at startup and prints it once. That is the Jenkins/Grafana trade,
and a better one than a shipped default credential or an opt-in control.
**Why two scopes and not more.** ADR-0019 says findings do not travel to CI.
Without a scope that is a convention the first `curl` breaks — so `ci` may
submit an artifact, poll it, request a verdict and fetch SARIF, and may not read
the findings list, artifact bytes, or run triage. Finer permissions on a
two-actor system (a build agent and a human) are configuration nobody maintains
correctly.
**Why SHA-256 rather than a password KDF:** these are 256-bit random secrets,
not user-chosen passwords. There is no dictionary to slow down; what matters is
that plaintext is never stored, comparison is by indexed hash lookup, and a
database dump yields nothing usable.
**Failure posture:** 401 for an absent, unknown, revoked or expired credential;
403 for a valid one with the wrong scope, because "rotate your token" and "use
the right one" are different instructions. Every rejection is written to the
audit log with the redacted prefix — a burst of them is the first visible sign
of someone probing the gate. Revocation is a flag, never a delete.
**Rejected:** mTLS (correct for a service mesh, far too much operational weight
for a self-hosted, air-gap-capable tool); OAuth/OIDC (an identity provider is
exactly what an air-gapped deployment does not have); a token-minting endpoint
(a privilege-escalation target, and the first token cannot require a token).

---
