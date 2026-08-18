# Sightglass — GUI redesign brief

Paste this whole file to Claude (Design mode, or any capable agent) to redesign
the Sightglass dashboard. It is written to be self-contained: an agent should
not need to read the codebase to understand what the product is or who uses it.

---

## 1. What the product is

Sightglass scans the binaries a company is about to ship — installers,
executables, DLLs, firmware images, update bundles — and reports the secrets,
internal infrastructure, and intellectual property accidentally baked into
them. It unpacks archives recursively, so a single upload becomes a tree of
hundreds of files, and reports findings with byte offsets and full provenance.

It is self-hosted and air-gap capable. Nothing leaves the customer's network.

A real example of what it finds, from an actual vendor release:

```
svn+ssh://delinux03.de.moog.com/data/svn/nvce/tags/B99133-DV002-B-211b_11827
```

One string, in a device-description file, four levels deep inside an MSI inside
a ZIP. It discloses the company's internal Subversion host, its SSH transport,
the repository layout, and the firmware part-numbering scheme. The customer
shipped it to every user of the product without knowing.

**The redesign has to make that finding feel as consequential as it is, without
making the other 400 files feel like noise.**

## 2. Who uses it, and when

**Release engineer (primary).** Gates every build in CI. Opens the dashboard
when a gate fails. Wants one question answered in under five seconds: *can we
ship?* If not, *what exactly do I fix?* They are usually mid-release, slightly
stressed, and not browsing.

**AppSec engineer (primary).** Works through findings for an hour at a time,
triaging. Lives in the keyboard. Needs density — forty rows on screen, not
eight. Will export to a spreadsheet the moment the tool becomes slower than a
spreadsheet.

**Compliance officer (secondary).** Needs an evidence artifact per release, and
needs to believe the numbers. Reads the methodology appendix.

Design for the first two. The third is a report consumer.

## 3. The one constraint that shapes everything

The product's core promise is **deterministic spine, AI enhancement layer**:

- Every finding comes from a deterministic rule. Same artifact + same rules ⇒
  byte-identical results, every time.
- The AI layer triages, explains, and proposes new rules. It can suppress or
  demote a finding, and it can never invent one.
- A user must **always** be able to answer *"would this finding exist without
  the AI?"*

The UI is where that promise is kept or broken. Requirements:

- AI-derived content must be visually distinct from rule-derived content, at a
  glance, without reading labels.
- A **"deterministic only"** toggle hides every AI-derived field. What remains
  must be exactly what the scanner produces with no model configured.
- Never blend a model's verdict into a finding's severity or title. Severity
  comes from the rule and cannot be overridden by a model — the product
  demotes a model's "false positive" verdict to "needs review" on anything
  critical or high, and the UI should make that visible when it happens.

## 4. What exists today (your starting point)

Next.js 15 App Router, TypeScript, Tailwind v4. Server components render every
page; charts are hand-built inline SVG. **The dashboard must keep working with
JavaScript disabled** — this is a hard requirement for the static export path,
so avoid designs that depend on client-side rendering for core content.

Current screens:

| Route | Purpose |
| --- | --- |
| `/` | Posture overview: gauge, severity donut, trend bars, exposure ranking, runs table |
| `/scan` | Upload: drag-and-drop, options |
| `/runs/[id]` | Run detail: posture, severity mix, category bars, analyzer stages, run manifest, artifact tree, findings table |
| `/rules` | The detection pack, grouped by category |
| `/settings` | LLM provider health, egress policy, role routing |

Design tokens already exist as CSS custom properties (`--color-surface`,
`--color-content`, `--color-critical`, `--color-high`, …) with a light default
and a dark override under `prefers-color-scheme`. Keep the token names; change
their values freely.

## 5. What to design

Redesign the whole console to feel like a serious, modern security platform —
the Palo Alto / CrowdStrike / Wiz register: dense, calm, confident, built for
operators rather than for a landing page.

Deliverables, in priority order:

0. **Landing page** (`/` public, unauthenticated) — see §5a. The console moves
   to `/app`. This is the page that has to make someone want the product in
   fifteen seconds.
1. **Overview** — the "can we ship?" screen. Currently a gauge, a donut, a
   trend, an exposure ranking, and a runs table. Rethink the whole information
   hierarchy; do not just restyle the panels.
2. **Findings explorer** — the screen people spend real time in. Dense table,
   keyboard-first, expandable rows, faceted filtering, bulk triage. This is
   the hardest and most valuable screen.
3. **Run detail** — the artifact tree with per-file finding counts, analyzer
   stage timeline, and the run manifest.
4. **Finding detail** — masked value, entropy, every location in the tree, hex
   context at the offset, remediation, AI assessment, triage actions.
5. **Empty, loading, degraded, and error states** for all of the above.

## 5a. The landing page

A public marketing page, and it should be genuinely good — the kind of page a
security engineer sends to their manager to justify the procurement.

**The story it tells, in order:**

1. **The gap.** Everyone scans source code. Almost nobody looks at the binary
   that comes out the other end — and the build pipeline leaks. CI variables
   get baked into strings tables. Debug builds ship PDB paths exposing internal
   directory trees and developer usernames. Installers bundle a config with a
   real staging token in it.
2. **The proof.** Show the real finding. A code block, monospace, with the
   provenance path rendered as a tree:

   ```
   MoVaPuCo_4.3.zip
     └─ MoVaPuCo-4.3.7055.0-Release-x86.msi
          └─ device-description.xml
               svn+ssh://delinux03.de.moog.com/data/svn/nvce/tags/B99133-DV002-B-211b_11827
   ```

   Four levels deep, in a shipped product, disclosing an internal SCM host and
   the firmware part-number scheme. This is the most persuasive asset the
   product has. Do not bury it below the fold.
3. **How it works.** Upload → sandboxed unpack → deterministic rules → optional
   AI triage. A diagram, animated on scroll, showing an artifact decomposing
   into a tree and findings surfacing from it.
4. **Why you can trust it.** Deterministic: same artifact, same rules,
   byte-identical results. Self-hosted and air-gap capable: artifacts never
   leave the network. Analyzers run with no network, read-only root, dropped
   capabilities. The AI never invents a finding.
5. **The differentiator, stated plainly.** Most scanners read ASCII strings.
   Windows binaries hide roughly half their secrets in UTF-16, and Sightglass
   reads both. Show an ASCII-only scanner finding nothing next to Sightglass
   finding the key.
6. **Call to action** — self-host it; open the console.

**Tone:** confident and technical. The audience is engineers who will be
annoyed by "revolutionise your security posture" and convinced by an offset and
a hex dump. Show real output, not stock illustration. No stock photography of
people pointing at monitors, ever.

The landing page may use client-side JavaScript freely — the
no-JS requirement applies to the console, not here.

## 5b. Motion

Motion is part of the quality signal, and the console should feel alive and
responsive. Use it deliberately:

**Where motion earns its place:**

- **Live scan progress.** Stages transitioning pending → running → completed,
  with a real-time counter as findings appear. This is the moment the product
  feels alive; make it good.
- **Severity bars and donuts** animating from zero on first paint (respecting
  `prefers-reduced-motion`).
- **Row expansion** in the findings table — height and opacity, fast (150–200ms),
  with an easing curve that decelerates.
- **Artifact tree** expand/collapse, with children staggered by ~20ms so the
  hierarchy is legible as it opens.
- **Triage feedback** — a row changing status should acknowledge visibly and
  immediately, before the server responds.
- **Landing page** — scroll-driven reveals, the pipeline diagram animating, the
  artifact tree unfolding to reveal the finding. Be ambitious here.
- **Number transitions** on counters, so a changing figure reads as a change
  rather than a redraw.

**Rules:**

- Never delay information the server has already sent. A spinner covering a
  number we already have is a regression, not polish.
- Honour `prefers-reduced-motion: reduce` — drop to opacity-only or none.
- Console motion is fast: 120–250ms. Landing-page motion may be slower and more
  expressive.
- Prefer `transform` and `opacity`. Do not animate layout properties in a table
  with hundreds of rows.
- Motion must not be the only way to perceive a state change.

## 5c. The API — build against this directly

Every endpoint below is live. The dashboard proxies them same-origin through
`web/app/api/[...path]/route.ts`, so from the browser you call `/api/…`
directly with no CORS and no base URL. Types already exist in `web/lib/api.ts`
— import them rather than redeclaring.

Run the stack with `make dev` (or `./make.ps1 dev` on Windows); the console is
on `:3000` and the API on `:8000`, with interactive docs at
<http://localhost:8000/docs>.

### Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/runs` | List runs, newest first. `?limit=&offset=` |
| `POST` | `/api/runs` | Upload. `multipart/form-data`: `file`, plus optional `llm_enabled`, `attestation_reference`, `profile` |
| `GET` | `/api/runs/{run_id}` | Run detail: stages, manifest, artifact tree |
| `GET` | `/api/runs/{run_id}/events` | **SSE** live progress while a scan runs |
| `GET` | `/api/runs/{run_id}/findings` | Findings. `?severity=&status=&category=&detected_by=&new_only=&limit=` (repeat `severity` to OR) |
| `GET` | `/api/runs/{run_id}/findings/{finding_id}` | One finding |
| `PATCH` | `/api/runs/{run_id}/findings/{finding_id}` | Triage. Body `{"status": "...", "note": "..."}` |
| `POST` | `/api/runs/{run_id}/triage` | Run AI triage over the run's findings |
| `POST` | `/api/runs/{run_id}/discover` | AI proposes new detection rules from unmatched strings |
| `GET` | `/api/artifacts/{artifact_id}/bytes` | Hex window. `?offset=&length=` (≤4096) → `{hex, ascii}` |
| `GET` | `/api/settings/llm` | Provider config + live health probe |
| `GET` | `/api/settings/rules` | The loaded rule pack |
| `GET` | `/readyz` | Dependency health (`checks` gate readiness, `advisory` does not) |

Finding routes are **run-scoped** on purpose: finding IDs are content-derived
and shared across runs, so the same secret carries the same ID in every release
that ships it. `/api/findings/{id}` would be ambiguous.

### Shapes worth knowing

```ts
RunSummary {
  id, status: "queued"|"running"|"completed"|"failed",
  artifact_name, artifact_sha256, artifact_size_bytes,
  finding_count, severity_counts: { critical?, high?, medium?, low?, info? },
  artifact_count,               // files analysed, incl. everything unpacked
  new_since_previous: number|null,   // null = baseline run
  created_at, started_at, finished_at, error,
  llm_enabled, attested_by, attestation_reference
}

RunDetail extends RunSummary {
  stages: [{ analyzer, status, duration_s, evidence_count, image_digest, error }],
  manifest: { sightglass_version, artifact_sha256, rule_pack_version,
              rule_pack_hash, image_digests, tool_versions, fingerprint } | null,
  artifact_tree: ArtifactNode | null,
  previous_run_id: string | null
}

ArtifactNode {
  id, name, path_in_tree, depth, sha256, size_bytes,
  kind: "pe"|"elf"|"macho"|"archive"|"installer"|"filesystem"|"text"|…,
  media_type, architecture, identified,
  finding_count,               // drives the badge on a tree node
  children: ArtifactNode[]
}

Finding {
  id, run_id, rule_id, category, title,
  severity: "critical"|"high"|"medium"|"low"|"info",
  confidence, value_masked, entropy, context_snippet, cwe, tags,
  remediation_md,
  status: "open"|"confirmed"|"needs_review"|"false_positive"|"accepted_risk"|"fixed",
  detected_by: "rule"|"both",   // never "llm" — a DB constraint enforces it
  is_new,
  locations: [{ artifact_id, path_in_tree, offset, section,
                encoding: "ascii"|"utf-16le", xref_function }],
  location_count,
  llm: { verdict, reasoning, model, assessed_at } | null   // hidden by the toggle
}
```

A **clustered** finding (one rule that fired many times) has a title like
`Source control URL (28 distinct values)`, `value_masked` reading
`28 values, e.g. …`, `"clustered"` in `tags`, and every instance in
`locations`.

### Live progress (SSE)

```ts
const source = new EventSource(`/api/runs/${runId}/events`);
source.onmessage = (e) => {
  const { status, stages, finding_count } = JSON.parse(e.data);
  // stages: [{ analyzer: "unpack"|"static", status, duration_s }]
};
// Emits only on change; closes itself when the run reaches a terminal state.
```

### Files you will touch

```
web/
├── app/
│   ├── layout.tsx              root shell + sidebar
│   ├── page.tsx                overview  → becomes /app, freeing / for landing
│   ├── scan/page.tsx           upload
│   ├── runs/[id]/page.tsx      run detail
│   ├── rules/page.tsx          detection pack
│   ├── settings/page.tsx       providers, egress, roles
│   ├── globals.css             design tokens (@theme + dark override)
│   └── api/[...path]/route.ts  runtime proxy — do not add a next.config rewrite
├── components/
│   ├── ui.tsx                  Panel, Metric, Button, SeverityTag, StatusDot, formatters
│   ├── charts.tsx              SeverityDonut, BarList, TrendBars, PostureGauge, Sparkline
│   ├── findings-explorer.tsx   the dense table (client)
│   ├── artifact-tree.tsx       unpack tree (client)
│   ├── run-progress.tsx        SSE live progress (client)
│   └── sidebar-nav.tsx         navigation (client, needs usePathname)
└── lib/api.ts                  typed client + all response types
```

**Two traps, both already paid for:**

- Do **not** add `rewrites()` to `next.config.ts` for the API. Rewrites resolve
  at build time and bake in whatever `SIGHTGLASS_API_URL` was set during
  `docker build` — which is nothing — so uploads 500 in production while every
  page still renders. The runtime proxy exists for this reason.
- Tailwind v4: `@theme` must be **top level**. Nesting it inside
  `@media (prefers-color-scheme: dark)` silently flattens it and the dark
  values become the only palette. Declare light in `@theme`, override the same
  custom properties in a plain `:root` rule inside the media query.

### Sample data

```bash
make corpus     # builds tests/corpus/build/nested-release.zip — 3 levels, 12 findings
uv run python scripts/demo.py    # upload + scan + triage, end to end
```

## 6. Domain concepts the design must express

Getting these right matters more than the visual style.

**Severity** — critical, high, medium, low, info. Critical and high are
"release-blocking". Severity is the primary sort and the primary colour signal.
Colour should be reserved almost entirely for severity: if everything is
coloured, severity stops being visible.

**Provenance path** — findings carry a path through the unpack tree:
`release.zip → payload.tar.gz → config/prod.json`. These get long. They are the
single most useful field for an engineer deciding what to fix, so they must
stay readable at a glance and never be truncated into uselessness.

**Offsets and encoding** — `0x4a2c`, and `ascii` vs `utf-16le`. Wide-string
findings are the ones other scanners miss, so the encoding badge is a selling
point, not a technical detail.

**Clustering** — when one rule fires many times (867 build paths in one binary
is a real measured case), the product collapses them into a single finding
carrying all 867 locations. The design needs a way to show "one issue, 867
instances" and let a user drill into the instances.

**Run delta** — "what is new since the last release" is the question CI
actually asks. Findings are marked new / unchanged / resolved versus the
previous run of the same artifact.

**Degraded analyzers** — an analyzer can time out or be OOM-killed. A scan with
a degraded analyzer is *not* a clean artifact, and the UI must never let those
two look alike.

**The run manifest** — artifact hash, rule-pack version and hash, analyzer
image digests, tool versions, and a fingerprint. Two runs sharing a fingerprint
produce identical findings. This is the product's evidence of determinism, and
auditors read it.

## 7. Constraints

- **Next.js App Router + Tailwind v4.** Server components by default.
- **No charting library.** Charts are inline SVG. This keeps the air-gap bundle
  small and keeps charts rendering without JS. Design charts that survive that
  constraint — they can be beautiful, they cannot be interactive-only.
- **Light and dark**, driven by `prefers-color-scheme`. Both must be first
  class; this is a tool people run at 2am.
- **Accessible**: WCAG AA contrast, full keyboard navigation, real focus
  states, semantic tables. Severity must never be communicated by colour alone.
- **Dense but not cramped.** Target 40+ findings visible on a 1440px viewport
  without horizontal scrolling. Wide content scrolls in its own container; the
  page never scrolls horizontally.
- Existing keyboard bindings to preserve: `j`/`k` move, `e` expand, `c`
  confirm, `x` dismiss, `d` toggle deterministic-only.

## 8. What to deliver

- **The landing page**, in full — it is a deliverable in its own right, not a
  mockup. Scroll-driven, animated, with the real finding as its centrepiece.
- High-fidelity designs for the five console screens, in light **and** dark.
- A token set: colour, type scale, spacing, radii, elevation — as CSS custom
  properties, reusing the existing semantic names (`--color-surface`,
  `--color-content`, `--color-critical`, …) so the swap is a stylesheet change.
- Component specs for: severity tag, finding row (collapsed and expanded),
  artifact tree node, stat tile, chart family, filter bar, panel.
- **Motion spec**: durations, easing curves, stagger intervals, and the
  `prefers-reduced-motion` fallback for each animated element.
- Interaction notes for filtering, expansion, bulk triage, and live scan
  progress.
- A short rationale for the information hierarchy on the overview screen.

Working code beats static mockups here. The stack runs locally, the API is
live, and `make corpus` gives you real data to design against — build it.

## 9. Explicit non-goals

- **No vanity metrics.** Do not invent a 0–100 "risk score". A synthesised
  number invites arguing with the number instead of fixing the finding. Show
  the count that actually gates a release.
- **No stock imagery or generic SaaS copy.** The landing page should be
  ambitious and animated, but it persuades with real output — an offset, a
  provenance tree, a hex dump — not with abstract illustration or
  "revolutionise your security posture".
- **No motion that costs information.** Be expressive on the landing page and
  purposeful in the console, but never let an animation delay a number the
  server already sent, and always honour `prefers-reduced-motion`.
- **Do not soften the security posture.** If an artifact ships a private key,
  the screen should be uncomfortable to look at.

## 10. The test

An engineer opens the dashboard after a CI gate fails. Within five seconds they
should know whether they can ship, and within thirty they should know which
file to open and what to change.

If the design achieves that and still looks like something a security team
would be proud to put on a screen in front of an auditor, it has worked.
