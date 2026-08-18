/**
 * Posture overview — the console's home.
 *
 * Server-rendered with no client JavaScript: §4 requires the dashboard to
 * render usefully with JS disabled, and every chart here is inline SVG.
 *
 * The layout answers three questions in descending order of urgency: can we
 * ship, what is wrong, and is it getting better. Everything else is a click
 * away rather than on this page.
 */

import Link from "next/link";
import { api, type RunSummary, type Severity } from "@/lib/api";
import {
  Button,
  EmptyState,
  ErrorNotice,
  Mono,
  Panel,
  SeverityBar,
  StatusDot,
  bytes,
  relativeTime,
} from "@/components/ui";
import {
  BarList,
  PostureGauge,
  SeverityDonut,
  SeverityLegend,
  TrendBars,
} from "@/components/charts";

export const dynamic = "force-dynamic";

function sumCounts(runs: RunSummary[]): Partial<Record<Severity, number>> {
  const totals: Partial<Record<Severity, number>> = {};
  for (const run of runs) {
    for (const [severity, count] of Object.entries(run.severity_counts)) {
      const key = severity as Severity;
      totals[key] = (totals[key] ?? 0) + count;
    }
  }
  return totals;
}

/**
 * The most recent completed run per artifact.
 *
 * Fleet totals must not sum every run ever recorded. Re-scanning an artifact —
 * after a fix, or after a rule-pack change — would otherwise count it twice and
 * keep superseded findings in the posture forever. "Where do we stand" is a
 * question about current builds, and the answer is the latest run of each.
 *
 * The runs list is newest-first, so the first sighting of a name wins.
 */
function latestPerArtifact(runs: RunSummary[]): RunSummary[] {
  const seen = new Set<string>();
  const current: RunSummary[] = [];
  for (const run of runs) {
    const key = run.artifact_name ?? run.id;
    if (seen.has(key)) continue;
    seen.add(key);
    current.push(run);
  }
  return current;
}

export default async function OverviewPage() {
  let runs: RunSummary[] = [];
  let error: string | null = null;

  try {
    runs = await api.listRuns();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const completed = runs.filter((r) => r.status === "completed");
  // Fleet panels use the current build of each artifact; the trend and the run
  // table deliberately keep full history.
  const current = latestPerArtifact(completed);
  const latest = completed[0];
  const latestCounts = latest?.severity_counts ?? {};
  const latestBlocking = (latestCounts.critical ?? 0) + (latestCounts.high ?? 0);

  // Oldest-first, so the trend reads left to right like every other chart.
  const trend = [...completed]
    .reverse()
    .slice(-24)
    .map((run) => ({
      label: run.artifact_name ?? run.id.slice(0, 8),
      counts: run.severity_counts,
    }));

  const worst = [...current]
    .map((run) => ({
      label: run.artifact_name ?? run.id.slice(0, 8),
      value: (run.severity_counts.critical ?? 0) + (run.severity_counts.high ?? 0),
      tone: "critical" as Severity,
    }))
    .filter((entry) => entry.value > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, 6);

  const fleetCounts = sumCounts(current);
  const filesAnalysed = current.reduce((sum, r) => sum + (r.artifact_count ?? 1), 0);

  return (
    <div className="space-y-5">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Release posture</h1>
          <p className="mt-1 text-sm text-content-muted">
            {current.length} artifact{current.length === 1 ? "" : "s"} ·{" "}
            {filesAnalysed.toLocaleString()} files analysed ·{" "}
            {completed.length} completed scan{completed.length === 1 ? "" : "s"}
          </p>
        </div>
        <Link href="/scan">
          <Button variant="primary">New scan</Button>
        </Link>
      </header>

      {error && <ErrorNotice title="API unreachable" detail={error} />}

      {!error && runs.length === 0 && (
        <Panel>
          <EmptyState
            title="No scans yet"
            action={
              <Link href="/scan">
                <Button variant="primary">Scan an artifact</Button>
              </Link>
            }
          >
            Upload an installer, executable, archive, or firmware image.
            Sightglass unpacks it recursively and reports the secrets, internal
            hostnames, and build metadata baked into it.
          </EmptyState>
        </Panel>
      )}

      {latest && (
        <>
          <div className="grid gap-4 lg:grid-cols-12">
            <Panel
              title="Latest release"
              description={latest.artifact_name ?? undefined}
              className="lg:col-span-4"
            >
              <div className="flex flex-col items-center px-4 py-5">
                <PostureGauge
                  blocking={latestBlocking}
                  total={latest.finding_count}
                />
                <p className="mt-3 max-w-[16rem] text-center text-xs text-content-muted">
                  {latestBlocking === 0
                    ? "No critical or high findings. This build clears the gate."
                    : `${latestBlocking} finding${latestBlocking === 1 ? "" : "s"} at critical or high would block a release gated on severity.`}
                </p>
                <Link
                  href={`/runs/${latest.id}`}
                  className="mt-3 text-xs text-accent underline-offset-2 hover:underline"
                >
                  Inspect run →
                </Link>
              </div>
            </Panel>

            <Panel title="Severity mix" className="lg:col-span-4">
              <div className="flex items-center justify-center gap-6 px-4 py-5">
                <SeverityDonut
                  counts={latestCounts}
                  centerValue={latest.finding_count}
                  centerLabel="findings"
                />
                <div className="min-w-[7rem]">
                  <SeverityLegend counts={latestCounts} />
                </div>
              </div>
            </Panel>

            <Panel
              title="Trend"
              description="Findings per completed run, oldest to newest"
              className="lg:col-span-4"
            >
              <TrendBars series={trend} />
              <div className="border-t border-border px-4 py-2 text-xs text-content-muted">
                {latest.new_since_previous === null ? (
                  "Baseline run — nothing to compare against yet."
                ) : latest.new_since_previous === 0 ? (
                  <span className="text-ok">
                    No new findings since the previous run of this artifact.
                  </span>
                ) : (
                  <span className="text-high">
                    {latest.new_since_previous} finding
                    {latest.new_since_previous === 1 ? "" : "s"} new since the
                    previous run.
                  </span>
                )}
              </div>
            </Panel>
          </div>

          <div className="grid gap-4 lg:grid-cols-12">
            <Panel
              title="Highest exposure"
              description="Artifacts by release-blocking findings"
              className="lg:col-span-5"
            >
              {worst.length > 0 ? (
                <BarList items={worst} />
              ) : (
                <p className="px-4 py-6 text-sm text-ok">
                  No artifact currently carries a critical or high finding.
                </p>
              )}
            </Panel>

            <Panel
              title="Current exposure"
              description="Latest run of each artifact — superseded scans excluded"
              className="lg:col-span-7"
            >
              <div className="flex flex-wrap items-center gap-8 px-4 py-5">
                <SeverityDonut
                  counts={fleetCounts}
                  size={140}
                  thickness={14}
                  centerLabel="total"
                />
                <div className="min-w-[8rem]">
                  <SeverityLegend counts={fleetCounts} />
                </div>
                <p className="max-w-xs text-xs text-content-muted">
                  Every finding here comes from a deterministic rule. Rules that
                  fire en masse are clustered into a single finding with all its
                  locations, so a build that leaks 800 source paths reads as one
                  issue rather than eight hundred.
                </p>
              </div>
            </Panel>
          </div>
        </>
      )}

      {runs.length > 0 && (
        <Panel title="Runs" description="Newest first">
          <div className="scroll-x">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-content-subtle">
                  <th scope="col" className="px-4 py-2 font-medium">Artifact</th>
                  <th scope="col" className="px-4 py-2 font-medium">Status</th>
                  <th scope="col" className="px-4 py-2 font-medium">Findings</th>
                  <th scope="col" className="px-4 py-2 font-medium">Delta</th>
                  <th scope="col" className="px-4 py-2 font-medium">Files</th>
                  <th scope="col" className="px-4 py-2 font-medium">Started</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr
                    key={run.id}
                    className="border-b border-border/60 last:border-0 hover:bg-surface-sunken/60"
                  >
                    <td className="px-4 py-2.5">
                      <Link
                        href={`/runs/${run.id}`}
                        className="font-medium underline-offset-2 hover:underline"
                      >
                        {run.artifact_name ?? run.id.slice(0, 8)}
                      </Link>
                      <div className="mt-0.5 flex items-center gap-2 text-xs text-content-subtle">
                        <Mono title={run.artifact_sha256 ?? undefined}>
                          {run.artifact_sha256?.slice(0, 12) ?? "—"}
                        </Mono>
                        <span>{bytes(run.artifact_size_bytes)}</span>
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <StatusDot status={run.status} />
                      {run.error && (
                        <div className="mt-0.5 max-w-[18rem] truncate font-mono text-xs text-critical">
                          {run.error}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2.5">
                      <SeverityBar counts={run.severity_counts} total={run.finding_count} />
                    </td>
                    <td className="px-4 py-2.5 tnum">
                      {run.new_since_previous === null ? (
                        <span className="text-xs text-content-subtle">baseline</span>
                      ) : run.new_since_previous === 0 ? (
                        <span className="text-xs text-ok">no change</span>
                      ) : (
                        <span className="text-xs font-medium text-high">
                          +{run.new_since_previous}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 tnum text-content-muted">
                      {run.artifact_count ?? 1}
                    </td>
                    <td className="px-4 py-2.5 text-content-muted">
                      {relativeTime(run.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}
