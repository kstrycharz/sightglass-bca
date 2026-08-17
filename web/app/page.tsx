/**
 * Runs list — the console's home. Server-rendered with no client JavaScript:
 * §4 requires the dashboard to render usefully with JS disabled, and a table
 * has no reason to need it.
 */

import Link from "next/link";
import { api, type RunSummary, type Severity } from "@/lib/api";
import {
  Button,
  EmptyState,
  ErrorNotice,
  Metric,
  Mono,
  Panel,
  SeverityBar,
  StatusDot,
  bytes,
  relativeTime,
} from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function RunsPage() {
  let runs: RunSummary[] = [];
  let error: string | null = null;

  try {
    runs = await api.listRuns();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const completed = runs.filter((r) => r.status === "completed");
  const blocking = completed.reduce(
    (sum, r) => sum + (r.severity_counts.critical ?? 0) + (r.severity_counts.high ?? 0),
    0,
  );
  const newest = completed[0];

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Runs</h1>
          <p className="mt-1 text-sm text-content-muted">
            Every scan, newest first. Delta is what changed since the previous
            run of the same artifact.
          </p>
        </div>
        <Link href="/scan">
          <Button variant="primary">New scan</Button>
        </Link>
      </header>

      {error && <ErrorNotice title="API unreachable" detail={error} />}

      {!error && runs.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Runs" value={runs.length} />
          <Metric
            label="Release-blocking"
            value={blocking}
            hint="critical + high, all runs"
            tone={blocking > 0 ? "bad" : "good"}
          />
          <Metric
            label="Latest findings"
            value={newest?.finding_count ?? 0}
            hint={newest?.artifact_name ?? "—"}
          />
          <Metric
            label="New in latest"
            value={
              newest?.new_since_previous === null || newest?.new_since_previous === undefined
                ? "—"
                : newest.new_since_previous
            }
            hint="vs previous run"
            tone={newest?.new_since_previous ? "warn" : "neutral"}
          />
        </div>
      )}

      <Panel>
        {!error && runs.length === 0 ? (
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
        ) : (
          <div className="scroll-x">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-content-subtle">
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
                          +{run.new_since_previous} new
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
        )}
      </Panel>
    </div>
  );
}

export type { Severity };
