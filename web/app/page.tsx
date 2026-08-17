/**
 * Runs list. Server-rendered, no client JavaScript — §4 requires the dashboard
 * to render usefully with JS disabled, and the list view has no reason to need it.
 */

import Link from "next/link";
import { api, formatBytes, formatTime, type RunSummary } from "@/lib/api";
import { SeverityRollup, StatusText } from "@/components/severity";

export const dynamic = "force-dynamic";

export default async function RunsPage() {
  let runs: RunSummary[] = [];
  let error: string | null = null;

  try {
    runs = await api.listRuns();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Runs</h1>
          <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
            Every scan, newest first. Delta shows what is new since the previous
            run of the same artifact.
          </p>
        </div>
        <Link
          href="/upload"
          className="rounded-md bg-neutral-900 px-3 py-2 text-sm font-medium text-white transition-colors hover:bg-neutral-700 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-neutral-300"
        >
          New scan
        </Link>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/5 p-4">
          <p className="font-medium text-red-700 dark:text-red-400">API unreachable</p>
          <p className="mt-1 font-mono text-xs text-neutral-600 dark:text-neutral-400">
            {error}
          </p>
        </div>
      )}

      {!error && runs.length === 0 && (
        <div className="rounded-lg border border-dashed border-neutral-300 p-10 text-center dark:border-neutral-700">
          <p className="font-medium">No scans yet</p>
          <p className="mx-auto mt-2 max-w-md text-sm text-neutral-600 dark:text-neutral-400">
            Upload an installer, executable, or firmware image and Sightglass
            will report the secrets, internal hostnames, and build metadata
            baked into it.
          </p>
          <Link
            href="/upload"
            className="mt-4 inline-block rounded-md bg-neutral-900 px-3 py-2 text-sm font-medium text-white dark:bg-neutral-100 dark:text-neutral-900"
          >
            Scan an artifact
          </Link>
        </div>
      )}

      {runs.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-neutral-200 text-left dark:border-neutral-800">
                <th scope="col" className="py-2 pr-4 font-medium">Artifact</th>
                <th scope="col" className="py-2 pr-4 font-medium">Status</th>
                <th scope="col" className="py-2 pr-4 font-medium">Findings</th>
                <th scope="col" className="py-2 pr-4 font-medium">Delta</th>
                <th scope="col" className="py-2 pr-4 font-medium">Attested by</th>
                <th scope="col" className="py-2 font-medium">Started</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => (
                <tr
                  key={run.id}
                  className="border-b border-neutral-100 align-top hover:bg-neutral-50 dark:border-neutral-900 dark:hover:bg-neutral-900/50"
                >
                  <td className="py-3 pr-4">
                    <Link href={`/runs/${run.id}`} className="font-medium underline-offset-2 hover:underline">
                      {run.artifact_name ?? run.id.slice(0, 8)}
                    </Link>
                    <div className="mt-0.5 font-mono text-xs text-neutral-500">
                      {run.artifact_sha256?.slice(0, 16) ?? "—"} ·{" "}
                      {formatBytes(run.artifact_size_bytes)}
                    </div>
                  </td>
                  <td className="py-3 pr-4">
                    <StatusText status={run.status} />
                    {run.error && (
                      <div className="mt-0.5 max-w-xs truncate font-mono text-xs text-red-600 dark:text-red-400">
                        {run.error}
                      </div>
                    )}
                  </td>
                  <td className="py-3 pr-4">
                    <SeverityRollup counts={run.severity_counts} />
                  </td>
                  <td className="py-3 pr-4 tabular-nums">
                    {run.new_since_previous === null ? (
                      <span className="text-neutral-400">first run</span>
                    ) : run.new_since_previous === 0 ? (
                      <span className="text-emerald-600 dark:text-emerald-400">no new</span>
                    ) : (
                      <span className="text-orange-600 dark:text-orange-400">
                        +{run.new_since_previous} new
                      </span>
                    )}
                  </td>
                  <td className="py-3 pr-4">
                    <div>{run.attested_by}</div>
                    <div
                      className="max-w-[16rem] truncate text-xs text-neutral-500"
                      title={run.attestation_reference}
                    >
                      {run.attestation_reference}
                    </div>
                  </td>
                  <td className="py-3 text-neutral-500">{formatTime(run.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
