import Link from "next/link";
import { notFound } from "next/navigation";
import {
  api,
  formatBytes,
  formatDuration,
  formatTime,
  type Finding,
  type RunDetail,
} from "@/lib/api";
import { SeverityRollup, StatusText } from "@/components/severity";
import { FindingsExplorer } from "@/components/findings-explorer";
import { RunProgress } from "@/components/run-progress";

export const dynamic = "force-dynamic";

export default async function RunPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;

  let run: RunDetail;
  try {
    run = await api.getRun(id);
  } catch {
    notFound();
  }

  let findings: Finding[] = [];
  try {
    findings = await api.listFindings(id);
  } catch {
    /* a run that is still queued has no findings yet */
  }

  const active = run.status === "queued" || run.status === "running";

  return (
    <div className="space-y-8">
      <div>
        <Link href="/" className="text-sm text-neutral-500 underline-offset-2 hover:underline">
          ← All runs
        </Link>
        <div className="mt-2 flex flex-wrap items-baseline gap-x-4 gap-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">
            {run.artifact_name ?? run.id.slice(0, 8)}
          </h1>
          <StatusText status={run.status} />
        </div>
        <p className="mt-1 font-mono text-xs text-neutral-500">
          sha256 {run.artifact_sha256} · {formatBytes(run.artifact_size_bytes)}
        </p>
      </div>

      {run.error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/5 p-4">
          <p className="font-medium text-red-700 dark:text-red-400">Run failed</p>
          <p className="mt-1 font-mono text-xs">{run.error}</p>
        </div>
      )}

      {/* Live progress replaces itself with the static stage list once terminal. */}
      {active ? (
        <RunProgress runId={run.id} initialStatus={run.status} />
      ) : (
        <section className="space-y-2">
          <h2 className="text-lg font-semibold">Stages</h2>
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left dark:border-neutral-800">
                  <th scope="col" className="py-2 pr-4 font-medium">Analyzer</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Status</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Duration</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Evidence</th>
                  <th scope="col" className="py-2 font-medium">Image</th>
                </tr>
              </thead>
              <tbody>
                {run.stages.map((stage) => (
                  <tr key={stage.analyzer} className="border-b border-neutral-100 dark:border-neutral-900">
                    <td className="py-2 pr-4 font-mono text-xs">{stage.analyzer}</td>
                    <td className="py-2 pr-4"><StatusText status={stage.status} /></td>
                    <td className="py-2 pr-4 tabular-nums">{formatDuration(stage.duration_s)}</td>
                    <td className="py-2 pr-4 tabular-nums">{stage.evidence_count}</td>
                    <td className="py-2 font-mono text-xs text-neutral-500">
                      {stage.image_digest?.slice(0, 24) ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {run.stages.some((s) => s.status !== "completed") && (
            <p className="text-xs text-orange-700 dark:text-orange-400">
              One or more analyzers degraded. Findings below are incomplete — a
              timed-out analyzer is not the same as a clean artifact.
            </p>
          )}
        </section>
      )}

      <section className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-1 lg:col-span-1">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            Summary
          </h2>
          <SeverityRollup counts={run.severity_counts} total={run.finding_count} />
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            Started {formatTime(run.created_at)}
          </p>
          {run.new_since_previous !== null && (
            <p className="text-sm">
              <span className="text-neutral-500">vs previous run: </span>
              {run.new_since_previous === 0 ? (
                <span className="text-emerald-600 dark:text-emerald-400">no new findings</span>
              ) : (
                <span className="text-orange-600 dark:text-orange-400">
                  {run.new_since_previous} new
                </span>
              )}
            </p>
          )}
        </div>

        <div className="space-y-1 lg:col-span-1">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
            Attestation
          </h2>
          <p className="text-sm">{run.attested_by}</p>
          <p className="text-sm text-neutral-600 dark:text-neutral-400">
            {run.attestation_reference}
          </p>
        </div>

        {run.manifest && (
          <div className="space-y-1 lg:col-span-1">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-neutral-500">
              Run manifest
            </h2>
            <dl className="space-y-0.5 font-mono text-xs">
              <div>
                <span className="text-neutral-500">sightglass </span>
                {run.manifest.sightglass_version}
              </div>
              <div>
                <span className="text-neutral-500">rules </span>
                {run.manifest.rule_pack_version} ({run.manifest.rule_pack_hash.slice(0, 12)})
              </div>
              <div>
                <span className="text-neutral-500">fingerprint </span>
                {run.manifest.fingerprint.slice(0, 16)}
              </div>
            </dl>
            <p className="text-xs text-neutral-500">
              Two runs with a matching fingerprint produce identical findings.
            </p>
          </div>
        )}
      </section>

      {run.artifact_tree && (
        <section className="space-y-2">
          <h2 className="text-lg font-semibold">Artifact</h2>
          <div className="rounded-lg border border-neutral-200 p-3 text-sm dark:border-neutral-800">
            <div className="font-mono text-xs">{run.artifact_tree.path_in_tree}</div>
            <div className="mt-1 text-xs text-neutral-500">
              {run.artifact_tree.kind}
              {run.artifact_tree.architecture && ` · ${run.artifact_tree.architecture}`}
              {run.artifact_tree.media_type && ` · ${run.artifact_tree.media_type}`}
              {" · "}
              {formatBytes(run.artifact_tree.size_bytes)}
            </div>
            {run.artifact_tree.children.length === 0 && (
              <p className="mt-2 text-xs text-neutral-500">
                Recursive unpacking arrives in M2 — nested installers, archives,
                and firmware images will appear here as a tree.
              </p>
            )}
          </div>
        </section>
      )}

      <FindingsExplorer runId={run.id} initialFindings={findings} llmEnabled={run.llm_enabled} />
    </div>
  );
}
