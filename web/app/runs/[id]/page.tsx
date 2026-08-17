import Link from "next/link";
import { notFound } from "next/navigation";
import { api, type Finding, type RunDetail } from "@/lib/api";
import {
  ErrorNotice,
  Metric,
  Mono,
  Panel,
  StatusDot,
  bytes,
  duration,
  relativeTime,
} from "@/components/ui";
import { ArtifactTree } from "@/components/artifact-tree";
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
    /* a queued run has no findings yet */
  }

  const active = run.status === "queued" || run.status === "running";
  const blocking =
    (run.severity_counts.critical ?? 0) + (run.severity_counts.high ?? 0);
  const degraded = run.stages.filter((s) => s.status !== "completed");

  return (
    <div className="space-y-5">
      <header>
        <Link
          href="/"
          className="text-xs text-content-muted underline-offset-2 hover:underline"
        >
          ← Runs
        </Link>
        <div className="mt-1.5 flex flex-wrap items-baseline gap-x-3 gap-y-1">
          <h1 className="text-xl font-semibold tracking-tight">
            {run.artifact_name ?? run.id.slice(0, 8)}
          </h1>
          <StatusDot status={run.status} />
          <span className="text-xs text-content-subtle">
            {relativeTime(run.created_at)}
          </span>
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 text-xs text-content-subtle">
          <Mono title={run.artifact_sha256 ?? undefined}>
            sha256:{run.artifact_sha256?.slice(0, 24)}
          </Mono>
          <span>{bytes(run.artifact_size_bytes)}</span>
          {run.attestation_reference && <span>· {run.attestation_reference}</span>}
        </div>
      </header>

      {run.error && <ErrorNotice title="Run failed" detail={run.error} />}

      {active ? (
        <RunProgress runId={run.id} initialStatus={run.status} />
      ) : (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Metric
              label="Release-blocking"
              value={blocking}
              hint="critical + high"
              tone={blocking > 0 ? "bad" : "good"}
            />
            <Metric label="Total findings" value={run.finding_count} />
            <Metric
              label="Files analysed"
              value={run.artifact_count}
              hint={run.artifact_count > 1 ? "unpacked recursively" : "no nested containers"}
            />
            <Metric
              label="New vs previous"
              value={run.new_since_previous ?? "—"}
              hint={run.previous_run_id ? "since last run" : "baseline run"}
              tone={run.new_since_previous ? "warn" : "neutral"}
            />
          </div>

          <div className="grid gap-5 lg:grid-cols-3">
            <Panel title="Analyzer stages" className="lg:col-span-2">
              <div className="scroll-x">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-[11px] uppercase tracking-wider text-content-subtle">
                      <th scope="col" className="px-4 py-1.5 font-medium">Analyzer</th>
                      <th scope="col" className="px-2 py-1.5 font-medium">Status</th>
                      <th scope="col" className="px-2 py-1.5 font-medium">Duration</th>
                      <th scope="col" className="px-2 py-1.5 font-medium">Output</th>
                      <th scope="col" className="px-4 py-1.5 font-medium">Image</th>
                    </tr>
                  </thead>
                  <tbody>
                    {run.stages.map((stage) => (
                      <tr key={stage.analyzer} className="border-b border-border/60 last:border-0">
                        <td className="px-4 py-1.5 font-mono text-xs">{stage.analyzer}</td>
                        <td className="px-2 py-1.5">
                          <StatusDot status={stage.status} />
                        </td>
                        <td className="px-2 py-1.5 tnum text-content-muted">
                          {duration(stage.duration_s)}
                        </td>
                        <td className="px-2 py-1.5 tnum text-content-muted">
                          {stage.evidence_count}
                        </td>
                        <td className="px-4 py-1.5">
                          <Mono className="text-content-subtle" title={stage.image_digest ?? ""}>
                            {stage.image_digest?.split(":").pop()?.slice(0, 12) ?? "—"}
                          </Mono>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {degraded.length > 0 && (
                <p className="border-t border-border bg-high-bg px-4 py-2 text-xs text-high">
                  {degraded.length} analyzer(s) degraded. Findings below are
                  incomplete — a timed-out analyzer is not a clean artifact.
                </p>
              )}
            </Panel>

            {run.manifest && (
              <Panel
                title="Run manifest"
                description="Two runs sharing a fingerprint produce identical findings."
              >
                <dl className="space-y-1.5 px-4 py-3 text-xs">
                  <ManifestRow label="fingerprint" value={run.manifest.fingerprint.slice(0, 20)} />
                  <ManifestRow label="sightglass" value={run.manifest.sightglass_version} />
                  <ManifestRow
                    label="rule pack"
                    value={`${run.manifest.rule_pack_version} · ${run.manifest.rule_pack_hash.slice(0, 10)}`}
                  />
                  {Object.entries(run.manifest.tool_versions).map(([tool, version]) => (
                    <ManifestRow key={tool} label={tool} value={String(version).slice(0, 28)} />
                  ))}
                </dl>
              </Panel>
            )}
          </div>

          {run.artifact_tree && (
            <Panel
              title="Artifact tree"
              description="Recursively unpacked. Badges show findings per file."
            >
              <ArtifactTree root={run.artifact_tree} />
            </Panel>
          )}

          <FindingsExplorer
            runId={run.id}
            initialFindings={findings}
            llmEnabled={run.llm_enabled}
          />
        </>
      )}
    </div>
  );
}

// Next.js page modules may only export a fixed set of names, so shared helpers
// stay local rather than being re-exported from here.
function ManifestRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="shrink-0 text-content-subtle">{label}</dt>
      <dd className="truncate font-mono" title={value}>
        {value}
      </dd>
    </div>
  );
}

