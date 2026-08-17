"use client";

/**
 * Findings explorer.
 *
 * The "deterministic view only" toggle is the important control here (§2.5).
 * When it is on, every AI-derived field disappears — verdicts, reasoning,
 * model attribution — and what remains is exactly what the scanner would have
 * produced with no model configured at all. A user must always be able to
 * answer "would this finding exist without the AI?", and the honest way to
 * answer it is to show them.
 */

import { useMemo, useState } from "react";
import {
  SEVERITY_ORDER,
  formatDuration,
  type Finding,
  type Severity,
  type TriageResponse,
} from "@/lib/api";
import { SeverityBadge } from "@/components/severity";

const STATUS_LABELS: Record<string, string> = {
  open: "Open",
  confirmed: "Confirmed",
  needs_review: "Needs review",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  fixed: "Fixed",
};

export function FindingsExplorer({
  runId,
  initialFindings,
  llmEnabled,
}: {
  runId: string;
  initialFindings: Finding[];
  llmEnabled: boolean;
}) {
  const [findings, setFindings] = useState(initialFindings);
  const [deterministicOnly, setDeterministicOnly] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set());
  const [newOnly, setNewOnly] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [triaging, setTriaging] = useState(false);
  const [triageResult, setTriageResult] = useState<TriageResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const visible = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter.size > 0 && !severityFilter.has(f.severity)) return false;
      if (newOnly && !f.is_new) return false;
      return true;
    });
  }, [findings, severityFilter, newOnly]);

  const counts = useMemo(() => {
    const result: Partial<Record<Severity, number>> = {};
    for (const f of findings) result[f.severity] = (result[f.severity] ?? 0) + 1;
    return result;
  }, [findings]);

  function toggleSeverity(severity: Severity) {
    const next = new Set(severityFilter);
    if (next.has(severity)) next.delete(severity);
    else next.add(severity);
    setSeverityFilter(next);
  }

  async function runTriage() {
    setTriaging(true);
    setError(null);
    try {
      const response = await fetch(`/api/runs/${runId}/triage`, { method: "POST" });
      if (!response.ok) {
        const body = (await response.json().catch(() => ({}))) as { detail?: string };
        throw new Error(body.detail ?? response.statusText);
      }
      setTriageResult((await response.json()) as TriageResponse);
      const refreshed = await fetch(`/api/runs/${runId}/findings`);
      setFindings((await refreshed.json()) as Finding[]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setTriaging(false);
    }
  }

  async function setStatus(finding: Finding, status: string) {
    const response = await fetch(`/api/runs/${runId}/findings/${finding.id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    if (response.ok) {
      const updated = (await response.json()) as Finding;
      setFindings((current) => current.map((f) => (f.id === updated.id ? updated : f)));
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <h2 className="text-lg font-semibold">Findings</h2>

        <div className="flex flex-wrap items-center gap-1.5">
          {SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0).map((severity) => {
            const active = severityFilter.has(severity);
            return (
              <button
                key={severity}
                type="button"
                onClick={() => toggleSeverity(severity)}
                aria-pressed={active}
                className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs ring-1 ring-inset transition-opacity ${
                  active
                    ? "ring-neutral-900 dark:ring-neutral-100"
                    : "opacity-60 ring-transparent hover:opacity-100"
                }`}
              >
                <SeverityBadge severity={severity} />
                <span className="tabular-nums">{counts[severity]}</span>
              </button>
            );
          })}
        </div>

        <label className="flex items-center gap-1.5 text-sm">
          <input type="checkbox" checked={newOnly} onChange={(e) => setNewOnly(e.target.checked)} />
          New only
        </label>

        <label className="ml-auto flex items-center gap-1.5 text-sm">
          <input
            type="checkbox"
            checked={deterministicOnly}
            onChange={(e) => setDeterministicOnly(e.target.checked)}
          />
          <span title="Hide every AI-derived field, showing exactly what the scanner produces with no model configured.">
            Deterministic view only
          </span>
        </label>

        {llmEnabled && !deterministicOnly && (
          <button
            type="button"
            onClick={runTriage}
            disabled={triaging || findings.length === 0}
            className="rounded-md border border-neutral-300 px-2.5 py-1 text-sm transition-colors hover:bg-neutral-100 disabled:opacity-40 dark:border-neutral-700 dark:hover:bg-neutral-900"
          >
            {triaging ? "Triaging…" : "Run AI triage"}
          </button>
        )}
      </div>

      {deterministicOnly && (
        <p className="rounded-md border border-neutral-300 bg-neutral-50 p-2 text-xs text-neutral-600 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-400">
          Showing rule output only. Every finding below exists without any model
          involvement.
        </p>
      )}

      {triageResult && !deterministicOnly && (
        <p className="rounded-md border border-sky-500/40 bg-sky-500/5 p-2 text-xs text-neutral-700 dark:text-neutral-300">
          Triaged {triageResult.triaged} with{" "}
          <span className="font-mono">{triageResult.model}</span> in{" "}
          {formatDuration(triageResult.duration_s)} — {triageResult.confirmed} confirmed,{" "}
          {triageResult.dismissed} dismissed, {triageResult.needs_review} need review
          {triageResult.errors > 0 && `, ${triageResult.errors} errored`}.
        </p>
      )}

      {error && (
        <p className="rounded-md border border-red-500/40 bg-red-500/5 p-2 text-sm text-red-700 dark:text-red-400">
          {error}
        </p>
      )}

      {visible.length === 0 ? (
        <p className="rounded-lg border border-dashed border-neutral-300 p-8 text-center text-sm text-neutral-500 dark:border-neutral-700">
          {findings.length === 0
            ? "No findings. Either this artifact is clean, or check the stage list above for a degraded analyzer."
            : "No findings match the current filters."}
        </p>
      ) : (
        <ul className="space-y-2">
          {visible.map((finding) => {
            const open = expanded === finding.id;
            return (
              <li
                key={finding.id}
                className="rounded-lg border border-neutral-200 dark:border-neutral-800"
              >
                <button
                  type="button"
                  onClick={() => setExpanded(open ? null : finding.id)}
                  aria-expanded={open}
                  className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 p-3 text-left hover:bg-neutral-50 dark:hover:bg-neutral-900/50"
                >
                  <SeverityBadge severity={finding.severity} />
                  <span className="font-medium">{finding.title}</span>
                  <code className="rounded bg-neutral-100 px-1.5 py-0.5 text-xs dark:bg-neutral-900">
                    {finding.value_masked}
                  </code>
                  {finding.is_new && (
                    <span className="rounded bg-orange-500/15 px-1.5 py-0.5 text-xs text-orange-700 dark:text-orange-300">
                      new
                    </span>
                  )}
                  <span className="text-xs text-neutral-500">
                    {finding.location_count} location{finding.location_count === 1 ? "" : "s"}
                  </span>
                  {!deterministicOnly && finding.llm && (
                    <span className="rounded bg-violet-500/15 px-1.5 py-0.5 text-xs text-violet-700 dark:text-violet-300">
                      AI: {finding.llm.verdict.replace(/_/g, " ")}
                    </span>
                  )}
                  <span className="ml-auto text-xs text-neutral-500">
                    {STATUS_LABELS[finding.status] ?? finding.status}
                  </span>
                </button>

                {open && (
                  <div className="space-y-4 border-t border-neutral-200 p-4 text-sm dark:border-neutral-800">
                    <dl className="grid grid-cols-2 gap-x-6 gap-y-2 sm:grid-cols-4">
                      <Detail label="Rule" value={finding.rule_id} mono />
                      <Detail label="Category" value={finding.category} />
                      <Detail
                        label="Entropy"
                        value={finding.entropy?.toFixed(2) ?? "—"}
                      />
                      <Detail label="CWE" value={finding.cwe ?? "—"} />
                      <Detail
                        label="Confidence"
                        value={finding.confidence.toFixed(2)}
                      />
                      <Detail label="Detected by" value={deterministicOnly ? "rule" : finding.detected_by} />
                      <Detail label="Finding ID" value={finding.id.slice(0, 16)} mono />
                    </dl>

                    <div>
                      <h4 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
                        Locations
                      </h4>
                      <ul className="mt-1 space-y-0.5 font-mono text-xs">
                        {finding.locations.map((location, index) => (
                          <li key={index}>
                            {location.path_in_tree}
                            {location.offset !== null && (
                              <>
                                {" @ "}
                                <span className="text-neutral-500">
                                  0x{location.offset.toString(16)}
                                </span>
                              </>
                            )}
                            {location.encoding && (
                              <span className="ml-2 rounded bg-neutral-100 px-1 dark:bg-neutral-900">
                                {location.encoding}
                              </span>
                            )}
                          </li>
                        ))}
                      </ul>
                    </div>

                    {finding.context_snippet && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
                          Context (value masked)
                        </h4>
                        <pre className="mt-1 overflow-x-auto rounded bg-neutral-100 p-2 text-xs dark:bg-neutral-900">
                          {finding.context_snippet}
                        </pre>
                      </div>
                    )}

                    {!deterministicOnly && finding.llm && (
                      <div className="rounded border border-violet-500/40 bg-violet-500/5 p-3">
                        <h4 className="text-xs font-semibold uppercase tracking-wide text-violet-700 dark:text-violet-300">
                          AI assessment — advisory
                        </h4>
                        <p className="mt-1">{finding.llm.reasoning}</p>
                        <p className="mt-2 text-xs text-neutral-500">
                          Verdict{" "}
                          <span className="font-medium">
                            {finding.llm.verdict.replace(/_/g, " ")}
                          </span>{" "}
                          from <span className="font-mono">{finding.llm.model}</span>. The
                          finding, its severity, and its offsets come from the rule and are
                          unchanged by this assessment.
                        </p>
                      </div>
                    )}

                    {finding.remediation_md && (
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wide text-neutral-500">
                          Remediation
                        </h4>
                        <pre className="mt-1 whitespace-pre-wrap font-sans text-sm">
                          {finding.remediation_md}
                        </pre>
                      </div>
                    )}

                    <div className="flex flex-wrap gap-2 pt-1">
                      {["confirmed", "false_positive", "accepted_risk", "fixed"].map((status) => (
                        <button
                          key={status}
                          type="button"
                          onClick={() => setStatus(finding, status)}
                          disabled={finding.status === status}
                          className="rounded border border-neutral-300 px-2 py-1 text-xs transition-colors hover:bg-neutral-100 disabled:opacity-40 dark:border-neutral-700 dark:hover:bg-neutral-900"
                        >
                          {STATUS_LABELS[status]}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-neutral-500">{label}</dt>
      <dd className={mono ? "font-mono text-xs" : ""}>{value}</dd>
    </div>
  );
}
