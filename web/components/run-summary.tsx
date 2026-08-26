"use client";

/**
 * The `summarize` role: one reviewer-facing paragraph over the whole run.
 *
 * Placed at the top of the run page because that is where a briefing belongs,
 * but generated on request rather than automatically — a scan must be complete
 * and useful with no model configured at all (§2.5), so nothing here may run
 * as a side effect of opening the page.
 *
 * The panel states the role, the model, and when it ran. Before this, the only
 * AI output in the product was an unlabelled box on an expanded finding, which
 * left no way to tell what had produced it or when.
 */

import { useState } from "react";
import type { SummaryResponse } from "@/lib/api";
import { Button, Panel, relativeTime } from "@/components/ui";

export function RunSummary({
  runId,
  initialSummary,
  initialModel,
  initialAt,
}: {
  runId: string;
  initialSummary: string | null;
  initialModel: string | null;
  initialAt: string | null;
}) {
  const [summary, setSummary] = useState(initialSummary);
  const [model, setModel] = useState(initialModel);
  const [at, setAt] = useState(initialAt);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      // Through the proxy route, not `lib/api` — that module is server-only.
      const response = await fetch(`/api/runs/${runId}/summarize`, { method: "POST" });
      const body = await response.json();
      if (!response.ok) {
        throw new Error(body.detail ?? `summarize failed (HTTP ${response.status})`);
      }
      const result = body as SummaryResponse;
      setSummary(result.summary);
      setModel(result.model);
      setAt(new Date().toISOString());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel
      title="AI summary"
      description="Advisory. Written from the findings below — it cannot add, remove, or re-rank them."
      actions={
        <Button onClick={run} disabled={busy}>
          {busy ? "Writing…" : summary ? "Regenerate" : "Write summary"}
        </Button>
      }
    >
      <div className="px-4 py-4">
        {summary ? (
          <>
            <p className="whitespace-pre-wrap text-sm leading-relaxed">{summary}</p>
            <p className="mt-2.5 text-xs text-content-muted">
              Written by <span className="font-mono">{model ?? "an AI model"}</span>
              {at && ` · ${relativeTime(at)}`}.
            </p>
          </>
        ) : (
          <p className="text-sm text-content-muted">
            No summary yet. The report below is complete without one — this adds a
            plain-language briefing over the same findings.
          </p>
        )}
        {error && <p className="mt-2 text-xs text-critical">{error}</p>}
      </div>
    </Panel>
  );
}
