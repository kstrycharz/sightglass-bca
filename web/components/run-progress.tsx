"use client";

/**
 * Live run progress over Server-Sent Events.
 *
 * SSE rather than WebSocket (§4): it survives corporate proxies that mangle
 * upgrade handshakes, and the browser reconnects on its own. When the run
 * reaches a terminal state the page refreshes once so the server-rendered
 * findings appear — no client-side duplication of the report view.
 */

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { StatusText } from "@/components/severity";

interface StageEvent {
  analyzer: string;
  status: string;
  duration_s: number | null;
}

interface ProgressEvent {
  status: string;
  stages: StageEvent[];
  finding_count: number;
  error?: string;
}

export function RunProgress({
  runId,
  initialStatus,
}: {
  runId: string;
  initialStatus: string;
}) {
  const router = useRouter();
  const [state, setState] = useState<ProgressEvent>({
    status: initialStatus,
    stages: [],
    finding_count: 0,
  });
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const source = new EventSource(`/api/runs/${runId}/events`);

    source.onopen = () => setConnected(true);
    source.onmessage = (event) => {
      const payload = JSON.parse(event.data) as ProgressEvent;
      setState(payload);
      if (payload.status === "completed" || payload.status === "failed") {
        source.close();
        // One refresh, not a poll: the finished view is server-rendered.
        router.refresh();
      }
    };
    source.onerror = () => setConnected(false);

    return () => source.close();
  }, [runId, router]);

  return (
    <section className="space-y-3 rounded-lg border border-sky-500/40 bg-sky-500/5 p-4">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="text-lg font-semibold">Scanning</h2>
        <StatusText status={state.status} />
        <span className="text-sm text-neutral-500">
          {state.finding_count} finding{state.finding_count === 1 ? "" : "s"} so far
        </span>
        <span className="ml-auto text-xs text-neutral-500">
          {connected ? "live" : "reconnecting…"}
        </span>
      </div>

      {state.stages.length === 0 ? (
        <p className="text-sm text-neutral-600 dark:text-neutral-400">
          Waiting for a worker to pick up the run. Each analyzer runs in its own
          disposable container with no network access.
        </p>
      ) : (
        <ul className="space-y-1 text-sm">
          {state.stages.map((stage) => (
            <li key={stage.analyzer} className="flex items-center gap-3">
              <span className="font-mono text-xs">{stage.analyzer}</span>
              <StatusText status={stage.status} />
              {stage.duration_s !== null && (
                <span className="text-xs tabular-nums text-neutral-500">
                  {stage.duration_s.toFixed(1)}s
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
