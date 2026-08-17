"use client";

/**
 * Live run progress over Server-Sent Events.
 *
 * SSE rather than WebSocket (§4): it survives corporate proxies that mangle
 * upgrade handshakes, and the browser reconnects on its own. When the run
 * reaches a terminal state the page refreshes once so the server-rendered
 * report appears — no client-side duplication of the report view.
 */

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Panel, StatusDot, duration } from "@/components/ui";

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

const STAGE_DESCRIPTION: Record<string, string> = {
  unpack: "Recursively extracting nested containers",
  static: "Extracting strings and matching rules",
};

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
    <Panel
      title="Scanning"
      actions={
        <span className="text-xs text-content-subtle">
          {connected ? "live" : "reconnecting…"}
        </span>
      }
    >
      <div className="flex flex-wrap items-center gap-3 border-b border-border px-4 py-2.5">
        <StatusDot status={state.status} />
        <span className="text-sm text-content-muted">
          {state.finding_count} finding{state.finding_count === 1 ? "" : "s"} so far
        </span>
      </div>

      {state.stages.length === 0 ? (
        <p className="px-4 py-6 text-sm text-content-muted">
          Waiting for a worker to pick up the run. Each analyzer runs in its own
          disposable container with no network access.
        </p>
      ) : (
        <ul>
          {state.stages.map((stage) => (
            <li
              key={stage.analyzer}
              className="flex flex-wrap items-center gap-3 border-b border-border/60 px-4 py-2 last:border-0"
            >
              <span className="w-16 shrink-0 font-mono text-xs">{stage.analyzer}</span>
              <StatusDot status={stage.status} />
              <span className="text-xs text-content-subtle">
                {STAGE_DESCRIPTION[stage.analyzer] ?? ""}
              </span>
              {stage.duration_s !== null && (
                <span className="ml-auto text-xs text-content-subtle tnum">
                  {duration(stage.duration_s)}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
