import type { Severity } from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/api";

const STYLES: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-700 ring-red-500/30 dark:text-red-300",
  high: "bg-orange-500/15 text-orange-700 ring-orange-500/30 dark:text-orange-300",
  medium: "bg-amber-500/15 text-amber-700 ring-amber-500/30 dark:text-amber-300",
  low: "bg-sky-500/15 text-sky-700 ring-sky-500/30 dark:text-sky-300",
  info: "bg-neutral-500/15 text-neutral-700 ring-neutral-500/30 dark:text-neutral-300",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide ring-1 ring-inset ${STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

/**
 * Severity rollup. Always rendered in severity order, never in count order —
 * a bar whose columns move between runs is unreadable at a glance.
 */
export function SeverityRollup({
  counts,
  total,
}: {
  counts: Partial<Record<Severity, number>>;
  total?: number;
}) {
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  if (present.length === 0) {
    return <span className="text-sm text-neutral-500">no findings</span>;
  }
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {present.map((severity) => (
        <span key={severity} className="inline-flex items-center gap-1">
          <SeverityBadge severity={severity} />
          <span className="text-sm tabular-nums">{counts[severity]}</span>
        </span>
      ))}
      {total !== undefined && (
        <span className="ml-1 text-sm text-neutral-500">({total} total)</span>
      )}
    </span>
  );
}

const STATUS_STYLES: Record<string, string> = {
  completed: "text-emerald-600 dark:text-emerald-400",
  running: "text-sky-600 dark:text-sky-400",
  queued: "text-neutral-500",
  failed: "text-red-600 dark:text-red-400",
  timeout: "text-orange-600 dark:text-orange-400",
  oom: "text-orange-600 dark:text-orange-400",
  cancelled: "text-neutral-500",
  pending: "text-neutral-500",
};

export function StatusText({ status }: { status: string }) {
  const spinning = status === "running" || status === "queued";
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-sm font-medium ${
        STATUS_STYLES[status] ?? "text-neutral-500"
      }`}
    >
      {spinning && (
        <span className="inline-block h-1.5 w-1.5 animate-pulse rounded-full bg-current" />
      )}
      {status}
    </span>
  );
}
