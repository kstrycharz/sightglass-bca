/**
 * Shared primitives.
 *
 * Deliberately small and unstyled-by-default. A security console lives or dies
 * on information density and consistency, so these enforce one spacing scale
 * and one severity palette rather than offering options.
 */

import type { ReactNode } from "react";
import type { Severity } from "@/lib/api";

/* ---------------------------------------------------------------- severity */

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-critical-bg text-critical border-critical/30",
  high: "bg-high-bg text-high border-high/30",
  medium: "bg-medium-bg text-medium border-medium/30",
  low: "bg-low-bg text-low border-low/30",
  info: "bg-info-bg text-info border-info/30",
};

export function SeverityTag({
  severity,
  size = "sm",
}: {
  severity: Severity;
  size?: "sm" | "xs";
}) {
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded border font-medium uppercase tracking-wider ${
        SEVERITY_STYLE[severity]
      } ${size === "xs" ? "px-1 py-px text-[10px]" : "px-1.5 py-0.5 text-[11px]"}`}
    >
      {severity}
    </span>
  );
}

/** A severity count bar. Fixed order — a bar whose columns move between runs
 *  is unreadable at a glance, which defeats the point of a rollup. */
export function SeverityBar({
  counts,
  total,
}: {
  counts: Partial<Record<Severity, number>>;
  total?: number;
}) {
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  const present = order.filter((s) => (counts[s] ?? 0) > 0);

  if (present.length === 0) {
    return <span className="text-sm text-content-subtle">—</span>;
  }

  return (
    <span className="flex items-center gap-1">
      {present.map((severity) => (
        <span
          key={severity}
          className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${SEVERITY_STYLE[severity]}`}
          title={`${counts[severity]} ${severity}`}
        >
          <span className="uppercase tracking-wider">{severity.slice(0, 4)}</span>
          <span className="tnum">{counts[severity]}</span>
        </span>
      ))}
      {total !== undefined && total > 0 && (
        <span className="ml-1 text-xs text-content-subtle tnum">{total}</span>
      )}
    </span>
  );
}

/* ------------------------------------------------------------------ status */

const STATUS_STYLE: Record<string, string> = {
  completed: "text-ok",
  running: "text-accent",
  queued: "text-content-muted",
  pending: "text-content-subtle",
  failed: "text-critical",
  timeout: "text-high",
  oom: "text-high",
  cancelled: "text-content-subtle",
  skipped: "text-content-subtle",
};

export function StatusDot({ status, label }: { status: string; label?: string }) {
  const active = status === "running" || status === "queued";
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-sm ${
        STATUS_STYLE[status] ?? "text-content-muted"
      }`}
    >
      <span
        className={`h-1.5 w-1.5 shrink-0 rounded-full bg-current ${active ? "animate-pulse" : ""}`}
        aria-hidden
      />
      {label ?? status}
    </span>
  );
}

/* ------------------------------------------------------------------- shell */

export function Panel({
  title,
  description,
  actions,
  children,
  className = "",
}: {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section
      className={`rounded-lg border border-border bg-surface shadow-[0_1px_2px_rgba(0,0,0,0.03)] ${className}`}
    >
      {(title || actions) && (
        <header className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-border px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {description && (
              <p className="mt-0.5 text-xs text-content-muted">{description}</p>
            )}
          </div>
          {actions && <div className="ml-auto flex items-center gap-2">{actions}</div>}
        </header>
      )}
      {children}
    </section>
  );
}

export function Metric({
  label,
  value,
  hint,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: "neutral" | "good" | "warn" | "bad";
}) {
  const toneClass =
    tone === "good"
      ? "text-ok"
      : tone === "warn"
        ? "text-high"
        : tone === "bad"
          ? "text-critical"
          : "text-content";
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wider text-content-subtle">
        {label}
      </div>
      <div className={`mt-1 text-xl font-semibold tnum ${toneClass}`}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-content-muted">{hint}</div>}
    </div>
  );
}

export function Mono({
  children,
  className = "",
  title,
}: {
  children: ReactNode;
  className?: string;
  title?: string;
}) {
  return (
    <span className={`font-mono text-xs ${className}`} title={title}>
      {children}
    </span>
  );
}

export function Button({
  children,
  variant = "secondary",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost";
}) {
  const styles = {
    primary:
      "bg-content text-surface hover:opacity-90 border-transparent",
    secondary:
      "bg-surface text-content border-border hover:bg-surface-raised",
    ghost: "bg-transparent text-content-muted border-transparent hover:text-content",
  }[variant];

  return (
    <button
      {...props}
      className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${styles} ${
        props.className ?? ""
      }`}
    >
      {children}
    </button>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <p className="text-sm font-medium">{title}</p>
      {children && (
        <p className="mt-1.5 max-w-md text-sm text-content-muted">{children}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorNotice({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="rounded-lg border border-critical/30 bg-critical-bg px-4 py-3">
      <p className="text-sm font-medium text-critical">{title}</p>
      {detail && (
        <p className="mt-1 break-words font-mono text-xs text-content-muted">{detail}</p>
      )}
    </div>
  );
}

/* -------------------------------------------------------------- formatting */

export function bytes(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = value / 1024;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${scaled < 10 ? scaled.toFixed(1) : Math.round(scaled)} ${units[unit]}`;
}

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds % 60)}s`;
}

export function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  const delta = Date.now() - then;
  const minute = 60_000;
  if (delta < minute) return "just now";
  if (delta < 60 * minute) return `${Math.floor(delta / minute)}m ago`;
  if (delta < 24 * 60 * minute) return `${Math.floor(delta / (60 * minute))}h ago`;
  if (delta < 7 * 24 * 60 * minute) return `${Math.floor(delta / (24 * 60 * minute))}d ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
