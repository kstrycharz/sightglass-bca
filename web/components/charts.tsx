/**
 * Chart primitives.
 *
 * Hand-built inline SVG rather than a charting library, for three reasons that
 * all matter here: the dashboard must render with JavaScript disabled (§4), an
 * air-gapped bundle should not carry a charting runtime it does not need, and
 * these charts are simple enough that a library would cost more in
 * configuration than it saves in code.
 *
 * Colour is reserved almost entirely for severity. A security console where
 * everything is coloured is one where severity is invisible, which defeats the
 * only job the colour has.
 */

import type { ReactNode } from "react";
import type { Severity } from "@/lib/api";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_VAR: Record<Severity, string> = {
  critical: "var(--color-critical)",
  high: "var(--color-high)",
  medium: "var(--color-medium)",
  low: "var(--color-low)",
  info: "var(--color-info)",
};

/* ------------------------------------------------------------------ donut */

/**
 * Severity distribution as a ring.
 *
 * The centre carries the number that decides whether a release ships, so the
 * ring is context and the label is the answer — not the other way round.
 */
export function SeverityDonut({
  counts,
  size = 180,
  thickness = 18,
  centerValue,
  centerLabel,
}: {
  counts: Partial<Record<Severity, number>>;
  size?: number;
  thickness?: number;
  centerValue?: ReactNode;
  centerLabel?: string;
}) {
  const segments = SEVERITY_ORDER.map((severity) => ({
    severity,
    value: counts[severity] ?? 0,
  })).filter((s) => s.value > 0);

  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const radius = (size - thickness) / 2;
  const circumference = 2 * Math.PI * radius;
  const gap = total > 1 ? 1.5 : 0;

  let offset = 0;

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        role="img"
        aria-label={
          total === 0
            ? "No findings"
            : `Severity distribution: ${segments.map((s) => `${s.value} ${s.severity}`).join(", ")}`
        }
      >
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="none"
          stroke="var(--color-surface-sunken)"
          strokeWidth={thickness}
        />
        {segments.map(({ severity, value }) => {
          const fraction = value / total;
          const length = Math.max(circumference * fraction - gap, 0.5);
          const dash = `${length} ${circumference - length}`;
          const rotation = (offset / total) * 360 - 90;
          offset += value;
          return (
            <circle
              key={severity}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={SEVERITY_VAR[severity]}
              strokeWidth={thickness}
              strokeDasharray={dash}
              strokeLinecap="butt"
              transform={`rotate(${rotation} ${size / 2} ${size / 2})`}
            />
          );
        })}
      </svg>
      <div className="pointer-events-none absolute flex flex-col items-center">
        <span className="text-2xl font-semibold tnum leading-none">
          {centerValue ?? total}
        </span>
        {centerLabel && (
          <span className="mt-1 text-[10px] uppercase tracking-wider text-content-subtle">
            {centerLabel}
          </span>
        )}
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- bar list */

/** Horizontal bars. Sorted by value, because a ranking is the point. */
export function BarList({
  items,
  max,
  formatValue,
}: {
  items: { label: string; value: number; tone?: Severity }[];
  max?: number;
  formatValue?: (value: number) => string;
}) {
  const ceiling = max ?? Math.max(1, ...items.map((i) => i.value));

  if (items.length === 0) {
    return <p className="px-4 py-6 text-sm text-content-subtle">No data</p>;
  }

  return (
    <ul className="space-y-1.5 px-4 py-3">
      {items.map((item) => (
        <li key={item.label}>
          <div className="flex items-baseline justify-between gap-3 text-sm">
            <span className="min-w-0 truncate" title={item.label}>
              {item.label}
            </span>
            <span className="shrink-0 tnum text-content-muted">
              {formatValue ? formatValue(item.value) : item.value}
            </span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-surface-sunken">
            <div
              className="h-full rounded-full"
              style={{
                width: `${Math.max((item.value / ceiling) * 100, 2)}%`,
                background: item.tone ? SEVERITY_VAR[item.tone] : "var(--color-accent)",
              }}
            />
          </div>
        </li>
      ))}
    </ul>
  );
}

/* ------------------------------------------------------------ stacked bars */

/**
 * Severity mix per run, oldest to newest.
 *
 * The question this answers is the one CI asks — "is this getting better or
 * worse?" — so the axis is runs, not time, and the bars are stacked by
 * severity rather than totalled.
 */
export function TrendBars({
  series,
  height = 120,
}: {
  series: { label: string; counts: Partial<Record<Severity, number>>; href?: string }[];
  height?: number;
}) {
  if (series.length === 0) {
    return <p className="px-4 py-6 text-sm text-content-subtle">No completed runs yet</p>;
  }

  const totals = series.map((s) =>
    SEVERITY_ORDER.reduce((sum, sev) => sum + (s.counts[sev] ?? 0), 0),
  );
  const ceiling = Math.max(1, ...totals);
  const barWidth = Math.max(100 / series.length - 2, 4);

  return (
    <div className="px-4 py-3">
      <div className="flex items-end gap-[2%]" style={{ height }}>
        {series.map((entry, index) => {
          const total = totals[index] ?? 0;
          const barHeight = total === 0 ? 2 : Math.max((total / ceiling) * height, 3);
          return (
            <div
              key={`${entry.label}-${index}`}
              className="flex flex-col justify-end"
              style={{ width: `${barWidth}%`, height }}
              title={`${entry.label}: ${total} findings`}
            >
              <div
                className="flex w-full flex-col-reverse overflow-hidden rounded-sm"
                style={{ height: barHeight }}
              >
                {SEVERITY_ORDER.map((severity) => {
                  const value = entry.counts[severity] ?? 0;
                  if (value === 0) return null;
                  return (
                    <div
                      key={severity}
                      style={{
                        height: `${(value / Math.max(total, 1)) * 100}%`,
                        background: SEVERITY_VAR[severity],
                      }}
                    />
                  );
                })}
                {total === 0 && (
                  <div className="h-full w-full bg-surface-sunken" />
                )}
              </div>
            </div>
          );
        })}
      </div>
      <div className="mt-2 flex justify-between text-[10px] text-content-subtle">
        <span>oldest</span>
        <span>latest</span>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- legend */

export function SeverityLegend({
  counts,
}: {
  counts: Partial<Record<Severity, number>>;
}) {
  const present = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0);
  if (present.length === 0) return null;

  return (
    <ul className="space-y-1">
      {present.map((severity) => (
        <li key={severity} className="flex items-center gap-2 text-xs">
          <span
            className="h-2 w-2 shrink-0 rounded-sm"
            style={{ background: SEVERITY_VAR[severity] }}
            aria-hidden
          />
          <span className="capitalize text-content-muted">{severity}</span>
          <span className="ml-auto tnum">{counts[severity]}</span>
        </li>
      ))}
    </ul>
  );
}

/* ------------------------------------------------------------------ gauge */

/**
 * Release posture as a half-ring.
 *
 * Deliberately not a 0-100 "risk score". A synthesised number invites arguing
 * with the number instead of fixing the finding; this shows the count that
 * actually gates a release and says plainly what it means.
 */
export function PostureGauge({
  blocking,
  total,
  size = 200,
}: {
  blocking: number;
  total: number;
  size?: number;
}) {
  const thickness = 14;
  const radius = (size - thickness) / 2;
  const circumference = Math.PI * radius;
  const ratio = total === 0 ? 0 : Math.min(blocking / total, 1);
  const filled = circumference * ratio;

  const tone =
    blocking === 0
      ? "var(--color-ok)"
      : blocking <= 2
        ? "var(--color-medium)"
        : "var(--color-critical)";

  return (
    <div className="flex flex-col items-center">
      <svg
        width={size}
        height={size / 2 + 8}
        viewBox={`0 0 ${size} ${size / 2 + 8}`}
        role="img"
        aria-label={`${blocking} release-blocking findings of ${total} total`}
      >
        <path
          d={`M ${thickness / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - thickness / 2} ${size / 2}`}
          fill="none"
          stroke="var(--color-surface-sunken)"
          strokeWidth={thickness}
          strokeLinecap="round"
        />
        <path
          d={`M ${thickness / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - thickness / 2} ${size / 2}`}
          fill="none"
          stroke={tone}
          strokeWidth={thickness}
          strokeLinecap="round"
          strokeDasharray={`${Math.max(filled, blocking > 0 ? 6 : 0)} ${circumference}`}
        />
      </svg>
      <div className="-mt-8 flex flex-col items-center">
        <span className="text-3xl font-semibold tnum leading-none" style={{ color: tone }}>
          {blocking}
        </span>
        <span className="mt-1 text-[10px] uppercase tracking-wider text-content-subtle">
          release-blocking
        </span>
      </div>
    </div>
  );
}

/* --------------------------------------------------------------- sparkline */

export function Sparkline({
  values,
  width = 120,
  height = 28,
}: {
  values: number[];
  width?: number;
  height?: number;
}) {
  if (values.length < 2) return null;

  const max = Math.max(1, ...values);
  const step = width / (values.length - 1);
  const points = values
    .map((value, index) => `${index * step},${height - (value / max) * (height - 3) - 1.5}`)
    .join(" ");

  const rising = (values.at(-1) ?? 0) > (values.at(-2) ?? 0);

  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden>
      <polyline
        points={points}
        fill="none"
        stroke={rising ? "var(--color-high)" : "var(--color-ok)"}
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}
