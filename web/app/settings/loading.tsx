import { Panel } from "@/components/ui";

/**
 * Shown while the settings page resolves on the server.
 *
 * The page is a dynamic server component that awaits a live probe of every
 * configured provider before it can render anything. Probes are concurrent and
 * bounded now, but "bounded" is still seconds against a host that is off the
 * network — and without this the browser showed the previous page, or nothing,
 * for the whole wait, which reads as a hang rather than as work in progress.
 */
export default function Loading() {
  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 max-w-3xl text-sm text-content-muted">
          Probing each configured provider…
        </p>
      </header>

      <Panel
        title="Providers"
        description="Probed live on page load — a stale green tick is worse than none."
      >
        <div className="divide-y divide-border" aria-busy="true" aria-live="polite">
          {[0, 1].map((row) => (
            <div key={row} className="flex items-center gap-3 px-4 py-3">
              <span className="h-2 w-2 shrink-0 animate-pulse rounded-full bg-border" />
              <span className="h-3 w-28 animate-pulse rounded bg-border" />
              <span className="h-3 w-56 animate-pulse rounded bg-border" />
            </div>
          ))}
        </div>
      </Panel>

      <span className="sr-only">Loading settings</span>
    </div>
  );
}
