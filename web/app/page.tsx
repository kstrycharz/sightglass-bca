/**
 * System status.
 *
 * Deliberately a server component with no client JavaScript: §4 requires the
 * dashboard to render usefully with JS disabled, and the place to establish
 * that habit is the first page, not the last. Interactive views (the findings
 * explorer) become client components later; report pages stay server-rendered.
 */

const API_URL = process.env.SIGHTGLASS_API_URL ?? "http://localhost:8000";

type Check = { healthy: boolean; detail: string };
type Readiness = {
  ready: boolean;
  version: string;
  /** Hard dependencies. These gate readiness. */
  checks: Record<string, Check>;
  /** Reported but non-gating — the sandbox belongs to the worker, not the API. */
  advisory?: Record<string, Check>;
};

async function fetchReadiness(): Promise<Readiness | { error: string }> {
  try {
    const response = await fetch(`${API_URL}/readyz`, {
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    return (await response.json()) as Readiness;
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

export default async function Home() {
  const readiness = await fetchReadiness();

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-semibold tracking-tight">System status</h1>
        <p className="mt-2 max-w-2xl text-sm text-neutral-600 dark:text-neutral-400">
          Sightglass is at milestone M0: the sandbox boundary and the deployment
          stack. Artifact ingestion and the findings explorer arrive in M1.
        </p>
      </section>

      {"error" in readiness ? (
        <div className="rounded-lg border border-severity-critical/40 bg-severity-critical/5 p-4">
          <p className="font-medium text-severity-critical">API unreachable</p>
          <p className="mt-1 font-mono text-xs text-neutral-600 dark:text-neutral-400">
            {readiness.error}
          </p>
        </div>
      ) : (
        <section className="space-y-3">
          <div className="flex items-center gap-3">
            <span
              className={`inline-block h-2.5 w-2.5 rounded-full ${
                readiness.ready ? "bg-emerald-500" : "bg-severity-high"
              }`}
              aria-hidden
            />
            <span className="font-medium">
              {readiness.ready ? "Ready" : "Not ready"}
            </span>
            <span className="text-sm text-neutral-500">v{readiness.version}</span>
          </div>

          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Dependency health checks</caption>
            <thead>
              <tr className="border-b border-neutral-200 text-left dark:border-neutral-800">
                <th scope="col" className="py-2 pr-4 font-medium">
                  Dependency
                </th>
                <th scope="col" className="py-2 pr-4 font-medium">
                  Status
                </th>
                <th scope="col" className="py-2 font-medium">
                  Detail
                </th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(readiness.checks).map(([name, check]) => (
                <tr
                  key={name}
                  className="border-b border-neutral-100 dark:border-neutral-900"
                >
                  <td className="py-2 pr-4 font-mono text-xs">{name}</td>
                  <td className="py-2 pr-4">
                    <span
                      className={
                        check.healthy
                          ? "text-emerald-600 dark:text-emerald-400"
                          : "text-severity-critical"
                      }
                    >
                      {check.healthy ? "healthy" : "unhealthy"}
                    </span>
                  </td>
                  <td className="py-2 font-mono text-xs text-neutral-500">
                    {check.detail || "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {readiness.advisory && (
            <div className="pt-2">
              <h2 className="text-sm font-medium">Advisory</h2>
              <p className="mt-1 text-xs text-neutral-500">
                Reported but not gating readiness. The API has no Docker socket
                by design — analyzer containers are spawned by the worker.
              </p>
              <ul className="mt-2 space-y-1">
                {Object.entries(readiness.advisory).map(([name, check]) => (
                  <li key={name} className="font-mono text-xs text-neutral-500">
                    {name}: {check.healthy ? "healthy" : "unavailable"}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
