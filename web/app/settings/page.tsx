import { api, type LlmSettings } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function SettingsPage() {
  let settings: LlmSettings | null = null;
  let error: string | null = null;

  try {
    settings = await api.llmSettings();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 max-w-2xl text-sm text-neutral-600 dark:text-neutral-400">
          Sightglass is deterministic first. Everything below is optional — with
          no model configured, scans still run and reports are still complete.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/5 p-4 text-sm">
          <p className="font-medium text-red-700 dark:text-red-400">
            Could not load LLM settings
          </p>
          <p className="mt-1 font-mono text-xs">{error}</p>
        </div>
      )}

      {settings && (
        <>
          <section className="space-y-3">
            <h2 className="text-lg font-semibold">Trust boundary</h2>
            <dl className="grid gap-4 sm:grid-cols-3">
              <Card
                label="Egress policy"
                value={settings.egress}
                note={
                  settings.egress === "deny"
                    ? "No outbound calls except to loopback and private addresses. A model on your own LAN is permitted; the public internet is not."
                    : "Cloud providers are permitted. Artifact-derived context may leave your network."
                }
                tone={settings.egress === "deny" ? "good" : "warn"}
              />
              <Card
                label="Redaction"
                value={settings.redaction}
                note="Candidates are sent as shape, entropy, rule name, masked value, and offsets. Secret plaintext is never sent to any provider during triage."
                tone="good"
              />
              <Card
                label="LLM layer"
                value={settings.enabled ? "enabled" : "disabled"}
                note={
                  settings.enabled
                    ? "Triage is available. It never creates findings — only classifies and explains them."
                    : "Deterministic-only. This is the CI default."
                }
                tone="neutral"
              />
            </dl>
            {settings.config_path && (
              <p className="font-mono text-xs text-neutral-500">{settings.config_path}</p>
            )}
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-semibold">Role routing</h2>
            <p className="max-w-2xl text-sm text-neutral-600 dark:text-neutral-400">
              Different jobs want different models. Triage runs over every
              candidate and needs a small, fast, non-reasoning model; explanation
              runs over a handful of confirmed findings and can afford a large one.
            </p>
            <table className="text-sm">
              <tbody>
                {Object.entries(settings.roles).map(([role, provider]) => (
                  <tr key={role}>
                    <td className="py-1 pr-6 font-mono text-xs">{role}</td>
                    <td className="py-1 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                      {provider}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="space-y-3">
            <h2 className="text-lg font-semibold">Providers</h2>
            <p className="text-sm text-neutral-600 dark:text-neutral-400">
              Probed live on page load — a stale green tick is worse than none.
            </p>
            <ul className="space-y-2">
              {settings.providers.map((provider) => (
                <li
                  key={provider.name}
                  className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800"
                >
                  <div className="flex flex-wrap items-center gap-3">
                    <span
                      className={`inline-block h-2 w-2 rounded-full ${
                        provider.healthy ? "bg-emerald-500" : "bg-red-500"
                      }`}
                      aria-hidden
                    />
                    <span className="font-medium">{provider.name}</span>
                    <code className="rounded bg-neutral-100 px-1.5 py-0.5 text-xs dark:bg-neutral-900">
                      {provider.model}
                    </code>
                    <span
                      className={`rounded px-1.5 py-0.5 text-xs ${
                        provider.is_local
                          ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                      }`}
                    >
                      {provider.is_local ? "local" : "remote"}
                    </span>
                    {provider.latency_s !== null && (
                      <span className="text-xs tabular-nums text-neutral-500">
                        {(provider.latency_s * 1000).toFixed(0)} ms
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-400">
                    {provider.detail}
                  </p>
                  {provider.available_models.length > 0 && (
                    <p className="mt-1 font-mono text-xs text-neutral-500">
                      available: {provider.available_models.join(", ")}
                    </p>
                  )}
                </li>
              ))}
            </ul>
          </section>
        </>
      )}
    </div>
  );
}

function Card({
  label,
  value,
  note,
  tone,
}: {
  label: string;
  value: string;
  note: string;
  tone: "good" | "warn" | "neutral";
}) {
  const ring =
    tone === "good"
      ? "border-emerald-500/40"
      : tone === "warn"
        ? "border-amber-500/40"
        : "border-neutral-200 dark:border-neutral-800";
  return (
    <div className={`rounded-lg border p-3 ${ring}`}>
      <dt className="text-xs uppercase tracking-wide text-neutral-500">{label}</dt>
      <dd className="mt-0.5 font-medium">{value}</dd>
      <p className="mt-1 text-xs text-neutral-600 dark:text-neutral-400">{note}</p>
    </div>
  );
}
