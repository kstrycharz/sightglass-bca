import { api, type RulePackInfo } from "@/lib/api";
import { SeverityBadge } from "@/components/severity";

export const dynamic = "force-dynamic";

export default async function RulesPage() {
  let pack: RulePackInfo | null = null;
  let error: string | null = null;

  try {
    pack = await api.rulePack();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Detection rules</h1>
        <p className="mt-1 max-w-2xl text-sm text-neutral-600 dark:text-neutral-400">
          Every finding Sightglass reports comes from one of these. Rules are
          data, not code — the pack version and hash are recorded in each run
          manifest, which is what lets two runs claim identical results.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/5 p-4 text-sm">
          <p className="font-mono text-xs">{error}</p>
        </div>
      )}

      {pack && (
        <>
          <dl className="flex flex-wrap gap-x-8 gap-y-2 text-sm">
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Version</dt>
              <dd className="font-mono">{pack.version}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Pack hash</dt>
              <dd className="font-mono text-xs">{pack.hash.slice(0, 24)}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">Rules</dt>
              <dd className="tabular-nums">{pack.rule_count}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-neutral-500">
                False-positive corpus
              </dt>
              <dd className="tabular-nums">{pack.false_positive_corpus_size} entries</dd>
            </div>
          </dl>

          <p className="max-w-2xl text-xs text-neutral-600 dark:text-neutral-400">
            Rules are deliberately over-inclusive: missing a live key is far
            worse than surfacing a dud. The false-positive corpus drops values
            published in vendor documentation and RFCs before they ever become
            findings, and AI triage handles the rest.
          </p>

          <ul className="space-y-2">
            {pack.rules.map((rule) => (
              <li
                key={rule.id}
                className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={rule.severity} />
                  <span className="font-medium">{rule.name}</span>
                  <code className="rounded bg-neutral-100 px-1.5 py-0.5 text-xs dark:bg-neutral-900">
                    {rule.id}
                  </code>
                  <span className="text-xs text-neutral-500">{rule.category}</span>
                  {rule.cwe && <span className="text-xs text-neutral-500">{rule.cwe}</span>}
                  {rule.tags.includes("high-noise") && (
                    <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-xs text-amber-700 dark:text-amber-300">
                      high noise — relies on triage
                    </span>
                  )}
                </div>
                <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
                  {rule.description}
                </p>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
