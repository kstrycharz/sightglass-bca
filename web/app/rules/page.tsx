import { api, type RulePackInfo } from "@/lib/api";
import { ErrorNotice, Metric, Mono, Panel, SeverityTag } from "@/components/ui";

export const dynamic = "force-dynamic";

export default async function RulesPage() {
  let pack: RulePackInfo | null = null;
  let error: string | null = null;

  try {
    pack = await api.rulePack();
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const byCategory = new Map<string, RulePackInfo["rules"]>();
  for (const rule of pack?.rules ?? []) {
    byCategory.set(rule.category, [...(byCategory.get(rule.category) ?? []), rule]);
  }

  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold tracking-tight">Detections</h1>
        <p className="mt-1 max-w-3xl text-sm text-content-muted">
          Every finding comes from one of these rules. Rules are data, not code
          — the pack version and hash go into each run manifest, which is what
          lets two runs claim identical results.
        </p>
      </header>

      {error && <ErrorNotice title="Could not load the rule pack" detail={error} />}

      {pack && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Metric label="Rules" value={pack.rule_count} />
            <Metric label="Categories" value={byCategory.size} />
            <Metric
              label="False-positive corpus"
              value={pack.false_positive_corpus_size}
              hint="values dropped before they become findings"
            />
            <Metric
              label="Pack version"
              value={pack.version}
              hint={pack.hash.slice(0, 12)}
            />
          </div>

          <p className="max-w-3xl text-xs text-content-muted">
            Rules are deliberately over-inclusive: missing a live key is far
            worse than surfacing a dud. The false-positive corpus drops values
            published in vendor documentation and RFCs before they ever become
            findings, and AI triage handles the remainder.
          </p>

          {[...byCategory.entries()]
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([category, rules]) => (
              <Panel key={category} title={category} description={`${rules.length} rules`}>
                <ul>
                  {rules.map((rule) => (
                    <li
                      key={rule.id}
                      className="border-b border-border/60 px-4 py-2.5 last:border-0"
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityTag severity={rule.severity} size="xs" />
                        <span className="text-sm font-medium">{rule.name}</span>
                        <Mono className="rounded bg-surface-sunken px-1.5 py-px text-content-muted">
                          {rule.id}
                        </Mono>
                        {rule.cwe && (
                          <span className="text-[11px] text-content-subtle">{rule.cwe}</span>
                        )}
                        {rule.tags.includes("high-noise") && (
                          <span className="rounded bg-medium-bg px-1.5 py-px text-[10px] font-medium uppercase tracking-wider text-medium">
                            high noise
                          </span>
                        )}
                        <span className="ml-auto text-[11px] text-content-subtle tnum">
                          conf {rule.confidence.toFixed(2)}
                        </span>
                      </div>
                      <p className="mt-1 max-w-4xl text-xs text-content-muted">
                        {rule.description}
                      </p>
                    </li>
                  ))}
                </ul>
              </Panel>
            ))}
        </>
      )}
    </div>
  );
}
