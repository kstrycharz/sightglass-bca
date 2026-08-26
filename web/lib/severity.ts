/**
 * Split out of `api.ts` so a client component can use `SEVERITY_ORDER`
 * without pulling in that file's server-only fetch machinery — which reaches
 * `node:fs` (via `runtime-token.ts`, to read the token the setup wizard
 * persisted) and fails the client build outright if bundled there, dead code
 * or not.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];
