/**
 * Typed API client.
 *
 * Server components call the API directly (inside the compose network); client
 * components go through Next's rewrite on the same origin. `apiUrl` picks the
 * right base for whichever side is calling, so no component needs to know.
 */

const SERVER_API = process.env.SIGHTGLASS_API_URL ?? "http://localhost:8000";

export function apiUrl(path: string): string {
  return typeof window === "undefined" ? `${SERVER_API}${path}` : path;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface RunSummary {
  id: string;
  status: string;
  profile: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  attested_by: string;
  attestation_reference: string;
  llm_enabled: boolean;
  artifact_name: string | null;
  artifact_sha256: string | null;
  artifact_size_bytes: number | null;
  finding_count: number;
  severity_counts: Partial<Record<Severity, number>>;
  /** Files analysed, including everything unpacked out of the artifact. */
  artifact_count: number;
  new_since_previous: number | null;
}

export interface Stage {
  analyzer: string;
  status: string;
  duration_s: number | null;
  exit_code: number | null;
  evidence_count: number;
  error: string | null;
  image_digest: string | null;
}

export interface Manifest {
  sightglass_version: string;
  artifact_sha256: string;
  rule_pack_version: string;
  rule_pack_hash: string;
  image_digests: Record<string, string>;
  tool_versions: Record<string, string>;
  fingerprint: string;
}

export interface ArtifactNode {
  id: string;
  name: string;
  path_in_tree: string;
  depth: number;
  sha256: string;
  size_bytes: number;
  kind: string;
  media_type: string | null;
  architecture: string | null;
  identified: Record<string, unknown>;
  finding_count: number;
  children: ArtifactNode[];
}

export interface RunDetail extends RunSummary {
  stages: Stage[];
  manifest: Manifest | null;
  artifact_tree: ArtifactNode | null;
  previous_run_id: string | null;
}

export interface FindingLocation {
  artifact_id: string;
  path_in_tree: string;
  offset: number | null;
  section: string | null;
  encoding: string | null;
  xref_function: string | null;
}

/** Every AI-derived field, in one object. The determinism toggle drops it whole. */
export interface LlmAssessment {
  verdict: string;
  reasoning: string | null;
  model: string | null;
  assessed_at: string | null;
}

export interface Finding {
  id: string;
  run_id: string;
  rule_id: string;
  category: string;
  title: string;
  severity: Severity;
  confidence: number;
  value_masked: string;
  entropy: number | null;
  context_snippet: string | null;
  cwe: string | null;
  tags: string[];
  remediation_md: string | null;
  status: string;
  detected_by: string;
  is_new: boolean;
  locations: FindingLocation[];
  location_count: number;
  llm: LlmAssessment | null;
}

export interface ProviderHealth {
  name: string;
  healthy: boolean;
  model: string;
  detail: string;
  latency_s: number | null;
  is_local: boolean;
  available_models: string[];
}

export interface LlmSettings {
  enabled: boolean;
  egress: string;
  redaction: string;
  roles: Record<string, string>;
  providers: ProviderHealth[];
  config_path: string | null;
}

export interface RuleSummary {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  confidence: number;
  cwe: string | null;
  description: string;
  tags: string[];
}

export interface RulePackInfo {
  version: string;
  hash: string;
  rule_count: number;
  false_positive_corpus_size: number;
  rules: RuleSummary[];
}

export interface TriageResponse {
  run_id: string;
  triaged: number;
  confirmed: number;
  dismissed: number;
  needs_review: number;
  errors: number;
  duration_s: number;
  model: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), { cache: "no-store", ...init });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      if (body.detail) detail = body.detail;
    } catch {
      /* the body was not JSON; the status text will do */
    }
    throw new Error(detail);
  }
  return (await response.json()) as T;
}

export const api = {
  listRuns: () => request<RunSummary[]>("/api/runs"),
  getRun: (id: string) => request<RunDetail>(`/api/runs/${id}`),
  listFindings: (runId: string, query = "") =>
    request<Finding[]>(`/api/runs/${runId}/findings${query}`),
  getFinding: (runId: string, id: string) =>
    request<Finding>(`/api/runs/${runId}/findings/${id}`),
  setFindingStatus: (runId: string, id: string, status: string, note?: string) =>
    request<Finding>(`/api/runs/${runId}/findings/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status, note }),
    }),
  triage: (runId: string) =>
    request<TriageResponse>(`/api/runs/${runId}/triage`, { method: "POST" }),
  llmSettings: () => request<LlmSettings>("/api/settings/llm"),
  rulePack: () => request<RulePackInfo>("/api/settings/rules"),
};

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
}

export function formatDuration(seconds: number | null): string {
  if (seconds === null) return "—";
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

export function formatTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
