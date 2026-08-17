"use client";

/**
 * Upload with the authorization gate.
 *
 * The attestation is presented as a real question, not a checkbox to click
 * past. The reference field is required and validated server-side, because an
 * audit record reading "yes" is worth nothing to the compliance officer who
 * has to rely on it two years from now (§14).
 */

import { useRouter } from "next/navigation";
import { useState } from "react";

export default function UploadPage() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [attestedBy, setAttestedBy] = useState("");
  const [reference, setReference] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [llmEnabled, setLlmEnabled] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ready =
    file !== null && attestedBy.trim().length > 0 && reference.trim().length >= 8 && acknowledged;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!file || !ready) return;

    setSubmitting(true);
    setError(null);

    const body = new FormData();
    body.append("file", file);
    body.append("attested_by", attestedBy.trim());
    body.append("attestation_reference", reference.trim());
    body.append("llm_enabled", String(llmEnabled));

    try {
      const response = await fetch("/api/runs", { method: "POST", body });
      if (!response.ok) {
        const detail = (await response.json().catch(() => ({}))) as { detail?: string };
        throw new Error(detail.detail ?? response.statusText);
      }
      const created = (await response.json()) as { run_id: string };
      router.push(`/runs/${created.run_id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit} className="mx-auto max-w-2xl space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">New scan</h1>
        <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
          Upload the artifact you are about to ship — an installer, executable,
          DLL, firmware image, or update bundle.
        </p>
      </div>

      <section className="space-y-2">
        <label htmlFor="file" className="block text-sm font-medium">
          Artifact
        </label>
        <input
          id="file"
          type="file"
          required
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="block w-full rounded-md border border-neutral-300 p-2 text-sm file:mr-3 file:rounded file:border-0 file:bg-neutral-900 file:px-3 file:py-1.5 file:text-sm file:text-white dark:border-neutral-700 dark:file:bg-neutral-100 dark:file:text-neutral-900"
        />
        {file && (
          <p className="text-xs text-neutral-500">
            {file.name} · {(file.size / 1024 / 1024).toFixed(2)} MB
          </p>
        )}
      </section>

      <section className="space-y-4 rounded-lg border border-amber-500/40 bg-amber-500/5 p-4">
        <div>
          <h2 className="text-sm font-semibold">Authorization attestation</h2>
          <p className="mt-1 text-sm text-neutral-700 dark:text-neutral-300">
            Sightglass analyses artifacts you own or are contractually
            authorized to test. This record is written to an append-only audit
            log and printed in every report generated from this scan.
          </p>
        </div>

        <div className="space-y-2">
          <label htmlFor="attested_by" className="block text-sm font-medium">
            Attesting identity
          </label>
          <input
            id="attested_by"
            type="text"
            required
            value={attestedBy}
            onChange={(e) => setAttestedBy(e.target.value)}
            placeholder="jordan.reyes@example.com"
            className="w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950"
          />
        </div>

        <div className="space-y-2">
          <label htmlFor="reference" className="block text-sm font-medium">
            Authorization reference
          </label>
          <textarea
            id="reference"
            required
            minLength={8}
            rows={2}
            value={reference}
            onChange={(e) => setReference(e.target.value)}
            placeholder="Internal release gate, RELEASE-4821 — we build and ship this artifact"
            className="w-full rounded-md border border-neutral-300 bg-white px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950"
          />
          <p className="text-xs text-neutral-600 dark:text-neutral-400">
            Cite the contract, ticket, or engagement. An auditor reading this in
            two years should be able to tell what authorised the analysis —
            &ldquo;yes&rdquo; will be rejected.
          </p>
        </div>

        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(e) => setAcknowledged(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            I own this artifact, or I am contractually authorized to analyse it.
          </span>
        </label>
      </section>

      <section className="space-y-2">
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={llmEnabled}
            onChange={(e) => setLlmEnabled(e.target.checked)}
            className="mt-0.5"
          />
          <span>
            Enable AI triage for this run
            <span className="mt-0.5 block text-xs text-neutral-600 dark:text-neutral-400">
              Optional. The scan produces the same findings either way — triage
              only classifies and explains them. Masked values and context are
              sent to your configured model; secret plaintext never is.
            </span>
          </span>
        </label>
      </section>

      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/5 p-3 text-sm text-red-700 dark:text-red-400">
          {error}
        </div>
      )}

      <button
        type="submit"
        disabled={!ready || submitting}
        className="rounded-md bg-neutral-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-neutral-700 disabled:cursor-not-allowed disabled:opacity-40 dark:bg-neutral-100 dark:text-neutral-900 dark:hover:bg-neutral-300"
      >
        {submitting ? "Uploading…" : "Start scan"}
      </button>
    </form>
  );
}
