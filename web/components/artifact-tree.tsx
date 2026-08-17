"use client";

/**
 * The unpack tree.
 *
 * The whole reason this is a tree and not a list: an engineer needs to know
 * *which nested file* leaked the key, because that determines which build step
 * to fix. "A secret is in release.zip" is an argument; "a secret is in
 * release.zip → payload.tar.gz → config/prod.json" is a ticket.
 *
 * Nodes with findings are expanded by default — the operator came here to find
 * the problem, not to click through folders looking for it.
 */

import { useState } from "react";
import type { ArtifactNode } from "@/lib/api";
import { Mono, bytes } from "@/components/ui";

const KIND_LABEL: Record<string, string> = {
  pe: "PE",
  elf: "ELF",
  macho: "Mach-O",
  archive: "archive",
  installer: "installer",
  filesystem: "filesystem",
  certificate: "certificate",
  text: "text",
  config: "config",
  unknown: "",
};

function hasFindings(node: ArtifactNode): boolean {
  return node.finding_count > 0 || node.children.some(hasFindings);
}

function countNodes(node: ArtifactNode): number {
  return 1 + node.children.reduce((sum, child) => sum + countNodes(child), 0);
}

function TreeNode({ node, depth }: { node: ArtifactNode; depth: number }) {
  const interesting = hasFindings(node);
  const [open, setOpen] = useState(depth < 1 || interesting);
  const expandable = node.children.length > 0;

  return (
    <li>
      <div
        className="flex items-center gap-2 rounded px-2 py-1 hover:bg-surface-sunken"
        style={{ paddingLeft: `${depth * 14 + 8}px` }}
      >
        {expandable ? (
          <button
            type="button"
            onClick={() => setOpen(!open)}
            aria-expanded={open}
            aria-label={open ? `Collapse ${node.name}` : `Expand ${node.name}`}
            className="w-3 shrink-0 text-content-subtle hover:text-content"
          >
            {open ? "▾" : "▸"}
          </button>
        ) : (
          <span className="w-3 shrink-0" aria-hidden />
        )}

        <span className="min-w-0 truncate text-sm" title={node.path_in_tree}>
          {node.name}
        </span>

        {KIND_LABEL[node.kind] && (
          <span className="shrink-0 rounded bg-surface-sunken px-1.5 py-px text-[10px] uppercase tracking-wider text-content-subtle">
            {KIND_LABEL[node.kind]}
          </span>
        )}
        {node.architecture && (
          <span className="shrink-0 text-[10px] text-content-subtle">{node.architecture}</span>
        )}

        <span className="ml-auto shrink-0 text-xs text-content-subtle tnum">
          {bytes(node.size_bytes)}
        </span>

        {node.finding_count > 0 && (
          <span className="shrink-0 rounded bg-critical-bg px-1.5 py-px text-[11px] font-medium text-critical tnum">
            {node.finding_count}
          </span>
        )}
      </div>

      {open && expandable && (
        <ul>
          {node.children.map((child) => (
            <TreeNode key={child.id} node={child} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function ArtifactTree({ root }: { root: ArtifactNode }) {
  const total = countNodes(root);

  return (
    <div>
      <ul className="py-1">
        <TreeNode node={root} depth={0} />
      </ul>
      <div className="border-t border-border px-4 py-2 text-xs text-content-subtle">
        {total === 1 ? (
          <>
            No nested containers found. <Mono>{root.kind}</Mono> artifacts are
            scanned directly.
          </>
        ) : (
          <>
            {total} files analysed across {maxDepth(root)} level
            {maxDepth(root) === 1 ? "" : "s"}. Every extracted file is scanned
            with the same rule pack as the original.
          </>
        )}
      </div>
    </div>
  );
}

function maxDepth(node: ArtifactNode): number {
  if (node.children.length === 0) return node.depth;
  return Math.max(...node.children.map(maxDepth));
}
