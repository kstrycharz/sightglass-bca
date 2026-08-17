"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV = [
  { href: "/", label: "Runs", exact: true },
  { href: "/scan", label: "New scan" },
  { href: "/rules", label: "Detections" },
  { href: "/settings", label: "Settings" },
];

export function SidebarNav() {
  const pathname = usePathname();

  return (
    <aside className="sticky top-0 hidden h-screen w-56 shrink-0 flex-col border-r border-border bg-surface md:flex">
      <div className="border-b border-border px-5 py-4">
        <Link href="/" className="block">
          <div className="flex items-center gap-2">
            {/* A lens: the product is about looking at what you ship. */}
            <svg viewBox="0 0 20 20" className="h-5 w-5 text-accent" aria-hidden>
              <circle cx="9" cy="9" r="6" fill="none" stroke="currentColor" strokeWidth="1.6" />
              <circle cx="9" cy="9" r="2.2" fill="currentColor" opacity="0.35" />
              <path d="M13.5 13.5 L18 18" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
            <span className="text-[15px] font-semibold tracking-tight">Sightglass</span>
          </div>
          <p className="mt-1 text-[11px] leading-tight text-content-subtle">
            Shipped-artifact exposure scanner
          </p>
        </Link>
      </div>

      <nav className="flex-1 px-3 py-3">
        <ul className="space-y-0.5">
          {NAV.map((item) => {
            const active = item.exact
              ? pathname === item.href
              : pathname.startsWith(item.href);
            return (
              <li key={item.href}>
                <Link
                  href={item.href}
                  aria-current={active ? "page" : undefined}
                  className={`block rounded-md px-3 py-1.5 text-sm transition-colors ${
                    active
                      ? "bg-surface-sunken font-medium text-content"
                      : "text-content-muted hover:bg-surface-sunken hover:text-content"
                  }`}
                >
                  {item.label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="border-t border-border px-5 py-3">
        <p className="text-[11px] leading-relaxed text-content-subtle">
          Self-hosted. Artifacts never leave this network.
        </p>
      </div>
    </aside>
  );
}
