import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sightglass",
  description:
    "Shipped-artifact exposure scanner: secrets, sensitive data, and IP disclosure in the binaries you ship.",
};

const NAV = [
  { href: "/", label: "Runs" },
  { href: "/upload", label: "New scan" },
  { href: "/rules", label: "Rules" },
  { href: "/settings", label: "Settings" },
];

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="border-b border-neutral-200 dark:border-neutral-800">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-2 px-6 py-3">
            <Link href="/" className="flex items-baseline gap-2">
              <span className="text-lg font-semibold tracking-tight">Sightglass</span>
              <span className="hidden text-xs text-neutral-500 sm:inline">
                shipped-artifact exposure scanner
              </span>
            </Link>
            <nav className="flex items-center gap-4 text-sm">
              {NAV.map((item) => (
                <Link
                  key={item.href}
                  href={item.href}
                  className="text-neutral-600 transition-colors hover:text-neutral-950 dark:text-neutral-400 dark:hover:text-neutral-50"
                >
                  {item.label}
                </Link>
              ))}
            </nav>
          </div>
        </header>
        <main className="mx-auto max-w-7xl px-6 py-8">{children}</main>
        <footer className="mx-auto max-w-7xl px-6 pb-10 pt-4 text-xs text-neutral-500">
          Every finding on this dashboard comes from a deterministic rule. AI
          assessments are labelled and can be hidden entirely.
        </footer>
      </body>
    </html>
  );
}
