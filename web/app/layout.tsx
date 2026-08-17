import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Sightglass",
  description:
    "Shipped-artifact exposure scanner: secrets, sensitive data, and IP disclosure in the binaries you ship.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="border-b border-neutral-200 dark:border-neutral-800">
          <div className="mx-auto flex max-w-6xl items-baseline gap-3 px-6 py-4">
            <span className="text-lg font-semibold tracking-tight">Sightglass</span>
            <span className="text-sm text-neutral-500">
              shipped-artifact exposure scanner
            </span>
          </div>
        </header>
        <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
      </body>
    </html>
  );
}
