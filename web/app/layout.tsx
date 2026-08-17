import type { Metadata } from "next";
import "./globals.css";
import { SidebarNav } from "@/components/sidebar-nav";

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
        {/* Sidebar rather than a top bar: this console is a workbench, not a
            marketing site. Navigation stays put while a long findings table
            scrolls, and the viewport keeps its vertical space for data. */}
        <div className="flex min-h-screen">
          <SidebarNav />
          <div className="flex min-w-0 flex-1 flex-col">
            <main className="min-w-0 flex-1 px-6 py-6 lg:px-8">{children}</main>
            <footer className="border-t border-border px-6 py-3 text-xs text-content-subtle lg:px-8">
              Every finding is produced by a deterministic rule. AI assessments
              are labelled and can be hidden entirely.
            </footer>
          </div>
        </div>
      </body>
    </html>
  );
}
