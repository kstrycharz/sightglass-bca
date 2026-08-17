import type { NextConfig } from "next";

// Inside compose this is http://api:8000; running the dashboard directly
// against a local API it is http://localhost:8000.
const API_URL = process.env.SIGHTGLASS_API_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  // Standalone output keeps the production image small and, more importantly,
  // makes the air-gap bundle (M6) a single self-contained tree.
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  eslint: { ignoreDuringBuilds: false },
  typescript: { ignoreBuildErrors: false },

  // Proxy the API under the dashboard's own origin. This is why the backend
  // ships no CORS configuration at all: the browser only ever talks to Next,
  // and a findings page — a list of a company's exposed secrets — is never
  // reachable cross-origin.
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${API_URL}/api/:path*` },
      { source: "/healthz", destination: `${API_URL}/healthz` },
      { source: "/readyz", destination: `${API_URL}/readyz` },
    ];
  },
};

export default nextConfig;
