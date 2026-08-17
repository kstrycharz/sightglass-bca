import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output keeps the production image small and, more importantly,
  // makes the air-gap bundle (M6) a single self-contained tree.
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  eslint: { ignoreDuringBuilds: false },
  typescript: { ignoreBuildErrors: false },
};

export default nextConfig;
