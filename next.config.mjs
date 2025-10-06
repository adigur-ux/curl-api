/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/zap/:path*",
        destination: "https://curl-api-zeta.vercel.app/api/zap/:path*",
      },
    ];
  },
};

export default nextConfig;
