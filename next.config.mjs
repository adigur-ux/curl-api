/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/zap/:path*",
        destination: "https://curl-api-zeta.vercel.app/:path*",
      },
    ];
  },
};

export default nextConfig;
