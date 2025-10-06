/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    if (process.env.NODE_ENV === "development") {
      return [
        {
          source: "/api/zap/:path*",
          destination: "https://curl-api-zeta.vercel.app/:path*",
        },
      ];
    }
    return [];
  },
};
export default nextConfig;
