/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  images: { unoptimized: true },
  swcMinify: false, // SWC minifier mangles nested template literals in @radix-ui/react-progress
  async rewrites() {
    const target = process.env.API_INTERNAL_URL || 'http://api:3001';
    return [{ source: '/api/:path*', destination: `${target}/api/:path*` }];
  },
};

module.exports = nextConfig;
