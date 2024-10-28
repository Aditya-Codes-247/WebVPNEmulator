import { NextConfig } from 'next';
import { Configuration } from 'webpack';

/** @type {import('next').NextConfig} */
const nextConfig: NextConfig = {
  reactStrictMode: true,
  swcMinify: true,
  images: {
    domains: ['localhost'],
  },
  webpack: (config: Configuration, { buildId, dev, isServer, defaultLoaders, webpack }) => {
    // Check if externals is an array and append accordingly
    if (Array.isArray(config.externals)) {
      config.externals.push({ canvas: 'canvas' });
    } else {
      config.externals = [{ canvas: 'canvas' }];
    }
    return config;
  },
};

export default nextConfig;
