import webpack from "webpack";

/** @type {import('next').NextConfig} */
const nextConfig = {
  webpack(config, { isServer }) {
    // Enable WebAssembly support
    config.experiments = {
      ...config.experiments,
      asyncWebAssembly: true, // use async since sync is deprecated
    };
    config.infrastructureLogging = {
      level: "error",
    };

    // Handle .wasm files (emit as file and return URL)
    config.module.rules.push({
      test: /\.wasm$/,
      type: "asset/resource",
    });

    // Fallbacks for Node core modules (if needed)
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      path: false,
    };

    // Provide Buffer (if you're using it somewhere)
    config.plugins.push(
      new webpack.ProvidePlugin({
        Buffer: ["buffer", "Buffer"],
      }),
    );

    return config;
  },
};

export default nextConfig;
