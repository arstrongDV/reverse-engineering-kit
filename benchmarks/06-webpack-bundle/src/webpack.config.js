module.exports = {
  mode: "production",
  devtool: false,
  entry: "./app/index.js",
  output: { filename: "main.js" },
  // Keep each module separate, as most real bundles do, so there is a module map to recover.
  optimization: { concatenateModules: false },
};
