module.exports = {
  babel: {
    plugins: [
      "@babel/plugin-transform-destructuring" // Add destructuring transform
    ]
  },
  webpack: {
    configure: (webpackConfig) => {
      webpackConfig.output = {
        ...webpackConfig.output,
        filename: "static/js/[name].js",
      };
      webpackConfig.optimization = {
        ...webpackConfig.optimization,
        splitChunks: {
          chunks: "all",
          cacheGroups: {
            vendor: {
              test: /[\\/]node_modules[\\/]/,
              name: "vendor",
            },
          },
        },
      };

      // inline all assets into the JS bundle
      webpackConfig.module.rules[0].oneOf.unshift({
        test: /\.(png|jpg|jpeg|woff|woff2|eot|ttf|svg)$/,
        type: "asset/inline",
      });

      return webpackConfig;
    },
  },
  plugins: [
    {
      plugin: {
        overrideWebpackConfig: ({ webpackConfig }) => {
          webpackConfig.plugins[5].options.filename = "static/css/[name].css";
          return webpackConfig;
        },
      },
      options: {},
    },
  ],
};
