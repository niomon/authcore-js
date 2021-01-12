const path = require('path')
const webpack = require('webpack')
const TerserPlugin = require('terser-webpack-plugin')

module.exports = {
  mode: 'production',
  entry: './src/index.js', // or './src/index.ts' if TypeScript
  output: {
    filename: 'authcore.min.js', // Desired file name. Same as in package.json's "main" field.
    path: path.resolve(__dirname, 'dist'),
    library: 'authcore', // Desired name for the global variable when using as a drop-in script-tag.
    libraryTarget: 'umd',
    globalObject: 'this'
  },
  module: {
    rules: [
      {
        include: path.resolve(__dirname, 'src'),
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              '@babel/preset-env'
            ],
            plugins: [
              '@babel/plugin-transform-runtime', 
              '@babel/plugin-transform-modules-commonjs',
            ],
            sourceMaps: true
          }
        }
      }
    ]
  },
  resolve: {
    fallback: {
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
    }
  },
  plugins: [
    // fix "process is not defined" error:
    // (do "npm install process" before running the build)
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
      process: 'process/browser',
    }),
  ],
  optimization: {
    minimize: true,
    minimizer: [new TerserPlugin()]
  }
}
