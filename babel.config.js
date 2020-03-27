
module.exports = {
  presets: [
    [
      '@babel/preset-env',
      { modules: 'commonjs' }
    ]
  ],
  plugins: [
    [
      '@babel/plugin-transform-runtime',
      {
        'corejs': 3
      }
    ]
  ],
  sourceMaps: true
}
