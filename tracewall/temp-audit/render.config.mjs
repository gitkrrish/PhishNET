// Bundler config for the render harnesses.
//
//   npx rolldown -c temp-audit/render.config.mjs
//   npm run verify:render
//
// Both harnesses are built in one pass and share their chunks, so there is no
// entry-name argument to get wrong when this runs from an npm script.
//
// Stylesheets are replaced with an empty module: the harnesses render to static
// markup in Node, where a CSS side-effect import has no meaning and would
// otherwise fail the bundle for reasons that have nothing to do with the code
// under test.
const emptyStyleModule = `
const style = {};
export default style;
`;

export default {
  input: ['temp-audit/protection-panels.tsx', 'temp-audit/protection-render.tsx', 'temp-audit/protection-effects.tsx', 'temp-audit/custody-nl-render.tsx', 'temp-audit/monitoring-hub-client.mts'],
  platform: 'node',
  output: {
    dir: 'temp-audit/.out',
    entryFileNames: '[name].mjs',
    format: 'esm',
    // `mockBackend` reads `import.meta.env` at module scope, and Vite's
    // replacement of that expression does not happen here, so the object is
    // created before any module body runs. The point is unreachable on
    // purpose: this pass must never reach a real API.
    banner: "import.meta.env = { VITE_API_URL: 'http://127.0.0.1:9/api' };",
  },
  plugins: [
    {
      name: 'css-stub',
      resolveId(source) {
        if (/\.css$/.test(source)) return '\0css-stub';
        return null;
      },
      load(id) {
        if (id === '\0css-stub') return emptyStyleModule;
        return null;
      },
    },
  ],
  transform: {
    jsx: 'react-jsx',
  },
};
