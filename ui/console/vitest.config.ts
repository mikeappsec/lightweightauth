import { defineConfig } from "vitest/config";
import solidPlugin from "vite-plugin-solid";

// Vitest configuration is split from vite.config.ts to keep test-only
// options (jsdom environment, test globals) out of the production build
// path. The solid plugin handles JSX transform + dev-mode reactivity
// automatically under vitest (it detects `import.meta.env.DEV === true`
// which vitest sets by default).
//
// `solidPlugin({ hot: false })` disables the @solid-refresh virtual
// module that vite-plugin-solid injects under Vite — under Vitest
// the module resolves to an invalid `file:///@solid-refresh` URL,
// which throws on import. Disabling HMR is the documented fix and
// has no effect on test reactivity or signal behaviour.
export default defineConfig({
  plugins: [solidPlugin({ hot: false })],
  test: {
    environment: "jsdom",
    globals: true,
    // SolidJS signal effects + jsdom requestAnimationFrame interplay
    // can race the standard vitest timeout; relax to 10s to keep CI
    // stable without masking real hangs.
    testTimeout: 10_000,
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.{test,spec}.ts", "src/main.tsx", "src/index.tsx"],
    },
  },
});