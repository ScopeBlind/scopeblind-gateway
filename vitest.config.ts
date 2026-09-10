import { defineConfig } from 'vitest/config';

export default defineConfig({
  // This package has no CSS. Without this, vite walks up to the monorepo root,
  // finds the web client's PostCSS config, and fails to start when tailwindcss
  // is not installed at the root (any checkout that only installed this package).
  css: { postcss: {} },
    test: {
        include: ['src/**/*.test.ts'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'text-summary', 'lcov'],
            reportsDirectory: './coverage',
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.test.ts', 'src/types.ts', 'src/cli.ts'],
        },
    },
});
