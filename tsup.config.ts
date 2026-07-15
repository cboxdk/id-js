import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    nextjs: 'src/nextjs.ts',
  },
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  // `next` is an optional peer — never bundle it into the output.
  external: ['next', 'next/headers', 'next/server'],
});
