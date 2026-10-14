import { defineConfig } from 'vite';
import React from '@vitejs/plugin-react';
import Tailwind from '@tailwindcss/vite';

/** @brief 只在唯一仓库 build 中生成本机管理页面；发布后无需独立 Web server。 */
export default defineConfig({
    plugins: [React(), Tailwind()],
    base: '/',
    build: { outDir: '../build/Web', emptyOutDir: false, sourcemap: false, manifest: true },
    server: { host: '127.0.0.1', strictPort: true },
});
