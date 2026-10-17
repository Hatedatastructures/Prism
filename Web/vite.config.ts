import { defineConfig } from 'vite';
import React from '@vitejs/plugin-react';
import { TrustedProxyOrigin } from './scripts/ProxyOrigin.ts';

/** @brief 手动构建默认写入仓库 build/Web；CMake 通过 --outDir 写入二进制树。 */
export default defineConfig({
    plugins: [React()],
    base: '/',
    build: { outDir: '../build/Web', emptyOutDir: false, sourcemap: false, manifest: true },
    server: {
        host: '127.0.0.1',
        strictPort: true,
        proxy: {
            '/Operations': {
                target: 'http://127.0.0.1:9090', changeOrigin: true,
                configure(Proxy) {
                    Proxy.on('proxyReq', (Outgoing, Incoming) => {
                        const Origin = TrustedProxyOrigin(Incoming.headers, 'http://127.0.0.1:9090');
                        if (Origin) Outgoing.setHeader('origin', Origin);
                    });
                },
            },
        },
    },
});
