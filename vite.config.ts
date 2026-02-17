import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  return {
    // Prevent vite from obscuring Rust errors
    clearScreen: false,
    server: {
      port: 3000,
      host: '0.0.0.0',
      // Tauri expects a fixed port
      strictPort: true,
    },
    // Env variables starting with TAURI_ are exposed to tauri
    envPrefix: ['VITE_', 'TAURI_'],
    plugins: [react()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, 'src'),
      }
    },
    build: {
      // Tauri uses Chromium on Windows and WebKit on macOS and Linux
      target: process.env.TAURI_ENV_PLATFORM === 'windows' ? 'chrome105' : 'safari13',
      // Don't minify for debug builds
      minify: !process.env.TAURI_ENV_DEBUG ? 'esbuild' : false,
      // Produce sourcemaps for debug builds
      sourcemap: !!process.env.TAURI_ENV_DEBUG,
    }
  };
});
