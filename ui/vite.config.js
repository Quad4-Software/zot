// vite.config.js
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [
    react({
      include: '**/*.{jsx,js}'
    })
  ],
  publicDir: 'public',
  resolve: {
    alias: {
      api: path.resolve(__dirname, './src/api.js'),
      theme: path.resolve(__dirname, './src/theme.js'),
      utilities: path.resolve(__dirname, './src/utilities'),
      components: path.resolve(__dirname, './src/components'),
      pages: path.resolve(__dirname, './src/pages'),
      assets: path.resolve(__dirname, './src/assets'),
      __mocks__: path.resolve(__dirname, './src/__mocks__'),
      host: path.resolve(__dirname, './src/host.js'),
      session: path.resolve(__dirname, './src/session.js')
    }
  },
  build: {
    outDir: 'build',
    target: 'es2020',
    cssCodeSplit: true,
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router', 'react-router-dom'],
          mui: ['@mui/material', '@mui/icons-material', '@mui/lab', '@mui/styles', '@mui/x-date-pickers'],
          emotion: ['@emotion/react', '@emotion/styled']
        }
      }
    }
  },
  esbuild: {
    loader: 'jsx',
    include: /src\/.*\.[jt]sx?$/,
    exclude: []
  }
});
