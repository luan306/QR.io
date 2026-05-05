// import { defineConfig } from "vite";
// import react from "@vitejs/plugin-react";

// export default defineConfig({
//   plugins: [react()],
//   server: {
//     proxy: {
//       "/api": {
//         target: "https://192.168.88.131:3000",
//         changeOrigin: true,
//         secure: false,
//       },
//       "/logout": {
//         target: "https://192.168.88.131:3000",
//         changeOrigin: true,
//         secure: false,
//       },
//     },
//   },
// });

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  optimizeDeps: {
    include: ['pdfjs-dist'],
  },
  server: {
    proxy: {
      "/api": {
        target: "https://192.168.169.1:3000",
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: "localhost",  // ← rewrite cookie domain về localhost
      },
      "/logout": {
        target: "https://192.168.169.1:3000",
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: "localhost",
      },
      "/layouts": {
        target: "https://192.168.169.1:3000",
        changeOrigin: true,
        secure: false,
        cookieDomainRewrite: "localhost",
      },
      "/socket.io": {
        target: "https://192.168.169.1:3000",
        changeOrigin: true,
        secure: false,
        ws: true,
        cookieDomainRewrite: "localhost",
      },
    },
  },
});