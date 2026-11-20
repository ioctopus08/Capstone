import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv } from 'vite'

// Content-Security-Policy for the production build. The page only needs its own
// bundled JS/CSS and to talk to the analysis API - nothing else may load, which
// neutralises XSS even if a hostile sample's strings ever slipped past React's
// escaping. (Dev mode is left without it: Vite's HMR needs inline scripts.)
function cspPlugin(apiBase) {
  let apiOrigin = ''
  try {
    apiOrigin = new URL(apiBase).origin
  } catch {
    apiOrigin = ''
  }
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    `connect-src 'self' ${apiOrigin}`.trim(),
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; ')
  return {
    name: 'gozetci-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '<meta charset="UTF-8" />',
        `<meta charset="UTF-8" />\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />\n    <meta name="referrer" content="no-referrer" />`,
      )
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiBase = env.VITE_API_BASE || 'http://127.0.0.1:8002'
  return {
    plugins: [react(), cspPlugin(apiBase)],
    // Localhost only by default - pass --host explicitly to expose on a LAN.
    server: { host: '127.0.0.1', port: 5173, strictPort: true },
    preview: { host: '127.0.0.1', port: 4173, strictPort: true },
    build: { sourcemap: false },
  }
})
