import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

/*
=====================================================
 VITE CONFIGURATION
=====================================================

✔ Framework: React (SWC)
✔ Router: BrowserRouter compatible
✔ Deployment: Vercel-safe
✔ Alias support: @ -> /src
✔ Dev-only tooling: lovable-tagger
✔ NO base path (important for SPA routing)
✔ NO server-side routing assumptions

=====================================================
*/

export default defineConfig(({ mode }) => {
  return {
    /*
    --------------------------------------------------
    Development Server Configuration
    --------------------------------------------------
    - Only affects local development
    - Does NOT affect Vercel or production builds
    */
    server: {
      host: "::",          // Allow IPv4 + IPv6
      port: 8080,          // Fixed dev port
      proxy: {
        // Proxy Library of Leaks API requests during development
        '/api/library-of-leaks': {
          target: 'https://search.libraryofleaks.org',
          changeOrigin: true,
          rewrite: (path) => {
            // Extract query params and convert to the Aleph API format
            const url = new URL(path, 'http://localhost');
            const q = url.searchParams.get('q') || '';
            const limit = url.searchParams.get('limit') || '30';
            const schema = url.searchParams.get('schema') || 'Thing';
            return `/api/2/entities?filter:schemata=${schema}&highlight=true&limit=${limit}&q=${encodeURIComponent(q)}`;
          },
          headers: {
            'Accept': 'application/json',
            'Accept-Language': 'en',
            'Origin': 'https://search.libraryofleaks.org',
            'Referer': 'https://search.libraryofleaks.org/',
          },
        },
        // Proxy abuse.ch Feodo Tracker API
        '/api/feodo': {
          target: 'https://feodotracker.abuse.ch',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/feodo/, '/downloads'),
        },
        // Proxy abuse.ch URLhaus API
        '/api/urlhaus': {
          target: 'https://urlhaus.abuse.ch',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/urlhaus/, '/downloads'),
        },
        // Proxy abuse.ch ThreatFox API
        '/api/threatfox': {
          target: 'https://threatfox.abuse.ch',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/threatfox/, '/export'),
        },
        // Proxy abuse.ch MalwareBazaar API
        '/api/bazaar': {
          target: 'https://bazaar.abuse.ch',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/bazaar/, '/export'),
        },
        // Proxy Cisco Talos Intelligence - Reputation Center
        '/api/talos': {
          target: 'https://talosintelligence.com',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/talos/, ''),
        },
        // Proxy AlienVault OTX - Open Threat Exchange
        '/api/otx': {
          target: 'https://otx.alienvault.com',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/otx/, '/api/v1'),
        },
        // Proxy Phishtank API
        '/api/phishtank': {
          target: 'https://data.phishtank.com',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/phishtank/, '/data'),
        },
        // Proxy Botvrij.eu blocklists  
        '/api/botvrij': {
          target: 'https://www.botvrij.eu',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/botvrij/, '/data'),
        },
        // Proxy OpenPhish feed
        '/api/openphish': {
          target: 'https://openphish.com',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/openphish/, ''),
        },
        // Proxy SSLBL - SSL Blacklist by abuse.ch
        '/api/sslbl': {
          target: 'https://sslbl.abuse.ch',
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/sslbl/, '/blacklist'),
        },
      },
    },

    /*
    --------------------------------------------------
    Plugins
    --------------------------------------------------
    - React SWC for fast compilation
    - lovable-tagger ONLY in development
    - filter(Boolean) ensures no false plugins
    */
    plugins: [
      react(),
      mode === "development" && componentTagger(),
    ].filter(Boolean),

    /*
    --------------------------------------------------
    Path Resolution / Aliases
    --------------------------------------------------
    - Enables import "@/..." from /src
    - Works across TS, Vite, and IDE
    */
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },

    /*
    --------------------------------------------------
    IMPORTANT NOTES (DO NOT REMOVE)
    --------------------------------------------------
    - NO `base` option is defined here
      This is REQUIRED for Vercel SPA routing.

    - React Router relies on index.html fallback
      Handled by vercel.json rewrite.

    - DO NOT add:
        base: "/"
        base: "./"
        base: "/app"
      Doing so WILL break refresh routing.

    - This config assumes:
        ✔ BrowserRouter
        ✔ vercel.json rewrite
        ✔ index.html at root
    */
  };
});
