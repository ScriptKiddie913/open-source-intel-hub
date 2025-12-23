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
