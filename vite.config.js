import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, process.cwd(), "");
    const configuredBase = env.VITE_BASE_PATH || "/";
    const withLeadingSlash = configuredBase.startsWith("/") ? configuredBase : `/${configuredBase}`;
    const base = withLeadingSlash.endsWith("/") ? withLeadingSlash : `${withLeadingSlash}/`;
    return {
        base,
        plugins: [react()],
    };
});
