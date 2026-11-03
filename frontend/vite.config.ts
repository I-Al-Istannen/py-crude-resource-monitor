import { defineConfig } from "vite";
import { viteSingleFile } from "vite-plugin-singlefile"

export default defineConfig(() => ({
    build: {
        minify: false,
    },
    plugins: [viteSingleFile()]
}));
