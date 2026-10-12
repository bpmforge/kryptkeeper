// Serve the PRODUCTION ui/dist bundle with an /api proxy to the real backend.
//
// Why this exists: `npm run dev` starts MSW whenever import.meta.env.DEV, so
// the dev server answers from ui/src/mocks/fixtures.ts and accepts any
// credentials — anything reviewed there documents fixtures, not the product.
// SESSION_STATUS.md's review recipe depends on this file; it was previously
// recreated by hand each session.
//
//   ./scripts/dev/local-review-env.sh start
//   npm --prefix ui run build && node scripts/dev/serve-real.mjs
import http from "node:http";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const DIST = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../ui/dist");
const API = process.env.KK_REVIEW_API ?? "http://127.0.0.1:8080";
const PORT = Number(process.env.KK_REVIEW_PORT ?? 4180);

const types = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".json": "application/json",
};

http
  .createServer(async (req, res) => {
    if (req.url.startsWith("/api/")) {
      const target = new URL(API);
      const proxied = http.request(
        API + req.url,
        { method: req.method, headers: { ...req.headers, host: target.host } },
        (pr) => {
          res.writeHead(pr.statusCode, pr.headers);
          pr.pipe(res);
        },
      );
      proxied.on("error", (e) => {
        res.writeHead(502);
        res.end(String(e));
      });
      req.pipe(proxied);
      return;
    }
    // SPA fallback: any non-file route serves index.html so deep links work.
    let fp = path.join(DIST, decodeURIComponent(req.url.split("?")[0]));
    if (!fp.startsWith(DIST) || !existsSync(fp) || fp === DIST + path.sep) {
      fp = path.join(DIST, "index.html");
    }
    try {
      const body = await readFile(fp);
      res.writeHead(200, {
        "content-type": types[path.extname(fp)] || "application/octet-stream",
      });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end("not found");
    }
  })
  .listen(PORT, () => console.log(`ui http://127.0.0.1:${PORT} -> api ${API}`));
