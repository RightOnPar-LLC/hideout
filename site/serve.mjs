// Local preview of the site: serves public/ on 127.0.0.1 with the same headers as _headers,
// and 404.html for anything missing. `node site/serve.mjs [port]`
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "public");
const PORT = Number(process.argv[2] || process.env.PORT || 4388);
const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8" };
const headers = Object.fromEntries(fs.readFileSync(path.join(ROOT, "_headers"), "utf8").split(/\r?\n/).filter((l) => /^\s+\S+:/.test(l)).map((l) => { const i = l.indexOf(":"); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; }));

http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p.endsWith("/")) p += "index.html";
  const file = path.join(ROOT, path.normalize(p));
  const inside = file.startsWith(ROOT + path.sep) && !path.basename(file).startsWith("_");
  const found = inside && fs.existsSync(file) && fs.statSync(file).isFile();
  const target = found ? file : path.join(ROOT, "404.html");
  res.writeHead(found ? 200 : 404, { ...headers, "content-type": TYPES[path.extname(target)] || "application/octet-stream" });
  fs.createReadStream(target).pipe(res);
}).listen(PORT, "127.0.0.1", () => console.log(`site preview: http://127.0.0.1:${PORT}/`));
