import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "..");
const siteRoot = path.join(repositoryRoot, "site");
const pagesRoot = path.join(repositoryRoot, "docs");

const { default: worker } = await import(
  pathToFileURL(path.join(siteRoot, "dist", "server", "index.js")).href
);

const response = await worker.fetch(
  new Request("https://wireguardtcp.net/"),
  {
    ASSETS: {
      fetch: async () => new Response("Not found", { status: 404 }),
    },
  },
  {
    waitUntil() {},
    passThroughOnException() {},
  },
);

if (!response.ok) {
  throw new Error(`Site render failed with HTTP ${response.status}`);
}

const css = await readFile(
  path.join(siteRoot, "dist", "client", "assets", "index-DXb3C1so.css"),
  "utf8",
).catch(async () => {
  const assets = await import("node:fs/promises").then(({ readdir }) =>
    readdir(path.join(siteRoot, "dist", "client", "assets")),
  );
  const cssFile = assets.find((name) => /^index-.*\.css$/.test(name));
  if (!cssFile) throw new Error("Built CSS asset was not found");
  return readFile(path.join(siteRoot, "dist", "client", "assets", cssFile), "utf8");
});

let html = await response.text();
html = html
  .replace(/<link[^>]+rel="stylesheet"[^>]*\/?>/gi, "")
  .replace(/<link[^>]+rel="modulepreload"[^>]*\/?>/gi, "")
  .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "")
  .replace("</head>", `<style>${css}</style></head>`);

await mkdir(pagesRoot, { recursive: true });
await cp(path.join(siteRoot, "public", "downloads"), path.join(pagesRoot, "downloads"), {
  recursive: true,
  force: true,
});
await cp(path.join(siteRoot, "public", "og.png"), path.join(pagesRoot, "og.png"), {
  force: true,
});
await cp(
  path.join(siteRoot, "public", "favicon.svg"),
  path.join(pagesRoot, "favicon.svg"),
  { force: true },
);
await writeFile(path.join(pagesRoot, "index.html"), html, "utf8");
await writeFile(path.join(pagesRoot, "CNAME"), "wireguardtcp.net\n", "utf8");
await writeFile(
  path.join(pagesRoot, ".nojekyll"),
  "Serve the generated static assets without Jekyll processing.\n",
  "utf8",
);

console.log(`GitHub Pages export written to ${pagesRoot}`);
