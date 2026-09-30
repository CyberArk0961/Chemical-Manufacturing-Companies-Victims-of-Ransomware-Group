// Pulls ransomware victim data from the ransomware.live API PRO and writes two
// JSON feeds for the Ransomware Intelligence Dashboard (GitHub feed mode):
//   output/live/victims.json   – most recent disclosed victims (all sectors)
//   output/live/chemical.json  – chemical / manufacturing victims for the last N months
// Runs in GitHub Actions on Node 20 (built-in fetch). No dependencies.
// Data source: ransomware.live – https://www.ransomware.live (credit required by its terms).
import { mkdir, readFile, writeFile } from "node:fs/promises";

const KEY = process.env.RL_API_KEY || "";
const BASE = (process.env.RL_BASE || "https://api-pro.ransomware.live").replace(/\/+$/, "");
const MONTHS = Math.max(1, Math.min(24, parseInt(process.env.MONTHS || "12", 10)));
const OUT = process.env.OUT || "output/live";
const SECTOR_RE = new RegExp(process.env.SECTOR_REGEX || "chem|manufactur|industrial", "i");
const CHEM_RE = new RegExp(process.env.CHEM_REGEX ||
  "chem|chimi|quimic|químic|polymer|resin|coating|paint|pigment|adhesive|sealant|surfactant|catalyst|plastic|petrochem|fertili[sz]|agrochem|specialty materials|cellulose|peroxide", "i");
const SOURCE = "ransomware.live API PRO – https://www.ransomware.live (leak-site claims, not confirmed incidents)";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let requests = 0, warnings = 0;

class Fatal extends Error {}
async function get(path) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    requests++;
    let r;
    try {
      r = await fetch(BASE + path, { headers: { "X-API-KEY": KEY, Accept: "application/json", "User-Agent": "ransomware-intel-dashboard-feed/1.0" } });
    } catch (e) {
      if (attempt === 3) { warnings++; console.log(`::warning::${path} network error: ${e.message}`); return []; }
      await sleep(3000 * attempt); continue;
    }
    if (r.status === 401 || r.status === 403) throw new Fatal(`API key rejected (${r.status}) – check the RL_API_KEY secret`);
    if (r.status === 429) throw new Fatal("API quota exceeded (429)");
    if (r.status >= 500 && attempt < 3) { await sleep(3000 * attempt); continue; }
    if (!r.ok) { warnings++; console.log(`::warning::${path} returned HTTP ${r.status}`); return []; }
    try { return await r.json(); } catch { warnings++; console.log(`::warning::${path} returned invalid JSON`); return []; }
  }
  return [];
}

const arr = (d) => {
  if (Array.isArray(d)) return d;
  if (d && typeof d === "object") {
    for (const k of ["victims", "data", "results", "items"]) if (Array.isArray(d[k])) return d[k];
    return Object.values(d).find(Array.isArray) || [];
  }
  return [];
};
const str = (v) => (typeof v === "string" ? v : v == null ? "" : String(v));
const slim = (v) => {
  const victim = str(v.victim ?? v.post_title).trim(), group = str(v.group ?? v.group_name).trim();
  const info = v.infostealer;
  return {
    victim, group,
    discovered: str(v.discovered), attackdate: str(v.attackdate ?? v.published),
    country: str(v.country).toUpperCase(), activity: str(v.activity ?? v.sector),
    website: str(v.website), description: str(v.description).slice(0, 600),
    permalink: str(v.permalink), press: typeof v.press === "string" ? v.press : "",
    infostealer: !!(info && (typeof info === "object" ? Object.keys(info).length : String(info).length)),
    id: str(v.id) || `${victim}@${group}`,
  };
};
const sectorNames = (d) => {
  if (Array.isArray(d)) return d.map((x) => (typeof x === "string" ? x : x && (x.sector || x.name || x.activity))).filter(Boolean);
  if (d && typeof d === "object") return d.sectors ? sectorNames(d.sectors) : Object.keys(d);
  return [];
};
const monthList = (n) => {
  const now = new Date(), out = [];
  for (let i = 0; i < n; i++) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - i, 1));
    out.push([String(d.getUTCFullYear()), String(d.getUTCMonth() + 1).padStart(2, "0")]);
  }
  return out;
};

// Write only when the victim list changed, so the repo is not committed every run.
async function writeIfChanged(file, victims, extra) {
  const path = `${OUT}/${file}`;
  try {
    const old = JSON.parse(await readFile(path, "utf8"));
    if (JSON.stringify(old.victims) === JSON.stringify(victims)) { console.log(`${file}: unchanged (${victims.length})`); return; }
  } catch { /* first run */ }
  const body = { last_updated: new Date().toISOString(), source: SOURCE, count: victims.length, ...extra, victims };
  await writeFile(path, JSON.stringify(body, null, 1) + "\n");
  console.log(`${file}: written (${victims.length})`);
}

async function main() {
  if (!KEY) throw new Fatal("RL_API_KEY secret is not set (Settings → Secrets and variables → Actions)");
  await mkdir(OUT, { recursive: true });
  await get("/validate");

  const recent = arr(await get("/victims/recent")).map(slim)
    .sort((a, b) => (b.discovered || b.attackdate).localeCompare(a.discovered || a.attackdate));

  let sectors = sectorNames(await get("/listsectors")).filter((s) => SECTOR_RE.test(s));
  if (!sectors.length) sectors = ["Manufacturing"];
  console.log(`Sectors: ${sectors.join(", ")} · months: ${MONTHS}`);

  const byId = new Map();
  const add = (list) => list.map(slim).forEach((v) => byId.set(v.id, v));
  for (const s of sectors) {
    for (const [y, m] of monthList(MONTHS)) {
      add(arr(await get(`/victims/?sector=${encodeURIComponent(s)}&year=${y}&month=${m}`)));
      await sleep(250);
    }
  }
  add(arr(await get("/victims/search?q=chem")));
  recent.filter((v) => SECTOR_RE.test(v.activity) || CHEM_RE.test(`${v.activity} ${v.victim} ${v.website} ${v.description}`)).forEach((v) => byId.set(v.id, v));

  const [y0, m0] = monthList(MONTHS).at(-1), cutoff = `${y0}-${m0}-01`;
  const chemical = [...byId.values()]
    .filter((v) => (v.discovered || v.attackdate) >= cutoff)
    .map((v) => ({ ...v, chemical: CHEM_RE.test(`${v.activity} ${v.victim} ${v.website} ${v.description}`) }))
    .sort((a, b) => (b.discovered || b.attackdate).localeCompare(a.discovered || a.attackdate) || a.id.localeCompare(b.id));

  await writeIfChanged("victims.json", recent, {});
  await writeIfChanged("chemical.json", chemical, { months: MONTHS, sectors, chemical_matches: chemical.filter((v) => v.chemical).length });
  console.log(`Done – ${requests} API requests, ${warnings} warning(s).`);
}

main().catch((e) => { console.log(`::error::${e.message}`); process.exit(1); });
