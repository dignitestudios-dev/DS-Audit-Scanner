import tls from "node:tls";
import { fetchSafe, normalizeUrl, safeLookup, ScanError, type FetchResult, type Headers } from "./ssrf";
import { analyzeSeo, type SeoFacts } from "./seo";
import { checkVersions, detectTech } from "./tech";

export type Severity = "high" | "medium" | "low";
export type Category = "security" | "https" | "speed" | "mobile" | "seo" | "access";

export interface Finding {
  id: string;
  category: Category;
  severity: Severity;
  title: string;
  detail: string;
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  scannedAt: string;
  scores: Record<Category | "overall", number>;
  findings: Finding[];
  usedPageSpeed: boolean;
  insights: Insights;
}

export interface Insights {
  tech: string[];
  facts: SeoFacts;
  ttfbMs: number;
  vitals: Vitals | null;
  psiScores: PsiScores | null;
  opportunities: string[];
}

const PENALTY: Record<Severity, number> = { high: 25, medium: 12, low: 4 };
const WEIGHT: Record<Category, number> = {
  security: 0.25,
  https: 0.15,
  speed: 0.2,
  mobile: 0.1,
  seo: 0.2,
  access: 0.1,
};

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);
const has = (h: Headers, name: string) => !!first(h[name]);

/* -------------------------------- security -------------------------------- */

function checkHeaders(res: FetchResult): Finding[] {
  const h = res.headers;
  const out: Finding[] = [];
  const add = (f: Omit<Finding, "category">) => out.push({ ...f, category: "security" });
  const isHttps = res.finalUrl.protocol === "https:";

  if (isHttps && !has(h, "strict-transport-security")) {
    add({
      id: "hsts",
      severity: "medium",
      title: "Browsers aren't told to always use HTTPS",
      detail: "The Strict-Transport-Security header is missing, so visitors can be downgraded to an unencrypted connection.",
    });
  }
  if (!has(h, "content-security-policy")) {
    add({
      id: "csp",
      severity: "medium",
      title: "No Content Security Policy",
      detail: "Without a Content-Security-Policy header, injected scripts are much easier to run on your pages.",
    });
  }
  const csp = first(h["content-security-policy"]) ?? "";
  if (!has(h, "x-frame-options") && !/frame-ancestors/i.test(csp)) {
    add({
      id: "clickjacking",
      severity: "medium",
      title: "Pages can be embedded in other sites",
      detail: "No X-Frame-Options or frame-ancestors rule, which leaves the site open to clickjacking.",
    });
  }
  if (first(h["x-content-type-options"])?.toLowerCase() !== "nosniff") {
    add({
      id: "nosniff",
      severity: "low",
      title: "Missing X-Content-Type-Options",
      detail: "Browsers may guess file types instead of trusting the server, which can turn uploads into attacks.",
    });
  }
  if (!has(h, "referrer-policy")) {
    add({
      id: "referrer",
      severity: "low",
      title: "No Referrer-Policy",
      detail: "Full page addresses, which can contain private details, may be passed to other sites.",
    });
  }
  if (!has(h, "permissions-policy")) {
    add({
      id: "permissions",
      severity: "low",
      title: "No Permissions-Policy",
      detail: "Browser features such as camera and location aren't explicitly restricted.",
    });
  }
  const server = first(h["server"]) ?? "";
  const powered = first(h["x-powered-by"]) ?? "";
  if (/\d+\.\d+/.test(server) || powered) {
    add({
      id: "version-leak",
      severity: "low",
      title: "Server software details are exposed",
      detail: `The server announces what it runs (${[server, powered].filter(Boolean).join(", ")}), which helps attackers pick known exploits.`,
    });
  }
  const cookies = h["set-cookie"];
  const list = Array.isArray(cookies) ? cookies : cookies ? [cookies] : [];
  const weak = list.filter((c) => (isHttps && !/;\s*secure/i.test(c)) || !/;\s*httponly/i.test(c));
  if (weak.length) {
    add({
      id: "cookies",
      severity: "medium",
      title: `${weak.length} cookie${weak.length > 1 ? "s" : ""} missing security flags`,
      detail: "Cookies set without Secure or HttpOnly can be read by scripts or sent over unencrypted connections.",
    });
  }
  return out;
}

/* ---------------------------------- https --------------------------------- */

function peekTls(host: string): Promise<Finding[]> {
  return new Promise((resolve) => {
    const out: Finding[] = [];
    const add = (f: Omit<Finding, "category">) => out.push({ ...f, category: "https" });
    const socket = tls.connect({
      host,
      port: 443,
      servername: host,
      rejectUnauthorized: false,
      lookup: safeLookup,
      timeout: 8000,
    });
    const finish = () => {
      socket.destroy();
      resolve(out);
    };
    socket.on("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      if (!socket.authorized) {
        add({
          id: "cert-invalid",
          severity: "high",
          title: "Security certificate is not trusted",
          detail: `Visitors will see a browser warning (${String(socket.authorizationError)}).`,
        });
      }
      if (cert?.valid_to) {
        const days = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / 86_400_000);
        if (days < 0) {
          add({ id: "cert-expired", severity: "high", title: "Security certificate has expired", detail: "Browsers will block or warn about this site." });
        } else if (days < 14) {
          add({ id: "cert-soon", severity: "high", title: `Certificate expires in ${days} day${days === 1 ? "" : "s"}`, detail: "If it isn't renewed, visitors will get a security warning." });
        } else if (days < 30) {
          add({ id: "cert-soon", severity: "medium", title: `Certificate expires in ${days} days`, detail: "Check that automatic renewal is working." });
        }
      }
      finish();
    });
    socket.on("timeout", () => {
      add({ id: "https-unreachable", severity: "high", title: "HTTPS connection timed out", detail: "The secure version of the site didn't answer in time." });
      finish();
    });
    socket.on("error", () => {
      add({ id: "https-unavailable", severity: "high", title: "The site doesn't support HTTPS", detail: "No secure connection could be made. Browsers label such sites “Not secure”." });
      finish();
    });
  });
}

function checkProtocol(res: FetchResult, requestedHttp: boolean): Finding[] {
  if (res.finalUrl.protocol === "http:") {
    return [
      {
        id: "no-https-redirect",
        category: "https",
        severity: "high",
        title: "Site is served without encryption",
        detail: requestedHttp
          ? "The plain http:// address does not redirect to https://."
          : "The site ends up on an unencrypted http:// page.",
      },
    ];
  }
  return [];
}

/* ----------------------------- html / mobile ------------------------------ */

function checkHtml(res: FetchResult): Finding[] {
  const html = res.body;
  const out: Finding[] = [];
  if (!html || !/<html|<!doctype/i.test(html)) return out;

  if (!/<meta[^>]+name=["']?viewport["']?/i.test(html)) {
    out.push({
      id: "viewport",
      category: "mobile",
      severity: "high",
      title: "Not set up for phones",
      detail: "There is no viewport tag, so mobile browsers show a tiny zoomed-out desktop page.",
    });
  } else if (/user-scalable\s*=\s*(no|0)|maximum-scale\s*=\s*1(\.0)?\b/i.test(html)) {
    out.push({
      id: "zoom-blocked",
      category: "mobile",
      severity: "low",
      title: "Pinch-to-zoom is disabled",
      detail: "Blocking zoom makes the page hard to use for people with poor eyesight.",
    });
  }

  if (res.finalUrl.protocol === "https:") {
    const mixedScripts = /<(script|iframe)[^>]+(src)=["']?http:\/\//i.test(html);
    const mixedOther = /<(img|link|source|video|audio)[^>]+(src|href)=["']?http:\/\/(?!www\.w3\.org)/i.test(html);
    if (mixedScripts) {
      out.push({
        id: "mixed-active",
        category: "security",
        severity: "high",
        title: "Insecure scripts loaded on a secure page",
        detail: "Some scripts or frames load over plain http://, which browsers block and attackers can tamper with.",
      });
    } else if (mixedOther) {
      out.push({
        id: "mixed-passive",
        category: "https",
        severity: "medium",
        title: "Insecure images or files on a secure page",
        detail: "Some resources load over plain http://, which triggers “Not secure” warnings.",
      });
    }
  }

  const jq = html.match(/jquery[-.\/@]?(?:min\.)?v?(\d+)\.(\d+)(?:\.(\d+))?/i);
  if (jq) {
    const major = Number(jq[1]);
    const minor = Number(jq[2]);
    if (major < 3 || (major === 3 && minor < 5)) {
      out.push({
        id: "old-jquery",
        category: "security",
        severity: "medium",
        title: `Outdated jQuery (${jq[1]}.${jq[2]}) in use`,
        detail: "Versions before 3.5 have known cross-site scripting vulnerabilities.",
      });
    }
  }
  return out;
}

/* ---------------------------------- speed --------------------------------- */

function checkSpeed(res: FetchResult): Finding[] {
  const out: Finding[] = [];
  const add = (f: Omit<Finding, "category">) => out.push({ ...f, category: "speed" });
  if (res.ttfbMs > 1800) {
    add({ id: "ttfb", severity: "high", title: `Server is slow to respond (${(res.ttfbMs / 1000).toFixed(1)}s)`, detail: "The first byte took far longer than the recommended 0.8s, which delays everything else." });
  } else if (res.ttfbMs > 800) {
    add({ id: "ttfb", severity: "medium", title: `Server response is sluggish (${(res.ttfbMs / 1000).toFixed(1)}s)`, detail: "The first byte took longer than the recommended 0.8s." });
  }
  const enc = first(res.headers["content-encoding"]);
  if (!enc && res.body.length > 5000) {
    add({ id: "compression", severity: "medium", title: "Pages aren't compressed", detail: "Turning on gzip or Brotli typically cuts page size by 70% or more." });
  }
  if (!has(res.headers, "cache-control") && !has(res.headers, "expires") && !has(res.headers, "etag")) {
    add({ id: "caching", severity: "low", title: "No caching instructions", detail: "Returning visitors re-download everything because no cache rules are sent." });
  }
  return out;
}

export interface Vitals {
  lcpMs: number | null;
  cls: number | null;
  tbtMs: number | null;
  fcpMs: number | null;
}

export interface PsiScores {
  performance: number;
  accessibility: number | null;
  seo: number | null;
  bestPractices: number | null;
}

interface PsiOutcome {
  findings: Finding[];
  ok: boolean;
  vitals: Vitals | null;
  scores: PsiScores | null;
  opportunities: string[];
}

const EMPTY_PSI: PsiOutcome = { findings: [], ok: false, vitals: null, scores: null, opportunities: [] };

async function pageSpeed(url: string): Promise<PsiOutcome> {
  const key = process.env.PSI_API_KEY;
  if (!key) return EMPTY_PSI;
  try {
    const api = new URL("https://www.googleapis.com/pagespeedonline/v5/runPagespeed");
    api.searchParams.set("url", url);
    api.searchParams.set("strategy", "mobile");
    for (const c of ["performance", "accessibility", "seo", "best-practices"]) api.searchParams.append("category", c);
    api.searchParams.set("key", key);
    const r = await fetch(api, { signal: AbortSignal.timeout(35_000) });
    if (!r.ok) return EMPTY_PSI;
    const j = (await r.json()) as {
      lighthouseResult?: {
        categories?: Record<string, { score?: number | null }>;
        audits?: Record<string, { numericValue?: number; title?: string; details?: { type?: string; overallSavingsMs?: number } }>;
      };
    };
    const lh = j.lighthouseResult;
    const pct = (k: string) => (typeof lh?.categories?.[k]?.score === "number" ? Math.round(lh!.categories![k]!.score! * 100) : null);
    const perf = pct("performance");
    if (perf === null) return EMPTY_PSI;
    const a = lh?.audits ?? {};
    const num = (k: string) => (typeof a[k]?.numericValue === "number" ? a[k].numericValue! : null);
    const vitals: Vitals = {
      lcpMs: num("largest-contentful-paint"),
      cls: num("cumulative-layout-shift"),
      tbtMs: num("total-blocking-time"),
      fcpMs: num("first-contentful-paint"),
    };
    const scores: PsiScores = { performance: perf, accessibility: pct("accessibility"), seo: pct("seo"), bestPractices: pct("best-practices") };

    const findings: Finding[] = [];
    const lcpText = vitals.lcpMs !== null ? ` Main content appears after ${(vitals.lcpMs / 1000).toFixed(1)}s on a phone.` : "";
    if (perf < 50) {
      findings.push({ id: "psi", category: "speed", severity: "high", title: `Slow on mobile (Google score ${perf}/100)`, detail: `Google's PageSpeed test rates this site as poor.${lcpText}` });
    } else if (perf < 90) {
      findings.push({ id: "psi", category: "speed", severity: "medium", title: `Mobile speed needs work (Google score ${perf}/100)`, detail: `Google's PageSpeed test finds room for improvement.${lcpText}` });
    }
    if (vitals.cls !== null && vitals.cls > 0.25) {
      findings.push({ id: "cls", category: "speed", severity: "medium", title: "Page jumps around while loading", detail: `Layout shift score is ${vitals.cls.toFixed(2)} (should be under 0.1). Visitors mis-tap buttons when content moves.` });
    }
    if (vitals.tbtMs !== null && vitals.tbtMs > 600) {
      findings.push({ id: "tbt", category: "speed", severity: "medium", title: "Page is slow to react to taps", detail: `Scripts block the page for ${Math.round(vitals.tbtMs)} ms on a phone (should be under 200 ms).` });
    }
    if (scores.accessibility !== null && scores.accessibility < 90) {
      findings.push({ id: "psi-a11y", category: "access", severity: scores.accessibility < 70 ? "high" : "medium", title: `Accessibility score ${scores.accessibility}/100`, detail: "Google's automated test found barriers such as low contrast, missing labels or unnamed buttons." });
    }
    if (scores.seo !== null && scores.seo < 90) {
      findings.push({ id: "psi-seo", category: "seo", severity: "medium", title: `Google's SEO check scores ${scores.seo}/100`, detail: "Google's basic search-readiness test found things that stop pages from being crawled or understood." });
    }
    if (scores.bestPractices !== null && scores.bestPractices < 80) {
      findings.push({ id: "psi-bp", category: "security", severity: "low", title: `Web best-practices score ${scores.bestPractices}/100`, detail: "Browser console errors, deprecated features or insecure requests were detected." });
    }

    const opportunities = Object.values(a)
      .filter((x) => x.details?.type === "opportunity" && (x.details.overallSavingsMs ?? 0) > 300 && x.title)
      .sort((x, y) => (y.details!.overallSavingsMs ?? 0) - (x.details!.overallSavingsMs ?? 0))
      .slice(0, 5)
      .map((x) => x.title!);

    return { findings, ok: true, vitals, scores, opportunities };
  } catch {
    return EMPTY_PSI;
  }
}

/* --------------------------------- scoring -------------------------------- */

const CATEGORIES = Object.keys(WEIGHT) as Category[];

function score(findings: Finding[]): ScanResult["scores"] {
  const cats = {} as Record<Category, number>;
  for (const c of CATEGORIES) {
    const loss = findings.filter((f) => f.category === c).reduce((s, f) => s + PENALTY[f.severity], 0);
    cats[c] = Math.max(0, 100 - loss);
  }
  const overall = Math.round(CATEGORIES.reduce((s, c) => s + cats[c] * WEIGHT[c], 0));
  return { ...cats, overall };
}

async function sideFetch(base: URL, path: string): Promise<FetchResult | null> {
  try {
    return await fetchSafe(new URL(path, base));
  } catch {
    return null;
  }
}

export async function scanUrl(input: string): Promise<ScanResult> {
  const start = normalizeUrl(input);
  const requestedHttp = start.protocol === "http:";

  const psiPromise = pageSpeed(start.toString());
  const res = await fetchSafe(start);

  if (res.status >= 400) {
    throw new ScanError(`The website answered with an error (HTTP ${res.status}). Check the address and try again.`);
  }

  const [tlsFindings, robots, sitemap] = await Promise.all([
    res.finalUrl.protocol === "https:" ? peekTls(res.finalUrl.hostname) : Promise.resolve([] as Finding[]),
    sideFetch(res.finalUrl, "/robots.txt"),
    sideFetch(res.finalUrl, "/sitemap.xml"),
  ]);
  const psi = await psiPromise;
  const seo = analyzeSeo(res, { robots, sitemap });

  const findings: Finding[] = [
    ...checkProtocol(res, requestedHttp),
    ...tlsFindings,
    ...checkHeaders(res),
    ...checkHtml(res),
    ...checkVersions(res.body, res.headers),
    ...checkSpeed(res),
    ...seo.findings,
    ...psi.findings,
  ];

  return {
    url: start.toString(),
    finalUrl: res.finalUrl.toString(),
    scannedAt: new Date().toISOString(),
    scores: score(findings),
    findings,
    usedPageSpeed: psi.ok,
    insights: {
      tech: detectTech(res.body, res.headers),
      facts: seo.facts,
      ttfbMs: res.ttfbMs,
      vitals: psi.vitals,
      psiScores: psi.scores,
      opportunities: psi.opportunities,
    },
  };
}

const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
export const bySeverity = (a: Finding, b: Finding) => ORDER[a.severity] - ORDER[b.severity];
