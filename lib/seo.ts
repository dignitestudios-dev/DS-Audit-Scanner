import type { Finding } from "./scan";
import type { FetchResult, Headers } from "./ssrf";

export interface SeoFacts {
  title: string | null;
  description: string | null;
  h1Count: number;
  wordCount: number;
  images: number;
  imagesMissingAlt: number;
  hasCanonical: boolean;
  hasOpenGraph: boolean;
  hasStructuredData: boolean;
  hasRobots: boolean;
  hasSitemap: boolean;
  lang: string | null;
  indexable: boolean;
  htmlKb: number;
}

export interface Extras {
  robots: FetchResult | null;
  sitemap: FetchResult | null;
}

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

function attr(tag: string, name: string): string | undefined {
  const m = tag.match(new RegExp(`[\\s"']${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3]) : undefined;
}

function metaContent(html: string, key: string): string | undefined {
  for (const tag of html.match(/<meta\b[^>]*>/gi) ?? []) {
    const k = (attr(tag, "name") ?? attr(tag, "property"))?.toLowerCase();
    if (k === key) return attr(tag, "content");
  }
  return undefined;
}

const decode = (s: string) =>
  s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d))).replace(/\s+/g, " ").trim();

export function analyzeSeo(res: FetchResult, extras: Extras): { findings: Finding[]; facts: SeoFacts } {
  const html = res.body;
  const findings: Finding[] = [];
  const add = (category: "seo" | "access", f: Omit<Finding, "category">) => findings.push({ ...f, category });

  const titleRaw = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1];
  const title = titleRaw ? decode(titleRaw) : null;
  const description = metaContent(html, "description")?.trim() || null;
  const h1Count = (html.match(/<h1\b/gi) ?? []).length;
  const imgs = html.match(/<img\b[^>]*>/gi) ?? [];
  const imagesMissingAlt = imgs.filter((t) => attr(t, "alt") === undefined).length;
  const hasCanonical = (html.match(/<link\b[^>]*>/gi) ?? []).some((t) => attr(t, "rel")?.toLowerCase() === "canonical");
  const hasOpenGraph = !!metaContent(html, "og:title") && !!metaContent(html, "og:image");
  const hasStructuredData = /<script[^>]+application\/ld\+json/i.test(html);
  const lang = attr(html.match(/<html\b[^>]*>/i)?.[0] ?? "", "lang") ?? null;

  const text = html
    .replace(/<(script|style|noscript|svg)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&[a-z#0-9]+;/gi, " ");
  const wordCount = (text.match(/[\p{L}\p{N}'’-]+/gu) ?? []).length;

  const robotsMeta = (metaContent(html, "robots") ?? "") + " " + (first(res.headers["x-robots-tag"] as Headers[string]) ?? "");
  const noindex = /noindex/i.test(robotsMeta);

  const robotsOk = !!extras.robots && extras.robots.status === 200 && !/<html/i.test(extras.robots.body.slice(0, 300));
  const robotsTxt = robotsOk ? extras.robots!.body : "";
  const blocksAll = (() => {
    let star = false;
    for (const raw of robotsTxt.split(/\r?\n/)) {
      const line = raw.split("#")[0].trim().toLowerCase();
      if (line.startsWith("user-agent:")) star = line.slice(11).trim() === "*";
      else if (star && /^disallow:\s*\/\s*$/.test(line)) return true;
    }
    return false;
  })();
  const sitemapInRobots = /^sitemap:/im.test(robotsTxt);
  const sitemapOk =
    !!extras.sitemap && extras.sitemap.status === 200 && /<urlset|<sitemapindex/i.test(extras.sitemap.body.slice(0, 2000));
  const hasSitemap = sitemapOk || sitemapInRobots;

  const facts: SeoFacts = {
    title,
    description,
    h1Count,
    wordCount,
    images: imgs.length,
    imagesMissingAlt,
    hasCanonical,
    hasOpenGraph,
    hasStructuredData,
    hasRobots: robotsOk,
    hasSitemap,
    lang,
    indexable: !noindex && !blocksAll,
    htmlKb: Math.round(Buffer.byteLength(html) / 1024),
  };

  if (!html || !/<html|<!doctype/i.test(html)) return { findings, facts };

  if (noindex) {
    add("seo", { id: "noindex", severity: "high", title: "Page is hidden from Google", detail: "A noindex instruction tells search engines not to list this page. If that's not intentional, you are invisible in search." });
  }
  if (blocksAll) {
    add("seo", { id: "robots-block", severity: "high", title: "robots.txt blocks all search engines", detail: "The robots.txt file disallows the whole site for every crawler." });
  }
  if (!title) {
    add("seo", { id: "title-missing", severity: "high", title: "Page has no title", detail: "The title is the headline people see in Google results. Without one, rankings and clicks suffer." });
  } else if (title.length < 15 || title.length > 70) {
    add("seo", { id: "title-length", severity: "low", title: `Page title is ${title.length < 15 ? "too short" : "too long"} (${title.length} characters)`, detail: "Aim for about 30–60 characters so it isn't cut off or wasted in search results." });
  }
  if (!description) {
    add("seo", { id: "description-missing", severity: "medium", title: "No meta description", detail: "Google will invent a snippet instead of the pitch you'd write, which lowers click-through." });
  } else if (description.length < 50 || description.length > 175) {
    add("seo", { id: "description-length", severity: "low", title: `Meta description is ${description.length < 50 ? "too short" : "too long"} (${description.length} characters)`, detail: "Around 70–160 characters displays best in search results." });
  }
  if (h1Count === 0) {
    add("seo", { id: "h1-missing", severity: "medium", title: "No main heading (H1)", detail: "Search engines and screen readers use the H1 to understand what the page is about." });
  } else if (h1Count > 1) {
    add("seo", { id: "h1-multiple", severity: "low", title: `${h1Count} main headings (H1) on one page`, detail: "Use a single H1 so the page's topic is clear." });
  }
  if (wordCount < 50 && /id=["']?(root|app)["']?/i.test(html)) {
    add("seo", { id: "js-content", severity: "medium", title: "Content may be invisible to search engines", detail: "The page loads almost no text until JavaScript runs, so crawlers and link previews may see an empty page." });
  } else if (wordCount < 150) {
    add("seo", { id: "thin-content", severity: "low", title: `Very little text on the page (${wordCount} words)`, detail: "Pages with almost no written content struggle to rank." });
  }
  if (!hasCanonical) {
    add("seo", { id: "canonical", severity: "low", title: "No canonical address set", detail: "Without a canonical link, duplicate versions of the page (www, tracking links) can split your ranking." });
  }
  if (!hasOpenGraph) {
    add("seo", { id: "open-graph", severity: "low", title: "Links look plain when shared", detail: "Missing Open Graph title or image, so shares on WhatsApp, Facebook and LinkedIn show no preview card." });
  }
  if (!hasStructuredData) {
    add("seo", { id: "structured-data", severity: "low", title: "No structured data", detail: "Schema markup is how sites earn rich results such as stars, prices and FAQs in Google." });
  }
  if (!robotsOk) {
    add("seo", { id: "robots-missing", severity: "low", title: "No robots.txt file", detail: "A robots.txt file tells search engines where they may look and where your sitemap is." });
  }
  if (!hasSitemap) {
    add("seo", { id: "sitemap-missing", severity: "medium", title: "No XML sitemap found", detail: "Without a sitemap, search engines may take longer to find new and deeper pages." });
  }

  if (!lang) {
    add("access", { id: "lang", severity: "low", title: "Page language isn't declared", detail: "Screen readers and translation tools need the lang attribute to pronounce and translate text correctly." });
  }
  if (imagesMissingAlt > 0) {
    add("access", {
      id: "alt-text",
      severity: imagesMissingAlt > 5 ? "medium" : "low",
      title: `${imagesMissingAlt} image${imagesMissingAlt > 1 ? "s" : ""} without alt text`,
      detail: "Alt text lets blind visitors understand images and helps Google Images rank you. It is also a common basis for accessibility complaints.",
    });
  }
  return { findings, facts };
}
