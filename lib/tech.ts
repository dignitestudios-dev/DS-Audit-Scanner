import type { Finding } from "./scan";
import type { Headers } from "./ssrf";

const first = (v: string | string[] | undefined) => (Array.isArray(v) ? v[0] : v);

const SIGNS: [string, RegExp][] = [
  ["WordPress", /\/wp-content\/|\/wp-includes\/|<meta[^>]+generator[^>]+WordPress/i],
  ["WooCommerce", /wp-content\/plugins\/woocommerce|woocommerce-(layout|general|smallscreen)/i],
  ["Shopify", /cdn\.shopify\.com|Shopify\.theme/i],
  ["Wix", /static\.wixstatic\.com|wix-/i],
  ["Squarespace", /static1\.squarespace\.com|squarespace/i],
  ["Webflow", /assets\.website-files\.com|webflow/i],
  ["Magento", /\/static\/version\d+\/|Magento_/i],
  ["Drupal", /Drupal\.settings|\/sites\/default\/files/i],
  ["Joomla", /\/media\/jui\/|<meta[^>]+generator[^>]+Joomla/i],
  ["Next.js", /\/_next\/static\//i],
  ["Nuxt", /\/_nuxt\//i],
  ["Gatsby", /___gatsby/i],
  ["React", /data-reactroot|react(-dom)?(\.min)?\.js/i],
  ["Angular", /ng-version=|<app-root/i],
  ["Vue", /data-v-[0-9a-f]{6,}|vue(\.min)?\.js/i],
  ["jQuery", /jquery/i],
  ["Bootstrap", /bootstrap(\.min)?\.(css|js)|bootstrap@/i],
  ["Tailwind CSS", /tailwindcss|cdn\.tailwindcss\.com/i],
  ["Google Analytics", /googletagmanager\.com\/gtag|google-analytics\.com\/analytics|ga\('create'/i],
  ["Google Tag Manager", /googletagmanager\.com\/gtm\.js/i],
  ["Meta Pixel", /connect\.facebook\.net\/[^"']*fbevents\.js|fbq\(/i],
  ["Stripe", /js\.stripe\.com/i],
  ["reCAPTCHA", /google\.com\/recaptcha/i],
];

export function detectTech(html: string, headers: Headers): string[] {
  const found = new Set<string>();
  for (const [name, re] of SIGNS) if (re.test(html)) found.add(name);
  const server = (first(headers["server"]) ?? "").toLowerCase();
  const powered = first(headers["x-powered-by"]) ?? "";
  if (first(headers["cf-ray"]) || server.includes("cloudflare")) found.add("Cloudflare");
  if (server.includes("vercel") || first(headers["x-vercel-id"])) found.add("Vercel");
  if (server.includes("netlify") || first(headers["x-nf-request-id"])) found.add("Netlify");
  if (server.includes("nginx")) found.add("nginx");
  if (server.includes("apache")) found.add("Apache");
  if (server.includes("litespeed")) found.add("LiteSpeed");
  if (/php/i.test(powered)) found.add("PHP");
  if (/asp\.net/i.test(powered)) found.add("ASP.NET");
  if (/express/i.test(powered)) found.add("Express");
  return [...found];
}

/** Version-based findings: only what we can state with confidence. */
export function checkVersions(html: string, headers: Headers): Finding[] {
  const out: Finding[] = [];
  const wp = html.match(/<meta[^>]+name=["']?generator["']?[^>]+content=["']?WordPress\s+(\d+)\.(\d+)/i);
  if (wp && Number(wp[1]) < 6) {
    out.push({
      id: "old-wordpress",
      category: "security",
      severity: "high",
      title: `Very old WordPress (${wp[1]}.${wp[2]}) detected`,
      detail: "This version no longer receives security fixes, and known exploits are widely available.",
    });
  } else if (wp) {
    out.push({
      id: "wp-generator",
      category: "security",
      severity: "low",
      title: "WordPress version is publicly advertised",
      detail: "The page tells everyone exactly which WordPress version it runs, which helps attackers target known flaws.",
    });
  }
  const php = (first(headers["x-powered-by"]) ?? "").match(/PHP\/(\d+)\.(\d+)/i);
  if (php && (Number(php[1]) < 8 || (Number(php[1]) === 8 && Number(php[2]) < 1))) {
    out.push({
      id: "old-php",
      category: "security",
      severity: "high",
      title: `Unsupported PHP version (${php[1]}.${php[2]})`,
      detail: "This PHP release has reached end-of-life, so it no longer gets security patches.",
    });
  }
  return out;
}
