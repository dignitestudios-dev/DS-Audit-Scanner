import { accessEnabled, makeLimiter, validCode } from "@/lib/access";
import { EFFORT, FIXES } from "@/lib/fixes";
import { bySeverity, scanUrl, type Category, type Finding } from "@/lib/scan";
import { ScanError } from "@/lib/ssrf";

export const maxDuration = 60;

const TEASER_COUNT = 3;
const HOUR = 60 * 60 * 1000;

// In-memory limiters: fine for one server instance. On serverless/multi-instance
// hosting, swap for a shared store (e.g. Upstash Redis free tier).
const scanLimiter = makeLimiter(8, HOUR); // scans per IP per hour
const codeLimiter = makeLimiter(10, HOUR); // wrong access-code attempts per IP per hour

const json = (body: unknown, status = 200) =>
  Response.json(body, { status, headers: { "cache-control": "no-store" } });

export async function POST(req: Request) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";

  let url: unknown;
  let code: unknown;
  try {
    ({ url, code } = (await req.json()) as { url?: unknown; code?: unknown });
  } catch {
    return json({ error: "Invalid request." }, 400);
  }
  if (typeof url !== "string") return json({ error: "Enter a website address." }, 400);

  // Access code: checked before any scanning so wrong guesses cost nothing.
  let unlocked = false;
  if (typeof code === "string" && code.trim()) {
    if (!accessEnabled()) return json({ error: "Access codes aren't available right now." }, 403);
    if (codeLimiter.blocked(ip)) return json({ error: "Too many incorrect codes. Please try again later." }, 429);
    if (code.length > 64 || !validCode(code)) {
      codeLimiter.hit(ip);
      return json({ error: "That access code isn't valid. Check it and try again." }, 403);
    }
    unlocked = true;
  }

  if (scanLimiter.blocked(ip)) {
    return json({ error: "You've run a lot of scans. Please try again in an hour." }, 429);
  }
  scanLimiter.hit(ip);

  try {
    const result = await scanUrl(url);
    const sorted = [...result.findings].sort(bySeverity);

    const counts = { high: 0, medium: 0, low: 0 };
    const perCategory: Record<Category, number> = { security: 0, https: 0, speed: 0, mobile: 0, seo: 0, access: 0 };
    for (const f of sorted) {
      counts[f.severity]++;
      perCategory[f.category]++;
    }

    const pick = ({ id, category, severity, title, detail }: Finding) => ({ id, category, severity, title, detail });

    // Gate: without a valid code only the teaser findings leave the server.
    // The remaining findings and all fix guidance are the full report.
    return json({
      url: result.url,
      finalUrl: result.finalUrl,
      scannedAt: result.scannedAt,
      scores: result.scores,
      total: sorted.length,
      counts,
      perCategory,
      unlocked,
      teaser: sorted.slice(0, TEASER_COUNT).map(pick),
      findings: unlocked ? sorted.map((f) => ({ ...pick(f), fix: FIXES[f.id] ?? null, effort: EFFORT[f.id] ?? "Low" })) : undefined,
      lockedCount: unlocked ? 0 : Math.max(0, sorted.length - TEASER_COUNT),
      usedPageSpeed: result.usedPageSpeed,
      insights: {
        ...result.insights,
        opportunities: unlocked ? result.insights.opportunities : result.insights.opportunities.slice(0, 3),
      },
    });
  } catch (e) {
    if (e instanceof ScanError) return json({ error: e.message }, 422);
    console.error("scan failed", e);
    return json({ error: "Something went wrong while scanning. Please try again." }, 500);
  }
}
