import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Access codes unlock the full report for free (pilot customers, partners,
 * promotions). They live in the ACCESS_CODES env var, comma separated, so they
 * can be added or revoked without a code change.
 */
function codes(): string[] {
  return (process.env.ACCESS_CODES ?? "")
    .split(",")
    .map((s) => s.trim().toUpperCase())
    .filter(Boolean);
}

export const accessEnabled = () => codes().length > 0;

const digest = (s: string) => createHash("sha256").update(s).digest();

export function validCode(input: string): boolean {
  const list = codes();
  if (!list.length) return false;
  const given = digest(input.trim().toUpperCase());
  let ok = false;
  for (const c of list) if (timingSafeEqual(digest(c), given)) ok = true; // no early exit
  return ok;
}

export function makeLimiter(limit: number, windowMs: number) {
  const hits = new Map<string, number[]>();
  const recent = (ip: string, now: number) => (hits.get(ip) ?? []).filter((t) => now - t < windowMs);
  return {
    /** True when this IP has used up its allowance (does not record a hit). */
    blocked(ip: string): boolean {
      return recent(ip, Date.now()).length >= limit;
    },
    hit(ip: string): void {
      const now = Date.now();
      const list = recent(ip, now);
      list.push(now);
      hits.set(ip, list);
      if (hits.size > 5000) {
        for (const [k, v] of hits) if (v.every((t) => now - t >= windowMs)) hits.delete(k);
      }
    },
  };
}
