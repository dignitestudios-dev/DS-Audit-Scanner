import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import zlib from "node:zlib";

export class ScanError extends Error {}

const MAX_BODY = 1_000_000; // 1 MB of HTML is plenty
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 12_000;
const UA = "DigniteScanner/1.0 (passive surface check)";

export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  const v = ip.toLowerCase();
  if (v === "::1" || v === "::") return true;
  if (v.startsWith("::ffff:")) {
    const rest = v.slice(7);
    return net.isIPv4(rest) ? isPrivateIp(rest) : true;
  }
  return /^(fc|fd|fe[89ab]|ff)/.test(v);
}

/**
 * DNS lookup that refuses private/internal addresses. Used as the `lookup`
 * option of every outgoing connection, so the address that is validated is the
 * very address that is connected to (no DNS-rebinding gap).
 */
export const safeLookup = ((
  hostname: string,
  options: dns.LookupOptions,
  cb: (...args: unknown[]) => void,
) => {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return cb(err);
    const list = addresses as dns.LookupAddress[];
    if (!list.length || list.some((a) => isPrivateIp(a.address))) {
      return cb(new ScanError("That address is not publicly reachable."));
    }
    if (options.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}) as unknown as net.LookupFunction;

export function normalizeUrl(input: string): URL {
  let raw = input.trim();
  if (!raw || raw.length > 2048) throw new ScanError("Enter a website address.");
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ScanError("That doesn't look like a valid web address.");
  }
  assertPublic(url);
  return url;
}

function assertPublic(url: URL) {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ScanError("Only http and https addresses can be scanned.");
  }
  if (url.username || url.password) {
    throw new ScanError("Addresses with credentials are not supported.");
  }
  const port = url.port || (url.protocol === "https:" ? "443" : "80");
  if (port !== "80" && port !== "443") {
    throw new ScanError("Only standard ports (80 and 443) can be scanned.");
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new ScanError("That address is not publicly reachable.");
  } else if (!host.includes(".") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new ScanError("Enter a public website address, like example.com.");
  }
}

export type Headers = Record<string, string | string[] | undefined>;

export interface FetchResult {
  status: number;
  headers: Headers;
  body: string;
  finalUrl: URL;
  redirects: URL[];
  ttfbMs: number;
  totalMs: number;
}

function requestOnce(url: URL): Promise<{
  status: number;
  headers: Headers;
  body: string;
  ttfbMs: number;
  totalMs: number;
}> {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === "https:" ? https : http;
    const started = Date.now();
    let ttfb = 0;
    const req = lib.request(
      url,
      {
        method: "GET",
        lookup: safeLookup,
        timeout: TIMEOUT_MS,
        headers: {
          "user-agent": UA,
          accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
          "accept-encoding": "gzip, br",
        },
      },
      (res) => {
        ttfb = Date.now() - started;
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > MAX_BODY) {
            res.destroy();
            return;
          }
          chunks.push(c);
        });
        let settled = false;
        const done = () => {
          if (settled) return;
          settled = true;
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers as Headers,
            body: decode(Buffer.concat(chunks), res.headers["content-encoding"]),
            ttfbMs: ttfb,
            totalMs: Date.now() - started,
          });
        };
        res.on("end", done);
        res.on("close", done);
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new ScanError("The site took too long to respond.")));
    req.on("error", (e) =>
      reject(e instanceof ScanError ? e : new ScanError(friendlyNetError(e))),
    );
    req.end();
  });
}

function decode(buf: Buffer, encoding: string | undefined): string {
  try {
    const opts = { maxOutputLength: MAX_BODY * 3 };
    if (encoding === "gzip") return zlib.gunzipSync(buf, opts).toString("utf8");
    if (encoding === "br") return zlib.brotliDecompressSync(buf, opts).toString("utf8");
    if (encoding === "deflate") return zlib.inflateSync(buf, opts).toString("utf8");
  } catch {
    return ""; // truncated or oversized: skip HTML checks rather than guess
  }
  return buf.toString("utf8");
}

function friendlyNetError(e: Error & { code?: string }): string {
  switch (e.code) {
    case "ENOTFOUND":
      return "We couldn't find that website. Check the address.";
    case "ECONNREFUSED":
      return "The website refused the connection.";
    case "ECONNRESET":
      return "The connection was reset by the website.";
    case "CERT_HAS_EXPIRED":
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
    case "SELF_SIGNED_CERT_IN_CHAIN":
    case "UNABLE_TO_VERIFY_LEAF_SIGNATURE":
    case "ERR_TLS_CERT_ALTNAME_INVALID":
      return "The website's security certificate is invalid.";
    default:
      return "We couldn't reach that website.";
  }
}

/** GET with manual redirects; every hop is re-validated. */
export async function fetchSafe(start: URL): Promise<FetchResult> {
  let url = start;
  const redirects: URL[] = [];
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const r = await requestOnce(url);
    const loc = r.headers.location;
    if (r.status >= 300 && r.status < 400 && typeof loc === "string") {
      let next: URL;
      try {
        next = new URL(loc, url);
      } catch {
        throw new ScanError("The website sent an invalid redirect.");
      }
      assertPublic(next);
      redirects.push(next);
      url = next;
      continue;
    }
    return { ...r, finalUrl: url, redirects };
  }
  throw new ScanError("The website redirects too many times.");
}
