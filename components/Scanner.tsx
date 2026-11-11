"use client";

import { useSearchParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

type Sev = "high" | "medium" | "low";
interface Finding {
  id: string;
  category: string;
  severity: Sev;
  title: string;
  detail: string;
  fix?: string | null;
  effort?: string;
}
interface Insights {
  tech: string[];
  ttfbMs: number;
  opportunities: string[];
  psiScores: { performance: number; accessibility: number | null; seo: number | null; bestPractices: number | null } | null;
  vitals: { lcpMs: number | null; cls: number | null; tbtMs: number | null; fcpMs: number | null } | null;
  facts: {
    title: string | null;
    description: string | null;
    wordCount: number;
    images: number;
    imagesMissingAlt: number;
    hasSitemap: boolean;
    hasRobots: boolean;
    hasStructuredData: boolean;
    hasOpenGraph: boolean;
    hasCanonical: boolean;
    htmlKb: number;
    indexable: boolean;
  };
}
interface Result {
  url: string;
  finalUrl: string;
  scannedAt: string;
  usedPageSpeed: boolean;
  scores: { overall: number; security: number; https: number; speed: number; mobile: number; seo: number; access: number };
  total: number;
  counts: Record<Sev, number>;
  unlocked: boolean;
  teaser: Finding[];
  findings?: Finding[];
  lockedCount: number;
  summary: string | null;
  insights: Insights;
}

const AUDIT_URL = process.env.NEXT_PUBLIC_AUDIT_URL ?? "https://dignitestudios.net";
const EMAIL = process.env.NEXT_PUBLIC_CONTACT_EMAIL ?? "info@dignitestudios.com";
const PHONE = process.env.NEXT_PUBLIC_CONTACT_PHONE ?? "+18777141770";

const CATS: { key: keyof Result["scores"]; label: string }[] = [
  { key: "security", label: "Security" },
  { key: "https", label: "HTTPS & SSL" },
  { key: "speed", label: "Speed" },
  { key: "mobile", label: "Mobile" },
  { key: "seo", label: "SEO" },
  { key: "access", label: "Accessibility" },
];

/** Steps shown while scanning. `at` is the second each step becomes active. */
const STEPS = [
  { at: 0, label: "Connecting to your site", hint: "Resolving the address and loading the page" },
  { at: 1.6, label: "Checking HTTPS and certificate", hint: "Encryption, redirects and expiry" },
  { at: 3.2, label: "Reviewing security headers", hint: "Cookies, framing and content rules" },
  { at: 5, label: "Testing search readiness", hint: "Titles, sitemap, robots and structure" },
  { at: 7, label: "Measuring speed on a phone", hint: "Asking Google PageSpeed. This is the slow one" },
  { at: 16, label: "Checking accessibility and mobile", hint: "Alt text, language and layout" },
  { at: 22, label: "Building your report", hint: "Scoring and ranking every issue" },
];

const grade = (n: number) => (n >= 85 ? "good" : n >= 60 ? "ok" : "bad");
const sec = (ms: number | null) => (ms === null ? "n/a" : `${(ms / 1000).toFixed(1)}s`);
const vitalGrade = (v: number | null, good: number, poor: number) => (v === null ? "" : v <= good ? "good" : v <= poor ? "ok" : "bad");

const CLIENT_TIMEOUT_MS = 90_000;

async function savePdf(r: Result): Promise<void> {
  const { downloadReport } = await import("@/lib/pdf");
  await downloadReport({
    finalUrl: r.finalUrl,
    scannedAt: r.scannedAt,
    scores: r.scores,
    counts: r.counts,
    findings: r.findings ?? r.teaser,
    summary: r.summary,
    usedPageSpeed: r.usedPageSpeed,
    insights: r.insights,
    contact: { email: EMAIL, phone: PHONE.replace(/^\+1(\d{3})(\d{3})(\d{4})$/, "+1 $1 $2 $3"), site: AUDIT_URL },
  });
}

export default function Scanner() {
  const initial = useSearchParams().get("url")?.slice(0, 2048) ?? "";
  const [url, setUrl] = useState(initial);
  const [scanning, setScanning] = useState(false);
  const [finishing, setFinishing] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [error, setError] = useState("");
  const [codeError, setCodeError] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [scanned, setScanned] = useState("");
  const abort = useRef<AbortController | null>(null);
  const runId = useRef(0);
  const lastTarget = useRef("");
  const resultRef = useRef<HTMLElement | null>(null);

  // Drive the loader clock while a scan is running.
  useEffect(() => {
    if (!scanning) return;
    const start = Date.now();
    const id = setInterval(() => setElapsed((Date.now() - start) / 1000), 150);
    return () => clearInterval(id);
  }, [scanning]);

  // Lock page scroll behind the loader and allow Escape to cancel.
  useEffect(() => {
    if (!scanning) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && abort.current?.abort();
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [scanning]);

  const run = useCallback(async (target: string, code?: string) => {
    // Cancel anything still in flight and make sure only this run may touch state.
    abort.current?.abort();
    const ctl = new AbortController();
    abort.current = ctl;
    const id = ++runId.current;
    const current = () => runId.current === id;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      ctl.abort();
    }, CLIENT_TIMEOUT_MS);

    setElapsed(0);
    setScanning(true);
    setFinishing(false);
    setError("");
    setCodeError("");
    try {
      const r = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url: target, code }),
        signal: ctl.signal,
      });
      const j = await r.json();
      if (!current()) return;
      if (!r.ok) {
        if (code) setCodeError(j.error ?? "Something went wrong.");
        else {
          setResult(null);
          setError(j.error ?? "Something went wrong.");
        }
        return;
      }
      setFinishing(true);
      await new Promise((res) => setTimeout(res, 900));
      if (!current()) return;
      setResult(j as Result);
      setScanned(target);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
      if (code && (j as Result).unlocked) {
        savePdf(j as Result).catch(() => setCodeError("Report unlocked, but the PDF couldn't be created. Use the Download button to try again."));
      }
    } catch (e) {
      if (!current()) return;
      const msg = timedOut
        ? "The scan took too long and was stopped. The site may be slow or blocking us. Please try again."
        : "Couldn't reach the scanner. Check your connection and try again.";
      if ((e as Error).name !== "AbortError" || timedOut) {
        if (code) setCodeError(msg);
        else setError(msg);
      }
    } finally {
      clearTimeout(timer);
      if (current()) {
        setScanning(false);
        setFinishing(false);
      }
    }
  }, []);

  // Opening /?url=example.com starts the scan straight away (also on reload).
  // lastTarget stops the effect re-firing when our own replaceState updates the address.
  useEffect(() => {
    const t = initial.trim();
    if (!t || t === lastTarget.current) return;
    const id = setTimeout(() => {
      lastTarget.current = t;
      setUrl(t);
      run(t);
    }, 0);
    return () => clearTimeout(id);
  }, [initial, run]);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (scanning || !url.trim()) return;
    const target = url.trim();
    lastTarget.current = target;
    window.history.replaceState(null, "", `?url=${encodeURIComponent(target)}`);
    setResult(null);
    run(target);
  }

  return (
    <>
      <form className="form" onSubmit={submit}>
        <label htmlFor="url" className="sr">
          Website address
        </label>
        <input
          id="url"
          type="text"
          inputMode="url"
          autoComplete="url"
          autoCapitalize="off"
          spellCheck={false}
          placeholder="yourwebsite.com"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          required
        />
        <button type="submit" disabled={scanning}>
          Scan my site
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M5 12h14M13 6l6 6-6 6" />
          </svg>
        </button>
      </form>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {scanning && <Loader url={scanned && result ? scanned : url} elapsed={elapsed} finishing={finishing} onCancel={() => abort.current?.abort()} />}

      {result && (
        <Report result={result} scannedUrl={scanned} refEl={resultRef} codeError={codeError} busy={scanning} onUnlock={(code) => run(scanned, code)} />
      )}
    </>
  );
}

/* --------------------------------- loader --------------------------------- */

function Loader({ url, elapsed, finishing, onCancel }: { url: string; elapsed: number; finishing: boolean; onCancel: () => void }) {
  const activeIdx = finishing ? STEPS.length : Math.min(STEPS.length - 1, STEPS.filter((s) => s.at <= elapsed).length - 1);
  const progress = finishing ? 100 : Math.min(94, 100 * (1 - Math.exp(-elapsed / 14)));
  const host = url.replace(/^https?:\/\//i, "").replace(/[/?#].*$/, "");
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => ref.current?.focus(), []);

  return (
    <div className="loader" role="dialog" aria-modal="true" aria-label="Scanning your website" ref={ref} tabIndex={-1}>
      <div className="loader-inner">
        <div className="radar" aria-hidden="true">
          <i />
          <i />
          <i />
          <b />
          <span className="sweep" />
        </div>
        <p className="loader-eyebrow">Scanning</p>
        <h2 className="loader-host">{host || "your site"}</h2>

        <ol className="steps">
          {STEPS.map((s, i) => {
            const state = i < activeIdx ? "done" : i === activeIdx ? "active" : "todo";
            return (
              <li key={s.label} className={state} aria-current={state === "active" ? "step" : undefined}>
                <span className="dot" aria-hidden="true">
                  {state === "done" ? (
                    <svg viewBox="0 0 24 24">
                      <path d="M5 12.5l4.5 4.5L19 7.5" />
                    </svg>
                  ) : state === "active" ? (
                    <em />
                  ) : null}
                </span>
                <span className="txt">
                  <strong>{s.label}</strong>
                  {state === "active" && <small>{s.hint}</small>}
                </span>
              </li>
            );
          })}
        </ol>

        <div className="bar-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(progress)} aria-label="Scan progress">
          <div style={{ width: `${progress}%` }} />
        </div>
        <p className="loader-note" aria-live="polite">
          {finishing ? "Done. Opening your report…" : elapsed > 25 ? "Google's speed test is taking longer than usual. Almost there…" : "Most scans take 10 to 30 seconds."}
        </p>
        <button className="ghost" type="button" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

/* --------------------------------- report --------------------------------- */

function Report({
  result,
  scannedUrl,
  refEl,
  codeError,
  busy,
  onUnlock,
}: {
  result: Result;
  scannedUrl: string;
  refEl: React.RefObject<HTMLElement | null>;
  codeError: string;
  busy: boolean;
  onUnlock: (code: string) => void;
}) {
  const s = result.scores;
  const list = result.findings ?? result.teaser;
  const host = (() => {
    try {
      return new URL(result.finalUrl).hostname;
    } catch {
      return scannedUrl;
    }
  })();
  const C = 2 * Math.PI * 52;

  return (
    <section className="result" aria-label="Scan results" ref={refEl} tabIndex={-1}>
      <div className="top">
        <div className={`ring ${grade(s.overall)}`} role="img" aria-label={`Overall score ${s.overall} out of 100`}>
          <svg viewBox="0 0 120 120" aria-hidden="true">
            <circle cx="60" cy="60" r="52" className="track" />
            <circle cx="60" cy="60" r="52" className="arc" style={{ strokeDasharray: C, strokeDashoffset: C * (1 - s.overall / 100) }} />
          </svg>
          <div>
            <strong>{s.overall}</strong>
            <span>out of 100</span>
          </div>
        </div>
        <div className="headline">
          <p className="chip-line">
            {result.unlocked && <span className="badge">Full report unlocked</span>}
            <span className="host">{host}</span>
          </p>
          <h2>{result.total === 0 ? "No issues found by the automated scan" : `${result.total} issue${result.total > 1 ? "s" : ""} found`}</h2>
          {result.total > 0 && (
            <p className="counts">
              <b className="c-high">{result.counts.high} high</b>
              <b className="c-med">{result.counts.medium} medium</b>
              <b className="c-low">{result.counts.low} low</b>
            </p>
          )}
          {result.unlocked && <DownloadButton result={result} />}
        </div>
      </div>

      {result.summary && <p className="summary">{result.summary}</p>}

      <ul className="cats">
        {CATS.map((c, i) => (
          <li key={c.key}>
            <div>
              <span>{c.label}</span>
              <b className={grade(s[c.key])}>{s[c.key]}</b>
            </div>
            <i className={grade(s[c.key])} style={{ width: `${s[c.key]}%`, animationDelay: `${i * 70}ms` }} />
          </li>
        ))}
      </ul>

      <Insights i={result.insights} unlocked={result.unlocked} />

      {list.length > 0 && (
        <>
          <h3>{result.unlocked ? "Every issue, with how to fix it" : "Top issues"}</h3>
          <ul className="issues">
            {list.map((f) => (
              <li key={f.id}>
                <span className={`sev ${f.severity}`}>{f.severity}</span>
                <div>
                  <strong>{f.title}</strong>
                  <p>{f.detail}</p>
                  {result.unlocked && f.fix && (
                    <p className="fix">
                      <b>How to fix:</b> {f.fix}
                    </p>
                  )}
                </div>
              </li>
            ))}
            {!result.unlocked && result.lockedCount > 0 && (
              <li className="locked">
                <span className="sev lock">locked</span>
                <div>
                  <strong>
                    + {result.lockedCount} more issue{result.lockedCount > 1 ? "s" : ""} in the full report
                  </strong>
                  <p>Each one explained, with step-by-step fix instructions.</p>
                </div>
              </li>
            )}
          </ul>
        </>
      )}

      {!result.unlocked && <Unlock onUnlock={onUnlock} error={codeError} busy={busy} />}
      <Contact host={host} score={s.overall} unlocked={result.unlocked} />
    </section>
  );
}

function DownloadButton({ result }: { result: Result }) {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  async function go() {
    setBusy(true);
    setFailed(false);
    try {
      await savePdf(result);
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="dl-wrap">
      <button type="button" className="dl" onClick={go} disabled={busy}>
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 4v11M7 11l5 5 5-5M5 20h14" />
        </svg>
        {busy ? "Preparing PDF…" : "Download PDF report"}
      </button>
      {failed && (
        <span className="error" role="alert">
          Couldn&apos;t create the PDF. Please try again.
        </span>
      )}
    </div>
  );
}

function Unlock({ onUnlock, error, busy }: { onUnlock: (code: string) => void; error: string; busy: boolean }) {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  return (
    <div className="unlock">
      {!open ? (
        <button type="button" className="link" onClick={() => setOpen(true)}>
          Have an access code? Unlock the full report free
        </button>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (code.trim() && !busy) onUnlock(code.trim());
          }}
        >
          <label htmlFor="code">Access code</label>
          <div className="code-row">
            <input
              id="code"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Enter your code"
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              maxLength={64}
              aria-invalid={!!error}
              aria-describedby={error ? "code-err" : undefined}
              autoFocus
            />
            <button type="submit" disabled={busy || !code.trim()}>
              Unlock
            </button>
          </div>
          {error && (
            <p id="code-err" className="error" role="alert">
              {error}
            </p>
          )}
        </form>
      )}
    </div>
  );
}

function Contact({ host, score, unlocked }: { host: string; score: number; unlocked: boolean }) {
  const subject = encodeURIComponent(`Website audit enquiry: ${host}`);
  const body = encodeURIComponent(
    `Hi Dignite Studios,\n\nI ran the free scanner on ${host} and it scored ${score}/100. I'd like to talk about ${unlocked ? "getting these issues fixed" : "a full audit"}.\n\nThanks`,
  );
  return (
    <div className="cta">
      <h3>{unlocked ? "Want us to fix these for you?" : "This scan only sees the surface"}</h3>
      <p>
        {unlocked
          ? "Our team can fix what the scan found and test the parts a tool can't, like checkout and sign-up on real phones."
          : "Tools can't tell you whether checkout works on an iPhone, or whether login can be abused. Talk to our team and we'll test real user flows on real devices."}
      </p>
      <div className="cta-row">
        <a className="btn" href={`mailto:${EMAIL}?subject=${subject}&body=${body}`}>
          Contact us
        </a>
        <a className="btn alt" href={`tel:${PHONE}`}>
          Call us
        </a>
        <a className="link" href={AUDIT_URL}>
          See the full audit
        </a>
      </div>
    </div>
  );
}

function Yes({ ok, label }: { ok: boolean; label: string }) {
  return (
    <li className={ok ? "yes" : "no"}>
      <span aria-hidden="true">{ok ? "✓" : "✗"}</span> {label}
      <span className="sr"> {ok ? "present" : "missing"}</span>
    </li>
  );
}

function Insights({ i, unlocked }: { i: Insights; unlocked: boolean }) {
  const v = i.vitals;
  const f = i.facts;
  return (
    <div className="insights">
      {v && (
        <>
          <h3>Speed on a phone (Google)</h3>
          <ul className="vitals">
            <li>
              <span>Main content</span>
              <b className={vitalGrade(v.lcpMs, 2500, 4000)}>{sec(v.lcpMs)}</b>
            </li>
            <li>
              <span>First paint</span>
              <b className={vitalGrade(v.fcpMs, 1800, 3000)}>{sec(v.fcpMs)}</b>
            </li>
            <li>
              <span>Layout shift</span>
              <b className={vitalGrade(v.cls, 0.1, 0.25)}>{v.cls === null ? "n/a" : v.cls.toFixed(2)}</b>
            </li>
            <li>
              <span>Tap delay</span>
              <b className={vitalGrade(v.tbtMs, 200, 600)}>{v.tbtMs === null ? "n/a" : `${Math.round(v.tbtMs)} ms`}</b>
            </li>
          </ul>
          {i.opportunities.length > 0 && (
            <p className="muted opp">
              {unlocked ? "Speed wins" : "Biggest speed wins"}: {i.opportunities.join(" · ")}
            </p>
          )}
        </>
      )}

      <h3>Search readiness</h3>
      <ul className="checks">
        <Yes ok={f.indexable} label="Visible to Google" />
        <Yes ok={!!f.title} label="Page title" />
        <Yes ok={!!f.description} label="Meta description" />
        <Yes ok={f.hasSitemap} label="XML sitemap" />
        <Yes ok={f.hasRobots} label="robots.txt" />
        <Yes ok={f.hasStructuredData} label="Structured data" />
        <Yes ok={f.hasOpenGraph} label="Share preview" />
        <Yes ok={f.imagesMissingAlt === 0} label={f.images ? `Image alt text (${f.images - f.imagesMissingAlt}/${f.images})` : "Image alt text"} />
      </ul>
      {f.title && <p className="muted">Title: “{f.title}”</p>}

      {i.tech.length > 0 && (
        <>
          <h3>Technology we spotted</h3>
          <ul className="chips">
            {i.tech.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}
