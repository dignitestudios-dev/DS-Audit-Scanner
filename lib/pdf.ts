import type { jsPDF } from "jspdf";

export interface PdfFinding {
  id: string;
  category: string;
  severity: "high" | "medium" | "low";
  title: string;
  detail: string;
  fix?: string | null;
  effort?: string;
}

export interface PdfData {
  finalUrl: string;
  scannedAt: string;
  scores: Record<"overall" | "security" | "https" | "speed" | "mobile" | "seo" | "access", number>;
  counts: Record<"high" | "medium" | "low", number>;
  findings: PdfFinding[];
  summary: string | null;
  usedPageSpeed: boolean;
  insights: {
    tech: string[];
    ttfbMs: number;
    opportunities: string[];
    vitals: { lcpMs: number | null; cls: number | null; tbtMs: number | null; fcpMs: number | null } | null;
    psiScores: { performance: number; accessibility: number | null; seo: number | null; bestPractices: number | null } | null;
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
      indexable: boolean;
      htmlKb: number;
    };
  };
  contact: { email: string; phone: string; site: string };
}

type RGB = [number, number, number];
const ORANGE: RGB = [241, 92, 32];
const INK: RGB = [34, 34, 34];
const GREY: RGB = [110, 110, 118];
const LIGHT: RGB = [226, 226, 230];
const FAINT: RGB = [244, 244, 246];
const RED: RGB = [200, 50, 40];
const AMBER: RGB = [196, 120, 10];
const GREEN: RGB = [30, 140, 70];

const CATS: [keyof PdfData["scores"], string][] = [
  ["security", "Security"],
  ["https", "HTTPS and SSL"],
  ["speed", "Speed"],
  ["mobile", "Mobile"],
  ["seo", "SEO"],
  ["access", "Accessibility"],
];

/** jsPDF's built-in fonts only cover Latin-1, so map or drop everything else. */
const clean = (s: string) =>
  s
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[–—]/g, "-")
    .replace(/…/g, "...")
    .replace(/[·•]/g, "-")
    .replace(/[^\x20-\x7E -ÿ]/g, "");

const gradeColor = (n: number): RGB => (n >= 85 ? GREEN : n >= 60 ? AMBER : RED);
const sevColor = (s: string): RGB => (s === "high" ? RED : s === "medium" ? AMBER : GREY);
const sevLabel = (s: string) => (s === "high" ? "High" : s === "medium" ? "Medium" : "Low");

export async function downloadReport(d: PdfData): Promise<void> {
  const { jsPDF } = await import("jspdf");
  const doc: jsPDF = new jsPDF({ unit: "pt", format: "a4" });

  const W = doc.internal.pageSize.getWidth();
  const H = doc.internal.pageSize.getHeight();
  const M = 56;
  const CW = W - M * 2;
  const BOTTOM = H - 64;
  let y = 0;

  const host = (() => {
    try {
      return new URL(d.finalUrl).hostname.replace(/^www\./, "");
    } catch {
      return d.finalUrl;
    }
  })();
  const date = new Date(d.scannedAt).toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });

  const color = (c: RGB) => doc.setTextColor(c[0], c[1], c[2]);
  const font = (face: "helvetica" | "times", style: "normal" | "bold", size: number, c: RGB = INK) => {
    doc.setFont(face, style);
    doc.setFontSize(size);
    color(c);
  };
  const rule = (x1: number, yy: number, x2: number, c: RGB = LIGHT, w = 0.6) => {
    doc.setDrawColor(c[0], c[1], c[2]);
    doc.setLineWidth(w);
    doc.line(x1, yy, x2, yy);
  };
  const fill = (x: number, yy: number, w: number, h: number, c: RGB) => {
    doc.setFillColor(c[0], c[1], c[2]);
    doc.rect(x, yy, w, h, "F");
  };
  const wrap = (text: string, w: number, face: "helvetica" | "times", style: "normal" | "bold", size: number): string[] => {
    font(face, style, size);
    return doc.splitTextToSize(clean(text), w) as string[];
  };
  const newPage = () => {
    doc.addPage();
    y = M;
  };
  const need = (h: number) => {
    if (y + h > BOTTOM) newPage();
  };

  /** Paragraph that flows across pages. */
  const para = (text: string, opts: { size?: number; c?: RGB; gap?: number; x?: number; w?: number; style?: "normal" | "bold" } = {}) => {
    const size = opts.size ?? 10;
    const x = opts.x ?? M;
    const lines = wrap(text, opts.w ?? CW - (x - M), "helvetica", opts.style ?? "normal", size);
    const lh = size * 1.55;
    font("helvetica", opts.style ?? "normal", size, opts.c ?? INK);
    for (const ln of lines) {
      need(lh);
      font("helvetica", opts.style ?? "normal", size, opts.c ?? INK);
      doc.text(ln, x, y + size);
      y += lh;
    }
    y += opts.gap ?? 8;
  };

  const section = (n: number, title: string) => {
    need(170); // keep the heading with some content, never alone at the page bottom
    y += 14;
    fill(M, y, CW, 2.2, ORANGE);
    y += 30;
    font("times", "bold", 19, ORANGE);
    doc.text(String(n), M, y);
    font("times", "bold", 19, INK);
    doc.text(clean(title), M + 24, y);
    y += 22;
  };

  const heading = (t: string) => {
    need(40);
    font("times", "bold", 13, INK);
    doc.text(clean(t), M, y + 10);
    y += 26;
  };

  interface Col {
    head: string;
    w: number;
    align?: "left" | "right";
  }
  interface Cell {
    t: string;
    c?: RGB;
    bold?: boolean;
  }
  const table = (cols: Col[], rows: Cell[][]) => {
    const total = cols.reduce((s, c) => s + c.w, 0);
    const widths = cols.map((c) => (c.w / total) * CW);
    const header = () => {
      need(40);
      font("helvetica", "bold", 7.5, GREY);
      let x = M;
      cols.forEach((c, i) => {
        const tx = c.align === "right" ? x + widths[i] - 6 : x;
        doc.text(c.head.toUpperCase(), tx, y + 8, { align: c.align === "right" ? "right" : "left", charSpace: 0.8 } as never);
        x += widths[i];
      });
      y += 16;
      rule(M, y, M + CW, INK, 1.1);
      y += 2;
    };
    header();
    for (const r of rows) {
      const cellLines = r.map((cell, i) => wrap(cell.t, widths[i] - 12, "helvetica", cell.bold ? "bold" : "normal", 9));
      const rh = Math.max(...cellLines.map((l) => l.length)) * 13.5 + 14;
      if (y + rh > BOTTOM) {
        newPage();
        header();
      }
      let x = M;
      r.forEach((cell, i) => {
        font("helvetica", cell.bold ? "bold" : "normal", 9, cell.c ?? INK);
        const tx = cols[i].align === "right" ? x + widths[i] - 6 : x;
        cellLines[i].forEach((ln, k) => doc.text(ln, tx, y + 15 + k * 13.5, { align: cols[i].align === "right" ? "right" : "left" }));
        x += widths[i];
      });
      y += rh;
      rule(M, y, M + CW);
    }
    y += 12;
  };

  /* ---------------------------------- cover --------------------------------- */
  fill(0, 0, W, 38, ORANGE);
  font("helvetica", "bold", 8, ORANGE);
  doc.text("WEBSITE HEALTH REPORT", M, 178, { charSpace: 1.6 } as never);
  let hs = 40;
  font("times", "bold", hs, INK);
  while (doc.getTextWidth(clean(host)) > CW && hs > 18) {
    hs -= 2;
    font("times", "bold", hs, INK);
  }
  doc.text(clean(host), M, 232);
  fill(M, 318, 62, 6, ORANGE);
  font("helvetica", "normal", 13, [70, 70, 76]);
  doc.text(["Security, HTTPS, speed, mobile, SEO and", "accessibility review with a prioritised action plan."], M, 352, { lineHeightFactor: 1.5 });

  const stack = d.insights.tech.length ? d.insights.tech.join(", ") : "Not identified";
  const meta: [string, string][] = [
    ["Website", d.finalUrl],
    ["Date", date],
    ["Scope", `Homepage, response headers, certificate, robots.txt and sitemap${d.usedPageSpeed ? ", Google PageSpeed (mobile)" : ""}`],
    ["Stack observed", stack],
    ["Overall score", `${d.scores.overall} / 100`],
    ["Prepared by", "Dignite Studios"],
  ];
  let my = 600;
  rule(M, my, M + CW);
  for (const [k, v] of meta) {
    const lines = wrap(v, CW - 120, "helvetica", "normal", 9);
    const rh = lines.length * 13 + 14;
    font("helvetica", "normal", 9, GREY);
    doc.text(k, M + 6, my + 16);
    font("helvetica", "normal", 9, INK);
    lines.forEach((ln, i) => doc.text(ln, M + 120, my + 16 + i * 13));
    my += rh;
    rule(M, my, M + CW);
  }

  /* --------------------------- 1. executive summary -------------------------- */
  newPage();
  section(1, "Executive summary");

  const total = d.findings.length;
  const ranked = [...CATS].sort((a, b) => d.scores[b[0]] - d.scores[a[0]]);
  const best = ranked[0];
  const worst = ranked[ranked.length - 1];
  const top = d.findings.slice(0, 3).map((f) => f.title);
  if (d.summary) para(d.summary, { gap: 8 });
  para(
    `${host} scored ${d.scores.overall} out of 100 in our automated scan. We found ${total} issue${total === 1 ? "" : "s"} across six areas: ${d.counts.high} high, ${d.counts.medium} medium and ${d.counts.low} low priority. The strongest area is ${best[1].toLowerCase()} (${d.scores[best[0]]}/100) and the weakest is ${worst[1].toLowerCase()} (${d.scores[worst[0]]}/100).`,
  );
  if (top.length) {
    para(`The most important items to address first: ${top.join("; ")}. Detail and recommended fixes follow in section 4, and a step-by-step plan is in section 6.`);
  } else {
    para("The automated scan did not find any issues. A manual review is still worthwhile for flows a tool cannot test.");
  }

  // stat boxes
  const lcp = d.insights.vitals?.lcpMs ?? null;
  const stats: [string, string][] = [
    [`${d.scores.overall}/100`, "overall score"],
    [String(total), "issues found"],
    [String(d.counts.high), "high priority issues"],
    lcp !== null ? [`${(lcp / 1000).toFixed(1)} s`, "main content on a phone"] : [`${d.insights.facts.htmlKb} KB`, "homepage HTML size"],
  ];
  need(86);
  const bw = CW / 4;
  rule(M, y, M + CW);
  stats.forEach(([big, label], i) => {
    const x = M + i * bw;
    if (i > 0) {
      doc.setDrawColor(LIGHT[0], LIGHT[1], LIGHT[2]);
      doc.setLineWidth(0.6);
      doc.line(x, y, x, y + 76);
    }
    font("times", "bold", 22, ORANGE);
    doc.text(big, x + 12, y + 34);
    font("helvetica", "normal", 8.5, GREY);
    doc.text(label, x + 12, y + 56);
  });
  y += 76;
  rule(M, y, M + CW);
  y += 20;

  table(
    [
      { head: "Area", w: 2 },
      { head: "Score", w: 1.2 },
      { head: "Basis", w: 6 },
    ],
    CATS.map(([k, label]) => {
      const issues = d.findings.filter((f) => f.category === k);
      return [
        { t: label },
        { t: `${d.scores[k]} / 100`, c: gradeColor(d.scores[k]), bold: true },
        { t: issues.length ? issues.slice(0, 2).map((f) => f.title).join("; ") + (issues.length > 2 ? `; plus ${issues.length - 2} more` : "") : "No issues found by the automated checks" },
      ];
    }),
  );
  para("Scores are computed from automated checks (each issue lowers its area's score by its priority) and are indicative, not a guarantee of how the site performs for every visitor.", { size: 8.5, c: GREY });

  /* ---------------------------- 2. findings register ------------------------- */
  section(2, "Findings register");
  if (total === 0) {
    para("No issues were found by the automated checks.");
  } else {
    para("Every finding, ordered by priority. Detail and recommended fixes follow in section 4.");
    table(
      [
        { head: "Ref", w: 0.9 },
        { head: "Finding", w: 7 },
        { head: "Priority", w: 1.4 },
        { head: "Effort", w: 1.2 },
      ],
      d.findings.map((f, i) => [
        { t: `F${i + 1}`, c: GREY },
        { t: f.title },
        { t: sevLabel(f.severity), c: sevColor(f.severity), bold: true },
        { t: f.effort ?? "Low" },
      ]),
    );
  }

  /* ----------------------- 3. core web vitals & performance ------------------- */
  section(3, "Speed and performance");
  if (!d.usedPageSpeed) {
    const lines = wrap("Measurement limits. Google PageSpeed data was not available for this scan, so Core Web Vitals (main content time, layout shift and tap delay) could not be measured. Only server response time and delivery settings are shown. Run the address at pagespeed.web.dev to confirm.", CW - 28, "helvetica", "normal", 9);
    const bh = lines.length * 13.5 + 20;
    need(bh + 10);
    fill(M, y, CW, bh, [253, 236, 228]);
    fill(M, y, 3, bh, ORANGE);
    font("helvetica", "normal", 9, INK);
    lines.forEach((ln, i) => doc.text(ln, M + 14, y + 17 + i * 13.5));
    y += bh + 14;
  }
  const v = d.insights.vitals;
  const rate = (val: number | null, good: number, poor: number): Cell => {
    if (val === null) return { t: "Not measured", c: GREY };
    return val <= good ? { t: "Good", c: GREEN, bold: true } : val <= poor ? { t: "Needs work", c: AMBER, bold: true } : { t: "Poor", c: RED, bold: true };
  };
  const vrows: Cell[][] = [];
  if (v) {
    vrows.push(
      [{ t: "Largest Contentful Paint" }, { t: v.lcpMs === null ? "Not measured" : `${(v.lcpMs / 1000).toFixed(1)} s` }, { t: "2.5 s or less" }, rate(v.lcpMs, 2500, 4000)],
      [{ t: "First Contentful Paint" }, { t: v.fcpMs === null ? "Not measured" : `${(v.fcpMs / 1000).toFixed(1)} s` }, { t: "1.8 s or less" }, rate(v.fcpMs, 1800, 3000)],
      [{ t: "Cumulative Layout Shift" }, { t: v.cls === null ? "Not measured" : v.cls.toFixed(2) }, { t: "0.1 or less" }, rate(v.cls, 0.1, 0.25)],
      [{ t: "Total Blocking Time" }, { t: v.tbtMs === null ? "Not measured" : `${Math.round(v.tbtMs)} ms` }, { t: "200 ms or less" }, rate(v.tbtMs, 200, 600)],
    );
  }
  vrows.push(
    [{ t: "Server response time" }, { t: `${Math.round(d.insights.ttfbMs)} ms` }, { t: "800 ms or less" }, rate(d.insights.ttfbMs, 800, 1800)],
    [{ t: "Homepage HTML size" }, { t: `${d.insights.facts.htmlKb} KB` }, { t: "Under about 200 KB" }, rate(d.insights.facts.htmlKb, 200, 500)],
  );
  table(
    [
      { head: "Metric", w: 3.2 },
      { head: "Result", w: 2.4 },
      { head: "Target", w: 2.4 },
      { head: "Assessment", w: 2 },
    ],
    vrows,
  );
  const ps = d.insights.psiScores;
  if (ps) {
    heading("Google Lighthouse scores (mobile)");
    const sc = (n: number | null): Cell => (n === null ? { t: "n/a", c: GREY } : { t: `${n} / 100`, c: gradeColor(n), bold: true });
    table(
      [
        { head: "Category", w: 4 },
        { head: "Score", w: 3 },
      ],
      [
        [{ t: "Performance" }, sc(ps.performance)],
        [{ t: "Accessibility" }, sc(ps.accessibility)],
        [{ t: "SEO" }, sc(ps.seo)],
        [{ t: "Best practices" }, sc(ps.bestPractices)],
      ],
    );
  }
  if (d.insights.opportunities.length) {
    para(`Biggest speed opportunities identified by Google: ${d.insights.opportunities.join("; ")}.`, { size: 9.5 });
  }

  /* ------------------------ 4. detailed findings and fixes -------------------- */
  section(4, "Detailed findings and recommended fixes");
  if (total === 0) para("Nothing to report.");
  d.findings.forEach((f, i) => {
    const dl = wrap(f.detail, CW - 16, "helvetica", "normal", 9.5);
    const fl = f.fix ? wrap(f.fix, CW - 16, "helvetica", "normal", 9.5) : [];
    const h = 22 + dl.length * 14.5 + (fl.length ? 20 + fl.length * 14.5 : 0) + 14;
    need(Math.min(h, 200));
    font("helvetica", "bold", 8.5, GREY);
    doc.text(`F${i + 1}`, M, y + 11);
    font("helvetica", "bold", 11, INK);
    const tl = wrap(f.title, CW - 130, "helvetica", "bold", 11);
    tl.forEach((ln, k) => {
      font("helvetica", "bold", 11, INK);
      doc.text(ln, M + 26, y + 11 + k * 14);
    });
    font("helvetica", "bold", 8.5, sevColor(f.severity));
    doc.text(`${sevLabel(f.severity).toUpperCase()} PRIORITY`, M + CW, y + 11, { align: "right", charSpace: 0.6 } as never);
    y += 12 + tl.length * 14;
    para(f.detail, { size: 9.5, c: [70, 70, 76], gap: 4, x: M + 26, w: CW - 26 });
    if (f.fix) {
      font("helvetica", "bold", 9, ORANGE);
      need(20);
      doc.text("RECOMMENDED FIX", M + 26, y + 9, { charSpace: 0.6 } as never);
      y += 16;
      para(f.fix, { size: 9.5, gap: 4, x: M + 26, w: CW - 26 });
    }
    y += 6;
    rule(M, y, M + CW);
    y += 14;
  });

  /* ---------------------- 5. search readiness & technology -------------------- */
  const fa = d.insights.facts;
  section(5, "Search readiness and technology");
  const yn = (ok: boolean): Cell => (ok ? { t: "Present", c: GREEN, bold: true } : { t: "Missing", c: RED, bold: true });
  table(
    [
      { head: "Check", w: 5 },
      { head: "Status", w: 2 },
    ],
    [
      [{ t: "Visible to search engines (no noindex or full block)" }, yn(fa.indexable)],
      [{ t: "Page title" }, yn(!!fa.title)],
      [{ t: "Meta description" }, yn(!!fa.description)],
      [{ t: "Canonical address" }, yn(fa.hasCanonical)],
      [{ t: "XML sitemap" }, yn(fa.hasSitemap)],
      [{ t: "robots.txt" }, yn(fa.hasRobots)],
      [{ t: "Structured data (JSON-LD)" }, yn(fa.hasStructuredData)],
      [{ t: "Social share preview (Open Graph)" }, yn(fa.hasOpenGraph)],
      [{ t: `Image alt text (${fa.images - fa.imagesMissingAlt} of ${fa.images} images)` }, yn(fa.imagesMissingAlt === 0)],
    ],
  );
  if (fa.title) para(`Page title: "${fa.title}"`, { size: 9, c: GREY });
  para(`Approximate visible words on the homepage: ${fa.wordCount}.`, { size: 9, c: GREY });
  para(`Technology detected: ${stack}.`, { size: 9, c: GREY });

  /* ----------------------------- 6. action plan ------------------------------ */
  section(6, "Prioritised action plan");
  const refs = (sev: string) => d.findings.map((f, i) => ({ f, ref: `F${i + 1}` })).filter((x) => x.f.severity === sev);
  const steps: { lead: string; body: string }[] = [];
  const high = refs("high");
  const med = refs("medium");
  const low = refs("low");
  if (high.length) steps.push({ lead: "Fix the high-priority issues first.", body: high.map((x) => `${x.f.title} (${x.ref})`).join("; ") + "." });
  if (med.length) steps.push({ lead: "Then work through the medium-priority issues.", body: med.map((x) => `${x.f.title} (${x.ref})`).join("; ") + "." });
  if (low.length) steps.push({ lead: "Finish with the low-priority items.", body: `${low.length} smaller fix${low.length > 1 ? "es" : ""}, mostly quick configuration changes (${low.map((x) => x.ref).join(", ")}).` });
  steps.push({ lead: "Re-scan after changes.", body: "Run the scanner again on the same address to confirm each fix and compare your scores." });
  steps.push({ lead: "Test what a scanner cannot see.", body: "Checkout, sign-up, login and booking flows on real phones and browsers need a hands-on review." });
  steps.forEach((s, i) => {
    need(54);
    font("helvetica", "bold", 10, ORANGE);
    doc.text(`${i + 1}.`, M, y + 10);
    font("helvetica", "bold", 10, INK);
    doc.text(clean(s.lead), M + 20, y + 10);
    y += 16;
    para(s.body, { size: 9.5, c: [70, 70, 76], x: M + 20, w: CW - 20, gap: 10 });
  });

  // contact box
  need(110);
  y += 6;
  fill(M, y, CW, 92, FAINT);
  fill(M, y, 3, 92, ORANGE);
  font("times", "bold", 14, INK);
  doc.text("Want help fixing these?", M + 18, y + 26);
  font("helvetica", "normal", 9.5, [70, 70, 76]);
  doc.text(
    doc.splitTextToSize("Dignite Studios can fix what this report found and test the flows an automated scan cannot, such as checkout and sign-up on real devices.", CW - 36) as string[],
    M + 18,
    y + 44,
    { lineHeightFactor: 1.5 },
  );
  font("helvetica", "bold", 9.5, ORANGE);
  doc.text(clean(`${d.contact.email}   |   ${d.contact.phone}`), M + 18, y + 82);
  y += 106;

  /* ------------------------- 7. method and limitations ------------------------ */
  section(7, "Method and limitations");
  para(
    `Evidence was gathered on ${date} from a single, passive scan of ${d.finalUrl}: the homepage HTML and response headers, the TLS certificate, robots.txt and sitemap.xml requests${d.usedPageSpeed ? ", and Google PageSpeed Insights (mobile)" : ""}. The scan reads only what any visitor's browser can see and changes nothing on the site. Not covered: pages beyond the homepage, logged-in areas, checkout and sign-up flows, real-device and cross-browser testing, Search Console or analytics data, backlinks, keyword data, and any active security testing. This is not a penetration test or a compliance certification. Timing figures come from one load and are indicative only; scores are derived from automated rules, not from a human reviewer.`,
    { size: 8.5, c: GREY },
  );

  /* -------------------------------- footers ---------------------------------- */
  const pages = doc.getNumberOfPages();
  for (let p = 2; p <= pages; p++) {
    doc.setPage(p);
    font("helvetica", "normal", 8, GREY);
    doc.text(clean(`${host} | Website health report`), M, H - 36);
    doc.text(String(p), W - M, H - 36, { align: "right" });
  }

  doc.setProperties({ title: `Website health report: ${host}`, author: "Dignite Studios", subject: "Automated website scan" });
  doc.save(`website-report-${host.replace(/[^a-z0-9.-]/gi, "_")}-${new Date(d.scannedAt).toISOString().slice(0, 10)}.pdf`);
}
