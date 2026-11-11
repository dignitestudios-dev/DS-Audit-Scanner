import { Suspense } from "react";
import Scanner from "@/components/Scanner";

const AREAS = [
  { t: "Security", d: "Headers, cookies, outdated software", p: "M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z" },
  { t: "HTTPS & SSL", d: "Certificate, redirects, mixed content", p: "M7 11V8a5 5 0 0110 0v3M6 11h12v9H6z" },
  { t: "Speed", d: "Real Google data on a phone", p: "M13 2L4 14h7l-1 8 9-12h-7l1-8z" },
  { t: "Mobile", d: "Viewport and touch readiness", p: "M8 2h8a1 1 0 011 1v18a1 1 0 01-1 1H8a1 1 0 01-1-1V3a1 1 0 011-1zM11 18h2" },
  { t: "SEO", d: "Titles, sitemap, search visibility", p: "M11 4a7 7 0 105 12l4 4M11 8v6M8 11h6" },
  { t: "Accessibility", d: "Alt text, language, contrast", p: "M12 4a1.5 1.5 0 110 3 1.5 1.5 0 010-3zM5 9l7 1 7-1M12 10v5M9 21l3-6 3 6" },
];

export default function Home() {
  return (
    <main>
      <header className="bar">
        <span className="brand">
          <i aria-hidden="true" /> Dignite Studios
        </span>
        <a className="bar-link" href="https://dignitestudios.net">
          Full audits
        </a>
      </header>

      <section className="hero">
        <p className="pill">
          <span aria-hidden="true" /> Free website health check
        </p>
        <h1>
          Is your website quietly <em>losing you customers?</em>
        </h1>
        <p className="lede">
          Get an instant score for security, speed, SEO, accessibility and mobile readiness. No
          sign-up. No tools to install.
        </p>
        <Suspense fallback={null}>
          <Scanner />
        </Suspense>
        <ul className="trust">
          <li>100% free</li>
          <li>Takes under a minute</li>
          <li>Passive, read-only scan</li>
          <li>No account needed</li>
        </ul>
      </section>

      <section className="areas" aria-labelledby="areas-h">
        <h2 id="areas-h">Six checks, one score</h2>
        <ul>
          {AREAS.map((a) => (
            <li key={a.t}>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d={a.p} />
              </svg>
              <strong>{a.t}</strong>
              <span>{a.d}</span>
            </li>
          ))}
        </ul>
      </section>

      <p className="fine">
        This is an automated, passive surface scan. It reads what any visitor&apos;s browser can see,
        changes nothing, and is not a penetration test or compliance certification. Only scan sites
        you own or are authorised to check.
      </p>
    </main>
  );
}
