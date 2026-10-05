"use client";

import { useMemo, useState } from "react";

type Finding = { severity: "high" | "medium" | "low"; title: string; detail: string };
type Report = {
  score: number;
  label: string;
  entropy: number;
  guesses: number;
  findings: Finding[];
  crack: { online: string; offline: string; gpu: string };
  length: number;
};

type PwnedState = { status: "idle" | "checking" | "found" | "clear" | "error"; count?: number; message?: string };

const common = new Set(["password", "password1", "123456", "12345678", "qwerty", "qwerty123", "letmein", "admin", "welcome", "iloveyou", "monkey", "dragon", "football", "abc123"]);
const leet = (s: string) => s.toLowerCase().replaceAll("@", "a").replaceAll("4", "a").replaceAll("3", "e").replaceAll("1", "i").replaceAll("!", "i").replaceAll("0", "o").replaceAll("5", "s").replaceAll("7", "t");

function humanGuesses(n: number) {
  if (n < 1e3) return `${Math.round(n)} guesses`;
  if (n < 1e6) return `${(n / 1e3).toFixed(1)}K guesses`;
  if (n < 1e9) return `${(n / 1e6).toFixed(1)}M guesses`;
  if (n < 1e12) return `${(n / 1e9).toFixed(1)}B guesses`;
  return n.toExponential(1) + " guesses";
}

function time(guesses: number, rate: number) {
  const s = guesses / rate;
  if (s < 60) return `${Math.max(1, Math.round(s))} sec`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  if (s < 86400) return `${Math.round(s / 3600)} hr`;
  if (s < 31557600) return `${Math.round(s / 86400)} days`;
  if (s < 3155760000) return `${Math.round(s / 31557600)} years`;
  return `${(s / 31557600).toExponential(1)} years`;
}

function analyze(p: string): Report {
  const lower = /[a-z]/.test(p), upper = /[A-Z]/.test(p), digit = /\d/.test(p), symbol = /[^A-Za-z0-9]/.test(p);
  const pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (symbol ? 33 : 0);
  let entropy = p.length * Math.log2(Math.max(pool, 1));
  const findings: Finding[] = [];
  const normalized = leet(p);

  if (common.has(normalized)) findings.push({ severity: "high", title: "Common password", detail: "This value or its leetspeak-normalized form is highly predictable." });
  if (/^(.)\1+$/.test(p)) findings.push({ severity: "high", title: "Repeated character", detail: "A single repeated character is cheap to guess regardless of length." });
  if (/^(0123|1234|2345|3456|4567|5678|6789|abcd|qwerty)/i.test(p)) findings.push({ severity: "high", title: "Sequence or keyboard pattern", detail: "Predictable sequences and keyboard walks are heavily favored by crackers." });
  if (/^(19|20)\d{2}/.test(p) || /\d{4}$/.test(p)) findings.push({ severity: "medium", title: "Date/year pattern", detail: "Year-like suffixes and dates are common mutation candidates." });
  if (p.length < 12) findings.push({ severity: "medium", title: "Short password", detail: "Prefer a long passphrase; length matters more than cosmetic complexity." });
  if (new Set(p).size < 5 && p.length > 0) findings.push({ severity: "low", title: "Low character diversity", detail: "A narrow set of repeated characters reduces the effective search space." });

  if (findings.some(x => x.severity === "high")) entropy = Math.min(entropy, 28);
  else if (findings.some(x => x.severity === "medium")) entropy = Math.min(entropy, 55);
  const guesses = Math.max(1, Math.pow(2, Math.min(entropy, 100)));
  let score = entropy < 28 ? 1 : entropy < 40 ? 2 : entropy < 60 ? 3 : 4;
  if (findings.some(x => x.severity === "high")) score = 1;
  if (p.length >= 20 && !findings.some(x => x.severity === "high")) score = 4;
  return { score, label: ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score], entropy, guesses, length: p.length, findings, crack: { online: time(guesses, 100), offline: time(guesses, 1e4), gpu: time(guesses, 1e9) } };
}

async function sha1Hex(value: string) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", data);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

export default function Home() {
  const [password, setPassword] = useState("");
  const [pwned, setPwned] = useState<PwnedState>({ status: "idle" });
  const [generated, setGenerated] = useState("");
  const r = useMemo(() => analyze(password), [password]);

  const checkPwned = async () => {
    if (!password) return;
    setPwned({ status: "checking" });
    try {
      const hash = await sha1Hex(password);
      const response = await fetch("/api/pwned", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ prefix: hash.slice(0, 5) }) });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "HIBP request failed");
      const suffix = hash.slice(5);
      const line = String(payload.data).split("\n").find((x: string) => x.toUpperCase().startsWith(`${suffix}:`));
      if (line) setPwned({ status: "found", count: Number(line.split(":")[1]) || 0 });
      else setPwned({ status: "clear" });
    } catch (error) {
      setPwned({ status: "error", message: error instanceof Error ? error.message : "Unknown error" });
    }
  };

  const generate = () => {
    const words = ["amber", "anchor", "atlas", "canyon", "cobalt", "comet", "crystal", "ember", "falcon", "forest", "harbor", "horizon", "lantern", "meadow", "mercury", "nebula", "orbit", "otter", "pixel", "quartz", "raven", "rocket", "signal", "silver", "summit", "thunder", "vector", "violet", "walnut", "zenith"];
    const values = Array.from({ length: 6 }, () => words[Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32 * words.length)]);
    setGenerated(values.join("-"));
    setPassword(values.join("-"));
    setPwned({ status: "idle" });
  };

  return <main className="shell">
    <nav className="nav"><div className="brand">SentinelPass</div><div className="badge">LOCAL-FIRST · v2.1</div></nav>

    <section className="hero">
      <div className="eyebrow">Password security intelligence</div>
      <h1>Model the attack.<br />Not just the password.</h1>
      <p>Analyze predictability, effective entropy and attacker scenarios locally. Then separately check whether the password has appeared in known breach data.</p>
    </section>

    <section className="panel">
      <div className="inputRow">
        <input aria-label="Password" className="input" type="password" autoComplete="off" value={password} onChange={e => { setPassword(e.target.value); setPwned({ status: "idle" }); }} placeholder="Enter a password to analyze locally…" />
        <button className="btn secondary" onClick={generate}>Generate</button>
        <button className="btn" onClick={() => { setPassword(""); setGenerated(""); setPwned({ status: "idle" }); }}>Clear</button>
      </div>

      <div className="result">
        <div className="score"><div className="scoreNum">{r.score}/4</div><div className="label">{password ? r.label : "Waiting for input"}</div></div>
        <div className="meter"><i style={{ width: `${r.score * 25}%` }} /></div>

        <div className="grid">
          <div className="card"><small>Effective entropy</small><strong>{password ? `${r.entropy.toFixed(1)} bits` : "—"}</strong></div>
          <div className="card"><small>Estimated guesses</small><strong>{password ? humanGuesses(r.guesses) : "—"}</strong></div>
          <div className="card"><small>Length</small><strong>{password ? r.length : "—"}</strong></div>
        </div>

        {password && <>
          <div className="grid">
            <div className="card"><small>Rate-limited online</small><strong>{r.crack.online}</strong></div>
            <div className="card"><small>Offline slow hash</small><strong>{r.crack.offline}</strong></div>
            <div className="card"><small>Fast/GPU model</small><strong>{r.crack.gpu}</strong></div>
          </div>

          <div className="breachBox">
            <div><small>Compromise intelligence</small><strong>{pwned.status === "found" ? `Seen ${pwned.count?.toLocaleString()} times` : pwned.status === "clear" ? "No match found" : pwned.status === "checking" ? "Checking…" : pwned.status === "error" ? "Check failed" : "Not checked"}</strong></div>
            <button className="btn" disabled={pwned.status === "checking"} onClick={checkPwned}>{pwned.status === "checking" ? "Checking…" : "Check with HIBP"}</button>
          </div>
          {pwned.status === "found" && <div className="notice danger">This password appears in known breach data. Treat it as compromised and do not reuse it.</div>}
          {pwned.status === "clear" && <div className="notice good">No matching hash was found in the current Pwned Passwords corpus. This is not proof that the password is unique.</div>}
          {pwned.status === "error" && <div className="notice warn">{pwned.message}</div>}

          <div className="issues">
            {r.findings.length ? r.findings.map((f, i) => <div className="issue" key={i}><span className={`dot ${f.severity}`} /><div><strong>{f.title}</strong><br /><span className="warn">{f.detail}</span></div></div>) : <div className="issue"><span className="dot goodDot" /><div><strong className="goodText">No obvious structural weakness detected.</strong><br /><span>That does not prove a password is breach-free or mathematically uncrackable.</span></div></div>}
          </div>
        </>}
      </div>
    </section>

    {generated && <div className="generated"><small>CSPRNG-generated passphrase</small><code>{generated}</code></div>}
    <p className="footer">Privacy model: analysis stays in the browser. HIBP receives only a five-character SHA-1 hash prefix through the k-anonymity range API; SentinelPass never sends the plaintext password. Threat-model times are estimates, not measurements of a specific cracking rig.</p>
  </main>;
}
