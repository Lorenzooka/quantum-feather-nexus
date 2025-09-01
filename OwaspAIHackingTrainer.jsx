'use client';

import React, { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  ShieldCheck,
  Bug,
  Lock,
  KeyRound,
  Network,
  ScanSearch,
  Server,
  FileWarning,
  Radar,
  ChevronRight,
  ChevronLeft,
  RefreshCw,
  Sparkles,
  TimerReset,
  Trophy,
  Info,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";

/**
 * OWASP AI Hacking Trainer (Pilot)
 * ----------------------------------------------------------
 * Educational, safe, and fully in-browser simulation game for teaching
 * OWASP Top 10 (2021) concepts through interactive scenarios.
 *
 * ✨ Features
 * - 10 themed levels (A01–A10) with scenario cards
 * - Multiple challenge modes (scenario choice, code review, fix-it quiz)
 * - Beautiful UI: glassmorphism + subtle motion + badges & progress
 * - Instructor Mode: show answers, reset progress, disable timer
 * - No network calls, no real targets — 100% ethical & legal
 *
 * 🔒 Compliance
 * - This trainer avoids real exploitation or evasion. It focuses on
 *   recognizing patterns, choosing mitigations, and secure-by-design thinking.
 */

const A_COLORS = {
  A01: "from-rose-400/80 to-rose-600/60",
  A02: "from-blue-400/80 to-blue-600/60",
  A03: "from-emerald-400/80 to-emerald-600/60",
  A04: "from-amber-400/80 to-amber-600/60",
  A05: "from-purple-400/80 to-purple-600/60",
  A06: "from-sky-400/80 to-sky-600/60",
  A07: "from-fuchsia-400/80 to-fuchsia-600/60",
  A08: "from-cyan-400/80 to-cyan-600/60",
  A09: "from-orange-400/80 to-orange-600/60",
  A10: "from-lime-400/80 to-lime-600/60",
};

const ICONS = {
  A01: ShieldCheck,
  A02: Lock,
  A03: Bug,
  A04: Sparkles,
  A05: Network,
  A06: Server,
  A07: KeyRound,
  A08: FileWarning,
  A09: ScanSearch,
  A10: Radar,
};

/** Level content — concise, classroom-safe scenarios */
const LEVELS = [
  {
    id: "A01",
    title: "Broken Access Control",
    aiAngle:
      "Your AI assistant must infer missing authorization checks and recommend defensive patterns (ABAC/RBAC, deny-by-default).",
    scenario:
      "A project management app exposes /api/tasks?userId=42. Changing it to 43 returns another user's tasks despite being logged in as user 42.",
    codeSnippet: `// TaskController.js (simplified)
app.get('/api/tasks', async (req, res) => {
  const tasks = await db.tasks.find({ userId: req.query.userId });
  res.json(tasks);
});
// ❌ Authorization relies on client-provided userId
`,
    question: "What is the best immediate mitigation?",
    choices: [
      { text: "Validate userId is numeric.", correct: false },
      {
        text: "Enforce server-side ownership using req.user.id and access checks.",
        correct: true,
      },
      { text: "Add a CAPTCHA to /api/tasks.", correct: false },
      { text: "Use client-side filtering only.", correct: false },
    ],
    explanation:
      "Never trust userId from the client. Derive identity from the session/token and enforce ownership (RBAC/ABAC). Deny-by-default and use parameterized queries for defense-in-depth.",
  },
  {
    id: "A02",
    title: "Cryptographic Failures",
    aiAngle:
      "The AI spots plaintext secrets and recommends modern crypto (TLS 1.2+, AES-GCM, Argon2id for passwords, proper key management).",
    scenario:
      "Login responses include a session token set over HTTP without Secure/HttpOnly flags. Passwords in the DB are hashed with MD5.",
    codeSnippet: `// auth.js (legacy)
res.cookie('session', token); // ❌ missing Secure & HttpOnly
// DB: users(password_md5 CHAR(32))
`,
    question: "Which combination is most appropriate?",
    choices: [
      { text: "Keep MD5 but add a salt.", correct: false },
      {
        text: "Switch to Argon2id for password hashing and set cookies Secure+HttpOnly+SameSite.",
        correct: true,
      },
      { text: "Base64-encode passwords in transit.", correct: false },
      { text: "Store passwords encrypted with AES and skip hashing.", correct: false },
    ],
    explanation:
      "Use a memory-hard KDF (Argon2id/PBKDF2/bcrypt), enforce TLS, and set cookie flags (Secure, HttpOnly, SameSite) to reduce theft risk.",
  },
  {
    id: "A03",
    title: "Injection",
    aiAngle:
      "AI detects untrusted input used in commands/queries and suggests parameterization and allowlists.",
    scenario:
      "An admin dashboard builds SQL with template strings using ?sort and ?filter directly into the query.",
    codeSnippet: `// reports.sql (bad)
const q = \`SELECT * FROM orders ORDER BY \${req.query.sort} LIMIT 50\`;
const rows = await db.query(q); // ❌ SQL injection via sort
`,
    question: "Best mitigation?",
    choices: [
      { text: "Escape quotes in input.", correct: false },
      {
        text: "Use parameterized queries/ORM and an allowlist for sortable columns.",
        correct: true,
      },
      { text: "Double-check with regex.", correct: false },
      { text: "Log the input to detect attacks only.", correct: false },
    ],
    explanation:
      "Parameterize everything and restrict dynamic parts to a strict allowlist (e.g., ['date','total','status']).",
  },
  {
    id: "A04",
    title: "Insecure Design",
    aiAngle:
      "AI helps threat-model flows and enforce defense-in-depth (STRIDE, secure defaults, rate limiting).",
    scenario:
      "A money transfer endpoint lacks daily limits and does not require step-up MFA for large amounts.",
    codeSnippet: `// transfer.js (missing design controls)
app.post('/api/transfer', requireAuth, async (req,res)=>{
  // sends funds immediately
});
`,
    question: "What design control improves security the most?",
    choices: [
      { text: "Add a nicer UI for transfers.", correct: false },
      {
        text: "Introduce risk-based controls: per-day caps, velocity checks, and step-up MFA.",
        correct: true,
      },
      { text: "Minify JavaScript to hide logic.", correct: false },
      { text: "Return fewer fields in JSON.", correct: false },
    ],
    explanation:
      "Design-stage controls prevent abuse: limits, velocity, risk scoring, and explicit authorization checkpoints for sensitive actions.",
  },
  {
    id: "A05",
    title: "Security Misconfiguration",
    aiAngle:
      "AI flags verbose error messages, default creds, and missing headers; suggests hardening baselines and IaC policies.",
    scenario:
      "Stack traces are returned in production. /admin uses default credentials from a container image.",
    codeSnippet: `// server.js
app.use(errorHandler({ showStack: process.env.NODE_ENV !== 'production' })); // ❌
// Dockerfile bakes default admin:admin
`,
    question: "Best remediation set?",
    choices: [
      { text: "Obfuscate HTML.", correct: false },
      {
        text: "Disable detailed errors in prod, rotate secrets, enforce baseline headers (CSP, HSTS).",
        correct: true,
      },
      { text: "Rely on WAF only.", correct: false },
      { text: "Hide admin path with robots.txt.", correct: false },
    ],
    explanation:
      "Harden configurations: no verbose errors in prod, unique creds, secure headers, least privilege, and IaC guardrails.",
  },
  {
    id: "A06",
    title: "Vulnerable & Outdated Components",
    aiAngle:
      "AI reads SBOMs, flags CVEs, and advises update/compensating controls.",
    scenario:
      "The app still uses a framework version with a known RCE; builds lack dependency pinning.",
    codeSnippet: `# package.json
"express": "^4.16.0" // floating versions, supply chain risk
`,
    question: "What should the team implement first?",
    choices: [
      { text: "Turn off logging.", correct: false },
      {
        text: "Pin & update dependencies, generate SBOM, and add CI/CD dependency scanning.",
        correct: true,
      },
      { text: "Copy node_modules into the repo.", correct: false },
      { text: "Ignore until exploited.", correct: false },
    ],
    explanation:
      "Adopt SBOM + pinned versions + automated scanning (SCA) and timely patching.",
  },
  {
    id: "A07",
    title: "Identification & Authentication Failures",
    aiAngle:
      "AI verifies MFA coverage, session lifecycle, and password policies.",
    scenario:
      "Session does not expire on logout, and password reset tokens never expire.",
    codeSnippet: `// sessions.js
store[token] = userId; // ❌ no TTL, logout doesn't revoke
`,
    question: "Pick the strongest fix set:",
    choices: [
      { text: "Add a logout button only.", correct: false },
      {
        text: "Short-lived, revocable sessions; rotate & expire reset tokens; enforce MFA.",
        correct: true,
      },
      { text: "Store sessions in localStorage.", correct: false },
      { text: "Only change the favicon.", correct: false },
    ],
    explanation:
      "Use server-side session stores with TTL/rotation, revoke on logout, and protect all sensitive flows with MFA.",
  },
  {
    id: "A08",
    title: "Software & Data Integrity Failures",
    aiAngle:
      "AI checks CI/CD for unsigned artifacts, missing review gates, and environment drift.",
    scenario:
      "Build pipeline downloads an unsigned bash script at runtime and executes it as root.",
    codeSnippet: `# CI step
curl https://example.com/build.sh | bash  # ❌ unauthenticated code
`,
    question: "Best remediation?",
    choices: [
      { text: "Pin to a specific URL.", correct: false },
      {
        text: "Signed artifacts, checksum verification, repo-pinned actions, and least-privileged runners.",
        correct: true,
      },
      { text: "Run everything as root to avoid permission errors.", correct: false },
      { text: "Cache scripts for faster builds.", correct: false },
    ],
    explanation:
      "Require signed, verified artifacts and hermetic builds; avoid piping untrusted code; principle of least privilege everywhere.",
  },
  {
    id: "A09",
    title: "Security Logging & Monitoring Failures",
    aiAngle:
      "AI correlates anomalies, ensures logs are tamper-evident and privacy-respecting.",
    scenario:
      "Auth events are logged only on success. Rate spikes and 401 storms go unnoticed.",
    codeSnippet: `// logging.js
if (status === 200) log('login_success'); // ❌ ignoring failures & metrics
`,
    question: "Choose the strongest improvement:",
    choices: [
      { text: "Log everything forever.", correct: false },
      {
        text: "Structured, privacy-aware logs for successes & failures; alerts on anomalies; protected log pipeline.",
        correct: true,
      },
      { text: "Email errors to devs.", correct: false },
      { text: "Turn off logs in prod.", correct: false },
    ],
    explanation:
      "Emit structured logs for both success and failure, centralize & protect them, and alert on thresholds/behaviors.",
  },
  {
    id: "A10",
    title: "Server-Side Request Forgery (SSRF)",
    aiAngle:
      "AI detects risky URL fetchers and suggests allowlists, metadata protection, and egress controls.",
    scenario:
      "Image fetcher accepts any URL and proxies bytes to clients; it can access http://169.254.169.254/ metadata.",
    codeSnippet: `// proxy.js
app.get('/proxy', async (req,res)=>{
  const url = req.query.url; // ❌ unvalidated URL
  const r = await fetch(url);
  r.body.pipe(res);
});
`,
    question: "Pick the best mitigation set:",
    choices: [
      { text: "Block only 127.0.0.1.", correct: false },
      {
        text: "Enforce URL allowlists, block private ranges/metadata IPs, and restrict egress at the firewall.",
        correct: true,
      },
      { text: "Add a retry loop.", correct: false },
      { text: "Base64-encode responses.", correct: false },
    ],
    explanation:
      "Use positive allowlists, block internal/metadata endpoints, and enforce egress policies and DNS pinning where possible.",
  },
];

// Utility: local storage hooks
const useStoredState = (key, initial) => {
  const [state, setState] = useState(() => {
    if (typeof window === 'undefined') return initial;
    try {
      const v = window.localStorage.getItem(key);
      return v ? JSON.parse(v) : initial;
    } catch {
      return initial;
    }
  });
  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(key, JSON.stringify(state));
    } catch {}
  }, [key, state]);
  return [state, setState];
};

export default function OwaspAIHackingTrainer() {
  const [index, setIndex] = useStoredState("owasp_pilot_index", 0);
  const [score, setScore] = useStoredState("owasp_pilot_score", 0);
  const [answers, setAnswers] = useStoredState("owasp_pilot_answers", {});
  const [instructor, setInstructor] = useStoredState("owasp_pilot_instructor", false);
  const [timerOn, setTimerOn] = useStoredState("owasp_pilot_timerOn", true);
  const [seconds, setSeconds] = useStoredState("owasp_pilot_seconds", 0);

  const level = LEVELS[index];
  const Icon = ICONS[level.id] || ShieldCheck;

  useEffect(() => {
    if (!timerOn) return;
    const t = setInterval(() => setSeconds((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, [timerOn, setSeconds]);

  const total = LEVELS.length;
  const progress = Math.round((Object.keys(answers).length / total) * 100);

  const answered = answers[level.id]?.answered || false;
  const correct = answers[level.id]?.correct || false;

  function choose(choiceIdx) {
    if (answered && !instructor) return;
    const isCorrect = level.choices[choiceIdx].correct;
    setAnswers((prev) => {
      if (isCorrect && !prev[level.id]?.correct) {
        setScore((s) => s + 1);
      }
      return {
        ...prev,
        [level.id]: { answered: true, correct: isCorrect, choice: choiceIdx },
      };
    });
  }

  function next() {
    setIndex((i) => Math.min(i + 1, total - 1));
  }
  function prev() {
    setIndex((i) => Math.max(i - 1, 0));
  }
  function reset() {
    setAnswers({});
    setScore(0);
    setIndex(0);
    setSeconds(0);
  }

  const grade = useMemo(() => {
    const pct = (score / total) * 100;
    if (pct === 100) return { label: "Legend", color: "bg-emerald-500" };
    if (pct >= 80) return { label: "Gold", color: "bg-yellow-500" };
    if (pct >= 60) return { label: "Silver", color: "bg-slate-400" };
    if (pct >= 40) return { label: "Bronze", color: "bg-amber-700" };
    return { label: "Learner", color: "bg-sky-500" };
  }, [score, total]);

  return (
    <div className="relative min-h-screen w-full bg-gradient-to-br from-slate-900 via-slate-950 to-black text-slate-100">
      {/* Glow decorations */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="absolute -top-24 -left-24 h-72 w-72 rounded-full bg-pink-500/10 blur-3xl" />
        <div className="absolute -bottom-32 -right-24 h-80 w-80 rounded-full bg-cyan-500/10 blur-3xl" />
      </div>

      {/* Header */}
      <header className="sticky top-0 z-20 backdrop-blur supports-[backdrop-filter]:bg-slate-900/40">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-4">
          <div className="flex items-center gap-3">
            <motion.div
              initial={{ rotate: -10, opacity: 0 }}
              animate={{ rotate: 0, opacity: 1 }}
              transition={{ type: "spring", stiffness: 120 }}
              className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-600 shadow-lg"
            >
              <ShieldCheck className="h-6 w-6" />
            </motion.div>
            <div>
              <h1 className="text-lg font-bold md:text-xl">OWASP Top 10 — AI Hacking Trainer (Pilot)</h1>
              <p className="text-xs text-slate-400">
                Ethical, legal, classroom-safe. Learn by simulating attacks & fixes.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Badge className={`${grade.color} text-black font-semibold`}>
              {grade.label}
            </Badge>
            <div className="hidden items-center gap-2 sm:flex">
              <TimerReset className="h-4 w-4" />
              <span className="text-xs tabular-nums">
                {Math.floor(seconds / 60)
                  .toString()
                  .padStart(2, "0")}
                :{(seconds % 60).toString().padStart(2, "0")}
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-slate-400">Instructor</span>
              <Switch checked={instructor} onCheckedChange={setInstructor} />
            </div>
            <Button variant="secondary" size="sm" onClick={reset} className="gap-2">
              <RefreshCw className="h-4 w-4" /> Reset
            </Button>
          </div>
        </div>
        <div className="mx-auto max-w-7xl px-4 pb-2">
          <Progress value={progress} className="h-2" />
          <div className="mt-1 text-right text-[11px] text-slate-400">
            Progress: {progress}% | Score: {score}/{LEVELS.length}
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="mx-auto grid max-w-7xl grid-cols-1 gap-4 px-4 py-6 md:grid-cols-12">
        {/* Sidebar */}
        <aside className="md:col-span-4 lg:col-span-3">
          <Card className="border-slate-800/60 bg-slate-900/40">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                <Info className="h-4 w-4" /> Levels
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {LEVELS.map((lvl, i) => {
                const LIcon = ICONS[lvl.id] || ShieldCheck;
                const isDone = answers[lvl.id]?.answered;
                const isCurrent = i === index;
                return (
                  <button
                    key={lvl.id}
                    onClick={() => setIndex(i)}
                    className={`group flex w-full items-center justify-between rounded-xl border px-3 py-2 text-left transition ${
                      isCurrent
                        ? "border-emerald-500/50 bg-emerald-500/10"
                        : "border-slate-800/60 hover:bg-slate-800/40"
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br ${A_COLORS[lvl.id]}`}
                      >
                        <LIcon className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="text-xs font-semibold text-slate-200">
                          {lvl.id}
                        </div>
                        <div className="text-[11px] text-slate-400">
                          {lvl.title}
                        </div>
                      </div>
                    </div>
                    {isDone && (
                      <Badge
                        variant="outline"
                        className={`border-emerald-500/40 text-emerald-300`}
                      >
                        Done
                      </Badge>
                    )}
                  </button>
                );
              })}
            </CardContent>
          </Card>
        </aside>

        {/* Main panel */}
        <section className="space-y-4 md:col-span-8 lg:col-span-9">
          <Card className="overflow-hidden border-slate-800/60 bg-slate-900/40">
            <div className={`h-2 w-full bg-gradient-to-r ${A_COLORS[level.id]}`} />
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-3 text-base font-semibold text-slate-100">
                  <Icon className="h-5 w-5" />
                  {level.id} — {level.title}
                </CardTitle>
                <div className="text-xs text-slate-400">
                  Level {index + 1} / {LEVELS.length}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-5">
                <div className="space-y-3 md:col-span-3">
                  <div className="rounded-xl border border-slate-800/60 bg-slate-950/40 p-3">
                    <p className="text-sm leading-relaxed text-slate-200">
                      <span className="font-semibold">Scenario:</span> {level.scenario}
                    </p>
                  </div>

                  <div className="rounded-xl border border-slate-800/60 bg-slate-950/40">
                    <div className="flex items-center justify-between border-b border-slate-800/60 px-3 py-2">
                      <div className="text-[11px] uppercase tracking-wider text-slate-400">
                        Code (simplified)
                      </div>
                      <div className="text-[11px] text-slate-500">Read-only</div>
                    </div>
                    <pre className="max-h-64 overflow-auto p-3 text-[12px] leading-5 text-emerald-200/90">
                      <code>{level.codeSnippet}</code>
                    </pre>
                  </div>
                </div>

                <div className="space-y-3 md:col-span-2">
                  <div className="rounded-xl border border-slate-800/60 bg-slate-950/40 p-3">
                    <p className="text-sm font-semibold text-slate-200">
                      {level.question}
                    </p>
                    <div className="mt-3 grid gap-2">
                      {level.choices.map((c, idx) => {
                        const chosen = answers[level.id]?.choice === idx;
                        const success = answered && c.correct;
                        const fail = answered && chosen && !c.correct;
                        return (
                          <Button
                            key={idx}
                            onClick={() => choose(idx)}
                            variant={
                              success
                                ? "default"
                                : fail
                                ? "destructive"
                                : "secondary"
                            }
                            className={`justify-start whitespace-normal break-words border ${
                              success
                                ? "border-emerald-500/50"
                                : fail
                                ? "border-rose-500/50"
                                : "border-slate-700/60"
                            }`}
                          >
                            <span className="text-left text-[13px]">{c.text}</span>
                          </Button>
                        );
                      })}
                    </div>
                    <AnimatePresence>
                      {(answered || instructor) && (
                        <motion.div
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          exit={{ opacity: 0, y: 8 }}
                          className={`mt-3 rounded-lg border p-3 text-sm ${
                            correct
                              ? "border-emerald-600/50 bg-emerald-500/10 text-emerald-200"
                              : "border-rose-600/50 bg-rose-500/10 text-rose-200"
                          }`}
                        >
                          <div className="font-semibold">
                            {correct ? "Correct" : "Explanation"}
                          </div>
                          <p className="mt-1 text-slate-200/90">
                            {level.explanation}
                          </p>
                          <div className="mt-2 text-[11px] text-slate-400">
                            <span className="font-semibold text-slate-300">
                              AI Mentor:
                            </span>{" "}
                            {level.aiAngle}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    <Button variant="ghost" className="gap-2" onClick={prev}>
                      <ChevronLeft className="h-4 w-4" /> Prev
                    </Button>
                    <Button variant="ghost" className="gap-2" onClick={next}>
                      Next <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Summary card */}
          <Card className="border-slate-800/60 bg-slate-900/40">
            <CardContent className="flex flex-wrap items-center justify-between gap-3 p-4">
              <div className="flex items-center gap-3">
                <Trophy className="h-5 w-5 text-amber-400" />
                <div>
                  <div className="text-sm font-semibold">Your Run</div>
                  <div className="text-xs text-slate-400">
                    Score {score}/{LEVELS.length} • Time {Math.floor(seconds / 60)}m {seconds % 60}s
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Badge
                  variant="outline"
                  className="border-slate-700/60 text-slate-300"
                >
                  Classroom Safe
                </Badge>
                <Badge
                  variant="outline"
                  className="border-slate-700/60 text-slate-300"
                >
                  No Real Targets
                </Badge>
                <Badge
                  variant="outline"
                  className="border-slate-700/60 text-slate-300"
                >
                  OWASP Top 10
                </Badge>
              </div>
            </CardContent>
          </Card>
        </section>
      </main>

      {/* Footer */}
      <footer className="mx-auto max-w-7xl px-4 pb-8 text-center text-[11px] text-slate-500">
        Built for ethical training. This simulation teaches secure patterns — not evasion.
      </footer>
    </div>
  );
}

