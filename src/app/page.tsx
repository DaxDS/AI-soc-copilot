"use client";

import { useEffect, useRef, useState } from "react";

type MitreTechnique = { id: string; name: string };

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
  evidence?: string[];
  severity?: "Low" | "Medium" | "High" | "Critical";
  confidence?: number;
  riskScore?: number;
  mitreTechniques?: MitreTechnique[];
  recommendedActions?: {
    label: string;
    risk: "Low" | "Medium" | "High";
    requiresApproval: boolean;
  }[];
};

type IncidentStatus = "New" | "Under Review" | "Resolved";

type Incident = {
  id: string;
  title: string;
  summary: string;
  severity: "Low" | "Medium" | "High" | "Critical" | "Unknown";
  source: string;
  status: IncidentStatus;
  riskScore?: number;
  createdAt: string;
};

type SimilarIncident = {
  id: string;
  title: string;
  summary: string;
  mitreTechniques: MitreTechnique[];
  riskScore: number;
  recommendedActions: string[];
};

const SAMPLE_INCIDENTS: Incident[] = [
  {
    id: "1",
    title: "Impossible travel",
    summary:
      "Sentinel: Impossible travel sign-in for user j.doe@company.com — Brazil and Germany within 28 minutes.",
    severity: "High",
    source: "Microsoft Sentinel",
    status: "New",
    createdAt: "2024-01-01T00:00:00.000Z",
  },
  {
    id: "2",
    title: "Phishing campaign",
    summary:
      "Microsoft Defender: Multiple users reported suspicious email with link to fake login page. Subject: 'Urgent: Verify your account'.",
    severity: "High",
    source: "Microsoft Defender",
    status: "New",
    createdAt: "2024-01-01T00:00:00.000Z",
  },
  {
    id: "3",
    title: "EDR malware alert",
    summary:
      "CrowdStrike: Host WORKSTATION-42 — suspicious process tree, unknown executable dropped in AppData, outbound C2-like connection.",
    severity: "Critical",
    source: "CrowdStrike",
    status: "New",
    createdAt: "2024-01-01T00:00:00.000Z",
  },
  {
    id: "4",
    title: "Unusual sign-in",
    summary:
      "Azure AD: User m.smith@company.com signed in from new device (Chrome, Windows) from VPN IP. No MFA challenge.",
    severity: "Medium",
    source: "Azure AD",
    status: "New",
    createdAt: "2024-01-01T00:00:00.000Z",
  },
];

export default function Home() {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "Hi, I’m your AI SOC copilot. Paste an alert or incident summary and I’ll triage it, enrich it, and suggest next steps.",
    },
  ]);
  const [input, setInput] = useState("");
  const [isThinking, setIsThinking] = useState(false);
  const [openaiConfigured, setOpenaiConfigured] = useState<boolean | null>(null);
  const [activeIncident, setActiveIncident] = useState<Incident | null>(null);
  const [incidentQueue, setIncidentQueue] = useState<Incident[]>([]);
  const [sampleIncidentsOpen, setSampleIncidentsOpen] = useState(true);
  const [lastTriageResult, setLastTriageResult] = useState<{
    riskScore?: number;
    mitreTechniques?: MitreTechnique[];
    recommendedActions?: { label: string; risk: string; requiresApproval: boolean }[];
  } | null>(null);
  const [investigationTimeline, setInvestigationTimeline] = useState<
    { time: string; event: string }[] | null
  >(null);
  const [playbookRunAt, setPlaybookRunAt] = useState<string | null>(null);
  const [explanationByIndex, setExplanationByIndex] = useState<Record<number, string>>({});
  const [loadingExplainIndex, setLoadingExplainIndex] = useState<number | null>(null);
  const [mode, setMode] = useState<
    "triage" | "incident-queue" | "log-ingestion" | "nl-query" | "knowledge" | "dedupe" | "simulation"
  >("triage");
  const [logIngestionInput, setLogIngestionInput] = useState("");
  const [nlQueryInput, setNlQueryInput] = useState("");
  const [nlQueryResult, setNlQueryResult] = useState<{ kql: string; spl: string } | null>(null);
  const [knowledgeInput, setKnowledgeInput] = useState("");
  const [knowledgeAnswer, setKnowledgeAnswer] = useState<string | null>(null);
  const [dedupeAlerts, setDedupeAlerts] = useState("");
  const [dedupeResult, setDedupeResult] = useState<{ incidentTitle: string; summary: string; count: number } | null>(null);
  const [simulateData, setSimulateData] = useState<{ title: string; alerts: string[]; timeline: { time: string; event: string }[] } | null>(null);
  const [threatIntelIoc, setThreatIntelIoc] = useState("");
  const [threatIntelResult, setThreatIntelResult] = useState<{ ioc: string; reputation: string; country?: string; association?: string } | null>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [similarIncidents, setSimilarIncidents] = useState<SimilarIncident[] | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);

  const addIncidentToQueue = (incident: Incident) => {
    setIncidentQueue((prev) => [incident, ...prev]);
  };

  const updateIncidentInQueue = (id: string, updates: Partial<Incident>) => {
    setIncidentQueue((prev) =>
      prev.map((inc) => (inc.id === id ? { ...inc, ...updates } : inc)),
    );
  };

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages.length]);

  useEffect(() => {
    fetch("/api/status")
      .then((r) => r.json())
      .then((d) => setOpenaiConfigured(d.openaiConfigured ?? false))
      .catch(() => setOpenaiConfigured(false));
  }, []);

  const triageWithMessages = async (nextMessages: ChatMessage[]) => {
    setIsThinking(true);
    try {
      const res = await fetch("/api/soc-copilot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: nextMessages }),
      });
      const data = await res.json();

      if (!res.ok) {
        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: `Error: ${data?.error ?? res.statusText}. Try again.`,
          },
        ]);
        return;
      }
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message ?? "No response.",
          evidence: data.evidence,
          severity: data.severity,
          confidence: data.confidence,
          riskScore: data.riskScore,
          mitreTechniques: data.mitreTechniques,
          recommendedActions: data.recommendedActions,
        },
      ]);
      setLastTriageResult({
        riskScore: data.riskScore,
        mitreTechniques: data.mitreTechniques,
        recommendedActions: data.recommendedActions,
      });
      setSimilarIncidents(
        Array.isArray(data.similarIncidents) ? data.similarIncidents : null,
      );
      setPlaybookRunAt(null);
      setActiveIncident((prev) => {
        if (!prev) return prev;
        const updated: Incident = {
          ...prev,
          riskScore: data.riskScore ?? prev.riskScore,
          severity: (data.severity as Incident["severity"]) ?? prev.severity,
          status: prev.status === "Resolved" ? prev.status : "Under Review",
        };
        updateIncidentInQueue(prev.id, {
          riskScore: updated.riskScore,
          severity: updated.severity,
          status: updated.status,
        });
        return updated;
      });
      const lastUserContent = nextMessages[nextMessages.length - 1]?.content;
      if (lastUserContent) {
        fetch("/api/soc-copilot/investigate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userMessage: lastUserContent }),
        })
          .then((r) => r.json())
          .then((d) => setInvestigationTimeline(d.timeline ?? null))
          .catch(() => setInvestigationTimeline(null));
      } else {
        setInvestigationTimeline(null);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "Network error. Check the console and try again.",
        },
      ]);
    } finally {
      setIsThinking(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || isThinking) return;

    const userMessage: ChatMessage = { role: "user", content: trimmed };
    const nextMessages = [...messages, userMessage];
    setMessages(nextMessages);
    setInput("");

    const newIncident: Incident = {
      id: `adhoc-${Date.now()}`,
      title: "Ad-hoc incident",
      summary: trimmed,
      severity: "Unknown",
      source: "Manual input",
      status: "Under Review",
      createdAt: new Date().toISOString(),
    };
    setActiveIncident(newIncident);
    addIncidentToQueue(newIncident);

    triageWithMessages(nextMessages);
  };

  const handleExplainDecision = async (idx: number) => {
    const prevUser = messages.slice(0, idx).filter((m) => m.role === "user").pop();
    const assistantMsg = messages[idx];
    if (!prevUser || !assistantMsg || assistantMsg.role !== "assistant") return;
    setLoadingExplainIndex(idx);
    try {
      const res = await fetch("/api/soc-copilot/explain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userMessage: prevUser.content,
          assistantSummary: assistantMsg.content,
        }),
      });
      const data = await res.json();
      setExplanationByIndex((prev) => ({ ...prev, [idx]: data.explanation ?? "Could not load explanation." }));
    } catch {
      setExplanationByIndex((prev) => ({ ...prev, [idx]: "Network error." }));
    } finally {
      setLoadingExplainIndex(null);
    }
  };

  const handleSampleIncident = (incident: Incident) => {
    if (isThinking) return;

    // Toggle behaviour: clicking the same incident again closes it.
    if (activeIncident && activeIncident.id === incident.id) {
      setActiveIncident(null);
      setLastTriageResult(null);
      setInvestigationTimeline(null);
      setPlaybookRunAt(null);
      setReportMarkdown(null);
      setSimilarIncidents(null);
      return;
    }

    const updatedIncident: Incident = {
      ...incident,
      status: "Under Review",
      createdAt: incident.createdAt ?? new Date().toISOString(),
    };
    setActiveIncident(updatedIncident);
    addIncidentToQueue(updatedIncident);

    const userMessage: ChatMessage = {
      role: "user",
      content: updatedIncident.summary,
    };
    const nextMessages = [...messages, userMessage];
    setMessages(nextMessages);
    triageWithMessages(nextMessages);
  };

  const handleAnalyzeInTriage = () => {
    if (!simulateData || isThinking) return;
    const alertText = simulateData.alerts.join("\n\n");
    const userMessage: ChatMessage = { role: "user", content: alertText };
    const nextMessages = [...messages, userMessage];
    const simIncident: Incident = {
      id: `sim-${Date.now()}`,
      title: simulateData.title,
      summary: alertText,
      severity: "Unknown",
      source: "Attack Simulation",
      status: "Under Review",
      createdAt: new Date().toISOString(),
    };
    setMode("triage");
    setActiveIncident(simIncident);
    addIncidentToQueue(simIncident);
    setMessages(nextMessages);
    setInvestigationTimeline(simulateData.timeline);
    triageWithMessages(nextMessages);
  };

  const getHuntQueryFromIncident = (): string => {
    if (!activeIncident) return "";
    const s = (activeIncident.summary + " " + activeIncident.title).toLowerCase();
    if (s.includes("powershell") || s.includes("encoded") || s.includes("script"))
      return "Show all PowerShell executions with encoded or suspicious commands in the last 24 hours";
    if (s.includes("impossible travel") || s.includes("sign-in") || s.includes("login") || s.includes("signin"))
      return "Show all suspicious sign-ins and impossible travel events in the last 24 hours";
    if (s.includes("phishing") || s.includes("email") || s.includes("clicked"))
      return "Show users who clicked links in suspicious emails in the last 7 days";
    if (s.includes("malware") || s.includes("edr") || s.includes("c2") || s.includes("host"))
      return "Show hosts with suspicious process execution and outbound connections in the last 24 hours";
    if (s.includes("mfa") || s.includes("2fa") || s.includes("credential"))
      return "Show MFA changes and credential modifications in the last 48 hours";
    return "Show related security events and anomalies for this incident type in the last 24 hours";
  };

  const handleHuntSimilarActivity = () => {
    setNlQueryInput(getHuntQueryFromIncident());
    setMode("nl-query");
    setNlQueryResult(null);
  };

  const getAffectedAssetsFromIncident = (): string[] => {
    if (!activeIncident) return [];
    const summary = activeIncident.summary;
    const assets: string[] = [];
    const emailMatch = summary.match(/[\w.-]+@[\w.-]+\.\w+/g);
    if (emailMatch) assets.push(...emailMatch);
    const hostMatch = summary.match(/(?:WORKSTATION|HOST|SERVER|PC)-[\w\d-]+/gi);
    if (hostMatch) assets.push(...hostMatch);
    if (assets.length === 0) assets.push("See incident summary for entities");
    return [...new Set(assets)];
  };

  const extractIndicatorsFromLogs = (raw: string): { ips: string[]; emails: string[]; hostnames: string[]; suspicious: string[] } => {
    const ips = [...new Set((raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []))];
    const emails = [...new Set((raw.match(/[\w.-]+@[\w.-]+\.\w+/g) ?? []))];
    const hostnames = [...new Set((raw.match(/(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/gi) ?? []).filter((h) => !emails.some((e) => e.includes(h))))];
    const keywords = ["powershell", "encoded", "c2", "malware", "phishing", "login failed", "suspicious", "outbound", "executed", "failed", "blocked", "alert"];
    const lower = raw.toLowerCase();
    const suspicious = keywords.filter((k) => lower.includes(k));
    return { ips, emails, hostnames, suspicious: [...new Set(suspicious)] };
  };

  const buildIncidentSummaryFromLines = (lines: string[]): string => {
    const nonEmpty = lines.map((l) => l.trim()).filter(Boolean);
    if (nonEmpty.length === 0) return "No logs provided.";
    const lower = nonEmpty.join(" ").toLowerCase();
    const parts: string[] = [];
    if (lower.includes("login") || lower.includes("failed") || lower.includes("sign-in")) parts.push("failed logins");
    if (lower.includes("powershell") || lower.includes("encoded") || lower.includes("script")) parts.push("PowerShell execution");
    if (lower.includes("outbound") || lower.includes("connection") || lower.includes("c2") || lower.includes("domain")) parts.push("outbound network connections");
    if (lower.includes("phishing") || lower.includes("email")) parts.push("phishing or email activity");
    if (lower.includes("malware") || lower.includes("ransomware")) parts.push("malware indicators");
    if (lower.includes("mfa") || lower.includes("2fa") || lower.includes("credential")) parts.push("credential or MFA changes");
    const summary = parts.length > 0
      ? `Multiple suspicious events detected including ${parts.join(", ")}. Raw log lines: ${nonEmpty.length}.`
      : `User-submitted security logs: ${nonEmpty.length} line(s). ${nonEmpty.slice(0, 3).join("; ")}${nonEmpty.length > 3 ? "…" : ""}`;
    return summary;
  };

  const buildTimelineFromLines = (lines: string[]): { time: string; event: string }[] => {
    const nonEmpty = lines.map((l) => l.trim()).filter(Boolean);
    const timeRegex = /(\d{1,2}:\d{2}(?:\s*[AP]M)?|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2})/i;
    return nonEmpty.map((line, i) => {
      const match = line.match(timeRegex);
      const time = match ? match[1] : "—";
      const event = line.length > 80 ? line.slice(0, 77) + "…" : line;
      return { time, event };
    });
  };

  const handleAnalyzeLogs = () => {
    const raw = logIngestionInput.trim();
    if (!raw || isThinking) return;
    const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) return;
    const summary = buildIncidentSummaryFromLines(lines);
    const timeline = buildTimelineFromLines(lines);
    const indicators = extractIndicatorsFromLogs(raw);
    const indicatorNote = [
      indicators.ips.length ? `IPs: ${indicators.ips.slice(0, 5).join(", ")}${indicators.ips.length > 5 ? "…" : ""}` : "",
      indicators.emails.length ? `Emails: ${indicators.emails.slice(0, 3).join(", ")}` : "",
      indicators.hostnames.length ? `Domains/hosts: ${indicators.hostnames.slice(0, 3).join(", ")}` : "",
      indicators.suspicious.length ? `Keywords: ${indicators.suspicious.join(", ")}` : "",
    ].filter(Boolean).join(" | ");
    const fullSummary = indicatorNote ? `${summary} Extracted indicators: ${indicatorNote}` : summary;
    const userMessage: ChatMessage = { role: "user", content: fullSummary };
    const nextMessages = [...messages, userMessage];
    const newIncident: Incident = {
      id: `logs-${Date.now()}`,
      title: "User-submitted security logs",
      summary: fullSummary,
      severity: "Unknown",
      source: "Log Ingestion",
      status: "Under Review",
      createdAt: new Date().toISOString(),
    };
    setMode("triage");
    setActiveIncident(newIncident);
    addIncidentToQueue(newIncident);
    setMessages(nextMessages);
    setInvestigationTimeline(timeline);
    setReportMarkdown(null);
    triageWithMessages(nextMessages);
  };

  const handleGenerateInvestigationReport = async () => {
    if (!activeIncident) return;
    const res = await fetch("/api/soc-copilot/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incidentTitle: activeIncident.title,
        incidentSummary: activeIncident.summary,
        severity: activeIncident.severity,
        riskScore: lastTriageResult?.riskScore,
        timeline: investigationTimeline ?? [],
        actionsTaken: playbookRunAt ? [`Playbook run at ${playbookRunAt} (simulated)`] : [],
        triageSummary: messages.find((m) => m.role === "assistant" && m.content)?.content ?? "",
        mitreTechniques: lastTriageResult?.mitreTechniques ?? [],
        recommendedActions: lastTriageResult?.recommendedActions ?? [],
        affectedAssets: getAffectedAssetsFromIncident(),
      }),
    });
    const data = await res.json();
    if (data.markdown) setReportMarkdown(data.markdown);
    // Optionally mark as resolved after report generation
    if (activeIncident) {
      const resolvedStatus: IncidentStatus = "Resolved";
      setActiveIncident((prev) => (prev ? { ...prev, status: resolvedStatus } : prev));
      updateIncidentInQueue(activeIncident.id, { status: resolvedStatus });
    }
  };

  return (
    <main className="min-h-screen bg-gradient-to-b from-zinc-950 via-slate-950 to-black text-zinc-50 flex flex-col items-center py-10 px-4">
      <div className="w-full max-w-5xl space-y-8">
        <header className="space-y-3">
          <div className="inline-flex items-center gap-2 rounded-full border border-sky-500/30 bg-sky-500/5 px-3 py-1">
            <span className="h-1.5 w-1.5 rounded-full bg-sky-400" />
            <span className="text-[11px] font-mono tracking-[0.16em] text-sky-300/90">
              AI SECURITY COPILOT · ALERTS
            </span>
          </div>
          <div className="space-y-2">
            <h1 className="text-3xl md:text-4xl lg:text-[2.6rem] font-semibold tracking-tight">
              AI Copilot for Security Teams
            </h1>
            <p className="text-sm md:text-base text-zinc-400 max-w-2xl">
              Paste any security alert or incident summary and get a clear explanation,
              risk level, and recommended next steps, so everyone on the team can
              understand what is happening and what to do next.
            </p>
          </div>
        </header>

        {/* Mode tabs */}
        <div className="flex flex-wrap gap-1 border-b border-zinc-800 pb-2 mb-2">
          {(["triage", "incident-queue", "log-ingestion", "nl-query", "knowledge", "dedupe", "simulation"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                mode === m
                  ? "bg-sky-600 text-white"
                  : "bg-zinc-800/80 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200"
              }`}
            >
              {m === "triage"
                ? "Incident Investigation"
                : m === "incident-queue"
                  ? "Incident Queue"
                  : m === "log-ingestion"
                    ? "Log Ingestion"
                    : m === "nl-query"
                      ? "Threat Hunting"
                      : m === "dedupe"
                        ? "Alert Correlation"
                        : m === "simulation"
                          ? "Attack Simulation"
                          : "Knowledge"}
            </button>
          ))}
        </div>

        {/* Triage mode: Sample incident queue + chat + incident panel */}
        {mode === "triage" && (
        <>
        {/* Sample incident queue — click header to open/close, click card to triage */}
        <section className="space-y-2">
          <button
            type="button"
            onClick={() => setSampleIncidentsOpen((open) => !open)}
            className="w-full flex items-center justify-between gap-2 rounded-lg border border-zinc-800 bg-zinc-950/70 px-4 py-3 text-left hover:bg-zinc-900/80 hover:border-sky-500/30 transition-colors"
          >
            <h2 className="text-sm font-semibold text-zinc-100">
              Sample incidents
            </h2>
            <span className="text-zinc-500 text-xs font-mono">
              {sampleIncidentsOpen ? "Click to close" : "Click to open"}
            </span>
            <span className="text-zinc-400 text-sm" aria-hidden>
              {sampleIncidentsOpen ? "▼" : "▶"}
            </span>
          </button>
          {sampleIncidentsOpen && (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {SAMPLE_INCIDENTS.map((inc) => (
                <button
                  key={inc.id}
                  type="button"
                  onClick={() => handleSampleIncident(inc)}
                  disabled={isThinking}
                  className={`text-left p-3 rounded-xl border transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                    activeIncident?.id === inc.id
                      ? "border-sky-500 bg-sky-500/10"
                      : "border-zinc-800 bg-zinc-950/70 hover:bg-slate-900/80 hover:border-sky-500/40"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-sky-300/90">
                      {inc.severity}
                    </span>
                    <span className="text-[10px] font-mono text-zinc-500">
                      {inc.source}
                    </span>
                  </div>
                  <p className="text-sm font-medium text-zinc-200 mt-1 line-clamp-2">
                    {inc.title}
                  </p>
                  <p className="text-xs text-zinc-500 mt-1 line-clamp-2">
                    {inc.summary}
                  </p>
                </button>
              ))}
            </div>
          )}
        </section>

        <section className="grid md:grid-cols-[3fr,2fr] gap-4 md:gap-6 items-start">
          {/* Chat panel / incident conversation */}
          <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 shadow-lg flex flex-col min-h-[420px] max-h-[600px]">
            <div className="border-b border-zinc-800 px-4 py-3 flex items-center justify-between flex-wrap gap-2">
              <span className="text-xs font-mono text-zinc-400">
                /copilot/chat
              </span>
              {activeIncident && lastTriageResult && (
                <button
                  type="button"
                  onClick={handleHuntSimilarActivity}
                  className="text-[11px] font-medium text-sky-400 hover:text-sky-300 border border-sky-500/40 rounded-lg px-2 py-1"
                >
                  Hunt similar activity
                </button>
              )}
              <span className="text-[10px] px-2 py-1 rounded-full bg-sky-500/10 text-sky-300 border border-sky-500/30">
                {openaiConfigured === null
                  ? "…"
                  : openaiConfigured
                    ? "LLM + rules"
                    : "Rules only"}
              </span>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3 text-sm">
              {messages.map((m, idx) => (
                <div
                  key={idx}
                  className={`max-w-full md:max-w-[85%] ${
                    m.role === "user" ? "ml-auto" : "mr-auto"
                  }`}
                >
                  <div className="space-y-1.5">
                    <div
                      className={`whitespace-pre-line ${
                        m.role === "user"
                          ? "bg-amber-500/15 border border-amber-500/30 rounded-lg px-3 py-2 text-amber-50"
                          : "bg-zinc-900/80 border border-zinc-700/80 rounded-lg px-3 py-2 text-zinc-100"
                      }`}
                    >
                      {m.content}
                    </div>
                    {m.role === "assistant" && (m.severity || m.confidence !== undefined) && (
                      <div className="flex flex-wrap items-center gap-2 text-[10px] font-mono text-zinc-400">
                        {m.severity && (
                          <span className="px-2 py-0.5 rounded-full border border-zinc-700 bg-zinc-900 text-zinc-100">
                            Severity: {m.severity}
                          </span>
                        )}
                        {m.confidence !== undefined && (
                          <span className="px-2 py-0.5 rounded-full border border-zinc-700 bg-zinc-900 text-zinc-100">
                            Confidence: {(m.confidence * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                    )}
                    {m.role === "assistant" &&
                      m.recommendedActions &&
                      m.recommendedActions.length > 0 && (
                        <div className="rounded-lg border border-zinc-700/60 bg-zinc-900/60 px-3 py-2">
                          <p className="text-[11px] font-mono text-zinc-400 mb-1">
                            Recommended actions
                          </p>
                          <ul className="space-y-1 text-xs text-zinc-300">
                            {m.recommendedActions.map((act, i) => (
                              <li key={i} className="flex items-center justify-between gap-2">
                                <span>{act.label}</span>
                                <span className="flex items-center gap-1 text-[10px]">
                                  <span className="px-1.5 py-0.5 rounded-full border border-zinc-600 text-zinc-300">
                                    {act.risk} risk
                                  </span>
                                  {act.requiresApproval && (
                                    <span className="px-1.5 py-0.5 rounded-full border border-amber-600/70 text-amber-300">
                                      Needs approval
                                    </span>
                                  )}
                                </span>
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    {m.role === "assistant" &&
                      m.evidence &&
                      m.evidence.length > 0 && (
                        <details className="mt-1 mr-auto w-fit rounded-lg border border-zinc-700/60 bg-zinc-900/60 overflow-hidden">
                          <summary className="px-3 py-2 text-xs font-mono text-zinc-400 cursor-pointer hover:text-sky-300/80">
                            Evidence sources
                          </summary>
                          <ul className="px-3 py-2 border-t border-zinc-700/60 text-xs text-zinc-400 space-y-1 list-disc list-inside">
                            {m.evidence.map((e, i) => (
                              <li key={i}>{e}</li>
                            ))}
                          </ul>
                        </details>
                      )}
                    {m.role === "assistant" &&
                      (m.severity || m.recommendedActions?.length) && (
                        <div className="mt-1.5 mr-auto">
                          <button
                            type="button"
                            onClick={() =>
                              explanationByIndex[idx]
                                ? setExplanationByIndex((p) => {
                                    const next = { ...p };
                                    delete next[idx];
                                    return next;
                                  })
                                : handleExplainDecision(idx)
                            }
                            disabled={loadingExplainIndex !== null}
                            className="text-[11px] font-mono text-sky-400 hover:text-sky-300 disabled:opacity-50"
                          >
                            {loadingExplainIndex === idx
                              ? "Loading…"
                              : explanationByIndex[idx]
                                ? "Hide explanation"
                                : "Explain this decision"}
                          </button>
                          {explanationByIndex[idx] && (
                            <div className="mt-1.5 rounded-lg border border-zinc-700/60 bg-zinc-900/70 px-3 py-2 text-xs text-zinc-300 whitespace-pre-line">
                              {explanationByIndex[idx]}
                            </div>
                          )}
                        </div>
                      )}
                  </div>
                </div>
              ))}
              {isThinking && (
                <div className="mr-auto bg-zinc-900/80 border border-zinc-700/80 rounded-lg px-3 py-2 text-zinc-400 text-xs font-mono">
                  Thinking like a Tier‑1 analyst…
                </div>
              )}
              <div ref={endRef} />
            </div>
            <form
              onSubmit={handleSubmit}
              className="border-t border-zinc-800 px-3 py-2 flex gap-2"
            >
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="e.g., Sentinel: impossible travel sign-in from Brazil and Germany within 30 minutes…"
                className="flex-1 bg-transparent text-sm text-zinc-100 placeholder:text-zinc-600 outline-none"
              />
              <button
                type="submit"
                disabled={isThinking || !input.trim()}
                className="px-3 py-1.5 text-xs md:text-sm rounded-md bg-amber-500 hover:bg-amber-400 text-zinc-950 font-mono font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Send
              </button>
            </form>
          </div>

          {/* Incident detail + product description */}
          <aside className="space-y-4 text-xs md:text-sm text-zinc-400">
            <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-2">
              <h2 className="text-sm font-semibold text-zinc-100">
                Incident details
              </h2>
              {activeIncident ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-medium text-zinc-100">
                      {activeIncident.title}
                    </p>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono border border-zinc-600/80 text-zinc-200">
                        {activeIncident.status}
                      </span>
                      <div className="flex gap-1">
                        {(["New", "Under Review", "Resolved"] as IncidentStatus[]).map((s) => (
                          <button
                            key={s}
                            type="button"
                            onClick={() => {
                              setActiveIncident((prev) => (prev ? { ...prev, status: s } : prev));
                              updateIncidentInQueue(activeIncident.id, { status: s });
                            }}
                            className={`px-2 py-0.5 rounded-full text-[10px] font-mono border ${
                              activeIncident.status === s
                                ? "border-sky-500/70 text-sky-300 bg-sky-500/10"
                                : "border-zinc-700 text-zinc-400 hover:border-sky-500/50 hover:text-sky-200"
                            }`}
                          >
                            {s}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                  <p className="text-xs text-zinc-400">
                    {activeIncident.summary}
                  </p>
                  <div className="flex flex-wrap gap-2 pt-1">
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-zinc-900 border border-zinc-700 text-zinc-200">
                      Source: {activeIncident.source}
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-zinc-900 border border-zinc-700 text-zinc-200">
                      Severity: {activeIncident.severity}
                    </span>
                  </div>
                  {/* Investigation context: risk explanation, MITRE, timeline, playbook */}
                  {activeIncident && lastTriageResult && (
                    <div className="pt-2 border-t border-zinc-800 space-y-3">
                      <h3 className="text-[11px] font-semibold text-zinc-200 uppercase tracking-wider">
                        Investigation context
                      </h3>
                      <div className="space-y-2">
                        <p className="text-[10px] font-mono text-zinc-500">Risk explanation</p>
                        <div className="rounded-lg border border-zinc-700/80 bg-zinc-900/60 px-3 py-2 text-xs text-zinc-300">
                          <p className="text-zinc-100 font-medium mb-1">This alert indicates a possible security incident.</p>
                          <p className="mb-1">Reasons: {lastTriageResult.mitreTechniques?.map((t) => t.name).join("; ") || "Unusual activity pattern."}</p>
                          <p>Risk level: {lastTriageResult.riskScore != null ? (lastTriageResult.riskScore >= 70 ? "High" : lastTriageResult.riskScore >= 40 ? "Medium" : "Low") : "—"}</p>
                        </div>
                      </div>
                      {similarIncidents && similarIncidents.length > 0 && (
                        <div className="space-y-2">
                          <p className="text-[10px] font-mono text-zinc-500 mb-1">
                            Similar Past Incidents
                          </p>
                          <div className="space-y-2">
                            {similarIncidents.map((inc) => (
                              <div
                                key={inc.id}
                                className="rounded-lg border border-zinc-700 bg-zinc-900/70 p-3 space-y-1"
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <p className="text-xs font-semibold text-zinc-100">
                                    {inc.title}
                                  </p>
                                  <span className="text-[10px] font-mono text-zinc-400">
                                    Risk score: {inc.riskScore}
                                  </span>
                                </div>
                                <p className="text-[11px] text-zinc-400 line-clamp-3">
                                  {inc.summary}
                                </p>
                                {inc.mitreTechniques && inc.mitreTechniques.length > 0 && (
                                  <div className="pt-1">
                                    <p className="text-[10px] font-mono text-zinc-500">
                                      MITRE techniques
                                    </p>
                                    <div className="flex flex-wrap gap-1 mt-1">
                                      {inc.mitreTechniques.map((t) => (
                                        <span
                                          key={t.id}
                                          className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-zinc-900 border border-sky-600/40 text-sky-200"
                                        >
                                          {t.id} · {t.name}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {inc.recommendedActions && inc.recommendedActions.length > 0 && (
                                  <div className="pt-1">
                                    <p className="text-[10px] font-mono text-zinc-500">
                                      Recommended actions (reference only)
                                    </p>
                                    <ul className="mt-1 space-y-0.5 text-[11px] text-zinc-300 list-disc list-inside">
                                      {inc.recommendedActions.map((a, idx) => (
                                        <li key={idx}>{a}</li>
                                      ))}
                                    </ul>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                  {lastTriageResult && (
                    <div className="space-y-2">
                      {lastTriageResult.riskScore !== undefined && (
                        <div>
                          <p className="text-[10px] font-mono text-zinc-500 mb-1">
                            Risk score
                          </p>
                          <div className="h-2 w-full rounded-full bg-zinc-800 overflow-hidden">
                            <div
                              className="h-full rounded-full bg-sky-500 transition-all"
                              style={{
                                width: `${Math.min(100, Math.max(0, lastTriageResult.riskScore))}%`,
                              }}
                            />
                          </div>
                          <span className="text-[10px] font-mono text-zinc-400">
                            {lastTriageResult.riskScore}/100
                          </span>
                        </div>
                      )}
                      {lastTriageResult.mitreTechniques &&
                        lastTriageResult.mitreTechniques.length > 0 && (
                          <div>
                            <p className="text-[10px] font-mono text-zinc-500 mb-1">
                              MITRE ATT&CK
                            </p>
                            <div className="flex flex-wrap gap-1">
                              {lastTriageResult.mitreTechniques.map((t) => (
                                <span
                                  key={t.id}
                                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-900 border border-sky-600/50 text-sky-200"
                                  title={t.name}
                                >
                                  {t.id} · {t.name}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                    </div>
                  )}
                  {investigationTimeline && investigationTimeline.length > 0 && (
                    <div className="pt-2 border-t border-zinc-800 space-y-1">
                      <p className="text-[10px] font-mono text-zinc-500 mb-2">
                        Timeline of events
                      </p>
                      <div className="relative pl-3 border-l-2 border-sky-600/40 space-y-2">
                        {investigationTimeline.map((e, i) => (
                          <div key={i} className="relative -left-[11px] flex items-start gap-2">
                            <span className="h-2 w-2 rounded-full bg-sky-500 shrink-0 mt-1.5" />
                            <div>
                              <span className="text-[10px] font-mono text-sky-300/90">
                                {e.time}
                              </span>
                              <p className="text-xs text-zinc-300">{e.event}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {investigationTimeline && investigationTimeline.length > 0 && (
                    <div className="pt-2 border-t border-zinc-800 space-y-2">
                      <p className="text-[10px] font-mono text-zinc-500">Attack graph</p>
                      <div className="flex flex-col items-center gap-0">
                        {["Source", ...investigationTimeline.map((e) => e.event)].map((label, i) => (
                          <div key={i} className="flex flex-col items-center">
                            <div className="rounded-lg border border-sky-600/50 bg-zinc-900 px-2 py-1.5 text-[10px] text-sky-200 max-w-[180px] text-center truncate" title={label}>
                              {label.length > 28 ? label.slice(0, 26) + "…" : label}
                            </div>
                            {i < investigationTimeline.length && (
                              <div className="w-0.5 h-3 bg-sky-500/50" />
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  {lastTriageResult?.recommendedActions &&
                    lastTriageResult.recommendedActions.length > 0 && (
                      <div className="pt-2 border-t border-zinc-800">
                        <p className="text-[10px] font-mono text-zinc-500 mb-2">
                          Recommended playbook actions
                        </p>
                        {playbookRunAt ? (
                          <div className="text-xs text-emerald-400/90">
                            Executed at {playbookRunAt} (simulated). In production, steps would run via Microsoft Graph / EDR APIs.
                          </div>
                        ) : (
                          <button
                            type="button"
                            onClick={() =>
                              setPlaybookRunAt(
                                new Date().toLocaleTimeString("en-US", {
                                  hour: "2-digit",
                                  minute: "2-digit",
                                }),
                              )
                            }
                            className="w-full px-3 py-2 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-xs font-mono hover:bg-sky-500/20 transition-colors"
                          >
                            Run playbook (simulated)
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                  )}
                  {/* Investigation report */}
                  {activeIncident && (
                    <div className="pt-2 border-t border-zinc-800">
                      <p className="text-[10px] font-mono text-zinc-500 mb-2">Investigation Report</p>
                      <button
                        type="button"
                        onClick={handleGenerateInvestigationReport}
                        className="w-full px-3 py-2 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-xs font-medium hover:bg-sky-500/20"
                      >
                        Generate Investigation Report
                      </button>
                      {reportMarkdown && (
                        <div className="mt-2 rounded-lg border border-zinc-700 bg-zinc-900/90 p-3 max-h-64 overflow-y-auto space-y-2">
                          <h4 className="text-xs font-semibold text-zinc-200">Report</h4>
                          <pre className="text-[10px] text-zinc-300 whitespace-pre-wrap font-mono leading-relaxed">{reportMarkdown}</pre>
                          <button
                            type="button"
                            onClick={() => navigator.clipboard.writeText(reportMarkdown ?? "")}
                            className="text-[10px] text-sky-400 hover:text-sky-300 font-medium"
                          >
                            Copy to clipboard
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-xs text-zinc-500">
                  Select a sample incident above or paste an alert/incident
                  summary into the chat to see a full triage view here.
                </p>
              )}
            </div>
            {/* Threat intel lookup */}
            <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-2">
              <h2 className="text-sm font-semibold text-zinc-100">Threat intel lookup</h2>
              <p className="text-[10px] text-zinc-500">IP, domain, or hash (mock VirusTotal/AbuseIPDB)</p>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={threatIntelIoc}
                  onChange={(e) => setThreatIntelIoc(e.target.value)}
                  placeholder="e.g. 185.220.101.45 or evil.com"
                  className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-2 py-1.5 text-xs text-zinc-100 placeholder:text-zinc-500"
                />
                <button
                  type="button"
                  onClick={async () => {
                    if (!threatIntelIoc.trim()) return;
                    setThreatIntelResult(null);
                    const res = await fetch("/api/soc-copilot/threat-intel", {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ ioc: threatIntelIoc }),
                    });
                    const data = await res.json();
                    if (data.reputation) setThreatIntelResult({ ioc: data.ioc, reputation: data.reputation, country: data.country, association: data.association });
                  }}
                  className="px-2 py-1.5 rounded-lg bg-sky-600 text-white text-xs font-medium hover:bg-sky-500"
                >
                  Lookup
                </button>
              </div>
              {threatIntelResult && (
                <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-2 text-xs space-y-1">
                  <p><span className="text-zinc-500">Reputation:</span> <span className={threatIntelResult.reputation === "Malicious" ? "text-red-400" : threatIntelResult.reputation === "Suspicious" ? "text-amber-400" : "text-zinc-300"}>{threatIntelResult.reputation}</span></p>
                  {threatIntelResult.country && <p><span className="text-zinc-500">Country:</span> {threatIntelResult.country}</p>}
                  {threatIntelResult.association && <p><span className="text-zinc-500">Association:</span> {threatIntelResult.association}</p>}
                </div>
              )}
            </div>
            <div className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-2">
              <h2 className="text-sm font-semibold text-zinc-100">
                Roadmap (product-level)
              </h2>
              <ul className="list-disc list-inside space-y-1">
                <li>Direct connectors to Sentinel, Splunk, and CrowdStrike.</li>
                <li>Evidence panel with exact logs and artifacts per decision.</li>
                <li>
                  Human-in-the-loop automation for isolation, sign-out, and
                  quarantine.
                </li>
              </ul>
            </div>
          </aside>
        </section>
        </>
        )}

        {/* Incident Queue dashboard */}
        {mode === "incident-queue" && (
          <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-4">
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-sm font-semibold text-zinc-100">Incident Queue</h2>
              <span className="text-[11px] font-mono text-zinc-500">
                Total: {incidentQueue.length}
              </span>
            </div>
            {incidentQueue.length === 0 ? (
              <p className="text-xs text-zinc-500">
                No incidents yet. Use Attack Simulation, Log Ingestion, or Alert Correlation to create incidents.
              </p>
            ) : (
              <div className="rounded-xl border border-zinc-800 bg-zinc-950/80 overflow-hidden">
                <div className="grid grid-cols-6 gap-2 px-3 py-2 text-[11px] font-mono text-zinc-500 border-b border-zinc-800">
                  <span>ID</span>
                  <span>Title</span>
                  <span>Severity</span>
                  <span>Source</span>
                  <span>Status</span>
                  <span className="text-right">Actions</span>
                </div>
                <div className="divide-y divide-zinc-800">
                  {incidentQueue.map((inc) => {
                    const sevColor =
                      inc.severity === "High" || inc.severity === "Critical"
                        ? "text-red-400 border-red-500/50 bg-red-500/10"
                        : inc.severity === "Medium"
                          ? "text-amber-300 border-amber-500/50 bg-amber-500/10"
                          : "text-emerald-300 border-emerald-500/50 bg-emerald-500/10";
                    return (
                      <div
                        key={inc.id}
                        className="grid grid-cols-6 gap-2 px-3 py-2 items-center text-xs text-zinc-200"
                      >
                        <span className="truncate text-[11px] font-mono text-zinc-500">
                          {inc.id}
                        </span>
                        <span className="truncate">{inc.title}</span>
                        <span>
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-mono border ${sevColor}`}
                          >
                            {inc.severity}
                          </span>
                        </span>
                        <span className="truncate text-[11px] font-mono text-zinc-400">
                          {inc.source}
                        </span>
                        <span className="text-[11px] font-mono text-zinc-300">
                          {inc.status}
                        </span>
                        <span className="flex justify-end">
                          <button
                            type="button"
                            onClick={() => {
                              const summaryMessage: ChatMessage = {
                                role: "user",
                                content: inc.summary,
                              };
                              const nextMessages = [...messages, summaryMessage];
                              setMessages(nextMessages);
                              setActiveIncident(inc);
                              setLastTriageResult(null);
                              setInvestigationTimeline(null);
                              setReportMarkdown(null);
                              setMode("triage");
                              triageWithMessages(nextMessages);
                            }}
                            className="px-3 py-1 rounded-lg border border-sky-500/50 bg-sky-500/10 text-[11px] font-mono text-sky-200 hover:bg-sky-500/20"
                          >
                            Open Investigation
                          </button>
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </section>
        )}

        {/* Log Ingestion mode */}
        {mode === "log-ingestion" && (
          <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-4">
            <h2 className="text-sm font-semibold text-zinc-100">Log Ingestion</h2>
            <p className="text-xs text-zinc-400">
              Paste raw security alerts or logs below. Each line is treated as an alert. Click &quot;Analyze Logs&quot; to convert them into an incident and run triage.
            </p>
            <label className="block text-[11px] font-medium text-zinc-400">Paste alerts or security logs</label>
            <textarea
              value={logIngestionInput}
              onChange={(e) => setLogIngestionInput(e.target.value)}
              placeholder={`User login failed from 185.23.44.1\nPowerShell executed encoded command\nOutbound connection to suspicious domain`}
              rows={10}
              className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 resize-y font-mono"
            />
            <button
              type="button"
              onClick={handleAnalyzeLogs}
              disabled={!logIngestionInput.trim() || isThinking}
              className="px-4 py-2 rounded-lg bg-sky-600 text-white text-sm font-medium hover:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Analyze Logs
            </button>
          </section>
        )}

        {/* Threat Hunting (NL Query) mode */}
        {mode === "nl-query" && (
          <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-4">
            <h2 className="text-sm font-semibold text-zinc-100">Threat Hunting</h2>
            <p className="text-xs text-zinc-400">Describe what you want to find in plain English; get KQL (Sentinel) and SPL (Splunk) detection queries.</p>
            <div className="flex gap-2">
              <input
                type="text"
                value={nlQueryInput}
                onChange={(e) => setNlQueryInput(e.target.value)}
                placeholder="e.g. Show all suspicious logins today"
                className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500"
              />
              <button
                type="button"
                onClick={async () => {
                  if (!nlQueryInput.trim()) return;
                  setNlQueryResult(null);
                  const res = await fetch("/api/soc-copilot/nl-query", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ query: nlQueryInput }),
                  });
                  const data = await res.json();
                  if (data.kql != null) setNlQueryResult({ kql: data.kql, spl: data.spl ?? "" });
                }}
                className="px-4 py-2 rounded-lg bg-sky-600 text-white text-sm font-medium hover:bg-sky-500"
              >
                Generate
              </button>
            </div>
            {nlQueryResult && (
              <div className="grid md:grid-cols-2 gap-4">
                <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-3">
                  <p className="text-[10px] font-mono text-sky-400 mb-2">KQL (Microsoft Sentinel)</p>
                  <pre className="text-xs text-zinc-300 whitespace-pre-wrap font-mono">{nlQueryResult.kql}</pre>
                </div>
                <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-3">
                  <p className="text-[10px] font-mono text-amber-400 mb-2">SPL (Splunk)</p>
                  <pre className="text-xs text-zinc-300 whitespace-pre-wrap font-mono">{nlQueryResult.spl}</pre>
                </div>
              </div>
            )}
          </section>
        )}

        {/* Knowledge mode */}
        {mode === "knowledge" && (
          <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-4">
            <h2 className="text-sm font-semibold text-zinc-100">SOC knowledge assistant</h2>
            <p className="text-xs text-zinc-400">Ask about alert types, investigation steps, and SOC concepts.</p>
            <div className="flex gap-2">
              <input
                type="text"
                value={knowledgeInput}
                onChange={(e) => setKnowledgeInput(e.target.value)}
                placeholder="e.g. What does Impossible travel alert mean?"
                className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500"
              />
              <button
                type="button"
                onClick={async () => {
                  if (!knowledgeInput.trim()) return;
                  setKnowledgeAnswer(null);
                  const res = await fetch("/api/soc-copilot/knowledge", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ question: knowledgeInput }),
                  });
                  const data = await res.json();
                  if (data.answer) setKnowledgeAnswer(data.answer);
                }}
                className="px-4 py-2 rounded-lg bg-sky-600 text-white text-sm font-medium hover:bg-sky-500"
              >
                Ask
              </button>
            </div>
            {knowledgeAnswer && (
              <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-3 text-sm text-zinc-300 whitespace-pre-line">
                {knowledgeAnswer}
              </div>
            )}
          </section>
        )}

        {/* Alert Correlation (Dedupe) mode */}
        {mode === "dedupe" && (
          <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-4">
            <h2 className="text-sm font-semibold text-zinc-100">Alert Correlation</h2>
            <p className="text-xs text-zinc-400">Paste multiple alerts (one per line); the copilot groups them into a single incident.</p>
            <textarea
              value={dedupeAlerts}
              onChange={(e) => setDedupeAlerts(e.target.value)}
              placeholder={"Alert 1: Suspicious login\nAlert 2: Impossible travel\nAlert 3: MFA change"}
              rows={5}
              className="w-full bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 resize-y"
            />
            <button
              type="button"
              onClick={async () => {
                const lines = dedupeAlerts.trim().split("\n").filter(Boolean);
                if (lines.length === 0) return;
                setDedupeResult(null);
                const res = await fetch("/api/soc-copilot/dedupe", {
                  method: "POST",
                  headers: { "Content-Type": "application/json" },
                  body: JSON.stringify({ alerts: lines }),
                });
                const data = await res.json();
                if (data.incidentTitle) setDedupeResult({ incidentTitle: data.incidentTitle, summary: data.summary, count: data.count ?? lines.length });
              }}
              className="px-4 py-2 rounded-lg bg-sky-600 text-white text-sm font-medium hover:bg-sky-500"
            >
              Group alerts
            </button>
            {dedupeResult && (
              <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-3 space-y-2">
                <p className="text-sm font-medium text-zinc-100">{dedupeResult.incidentTitle}</p>
                <p className="text-xs text-zinc-400">{dedupeResult.summary}</p>
                <span className="text-[10px] font-mono text-zinc-500">{dedupeResult.count} alerts grouped</span>
              </div>
            )}
          </section>
        )}

        {/* Attack Simulation mode */}
        {mode === "simulation" && (
          <section className="rounded-2xl border border-zinc-800 bg-zinc-950/70 p-4 space-y-4">
            <h2 className="text-sm font-semibold text-zinc-100">Attack Simulation</h2>
            <p className="text-xs text-zinc-400">Run a preset scenario to practice investigation. Use &quot;Analyze in Triage&quot; to send the scenario into Incident Investigation.</p>
            <div className="flex flex-wrap gap-2">
              {["phishing", "credential_theft", "malware"].map((scenario) => (
                <button
                  key={scenario}
                  type="button"
                  onClick={async () => {
                    const res = await fetch(`/api/soc-copilot/simulate?scenario=${scenario}`);
                    const data = await res.json();
                    setSimulateData({ title: data.title, alerts: data.alerts ?? [], timeline: data.timeline ?? [] });
                  }}
                  className="px-3 py-2 rounded-lg border border-zinc-600 bg-zinc-800 text-zinc-200 text-xs font-medium hover:bg-zinc-700 hover:border-sky-500/50"
                >
                  {scenario.replace("_", " ")}
                </button>
              ))}
            </div>
            {simulateData && (
              <>
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-3">
                    <p className="text-[10px] font-mono text-zinc-500 mb-2">Simulated alerts</p>
                    <ul className="space-y-1 text-xs text-zinc-300">
                      {simulateData.alerts.map((a, i) => (
                        <li key={i} className="list-disc list-inside">{a}</li>
                      ))}
                    </ul>
                  </div>
                  <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-3">
                    <p className="text-[10px] font-mono text-zinc-500 mb-2">Timeline</p>
                    <div className="relative pl-3 border-l-2 border-sky-600/40 space-y-2">
                      {simulateData.timeline.map((e, i) => (
                        <div key={i} className="relative -left-[11px] flex items-start gap-2">
                          <span className="h-2 w-2 rounded-full bg-sky-500 shrink-0 mt-1.5" />
                          <div>
                            <span className="text-[10px] font-mono text-sky-300/90">{e.time}</span>
                            <p className="text-xs text-zinc-300">{e.event}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleAnalyzeInTriage}
                  disabled={isThinking}
                  className="w-full md:w-auto px-4 py-2 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-sm font-medium hover:bg-sky-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Analyze in Triage
                </button>
              </>
            )}
          </section>
        )}
      </div>
    </main>
  );
}

