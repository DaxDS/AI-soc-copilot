"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  NodeTypes,
  Edge,
  Node,
} from "reactflow";
import "reactflow/dist/style.css";

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

type AttackNodeType = "user" | "host" | "ip" | "process" | "file" | "event";

type RiskLevel = "Critical" | "High" | "Medium" | "Informational";

type AttackGraphNodeData = {
  label: string;
  type: AttackNodeType;
  risk: RiskLevel;
  mitre?: MitreTechnique[];
  evidence?: string;
  raw?: string;
  entity?: string;
  stage?: AttackStageId;
};

type AttackGraphNode = Node<AttackGraphNodeData>;

type AttackGraphEdge = Edge;

type AttackStageId =
  | "initial-access"
  | "execution"
  | "persistence"
  | "credential-access"
  | "lateral-movement"
  | "impact"
  | "priv-esc"
  | "command-and-control"
  | "exfiltration";

type AttackStage = {
  id: AttackStageId;
  label: string;
  evidence: string[];
  nodeIds: string[];
};

type InvestigationTimelineEvent = { time: string; event: string; rawEvidence?: string };

type InvestigationIndicators = {
  ips: string[];
  domains: string[];
  emails: string[];
  processes: string[];
  hosts: string[];
  files: string[];
};

type InvestigationContext = {
  incidentId: string;
  riskScore: number;
  severity: "Low" | "Medium" | "High" | "Critical" | "Unknown";
  mitreTechniques: MitreTechnique[];
  attackStages: AttackStage[];
  indicators: InvestigationIndicators;
  timeline: InvestigationTimelineEvent[];
  recommendedActions: {
    label: string;
    risk: "Low" | "Medium" | "High";
    requiresApproval: boolean;
  }[];
};

type SimilarIncident = {
  id: string;
  title: string;
  summary: string;
  mitreTechniques: MitreTechnique[];
  riskScore: number;
  recommendedActions: string[];
};

/** Stored incident with attack stages for similar-attack-chain comparison (≥3 overlapping stages = similar). */
type PastIncidentStages = {
  id: string;
  stages: string[];
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

/** Strict mapping: severity is derived only from risk score. 0–30 Low, 31–60 Medium, 61–80 High, 81–100 Critical. */
function getSeverityFromRisk(score: number): "Low" | "Medium" | "High" | "Critical" {
  const s = Math.max(0, Math.min(100, score));
  if (s <= 30) return "Low";
  if (s <= 60) return "Medium";
  if (s <= 80) return "High";
  return "Critical";
}

function parseTimeForSort(timeStr: string): number {
  if (!timeStr || timeStr === "—") return 0;
  const t = timeStr.trim();
  const iso = t.match(/(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (iso) {
    const [, y, mo, d, h, mi, s] = iso;
    return new Date(
      parseInt(y!, 10),
      parseInt(mo!, 10) - 1,
      parseInt(d!, 10),
      parseInt(h!, 10),
      parseInt(mi!, 10),
      parseInt(s ?? "0", 10),
    ).getTime();
  }
  const timeOnly = t.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AP]M))?/i);
  if (timeOnly) {
    let [, h, mi, s, ampm] = timeOnly;
    let hour = parseInt(h!, 10);
    if (ampm) {
      if (ampm.toUpperCase() === "PM" && hour < 12) hour += 12;
      if (ampm.toUpperCase() === "AM" && hour === 12) hour = 0;
    }
    return hour * 3600000 + parseInt(mi!, 10) * 60000 + parseInt(s ?? "0", 10) * 1000;
  }
  return 0;
}

function sortTimelineByTime(
  events: InvestigationTimelineEvent[],
): InvestigationTimelineEvent[] {
  return [...events].sort(
    (a, b) => parseTimeForSort(a.time) - parseTimeForSort(b.time),
  );
}

/** Split incident text into one log entry per timestamp so each becomes a separate timeline event. */
function splitLogEntriesByTimestamp(incidentText: string): string[] {
  const trimmed = incidentText.trim();
  if (!trimmed) return [];
  const timestampPattern = /(?=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/;
  const entries = trimmed
    .split(timestampPattern)
    .map((s) => s.trim())
    .filter(Boolean);
  return entries;
}

/** Regex-based IOC extraction: IPs, domains, emails, process names, hostnames, file names. */
function extractIndicatorsFromText(text: string): InvestigationIndicators {
  const emails = [...new Set(text.match(/[\w.-]+@[\w.-]+\.\w+/g) ?? [])];
  const ips = [...new Set(text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? [])];
  const domains = [
    ...new Set(
      (text.match(
        /(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}/gi,
      ) ?? []).filter((d) => !emails.some((e) => e.includes(d))),
    ),
  ];
  const processNames = [
    ...new Set(
      text.match(
        /\b(?:powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|winword|excel|notepad|explorer|svchost|conhost)\.exe\b/gi,
      ) ?? [],
    ),
  ].map((p) => p.toLowerCase());
  const additionalProcesses = [...new Set(text.match(/\b[\w.-]+\.exe\b/gi) ?? [])].map((p) => p.toLowerCase());
  const processes = [...new Set([...processNames, ...additionalProcesses])];
  const hostnames = [
    ...new Set(
      text.match(
        /\b(?:WORKSTATION|PC|SERVER|HOST|DESKTOP|LAPTOP|DC|AD)-[A-Z0-9-]+\b/gi,
      ) ?? [],
    ),
  ].map((h) => h.toUpperCase());
  const fileNames = [
    ...new Set(
      text.match(
        /\b[\w.-]+\.(?:exe|dll|docm|doc|xls|xlsm|bat|ps1|vbs|js|scr|msi|zip)\b/gi,
      ) ?? [],
    ),
  ];
  const fileHashes = [...new Set(text.match(/\b[A-Fa-f0-9]{32,64}\b/g) ?? [])];
  const files = [...new Set([...fileNames, ...fileHashes])];
  return { ips, domains, emails, processes, hosts: hostnames, files };
}

/** Canonical MITRE attack flow order: Initial Access → Execution → Persistence → Lateral Movement → Impact → Command & Control → … */
const ATTACK_STAGE_ORDER: AttackStageId[] = [
  "initial-access",
  "execution",
  "persistence",
  "credential-access",
  "lateral-movement",
  "impact",
  "priv-esc",
  "command-and-control",
  "exfiltration",
];

function sortStagesByChainOrder(stages: AttackStage[]): AttackStage[] {
  return [...stages].sort(
    (a, b) =>
      ATTACK_STAGE_ORDER.indexOf(a.id) - ATTACK_STAGE_ORDER.indexOf(b.id),
  );
}

/**
 * Keyword-based stage classification from timeline events.
 * Maps event text to MITRE-style attack stages (Initial Access → Execution → … → Exfiltration).
 */
function detectStageForEvent(lowerEvent: string): AttackStageId | undefined {
  // Credential Access (check before generic "login" in Initial Access): entered credentials, credential harvesting, login from new IP
  if (
    lowerEvent.includes("entered credentials") ||
    lowerEvent.includes("credential harvesting") ||
    lowerEvent.includes("login from new ip")
  ) {
    return "credential-access";
  }
  if (lowerEvent.includes("credential") && (lowerEvent.includes("dump") || lowerEvent.includes("lsass"))) {
    return "credential-access";
  }

  // Initial Access: email, phishing, link clicked, attachment
  const isInitialAccess =
    lowerEvent.includes("phishing") ||
    lowerEvent.includes("email received") ||
    (lowerEvent.includes("email") && (lowerEvent.includes("received") || lowerEvent.includes("from") || lowerEvent.includes("clicked"))) ||
    lowerEvent.includes("link clicked") ||
    lowerEvent.includes("clicked link") ||
    (lowerEvent.includes("clicked") && lowerEvent.includes("link")) ||
    lowerEvent.includes("attachment") ||
    lowerEvent.includes("impossible travel") ||
    lowerEvent.includes("login") ||
    lowerEvent.includes("sign-in") ||
    lowerEvent.includes("signin");
  if (isInitialAccess) return "initial-access";

  // Execution: powershell, encoded command, script, payload download, file created, launched process
  const isExecution =
    lowerEvent.includes("powershell") ||
    lowerEvent.includes("powershell.exe") ||
    lowerEvent.includes("encoded command") ||
    (lowerEvent.includes("encoded") && lowerEvent.includes("command")) ||
    (lowerEvent.includes("launched") && (lowerEvent.includes("powershell") || lowerEvent.includes("cmd"))) ||
    lowerEvent.includes("script execution") ||
    (lowerEvent.includes("payload") && lowerEvent.includes("download")) ||
    lowerEvent.includes("payload downloaded") ||
    lowerEvent.includes("downloaded payload") ||
    (lowerEvent.includes("downloaded") && lowerEvent.includes("payload")) ||
    lowerEvent.includes("file created") ||
    (lowerEvent.includes("file") && lowerEvent.includes("created")) ||
    lowerEvent.includes("file creation") ||
    (lowerEvent.includes("browser downloaded") || (lowerEvent.includes("downloaded") && lowerEvent.includes("file"))) ||
    lowerEvent.includes("cmd") ||
    lowerEvent.includes("script") ||
    lowerEvent.includes("malware execution") ||
    lowerEvent.includes("malware");
  if (isExecution) return "execution";

  // Persistence: scheduled task, inbox rule, forwarding rule, new MFA device, registry, startup
  if (
    lowerEvent.includes("scheduled task") ||
    lowerEvent.includes("inbox rule") ||
    lowerEvent.includes("forwarding rule") ||
    lowerEvent.includes("new mfa device") ||
    lowerEvent.includes("registry run key") ||
    lowerEvent.includes("startup folder") ||
    lowerEvent.includes("persistence") ||
    lowerEvent.includes("registry") ||
    lowerEvent.includes("run key")
  ) {
    return "persistence";
  }
  if (
    lowerEvent.includes("smb") ||
    lowerEvent.includes("rdp") ||
    lowerEvent.includes("winrm") ||
    lowerEvent.includes("lateral")
  ) {
    return "lateral-movement";
  }
  // Impact: ransomware / data encrypted for impact (T1486)
  if (
    lowerEvent.includes("files encrypted") ||
    lowerEvent.includes("ransom note") ||
    lowerEvent.includes("data encrypted")
  ) {
    return "impact";
  }
  if (
    (lowerEvent.includes("privilege") && lowerEvent.includes("escalation")) ||
    lowerEvent.includes("elevation") ||
    lowerEvent.includes("admin privileges") ||
    lowerEvent.includes("domain admin")
  ) {
    return "priv-esc";
  }
  // Command & Control: outbound connection, external IP, beacon, C2 (before generic "download")
  const isC2 =
    lowerEvent.includes("outbound connection") ||
    lowerEvent.includes("outbound") ||
    (lowerEvent.includes("connection") && (lowerEvent.includes(" to ") || lowerEvent.includes(" from "))) ||
    lowerEvent.includes("external ip") ||
    lowerEvent.includes("external connection") ||
    lowerEvent.includes("beacon") ||
    lowerEvent.includes("c2") ||
    lowerEvent.includes("command and control") ||
    (lowerEvent.includes("connection") && /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lowerEvent));
  if (isC2) return "command-and-control";

  // Exfiltration: files downloaded, data export, sensitive documents, sharepoint, backup, etc.
  if (
    lowerEvent.includes("files downloaded") ||
    lowerEvent.includes("data export") ||
    lowerEvent.includes("sensitive documents downloaded") ||
    lowerEvent.includes("download") ||
    lowerEvent.includes("exfil") ||
    lowerEvent.includes("sharepoint") ||
    lowerEvent.includes("database export") ||
    lowerEvent.includes("backup") ||
    lowerEvent.includes("large upload") ||
    lowerEvent.includes("exported")
  ) {
    return "exfiltration";
  }
  return undefined;
}

function computeRiskScoreFromText(text: string): number {
  const lower = text.toLowerCase();
  let score = 0;

  // Phishing / email received / initial access
  if (
    lower.includes("phishing email") ||
    (lower.includes("phishing") && lower.includes("email")) ||
    lower.includes("email received") ||
    (lower.includes("email") && (lower.includes("received") || lower.includes("from")))
  )
    score += 20;

  // User clicked link / attachment opened
  if (
    lower.includes("clicked link") ||
    lower.includes("link clicked") ||
    (lower.includes("clicked") && lower.includes("link")) ||
    (lower.includes("link") && lower.includes("email"))
  )
    score += 10;

  // Encoded PowerShell / script execution
  if (
    lower.includes("encodedcommand") ||
    lower.includes("encoded command") ||
    (lower.includes("powershell") && lower.includes("encoded")) ||
    (lower.includes("powershell") && (lower.includes("launched") || lower.includes("executed"))) ||
    lower.includes("powershell.exe")
  )
    score += 25;

  // Malware / payload / file download
  if (
    lower.includes("malware download") ||
    lower.includes("payload download") ||
    (lower.includes("downloaded") && (lower.includes("payload") || lower.includes(".exe"))) ||
    (lower.includes("download") && (lower.includes("payload") || lower.includes("file"))) ||
    lower.includes("browser downloaded") ||
    lower.includes("downloaded file")
  )
    score += 20;

  // Outbound connection / external IP / C2
  if (
    lower.includes("outbound connection") ||
    (lower.includes("outbound") && lower.match(/\b(?:\d{1,3}\.){3}\d{1,3}/)) ||
    lower.includes("external ip") ||
    (lower.includes("connection") && lower.includes(" to ") && lower.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/))
  )
    score += 15;

  // Credential dumping
  if (
    (lower.includes("credential") && lower.includes("dump")) ||
    lower.includes("lsass") ||
    lower.includes("mimikatz")
  )
    score += 30;

  // Credential harvesting (phishing for credentials, credential theft)
  if (
    lower.includes("credential harvesting") ||
    lower.includes("credential harvest") ||
    (lower.includes("credential") && (lower.includes("harvest") || lower.includes("theft") || lower.includes("steal")))
  )
    score += 30;

  // Inbox rule persistence (mailbox rule, forwarding, persistence in email)
  if (
    lower.includes("inbox rule") ||
    lower.includes("inbox rule persistence") ||
    (lower.includes("mailbox") && lower.includes("rule")) ||
    (lower.includes("inbox") && lower.includes("rule"))
  )
    score += 25;

  // Bulk phishing / mass propagation
  if (
    lower.includes("bulk phishing") ||
    lower.includes("phishing propagation") ||
    (lower.includes("bulk") && lower.includes("phishing")) ||
    (lower.includes("mass") && lower.includes("phishing")) ||
    lower.includes("phishing campaign")
  )
    score += 25;

  // Privilege escalation
  if (
    lower.includes("privilege escalation") ||
    lower.includes("privilege elevation") ||
    lower.includes("admin privileges") ||
    lower.includes("domain admin")
  )
    score += 30;

  // Data exfiltration
  if (
    lower.includes("data exfiltration") ||
    lower.includes("exfil") ||
    lower.includes("database export") ||
    lower.includes("backup") ||
    lower.includes("large upload") ||
    lower.includes("exported")
  )
    score += 25;

  // Cap score at 100
  return Math.max(0, Math.min(100, score));
}

function buildInvestigationContext(
  incidentId: string,
  incidentSummary: string,
  severity: Incident["severity"],
  timeline: InvestigationTimelineEvent[],
  triage: {
    riskScore?: number;
    mitreTechniques?: MitreTechnique[];
    recommendedActions?: { label: string; risk: string; requiresApproval: boolean }[];
  },
): InvestigationContext {
  const textForAnalysis =
    incidentSummary +
    " " +
    timeline.map((t) => t.rawEvidence ?? `${t.time} ${t.event}`).join(" ");

  const indicators = extractIndicatorsFromText(textForAnalysis);

  const autoMitre: MitreTechnique[] = [];
  const lower = textForAnalysis.toLowerCase();
  if (lower.includes("phishing") || lower.includes("email")) {
    autoMitre.push({ id: "T1566", name: "Phishing" });
  }
  if (lower.includes("powershell") || lower.includes("cmd.exe")) {
    autoMitre.push({ id: "T1059", name: "Command and Scripting Interpreter" });
  }
  if (lower.includes("credential") || lower.includes("dump")) {
    autoMitre.push({ id: "T1003", name: "OS Credential Dumping" });
  }
  if (lower.includes("smb") || lower.includes("lateral")) {
    autoMitre.push({ id: "T1021", name: "Remote Services" });
  }
  if (lower.includes("exfil") || lower.includes("download") || lower.includes("sharepoint")) {
    autoMitre.push({ id: "T1041", name: "Exfiltration Over C2 Channel" });
  }
  // Impact: files encrypted, ransom note, data encrypted → T1486 (Data Encrypted for Impact)
  if (
    lower.includes("files encrypted") ||
    lower.includes("ransom note") ||
    lower.includes("data encrypted")
  ) {
    autoMitre.push({ id: "T1486", name: "Data Encrypted for Impact" });
  }
  // Command & Control: outbound connection, C2, beacon → T1071 (Application Layer Protocol) or T1041 (Exfiltration Over C2)
  if (
    lower.includes("outbound") ||
    lower.includes("c2") ||
    lower.includes("command and control") ||
    (lower.includes("connection") && /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower))
  ) {
    autoMitre.push({ id: "T1071", name: "Application Layer Protocol" });
    if (!autoMitre.some((t) => t.id === "T1041")) {
      autoMitre.push({ id: "T1041", name: "Exfiltration Over C2 Channel" });
    }
  }

  let mitreTechniques =
    triage.mitreTechniques && triage.mitreTechniques.length > 0
      ? triage.mitreTechniques
      : autoMitre;
  // If triage/LLM returned T1046 (Network Service Discovery) but the incident indicates C2, use C2 techniques instead
  const hasC2Indicators =
    lower.includes("outbound") ||
    lower.includes("c2") ||
    lower.includes("command and control") ||
    (lower.includes("connection") && /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(lower));
  if (hasC2Indicators && mitreTechniques.some((t) => t.id === "T1046")) {
    const withoutT1046 = mitreTechniques.filter((t) => t.id !== "T1046");
    const hasT1071 = withoutT1046.some((t) => t.id === "T1071");
    const hasT1041 = withoutT1046.some((t) => t.id === "T1041");
    mitreTechniques = [
      ...withoutT1046,
      ...(!hasT1071 ? [{ id: "T1071", name: "Application Layer Protocol" }] : []),
      ...(!hasT1041 ? [{ id: "T1041", name: "Exfiltration Over C2 Channel" }] : []),
    ];
  }

  const autoRisk = computeRiskScoreFromText(textForAnalysis);
  const riskScore = autoRisk;
  const severityFromScore: Incident["severity"] = getSeverityFromRisk(riskScore);

  const recommendedActions: InvestigationContext["recommendedActions"] =
    triage.recommendedActions && triage.recommendedActions.length > 0
      ? triage.recommendedActions.map((a) => ({
          label: a.label,
          risk: (a.risk === "Low" || a.risk === "Medium" || a.risk === "High" ? a.risk : "Low") as "Low" | "Medium" | "High",
          requiresApproval: a.requiresApproval,
        }))
      : [
          {
            label: "Review enriched context and confirm severity",
            risk: "Low",
            requiresApproval: false,
          },
        ];

  const stagesTemplate: AttackStage[] = [
    { id: "initial-access", label: "Initial Access", evidence: [], nodeIds: [] },
    { id: "execution", label: "Execution", evidence: [], nodeIds: [] },
    { id: "persistence", label: "Persistence", evidence: [], nodeIds: [] },
    { id: "credential-access", label: "Credential Access", evidence: [], nodeIds: [] },
    { id: "lateral-movement", label: "Lateral Movement", evidence: [], nodeIds: [] },
    { id: "impact", label: "Impact", evidence: [], nodeIds: [] },
    { id: "priv-esc", label: "Privilege Escalation", evidence: [], nodeIds: [] },
    { id: "command-and-control", label: "Command & Control", evidence: [], nodeIds: [] },
    { id: "exfiltration", label: "Exfiltration", evidence: [], nodeIds: [] },
  ];

  timeline.forEach((t) => {
    const stageId = detectStageForEvent((t.event || "").toLowerCase());
    if (!stageId) return;
    const stage = stagesTemplate.find((s) => s.id === stageId);
    if (!stage) return;
    stage.evidence.push(`${t.time} – ${t.event}`);
  });

  const attackStages = stagesTemplate.filter((s) => s.evidence.length > 0);

  return {
    incidentId,
    riskScore,
    severity: severityFromScore,
    mitreTechniques,
    attackStages,
    indicators,
    timeline,
    recommendedActions,
  };
}

const INITIAL_GREETING: ChatMessage = {
  role: "assistant",
  content: "Hi, I'm your AI SOC copilot. Paste an alert or incident summary and I'll triage it, enrich it, and suggest next steps.",
};

export default function Home() {
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_GREETING]);
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
    InvestigationTimelineEvent[] | null
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
  const [dedupeResult, setDedupeResult] = useState<{ incidentTitle: string; summary: string; count: number; mergedLogLines?: string[] } | null>(null);
  const [correlatedAlertsCount, setCorrelatedAlertsCount] = useState<number | null>(null);
  const [simulateData, setSimulateData] = useState<{ title: string; alerts: string[]; timeline: { time: string; event: string }[] } | null>(null);
  const [threatIntelIoc, setThreatIntelIoc] = useState("");
  const [threatIntelResult, setThreatIntelResult] = useState<{ ioc: string; reputation: string; country?: string; association?: string } | null>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [similarIncidents, setSimilarIncidents] = useState<SimilarIncident[] | null>(null);
  const [pastIncidentsWithStages, setPastIncidentsWithStages] = useState<PastIncidentStages[]>([]);
  const [attackGraphNodes, setAttackGraphNodes] = useState<AttackGraphNode[]>([]);
  const [attackGraphEdges, setAttackGraphEdges] = useState<AttackGraphEdge[]>([]);
  const [selectedAttackNode, setSelectedAttackNode] = useState<AttackGraphNode | null>(null);
  const [selectedEvidenceTimelineIndex, setSelectedEvidenceTimelineIndex] = useState<number | null>(null);
  const [attackNodeThreatIntel, setAttackNodeThreatIntel] = useState<{ ioc: string; reputation: string; country?: string; association?: string } | null>(null);
  const [attackStages, setAttackStages] = useState<AttackStage[]>([]);
  const [hoveredStageId, setHoveredStageId] = useState<AttackStageId | null>(null);
  const [investigationContext, setInvestigationContext] = useState<InvestigationContext | null>(
    null,
  );
  const [sessionCount, setSessionCount] = useState(0);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);
  const [reportPanelOpen, setReportPanelOpen] = useState(false);
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const endRef = useRef<HTMLDivElement | null>(null);

  const downloadReport = () => {
    if (!reportMarkdown) return;
    const blob = new Blob([reportMarkdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `investigation-report-${activeIncident?.title?.replace(/\s+/g, "-").slice(0, 40) ?? "report"}-${new Date().toISOString().slice(0, 10)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const addIncidentToQueue = (incident: Incident) => {
    setIncidentQueue((prev) => [incident, ...prev]);
  };

  const updateIncidentInQueue = (id: string, updates: Partial<Incident>) => {
    setIncidentQueue((prev) =>
      prev.map((inc) => (inc.id === id ? { ...inc, ...updates } : inc)),
    );
  };

  const removeFromQueue = (id: string) => {
    setIncidentQueue((prev) => prev.filter((inc) => inc.id !== id));
    if (activeIncident?.id === id) {
      resetStateForNewSession();
      setMessages([INITIAL_GREETING]);
    }
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

  const clearInvestigationState = () => {
    setInvestigationTimeline([]);
    setAttackGraphNodes([]);
    setAttackGraphEdges([]);
    setAttackStages([]);
    setInvestigationContext(null);
    setSelectedAttackNode(null);
    setSelectedEvidenceTimelineIndex(null);
    setAttackNodeThreatIntel(null);
    setHoveredStageId(null);
    setCorrelatedAlertsCount(null);
  };

  const resetStateForNewSession = () => {
    setActiveIncident(null);
    setReportMarkdown(null);
    setLastTriageResult(null);
    setSimilarIncidents(null);
    setPlaybookRunAt(null);
    setExplanationByIndex({});
    setThreatIntelResult(null);
    setAttackNodeThreatIntel(null);
    setCorrelatedAlertsCount(null);
    clearInvestigationState();
    setSessionCount((c) => c + 1);
  };

  const startNewInvestigation = () => {
    resetStateForNewSession();
    setMessages([INITIAL_GREETING]);
    void (async () => {
      try {
        const res = await fetch("/api/cases", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            title: `Ad-hoc Investigation (${new Date().toLocaleString()})`,
            summary: "",
            severity: "Unknown",
            source: "Manual",
          }),
        });
        const data = await res.json();
        if (res.ok && data?.case?.id) {
          sessionStorage.setItem("socCopilotCaseId", String(data.case.id));
        }
      } catch {
        // ignore for demo mode
      }
    })();
  };

  const similarChainCount = useMemo(() => {
    const currentLabels = attackStages.map((s) => s.label);
    if (currentLabels.length === 0) return 0;
    const currentId = activeIncident?.id ?? investigationContext?.incidentId;
    return pastIncidentsWithStages.filter(
      (p) =>
        p.id !== currentId &&
        currentLabels.filter((stage) => p.stages.includes(stage)).length >= 3,
    ).length;
  }, [attackStages, activeIncident?.id, investigationContext?.incidentId, pastIncidentsWithStages]);

  const triageWithMessages = async (
    nextMessages: ChatMessage[],
    logLines?: string[],
    incidentIdForContext?: string,
  ) => {
    setIsThinking(true);
    try {
      const caseId = sessionStorage.getItem("socCopilotCaseId") ?? "";
      const res = await fetch("/api/soc-copilot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ messages: nextMessages, caseId }),
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
      const riskScoreFromTriage = data.riskScore ?? 0;
      const severityFromRisk = getSeverityFromRisk(riskScoreFromTriage);
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: data.message ?? "No response.",
          evidence: data.evidence,
          severity: severityFromRisk,
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
          severity: severityFromRisk,
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
      const hasLogLines = Array.isArray(logLines) && logLines.length > 1;
      if (lastUserContent && hasLogLines) {
        fetch("/api/soc-copilot/investigate", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            userMessage: lastUserContent,
            logLines,
          }),
        })
          .then((r) => r.json())
          .then((d) => {
            const rawTimeline: InvestigationTimelineEvent[] = (d.timeline ?? []).map(
              (e: { time?: string; event?: string; rawEvidence?: string }) => ({
                time: e.time ?? "—",
                event: e.event ?? "",
                rawEvidence: e.rawEvidence ?? (e.time && e.event ? `${e.time} – ${e.event}` : e.event),
              }),
            );
            setInvestigationTimeline(rawTimeline);
            const ctx = buildInvestigationContext(
              incidentIdForContext ?? activeIncident?.id ?? "adhoc",
              lastUserContent,
              data.severity as Incident["severity"],
              rawTimeline,
              {
                riskScore: data.riskScore,
                mitreTechniques: data.mitreTechniques,
                recommendedActions: data.recommendedActions,
              },
            );
            setInvestigationContext(ctx);
            setAttackStages(ctx.attackStages);
            setLastTriageResult((prev) =>
              prev ? { ...prev, riskScore: ctx.riskScore } : prev,
            );
            setActiveIncident((prev) =>
              prev ? { ...prev, severity: ctx.severity } : prev,
            );
            setPastIncidentsWithStages((prev) => {
              const without = prev.filter((p) => p.id !== ctx.incidentId);
              return [...without, { id: ctx.incidentId, stages: ctx.attackStages.map((s) => s.label) }];
            });
          })
          .catch(() => {
            setInvestigationTimeline(null);
            setInvestigationContext(null);
          });
      } else {
        // For regular conversation or when there aren't real log lines, keep the attack chain empty.
        setInvestigationTimeline(null);
        setInvestigationContext(null);
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

    clearInvestigationState();
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

    const byTimestamp = splitLogEntriesByTimestamp(trimmed);
    const lines =
      byTimestamp.length > 1
        ? byTimestamp
        : trimmed.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    triageWithMessages(nextMessages, lines.length > 0 ? lines : [trimmed], newIncident.id);
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
    clearInvestigationState();

    void (async () => {
      try {
        const res = await fetch("/api/cases", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            title: updatedIncident.title,
            summary: updatedIncident.summary,
            severity: updatedIncident.severity,
            source: updatedIncident.source,
            riskScore: updatedIncident.riskScore,
          }),
        });
        const data = await res.json();
        if (res.ok && data?.case?.id) {
          sessionStorage.setItem("socCopilotCaseId", String(data.case.id));
        }
      } catch {
        // ignore for demo mode
      }
    })();

    const userMessage: ChatMessage = {
      role: "user",
      content: updatedIncident.summary,
    };
    const nextMessages = [...messages, userMessage];
    setMessages(nextMessages);
    const byTimestamp = splitLogEntriesByTimestamp(updatedIncident.summary);
    const lines =
      byTimestamp.length > 1
        ? byTimestamp
        : updatedIncident.summary.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    triageWithMessages(nextMessages, lines.length > 0 ? lines : [updatedIncident.summary], updatedIncident.id);
  };

  const handleAnalyzeInTriage = () => {
    if (!simulateData || isThinking) return;
    clearInvestigationState();
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
    const lines = simulateData.timeline.map((e) => `${e.time} ${e.event}`);
    triageWithMessages(nextMessages, lines, simIncident.id);
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
    const assets: string[] = [];
    if (investigationContext) {
      assets.push(
        ...investigationContext.indicators.emails,
        ...investigationContext.indicators.ips,
        ...investigationContext.indicators.domains,
        ...investigationContext.indicators.hosts,
        ...investigationContext.indicators.processes,
        ...investigationContext.indicators.files,
      );
    } else {
      const summary = activeIncident.summary;
      const emailMatch = summary.match(/[\w.-]+@[\w.-]+\.\w+/g);
      if (emailMatch) assets.push(...emailMatch);
      const hostMatch = summary.match(/(?:WORKSTATION|HOST|SERVER|PC)-[\w\d-]+/gi);
      if (hostMatch) assets.push(...hostMatch);
    }
    if (assets.length === 0) assets.push("See incident summary for entities");
    return [...new Set(assets)];
  };

  const extractEntitiesFromIncident = (): {
    users: string[];
    ips: string[];
    hosts: string[];
    processes: string[];
    files: string[];
  } => {
    const textParts: string[] = [];
    if (activeIncident?.summary) textParts.push(activeIncident.summary);
    if (investigationTimeline) {
      textParts.push(...investigationTimeline.map((e) => `${e.time} ${e.event}`));
    }
    const full = textParts.join(" ");
    const users = [...new Set((full.match(/[\w.-]+@[\w.-]+\.\w+/g) ?? []))];
    const ips = [...new Set((full.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) ?? []))];
    const hosts = [
      ...new Set(
        (full.match(/(?:WORKSTATION|HOST|SERVER|PC)-[\w\d-]+/gi) ?? []),
      ),
    ];
    const processes = [
      ...new Set(
        (full.match(
          /\b(?:powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe|rundll32\.exe|mshta\.exe)\b/gi,
        ) ?? []),
      ),
    ];
    const files = [
      ...new Set(
        (full.match(/\b[A-Fa-f0-9]{32,64}\b/g) ?? []),
      ),
    ];
    return { users, ips, hosts, processes, files };
  };

  const buildAttackGraph = () => {
    if (!activeIncident || !investigationTimeline || investigationTimeline.length === 0) {
      setAttackGraphNodes([]);
      setAttackGraphEdges([]);
      setSelectedAttackNode(null);
      setAttackNodeThreatIntel(null);
      setAttackStages([]);
      setHoveredStageId(null);
      return;
    }

    const entities = extractEntitiesFromIncident();

    const nodes: AttackGraphNode[] = [];
    const edges: AttackGraphEdge[] = [];

    const baseMitre = lastTriageResult?.mitreTechniques ?? [];

    const addNode = (
      id: string,
      label: string,
      type: AttackNodeType,
      risk: RiskLevel,
      stage: AttackStageId | undefined,
      extra?: Partial<AttackGraphNodeData>,
      positionIndex = 0,
    ) => {
      const x = positionIndex * 220;
      const existing = nodes.find((n) => n.id === id);
      if (existing) return existing;
      const node: AttackGraphNode = {
        id,
        position: { x, y: 0 },
        data: {
          label,
          type,
          risk,
          stage,
          mitre: extra?.mitre ?? baseMitre,
          evidence: extra?.evidence,
          raw: extra?.raw,
          entity: extra?.entity,
        },
        style: {
          borderRadius: 8,
          padding: 8,
          fontSize: 11,
          borderWidth: 1,
        },
      };
      nodes.push(node);
      return node;
    };

    const addEdge = (id: string, source: string, target: string, label?: string) => {
      edges.push({
        id,
        source,
        target,
        label,
        animated: true,
        style: { strokeWidth: 1.5 },
      });
    };

    const sourceNode = addNode(
      "source",
      activeIncident.title || "Source",
      "event",
      "Medium",
      "initial-access",
      { evidence: activeIncident.summary, raw: activeIncident.summary },
    );

    entities.users.forEach((u, idx) =>
      addNode(
        `user-${idx}`,
        u,
        "user",
        "High",
        "initial-access",
        {
          evidence: "User involved in this incident",
          entity: u,
        },
        idx,
      ),
    );
    entities.ips.forEach((ip, idx) =>
      addNode(
        `ip-${idx}`,
        ip,
        "ip",
        "High",
        "command-and-control",
        {
          evidence: "IP observed in related events",
          entity: ip,
        },
        idx + 1,
      ),
    );
    entities.hosts.forEach((h, idx) =>
      addNode(
        `host-${idx}`,
        h,
        "host",
        "High",
        "execution",
        { evidence: "Host observed in related events", entity: h },
        idx + 2,
      ),
    );
    entities.processes.forEach((p, idx) =>
      addNode(
        `proc-${idx}`,
        p,
        "process",
        "High",
        "execution",
        { evidence: "Suspicious process in incident context", entity: p },
        idx + 3,
      ),
    );

    let previousId = sourceNode.id;
    const sortedTimeline = sortTimelineByTime(investigationTimeline);
    sortedTimeline.forEach((e, index) => {
      const id = `event-${index}`;
      const risk: RiskLevel =
        e.event.toLowerCase().includes("ransomware") ||
        e.event.toLowerCase().includes("c2") ||
        e.event.toLowerCase().includes("lateral")
          ? "Critical"
          : e.event.toLowerCase().includes("download") ||
              e.event.toLowerCase().includes("login") ||
              e.event.toLowerCase().includes("mfa")
            ? "High"
            : "Medium";
      const lowerEvent = e.event.toLowerCase();
      const stage: AttackStageId | undefined = detectStageForEvent(lowerEvent);
      addNode(
        id,
        e.event,
        "event",
        risk,
        stage,
        {
          evidence: e.rawEvidence ?? `Timeline event at ${e.time}`,
          raw: e.rawEvidence ?? `${e.time} – ${e.event}`,
        },
        index + 1,
      );
      addEdge(`edge-${previousId}-${id}`, previousId, id);
      previousId = id;
    });

    entities.users.forEach((u, idx) => {
      const userId = `user-${idx}`;
      if (nodes.find((n) => n.id === userId)) {
        addEdge(`edge-source-user-${idx}`, sourceNode.id, userId, "involves user");
      }
    });
    entities.ips.forEach((ip, idx) => {
      const ipId = `ip-${idx}`;
      if (nodes.find((n) => n.id === ipId)) {
        addEdge(`edge-source-ip-${idx}`, sourceNode.id, ipId, "observed from IP");
      }
    });
    entities.hosts.forEach((h, idx) => {
      const hostId = `host-${idx}`;
      if (nodes.find((n) => n.id === hostId)) {
        addEdge(`edge-source-host-${idx}`, sourceNode.id, hostId, "host involved");
      }
    });
    entities.processes.forEach((p, idx) => {
      const procId = `proc-${idx}`;
      if (nodes.find((n) => n.id === procId)) {
        addEdge(`edge-source-proc-${idx}`, sourceNode.id, procId, "process executed");
      }
    });

    setAttackGraphNodes(nodes);
    setAttackGraphEdges(edges);
    setSelectedAttackNode(null);
    setAttackNodeThreatIntel(null);
    setHoveredStageId(null);
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

  const handleAnalyzeLogs = () => {
    const raw = logIngestionInput.trim();
    if (!raw || isThinking) return;
    const byTimestamp = splitLogEntriesByTimestamp(raw);
    const lines =
      byTimestamp.length > 1 ? byTimestamp : raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) return;

    clearInvestigationState();
    const summary = buildIncidentSummaryFromLines(lines);
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
    setReportMarkdown(null);
    triageWithMessages(nextMessages, lines, newIncident.id);
  };

  const handleGenerateInvestigationReport = async () => {
    if (!activeIncident || !investigationContext || investigationContext.incidentId !== activeIncident.id) {
      return;
    }
    setIsGeneratingReport(true);
    try {
    const caseId = sessionStorage.getItem("socCopilotCaseId") ?? "";
    const latestAssistant = [...messages]
      .reverse()
      .find(
        (m) =>
          m.role === "assistant" &&
          (m.severity !== undefined ||
            m.riskScore !== undefined ||
            (m.recommendedActions && m.recommendedActions.length > 0)),
      );
    const res = await fetch("/api/soc-copilot/report", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        caseId,
        incidentTitle: activeIncident.title,
        incidentSummary: activeIncident.summary,
        severity: investigationContext.severity,
        riskScore: investigationContext.riskScore,
        timeline: investigationContext.timeline,
        actionsTaken: playbookRunAt ? [`Playbook run at ${playbookRunAt} (simulated)`] : [],
        triageSummary: latestAssistant?.content ?? "",
        mitreTechniques: investigationContext.mitreTechniques,
        recommendedActions: investigationContext.recommendedActions,
        affectedAssets: getAffectedAssetsFromIncident(),
      }),
    });
    const data = await res.json();
    if (data.markdown) {
      setReportMarkdown(data.markdown);
      setReportPanelOpen(true);
      setReportModalOpen(true);
    }
    // Optionally mark as resolved after report generation
    if (activeIncident) {
      const resolvedStatus: IncidentStatus = "Resolved";
      setActiveIncident((prev) => (prev ? { ...prev, status: resolvedStatus } : prev));
      updateIncidentInQueue(activeIncident.id, { status: resolvedStatus });
    }
    } finally {
      setIsGeneratingReport(false);
    }
  };

  useEffect(() => {
    buildAttackGraph();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeIncident, JSON.stringify(investigationTimeline), JSON.stringify(lastTriageResult)]);

  return (
    <main className="min-h-screen bg-gradient-to-b from-zinc-950 via-slate-950 to-black text-zinc-50 flex flex-col">
      <div className="w-full flex flex-col flex-1">
        <header className="shrink-0 border-b border-zinc-800 bg-zinc-950/90 px-4 py-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex items-center gap-2 rounded-full border border-sky-500/30 bg-sky-500/5 px-3 py-1">
              <span className="h-1.5 w-1.5 rounded-full bg-sky-400" />
              <span className="text-[11px] font-mono tracking-[0.16em] text-sky-300/90">
                AI SOC INVESTIGATION CONSOLE
              </span>
            </div>
            <div className="flex flex-wrap gap-1">
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
                    ? "Investigation"
                    : m === "incident-queue"
                      ? "Queue"
                      : m === "log-ingestion"
                        ? "Log Ingestion"
                        : m === "nl-query"
                          ? "Threat Hunting"
                          : m === "dedupe"
                            ? "Alert Correlation"
                            : m === "simulation"
                              ? "Simulation"
                              : "Knowledge"}
                </button>
              ))}
            </div>
          </div>
        </header>

        {/* Triage mode: SOC console layout — Left queue | Center chat | Right insights | Bottom report */}
        {mode === "triage" && (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="flex-1 flex min-h-0">
            {/* Left Panel: Incident Queue — fixed width */}
            <aside className="w-[280px] shrink-0 border-r border-zinc-800 bg-zinc-950/80 flex flex-col overflow-hidden">
              <div className="p-3 border-b border-zinc-800">
                <h2 className="text-sm font-semibold text-zinc-100">Incident Queue</h2>
                <p className="text-[10px] text-zinc-500 mt-0.5">Total: {incidentQueue.length}</p>
                <p className="text-[10px] text-zinc-500 mt-1.5 leading-tight">Click a sample or queue item to investigate. Cancel removes from queue.</p>
              </div>
              <div className="p-2 flex-1 overflow-y-auto space-y-3">
                <button
                  type="button"
                  onClick={startNewInvestigation}
                  className="w-full px-3 py-2 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-xs font-medium hover:bg-sky-500/20"
                >
                  New Investigation
                </button>
                <div>
                  <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mb-1">Sample incidents</p>
                  <p className="text-[10px] text-zinc-600 mb-2">Click to run a demo investigation (chat refreshes).</p>
                  <div className="space-y-1.5">
                    {SAMPLE_INCIDENTS.map((inc) => (
                      <button
                        key={inc.id}
                        type="button"
                        onClick={() => handleSampleIncident(inc)}
                        disabled={isThinking}
                        className={`w-full text-left p-2 rounded-lg border transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
                          activeIncident?.id === inc.id
                            ? "border-sky-500 bg-sky-500/10"
                            : "border-zinc-800 bg-zinc-900/80 hover:border-sky-500/40"
                        }`}
                      >
                        <span className="text-[10px] font-mono text-zinc-500">{inc.source}</span>
                        <p className="text-xs font-medium text-zinc-200 mt-0.5 line-clamp-2">{inc.title}</p>
                        <span className="inline-block mt-1 px-1.5 py-0.5 rounded text-[10px] font-mono border border-zinc-600 text-zinc-400">{inc.severity}</span>
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider mb-1">Queue</p>
                  <p className="text-[10px] text-zinc-600 mb-2">Incidents you added. Open = investigate, Cancel = remove.</p>
                  {incidentQueue.length === 0 ? (
                    <p className="text-[11px] text-zinc-500">No incidents. Use Log Ingestion or Alert Correlation to add.</p>
                  ) : (
                    <div className="space-y-1.5">
                      {incidentQueue.map((inc) => (
                        <div
                          key={inc.id}
                          className={`rounded-lg border p-2 ${activeIncident?.id === inc.id ? "border-sky-500 bg-sky-500/10" : "border-zinc-800 bg-zinc-900/80"}`}
                        >
                          <p className="text-xs font-medium text-zinc-200 truncate">{inc.title}</p>
                          <div className="flex items-center justify-between gap-1 mt-1">
                            <span className="text-[10px] font-mono text-zinc-500">{inc.status}</span>
                            <div className="flex gap-1">
                              <button
                                type="button"
                                onClick={() => {
                                  resetStateForNewSession();
                                  setActiveIncident(inc);
                                  setReportMarkdown(null);
                                  const summaryMessage: ChatMessage = { role: "user", content: inc.summary };
                                  setMessages([INITIAL_GREETING, summaryMessage]);
                                  const byTimestamp = splitLogEntriesByTimestamp(inc.summary);
                                  const lines = byTimestamp.length > 1 ? byTimestamp : inc.summary.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
                                  triageWithMessages([INITIAL_GREETING, summaryMessage], lines.length > 0 ? lines : [inc.summary], inc.id);
                                }}
                                className="text-[10px] text-sky-400 hover:text-sky-300 font-medium"
                              >
                                Open
                              </button>
                              <button
                                type="button"
                                onClick={() => removeFromQueue(inc.id)}
                                className="text-[10px] text-zinc-500 hover:text-red-400 font-medium"
                                title="Remove from queue"
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </aside>

            {/* Center Panel: Investigation Chat — Header, then Messages, then Input */}
            <section className="flex-1 flex flex-col min-w-0 border-r border-zinc-800 min-h-0">
              <div className="shrink-0 border-b border-zinc-800 px-4 py-2 flex flex-wrap items-center justify-between gap-2 bg-zinc-950/70">
                <div className="space-y-1">
                  <h2 className="text-sm font-semibold text-zinc-100">Investigation</h2>
                  <p className="text-[11px] font-mono text-zinc-500">
                    Active Investigation — Session #{sessionCount}
                  </p>
                  {(lastTriageResult?.riskScore != null || activeIncident?.severity) && (
                    <div className="flex flex-wrap items-center gap-2 pt-1">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${
                        (() => {
                          const sev = lastTriageResult?.riskScore != null ? getSeverityFromRisk(lastTriageResult.riskScore) : (activeIncident?.severity ?? "Unknown");
                          if (sev === "Critical") return "bg-red-500/15 text-red-300 border-red-500/50";
                          if (sev === "High") return "bg-orange-500/15 text-orange-300 border-orange-500/50";
                          if (sev === "Medium") return "bg-amber-500/15 text-amber-300 border-amber-500/50";
                          return "bg-emerald-500/15 text-emerald-300 border-emerald-500/50";
                        })()
                      }`}>
                        Severity: {lastTriageResult?.riskScore != null ? getSeverityFromRisk(lastTriageResult.riskScore) : (activeIncident?.severity ?? "—")}
                      </span>
                      {lastTriageResult?.riskScore != null && (
                        <span className="text-[10px] font-mono text-zinc-400">
                          Risk Score: {lastTriageResult.riskScore}
                        </span>
                      )}
                    </div>
                  )}
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  {activeIncident && (
                    <button
                      type="button"
                      onClick={reportMarkdown ? () => setReportModalOpen(true) : handleGenerateInvestigationReport}
                      disabled={isGeneratingReport || (!reportMarkdown && !investigationContext)}
                      className="px-2.5 py-1.5 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-[11px] font-medium hover:bg-sky-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isGeneratingReport ? "Generating…" : reportMarkdown ? "View Report" : "Generate Report"}
                    </button>
                  )}
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
                    {openaiConfigured === null ? "…" : openaiConfigured ? "LLM + rules" : "Rules only"}
                  </span>
                </div>
              </div>
              <div className="flex-1 flex flex-col min-h-0 overflow-hidden">
                <div className="min-h-0 overflow-y-auto px-4 py-3 space-y-3 text-sm h-fit max-h-full">
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
                {/* Attack Chain Visualization — full width in center panel; compact when empty */}
                {(attackStages.length > 0 || attackGraphNodes.length > 0) ? (
                <div className="shrink-0 w-full rounded-lg border border-zinc-800 bg-zinc-950/70 p-4 space-y-3">
                  <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Attack Chain</h3>
                  {attackStages.length > 0 && (
                    <>
                      <p className="text-[10px] text-zinc-500">Similar chain in {similarChainCount} previous incident{similarChainCount !== 1 ? "s" : ""}.</p>
                      <div className="flex flex-wrap items-center gap-1">
                        {sortStagesByChainOrder(attackStages).map((stage, idx) => (
                          <div key={stage.id} onMouseEnter={() => setHoveredStageId(stage.id)} onMouseLeave={() => setHoveredStageId(null)} className={`rounded-full border px-2 py-0.5 text-[10px] font-mono cursor-pointer ${hoveredStageId === stage.id ? "border-sky-500 bg-sky-500/20 text-sky-100" : "border-zinc-700 bg-zinc-900/80 text-zinc-300"}`}>{idx > 0 && <span className="mr-1 text-zinc-500">→</span>}{stage.label}</div>
                        ))}
                      </div>
                    </>
                  )}
                  {attackGraphNodes.length > 0 && (
                    <div className="min-h-[300px] h-[320px] w-full rounded-lg border border-zinc-800 overflow-hidden bg-zinc-950">
                      <ReactFlow
                        nodes={attackGraphNodes.map((n) => {
                          const risk = n.data.risk;
                          const baseColor = risk === "Critical" ? "#ef4444" : risk === "High" ? "#f97316" : risk === "Medium" ? "#eab308" : "#38bdf8";
                          const isDimmed = hoveredStageId !== null && n.data.stage && n.data.stage !== hoveredStageId;
                          return { ...n, style: { ...n.style, borderColor: baseColor, background: "#020617", color: isDimmed ? "#6b7280" : "#e5e7eb", opacity: isDimmed ? 0.4 : 1 } };
                        })}
                        edges={attackGraphEdges}
                        fitView
                        onNodeClick={(_, node) => { setSelectedAttackNode(node as AttackGraphNode); setSelectedEvidenceTimelineIndex(null); setAttackNodeThreatIntel(null); }}
                        proOptions={{ hideAttribution: true }}
                      >
                        <MiniMap pannable zoomable />
                        <Controls />
                        <Background gap={16} />
                      </ReactFlow>
                    </div>
                  )}
                  {selectedAttackNode && (
                    <div className="rounded-lg border border-zinc-800 p-3 space-y-1.5 text-[11px]">
                      <p className="font-medium text-zinc-100">{selectedAttackNode.data.label}</p>
                      {selectedAttackNode.data.entity && (selectedAttackNode.data.type === "ip" || selectedAttackNode.data.type === "host" || selectedAttackNode.data.type === "file") && (
                        <button type="button" className="text-[10px] text-sky-400 hover:text-sky-300" onClick={async () => {
                          const ioc = selectedAttackNode.data.entity;
                          if (!ioc) return;
                          setAttackNodeThreatIntel(null);
                          const res = await fetch("/api/soc-copilot/threat-intel", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ioc }) });
                          const data = await res.json();
                          if (data.reputation) setAttackNodeThreatIntel({ ioc: data.ioc, reputation: data.reputation, country: data.country, association: data.association });
                        }}>Check Threat Intel</button>
                      )}
                      {attackNodeThreatIntel && (
                        <div className="rounded border border-zinc-700 p-2 text-[10px]">
                          <p><span className="text-zinc-500">Reputation:</span> <span className={attackNodeThreatIntel.reputation === "Malicious" ? "text-red-400" : "text-amber-400"}>{attackNodeThreatIntel.reputation}</span></p>
                          {attackNodeThreatIntel.country && <p><span className="text-zinc-500">Country:</span> {attackNodeThreatIntel.country}</p>}
                        </div>
                      )}
                    </div>
                  )}
                </div>
                ) : (
                <div className="shrink-0 w-full rounded-lg border border-zinc-800 bg-zinc-950/50 px-4 py-2">
                  <p className="text-[11px] text-zinc-500">Attack chain will appear here after you analyze an incident (e.g. use a sample incident or paste security logs).</p>
                </div>
                )}
                {/* Recommended Actions — part of investigation output, above chat input */}
                {lastTriageResult?.recommendedActions && lastTriageResult.recommendedActions.length > 0 && (
                  <div className="shrink-0 border-t border-zinc-800 px-4 py-3 bg-zinc-950/70">
                    <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider mb-2">Recommended Actions</h3>
                    <ul className="space-y-1.5 text-[11px] text-zinc-300 mb-2">
                      {lastTriageResult.recommendedActions.map((act, i) => (
                        <li key={i} className="flex justify-between gap-2 items-center">
                          <span>{act.label}</span>
                          <span className="text-[10px] font-mono text-zinc-500 shrink-0">{act.risk} risk</span>
                        </li>
                      ))}
                    </ul>
                    {playbookRunAt ? (
                      <p className="text-[10px] text-emerald-400/90">Playbook run at {playbookRunAt} (simulated)</p>
                    ) : (
                      <button type="button" onClick={() => setPlaybookRunAt(new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }))} className="w-full px-3 py-2 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-[11px] font-mono hover:bg-sky-500/20">Run playbook (simulated)</button>
                    )}
                  </div>
                )}
                <form
                  onSubmit={handleSubmit}
                  className="shrink-0 border-t border-zinc-800 px-3 py-2 flex gap-2 bg-zinc-950/70"
                >
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="e.g., Sentinel: impossible travel sign-in from Brazil and Germany within 30 minutes…"
                className="flex-1 bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2 text-sm text-zinc-100 placeholder:text-zinc-500 outline-none"
              />
              <button
                type="submit"
                disabled={isThinking || !input.trim()}
                className="px-3 py-2 text-xs font-medium rounded-lg bg-amber-500 hover:bg-amber-400 text-zinc-950 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                Send
              </button>
                </form>
              </div>
            </section>

            {/* Right Panel: Investigation Insights — fixed width, scrollable cards */}
            <aside className="w-[360px] shrink-0 flex flex-col overflow-hidden bg-zinc-950/60">
              <div className="flex-1 overflow-y-auto p-3 space-y-3">
                {/* Incident Summary — compact card */}
                {activeIncident ? (
                  <>
                    <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                      <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Incident Summary</h3>
                      <p className="text-xs font-medium text-zinc-100">{activeIncident.title}</p>
                      <div className="flex flex-wrap gap-2 text-[10px]">
                        <span className="text-zinc-500">Source: <span className="text-zinc-300">{activeIncident.source}</span></span>
                        <span className="text-zinc-500">Severity: <span className="text-zinc-300">{activeIncident.severity}</span></span>
                      </div>
                      {correlatedAlertsCount != null && correlatedAlertsCount > 0 && (
                        <p className="text-[10px] font-mono text-sky-300">Correlated Alerts: {correlatedAlertsCount}</p>
                      )}
                      {lastTriageResult?.riskScore != null && (
                        <div className="flex items-center gap-2 pt-0.5">
                          <span className="text-[10px] text-zinc-500 shrink-0">Risk</span>
                          <div className="flex-1 h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                            <div className="h-full rounded-full bg-sky-500" style={{ width: `${Math.min(100, Math.max(0, lastTriageResult.riskScore))}%` }} />
                          </div>
                          <span className="text-[10px] font-mono text-zinc-400 shrink-0">{lastTriageResult.riskScore}/100</span>
                        </div>
                      )}
                    </div>
                    {/* Investigation Status — compact card */}
                    <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                      <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Investigation Status</h3>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono border border-zinc-600 text-zinc-300">{activeIncident.status}</span>
                        {(["New", "Under Review", "Resolved"] as IncidentStatus[]).map((s) => (
                          <button key={s} type="button" onClick={() => { setActiveIncident((p) => (p ? { ...p, status: s } : p)); updateIncidentInQueue(activeIncident.id, { status: s }); }} className={`px-2 py-0.5 rounded text-[10px] font-mono border ${activeIncident.status === s ? "border-sky-500/70 text-sky-300 bg-sky-500/10" : "border-zinc-700 text-zinc-400 hover:border-sky-500/50"}`}>{s}</button>
                        ))}
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="rounded-lg border border-zinc-800 bg-zinc-900/80 p-3">
                    <p className="text-xs text-zinc-500">Select an incident from the queue or paste an alert in chat.</p>
                  </div>
                )}

                {/* Timeline */}
                <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                  <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Timeline</h3>
                  {investigationTimeline && investigationTimeline.length > 0 ? (
                    <div className="relative pl-3 border-l-2 border-sky-600/40 space-y-1.5 max-h-48 overflow-y-auto">
                      {sortTimelineByTime(investigationTimeline).map((e, i) => (
                        <button key={i} type="button" onClick={() => { setSelectedEvidenceTimelineIndex(i); setSelectedAttackNode(null); }} className={`w-full text-left flex items-start gap-2 rounded px-2 py-1 -ml-[11px] transition-colors ${selectedEvidenceTimelineIndex === i ? "bg-sky-500/10 border border-sky-500/40" : "hover:bg-zinc-800/50"}`}>
                          <span className="h-2 w-2 rounded-full bg-sky-500 shrink-0 mt-1" />
                          <div className="min-w-0">
                            <span className="text-[10px] font-mono text-sky-300/90">{e.time}</span>
                            <p className="text-[11px] text-zinc-300 truncate">{e.event}</p>
                          </div>
                        </button>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] text-zinc-500">No timeline events yet.</p>
                  )}
                </div>

                {/* Card: Indicators of Compromise */}
                <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                  <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Indicators of Compromise</h3>
                  {investigationContext && (investigationContext.indicators.ips.length > 0 || investigationContext.indicators.domains.length > 0 || investigationContext.indicators.emails.length > 0 || investigationContext.indicators.processes.length > 0 || investigationContext.indicators.hosts.length > 0 || investigationContext.indicators.files.length > 0) ? (
                    <div className="space-y-2 text-[11px] max-h-40 overflow-y-auto">
                      {investigationContext.indicators.ips.length > 0 && <div><p className="text-[10px] font-mono text-zinc-500">IPs</p><ul className="text-zinc-300 font-mono">{investigationContext.indicators.ips.map((ip, i) => <li key={i}>{ip}</li>)}</ul></div>}
                      {investigationContext.indicators.domains.length > 0 && <div><p className="text-[10px] font-mono text-zinc-500">Domains</p><ul className="text-zinc-300 font-mono">{investigationContext.indicators.domains.map((d, i) => <li key={i}>{d}</li>)}</ul></div>}
                      {investigationContext.indicators.emails.length > 0 && <div><p className="text-[10px] font-mono text-zinc-500">Emails</p><ul className="text-zinc-300 font-mono break-all">{investigationContext.indicators.emails.map((e, i) => <li key={i}>{e}</li>)}</ul></div>}
                      {investigationContext.indicators.processes.length > 0 && <div><p className="text-[10px] font-mono text-zinc-500">Processes</p><ul className="text-zinc-300 font-mono">{investigationContext.indicators.processes.map((p, i) => <li key={i}>{p}</li>)}</ul></div>}
                      {investigationContext.indicators.hosts.length > 0 && <div><p className="text-[10px] font-mono text-zinc-500">Hosts</p><ul className="text-zinc-300 font-mono">{investigationContext.indicators.hosts.map((h, i) => <li key={i}>{h}</li>)}</ul></div>}
                      {investigationContext.indicators.files.length > 0 && <div><p className="text-[10px] font-mono text-zinc-500">Files</p><ul className="text-zinc-300 font-mono">{investigationContext.indicators.files.map((f, i) => <li key={i}>{f}</li>)}</ul></div>}
                    </div>
                  ) : (
                    <p className="text-[11px] text-zinc-500">No IOCs extracted yet.</p>
                  )}
                </div>

                {/* Card: Evidence */}
                <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                  <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Evidence</h3>
                  {(selectedEvidenceTimelineIndex !== null && investigationTimeline && investigationTimeline.length > 0) || selectedAttackNode ? (
                    <div className="rounded border border-zinc-800 bg-zinc-900/80 p-2 space-y-1.5 max-h-40 overflow-y-auto">
                      {selectedEvidenceTimelineIndex !== null && investigationTimeline ? (() => {
                        const sorted = sortTimelineByTime(investigationTimeline);
                        const ev = sorted[selectedEvidenceTimelineIndex];
                        if (!ev) return null;
                        const rawEvidence = ev.rawEvidence ?? `${ev.time} – ${ev.event}`;
                        return <><p className="text-[10px] text-zinc-500">{ev.event}</p><pre className="text-[10px] font-mono text-zinc-300 whitespace-pre-wrap break-words">{rawEvidence}</pre></>;
                      })() : selectedAttackNode ? (
                        <><p className="text-[10px] text-zinc-500">{selectedAttackNode.data.label}</p><pre className="text-[10px] font-mono text-zinc-300 whitespace-pre-wrap break-words">{selectedAttackNode.data.raw ?? selectedAttackNode.data.evidence ?? "—"}</pre></>
                      ) : null}
                    </div>
                  ) : (
                    <p className="text-[11px] text-zinc-500">Click a timeline event or graph node to show evidence.</p>
                  )}
                </div>

                {/* Threat Intel Lookup */}
                <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                  <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Threat Intel Lookup</h3>
                  <div className="flex gap-2">
                    <input type="text" value={threatIntelIoc} onChange={(e) => setThreatIntelIoc(e.target.value)} placeholder="IP, domain, hash" className="flex-1 bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-[11px] text-zinc-100 placeholder:text-zinc-500" />
                    <button type="button" onClick={async () => { if (!threatIntelIoc.trim()) return; setThreatIntelResult(null); const res = await fetch("/api/soc-copilot/threat-intel", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ioc: threatIntelIoc }) }); const data = await res.json(); if (data.reputation) setThreatIntelResult({ ioc: data.ioc, reputation: data.reputation, country: data.country, association: data.association }); }} className="px-2 py-1.5 rounded bg-sky-600 text-white text-[11px] font-medium hover:bg-sky-500">Lookup</button>
                  </div>
                  {threatIntelResult && (
                    <div className="rounded border border-zinc-700 p-2 text-[11px] space-y-0.5">
                      <p><span className="text-zinc-500">Reputation:</span> <span className={threatIntelResult.reputation === "Malicious" ? "text-red-400" : threatIntelResult.reputation === "Suspicious" ? "text-amber-400" : "text-zinc-300"}>{threatIntelResult.reputation}</span></p>
                      {threatIntelResult.country && <p><span className="text-zinc-500">Country:</span> {threatIntelResult.country}</p>}
                    </div>
                  )}
                </div>

                {/* Similar Past Incidents */}
                {similarIncidents && similarIncidents.length > 0 && (
                  <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                    <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Similar Past Incidents</h3>
                    <div className="space-y-1.5 max-h-32 overflow-y-auto">
                      {similarIncidents.map((inc) => (
                        <div key={inc.id} className="rounded border border-zinc-700 p-2">
                          <p className="text-[11px] font-medium text-zinc-200 truncate">{inc.title}</p>
                          <p className="text-[10px] font-mono text-zinc-500">Risk: {inc.riskScore}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Investigation Report — collapsible card (does not push main content) */}
                <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3 space-y-2">
                  <details
                    open={reportPanelOpen}
                    onToggle={(e) => setReportPanelOpen((e.target as HTMLDetailsElement).open)}
                    className="group"
                  >
                    <summary className="cursor-pointer list-none flex items-center justify-between gap-2 py-0.5">
                      <h3 className="text-xs font-semibold text-zinc-100 uppercase tracking-wider">Investigation Report</h3>
                      <span className="text-[10px] font-mono text-zinc-500">{reportMarkdown ? "Generated" : "Not generated"}</span>
                    </summary>
                    <div className="pt-3 mt-2 border-t border-zinc-800 space-y-2">
                      {reportMarkdown ? (
                        <>
                          <div className="flex gap-2">
                            <button type="button" onClick={() => setReportModalOpen(true)} className="text-[11px] text-sky-400 hover:text-sky-300 font-medium">View full report</button>
                            <button type="button" onClick={() => navigator.clipboard.writeText(reportMarkdown ?? "")} className="text-[11px] text-zinc-400 hover:text-zinc-300 font-medium">Copy</button>
                          </div>
                          <div className="rounded-lg border border-zinc-700 bg-zinc-900/90 p-3 max-h-64 overflow-y-auto space-y-2">
                            <pre className="text-[11px] text-zinc-300 whitespace-pre-wrap font-mono leading-relaxed">{reportMarkdown}</pre>
                          </div>
                        </>
                      ) : (
                        <p className="text-[11px] text-zinc-500">Use &quot;Generate Report&quot; in the Investigation header to create a report.</p>
                      )}
                    </div>
                  </details>
                </div>
              </div>
            </aside>
          </div>
        </div>
        )}

        {/* Non-triage modes: full-width content */}
        {mode !== "triage" && (
        <div className="flex-1 p-4 max-w-5xl mx-auto w-full space-y-6">
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
                        <span className="flex justify-end gap-1">
                          <button
                            type="button"
                            onClick={() => {
                              resetStateForNewSession();
                              setActiveIncident(inc);
                              setReportMarkdown(null);
                              setMode("triage");
                              const summaryMessage: ChatMessage = {
                                role: "user",
                                content: inc.summary,
                              };
                              setMessages([INITIAL_GREETING, summaryMessage]);
                              const byTimestamp = splitLogEntriesByTimestamp(inc.summary);
                              const lines =
                                byTimestamp.length > 1
                                  ? byTimestamp
                                  : inc.summary.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
                              triageWithMessages([INITIAL_GREETING, summaryMessage], lines.length > 0 ? lines : [inc.summary], inc.id);
                            }}
                            className="px-3 py-1 rounded-lg border border-sky-500/50 bg-sky-500/10 text-[11px] font-mono text-sky-200 hover:bg-sky-500/20"
                          >
                            Open
                          </button>
                          <button
                            type="button"
                            onClick={() => removeFromQueue(inc.id)}
                            className="px-2 py-1 rounded-lg border border-zinc-600 text-zinc-400 hover:border-red-500/50 hover:text-red-400 text-[11px] font-mono"
                            title="Remove from queue"
                          >
                            Cancel
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
            <p className="text-xs text-zinc-400">Paste multiple alerts (one per line). Events are correlated by shared user, host, IP, or close timestamps and merged into one attack chain.</p>
            <textarea
              value={dedupeAlerts}
              onChange={(e) => setDedupeAlerts(e.target.value)}
              placeholder={"2026-03-14 10:00:00 CrowdStrike: Malware detected on WORKSTATION-42\n2026-03-14 10:02:00 Azure: Sign-in from 185.77.91.33 for alice@company.com\n2026-03-14 10:05:00 Firewall: Blocked outbound 443 to 185.77.91.33\n2026-03-14 10:01:00 EDR: PowerShell execution on PC-ALICE"}
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
                if (data.incidentTitle) {
                  setDedupeResult({
                    incidentTitle: data.incidentTitle,
                    summary: data.summary,
                    count: data.count ?? lines.length,
                    mergedLogLines: Array.isArray(data.mergedLogLines) ? data.mergedLogLines : lines,
                  });
                }
              }}
              className="px-4 py-2 rounded-lg bg-sky-600 text-white text-sm font-medium hover:bg-sky-500"
            >
              Group alerts
            </button>
            {dedupeResult && (
              <div className="rounded-lg border border-zinc-700 bg-zinc-900/80 p-3 space-y-3">
                <p className="text-sm font-medium text-zinc-100">{dedupeResult.incidentTitle}</p>
                <p className="text-xs text-zinc-400">{dedupeResult.summary}</p>
                <span className="text-[10px] font-mono text-zinc-500 block">{dedupeResult.count} alerts correlated</span>
                <button
                  type="button"
                  onClick={() => {
                    if (!dedupeResult?.mergedLogLines?.length) return;
                    const mergedLines = dedupeResult.mergedLogLines;
                    const summary = [dedupeResult.summary, "", "Merged timeline:", ...mergedLines].join("\n");
                    const newIncident: Incident = {
                      id: `corr-${Date.now()}`,
                      title: dedupeResult.incidentTitle,
                      summary,
                      severity: "Unknown",
                      source: "Alert Correlation",
                      status: "Under Review",
                      createdAt: new Date().toISOString(),
                    };
                    clearInvestigationState();
                    setLastTriageResult(null);
                    setCorrelatedAlertsCount(dedupeResult.count);
                    setActiveIncident(newIncident);
                    addIncidentToQueue(newIncident);
                    setMode("triage");
                    const userMessage: ChatMessage = { role: "user", content: `Correlated ${dedupeResult.count} alerts into one investigation.\n\n${mergedLines.slice(0, 5).join("\n")}${mergedLines.length > 5 ? "\n…" : ""}` };
                    const nextMessages = [INITIAL_GREETING, userMessage];
                    setMessages(nextMessages);
                    setReportMarkdown(null);
                    triageWithMessages(nextMessages, mergedLines, newIncident.id);
                  }}
                  className="px-3 py-1.5 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-xs font-medium hover:bg-sky-500/20"
                >
                  Open in Investigation
                </button>
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
        )}
      </div>

      {/* Investigation Report modal — center overlay, close + download */}
      {reportModalOpen && reportMarkdown && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
          onClick={() => setReportModalOpen(false)}
          role="dialog"
          aria-modal="true"
          aria-label="Investigation Report"
        >
          <div
            className="rounded-xl border border-zinc-700 bg-zinc-950 shadow-2xl w-full max-w-3xl max-h-[85vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="shrink-0 flex items-center justify-between gap-2 px-4 py-3 border-b border-zinc-800">
              <h2 className="text-sm font-semibold text-zinc-100">Investigation Report</h2>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={downloadReport}
                  className="px-3 py-1.5 rounded-lg border border-sky-500/50 bg-sky-500/10 text-sky-200 text-xs font-medium hover:bg-sky-500/20"
                >
                  Download
                </button>
                <button
                  type="button"
                  onClick={() => setReportModalOpen(false)}
                  className="p-1.5 rounded-lg border border-zinc-600 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors"
                  aria-label="Close"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" /></svg>
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto px-4 py-4 min-h-0">
              <pre className="text-xs text-zinc-300 whitespace-pre-wrap font-mono leading-relaxed">{reportMarkdown}</pre>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

