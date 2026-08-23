import { NextResponse } from "next/server";
import { getAnthropicKey } from "@/lib/openai";
import { prisma } from "@/lib/db";
import { auditCaseEvent } from "@/lib/audit";

const SOC_SYSTEM_PROMPT = `You are an AI SOC (Security Operations Center) Tier-1 copilot. Your job is to triage security alerts and incidents.

For any alert or incident summary the user provides, your internal reasoning should consider:
- Enrichment: which logs, user context, asset criticality, and threat intel to pull.
- Assessment: severity (Low/Medium/High/Critical), confidence, and likely attack step.
- Recommended actions: concrete next steps (e.g., force sign-out, isolate host, quarantine email) and which require human approval.

You may be provided with "Similar Past Incidents" from a knowledge base. Use these past incidents only as reference examples. Analyze the current incident independently and generate a fresh explanation.

However, your final response will be post-processed by the application, so return a clear, concise explanation as free-form text. Do not invent specific IOCs or log lines; say what you "would" pull from logs or tools.`;

type Message = { role: "user" | "assistant"; content: string };

type MitreTechnique = { id: string; name: string };

type RuleTriageResult = {
  message: string;
  evidence: string[];
  severity: "Low" | "Medium" | "High" | "Critical";
  confidence: number;
  riskScore: number;
  mitreTechniques: MitreTechnique[];
  recommendedActions: {
    label: string;
    risk: "Low" | "Medium" | "High";
    requiresApproval: boolean;
  }[];
};

type KnowledgeBaseIncident = {
  id: string;
  title: string;
  summary: string;
  mitreTechniques: MitreTechnique[];
  riskScore: number;
  recommendedActions: string[];
  keywords: string;
};

const KNOWLEDGE_BASE: KnowledgeBaseIncident[] = [
  {
    id: "kb-identity-1",
    title: "Impossible travel sign-in for privileged user",
    summary:
      "Privileged account observed logging in from two distant countries within 15 minutes. Multiple failed MFA prompts followed by successful sign-in from unfamiliar device.",
    mitreTechniques: [
      { id: "T1078", name: "Valid Accounts" },
      { id: "T1133", name: "External Remote Services" },
    ],
    riskScore: 88,
    recommendedActions: [
      "Force sign-out of all active sessions for the affected account.",
      "Require credential reset and enforce strong MFA re-registration.",
      "Hunt for related sign-ins from the same IPs or device fingerprints.",
    ],
    keywords: "impossible travel sign-in login identity mfa privileged account",
  },
  {
    id: "kb-phishing-1",
    title: "Credential harvesting phishing campaign",
    summary:
      "Multiple users received a fake password reset email with link to look-alike login page. At least one user entered credentials; follow-up sign-ins from new IP range.",
    mitreTechniques: [
      { id: "T1566", name: "Phishing" },
      { id: "T1598", name: "Phishing for Information" },
    ],
    riskScore: 90,
    recommendedActions: [
      "Quarantine the malicious email across all mailboxes.",
      "Reset credentials and revoke sessions for any users who clicked or entered passwords.",
      "Search for inbox rules or forwarding set up after the phishing event.",
    ],
    keywords:
      "phishing email campaign credential harvest fake login password reset mailbox",
  },
  {
    id: "kb-edr-1",
    title: "EDR-detected malware with outbound C2",
    summary:
      "Endpoint agent detected suspicious process tree spawning powershell.exe, dropping unknown binary in AppData, and making outbound connections to known C2 infrastructure.",
    mitreTechniques: [
      { id: "T1204", name: "User Execution" },
      { id: "T1071", name: "Application Layer Protocol" },
      { id: "T1041", name: "Exfiltration Over C2 Channel" },
    ],
    riskScore: 93,
    recommendedActions: [
      "Isolate the host using the EDR platform until triage is complete.",
      "Collect forensic artifacts (memory, disk, relevant logs) before remediation.",
      "Scan the environment for the same binary hash or network indicators.",
    ],
    keywords:
      "malware edr ransomware c2 command and control powershell host endpoint",
  },
];

function scoreKnowledgeIncident(
  userText: string,
  incident: KnowledgeBaseIncident,
): number {
  const text = `${incident.title} ${incident.summary} ${incident.keywords}`.toLowerCase();
  const userTokens = new Set(
    userText
      .toLowerCase()
      .split(/[^a-z0-9]+/g)
      .filter((t) => t.length > 3),
  );
  if (userTokens.size === 0) return 0;
  let overlap = 0;
  for (const token of userTokens) {
    if (text.includes(token)) overlap += 1;
  }
  return overlap;
}

function getSimilarIncidents(userText: string): KnowledgeBaseIncident[] {
  const scored = KNOWLEDGE_BASE.map((kb) => ({
    kb,
    score: scoreKnowledgeIncident(userText, kb),
  })).filter((x) => x.score > 0);

  return scored
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map((x) => x.kb);
}

function ruleBasedTriage(userContent: string): RuleTriageResult {
  const lower = userContent.toLowerCase();
  if (
    lower.includes("impossible travel") ||
    lower.includes("sign-in") ||
    lower.includes("signin") ||
    lower.includes("login")
  ) {
    return {
      message: `This looks like an **identity-related alert (e.g., impossible travel / suspicious sign-in)**.

1. **Enrichment**
   - Pull recent sign-ins for this user (IP, geo, device, MFA status).
   - Cross-check IPs against threat intel and known corp IP ranges.
   - Pull user context (role, department, high-value access? recent password reset?).

2. **Assessment**
   - If multiple new geos / devices with no MFA, severity = High.
   - If geo matches VPN range or travel pattern, severity can be lowered with justification.

3. **Recommended next steps**
   - Force sign-out of active sessions and require password reset.
   - Notify user and manager.
   - Hunt for similar activity across users/IPs.

In the real product, these steps would be partially automated with clear approvals and an evidence panel for each decision.`,
      evidence: [
        "Sign-in logs (IP, geo, device, MFA)",
        "Threat intel / known IP ranges",
        "User context (role, department, recent password reset)",
      ],
      severity: "High",
      confidence: 0.88,
      riskScore: 78,
      mitreTechniques: [
        { id: "T1078", name: "Valid Accounts" },
        { id: "T1133", name: "External Remote Services" },
      ],
      recommendedActions: [
        {
          label: "Force sign-out and require password reset",
          risk: "Medium",
          requiresApproval: true,
        },
        {
          label: "Notify user and manager about suspicious sign-in",
          risk: "Low",
          requiresApproval: false,
        },
        {
          label: "Hunt for similar sign-ins from same IPs/users",
          risk: "Low",
          requiresApproval: false,
        },
      ],
    };
  }
  if (lower.includes("phishing") || lower.includes("email")) {
    return {
      message: `This resembles a **phishing / malicious email incident**.

1. **Enrichment**
   - Extract sender, URLs, attachments, and run sandbox / reputation checks.
   - Check how many users received and interacted with the email.
   - Look for follow‑up sign-ins or MFA prompts from the same user.

2. **Assessment**
   - If payload or URLs are confirmed malicious and any user clicked, treat as High.
   - If only suspicious but no engagement, Medium with recommended monitoring.

3. **Recommended next steps**
   - Auto‑quarantine message across mailboxes (with approval).
   - Reset credentials / sessions for impacted users.
   - Open a formal incident with timeline and affected accounts.

The production copilot would show which emails, users, and sandboxes it used to reach these conclusions.`,
      evidence: [
        "Sender, URLs, attachments",
        "Sandbox / reputation checks",
        "Mailbox engagement (who received, clicked)",
      ],
      severity: "High",
      confidence: 0.82,
      riskScore: 85,
      mitreTechniques: [
        { id: "T1566", name: "Phishing" },
        { id: "T1598", name: "Phishing for Information" },
      ],
      recommendedActions: [
        {
          label: "Quarantine email across all mailboxes",
          risk: "Medium",
          requiresApproval: true,
        },
        {
          label: "Reset credentials and revoke sessions for impacted users",
          risk: "High",
          requiresApproval: true,
        },
        {
          label: "Open incident with full timeline of affected accounts",
          risk: "Low",
          requiresApproval: false,
        },
      ],
    };
  }
  if (
    lower.includes("malware") ||
    lower.includes("ransomware") ||
    lower.includes("edr")
  ) {
    return {
      message: `This sounds like an **endpoint malware / EDR alert**.

1. **Enrichment**
   - Pull process tree, file hash, parent process, and network connections for the host.
   - Check hash and domains against threat intel.
   - Pull asset criticality (server vs workstation, prod vs dev).

2. **Assessment**
   - Confirm if behavior matches commodity malware vs targeted tooling.
   - Elevate severity if the asset is high-value or lateral movement is detected.

3. **Recommended next steps**
   - Isolate the host via EDR (with explicit approval).
   - Collect forensic artifacts and persist logs.
   - Scan for the same indicators on other endpoints.

In production, the copilot would orchestrate EDR, SIEM, and ticketing tools to do this with minimal clicks.`,
      evidence: [
        "Process tree, file hash, parent process",
        "Network connections for host",
        "Threat intel (hash, domains)",
        "Asset criticality (CMDB)",
      ],
      severity: "Critical",
      confidence: 0.9,
      riskScore: 92,
      mitreTechniques: [
        { id: "T1204", name: "User Execution" },
        { id: "T1071", name: "Application Layer Protocol" },
        { id: "T1041", name: "Exfiltration Over C2 Channel" },
      ],
      recommendedActions: [
        {
          label: "Isolate host via EDR",
          risk: "High",
          requiresApproval: true,
        },
        {
          label: "Collect forensic artifacts and preserve logs",
          risk: "Medium",
          requiresApproval: false,
        },
        {
          label: "Scan for same indicators on other endpoints",
          risk: "Medium",
          requiresApproval: false,
        },
      ],
    };
  }
  return {
    message: `Here's how I'd handle this as a Tier‑1 SOC copilot:

1. **Enrichment**: Pull related logs, user context, and asset criticality.
2. **Assessment**: Classify severity, confidence, and likely attack step.
3. **Actions**: Propose concrete next steps and low‑risk automated actions.

In a production deployment this chat would be wired into your SIEM/XDR so every answer is backed by real evidence and is fully auditable.`,
    evidence: ["Related logs", "User context", "Asset criticality"],
    severity: "Medium",
    confidence: 0.6,
    riskScore: 50,
    mitreTechniques: [],
    recommendedActions: [
      {
        label: "Review enriched context and confirm severity",
        risk: "Low",
        requiresApproval: false,
      },
      {
        label: "Create a case if unusual behaviour is confirmed",
        risk: "Low",
        requiresApproval: false,
      },
    ],
  };
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const messages: Message[] = Array.isArray(body.messages) ? body.messages : [];
    const caseId = typeof body.caseId === "string" ? body.caseId.trim() : "";

    const lastUser = messages.filter((m) => m.role === "user").pop();
    const userContent = lastUser?.content?.trim() ?? "";

    if (!userContent) {
      return NextResponse.json(
        { error: "No user message provided" },
        { status: 400 },
      );
    }

    const similarIncidents = getSimilarIncidents(userContent);

    const anthropicApiKey = getAnthropicKey();
    if (anthropicApiKey) {
      const similarSection =
        similarIncidents.length > 0
          ? `Similar Past Incidents (for reference only):

${similarIncidents
  .map((inc, idx) => {
    const mitreList =
      inc.mitreTechniques.length > 0
        ? inc.mitreTechniques.map((t) => `${t.id} ${t.name}`).join(", ")
        : "None listed";
    const actionsList =
      inc.recommendedActions.length > 0
        ? inc.recommendedActions.map((a) => `- ${a}`).join("\n")
        : "- None listed";
    return `${idx + 1}. Incident title: ${inc.title}
   MITRE techniques: ${mitreList}
   Recommended actions:
${actionsList}`;
  })
  .join("\n\n")}

Remember: Use these past incidents only as reference examples. Do not copy their actions verbatim; adjust your reasoning and recommendations to the current incident.`
          : "No similar past incidents were found in the knowledge base for this alert.";

      const systemPrompt = `${SOC_SYSTEM_PROMPT}\n\n${similarSection}`;
      const anthropicMessages = messages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": anthropicApiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-sonnet-4-5",
          max_tokens: 1024,
          system: systemPrompt,
          messages: anthropicMessages,
        }),
      });

      if (!res.ok) {
        const err = await res.text();
        console.error("Anthropic API error:", res.status, err);
        return NextResponse.json(
          { error: "LLM request failed", detail: err },
          { status: 502 },
        );
      }

      const data = await res.json();
      const content = Array.isArray(data?.content)
        ? data.content
            .filter((block: { type?: string; text?: string }) => block.type === "text")
            .map((block: { text?: string }) => block.text ?? "")
            .join("\n")
            .trim()
        : "";

      if (!content) {
        return NextResponse.json(
          { error: "Empty response from LLM" },
          { status: 502 },
        );
      }

      const payload = {
        message: content,
        evidence: ["LLM analysis"],
        severity: "Medium",
        confidence: 0.5,
        riskScore: 50,
        mitreTechniques: [],
        recommendedActions: [],
        similarIncidents,
      };

      if (caseId) {
        await prisma.message.createMany({
          data: [
            { caseId, role: "user", content: userContent },
            { caseId, role: "assistant", content, metadata: payload as any },
          ],
        });
        await auditCaseEvent({
          caseId,
          action: "TRIAGE_RUN",
          actor: "system",
          detail: { mode: "anthropic" },
        });
      }

      return NextResponse.json(payload);
    }

    const {
      message,
      evidence,
      severity,
      confidence,
      riskScore,
      mitreTechniques,
      recommendedActions,
    } = ruleBasedTriage(userContent);
    const payload = {
      message,
      evidence,
      severity,
      confidence,
      riskScore,
      mitreTechniques,
      recommendedActions,
      similarIncidents,
    };

    if (caseId) {
      await prisma.message.createMany({
        data: [
          { caseId, role: "user", content: userContent },
          { caseId, role: "assistant", content: message, metadata: payload as any },
        ],
      });
      await auditCaseEvent({
        caseId,
        action: "TRIAGE_RUN",
        actor: "system",
        detail: { mode: "rules" },
      });
    }

    return NextResponse.json(payload);
  } catch (e) {
    console.error("soc-copilot API error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
