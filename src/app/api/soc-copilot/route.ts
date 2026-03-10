import { NextResponse } from "next/server";

const SOC_SYSTEM_PROMPT = `You are an AI SOC (Security Operations Center) Tier-1 copilot. Your job is to triage security alerts and incidents.

For any alert or incident summary the user provides, respond with:
1. **Enrichment** – What data you would pull (logs, user context, asset criticality, threat intel).
2. **Assessment** – Likely severity (Low/Medium/High/Critical), confidence, and probable attack step or root cause.
3. **Recommended next steps** – Concrete actions (e.g., force sign-out, isolate host, quarantine email) and any approvals needed.

Be concise, use bullet points, and speak in the first person as the copilot. Do not invent specific IOCs or log lines; say what you "would" pull or "would" check. If the input is vague, ask for one or two more details (e.g., which tool generated the alert, user/host name).`;

type Message = { role: "user" | "assistant"; content: string };

function ruleBasedTriage(userContent: string): string {
  const lower = userContent.toLowerCase();
  if (
    lower.includes("impossible travel") ||
    lower.includes("sign-in") ||
    lower.includes("signin") ||
    lower.includes("login")
  ) {
    return `This looks like an **identity-related alert (e.g., impossible travel / suspicious sign-in)**.

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

In the real product, these steps would be partially automated with clear approvals and an evidence panel for each decision.`;
  }
  if (lower.includes("phishing") || lower.includes("email")) {
    return `This resembles a **phishing / malicious email incident**.

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

The production copilot would show which emails, users, and sandboxes it used to reach these conclusions.`;
  }
  if (
    lower.includes("malware") ||
    lower.includes("ransomware") ||
    lower.includes("edr")
  ) {
    return `This sounds like an **endpoint malware / EDR alert**.

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

In production, the copilot would orchestrate EDR, SIEM, and ticketing tools to do this with minimal clicks.`;
  }
  return `Here’s how I’d handle this as a Tier‑1 SOC copilot:

1. **Enrichment**: Pull related logs, user context, and asset criticality.
2. **Assessment**: Classify severity, confidence, and likely attack step.
3. **Actions**: Propose concrete next steps and low‑risk automated actions.

In a production deployment this chat would be wired into your SIEM/XDR so every answer is backed by real evidence and is fully auditable.`;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const messages: Message[] = Array.isArray(body.messages) ? body.messages : [];

    const lastUser = messages.filter((m) => m.role === "user").pop();
    const userContent = lastUser?.content?.trim() ?? "";

    if (!userContent) {
      return NextResponse.json(
        { error: "No user message provided" },
        { status: 400 },
      );
    }

    const apiKey = process.env.OPENAI_API_KEY;
    if (apiKey) {
      const openaiMessages: {
        role: "system" | "user" | "assistant";
        content: string;
      }[] = [
        { role: "system", content: SOC_SYSTEM_PROMPT },
        ...messages.map((m) => ({
          role: m.role as "user" | "assistant",
          content: m.content,
        })),
      ];

      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: openaiMessages,
          max_tokens: 1024,
        }),
      });

      if (!res.ok) {
        const err = await res.text();
        console.error("OpenAI API error:", res.status, err);
        return NextResponse.json(
          { error: "LLM request failed", detail: err },
          { status: 502 },
        );
      }

      const data = await res.json();
      const content = data?.choices?.[0]?.message?.content?.trim();
      if (!content) {
        return NextResponse.json(
          { error: "Empty response from LLM" },
          { status: 502 },
        );
      }
      return NextResponse.json({ message: content });
    }

    const response = ruleBasedTriage(userContent);
    return NextResponse.json({ message: response });
  } catch (e) {
    console.error("soc-copilot API error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}

