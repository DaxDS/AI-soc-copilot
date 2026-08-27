import { NextResponse } from "next/server";
import { getAnthropicKey } from "@/lib/openai";

const KNOWLEDGE_PROMPT = `You are a SOC knowledge assistant. Answer questions about security operations, alert types, and investigation steps. Be concise and practical. Examples of what you explain:
- What "Impossible travel" or "suspicious sign-in" means and how to investigate
- How to investigate phishing attacks step by step
- What MITRE ATT&CK is and how it's used in SOC
- Common EDR alerts and what they indicate
- How to triage malware vs credential theft
- Best practices for incident response
If the user asks something outside SOC/security, say you're focused on SOC topics.`;

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const question = typeof body.question === "string" ? body.question.trim() : "";
    if (!question) {
      return NextResponse.json({ error: "question required" }, { status: 400 });
    }

    const apiKey = getAnthropicKey();
    if (apiKey) {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-sonnet-4-5",
          max_tokens: 1024,
          system: KNOWLEDGE_PROMPT,
          messages: [{ role: "user", content: question }],
        }),
      });

      if (!res.ok) {
        const err = await res.text();
        return NextResponse.json({ error: "LLM failed", detail: err }, { status: 502 });
      }

      const data = await res.json();
      const answer = Array.isArray(data?.content)
        ? data.content
            .filter((block: { type?: string; text?: string }) => block.type === "text")
            .map((block: { text?: string }) => block.text ?? "")
            .join("\n")
            .trim()
        : "No response.";

      return NextResponse.json({ answer });
    }

    const lower = question.toLowerCase();
    let answer = "I'm a SOC knowledge assistant. With an API key I can answer in depth. Here's a short answer: ";
    if (lower.includes("impossible travel")) {
      answer += "Impossible travel means sign-ins from two locations in a time frame that's physically impossible (e.g. US and Russia in 10 minutes). Usually indicates credential compromise or VPN leakage. Investigate: pull sign-in logs, check device tokens, and force sign-out if confirmed.";
    } else if (lower.includes("phishing")) {
      answer += "Phishing investigation: 1) Identify affected users and emails. 2) Check if links were clicked or credentials entered. 3) Revoke sessions and reset passwords for impacted accounts. 4) Hunt for similar emails and compromised mailbox rules.";
    } else if (lower.includes("mitre")) {
      answer += "MITRE ATT&CK is a framework that maps adversary tactics and techniques (e.g. T1078 Valid Accounts, T1566 Phishing). SOCs use it to classify alerts, prioritize by technique, and align response playbooks.";
    } else {
      answer += "Ask about specific alert types (e.g. impossible travel, phishing), investigation steps, or MITRE ATT&CK. Enable an API key for full answers.";
    }
    return NextResponse.json({ answer });
  } catch (e) {
    console.error("knowledge error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
