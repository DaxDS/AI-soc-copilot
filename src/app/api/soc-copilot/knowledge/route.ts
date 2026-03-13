import { NextResponse } from "next/server";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

function getOpenAIKey(): string | undefined {
  if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY;
  try {
    const parentEnv = join(process.cwd(), "..", ".env");
    if (existsSync(parentEnv)) {
      const content = readFileSync(parentEnv, "utf8");
      const match = content.match(/OPENAI_API_KEY\s*=\s*(.+)/m);
      if (match) return match[1].trim().replace(/^["']|["']$/g, "");
    }
  } catch {}
  return undefined;
}

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

    const apiKey = getOpenAIKey();
    if (apiKey) {
      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [
            { role: "system", content: KNOWLEDGE_PROMPT },
            { role: "user", content: question },
          ],
          max_tokens: 1024,
        }),
      });
      if (!res.ok) {
        const err = await res.text();
        return NextResponse.json({ error: "LLM failed", detail: err }, { status: 502 });
      }
      const data = await res.json();
      const answer = data?.choices?.[0]?.message?.content?.trim() ?? "No response.";
      return NextResponse.json({ answer });
    }

    const lower = question.toLowerCase();
    let answer = "I'm a SOC knowledge assistant. With an API key I can answer in depth. Here's a short answer: ";
    if (lower.includes("impossible travel")) {
      answer += "Impossible travel means sign-ins from two locations in a time frame that's physically impossible (e.g. US and Russia in 10 minutes). Usually indicates credential compromise or VPN. Investigate by checking sign-in logs, MFA status, and user activity after the event.";
    } else if (lower.includes("phishing")) {
      answer += "Phishing investigation: 1) Identify affected users and emails. 2) Check if links were clicked or credentials entered. 3) Revoke sessions and reset passwords for impacted accounts. 4) Quarantine the email and block sender/URL. 5) Hunt for mailbox rules or forwarding set by the attacker.";
    } else if (lower.includes("mitre")) {
      answer += "MITRE ATT&CK is a framework that maps adversary tactics and techniques (e.g. T1078 Valid Accounts, T1566 Phishing). SOCs use it to classify alerts, prioritize by technique, and align detection rules.";
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
