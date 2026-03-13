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
  } catch {
    // ignore
  }
  return undefined;
}

const EXPLAIN_PROMPT = `You are an AI SOC copilot. An analyst asked you to triage an alert, and you gave the response below. Now they want a step-by-step explanation of how you reached that conclusion.

Original alert/incident (user input):
---
{userMessage}
---

Your triage response:
---
{assistantSummary}
---

Respond with a short, numbered list (3–6 steps) explaining your reasoning: what you inferred from the alert, which data sources you considered, why you chose that severity/confidence, and how you decided on the recommended actions. Be concise and technical.`;

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const userMessage = typeof body.userMessage === "string" ? body.userMessage : "";
    const assistantSummary = typeof body.assistantSummary === "string" ? body.assistantSummary : "";

    if (!userMessage || !assistantSummary) {
      return NextResponse.json(
        { error: "userMessage and assistantSummary required" },
        { status: 400 },
      );
    }

    const apiKey = getOpenAIKey();
    if (apiKey) {
      const content = EXPLAIN_PROMPT.replace("{userMessage}", userMessage).replace(
        "{assistantSummary}",
        assistantSummary,
      );
      const res = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: "gpt-4o-mini",
          messages: [{ role: "user", content }],
          max_tokens: 512,
        }),
      });
      if (!res.ok) {
        const err = await res.text();
        console.error("OpenAI explain error:", res.status, err);
        return NextResponse.json(
          { error: "Explain request failed", detail: err },
          { status: 502 },
        );
      }
      const data = await res.json();
      const explanation = data?.choices?.[0]?.message?.content?.trim();
      return NextResponse.json({
        explanation: explanation || "Could not generate explanation.",
      });
    }

    return NextResponse.json({
      explanation:
        "1. Parsed the alert for keywords (e.g. impossible travel, sign-in, phishing, malware/EDR).\n2. Mapped to an incident type and selected the matching triage template.\n3. Assigned severity and confidence from that template and listed evidence sources.\n4. Recommended actions were chosen by risk level and approval requirements for that type.\n(Enable an API key for a full, model-generated step-by-step explanation.)",
    });
  } catch (e) {
    console.error("soc-copilot explain API error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
