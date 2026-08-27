import { NextResponse } from "next/server";
import { getAnthropicKey } from "@/lib/openai";

const EXPLAIN_PROMPT = `You are an AI SOC copilot. An analyst asked you to triage an alert, and you gave the response below. Now they want a step-by-step explanation of how you reached that conclusion.

Original alert/incident (user input):
---
{userMessage}
---

Your triage response:
---
{assistantSummary}
---

Respond with a short, numbered list (3–6 steps) explaining your reasoning: what you inferred from the alert, which data sources you considered, why you chose that severity/confidence, and how you arrived at those recommended actions.`;

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

    const apiKey = getAnthropicKey();
    if (apiKey) {
      const content = EXPLAIN_PROMPT.replace("{userMessage}", userMessage).replace(
        "{assistantSummary}",
        assistantSummary,
      );

      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-sonnet-4-5",
          max_tokens: 512,
          messages: [{ role: "user", content }],
        }),
      });

      if (!res.ok) {
        const err = await res.text();
        console.error("Anthropic explain error:", res.status, err);
        return NextResponse.json(
          { error: "Explain request failed", detail: err },
          { status: 502 },
        );
      }

      const data = await res.json();
      const explanation = Array.isArray(data?.content)
        ? data.content
            .filter((block: { type?: string; text?: string }) => block.type === "text")
            .map((block: { text?: string }) => block.text ?? "")
            .join("\n")
            .trim()
        : "";

      return NextResponse.json({
        explanation: explanation || "Could not generate explanation.",
      });
    }

    return NextResponse.json({
      explanation:
        "1. Parsed the alert for keywords (e.g. impossible travel, sign-in, phishing, malware/EDR).\n2. Mapped to an incident type and selected the matching triage template.\n3. Assigned severity based on the rule-based classifier (not connected to an LLM).\n4. Returned recommended actions from the template.\n5. Enable ANTHROPIC_API_KEY for AI-powered explanations.",
    });
  } catch (e) {
    console.error("soc-copilot explain API error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
