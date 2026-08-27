import { NextResponse } from "next/server";
import { getAnthropicKey } from "@/lib/openai";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const query = typeof body.query === "string" ? body.query.trim() : "";
    if (!query) {
      return NextResponse.json({ error: "query required" }, { status: 400 });
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
          max_tokens: 512,
          system: `You are a SOC analyst assistant. Convert the user's natural language question into SIEM queries. Respond with a JSON object only, no markdown, with two keys: "kql" (Microsoft Kusto Query Language / Azure Sentinel) and "spl" (Splunk Query Language). Base the queries on common SOC patterns.`,
          messages: [{ role: "user", content: query }],
        }),
      });

      if (!res.ok) {
        const err = await res.text();
        return NextResponse.json({ error: "LLM failed", detail: err }, { status: 502 });
      }

      const data = await res.json();
      const content = Array.isArray(data?.content)
        ? data.content
            .filter((block: { type?: string; text?: string }) => block.type === "text")
            .map((block: { text?: string }) => block.text ?? "")
            .join("\n")
            .trim()
        : "";

      try {
        const parsed = JSON.parse(content.replace(/```json\n?|\n?```/g, ""));
        return NextResponse.json({
          kql: parsed.kql ?? "// Could not generate",
          spl: parsed.spl ?? "// Could not generate",
        });
      } catch {
        return NextResponse.json({
          kql: "// Generated: " + content.slice(0, 200),
          spl: "// Use same logic in Splunk",
        });
      }
    }

    const lower = query.toLowerCase();
    let kql = "SigninLogs | where TimeGenerated > ago(24h)";
    let spl = "index=main sourcetype=signin | where _time > relative_time(now(), \"-24h\")";
    if (lower.includes("suspicious") || lower.includes("login")) {
      kql = "SigninLogs | where TimeGenerated > ago(24h) | where ResultType != 0 or Location != \"\"";
      spl = "index=main sourcetype=signin | where _time > relative_time(now(), \"-24h\") | search result!=0 OR location=*";
    }
    if (lower.includes("malware") || lower.includes("detect")) {
      kql = "CommonSecurityLog | where TimeGenerated > ago(24h) | where DeviceAction contains \"Malware\"";
      spl = "index=main sourcetype=edr | where _time > relative_time(now(), \"-24h\") | search action=*malware*";
    }
    if (lower.includes("file") || lower.includes("download")) {
      kql = "CommonSecurityLog | where TimeGenerated > ago(24h) | where Activity contains \"Download\"";
      spl = "index=main | where _time > relative_time(now(), \"-24h\") | search activity=*download*";
    }
    return NextResponse.json({ kql, spl });
  } catch (e) {
    console.error("nl-query error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
