import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const alerts = Array.isArray(body.alerts) ? body.alerts : [];
    const trimmed = alerts.map((a: unknown) => String(a).trim()).filter(Boolean);
    if (trimmed.length === 0) {
      return NextResponse.json({ error: "alerts array required" }, { status: 400 });
    }

    const text = trimmed.join(" ").toLowerCase();
    let incidentTitle = "Grouped incident";
    let summary = `${trimmed.length} alerts grouped. `;
    if (text.includes("login") || text.includes("sign-in") || text.includes("impossible travel") || text.includes("mfa")) {
      incidentTitle = "Possible account takeover";
      summary += "Multiple identity-related alerts for the same user or timeframe. Investigate sign-ins, MFA changes, and credential use.";
    } else if (text.includes("phishing") || text.includes("email")) {
      incidentTitle = "Phishing campaign";
      summary += "Email-related alerts. Check delivery, clicks, and compromised accounts.";
    } else if (text.includes("malware") || text.includes("edr")) {
      incidentTitle = "Malware / EDR activity";
      summary += "Endpoint and malware alerts. Correlate by host, hash, or time.";
    } else {
      summary += "Review alerts for common user, host, or time window.";
    }

    return NextResponse.json({
      incidentTitle,
      summary,
      count: trimmed.length,
      alertIds: trimmed.map((_: string, i: number) => `alert-${i + 1}`),
    });
  } catch (e) {
    console.error("dedupe error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
