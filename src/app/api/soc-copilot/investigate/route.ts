import { NextResponse } from "next/server";

type TimelineEvent = { time: string; event: string };

function mockTimeline(alertSummary: string): TimelineEvent[] {
  const lower = alertSummary.toLowerCase();
  if (
    lower.includes("impossible travel") ||
    lower.includes("sign-in") ||
    lower.includes("signin") ||
    lower.includes("login") ||
    lower.includes("suspicious login")
  ) {
    return [
      { time: "02:01 AM", event: "Login from unusual location (Russia)" },
      { time: "02:03 AM", event: "New MFA device added" },
      { time: "02:05 AM", event: "SharePoint files downloaded (12 files)" },
      { time: "02:07 AM", event: "Bulk emails sent to 50 internal users" },
      { time: "02:12 AM", event: "Sign-in from second country (Germany)" },
    ];
  }
  if (lower.includes("phishing") || lower.includes("email")) {
    return [
      { time: "01:15 AM", event: "Phishing email delivered to mailbox" },
      { time: "01:18 AM", event: "Link clicked by user" },
      { time: "01:22 AM", event: "Credential entered on fake login page" },
      { time: "01:25 AM", event: "Sign-in from new IP (attacker)" },
      { time: "01:28 AM", event: "Mailbox rule created to forward messages" },
    ];
  }
  if (
    lower.includes("malware") ||
    lower.includes("edr") ||
    lower.includes("ransomware") ||
    lower.includes("c2")
  ) {
    return [
      { time: "03:00 AM", event: "Suspicious process started (powershell.exe)" },
      { time: "03:01 AM", event: "Executable dropped in AppData" },
      { time: "03:02 AM", event: "Outbound connection to unknown IP (C2)" },
      { time: "03:05 AM", event: "Lateral movement attempt (SMB)" },
      { time: "03:08 AM", event: "Registry persistence key created" },
    ];
  }
  return [
    { time: "00:00 AM", event: "Initial alert generated" },
    { time: "00:02 AM", event: "Related events under investigation" },
    { time: "—", event: "Connect SIEM/EDR for full attack chain" },
  ];
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const userMessage = typeof body.userMessage === "string" ? body.userMessage : "";
    if (!userMessage.trim()) {
      return NextResponse.json(
        { error: "userMessage required" },
        { status: 400 },
      );
    }
    const timeline = mockTimeline(userMessage);
    const graphNodes = [
      { id: "0", label: "Attacker / Source" },
      ...timeline.map((e, i) => ({ id: String(i + 1), label: e.event })),
    ];
    return NextResponse.json({ timeline, graphNodes });
  } catch (e) {
    console.error("investigate API error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
