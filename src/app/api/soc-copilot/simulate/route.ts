import { NextResponse } from "next/server";

const SCENARIOS: Record<string, { title: string; alerts: string[]; timeline: { time: string; event: string }[] }> = {
  phishing: {
    title: "Phishing attack simulation",
    alerts: [
      "Microsoft Defender: User clicked link in phishing email (finance@company.com).",
      "Azure AD: New sign-in from unknown IP for user finance@company.com.",
      "Defender for Office: Mailbox rule created to forward messages to external address.",
    ],
    timeline: [
      { time: "09:00 AM", event: "Phishing email delivered" },
      { time: "09:05 AM", event: "User clicked link" },
      { time: "09:08 AM", event: "Credentials entered on fake page" },
      { time: "09:12 AM", event: "Attacker sign-in from new IP" },
      { time: "09:15 AM", event: "Mailbox rule created" },
    ],
  },
  credential_theft: {
    title: "Credential theft simulation",
    alerts: [
      "Sentinel: Impossible travel – user admin@company.com from US and Russia within 15 min.",
      "Azure AD: MFA method changed (SMS added).",
      "SharePoint: Large file download (500+ files) by admin@company.com.",
    ],
    timeline: [
      { time: "02:00 AM", event: "Suspicious login from Russia" },
      { time: "02:03 AM", event: "MFA method changed" },
      { time: "02:10 AM", event: "Bulk file download started" },
      { time: "02:25 AM", event: "Sign-in from second country" },
    ],
  },
  malware: {
    title: "Malware infection simulation",
    alerts: [
      "CrowdStrike: Suspicious process (powershell.exe) on WORKSTATION-07.",
      "CrowdStrike: File dropped in AppData – hash flagged as malware.",
      "CrowdStrike: Outbound connection to known C2 IP 185.220.101.45.",
    ],
    timeline: [
      { time: "11:00 AM", event: "Suspicious PowerShell execution" },
      { time: "11:01 AM", event: "Malicious file dropped" },
      { time: "11:02 AM", event: "C2 connection established" },
      { time: "11:05 AM", event: "Lateral movement attempt" },
    ],
  },
};

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const id = searchParams.get("scenario") ?? "phishing";
  const scenario = SCENARIOS[id] ?? SCENARIOS.phishing;
  return NextResponse.json(scenario);
}

export async function POST(request: Request) {
  return GET(request);
}
