import { NextResponse } from "next/server";

type MitreTechnique = { id?: string; name?: string };

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      incidentTitle = "Incident",
      incidentSummary = "",
      severity = "Unknown",
      riskScore,
      timeline = [],
      actionsTaken = [],
      triageSummary = "",
      mitreTechniques = [],
      recommendedActions = [],
      affectedAssets = [],
    } = body;

    const mitreList = Array.isArray(mitreTechniques)
      ? (mitreTechniques as MitreTechnique[]).map((t) => `- **${t.id ?? "—"}** – ${t.name ?? "—"}`)
      : [];
    const recommendedList = Array.isArray(recommendedActions)
      ? (recommendedActions as { label?: string; risk?: string }[]).map(
          (a) => `- ${a.label ?? ""} (Risk: ${a.risk ?? "—"})`
        )
      : [];
    const assetsList = Array.isArray(affectedAssets)
      ? (affectedAssets as string[]).map((a) => `- ${a}`)
      : [];

    const lines: string[] = [
      "# Investigation Report",
      "",
      "## Incident Summary",
      `**Title:** ${incidentTitle}`,
      `**Severity:** ${severity}`,
      riskScore != null ? `**Risk Score:** ${riskScore}/100` : "",
      "",
      incidentSummary ? "**Context:**" : "",
      incidentSummary || "",
      "",
      "## Risk Score",
      riskScore != null
        ? `Overall risk: **${riskScore}/100** – ${riskScore >= 70 ? "High" : riskScore >= 40 ? "Medium" : "Low"}`
        : "—",
      "",
      "## MITRE ATT&CK Techniques",
      ...(mitreList.length > 0 ? mitreList : ["- None identified."]),
      "",
      "## Affected Assets",
      ...(assetsList.length > 0 ? assetsList : ["- See incident details."]),
      "",
      "## Attack Timeline",
      ...(Array.isArray(timeline) && timeline.length > 0
        ? timeline.map((e: { time?: string; event?: string }) => `- **${e.time ?? ""}** – ${e.event ?? ""}`)
        : ["- No timeline available."]),
      "",
      "## Triage Summary",
      triageSummary || "—",
      "",
      "## Recommended Response Actions",
      ...(recommendedList.length > 0 ? recommendedList : ["- None specified."]),
      "",
      "## Actions Taken",
      ...(Array.isArray(actionsTaken) && actionsTaken.length > 0
        ? actionsTaken.map((a: string) => `- ${a}`)
        : ["- None recorded."]),
      "",
      "---",
      `*Report generated at ${new Date().toISOString()} by AI SOC Copilot*`,
    ];

    const markdown = lines.filter(Boolean).join("\n");
    return NextResponse.json({ markdown });
  } catch (e) {
    console.error("report error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
