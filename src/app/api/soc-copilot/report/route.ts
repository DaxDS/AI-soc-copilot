import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auditCaseEvent } from "@/lib/audit";

type MitreTechnique = { id?: string; name?: string };

/** Severity derived only from risk score: 0–30 Low, 31–60 Medium, 61–80 High, 81–100 Critical. */
function getSeverityFromRisk(score: number): "Low" | "Medium" | "High" | "Critical" {
  const s = Math.max(0, Math.min(100, score));
  if (s <= 30) return "Low";
  if (s <= 60) return "Medium";
  if (s <= 80) return "High";
  return "Critical";
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const {
      caseId = "",
      incidentTitle = "Incident",
      incidentSummary = "",
      severity: severityFromBody = "Unknown",
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

    const severity = riskScore != null ? getSeverityFromRisk(riskScore) : severityFromBody;
    const riskLabel = riskScore != null ? getSeverityFromRisk(riskScore) : "—";

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
      riskScore != null ? `Overall risk: **${riskScore}/100** – ${riskLabel}` : "—",
      "",
      "## MITRE ATT&CK Techniques",
      ...(mitreList.length > 0 ? mitreList : ["- None identified."]),
      "",
      "## Affected Assets",
      ...(assetsList.length > 0 ? assetsList : ["- See incident details."]),
      "",
      "## Attack Timeline",
      ...(Array.isArray(timeline) && timeline.length > 0
        ? timeline.map(
            (e: { time?: string; event?: string; rawEvidence?: string }) =>
              [
                `- **${e.time ?? ""}** – ${e.event ?? ""}`,
                e.rawEvidence ? `  - Raw evidence: \`${e.rawEvidence}\`` : "",
              ]
                .filter(Boolean)
                .join("\n"),
          )
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

    if (typeof caseId === "string" && caseId.trim()) {
      const trimmedCaseId = caseId.trim();
      await prisma.report.create({
        data: { caseId: trimmedCaseId, markdown },
      });
      await auditCaseEvent({
        caseId: trimmedCaseId,
        action: "REPORT_GENERATED",
        actor: "system",
        detail: { incidentTitle },
      });
    }

    return NextResponse.json({ markdown });
  } catch (e) {
    console.error("report error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
