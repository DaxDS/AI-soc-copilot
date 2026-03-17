import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auditCaseEvent } from "@/lib/audit";

export async function GET() {
  const cases = await prisma.case.findMany({
    orderBy: { updatedAt: "desc" },
    take: 50,
    select: {
      id: true,
      title: true,
      summary: true,
      severity: true,
      riskScore: true,
      source: true,
      status: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  return NextResponse.json({ cases });
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const title = typeof body.title === "string" ? body.title.trim() : "";
    const summary = typeof body.summary === "string" ? body.summary.trim() : "";
    const severity = typeof body.severity === "string" ? body.severity.trim() : "Unknown";
    const source = typeof body.source === "string" ? body.source.trim() : "Manual";
    const riskScore =
      typeof body.riskScore === "number" && Number.isFinite(body.riskScore)
        ? Math.max(0, Math.min(100, Math.round(body.riskScore)))
        : undefined;

    if (!title) {
      return NextResponse.json({ error: "title required" }, { status: 400 });
    }

    const created = await prisma.case.create({
      data: {
        title,
        summary,
        severity,
        source,
        riskScore,
      },
    });

    await auditCaseEvent({
      caseId: created.id,
      action: "CASE_CREATED",
      actor: "analyst",
      detail: { source },
    });

    return NextResponse.json({ case: created }, { status: 201 });
  } catch (e) {
    console.error("cases POST error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}

