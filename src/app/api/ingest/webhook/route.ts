import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auditCaseEvent } from "@/lib/audit";

function unauthorized() {
  return NextResponse.json({ error: "unauthorized" }, { status: 401 });
}

export async function POST(request: Request) {
  try {
    const secret = process.env.INGEST_WEBHOOK_SECRET?.trim();
    if (!secret) {
      return NextResponse.json(
        { error: "INGEST_WEBHOOK_SECRET not configured" },
        { status: 503 },
      );
    }

    const auth = request.headers.get("authorization") ?? "";
    const token = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
    if (token !== secret) return unauthorized();

    const body = await request.json();
    const title = typeof body.title === "string" ? body.title.trim() : "";
    const summary = typeof body.summary === "string" ? body.summary.trim() : "";
    const severity = typeof body.severity === "string" ? body.severity.trim() : "Unknown";
    const source = typeof body.source === "string" ? body.source.trim() : "Webhook";
    const riskScore =
      typeof body.riskScore === "number" && Number.isFinite(body.riskScore)
        ? Math.max(0, Math.min(100, Math.round(body.riskScore)))
        : undefined;
    const raw = body.raw ?? body;

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

    await prisma.message.create({
      data: {
        caseId: created.id,
        role: "user",
        content: summary ? `${title}\n\n${summary}` : title,
        metadata: { ingested: true, raw },
      },
    });

    await auditCaseEvent({
      caseId: created.id,
      action: "CASE_IMPORTED",
      actor: "integration",
      detail: { source },
    });

    return NextResponse.json({ caseId: created.id }, { status: 201 });
  } catch (e) {
    console.error("ingest webhook error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}

