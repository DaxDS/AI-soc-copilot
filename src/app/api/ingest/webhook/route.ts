import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auditCaseEvent } from "@/lib/audit";
import { validateIngestPayload } from "@/lib/ingest-validation";

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

    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.toLowerCase().includes("application/json")) {
      return NextResponse.json(
        { error: "content-type must be application/json" },
        { status: 415 },
      );
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json({ error: "invalid JSON body" }, { status: 400 });
    }

    const validation = validateIngestPayload(body);
    if (!validation.ok) {
      return NextResponse.json({ error: validation.error }, { status: 400 });
    }

    const { title, summary, severity, source, riskScore, raw } = validation.value;

    const created = await prisma.$transaction(async (tx) => {
      const incident = await tx.case.create({
        data: { title, summary, severity, source, riskScore },
      });

      await tx.message.create({
        data: {
          caseId: incident.id,
          role: "user",
          content: summary ? `${title}\n\n${summary}` : title,
          metadata: { ingested: true, raw: raw as any },
        },
      });

      await tx.auditEvent.create({
        data: {
          caseId: incident.id,
          action: "CASE_IMPORTED",
          actor: "integration",
          detail: { source },
        },
      });

      return incident;
    });

    return NextResponse.json({ caseId: created.id }, { status: 201 });
  } catch (e) {
    console.error("ingest webhook error:", e);
    return NextResponse.json(
      { error: "failed to ingest alert" },
      { status: 500 },
    );
  }
}
