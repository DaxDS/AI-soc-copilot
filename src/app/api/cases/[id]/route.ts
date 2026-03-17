import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auditCaseEvent } from "@/lib/audit";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id } = await params;
  const c = await prisma.case.findUnique({
    where: { id },
    include: {
      messages: { orderBy: { createdAt: "asc" }, take: 200 },
      reports: { orderBy: { createdAt: "desc" }, take: 10 },
    },
  });
  if (!c) return NextResponse.json({ error: "case not found" }, { status: 404 });
  return NextResponse.json({ case: c });
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id } = await params;
    const body = await request.json();

    const status =
      body.status === "NEW" || body.status === "UNDER_REVIEW" || body.status === "RESOLVED"
        ? body.status
        : undefined;
    const title = typeof body.title === "string" ? body.title.trim() : undefined;
    const summary = typeof body.summary === "string" ? body.summary.trim() : undefined;

    const updated = await prisma.case.update({
      where: { id },
      data: {
        ...(status ? { status } : {}),
        ...(title != null ? { title } : {}),
        ...(summary != null ? { summary } : {}),
      },
    });

    if (status) {
      await auditCaseEvent({
        caseId: id,
        action: "CASE_STATUS_CHANGED",
        actor: "analyst",
        detail: { status },
      });
    }

    return NextResponse.json({ case: updated });
  } catch (e) {
    console.error("case PATCH error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}

