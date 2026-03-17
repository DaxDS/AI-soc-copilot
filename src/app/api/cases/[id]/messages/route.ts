import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auditCaseEvent } from "@/lib/audit";

export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  try {
    const { id: caseId } = await params;
    const body = await request.json();
    const role =
      body.role === "user" || body.role === "assistant" ? body.role : undefined;
    const content = typeof body.content === "string" ? body.content.trim() : "";
    const metadata = body.metadata ?? undefined;

    if (!role || !content) {
      return NextResponse.json(
        { error: "role and content required" },
        { status: 400 },
      );
    }

    const msg = await prisma.message.create({
      data: { caseId, role, content, metadata },
    });

    await auditCaseEvent({
      caseId,
      action: "MESSAGE_ADDED",
      actor: "analyst",
      detail: { role },
    });

    return NextResponse.json({ message: msg }, { status: 201 });
  } catch (e) {
    console.error("case messages POST error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}

