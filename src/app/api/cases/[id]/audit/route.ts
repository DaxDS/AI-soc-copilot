import { NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string }> },
) {
  const { id: caseId } = await params;
  const events = await prisma.auditEvent.findMany({
    where: { caseId },
    orderBy: { createdAt: "desc" },
    take: 200,
  });
  return NextResponse.json({ events });
}

