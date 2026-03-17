import { prisma } from "@/lib/db";
import type { AuditAction } from "@prisma/client";

export async function auditCaseEvent(params: {
  caseId: string;
  action: AuditAction;
  actor: "system" | "analyst" | "integration";
  detail?: unknown;
}) {
  const { caseId, action, actor, detail } = params;
  await prisma.auditEvent.create({
    data: {
      caseId,
      action,
      actor,
      detail: detail == null ? undefined : (detail as any),
    },
  });
}

