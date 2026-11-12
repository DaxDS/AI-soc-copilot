export type IngestPayload = {
  title: string;
  summary: string;
  severity: "Low" | "Medium" | "High" | "Critical" | "Unknown";
  source: string;
  riskScore?: number;
  raw: unknown;
};

export type IngestValidationResult =
  | { ok: true; value: IngestPayload }
  | { ok: false; error: string };

/**
 * Validate and normalize an untrusted SIEM/SOAR webhook payload before it
 * reaches Prisma. Kept framework-free so the boundary can be unit tested.
 */
export function validateIngestPayload(input: unknown): IngestValidationResult {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "payload must be a JSON object" };
  }

  const body = input as Record<string, unknown>;
  const title = typeof body.title === "string" ? body.title.trim() : "";
  if (!title) return { ok: false, error: "title required" };
  if (title.length > 200) {
    return { ok: false, error: "title must be 200 characters or fewer" };
  }

  if (body.summary !== undefined && typeof body.summary !== "string") {
    return { ok: false, error: "summary must be a string" };
  }
  const summary = typeof body.summary === "string" ? body.summary.trim() : "";
  if (summary.length > 10_000) {
    return { ok: false, error: "summary must be 10000 characters or fewer" };
  }

  const allowedSeverities = ["Low", "Medium", "High", "Critical", "Unknown"] as const;
  if (body.severity !== undefined && typeof body.severity !== "string") {
    return { ok: false, error: "severity must be a string" };
  }
  const requestedSeverity =
    typeof body.severity === "string" ? body.severity.trim() : "Unknown";
  if (!allowedSeverities.includes(requestedSeverity as (typeof allowedSeverities)[number])) {
    return { ok: false, error: "severity must be Low, Medium, High, Critical, or Unknown" };
  }

  if (body.source !== undefined && typeof body.source !== "string") {
    return { ok: false, error: "source must be a string" };
  }
  const source = typeof body.source === "string" ? body.source.trim() : "Webhook";
  if (!source) return { ok: false, error: "source cannot be empty" };
  if (source.length > 120) {
    return { ok: false, error: "source must be 120 characters or fewer" };
  }

  let riskScore: number | undefined;
  if (body.riskScore !== undefined) {
    if (typeof body.riskScore !== "number" || !Number.isFinite(body.riskScore)) {
      return { ok: false, error: "riskScore must be a finite number" };
    }
    riskScore = Math.max(0, Math.min(100, Math.round(body.riskScore)));
  }

  return {
    ok: true,
    value: {
      title,
      summary,
      severity: requestedSeverity as IngestPayload["severity"],
      source,
      ...(riskScore !== undefined ? { riskScore } : {}),
      raw: body.raw ?? body,
    },
  };
}
