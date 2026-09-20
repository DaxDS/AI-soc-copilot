// Structured-verdict parsing for the SOC copilot LLM branch.
// Kept out of the route handler so it can be unit-tested without Next/Prisma.

export const SEVERITIES = ["Low", "Medium", "High", "Critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function severityFromRisk(score: number): Severity {
  if (score <= 30) return "Low";
  if (score <= 60) return "Medium";
  if (score <= 80) return "High";
  return "Critical";
}

function clamp(n: number, lo: number, hi: number) {
  return Math.min(hi, Math.max(lo, n));
}

export type MitreTechnique = { id: string; name: string };
export type RecommendedAction = {
  label: string;
  risk: "Low" | "Medium" | "High";
  requiresApproval: boolean;
};
export type StructuredTriage = {
  severity?: Severity;
  confidence?: number;
  riskScore?: number;
  evidence: string[];
  mitreTechniques: MitreTechnique[];
  recommendedActions: RecommendedAction[];
};

export type ParsedTriage = {
  prose: string;
  structured: StructuredTriage | null;
};

/**
 * Splits the model's reply into the analyst-facing prose and the structured
 * verdict it was asked to append. Returns structured: null when the block is
 * absent or unparseable, so the caller can fall back to rule-based triage
 * instead of shipping hardcoded placeholder values.
 */
export function parseLlmTriage(content: string): ParsedTriage {
  const fence =
    /```(?:soc-json|json)?\s*(\{[\s\S]*?\})\s*```\s*$/.exec(content) ??
    /```(?:soc-json|json)?\s*(\{[\s\S]*?\})\s*```/.exec(content);

  let raw: string | null = fence ? fence[1] : null;
  let prose = fence ? content.replace(fence[0], "").trim() : content.trim();

  // Model omitted the fence but still emitted a trailing JSON object.
  if (!raw) {
    const start = content.lastIndexOf("{");
    if (start !== -1 && content.slice(start).includes('"severity"')) {
      raw = content.slice(start);
      prose = content.slice(0, start).trim();
    }
  }

  if (!raw) return { prose, structured: null };

  let obj: any;
  try {
    obj = JSON.parse(raw);
  } catch {
    return { prose: content.trim(), structured: null };
  }
  if (!obj || typeof obj !== "object") {
    return { prose: content.trim(), structured: null };
  }

  const riskScore =
    typeof obj.riskScore === "number" && Number.isFinite(obj.riskScore)
      ? clamp(Math.round(obj.riskScore), 0, 100)
      : null;

  const severity: Severity | null = SEVERITIES.includes(obj.severity)
    ? obj.severity
    : riskScore !== null
      ? severityFromRisk(riskScore)
      : null;

  // If the model gave a severity but no score, derive a representative score so
  // the UI chip (which maps score -> severity) agrees with the stated verdict.
  const scoreBySeverity: Record<Severity, number> = {
    Low: 20,
    Medium: 50,
    High: 72,
    Critical: 92,
  };
  const resolvedScore =
    riskScore !== null
      ? riskScore
      : severity
        ? scoreBySeverity[severity]
        : null;

  // Guard against the model contradicting itself (e.g. "Critical" + score 50).
  // The stated severity wins; the score is snapped into its band so the UI chip,
  // which derives severity from the score, agrees with the written verdict.
  const resolvedSeverity: Severity | null = severity;
  const finalScore =
    resolvedSeverity !== null &&
    (resolvedScore === null || severityFromRisk(resolvedScore) !== resolvedSeverity)
      ? scoreBySeverity[resolvedSeverity]
      : resolvedScore;

  let confidence: number | null = null;
  if (typeof obj.confidence === "number" && Number.isFinite(obj.confidence)) {
    const rawConfidence: number =
      obj.confidence > 1 ? obj.confidence / 100 : obj.confidence;
    confidence = clamp(rawConfidence, 0, 1);
  }

  const mitreTechniques: MitreTechnique[] = Array.isArray(obj.mitreTechniques)
    ? obj.mitreTechniques
        .map((t: any) =>
          t && typeof t.id === "string"
            ? { id: t.id.trim(), name: String(t.name ?? "").trim() }
            : null,
        )
        .filter(Boolean)
    : [];

  const recommendedActions: RecommendedAction[] =
    Array.isArray(obj.recommendedActions)
      ? obj.recommendedActions
          .map((a: any) => {
            if (typeof a === "string") {
              return { label: a, risk: "Medium" as const, requiresApproval: true };
            }
            if (!a || typeof a.label !== "string") return null;
            const risk = ["Low", "Medium", "High"].includes(a.risk)
              ? a.risk
              : "Medium";
            return {
              label: a.label,
              risk,
              requiresApproval: a.requiresApproval !== false,
            };
          })
          .filter(Boolean)
      : [];

  const evidence: string[] = Array.isArray(obj.evidence)
    ? obj.evidence.filter((e: any) => typeof e === "string" && e.trim()).map((e: string) => e.trim())
    : [];

  return {
    prose: prose || content.trim(),
    structured: {
      severity: resolvedSeverity ?? undefined,
      confidence: confidence ?? undefined,
      riskScore: finalScore ?? undefined,
      mitreTechniques,
      recommendedActions,
      evidence,
    },
  };
}

