import assert from "node:assert/strict";
import { test } from "node:test";
import { validateIngestPayload } from "./ingest-validation";

test("normalizes a valid SIEM payload and preserves its raw evidence", () => {
  const raw = { alertId: "INC-42", host: "workstation-7" };
  const result = validateIngestPayload({
    title: "  Suspicious PowerShell  ",
    summary: "  Encoded command observed  ",
    severity: "High",
    source: "  Microsoft Sentinel  ",
    riskScore: 87.6,
    raw,
  });

  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.deepEqual(result.value, {
    title: "Suspicious PowerShell",
    summary: "Encoded command observed",
    severity: "High",
    source: "Microsoft Sentinel",
    riskScore: 88,
    raw,
  });
});

test("rejects null, arrays, and primitive payloads", () => {
  for (const input of [null, [], "alert", 42]) {
    const result = validateIngestPayload(input);
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.error, "payload must be a JSON object");
  }
});

test("requires a non-empty title and enforces its length limit", () => {
  assert.deepEqual(validateIngestPayload({ title: "   " }), {
    ok: false,
    error: "title required",
  });
  assert.equal(validateIngestPayload({ title: "x".repeat(201) }).ok, false);
});

test("rejects invalid optional field types instead of silently coercing them", () => {
  assert.equal(validateIngestPayload({ title: "Alert", summary: 12 }).ok, false);
  assert.equal(validateIngestPayload({ title: "Alert", severity: 3 }).ok, false);
  assert.equal(validateIngestPayload({ title: "Alert", source: false }).ok, false);
  assert.equal(validateIngestPayload({ title: "Alert", riskScore: "90" }).ok, false);
  assert.equal(validateIngestPayload({ title: "Alert", riskScore: Infinity }).ok, false);
});

test("rejects unsupported severities and oversized text fields", () => {
  assert.equal(
    validateIngestPayload({ title: "Alert", severity: "Urgent" }).ok,
    false,
  );
  assert.equal(
    validateIngestPayload({ title: "Alert", summary: "x".repeat(10_001) }).ok,
    false,
  );
  assert.equal(
    validateIngestPayload({ title: "Alert", source: "x".repeat(121) }).ok,
    false,
  );
});

test("clamps finite risk scores to the supported 0-100 range", () => {
  const low = validateIngestPayload({ title: "Alert", riskScore: -12 });
  const high = validateIngestPayload({ title: "Alert", riskScore: 140 });
  assert.equal(low.ok && low.value.riskScore, 0);
  assert.equal(high.ok && high.value.riskScore, 100);
});

test("uses safe defaults when optional fields are omitted", () => {
  const result = validateIngestPayload({ title: "Alert" });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.value.summary, "");
  assert.equal(result.value.severity, "Unknown");
  assert.equal(result.value.source, "Webhook");
});
