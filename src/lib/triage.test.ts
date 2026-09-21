import assert from "node:assert/strict";
import { test } from "node:test";
import { parseLlmTriage, severityFromRisk } from "./triage";

const critical = `## Assessment
This is a supply chain compromise.

\`\`\`soc-json
{
  "severity": "Critical",
  "confidence": 0.95,
  "riskScore": 95,
  "evidence": ["litellm_init.pth dropped in site-packages", "outbound POST to unknown host"],
  "mitreTechniques": [{"id":"T1195.001","name":"Compromise Software Dependencies and Development Tools"}],
  "recommendedActions": [{"label":"Isolate the build host","risk":"High","requiresApproval":true}]
}
\`\`\``;

test("critical verdict is carried through, not flattened to Medium/50", () => {
  const r = parseLlmTriage(critical);
  assert.equal(r.structured.severity, "Critical");
  assert.equal(r.structured.riskScore, 95);
  assert.equal(r.structured.confidence, 0.95);
  assert.equal(r.structured.mitreTechniques.length, 1);
  assert.equal(r.structured.recommendedActions[0].requiresApproval, true);
  assert.ok(!r.prose.includes("soc-json"), "fence must be stripped from prose");
  assert.ok(r.prose.includes("supply chain"));
});

test("benign verdict stays Low with high confidence", () => {
  const r = parseLlmTriage(`Approved change CHG-44817 explains the egress.

\`\`\`soc-json
{"severity":"Low","confidence":0.9,"riskScore":12,"evidence":["change ticket CHG-44817 approved"],"mitreTechniques":[],"recommendedActions":[{"label":"Close as benign","risk":"Low","requiresApproval":false}]}
\`\`\``);
  assert.equal(r.structured.severity, "Low");
  assert.equal(r.structured.riskScore, 12);
  assert.equal(r.structured.confidence, 0.9);
  assert.equal(r.structured.recommendedActions[0].requiresApproval, false);
});

test("severity and score disagreeing: severity wins, score snaps into band", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"severity":"Critical","riskScore":50}\n```');
  assert.equal(r.structured.severity, "Critical");
  assert.equal(severityFromRisk(r.structured.riskScore), "Critical");
});

test("severity given without a score gets a representative score", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"severity":"High"}\n```');
  assert.equal(severityFromRisk(r.structured.riskScore), "High");
});

test("score given without a severity derives the severity", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"riskScore":88}\n```');
  assert.equal(r.structured.severity, "Critical");
  assert.equal(r.structured.riskScore, 88);
});

test("plain ```json fence is accepted", () => {
  const r = parseLlmTriage('x\n```json\n{"severity":"High","riskScore":70}\n```');
  assert.equal(r.structured.severity, "High");
});

test("unfenced trailing JSON object is accepted", () => {
  const r = parseLlmTriage('Analysis text here.\n{"severity":"Medium","riskScore":45}');
  assert.equal(r.structured.severity, "Medium");
  assert.ok(r.prose.startsWith("Analysis"));
  assert.ok(!r.prose.includes("severity"));
});

test("confidence given as a percentage is normalised", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"severity":"High","confidence":95}\n```');
  assert.equal(r.structured.confidence, 0.95);
});

test("out-of-range values are clamped", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"riskScore":480,"confidence":-2}\n```');
  assert.equal(r.structured.riskScore, 100);
  assert.equal(r.structured.confidence, 0);
});

test("missing block returns null so the caller falls back", () => {
  const r = parseLlmTriage("Just prose, no structured verdict at all.");
  assert.equal(r.structured, null);
  assert.equal(r.prose, "Just prose, no structured verdict at all.");
});

test("malformed JSON returns null rather than throwing", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"severity": "Critical",,,}\n```');
  assert.equal(r.structured, null);
});

test("truncated response (fence never closed) returns null, prose preserved", () => {
  const r = parseLlmTriage('Section 3. Forensic Collection\n```soc-json\n{"severity":"Cri');
  assert.equal(r.structured, null);
  assert.ok(r.prose.includes("Forensic Collection"));
});

test("bogus severity string is rejected, not passed to the UI", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"severity":"CATASTROPHIC"}\n```');
  assert.equal(r.structured.severity, undefined);
  assert.equal(r.structured.riskScore, undefined);
});

test("string recommendedActions are normalised to objects needing approval", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"severity":"High","recommendedActions":["Isolate host"]}\n```');
  assert.deepEqual(r.structured.recommendedActions[0], {
    label: "Isolate host", risk: "Medium", requiresApproval: true,
  });
});

test("malformed mitre entries are dropped, good ones kept", () => {
  const r = parseLlmTriage('x\n```soc-json\n{"severity":"High","mitreTechniques":[{"id":"T1059.006","name":"Python"},"garbage",{"name":"no id"}]}\n```');
  assert.equal(r.structured.mitreTechniques.length, 1);
  assert.equal(r.structured.mitreTechniques[0].id, "T1059.006");
});

test("prose containing an unrelated code block is not mistaken for the verdict", () => {
  const r = parseLlmTriage('Run this:\n```bash\ncat /etc/passwd\n```\nVerdict below.\n```soc-json\n{"severity":"Low","riskScore":10}\n```');
  assert.equal(r.structured.severity, "Low");
  assert.ok(r.prose.includes("cat /etc/passwd"));
});

test("severity band boundaries match the UI mapping", () => {
  assert.equal(severityFromRisk(30), "Low");
  assert.equal(severityFromRisk(31), "Medium");
  assert.equal(severityFromRisk(60), "Medium");
  assert.equal(severityFromRisk(61), "High");
  assert.equal(severityFromRisk(80), "High");
  assert.equal(severityFromRisk(81), "Critical");
});

test("two opposite inputs do not produce the same output (the original bug)", () => {
  const a = parseLlmTriage(critical).structured;
  const b = parseLlmTriage('x\n```soc-json\n{"severity":"Low","confidence":0.9,"riskScore":12}\n```').structured;
  assert.notEqual(a.severity, b.severity);
  assert.notEqual(a.riskScore, b.riskScore);
  assert.notEqual(a.confidence, b.confidence);
});
