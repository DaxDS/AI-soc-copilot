import { NextResponse } from "next/server";

const TIMESTAMP_REGEX = /^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}(?::\d{2})?|\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?)/i;

function parseTimeForSort(timeStr: string): number {
  if (!timeStr || timeStr === "—") return 0;
  const t = timeStr.trim();
  const iso = t.match(/(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2})(?::(\d{2}))?/);
  if (iso) {
    const [, y, mo, d, h, mi, s] = iso;
    return new Date(
      parseInt(y!, 10),
      parseInt(mo!, 10) - 1,
      parseInt(d!, 10),
      parseInt(h!, 10),
      parseInt(mi!, 10),
      parseInt(s ?? "0", 10),
    ).getTime();
  }
  const timeOnly = t.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AP]M))?/i);
  if (timeOnly) {
    let [, h, mi, s, ampm] = timeOnly;
    let hour = parseInt(h!, 10);
    if (ampm) {
      if (ampm.toUpperCase() === "PM" && hour < 12) hour += 12;
      if (ampm.toUpperCase() === "AM" && hour === 12) hour = 0;
    }
    return hour * 3600000 + parseInt(mi!, 10) * 60000 + parseInt(s ?? "0", 10) * 1000;
  }
  return 0;
}

function extractTimestamp(line: string): string | null {
  const match = line.match(TIMESTAMP_REGEX);
  return match ? match[1].trim() : null;
}

const IP_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const HOST_REGEX = /\b(?:[A-Z][A-Z0-9-]{2,}(?:-[A-Z0-9]+)*|PC-[A-Z0-9-]+|WORKSTATION-\d+|SERVER-[A-Z0-9-]+)\b/g;

function extractEntities(line: string): { users: string[]; hosts: string[]; ips: string[]; timeMs: number } {
  const lower = line.toLowerCase();
  const users = [...(line.match(EMAIL_REGEX) ?? [])].map((e) => e.toLowerCase());
  const ips = [...(line.match(IP_REGEX) ?? [])];
  const hosts = [...(line.match(HOST_REGEX) ?? [])].map((h) => h.toUpperCase());
  const ts = extractTimestamp(line);
  const timeMs = ts ? parseTimeForSort(ts) : 0;
  return { users, hosts, ips, timeMs };
}

function unionFind(n: number, areConnected: (i: number, j: number) => boolean): (x: number) => number {
  const parent = Array.from({ length: n }, (_, i) => i);
  const find = (x: number): number => (parent[x] === x ? x : (parent[x] = find(parent[x])));
  const union = (a: number, b: number) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent[ra] = rb;
  };
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) if (areConnected(i, j)) union(i, j);
  return find;
}

const TIME_WINDOW_MS = 24 * 60 * 60 * 1000;

/** Group alerts by shared users, hosts, IPs, or close timestamps; return largest group merged and sorted. */
function correlateAndMerge(alerts: string[]): { merged: string[]; count: number } {
  const entities = alerts.map(extractEntities);
  const n = alerts.length;
  const find = unionFind(n, (i, j) => {
    const a = entities[i];
    const b = entities[j];
    const shareUser = a.users.some((u) => b.users.includes(u));
    const shareHost = a.hosts.some((h) => b.hosts.includes(h));
    const shareIp = a.ips.some((ip) => b.ips.includes(ip));
    const closeTime =
      a.timeMs > 0 && b.timeMs > 0 && Math.abs(a.timeMs - b.timeMs) < TIME_WINDOW_MS;
    return shareUser || shareHost || shareIp || closeTime;
  });
  const rootToIndices = new Map<number, number[]>();
  for (let i = 0; i < n; i++) {
    const r = find(i);
    if (!rootToIndices.has(r)) rootToIndices.set(r, []);
    rootToIndices.get(r)!.push(i);
  }
  const largest = [...rootToIndices.values()].sort((a, b) => b.length - a.length)[0] ?? [];
  const groupLines = largest.map((i) => alerts[i]);
  const withTime = groupLines.map((line) => {
    const ts = extractTimestamp(line);
    return { line, sortKey: ts ? parseTimeForSort(ts) : 0 };
  });
  withTime.sort((a, b) => a.sortKey - b.sortKey);
  return { merged: withTime.map((a) => a.line), count: groupLines.length };
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const alerts = Array.isArray(body.alerts) ? body.alerts : [];
    const trimmed = alerts.map((a: unknown) => String(a).trim()).filter(Boolean);
    if (trimmed.length === 0) {
      return NextResponse.json({ error: "alerts array required" }, { status: 400 });
    }

    const { merged: mergedLogLines, count: correlatedCount } = correlateAndMerge(trimmed);
    const text = trimmed.join(" ").toLowerCase();
    let incidentTitle = "Correlated incident";
    let summary = `${correlatedCount} alert${correlatedCount !== 1 ? "s" : ""} correlated into one attack sequence. `;
    if (text.includes("login") || text.includes("sign-in") || text.includes("impossible travel") || text.includes("mfa")) {
      incidentTitle = "Possible account takeover";
      summary += "Multiple identity-related alerts for the same user or timeframe. Investigate sign-ins, MFA changes, and credential use.";
    } else if (text.includes("phishing") || text.includes("email")) {
      incidentTitle = "Phishing campaign";
      summary += "Email-related alerts. Check delivery, clicks, and compromised accounts.";
    } else if (text.includes("malware") || text.includes("edr") || text.includes("crowdstrike")) {
      incidentTitle = "Malware / EDR activity";
      summary += "Endpoint and malware alerts. Correlate by host, hash, or time.";
    } else if (text.includes("powershell") || text.includes("firewall")) {
      incidentTitle = "Multi-source attack sequence";
      summary += "Alerts from multiple sources merged by shared user, host, or IP. One attack chain reconstructed.";
    } else {
      summary += "Review alerts for common user, host, or time window.";
    }

    return NextResponse.json({
      incidentTitle,
      summary,
      count: correlatedCount,
      mergedLogLines,
      alertIds: trimmed.map((_: string, i: number) => `alert-${i + 1}`),
    });
  } catch (e) {
    console.error("dedupe error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
