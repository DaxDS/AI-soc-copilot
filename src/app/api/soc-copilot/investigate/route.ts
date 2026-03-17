import { NextResponse } from "next/server";

type TimelineEvent = { time: string; event: string; rawEvidence?: string };

/**
 * Parse a timestamp from a log line for sorting.
 * Supports: "2026-03-14 10:12:02", "10:12:02", "02:01 AM", "14:01"
 */
function parseTimeForSort(timeStr: string): number {
  if (!timeStr || timeStr === "—") return 0;
  const trimmed = timeStr.trim();
  // ISO-like: 2026-03-14 10:12:02 or 2026-03-14T10:12:02
  const iso = trimmed.match(/(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2})(?::(\d{2}))?/);
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
  // Time only: 10:12:02 or 02:01 AM
  const timeOnly = trimmed.match(/(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AP]M))?/i);
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

/**
 * Normalize extracted timestamp to time-only for display (strip date portion).
 * e.g. "2026-03-15 15:10:11" -> "15:10:11", "02:01 AM" -> "02:01 AM"
 */
function timeOnlyForDisplay(timeStr: string): string {
  if (!timeStr || timeStr === "—") return "—";
  const t = timeStr.trim();
  const withDate = t.match(/\d{4}-\d{2}-\d{2}[T\s](\d{2}:\d{2}(?::\d{2})?)/i);
  if (withDate) return withDate[1]!;
  const timeOnly = t.match(/(\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?)/i);
  return timeOnly ? timeOnly[1]! : t;
}

/**
 * Build timeline from actual log lines. Splits by timestamp pattern so each log entry
 * is a separate event. For each entry:
 * - time: HH:MM:SS (date stripped)
 * - event: remaining message after timestamp
 * - rawEvidence: full log line
 * Events are sorted by timestamp.
 */
function buildTimelineFromLines(logLines: string[]): TimelineEvent[] {
  const timestampPattern = /(?=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/;
  const entries = (logLines as string[])
    .filter((l) => typeof l === "string" && l.trim())
    .flatMap((line) => {
      const trimmed = line.trim();
      const split = trimmed.split(timestampPattern).map((s) => s.trim()).filter(Boolean);
      return split.length > 1 ? split : [trimmed];
    });
  const timeRegex = /^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}(?::\d{2})?|\d{1,2}:\d{2}(?::\d{2})?(?:\s*[AP]M)?)\s+/i;
  const events: TimelineEvent[] = entries.map((line) => {
    const match = line.match(timeRegex);
    let time = "—";
    let eventDesc = line;
    if (match) {
      time = timeOnlyForDisplay(match[1]!);
      eventDesc = line.slice(match[0]!.length).trim();
      if (!eventDesc) eventDesc = line;
    }
    return {
      time,
      event: eventDesc,
      rawEvidence: line,
    };
  });
  events.sort((a, b) => parseTimeForSort(a.time) - parseTimeForSort(b.time));
  return events;
}

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const userMessage = typeof body.userMessage === "string" ? body.userMessage : "";
    const logLines = Array.isArray(body.logLines)
      ? (body.logLines as string[]).filter((l) => typeof l === "string")
      : [];

    if (!userMessage.trim()) {
      return NextResponse.json(
        { error: "userMessage required" },
        { status: 400 },
      );
    }

    // Always build timeline from provided log lines when present; otherwise return empty
    // so the UI never shows a static mock timeline.
    const timeline =
      logLines.length > 0
        ? buildTimelineFromLines(logLines)
        : [];

    const graphNodes = [
      { id: "0", label: "Source" },
      ...timeline.map((e, i) => ({ id: String(i + 1), label: e.event })),
    ];

    return NextResponse.json({ timeline, graphNodes });
  } catch (e) {
    console.error("investigate API error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
