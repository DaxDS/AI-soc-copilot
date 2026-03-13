import { NextResponse } from "next/server";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

function getOpenAIKey(): string | undefined {
  if (process.env.OPENAI_API_KEY) return process.env.OPENAI_API_KEY;
  try {
    const parentEnv = join(process.cwd(), "..", ".env");
    if (existsSync(parentEnv)) {
      const content = readFileSync(parentEnv, "utf8");
      const match = content.match(/OPENAI_API_KEY\s*=\s*(.+)/m);
      if (match) return match[1].trim().replace(/^["']|["']$/g, "");
    }
  } catch {
    // ignore
  }
  return undefined;
}

export async function GET() {
  return NextResponse.json({
    openaiConfigured: Boolean(getOpenAIKey()),
  });
}
