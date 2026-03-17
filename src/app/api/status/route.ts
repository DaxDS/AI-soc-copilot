import { NextResponse } from "next/server";
import { getOpenAIKey } from "@/lib/openai";

export async function GET() {
  return NextResponse.json({
    openaiConfigured: Boolean(getOpenAIKey()),
  });
}
