import { NextResponse } from "next/server";
import { getAnthropicKey } from "@/lib/openai";

export async function GET() {
  return NextResponse.json({
    anthropicConfigured: Boolean(getAnthropicKey()),
  });
}
