export function getAnthropicKey(): string | undefined {
  const key = process.env.ANTHROPIC_API_KEY;
  return typeof key === "string" && key.trim() ? key.trim() : undefined;
}
