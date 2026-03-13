import { NextResponse } from "next/server";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const ioc = typeof body.ioc === "string" ? body.ioc.trim() : "";
    if (!ioc) {
      return NextResponse.json({ error: "ioc required" }, { status: 400 });
    }
    const looksLikeIP = /^[\d.]+$/.test(ioc) || /^[a-fA-F0-9.:]+$/.test(ioc);
    const looksLikeHash = /^[a-fA-F0-9]{32,64}$/.test(ioc);
    const looksLikeDomain = /\./.test(ioc) && !looksLikeIP;

    let type: "ip" | "domain" | "hash" = "ip";
    if (looksLikeHash) type = "hash";
    else if (looksLikeDomain) type = "domain";
    else if (looksLikeIP) type = "ip";

    const mockReputation = (s: string) => {
      const n = s.split("").reduce((a, c) => a + c.charCodeAt(0), 0);
      return n % 3 === 0 ? "Malicious" : n % 3 === 1 ? "Suspicious" : "Clean";
    };
    const mockCountry = (s: string) => {
      const countries = ["Germany", "Russia", "Netherlands", "United States", "China"];
      return countries[s.length % countries.length];
    };

    const reputation = mockReputation(ioc);
    const country = type === "ip" ? mockCountry(ioc) : undefined;
    const association = reputation === "Malicious" ? "TOR exit node / C2" : reputation === "Suspicious" ? "Proxy / VPN" : undefined;

    return NextResponse.json({
      ioc,
      type,
      reputation,
      country,
      association,
      sources: ["VirusTotal (mock)", "AbuseIPDB (mock)", "ThreatFox (mock)"],
    });
  } catch (e) {
    console.error("threat-intel error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Server error" },
      { status: 500 },
    );
  }
}
