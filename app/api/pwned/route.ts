import { NextResponse } from "next/server";

export const runtime = "nodejs";

export async function POST(request: Request) {
  const body = await request.json().catch(() => null) as { prefix?: string } | null;
  const prefix = body?.prefix?.toUpperCase() ?? "";

  if (!/^[0-9A-F]{5}$/.test(prefix)) {
    return NextResponse.json({ error: "Invalid SHA-1 prefix" }, { status: 400 });
  }

  const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
    headers: { "User-Agent": "Sentinel-Pass/2.1 (password-security-tool)" },
    cache: "no-store",
  });

  if (!response.ok) {
    return NextResponse.json({ error: `HIBP returned HTTP ${response.status}` }, { status: 502 });
  }

  const text = await response.text();
  return NextResponse.json({ data: text });
}
