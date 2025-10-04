import { NextResponse } from "next/server";

const ZAP_C_WEBHOOK_URL = process.env.NEXT_PUBLIC_ZAP_C_WEBHOOK_URL || "https://hooks.zapier.com/hooks/catch/20378221/u94tkdy/";

export async function POST(request: Request) {
  try {
    const payload = await request.json().catch(() => ({}));
    const upstream = await fetch(ZAP_C_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
      cache: "no-store",
    });
    const text = await upstream.text();
    try {
      const data = JSON.parse(text);
      return NextResponse.json(data, { status: upstream.status });
    } catch {
      return new NextResponse(text, {
        status: upstream.status,
        headers: { "Content-Type": upstream.headers.get("content-type") || "text/plain" },
      });
    }
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || "Proxy error" }, { status: 502 });
  }
}


