import { NextResponse } from "next/server";

const ZAP_A_WEBHOOK_URL = process.env.NEXT_PUBLIC_ZAP_A_WEBHOOK_URL || "https://hooks.zapier.com/hooks/catch/20378221/u1j9fqy/";

export async function POST(request: Request) {
  try {
    const payload = await request.json().catch(() => ({}));
    const upstream = await fetch(ZAP_A_WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(payload),
      cache: "no-store",
    });
    const text = await upstream.text();
    try {
      const data = JSON.parse(text);
      if (typeof data === "string") {
        return NextResponse.json({ fixed_curl: data }, { status: upstream.status });
      }
      return NextResponse.json(data, { status: upstream.status });
    } catch {
      // If Zapier returns a plain string (e.g., only fixed cURL), wrap into JSON
      return NextResponse.json({ fixed_curl: text }, { status: upstream.status });
    }
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || "Proxy error" }, { status: 502 });
  }
}


