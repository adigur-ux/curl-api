// This catch-all route is no longer used; keeping a friendly response to avoid confusion.
import { NextResponse } from "next/server";

export async function POST() {
  return NextResponse.json(
    {
      error: "Use /api/zap/a, /api/zap/b, or /api/zap/c endpoints",
    },
    { status: 400 }
  );
}


