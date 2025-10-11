import "./globals.css";
import React from "react";
import { Analytics } from "@vercel/analytics/next";

export const metadata = {
  title: "Dr Curl - API Compatibility Checker",
  description: "Professional API compatibility tooling with intelligent cURL analysis and optimization",
  icons: {
    icon: "/favicon.ico", // your single existing favicon
  },
  openGraph: {
    title: "Dr Curl | API Compatibility Tool",
    description:
      "Fix and connect APIs effortlessly with Dr Curl — intelligent cURL compatibility and repair.",
    url: "https://heal-api.com",
    siteName: "Heal-API",
    locale: "en_US",
    type: "website",
  },
  themeColor: "#0A84FF",
};
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        {children}
        <Analytics />
      </body>
    </html>
  );
}








