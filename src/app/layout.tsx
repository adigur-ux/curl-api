import "./globals.css";
import React from "react";
import { Analytics } from "@vercel/analytics/next";

export const metadata = {
  title: "Dr Curl - API Compatibility Checker",
  description: "Professional API compatibility tooling with intelligent cURL analysis and optimization",
  icons: {
    icon: [
      { url: '/icon.svg', type: 'image/svg+xml' },
      { url: '/favicon.ico', sizes: 'any' }
    ],
    shortcut: '/favicon.ico',
    apple: '/icon.svg',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}








