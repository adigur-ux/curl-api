import "./globals.css";
import React from "react";

export const metadata = {
  title: "Dr Curl - API Compatibility Checker",
  description: "Professional API compatibility tooling with intelligent cURL analysis and optimization",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}








