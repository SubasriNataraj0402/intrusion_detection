import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI-NIDS | Threat Intelligence Platform",
  description: "AI-powered network intrusion detection and threat intelligence dashboard",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-bg text-slate-200 antialiased">{children}</body>
    </html>
  );
}
