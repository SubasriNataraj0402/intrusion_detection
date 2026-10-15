"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { clearSession, getUser } from "@/lib/auth";
import { UserOut } from "@/lib/api";

interface TopbarProps {
  connected: boolean;
  blockedCount?: number;
  onOpenBlockedModal?: () => void;
}

export default function Topbar({ connected, blockedCount = 0, onOpenBlockedModal }: TopbarProps) {
  const router = useRouter();
  const [user, setUser] = useState<UserOut | null>(null);

  useEffect(() => {
    setUser(getUser());
  }, []);

  function logout() {
    clearSession();
    router.push("/login");
  }

  return (
    <div className="flex items-center justify-between border-b border-border bg-panel px-6 py-4">
      <div className="flex items-center gap-2">
        <span className="text-lg">🛡️</span>
        <h1 className="text-sm font-semibold text-white">AI-NIDS Threat Intelligence Platform</h1>
        <span
          className={`ml-3 flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] ${
            connected ? "bg-low/10 text-low" : "bg-critical/10 text-critical"
          }`}
        >
          <span className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-low" : "bg-critical"}`} />
          {connected ? "Live" : "Disconnected"}
        </span>
      </div>
      <div className="flex items-center gap-3 text-xs text-slate-400">
        <button
          onClick={onOpenBlockedModal}
          className="rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 px-3 py-1 font-medium transition flex items-center gap-1.5"
        >
          <span>🛡️ Active Protection</span>
          {blockedCount > 0 && (
            <span className="rounded-full bg-rose-500 text-white text-[10px] font-bold px-1.5 py-0.2">
              {blockedCount}
            </span>
          )}
        </button>
        {user && (
          <span>
            {user.name} · <span className="uppercase text-accent">{user.role}</span>
          </span>
        )}
        <button onClick={logout} className="rounded border border-border px-2 py-1 hover:border-accent hover:text-accent">
          Log out
        </button>
      </div>
    </div>
  );
}

