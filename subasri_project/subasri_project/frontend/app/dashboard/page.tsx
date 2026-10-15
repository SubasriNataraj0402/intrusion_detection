"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, AttackRow, AlertRow, DashboardSummary, BlockedIPRow, getBlockedIps } from "@/lib/api";
import { getToken } from "@/lib/auth";
import { useLiveSocket, LiveEvent } from "@/lib/useLiveSocket";
import Topbar from "@/components/Topbar";
import StatCard from "@/components/StatCard";
import ChartPanel from "@/components/ChartPanel";
import PacketsPerSecChart from "@/components/charts/PacketsPerSecChart";
import ProtocolPieChart from "@/components/charts/ProtocolPieChart";
import AttackTypesChart from "@/components/charts/AttackTypesChart";
import SeverityChart from "@/components/charts/SeverityChart";
import AttackTable from "@/components/AttackTable";
import AlertPanel from "@/components/AlertPanel";
import BlockedIpsModal from "@/components/BlockedIpsModal";

const REFRESH_MS = 10000;

export default function DashboardPage() {
  const router = useRouter();
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [attacks, setAttacks] = useState<AttackRow[]>([]);
  const [alerts, setAlerts] = useState<AlertRow[]>([]);
  const [blockedIps, setBlockedIps] = useState<BlockedIPRow[]>([]);
  const [isBlockedModalOpen, setIsBlockedModalOpen] = useState(false);

  const loadBlocked = useCallback(async () => {
    try {
      const data = await getBlockedIps();
      setBlockedIps(data);
    } catch (e) {
      console.error("Failed to load blocked IPs:", e);
    }
  }, []);

  const loadAll = useCallback(async () => {
    const [s, a, al] = await Promise.all([
      api.get("/dashboard"),
      api.get("/attacks", { params: { limit: 50 } }),
      api.get("/alerts", { params: { limit: 50 } }),
    ]);
    setSummary(s.data);
    setAttacks(a.data);
    setAlerts(al.data);
    loadBlocked();
  }, [loadBlocked]);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    loadAll();
    const id = setInterval(loadAll, REFRESH_MS);
    return () => clearInterval(id);
  }, [loadAll, router]);

  const handleLive = useCallback((msg: LiveEvent) => {
    if (msg.event === "attack") {
      setAttacks((prev) => [msg.data, ...prev].slice(0, 50));
    }
    if (msg.event === "alert") {
      setAlerts((prev) => [{ ...msg.data, acknowledged: false, status: "open" }, ...prev].slice(0, 50));
    }
    if (msg.event === "ip_blocked") {
      setBlockedIps((prev) => [msg.data, ...prev.filter((b) => b.ip_address !== msg.data.ip_address)]);
    }
    if (msg.event === "ip_unblocked") {
      setBlockedIps((prev) => prev.filter((b) => b.ip_address !== msg.data.ip_address));
    }
  }, []);

  const connected = useLiveSocket(handleLive);

  function acknowledge(id: string) {
    setAlerts((prev) => prev.map((a) => (a.alert_id === id ? { ...a, acknowledged: true, status: "acknowledged" } : a)));
  }

  return (
    <div className="min-h-screen">
      <Topbar
        connected={connected}
        blockedCount={blockedIps.length}
        onOpenBlockedModal={() => setIsBlockedModalOpen(true)}
      />

      <main className="mx-auto max-w-7xl space-y-6 px-6 py-6">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <StatCard label="Total Packets" value={summary?.total_packets ?? "—"} />
          <StatCard label="Active Connections" value={summary?.active_connections ?? "—"} />
          <StatCard label="Current Threats" value={summary?.current_threats ?? "—"} accent="critical" />
          <StatCard label="Detection Rate" value={summary ? `${summary.detection_rate}%` : "—"} accent="low" />
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <ChartPanel title="Packets / sec (last hour)">
            <PacketsPerSecChart data={summary?.packets_per_sec_series ?? []} />
          </ChartPanel>
          <ChartPanel title="Protocol Distribution">
            <ProtocolPieChart data={summary?.protocol_distribution ?? []} />
          </ChartPanel>
          <ChartPanel title="Top Attack Types">
            <AttackTypesChart data={summary?.top_attack_types ?? []} />
          </ChartPanel>
          <ChartPanel title="Severity Distribution">
            <SeverityChart data={summary?.severity_distribution ?? []} />
          </ChartPanel>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            <AttackTable
              attacks={attacks}
              blockedIps={blockedIps}
              onRefreshBlocked={loadBlocked}
            />
          </div>
          <AlertPanel alerts={alerts} onAcknowledged={acknowledge} />
        </div>
      </main>

      <BlockedIpsModal
        blockedIps={blockedIps}
        isOpen={isBlockedModalOpen}
        onClose={() => setIsBlockedModalOpen(false)}
        onRefresh={loadBlocked}
      />
    </div>
  );
}

