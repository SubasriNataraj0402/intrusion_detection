import axios from "axios";

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";
export const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/api/ws";

export const api = axios.create({ baseURL: API_URL });

api.interceptors.request.use((config) => {
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("nids_token");
    if (token) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }
  }
  return config;
});

api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (typeof window !== "undefined" && error?.response?.status === 401) {
      localStorage.removeItem("nids_token");
      localStorage.removeItem("nids_user");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  }
);

export interface UserOut {
  id: string;
  name: string;
  email: string;
  role: string;
}

export interface TrafficRow {
  flow_id: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  total_packets: number;
  total_bytes: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  label: string;
  created_at: string;
}

export interface AttackRow {
  attack_id: string;
  source_ip: string;
  destination_ip: string;
  attack_name: string;
  confidence: number;
  severity: string;
  risk_score: number;
  recommendation: string;
  explanation?: string;
  detector: string;
  time: string;
}

export interface AlertRow {
  alert_id: string;
  attack_id?: string;
  message: string;
  severity: string;
  status: string;
  acknowledged: boolean;
  created_time: string;
}

export interface BlockedIPRow {
  id: string;
  ip_address: string;
  reason: string;
  attack_type: string;
  blocked_by: string;
  status: string;
  created_at: string;
}

export interface DashboardSummary {
  total_packets: number;
  active_connections: number;
  current_threats: number;
  detection_rate: number;
  packets_per_sec_series: { time: string; packets: number }[];
  protocol_distribution: { protocol: string; count: number }[];
  top_attack_types: { attack_name: string; count: number }[];
  severity_distribution: { severity: string; count: number }[];
  top_attacking_ips: { source_ip: string; count: number }[];
  hourly_attacks: { hour: string; count: number }[];
}

export async function getBlockedIps(): Promise<BlockedIPRow[]> {
  const res = await api.get("/blocked-ips");
  return res.data;
}

export async function blockIp(ipAddress: string, reason?: string, attackType?: string): Promise<BlockedIPRow> {
  const res = await api.post("/blocked-ips", {
    ip_address: ipAddress,
    reason: reason || "Manual administrative block",
    attack_type: attackType || "manual",
  });
  return res.data;
}

export async function unblockIp(ipAddress: string): Promise<void> {
  await api.delete(`/blocked-ips/${encodeURIComponent(ipAddress)}`);
}

