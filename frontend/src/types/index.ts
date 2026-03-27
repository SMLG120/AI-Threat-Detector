export type ThreatLevel = "LOW" | "MEDIUM" | "HIGH";

export interface RequestLog {
  id: string;
  timestamp: string;
  ip_address: string;
  method: string;
  url: string;
  threat_score: number;
  threat_level: ThreatLevel;
  is_malicious: boolean;
  attack_types: string[];
  rule_score?: number;
  random_forest_score?: number;
  isolation_forest_score?: number;
}

export interface Alert {
  id: string;
  timestamp: string;
  ip_address: string;
  threat_level: ThreatLevel;
  threat_score: number;
  attack_types: string[];
  message: string;
  acknowledged: boolean;
}

export interface DashboardStats {
  total_requests: number;
  malicious_count: number;
  requests_24h: number;
  avg_threat_score: number;
  high_threat_count: number;
  block_rate: number;
  attack_distribution: Record<string, number>;
}

export interface WSMessage {
  type: "new_request" | "alert";
  data: Partial<RequestLog> & Partial<Alert>;
}
