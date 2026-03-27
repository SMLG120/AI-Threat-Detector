import { useState, useEffect, useCallback, useRef } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend,
} from "recharts";
import {
  Shield,
  AlertTriangle,
  Activity,
  Zap,
  RefreshCw,
  Wifi,
  WifiOff,
  ChevronRight,
  Terminal,
  Database,
  Cpu,
  Globe,
} from "lucide-react";
import { useWebSocket } from "../hooks/useWebSocket";
import { api } from "../api/client";
import { RequestLog, Alert, DashboardStats, WSMessage, ThreatLevel } from "../types";
import { formatDistanceToNow } from "date-fns";

// ─── Constants ────────────────────────────────────────────────────────────────
const THREAT_COLORS: Record<ThreatLevel, string> = {
  LOW: "#22c55e",
  MEDIUM: "#f59e0b",
  HIGH: "#ef4444",
};

const ATTACK_COLOR_MAP: Record<string, string> = {
  SQL_INJECTION: "#ef4444",
  XSS: "#f97316",
  CMD_INJECTION: "#dc2626",
  PATH_TRAVERSAL: "#eab308",
  SSRF: "#a855f7",
};

// ─── Stat Card ────────────────────────────────────────────────────────────────
function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  accent,
}: {
  icon: any;
  label: string;
  value: string | number;
  sub?: string;
  accent?: string;
}) {
  return (
    <div className="stat-card">
      <div className="stat-header">
        <span className="stat-label">{label}</span>
        <div className="stat-icon" style={accent ? { color: accent } : {}}>
          <Icon size={16} />
        </div>
      </div>
      <div className="stat-value" style={accent ? { color: accent } : {}}>
        {value}
      </div>
      {sub && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

// ─── Threat Badge ─────────────────────────────────────────────────────────────
function ThreatBadge({ level }: { level: ThreatLevel }) {
  const color = THREAT_COLORS[level];
  return (
    <span
      className="threat-badge"
      style={{ color, borderColor: color + "40", background: color + "15" }}
    >
      {level}
    </span>
  );
}

// ─── Score Bar ────────────────────────────────────────────────────────────────
function ScoreBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  const color =
    pct >= 85 ? "#ef4444" : pct >= 60 ? "#f59e0b" : pct >= 30 ? "#eab308" : "#22c55e";
  return (
    <div className="score-bar-wrap">
      <div className="score-bar-track">
        <div
          className="score-bar-fill"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      <span className="score-bar-label" style={{ color }}>
        {(score * 100).toFixed(1)}%
      </span>
    </div>
  );
}

// ─── Main Dashboard ───────────────────────────────────────────────────────────
export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [logs, setLogs] = useState<RequestLog[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [timelineData, setTimelineData] = useState<any[]>([]);
  const [filter, setFilter] = useState<string>("ALL");
  const [retraining, setRetraining] = useState(false);
  const [modelReady, setModelReady] = useState(false);
  const [activeTab, setActiveTab] = useState<"logs" | "alerts">("logs");
  const logsRef = useRef<RequestLog[]>([]);

  const loadData = useCallback(async () => {
    try {
      const [statsData, logsData, alertsData, modelData] = await Promise.all([
        api.getStats(),
        api.getLogs(1, filter === "ALL" ? undefined : filter),
        api.getAlerts(),
        api.modelStatus(),
      ]);
      setStats(statsData);
      setLogs(logsData.logs || []);
      logsRef.current = logsData.logs || [];
      setAlerts(alertsData.alerts || []);
      setModelReady(modelData.models_ready);

      // Build timeline from logs
      buildTimeline(logsData.logs || []);
    } catch (err) {
      console.error("Data load failed:", err);
    }
  }, [filter]);

  const buildTimeline = (logData: RequestLog[]) => {
    const buckets: Record<string, { total: number; malicious: number }> = {};
    logData.slice(0, 200).forEach((l) => {
      const t = new Date(l.timestamp);
      const key = `${t.getHours()}:${String(t.getMinutes()).padStart(2, "0")}`;
      if (!buckets[key]) buckets[key] = { total: 0, malicious: 0 };
      buckets[key].total++;
      if (l.is_malicious) buckets[key].malicious++;
    });
    const sorted = Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-20)
      .map(([time, v]) => ({ time, ...v }));
    setTimelineData(sorted);
  };

  const onWsMessage = useCallback((msg: WSMessage) => {
    if (msg.type === "new_request" && msg.data) {
      const newLog = msg.data as RequestLog;
      setLogs((prev) => [newLog, ...prev].slice(0, 200));
      logsRef.current = [newLog, ...logsRef.current].slice(0, 200);
      buildTimeline(logsRef.current);
    }
    if (msg.type === "alert" && msg.data) {
      setAlerts((prev) => [msg.data as Alert, ...prev].slice(0, 50));
    }
  }, []);

  const { connected } = useWebSocket(onWsMessage);

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 15000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleRetrain = async () => {
    setRetraining(true);
    try {
      await api.retrain();
      setTimeout(() => setRetraining(false), 5000);
    } catch {
      setRetraining(false);
    }
  };

  const filteredLogs = filter === "ALL" ? logs : logs.filter((l) => l.threat_level === filter);

  const attackDist = stats?.attack_distribution
    ? Object.entries(stats.attack_distribution).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="dashboard">
      {/* ─── Header ─────────────────────────────────────────── */}
      <header className="dash-header">
        <div className="dash-brand">
          <div className="brand-icon">
            <Shield size={22} />
          </div>
          <div>
            <h1 className="brand-name">AI-WAF</h1>
            <span className="brand-sub">Threat Intelligence Platform</span>
          </div>
        </div>
        <div className="dash-controls">
          <div className={`ws-indicator ${connected ? "ws-on" : "ws-off"}`}>
            {connected ? <Wifi size={14} /> : <WifiOff size={14} />}
            <span>{connected ? "LIVE" : "RECONNECTING"}</span>
          </div>
          <div className={`model-badge ${modelReady ? "model-ok" : "model-warn"}`}>
            <Cpu size={13} />
            <span>ML {modelReady ? "READY" : "LOADING"}</span>
          </div>
          <button
            className="btn-retrain"
            onClick={handleRetrain}
            disabled={retraining}
          >
            <RefreshCw size={14} className={retraining ? "spinning" : ""} />
            {retraining ? "Training..." : "Retrain"}
          </button>
        </div>
      </header>

      {/* ─── Stat Cards ─────────────────────────────────────── */}
      <div className="stats-grid">
        <StatCard
          icon={Globe}
          label="Total Requests"
          value={(stats?.total_requests || 0).toLocaleString()}
          sub={`${stats?.requests_24h || 0} in last 24h`}
        />
        <StatCard
          icon={AlertTriangle}
          label="Threats Blocked"
          value={(stats?.malicious_count || 0).toLocaleString()}
          sub={`${stats?.block_rate || 0}% block rate`}
          accent="#ef4444"
        />
        <StatCard
          icon={Zap}
          label="High Severity"
          value={(stats?.high_threat_count || 0).toLocaleString()}
          sub="Critical detections"
          accent="#f97316"
        />
        <StatCard
          icon={Activity}
          label="Avg Threat Score"
          value={`${((stats?.avg_threat_score || 0) * 100).toFixed(1)}%`}
          sub="Ensemble weighted"
          accent={
            (stats?.avg_threat_score || 0) > 0.5 ? "#ef4444" : "#22c55e"
          }
        />
      </div>

      {/* ─── Charts ─────────────────────────────────────────── */}
      <div className="charts-grid">
        <div className="chart-card chart-wide">
          <div className="chart-title">
            <Activity size={16} />
            Traffic Timeline — Benign vs Malicious
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timelineData}>
              <defs>
                <linearGradient id="gTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gMal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" />
              <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 11 }} />
              <YAxis tick={{ fill: "#64748b", fontSize: 11 }} />
              <Tooltip
                contentStyle={{
                  background: "#0f172a",
                  border: "1px solid #1e293b",
                  borderRadius: 8,
                  color: "#e2e8f0",
                }}
              />
              <Area
                type="monotone"
                dataKey="total"
                stroke="#3b82f6"
                fill="url(#gTotal)"
                name="Total"
                strokeWidth={2}
              />
              <Area
                type="monotone"
                dataKey="malicious"
                stroke="#ef4444"
                fill="url(#gMal)"
                name="Malicious"
                strokeWidth={2}
              />
              <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 12 }} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <div className="chart-title">
            <Database size={16} />
            Attack Distribution
          </div>
          {attackDist.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={attackDist}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {attackDist.map((entry, i) => (
                    <Cell
                      key={entry.name}
                      fill={
                        ATTACK_COLOR_MAP[entry.name] ||
                        `hsl(${i * 60}, 70%, 55%)`
                      }
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#0f172a",
                    border: "1px solid #1e293b",
                    borderRadius: 8,
                    color: "#e2e8f0",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="empty-chart">No malicious traffic detected yet</div>
          )}
          <div className="attack-legend">
            {attackDist.map((a) => (
              <div key={a.name} className="attack-legend-item">
                <span
                  className="legend-dot"
                  style={{
                    background: ATTACK_COLOR_MAP[a.name] || "#94a3b8",
                  }}
                />
                <span className="legend-name">{a.name.replace(/_/g, " ")}</span>
                <span className="legend-count">{a.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ─── Log Table ──────────────────────────────────────── */}
      <div className="table-card">
        <div className="table-header">
          <div className="tab-row">
            <button
              className={`tab-btn ${activeTab === "logs" ? "tab-active" : ""}`}
              onClick={() => setActiveTab("logs")}
            >
              <Terminal size={14} />
              Request Logs
            </button>
            <button
              className={`tab-btn ${activeTab === "alerts" ? "tab-active" : ""}`}
              onClick={() => setActiveTab("alerts")}
            >
              <AlertTriangle size={14} />
              Alerts
              {alerts.length > 0 && (
                <span className="alert-count">{alerts.length}</span>
              )}
            </button>
          </div>
          {activeTab === "logs" && (
            <div className="filter-row">
              {(["ALL", "LOW", "MEDIUM", "HIGH"] as const).map((f) => (
                <button
                  key={f}
                  className={`filter-btn ${filter === f ? "filter-active" : ""}`}
                  onClick={() => setFilter(f)}
                  style={
                    filter === f && f !== "ALL"
                      ? { borderColor: THREAT_COLORS[f as ThreatLevel], color: THREAT_COLORS[f as ThreatLevel] }
                      : {}
                  }
                >
                  {f}
                </button>
              ))}
            </div>
          )}
        </div>

        {activeTab === "logs" ? (
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>IP Address</th>
                  <th>Method</th>
                  <th>URL</th>
                  <th>Threat Score</th>
                  <th>Level</th>
                  <th>Attack Types</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.slice(0, 100).map((log) => (
                  <tr
                    key={log.id}
                    className={`log-row ${log.is_malicious ? "row-malicious" : ""}`}
                  >
                    <td className="td-time">
                      {formatDistanceToNow(new Date(log.timestamp), {
                        addSuffix: true,
                      })}
                    </td>
                    <td className="td-ip">
                      <code>{log.ip_address}</code>
                    </td>
                    <td>
                      <span className={`method-badge method-${log.method}`}>
                        {log.method}
                      </span>
                    </td>
                    <td className="td-url" title={log.url}>
                      {log.url?.slice(0, 60)}
                      {(log.url?.length || 0) > 60 && "…"}
                    </td>
                    <td>
                      <ScoreBar score={log.threat_score} />
                    </td>
                    <td>
                      <ThreatBadge level={log.threat_level} />
                    </td>
                    <td className="td-attacks">
                      {(log.attack_types || []).map((t) => (
                        <span
                          key={t}
                          className="attack-chip"
                          style={{
                            background:
                              (ATTACK_COLOR_MAP[t] || "#64748b") + "25",
                            color: ATTACK_COLOR_MAP[t] || "#94a3b8",
                          }}
                        >
                          {t.replace(/_/g, " ")}
                        </span>
                      ))}
                    </td>
                  </tr>
                ))}
                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={7} className="empty-row">
                      No logs found. Run the attack simulator to generate traffic.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="alerts-list">
            {alerts.length === 0 && (
              <div className="empty-alerts">No alerts — system is clean.</div>
            )}
            {alerts.map((alert) => (
              <div
                key={alert.id}
                className={`alert-item alert-${alert.threat_level}`}
              >
                <div className="alert-left">
                  <AlertTriangle
                    size={16}
                    style={{ color: THREAT_COLORS[alert.threat_level] }}
                  />
                  <div>
                    <div className="alert-msg">{alert.message}</div>
                    <div className="alert-meta">
                      {alert.ip_address} ·{" "}
                      {formatDistanceToNow(new Date(alert.timestamp), {
                        addSuffix: true,
                      })}
                    </div>
                  </div>
                </div>
                <div className="alert-right">
                  <ThreatBadge level={alert.threat_level} />
                  <span className="alert-score">
                    {(alert.threat_score * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
