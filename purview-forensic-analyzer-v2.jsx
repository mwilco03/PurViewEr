import { useState, useMemo, useCallback, useRef, useEffect, useReducer } from "react";
import * as Papa from "papaparse";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from "recharts";

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS & ENUMS
// ═══════════════════════════════════════════════════════════════════════════════

const IP_CLASS = Object.freeze({
  TRUSTED: "trusted",
  SUSPICIOUS: "suspicious",
  UNKNOWN: "unknown",
});

const IP_CLASS_CYCLE = Object.freeze({
  [IP_CLASS.UNKNOWN]: IP_CLASS.TRUSTED,
  [IP_CLASS.TRUSTED]: IP_CLASS.SUSPICIOUS,
  [IP_CLASS.SUSPICIOUS]: IP_CLASS.UNKNOWN,
});

const IP_CLASS_META = Object.freeze({
  [IP_CLASS.TRUSTED]: { label: "Trusted", bg: "#dcfce7", fg: "#166534", dot: "#22c55e" },
  [IP_CLASS.SUSPICIOUS]: { label: "Suspicious", bg: "#fee2e2", fg: "#991b1b", dot: "#ef4444" },
  [IP_CLASS.UNKNOWN]: { label: "Unknown", bg: "#f1f5f9", fg: "#475569", dot: "#94a3b8" },
});

const VIEW = Object.freeze({
  TIMELINE: "timeline",
  BY_IP: "byIp",
  BY_USER: "byUser",
  BY_MESSAGE: "byMessage",
  BY_OPERATION: "byOperation",
  BY_SESSION: "bySession",
  RAW: "raw",
});

const VIEW_META = Object.freeze({
  [VIEW.TIMELINE]: { label: "Timeline", icon: "⏱" },
  [VIEW.BY_IP]: { label: "By IP", icon: "🌐" },
  [VIEW.BY_USER]: { label: "By User", icon: "👤" },
  [VIEW.BY_MESSAGE]: { label: "By Message", icon: "✉" },
  [VIEW.BY_OPERATION]: { label: "By Operation", icon: "⚙" },
  [VIEW.BY_SESSION]: { label: "By Session", icon: "🔗" },
  [VIEW.RAW]: { label: "Raw", icon: "▦" },
});

const RECORDS_PER_PAGE = 50;

const DEBOUNCE_MS = 250;

const STORAGE_KEY_IP_MAP = "purview-forensic-ip-classifications";
const STORAGE_KEY_IOCS = "purview-forensic-iocs";

const KNOWN_MSFT_PREFIXES = Object.freeze([
  "20.175.", "20.190.", "20.184.", "20.189.", "20.33.", "20.34.",
  "40.126.", "40.90.", "40.99.", "40.107.",
  "52.235.", "52.108.", "52.109.", "52.110.", "52.96.", "52.97.", "52.98.", "52.99.", "52.100.", "52.101.", "52.102.", "52.103.",
  "13.107.", "13.64.", "13.65.", "13.66.", "13.67.", "13.68.", "13.69.", "13.70.", "13.71.", "13.73.", "13.74.", "13.75.", "13.76.", "13.77.", "13.78.", "13.79.", "13.80.", "13.81.", "13.82.", "13.83.", "13.84.", "13.85.", "13.86.", "13.87.", "13.88.", "13.89.", "13.90.", "13.91.", "13.92.", "13.93.", "13.94.", "13.95.",
  "51.105.", "51.120.", "51.124.", "51.136.", "51.137.", "51.138.", "51.140.", "51.141.", "51.143.", "51.144.", "51.145.",
  "104.42.", "104.43.", "104.44.", "104.45.", "104.46.", "104.47.", "104.208.", "104.210.", "104.211.", "104.212.", "104.214.", "104.215.",
  "204.79.",
  "131.253.",
  "150.171.",
  "157.55.", "157.56.",
]);

const PRIVATE_RANGE_TESTS = Object.freeze([
  (ip) => ip.startsWith("10."),
  (ip) => ip.startsWith("192.168."),
  (ip) => {
    if (!ip.startsWith("172.")) return false;
    const second = parseInt(ip.split(".")[1], 10);
    return second >= 16 && second <= 31;
  },
  (ip) => ip === "127.0.0.1" || ip.startsWith("127."),
]);

// Field extraction paths from AuditData JSON (ordered by priority)
const FIELD_EXTRACTION = Object.freeze({
  clientIp: ["ClientIPAddress", "ClientIP"],
  timestamp: ["CreationTime"],
  operation: ["Operation"],
  user: ["MailboxOwnerUPN", "UserId"],
  subject: ["Item.Subject", "Subject"],
  messageId: ["Item.InternetMessageId", "InternetMessageId"],
  path: ["Item.Path", "Path"],
  sessionId: ["AppAccessContext.AADSessionId", "SessionId"],
  appId: ["AppAccessContext.APIId", "AppId"],
  clientAppId: ["ClientAppId", "AppAccessContext.ClientAppId"],
  externalAccess: ["ExternalAccess"],
  sizeInBytes: ["Item.SizeInBytes", "SizeInBytes"],
  logonType: ["LogonType", "InternalLogonType"],
  resultStatus: ["ResultStatus"],
  workload: ["Workload"],
  originatingServer: ["OriginatingServer"],
  clientInfoString: ["ClientInfoString"],
  organizationName: ["OrganizationName"],
  userType: ["UserType"],
  recordType: ["RecordType"],
});

// Chart colors
const CHART_COLORS = Object.freeze({
  [IP_CLASS.TRUSTED]: "#22c55e",
  [IP_CLASS.SUSPICIOUS]: "#ef4444",
  [IP_CLASS.UNKNOWN]: "#94a3b8",
});

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

function flattenObject(obj, prefix = "") {
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    const path = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      Object.assign(result, flattenObject(value, path));
    } else if (Array.isArray(value)) {
      result[path] = JSON.stringify(value);
    } else {
      result[path] = value;
    }
  }
  return result;
}

function extractField(flatData, baseData, paths) {
  for (const p of paths) {
    const val = flatData[p] ?? baseData[p];
    if (val !== undefined && val !== null && val !== "") return String(val);
  }
  return "";
}

function cleanIp(raw) {
  if (!raw) return "";
  return raw.replace(/[\[\]]/g, "").split(":")[0] || raw;
}

function classifyIp(ip) {
  if (!ip) return IP_CLASS.UNKNOWN;
  if (PRIVATE_RANGE_TESTS.some((test) => test(ip))) return IP_CLASS.TRUSTED;
  // Microsoft IPs default to unknown (need manual review), not trusted
  return IP_CLASS.UNKNOWN;
}

function isMicrosoftIp(ip) {
  return KNOWN_MSFT_PREFIXES.some((p) => ip.startsWith(p));
}

function processRecords(csvText, sourceFile = "file") {
  const parsed = Papa.parse(csvText, {
    header: true,
    skipEmptyLines: true,
    dynamicTyping: false,
    transformHeader: (h) => h.trim().replace(/^\uFEFF/, ""),
  });

  if (parsed.errors.length > 0) {
    const fatal = parsed.errors.filter((e) => e.type === "Delimiter" || e.type === "FieldMismatch");
    if (fatal.length > 0 && parsed.data.length === 0) {
      throw new Error(`CSV parse failed: ${fatal[0].message} (row ${fatal[0].row})`);
    }
  }

  const hasAuditData = parsed.meta.fields?.some(
    (f) => f.toLowerCase() === "auditdata"
  );
  const auditKey = parsed.meta.fields?.find(
    (f) => f.toLowerCase() === "auditdata"
  );

  return parsed.data.map((row, i) => {
    const auditRaw = hasAuditData ? (row[auditKey] || "") : "";
    let auditJson = null;
    let auditFlat = {};

    if (auditRaw) {
      try {
        auditJson = JSON.parse(auditRaw);
        auditFlat = flattenObject(auditJson);
      } catch {
        // Try relaxed parse
        try {
          const cleaned = auditRaw
            .replace(/[\x00-\x1f]/g, " ")
            .replace(/\\'/g, "'");
          auditJson = JSON.parse(cleaned);
          auditFlat = flattenObject(auditJson);
        } catch {
          // Leave auditFlat empty; record still loads with base columns
        }
      }
    }

    const ip = cleanIp(extractField(auditFlat, row, FIELD_EXTRACTION.clientIp));

    return {
      _index: i,
      _source: sourceFile,
      _raw: auditRaw,
      _parseError: !auditJson && auditRaw.length > 0,
      _clientIp: ip,
      _isMsft: isMicrosoftIp(ip),
      _timestamp: extractField(auditFlat, row, FIELD_EXTRACTION.timestamp),
      _operation: extractField(auditFlat, row, FIELD_EXTRACTION.operation),
      _user: extractField(auditFlat, row, FIELD_EXTRACTION.user),
      _subject: extractField(auditFlat, row, FIELD_EXTRACTION.subject),
      _messageId: extractField(auditFlat, row, FIELD_EXTRACTION.messageId),
      _path: extractField(auditFlat, row, FIELD_EXTRACTION.path),
      _sessionId: extractField(auditFlat, row, FIELD_EXTRACTION.sessionId),
      _appId: extractField(auditFlat, row, FIELD_EXTRACTION.appId),
      _clientAppId: extractField(auditFlat, row, FIELD_EXTRACTION.clientAppId),
      _externalAccess: extractField(auditFlat, row, FIELD_EXTRACTION.externalAccess),
      _sizeInBytes: extractField(auditFlat, row, FIELD_EXTRACTION.sizeInBytes),
      _logonType: extractField(auditFlat, row, FIELD_EXTRACTION.logonType),
      _resultStatus: extractField(auditFlat, row, FIELD_EXTRACTION.resultStatus),
      _workload: extractField(auditFlat, row, FIELD_EXTRACTION.workload),
      _originatingServer: extractField(auditFlat, row, FIELD_EXTRACTION.originatingServer),
      _clientInfoString: extractField(auditFlat, row, FIELD_EXTRACTION.clientInfoString),
      _orgName: extractField(auditFlat, row, FIELD_EXTRACTION.organizationName),
      _userType: extractField(auditFlat, row, FIELD_EXTRACTION.userType),
      _recordType: extractField(auditFlat, row, FIELD_EXTRACTION.recordType),
      _allFields: { ...row, ...auditFlat },
    };
  });
}

function useDebounce(value, ms) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(timer);
  }, [value, ms]);
  return debounced;
}

function bucketByMinute(records, ipMap) {
  const buckets = {};
  records.forEach((r) => {
    if (!r._timestamp) return;
    const key = r._timestamp.slice(0, 16); // YYYY-MM-DDTHH:MM
    if (!buckets[key]) {
      buckets[key] = { time: key, [IP_CLASS.TRUSTED]: 0, [IP_CLASS.SUSPICIOUS]: 0, [IP_CLASS.UNKNOWN]: 0 };
    }
    const cls = ipMap[r._clientIp] || IP_CLASS.UNKNOWN;
    buckets[key][cls]++;
  });
  return Object.values(buckets).sort((a, b) => a.time.localeCompare(b.time));
}

function formatTime(isoStr) {
  if (!isoStr) return "";
  return isoStr.replace("T", " ").slice(0, 19);
}

function matchesIoc(record, iocSet) {
  if (iocSet.size === 0) return false;
  const fields = [record._clientIp, record._appId, record._clientAppId, record._operation, record._subject, record._user];
  return fields.some((f) => f && iocSet.has(f.toLowerCase()));
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATE REDUCER
// ═══════════════════════════════════════════════════════════════════════════════

const ACTION = Object.freeze({
  SET_RECORDS: "SET_RECORDS",
  APPEND_RECORDS: "APPEND_RECORDS",
  SET_IP_CLASS: "SET_IP_CLASS",
  SET_IP_MAP: "SET_IP_MAP",
  SET_VIEW: "SET_VIEW",
  SET_FILTER: "SET_FILTER",
  CLEAR_FILTERS: "CLEAR_FILTERS",
  SET_IOCS: "SET_IOCS",
  SET_LOADING: "SET_LOADING",
  SET_ERROR: "SET_ERROR",
});

const INITIAL_FILTERS = Object.freeze({
  search: "",
  ipClass: "",
  operation: "",
  user: "",
  dateFrom: "",
  dateTo: "",
  suspiciousOnly: false,
  parseErrorsOnly: false,
  iocMatchOnly: false,
});

const initialState = {
  records: [],
  ipMap: {},
  view: VIEW.TIMELINE,
  filters: { ...INITIAL_FILTERS },
  iocs: [],
  loading: false,
  error: null,
  fileNames: [],
};

function reducer(state, action) {
  switch (action.type) {
    case ACTION.SET_RECORDS:
      return { ...state, records: action.payload.records, fileNames: [action.payload.fileName], error: null };
    case ACTION.APPEND_RECORDS:
      return {
        ...state,
        records: [...state.records, ...action.payload.records],
        fileNames: [...state.fileNames, action.payload.fileName],
        error: null,
      };
    case ACTION.SET_IP_CLASS:
      return { ...state, ipMap: { ...state.ipMap, [action.payload.ip]: action.payload.cls } };
    case ACTION.SET_IP_MAP:
      return { ...state, ipMap: action.payload };
    case ACTION.SET_VIEW:
      return { ...state, view: action.payload };
    case ACTION.SET_FILTER:
      return { ...state, filters: { ...state.filters, [action.payload.key]: action.payload.value } };
    case ACTION.CLEAR_FILTERS:
      return { ...state, filters: { ...INITIAL_FILTERS } };
    case ACTION.SET_IOCS:
      return { ...state, iocs: action.payload };
    case ACTION.SET_LOADING:
      return { ...state, loading: action.payload };
    case ACTION.SET_ERROR:
      return { ...state, error: action.payload, loading: false };
    default:
      return state;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PERSISTENCE (window.storage API)
// ═══════════════════════════════════════════════════════════════════════════════

async function persistIpMap(ipMap) {
  try {
    await window.storage.set(STORAGE_KEY_IP_MAP, JSON.stringify(ipMap));
  } catch { /* storage unavailable */ }
}

async function loadPersistedIpMap() {
  try {
    const result = await window.storage.get(STORAGE_KEY_IP_MAP);
    return result ? JSON.parse(result.value) : null;
  } catch {
    return null;
  }
}

async function persistIocs(iocs) {
  try {
    await window.storage.set(STORAGE_KEY_IOCS, JSON.stringify(iocs));
  } catch { /* storage unavailable */ }
}

async function loadPersistedIocs() {
  try {
    const result = await window.storage.get(STORAGE_KEY_IOCS);
    return result ? JSON.parse(result.value) : null;
  } catch {
    return null;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STYLES (inline to avoid Tailwind build dependency for complex states)
// ═══════════════════════════════════════════════════════════════════════════════

const FONT_STACK = "'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', 'Consolas', monospace";
const FONT_UI = "'DM Sans', 'Segoe UI', system-ui, sans-serif";

const S = {
  root: { fontFamily: FONT_UI, background: "#0c0e12", color: "#e2e8f0", minHeight: "100vh" },
  header: { background: "#12151c", borderBottom: "1px solid #1e293b", padding: "12px 20px", display: "flex", alignItems: "center", justifyContent: "space-between", position: "sticky", top: 0, zIndex: 50 },
  headerTitle: { fontSize: 16, fontWeight: 700, color: "#f8fafc", letterSpacing: "-0.02em" },
  headerSub: { fontSize: 11, color: "#64748b", marginTop: 1 },
  badge: (cls) => ({
    display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px",
    borderRadius: 9999, fontSize: 10, fontWeight: 600, fontFamily: FONT_STACK,
    background: IP_CLASS_META[cls].bg, color: IP_CLASS_META[cls].fg,
  }),
  dot: (cls) => ({
    width: 6, height: 6, borderRadius: "50%", background: IP_CLASS_META[cls].dot,
  }),
  card: { background: "#161a23", border: "1px solid #1e293b", borderRadius: 10, overflow: "hidden" },
  cardHeader: { padding: "12px 16px", borderBottom: "1px solid #1e293b", display: "flex", alignItems: "center", justifyContent: "space-between" },
  input: {
    background: "#0c0e12", border: "1px solid #334155", borderRadius: 8, padding: "6px 12px",
    color: "#e2e8f0", fontSize: 13, fontFamily: FONT_UI, outline: "none", transition: "border-color 0.15s",
  },
  select: {
    background: "#0c0e12", border: "1px solid #334155", borderRadius: 8, padding: "6px 10px",
    color: "#e2e8f0", fontSize: 12, fontFamily: FONT_UI, outline: "none", cursor: "pointer",
  },
  btn: (active) => ({
    padding: "6px 14px", borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: "pointer",
    border: "1px solid " + (active ? "#3b82f6" : "#334155"),
    background: active ? "#1e3a5f" : "transparent",
    color: active ? "#93c5fd" : "#94a3b8",
    transition: "all 0.15s",
  }),
  btnPrimary: {
    padding: "6px 14px", borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: "pointer",
    border: "none", background: "#2563eb", color: "#fff",
  },
  btnDanger: {
    padding: "6px 14px", borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: "pointer",
    border: "1px solid #7f1d1d", background: "#450a0a", color: "#fca5a5",
  },
  mono: { fontFamily: FONT_STACK, fontSize: 11 },
  row: (suspicious) => ({
    display: "flex", alignItems: "center", gap: 10, padding: "6px 12px", borderRadius: 8, fontSize: 11,
    fontFamily: FONT_STACK, background: suspicious ? "#1a0a0a" : "#0f1117",
    border: `1px solid ${suspicious ? "#7f1d1d44" : "#1e293b"}`,
    marginBottom: 2, transition: "background 0.1s",
  }),
  statCard: (alert) => ({
    background: alert ? "#1a0a0a" : "#161a23", border: `1px solid ${alert ? "#7f1d1d" : "#1e293b"}`,
    borderRadius: 10, padding: "12px 16px", flex: 1, minWidth: 140,
  }),
  statValue: (alert) => ({ fontSize: 26, fontWeight: 800, color: alert ? "#f87171" : "#f8fafc", fontFamily: FONT_STACK }),
  statLabel: { fontSize: 10, color: "#64748b", textTransform: "uppercase", letterSpacing: "0.05em", fontWeight: 600 },
  statSub: { fontSize: 10, color: "#475569", marginTop: 2 },
  groupHeader: {
    display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 16px",
    cursor: "pointer", transition: "background 0.1s", width: "100%", border: "none",
    background: "transparent", color: "#e2e8f0", textAlign: "left",
  },
  sidebar: { width: 280, flexShrink: 0, display: "flex", flexDirection: "column", gap: 12 },
  main: { flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 12 },
  layout: { display: "flex", gap: 16, padding: "16px 20px", alignItems: "flex-start" },
  scrollBox: { maxHeight: 300, overflowY: "auto", paddingRight: 4 },
  dropZone: {
    border: "2px dashed #334155", borderRadius: 16, padding: "60px 40px", textAlign: "center",
    cursor: "pointer", transition: "all 0.2s", background: "#12151c",
  },
  truncate: { overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" },
  tag: { display: "inline-block", padding: "1px 6px", borderRadius: 4, fontSize: 10, fontWeight: 600, fontFamily: FONT_STACK },
  errorBanner: { background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: 8, padding: "10px 16px", color: "#fca5a5", fontSize: 13, margin: "8px 20px" },
  tooltip: { background: "#1e293b", border: "1px solid #334155", borderRadius: 8, padding: "8px 12px", fontSize: 11, color: "#e2e8f0" },
};

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════════

function ErrorBoundaryFallback({ error, onReset }) {
  return (
    <div style={{ padding: 40, textAlign: "center" }}>
      <div style={{ fontSize: 40, marginBottom: 16 }}>⚠</div>
      <h2 style={{ color: "#f87171", fontSize: 18, fontWeight: 700, marginBottom: 8 }}>Something broke</h2>
      <p style={{ color: "#94a3b8", fontSize: 13, marginBottom: 16, fontFamily: FONT_STACK }}>{error?.message || "Unknown error"}</p>
      <button onClick={onReset} style={S.btnPrimary}>Reload App</button>
    </div>
  );
}

class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { error: null }; }
  static getDerivedStateFromError(error) { return { error }; }
  render() {
    if (this.state.error) {
      return <ErrorBoundaryFallback error={this.state.error} onReset={() => { this.setState({ error: null }); this.props.onReset?.(); }} />;
    }
    return this.props.children;
  }
}

// We need React available for the class component
import React from "react";

function Badge({ cls }) {
  const meta = IP_CLASS_META[cls] || IP_CLASS_META[IP_CLASS.UNKNOWN];
  return (
    <span style={S.badge(cls)}>
      <span style={S.dot(cls)} />
      {meta.label}
    </span>
  );
}

function MsftTag() {
  return <span style={{ ...S.tag, background: "#172554", color: "#60a5fa" }}>MSFT</span>;
}

function IocTag() {
  return <span style={{ ...S.tag, background: "#431407", color: "#fb923c" }}>IOC</span>;
}

function ParseErrorTag() {
  return <span style={{ ...S.tag, background: "#422006", color: "#fbbf24" }}>PARSE ERR</span>;
}

function StatCard({ label, value, sub, alert }) {
  return (
    <div style={S.statCard(alert)}>
      <div style={S.statLabel}>{label}</div>
      <div style={S.statValue(alert)}>{value}</div>
      {sub && <div style={S.statSub}>{sub}</div>}
    </div>
  );
}

function StatsBar({ records, filtered, ipMap, iocSet }) {
  const stats = useMemo(() => {
    const suspIps = new Set(Object.entries(ipMap).filter(([, c]) => c === IP_CLASS.SUSPICIOUS).map(([ip]) => ip));
    const suspCount = filtered.filter((r) => suspIps.has(r._clientIp)).length;
    const iocCount = filtered.filter((r) => matchesIoc(r, iocSet)).length;
    const msgs = new Set(filtered.filter((r) => r._messageId).map((r) => r._messageId)).size;
    const users = new Set(filtered.filter((r) => r._user).map((r) => r._user)).size;
    const parseErrs = filtered.filter((r) => r._parseError).length;
    const ops = {};
    filtered.forEach((r) => { ops[r._operation] = (ops[r._operation] || 0) + 1; });
    const topOps = Object.entries(ops).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => `${k}: ${v}`).join(" | ");
    return { suspCount, iocCount, msgs, users, parseErrs, topOps };
  }, [filtered, ipMap, iocSet]);

  return (
    <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
      <StatCard label="Total" value={records.length} sub={`${filtered.length} shown`} />
      <StatCard label="Suspicious" value={stats.suspCount} sub="from flagged IPs" alert={stats.suspCount > 0} />
      <StatCard label="IOC Matches" value={stats.iocCount} sub="matched indicators" alert={stats.iocCount > 0} />
      <StatCard label="Messages" value={stats.msgs} sub="unique message IDs" />
      <StatCard label="Users" value={stats.users} sub="mailbox owners" />
      {stats.parseErrs > 0 && <StatCard label="Parse Errors" value={stats.parseErrs} sub="audit data failures" alert />}
    </div>
  );
}

function ActivityChart({ records, ipMap }) {
  const data = useMemo(() => bucketByMinute(records, ipMap), [records, ipMap]);

  if (data.length === 0) return null;

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload) return null;
    return (
      <div style={S.tooltip}>
        <div style={{ fontWeight: 600, marginBottom: 4 }}>{formatTime(label)}</div>
        {payload.map((p) => (
          <div key={p.dataKey} style={{ color: CHART_COLORS[p.dataKey], fontSize: 11 }}>
            {IP_CLASS_META[p.dataKey]?.label}: {p.value}
          </div>
        ))}
      </div>
    );
  };

  return (
    <div style={{ ...S.card, padding: "12px 16px" }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: "#94a3b8", marginBottom: 8 }}>
        Activity Timeline (by minute)
      </div>
      <ResponsiveContainer width="100%" height={120}>
        <BarChart data={data} barCategoryGap={1}>
          <XAxis
            dataKey="time"
            tick={{ fontSize: 9, fill: "#475569", fontFamily: FONT_STACK }}
            tickFormatter={(v) => v.slice(11, 16)}
            interval={Math.max(0, Math.floor(data.length / 12))}
          />
          <YAxis tick={{ fontSize: 9, fill: "#475569" }} width={30} />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey={IP_CLASS.SUSPICIOUS} stackId="a" fill={CHART_COLORS[IP_CLASS.SUSPICIOUS]} radius={[0, 0, 0, 0]} />
          <Bar dataKey={IP_CLASS.UNKNOWN} stackId="a" fill={CHART_COLORS[IP_CLASS.UNKNOWN]} />
          <Bar dataKey={IP_CLASS.TRUSTED} stackId="a" fill={CHART_COLORS[IP_CLASS.TRUSTED]} radius={[2, 2, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function IpPanel({ ipMap, onClassify, records }) {
  const ipStats = useMemo(() => {
    const stats = {};
    records.forEach((r) => {
      if (!r._clientIp) return;
      if (!stats[r._clientIp]) stats[r._clientIp] = { count: 0, isMsft: r._isMsft };
      stats[r._clientIp].count++;
    });
    return Object.entries(ipMap)
      .map(([ip, cls]) => ({ ip, cls, count: stats[ip]?.count || 0, isMsft: stats[ip]?.isMsft || false }))
      .sort((a, b) => {
        const classOrder = { [IP_CLASS.SUSPICIOUS]: 0, [IP_CLASS.UNKNOWN]: 1, [IP_CLASS.TRUSTED]: 2 };
        const diff = classOrder[a.cls] - classOrder[b.cls];
        return diff !== 0 ? diff : b.count - a.count;
      });
  }, [ipMap, records]);

  return (
    <div style={S.card}>
      <div style={S.cardHeader}>
        <span style={{ fontSize: 12, fontWeight: 700, color: "#e2e8f0" }}>
          IP Classification ({ipStats.length})
        </span>
      </div>
      <div style={{ padding: "4px 8px", fontSize: 10, color: "#64748b" }}>
        Click to cycle: Unknown → Trusted → Suspicious
      </div>
      <div style={{ ...S.scrollBox, padding: "4px 8px 8px" }}>
        {ipStats.map(({ ip, cls, count, isMsft }) => (
          <button
            key={ip}
            onClick={() => onClassify(ip, IP_CLASS_CYCLE[cls])}
            style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              width: "100%", padding: "5px 8px", borderRadius: 6, border: "none",
              background: "transparent", color: "#e2e8f0", cursor: "pointer",
              transition: "background 0.1s", textAlign: "left",
            }}
            onMouseEnter={(e) => (e.currentTarget.style.background = "#1e293b")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6, minWidth: 0 }}>
              <code style={{ ...S.mono, color: "#cbd5e1", ...S.truncate, maxWidth: 130, display: "block" }}>{ip}</code>
              {isMsft && <MsftTag />}
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <span style={{ ...S.mono, color: "#64748b" }}>{count}</span>
              <Badge cls={cls} />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

function IocPanel({ iocs, onSetIocs }) {
  const [text, setText] = useState(iocs.join("\n"));
  const [isOpen, setIsOpen] = useState(false);

  useEffect(() => setText(iocs.join("\n")), [iocs]);

  const handleApply = () => {
    const items = text.split("\n").map((s) => s.trim()).filter(Boolean);
    onSetIocs(items);
  };

  return (
    <div style={S.card}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        style={{ ...S.groupHeader, padding: "10px 16px" }}
      >
        <span style={{ fontSize: 12, fontWeight: 700 }}>
          IOC Import ({iocs.length})
        </span>
        <span style={{ fontSize: 11, color: "#64748b" }}>{isOpen ? "▲" : "▼"}</span>
      </button>
      {isOpen && (
        <div style={{ padding: "0 12px 12px" }}>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder={"Paste IPs, AppIds, or strings (one per line)..."}
            style={{
              ...S.input, width: "100%", height: 100, resize: "vertical",
              fontFamily: FONT_STACK, fontSize: 11, boxSizing: "border-box",
            }}
          />
          <div style={{ display: "flex", gap: 6, marginTop: 6 }}>
            <button onClick={handleApply} style={S.btnPrimary}>Apply IOCs</button>
            <button onClick={() => { setText(""); onSetIocs([]); }} style={{ ...S.btn(false), fontSize: 11 }}>Clear</button>
          </div>
        </div>
      )}
    </div>
  );
}

function FilterBar({ filters, dispatch, uniqueOps, uniqueUsers }) {
  return (
    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
      <input
        type="text"
        placeholder="Search subject, IP, user, session..."
        value={filters.search}
        onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "search", value: e.target.value } })}
        style={{ ...S.input, width: 240 }}
      />
      <select
        value={filters.ipClass}
        onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "ipClass", value: e.target.value } })}
        style={S.select}
      >
        <option value="">All IP Classes</option>
        {Object.values(IP_CLASS).map((c) => <option key={c} value={c}>{IP_CLASS_META[c].label}</option>)}
      </select>
      <select
        value={filters.operation}
        onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "operation", value: e.target.value } })}
        style={S.select}
      >
        <option value="">All Operations</option>
        {uniqueOps.map((op) => <option key={op} value={op}>{op}</option>)}
      </select>
      <select
        value={filters.user}
        onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "user", value: e.target.value } })}
        style={S.select}
      >
        <option value="">All Users</option>
        {uniqueUsers.map((u) => <option key={u} value={u}>{u}</option>)}
      </select>
      <input
        type="datetime-local"
        value={filters.dateFrom}
        onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "dateFrom", value: e.target.value } })}
        style={{ ...S.input, fontSize: 11 }}
        title="From"
      />
      <input
        type="datetime-local"
        value={filters.dateTo}
        onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "dateTo", value: e.target.value } })}
        style={{ ...S.input, fontSize: 11 }}
        title="To"
      />
      <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#94a3b8", cursor: "pointer" }}>
        <input type="checkbox" checked={filters.iocMatchOnly}
          onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "iocMatchOnly", value: e.target.checked } })} />
        IOC only
      </label>
      <label style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#94a3b8", cursor: "pointer" }}>
        <input type="checkbox" checked={filters.parseErrorsOnly}
          onChange={(e) => dispatch({ type: ACTION.SET_FILTER, payload: { key: "parseErrorsOnly", value: e.target.checked } })} />
        Parse errors
      </label>
      <button
        onClick={() => dispatch({ type: ACTION.CLEAR_FILTERS })}
        style={{ ...S.btn(false), fontSize: 11, color: "#64748b" }}
      >
        Clear
      </button>
    </div>
  );
}

function Pagination({ page, pageCount, onPage }) {
  if (pageCount <= 1) return null;
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 8, paddingTop: 8, borderTop: "1px solid #1e293b" }}>
      <button onClick={() => onPage(Math.max(0, page - 1))} disabled={page === 0}
        style={{ ...S.btn(false), opacity: page === 0 ? 0.3 : 1 }}>← Prev</button>
      <span style={{ ...S.mono, color: "#64748b" }}>Page {page + 1} / {pageCount}</span>
      <button onClick={() => onPage(Math.min(pageCount - 1, page + 1))} disabled={page >= pageCount - 1}
        style={{ ...S.btn(false), opacity: page >= pageCount - 1 ? 0.3 : 1 }}>Next →</button>
    </div>
  );
}

function RecordRow({ r, ipMap, iocSet }) {
  const cls = ipMap[r._clientIp] || IP_CLASS.UNKNOWN;
  const isSusp = cls === IP_CLASS.SUSPICIOUS;
  const isIoc = matchesIoc(r, iocSet);

  return (
    <div style={S.row(isSusp)}>
      <span style={{ width: 140, flexShrink: 0, color: "#64748b" }}>{formatTime(r._timestamp)}</span>
      <span style={{ width: 80, flexShrink: 0 }}><Badge cls={cls} /></span>
      <span style={{ width: 120, flexShrink: 0, color: "#cbd5e1" }}>{r._clientIp}</span>
      {r._isMsft && <MsftTag />}
      {isIoc && <IocTag />}
      {r._parseError && <ParseErrorTag />}
      <span style={{ width: 80, flexShrink: 0, color: "#60a5fa", fontWeight: 600 }}>{r._operation}</span>
      <span style={{ width: 180, flexShrink: 0, color: "#94a3b8", ...S.truncate }} title={r._user}>{r._user}</span>
      <span style={{ flex: 1, color: "#64748b", ...S.truncate }} title={r._subject || r._path || r._messageId}>
        {r._subject || r._path || r._messageId || "\u2014"}
      </span>
    </div>
  );
}

function TimelineView({ records, ipMap, iocSet }) {
  const [page, setPage] = useState(0);
  const pageCount = Math.ceil(records.length / RECORDS_PER_PAGE);
  const slice = records.slice(page * RECORDS_PER_PAGE, (page + 1) * RECORDS_PER_PAGE);
  useEffect(() => setPage(0), [records]);

  return (
    <div>
      {slice.map((r) => <RecordRow key={r._index} r={r} ipMap={ipMap} iocSet={iocSet} />)}
      <Pagination page={page} pageCount={pageCount} onPage={setPage} />
    </div>
  );
}

function GroupedView({ records, ipMap, iocSet, groupKey, labelKey, extraInfo }) {
  const [expanded, setExpanded] = useState(new Set());

  const groups = useMemo(() => {
    const map = {};
    records.forEach((r) => {
      const key = r[groupKey] || "(empty)";
      if (!map[key]) map[key] = { key, label: r[labelKey] || key, records: [], extra: extraInfo?.(r) };
      map[key].records.push(r);
    });
    return Object.values(map).sort((a, b) => b.records.length - a.records.length);
  }, [records, groupKey, labelKey, extraInfo]);

  const toggle = (key) => setExpanded((prev) => {
    const next = new Set(prev);
    next.has(key) ? next.delete(key) : next.add(key);
    return next;
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      {groups.map((g) => {
        const suspCount = g.records.filter((r) => ipMap[r._clientIp] === IP_CLASS.SUSPICIOUS).length;
        const isOpen = expanded.has(g.key);
        const uniqueIps = [...new Set(g.records.map((r) => r._clientIp))];
        const timeRange = g.records.length > 0
          ? `${formatTime(g.records[g.records.length - 1]._timestamp)} \u2192 ${formatTime(g.records[0]._timestamp)}`
          : "";

        return (
          <div key={g.key} style={S.card}>
            <button onClick={() => toggle(g.key)} style={S.groupHeader}
              onMouseEnter={(e) => (e.currentTarget.style.background = "#1e293b22")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, minWidth: 0, flex: 1 }}>
                <span style={{ fontSize: 10, color: "#64748b" }}>{isOpen ? "▼" : "▶"}</span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, ...S.truncate, fontFamily: FONT_STACK }}>{g.label}</div>
                  {g.extra && <div style={{ fontSize: 10, color: "#64748b", ...S.truncate }}>{g.extra}</div>}
                  {groupKey === "_sessionId" && <div style={{ fontSize: 10, color: "#475569" }}>{timeRange}</div>}
                </div>
                {groupKey === "_clientIp" && (
                  <div style={{ marginLeft: 4 }}>
                    <Badge cls={ipMap[g.key] || IP_CLASS.UNKNOWN} />
                    {isMicrosoftIp(g.key) && <MsftTag />}
                  </div>
                )}
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, flexShrink: 0 }}>
                {suspCount > 0 && (
                  <span style={{ ...S.tag, background: "#450a0a", color: "#fca5a5" }}>
                    {suspCount} suspicious
                  </span>
                )}
                <span style={{ ...S.mono, color: "#64748b" }}>{g.records.length} events</span>
                {groupKey !== "_clientIp" && (
                  <span style={{ ...S.mono, color: "#475569" }}>{uniqueIps.length} IPs</span>
                )}
              </div>
            </button>
            {isOpen && (
              <div style={{ borderTop: "1px solid #1e293b", padding: "4px 8px 8px", maxHeight: 400, overflowY: "auto" }}>
                {g.records.map((r) => <RecordRow key={r._index} r={r} ipMap={ipMap} iocSet={iocSet} />)}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function RawView({ records }) {
  const [page, setPage] = useState(0);
  const [expandedRow, setExpandedRow] = useState(null);
  const pageCount = Math.ceil(records.length / RECORDS_PER_PAGE);
  const slice = records.slice(page * RECORDS_PER_PAGE, (page + 1) * RECORDS_PER_PAGE);
  useEffect(() => { setPage(0); setExpandedRow(null); }, [records]);

  return (
    <div>
      {slice.map((r) => (
        <div key={r._index} style={{ ...S.card, marginBottom: 2 }}>
          <button
            onClick={() => setExpandedRow(expandedRow === r._index ? null : r._index)}
            style={{ ...S.groupHeader, padding: "6px 12px", gap: 12 }}
          >
            <span style={{ ...S.mono, color: "#475569", width: 40 }}>#{r._index}</span>
            <span style={{ ...S.mono, color: "#64748b", width: 140 }}>{formatTime(r._timestamp)}</span>
            <span style={{ ...S.mono, color: "#60a5fa", width: 80 }}>{r._operation}</span>
            <span style={{ ...S.mono, color: "#94a3b8", flex: 1, ...S.truncate }}>{r._user}</span>
            {r._parseError && <ParseErrorTag />}
          </button>
          {expandedRow === r._index && (
            <div style={{ borderTop: "1px solid #1e293b", padding: 12, maxHeight: 400, overflowY: "auto" }}>
              <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: "2px 12px", fontSize: 11 }}>
                {Object.entries(r._allFields || {}).map(([k, v]) => (
                  <React.Fragment key={k}>
                    <span style={{ color: "#64748b", fontFamily: FONT_STACK, fontWeight: 600 }}>{k}</span>
                    <span style={{ color: "#cbd5e1", fontFamily: FONT_STACK, wordBreak: "break-all" }}>{String(v)}</span>
                  </React.Fragment>
                ))}
              </div>
              <details style={{ marginTop: 8 }}>
                <summary style={{ fontSize: 11, color: "#475569", cursor: "pointer" }}>Raw AuditData</summary>
                <pre style={{ ...S.mono, color: "#64748b", whiteSpace: "pre-wrap", wordBreak: "break-all", marginTop: 4 }}>{r._raw}</pre>
              </details>
            </div>
          )}
        </div>
      ))}
      <Pagination page={page} pageCount={pageCount} onPage={setPage} />
    </div>
  );
}

function ExportButton({ records, ipMap, iocSet }) {
  const handleExport = () => {
    const exportFields = [
      "timestamp", "ip", "ip_classification", "is_microsoft_ip", "ioc_match",
      "operation", "user", "subject", "message_id", "path",
      "session_id", "app_id", "client_app_id", "external_access",
      "size_bytes", "logon_type", "result_status", "workload",
      "client_info", "source_file",
    ];
    const rows = records.map((r) => ({
      timestamp: r._timestamp, ip: r._clientIp,
      ip_classification: ipMap[r._clientIp] || IP_CLASS.UNKNOWN,
      is_microsoft_ip: r._isMsft, ioc_match: matchesIoc(r, iocSet),
      operation: r._operation, user: r._user, subject: r._subject,
      message_id: r._messageId, path: r._path, session_id: r._sessionId,
      app_id: r._appId, client_app_id: r._clientAppId,
      external_access: r._externalAccess, size_bytes: r._sizeInBytes,
      logon_type: r._logonType, result_status: r._resultStatus,
      workload: r._workload, client_info: r._clientInfoString,
      source_file: r._source,
    }));
    const csv = Papa.unparse(rows, { columns: exportFields });
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `purview-forensic-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return <button onClick={handleExport} style={S.btnPrimary}>Export Filtered CSV</button>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN APP
// ═══════════════════════════════════════════════════════════════════════════════

function App() {
  const [state, dispatch] = useReducer(reducer, initialState);
  const fileRef = useRef();

  const iocSet = useMemo(
    () => new Set(state.iocs.map((s) => s.toLowerCase())),
    [state.iocs]
  );

  // Load persisted data on mount
  useEffect(() => {
    (async () => {
      const savedIpMap = await loadPersistedIpMap();
      if (savedIpMap) dispatch({ type: ACTION.SET_IP_MAP, payload: savedIpMap });
      const savedIocs = await loadPersistedIocs();
      if (savedIocs) dispatch({ type: ACTION.SET_IOCS, payload: savedIocs });
    })();
  }, []);

  // Persist IP map on changes
  const handleClassify = useCallback((ip, cls) => {
    dispatch({ type: ACTION.SET_IP_CLASS, payload: { ip, cls } });
    // persist in next tick so state is updated
    setTimeout(() => {
      // we need the latest ipMap -- use a closure-safe approach
    }, 0);
  }, []);

  // persist ipMap whenever it changes
  useEffect(() => {
    if (Object.keys(state.ipMap).length > 0) persistIpMap(state.ipMap);
  }, [state.ipMap]);

  const handleSetIocs = useCallback((items) => {
    dispatch({ type: ACTION.SET_IOCS, payload: items });
    persistIocs(items);

    // Auto-flag IOC IPs as suspicious
    const ipItems = new Set(items.map((s) => s.toLowerCase()));
    const updates = {};
    Object.keys(state.ipMap).forEach((ip) => {
      if (ipItems.has(ip.toLowerCase())) updates[ip] = IP_CLASS.SUSPICIOUS;
    });
    if (Object.keys(updates).length > 0) {
      dispatch({ type: ACTION.SET_IP_MAP, payload: { ...state.ipMap, ...updates } });
    }
  }, [state.ipMap]);

  const handleFile = useCallback(async (files, append = false) => {
    if (!files || files.length === 0) return;
    dispatch({ type: ACTION.SET_LOADING, payload: true });

    try {
      let allRecords = append ? [...state.records] : [];
      let allFileNames = append ? [...state.fileNames] : [];

      for (const file of files) {
        const text = await file.text();
        const records = processRecords(text, file.name);
        if (records.length === 0) {
          throw new Error(`No records found in ${file.name}. Ensure it's a Purview audit log CSV with an AuditData column.`);
        }
        // Re-index to avoid collisions on merge
        const offset = allRecords.length;
        records.forEach((r, i) => { r._index = offset + i; });
        allRecords = allRecords.concat(records);
        allFileNames.push(file.name);
      }

      if (append) {
        dispatch({ type: ACTION.SET_RECORDS, payload: { records: allRecords, fileName: allFileNames.join(", ") } });
      } else {
        dispatch({ type: ACTION.SET_RECORDS, payload: { records: allRecords, fileName: allFileNames.join(", ") } });
      }

      // Build IP map, preserving existing classifications
      const newIpMap = { ...state.ipMap };
      allRecords.forEach((r) => {
        if (r._clientIp && !newIpMap[r._clientIp]) {
          newIpMap[r._clientIp] = classifyIp(r._clientIp);
        }
      });
      // Auto-flag IOC matches
      state.iocs.forEach((ioc) => {
        const lower = ioc.toLowerCase();
        Object.keys(newIpMap).forEach((ip) => {
          if (ip.toLowerCase() === lower) newIpMap[ip] = IP_CLASS.SUSPICIOUS;
        });
      });
      dispatch({ type: ACTION.SET_IP_MAP, payload: newIpMap });
      dispatch({ type: ACTION.SET_LOADING, payload: false });
    } catch (err) {
      dispatch({ type: ACTION.SET_ERROR, payload: err.message });
    }
  }, [state.records, state.fileNames, state.ipMap, state.iocs]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) handleFile(files, state.records.length > 0);
  }, [handleFile, state.records.length]);

  const handleInputChange = useCallback((e) => {
    const files = Array.from(e.target.files);
    handleFile(files, state.records.length > 0);
  }, [handleFile, state.records.length]);

  // Debounced search
  const debouncedSearch = useDebounce(state.filters.search, DEBOUNCE_MS);

  const uniqueOps = useMemo(() => [...new Set(state.records.map((r) => r._operation))].filter(Boolean).sort(), [state.records]);
  const uniqueUsers = useMemo(() => [...new Set(state.records.map((r) => r._user))].filter(Boolean).sort(), [state.records]);

  const filtered = useMemo(() => {
    const search = debouncedSearch.toLowerCase();
    return state.records.filter((r) => {
      if (search) {
        const haystack = `${r._clientIp} ${r._user} ${r._subject} ${r._messageId} ${r._operation} ${r._path} ${r._sessionId} ${r._appId} ${r._clientAppId}`.toLowerCase();
        if (!haystack.includes(search)) return false;
      }
      if (state.filters.ipClass && (state.ipMap[r._clientIp] || IP_CLASS.UNKNOWN) !== state.filters.ipClass) return false;
      if (state.filters.operation && r._operation !== state.filters.operation) return false;
      if (state.filters.user && r._user !== state.filters.user) return false;
      if (state.filters.dateFrom) {
        const ts = new Date(r._timestamp).getTime();
        if (isNaN(ts) || ts < new Date(state.filters.dateFrom).getTime()) return false;
      }
      if (state.filters.dateTo) {
        const ts = new Date(r._timestamp).getTime();
        if (isNaN(ts) || ts > new Date(state.filters.dateTo).getTime()) return false;
      }
      if (state.filters.iocMatchOnly && !matchesIoc(r, iocSet)) return false;
      if (state.filters.parseErrorsOnly && !r._parseError) return false;
      return true;
    });
  }, [state.records, debouncedSearch, state.filters, state.ipMap, iocSet]);

  // ─── Empty state ──────────────────────────────────────────────────────

  if (state.records.length === 0) {
    return (
      <div style={S.root}>
        <style>{`
          @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
          * { box-sizing: border-box; margin: 0; padding: 0; }
          ::-webkit-scrollbar { width: 6px; }
          ::-webkit-scrollbar-track { background: #0c0e12; }
          ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
          button:hover { filter: brightness(1.1); }
        `}</style>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh", padding: 20 }}
          onDragOver={(e) => { e.preventDefault(); e.stopPropagation(); }}
          onDrop={handleDrop}
        >
          <div style={{ maxWidth: 520, width: "100%", textAlign: "center" }}>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#ef4444", letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 8 }}>
              FORENSIC TOOL
            </div>
            <h1 style={{ fontSize: 28, fontWeight: 800, color: "#f8fafc", marginBottom: 8, letterSpacing: "-0.03em" }}>
              Purview Audit Log Analyzer
            </h1>
            <p style={{ fontSize: 13, color: "#64748b", marginBottom: 32, lineHeight: 1.6 }}>
              Parse, classify, and investigate Microsoft Purview audit log exports.
              All processing happens locally in your browser. Your data never leaves this page.
            </p>
            <label style={S.dropZone}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = "#3b82f6"; e.currentTarget.style.background = "#0f172a"; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = "#334155"; e.currentTarget.style.background = "#12151c"; }}
            >
              <div style={{ fontSize: 36, marginBottom: 12 }}>📂</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: "#e2e8f0", marginBottom: 4 }}>
                Drop CSV files here or click to browse
              </div>
              <div style={{ fontSize: 11, color: "#475569" }}>
                Supports Purview audit log exports with AuditData column. Multiple files merge automatically.
              </div>
              <input ref={fileRef} type="file" accept=".csv" multiple onChange={handleInputChange} style={{ display: "none" }} />
            </label>
            {state.loading && <div style={{ marginTop: 16, color: "#60a5fa", fontSize: 13 }}>Parsing records...</div>}
            {state.error && <div style={{ ...S.errorBanner, marginTop: 16, margin: "16px 0" }}>{state.error}</div>}
            <div style={{ marginTop: 32, fontSize: 11, color: "#334155", lineHeight: 1.8 }}>
              <div>Powered by PapaParse for robust CSV handling</div>
              <div>IP classifications and IOCs persist across sessions</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ─── Main UI ──────────────────────────────────────────────────────────

  const viewContent = {
    [VIEW.TIMELINE]: <TimelineView records={filtered} ipMap={state.ipMap} iocSet={iocSet} />,
    [VIEW.BY_IP]: <GroupedView records={filtered} ipMap={state.ipMap} iocSet={iocSet} groupKey="_clientIp" labelKey="_clientIp" />,
    [VIEW.BY_USER]: <GroupedView records={filtered} ipMap={state.ipMap} iocSet={iocSet} groupKey="_user" labelKey="_user" />,
    [VIEW.BY_MESSAGE]: <GroupedView records={filtered} ipMap={state.ipMap} iocSet={iocSet} groupKey="_messageId" labelKey="_subject"
      extraInfo={(r) => r._subject} />,
    [VIEW.BY_OPERATION]: <GroupedView records={filtered} ipMap={state.ipMap} iocSet={iocSet} groupKey="_operation" labelKey="_operation" />,
    [VIEW.BY_SESSION]: <GroupedView records={filtered} ipMap={state.ipMap} iocSet={iocSet} groupKey="_sessionId" labelKey="_sessionId"
      extraInfo={(r) => `${r._user} via ${r._clientIp}`} />,
    [VIEW.RAW]: <RawView records={filtered} />,
  };

  const parseErrors = state.records.filter((r) => r._parseError).length;

  return (
    <div style={S.root}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0c0e12; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
        button:hover { filter: brightness(1.1); }
        select option { background: #0c0e12; color: #e2e8f0; }
      `}</style>

      <ErrorBoundary onReset={() => window.location.reload()}>
        {/* Header */}
        <div style={S.header}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: "#ef4444", letterSpacing: "0.1em" }}>FORENSIC</span>
            <div>
              <div style={S.headerTitle}>Purview Audit Analyzer</div>
              <div style={S.headerSub}>
                {state.records.length} records from {state.fileNames.length} file(s)
                {parseErrors > 0 && <span style={{ color: "#fbbf24" }}> | {parseErrors} parse errors</span>}
              </div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ExportButton records={filtered} ipMap={state.ipMap} iocSet={iocSet} />
            <label style={{ ...S.btn(false), cursor: "pointer", display: "inline-block" }}>
              + Add Files
              <input ref={fileRef} type="file" accept=".csv" multiple onChange={handleInputChange} style={{ display: "none" }} />
            </label>
          </div>
        </div>

        {state.error && <div style={S.errorBanner}>{state.error}</div>}

        <div style={S.layout}>
          {/* Sidebar */}
          <div style={S.sidebar}>
            <IpPanel ipMap={state.ipMap} onClassify={handleClassify} records={state.records} />
            <IocPanel iocs={state.iocs} onSetIocs={handleSetIocs} />
          </div>

          {/* Main */}
          <div style={S.main}>
            <StatsBar records={state.records} filtered={filtered} ipMap={state.ipMap} iocSet={iocSet} />
            <ActivityChart records={filtered} ipMap={state.ipMap} />

            {/* Filters */}
            <div style={{ ...S.card, padding: "10px 14px" }}>
              <FilterBar filters={state.filters} dispatch={dispatch} uniqueOps={uniqueOps} uniqueUsers={uniqueUsers} />
            </div>

            {/* View tabs */}
            <div style={{ display: "flex", gap: 2, background: "#161a23", borderRadius: 10, border: "1px solid #1e293b", padding: 3 }}>
              {Object.entries(VIEW_META).map(([key, meta]) => (
                <button
                  key={key}
                  onClick={() => dispatch({ type: ACTION.SET_VIEW, payload: key })}
                  style={{
                    ...S.btn(state.view === key),
                    display: "flex", alignItems: "center", gap: 4,
                    borderRadius: 8, flex: 1, justifyContent: "center",
                  }}
                >
                  <span>{meta.icon}</span>
                  <span>{meta.label}</span>
                </button>
              ))}
            </div>

            <div style={{ fontSize: 11, color: "#475569" }}>
              {filtered.length} of {state.records.length} records
            </div>

            {viewContent[state.view]}
          </div>
        </div>
      </ErrorBoundary>
    </div>
  );
}

export default App;
