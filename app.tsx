/**
 * GhostMesh — Orchestrator + Dashboard
 * ------------------------------------
 * Glues the attacker and defender modules together, owns network topology,
 * KPI strip, cycle summary, anomaly heatmap, defense-score chart, control
 * bar, and JSON event-log export.
 *
 * =========================================================================
 *  HOW TO RUN (VS Code / Antigravity / any node environment)
 * =========================================================================
 *
 *  1. Scaffold a Vite + React + TypeScript project:
 *
 *       npm create vite@latest ghostmesh -- --template react-ts
 *       cd ghostmesh
 *       npm install
 *
 *  2. Install runtime deps:
 *
 *       npm install framer-motion recharts
 *       npm install -D tailwindcss @tailwindcss/vite
 *
 *  3. Wire up Tailwind v4 by editing `vite.config.ts`:
 *
 *       import { defineConfig } from "vite";
 *       import react from "@vitejs/plugin-react";
 *       import tailwindcss from "@tailwindcss/vite";
 *       export default defineConfig({ plugins: [react(), tailwindcss()] });
 *
 *     and replace `src/index.css` with:
 *
 *       @import "tailwindcss";
 *       html, body, #root { height: 100%; background: #0a0a0a; color: #e5e5e5; }
 *
 *  4. Drop these three files into `src/`:
 *
 *       src/attacker.tsx
 *       src/defender.tsx
 *       src/app.tsx          ← this file
 *
 *  5. Replace `src/main.tsx` with:
 *
 *       import { StrictMode } from "react";
 *       import { createRoot } from "react-dom/client";
 *       import "./index.css";
 *       import App from "./app";
 *       createRoot(document.getElementById("root")!).render(
 *         <StrictMode><App /></StrictMode>
 *       );
 *
 *  6. Run:
 *
 *       npm run dev
 *
 *  Open http://localhost:5173 — the simulation auto-starts.
 * =========================================================================
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";

import {
  AttackerConsole,
  createAttackerInitialState,
  resetAttacker,
  tickAttacker,
  type AttackerEvent,
  type AttackerStage,
  type AttackerState,
} from "./attacker";

import {
  DefenderConsole,
  createDefenderInitialState,
  resetDefender,
  tickDefender,
  type DefenderEvent,
  type DefenderState,
  type DefenseActions,
} from "./defender";

/* =========================================================================
 * Types
 * ========================================================================= */

type NodeStatus = "idle" | "scanned" | "exploited" | "isolated" | "patched";

interface NetworkNode {
  id: string;
  label: string;
  type: "firewall" | "web" | "db" | "auth" | "admin" | "workstation";
  x: number;
  y: number;
  status: NodeStatus;
}

interface NetworkEdge {
  source: string;
  target: string;
  active: boolean;
}

interface Metrics {
  breachesAttempted: number;
  breachesDetected: number;
  mttd: number;
  nodesCompromised: number;
  defenseScore: number;
  cyclesCompleted: number;
}

interface CycleSummary {
  cycleId: string;
  stagesReached: AttackerStage[];
  primaryTechnique: string;
  mttdSeconds: number;
  peakAnomaly: number;
  defenseActions: DefenseActions;
  outcome: "CONTAINED" | "BREACHED";
  bytesExfiltrated: number;
}

type AnyEvent = AttackerEvent | DefenderEvent;

/* =========================================================================
 * Topology
 * ========================================================================= */

const INITIAL_NODES: NetworkNode[] = [
  { id: "fw-01",    label: "Firewall",  type: "firewall",    x: 10, y: 50, status: "idle" },
  { id: "web-01",   label: "Web-01",    type: "web",         x: 30, y: 30, status: "idle" },
  { id: "web-02",   label: "Web-02",    type: "web",         x: 30, y: 70, status: "idle" },
  { id: "auth-01",  label: "Auth-01",   type: "auth",        x: 50, y: 50, status: "idle" },
  { id: "db-01",    label: "DB-01",     type: "db",          x: 70, y: 30, status: "idle" },
  { id: "admin-01", label: "Admin-01",  type: "admin",       x: 70, y: 70, status: "idle" },
  { id: "ws-01",    label: "WS-01",     type: "workstation", x: 90, y: 20, status: "idle" },
  { id: "ws-02",    label: "WS-02",     type: "workstation", x: 90, y: 80, status: "idle" },
];

const INITIAL_EDGES: NetworkEdge[] = [
  { source: "fw-01",    target: "web-01",   active: false },
  { source: "fw-01",    target: "web-02",   active: false },
  { source: "web-01",   target: "auth-01",  active: false },
  { source: "web-02",   target: "auth-01",  active: false },
  { source: "auth-01",  target: "db-01",    active: false },
  { source: "auth-01",  target: "admin-01", active: false },
  { source: "admin-01", target: "ws-01",    active: false },
  { source: "admin-01", target: "ws-02",    active: false },
  { source: "db-01",    target: "ws-01",    active: false },
];

/* =========================================================================
 * Helpers
 * ========================================================================= */

function formatBytes(bytes: number) {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

/* =========================================================================
 * Main App
 * ========================================================================= */

export default function App() {
  // Sub-system state
  const [attacker, setAttacker] = useState<AttackerState>(createAttackerInitialState);
  const [defender, setDefender] = useState<DefenderState>(createDefenderInitialState);

  // World state
  const [nodes, setNodes] = useState<NetworkNode[]>(INITIAL_NODES);
  const [edges, setEdges] = useState<NetworkEdge[]>(INITIAL_EDGES);
  const [heatmap, setHeatmap] = useState<number[][]>(
    Array(8).fill(0).map(() => Array(24).fill(0))
  );
  const [eventLog, setEventLog] = useState<AnyEvent[]>([]);
  const [cycleHistory, setCycleHistory] = useState<CycleSummary[]>([]);
  const [metrics, setMetrics] = useState<Metrics>({
    breachesAttempted: 0,
    breachesDetected: 0,
    mttd: 0,
    nodesCompromised: 0,
    defenseScore: 100,
    cyclesCompleted: 0,
  });

  // Controls
  const [isRunning, setIsRunning] = useState(true);
  const [speed, setSpeed] = useState(1);
  const [aggression, setAggression] = useState(50);
  const [sensitivity, setSensitivity] = useState(50);

  const cycleStartRef = useRef<number>(Date.now());

  /* -------------------- Tick loop -------------------- */
  useEffect(() => {
    if (!isRunning) return;
    const id = setInterval(() => {
      setAttacker((prevAtk) => {
        const { state: nextAtk, event: atkEvent } = tickAttacker(prevAtk, aggression);

        setDefender((prevDef) => {
          const { state: nextDef, event: defEvent } = tickDefender(prevDef, {
            attackerActed: atkEvent !== null,
            sensitivity,
          });

          // Append to global event log
          if (atkEvent || defEvent) {
            setEventLog((log) => {
              const next = [...log];
              if (atkEvent) next.push(atkEvent);
              if (defEvent) next.push(defEvent);
              return next;
            });
          }

          // Update heatmap with current anomaly intensity
          setHeatmap((prev) =>
            prev.map((row) => [
              ...row.slice(1),
              Math.random() * nextDef.anomalyScore,
            ])
          );

          return nextDef;
        });

        // Animate edges randomly to convey "live traffic"
        setEdges((prev) => prev.map((e) => ({ ...e, active: Math.random() > 0.7 })));

        // Reflect attacker activity on nodes
        if (atkEvent) {
          setNodes((prev) => {
            const target = prev[Math.floor(Math.random() * prev.length)];
            return prev.map((n) =>
              n.id === target.id
                ? {
                    ...n,
                    status:
                      atkEvent.severity === "critical"
                        ? "exploited"
                        : atkEvent.severity === "medium"
                        ? "scanned"
                        : "scanned",
                  }
                : n
            );
          });
        }

        return nextAtk;
      });
    }, 1000 / speed);
    return () => clearInterval(id);
  }, [isRunning, speed, aggression, sensitivity]);

  /* -------------------- Cycle / reset -------------------- */
  const reset = useCallback(() => {
    setAttacker(resetAttacker());
    setDefender(resetDefender());
    setNodes(INITIAL_NODES);
    setEdges(INITIAL_EDGES);
    setHeatmap(Array(8).fill(0).map(() => Array(24).fill(0)));
    cycleStartRef.current = Date.now();
  }, []);

  const runCycle = useCallback(() => {
    const duration = (Date.now() - cycleStartRef.current) / 1000;
    const isBreached = attacker.stagesReached.has("DATA_EXFILTRATION");
    const summary: CycleSummary = {
      cycleId: `CYC-${Math.floor(Math.random() * 10000).toString().padStart(4, "0")}`,
      stagesReached: Array.from(attacker.stagesReached),
      primaryTechnique: attacker.primaryTechnique,
      mttdSeconds: parseFloat((duration * 0.4).toFixed(1)),
      peakAnomaly: parseFloat(defender.peakAnomaly.toFixed(1)),
      defenseActions: { ...defender.defenseActions },
      outcome: isBreached ? "BREACHED" : "CONTAINED",
      bytesExfiltrated: isBreached
        ? Math.floor(Math.random() * 5000) * 1024 * 1024
        : 0,
    };

    setCycleHistory((prev) => [...prev, summary]);
    setMetrics((prev) => ({
      ...prev,
      cyclesCompleted: prev.cyclesCompleted + 1,
      breachesAttempted: prev.breachesAttempted + 1,
      breachesDetected: prev.breachesDetected + (isBreached ? 0 : 1),
      mttd: parseFloat(
        (
          (prev.mttd * prev.cyclesCompleted + summary.mttdSeconds) /
          (prev.cyclesCompleted + 1)
        ).toFixed(1)
      ),
      nodesCompromised: prev.nodesCompromised + (isBreached ? 3 : 1),
      defenseScore: Math.max(
        0,
        100 - summary.bytesExfiltrated / (1024 * 1024 * 1024)
      ),
    }));

    reset();
    setIsRunning(true);
  }, [attacker, defender, reset]);

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(eventLog, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ghostmesh-events-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const latestCycle = cycleHistory[cycleHistory.length - 1] ?? null;

  /* -------------------- Render -------------------- */
  return (
    <div className="min-h-screen bg-black text-zinc-200 flex flex-col p-2 gap-2 h-screen overflow-hidden">
      {/* KPI strip */}
      <div className="flex gap-2 h-20 shrink-0">
        {[
          { label: "Breaches Attempted",  val: metrics.breachesAttempted },
          { label: "Breaches Detected",   val: metrics.breachesDetected },
          { label: "MTTD",                val: `${metrics.mttd}s` },
          { label: "Compromised Nodes",   val: metrics.nodesCompromised },
          { label: "Defense Score",       val: `${metrics.defenseScore.toFixed(0)}%` },
          { label: "Cycles",              val: metrics.cyclesCompleted },
        ].map((m, i) => (
          <div
            key={i}
            className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900/50 p-4 flex flex-col justify-center"
          >
            <span className="text-xs text-zinc-500 uppercase tracking-wider">
              {m.label}
            </span>
            <motion.span
              key={String(m.val)}
              initial={{ scale: 1.2, color: "#10b981" }}
              animate={{ scale: 1, color: "#e5e5e5" }}
              className="text-2xl font-mono font-bold"
            >
              {m.val}
            </motion.span>
          </div>
        ))}
      </div>

      {/* Main grid */}
      <div className="flex-1 flex gap-2 min-h-0">
        <AttackerConsole state={attacker} />

        <div className="flex-1 flex flex-col gap-2 min-w-0">
          {/* Topology */}
          <div className="flex-[2] relative overflow-hidden rounded-lg border border-zinc-800 bg-black/60">
            <svg
              width="100%"
              height="100%"
              viewBox="0 0 100 100"
              preserveAspectRatio="xMidYMid meet"
            >
              {edges.map((e, i) => {
                const src = nodes.find((n) => n.id === e.source);
                const tgt = nodes.find((n) => n.id === e.target);
                if (!src || !tgt) return null;
                return (
                  <g key={i}>
                    <line
                      x1={src.x}
                      y1={src.y}
                      x2={tgt.x}
                      y2={tgt.y}
                      stroke="#27272a"
                      strokeWidth="0.5"
                    />
                    {e.active && (
                      <motion.circle
                        r="1"
                        fill="#22d3ee"
                        initial={{ cx: src.x, cy: src.y }}
                        animate={{ cx: tgt.x, cy: tgt.y }}
                        transition={{ duration: 1, ease: "linear" }}
                      />
                    )}
                  </g>
                );
              })}
              {nodes.map((n) => (
                <g key={n.id} transform={`translate(${n.x}, ${n.y})`}>
                  <circle
                    r="3"
                    fill={
                      n.status === "exploited"
                        ? "#ef4444"
                        : n.status === "scanned"
                        ? "#f59e0b"
                        : n.status === "isolated"
                        ? "#52525b"
                        : n.status === "patched"
                        ? "#10b981"
                        : "#3b82f6"
                    }
                  />
                  <text
                    y="6"
                    fontSize="3"
                    fill="#a1a1aa"
                    textAnchor="middle"
                    className="font-mono"
                  >
                    {n.label}
                  </text>
                </g>
              ))}
            </svg>
          </div>

          {/* Cycle summary strip */}
          {latestCycle && (
            <motion.div
              key={latestCycle.cycleId}
              initial={{ scale: 0.98, opacity: 0.8 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.5 }}
              className="h-24 shrink-0 flex gap-2"
            >
              <SummaryCard label="ATTACK">
                <div className="text-xs font-mono text-red-400 truncate">
                  {latestCycle.primaryTechnique}
                </div>
                <div className="text-[10px] text-zinc-500 font-mono mt-1">
                  Stages: {latestCycle.stagesReached.length}
                </div>
              </SummaryCard>
              <SummaryCard label="DETECTION">
                <div className="text-xs font-mono">
                  MTTD:{" "}
                  <span className="text-cyan-400">
                    {latestCycle.mttdSeconds}s
                  </span>
                </div>
                <div className="text-[10px] text-zinc-500 font-mono mt-1">
                  Peak Anomaly: {latestCycle.peakAnomaly}
                </div>
              </SummaryCard>
              <SummaryCard label="DEFENSE">
                <div className="text-[10px] font-mono grid grid-cols-2 gap-x-2 gap-y-1">
                  <div>
                    Blocks:{" "}
                    <span className="text-emerald-400">
                      {latestCycle.defenseActions.blocks}
                    </span>
                  </div>
                  <div>
                    Iso:{" "}
                    <span className="text-emerald-400">
                      {latestCycle.defenseActions.isolations}
                    </span>
                  </div>
                  <div>
                    Patches:{" "}
                    <span className="text-emerald-400">
                      {latestCycle.defenseActions.patches}
                    </span>
                  </div>
                </div>
              </SummaryCard>
              <div
                className={`flex-1 rounded-lg p-3 flex flex-col justify-center border ${
                  latestCycle.outcome === "CONTAINED"
                    ? "bg-emerald-500/10 border-emerald-500/50"
                    : "bg-red-500/10 border-red-500/50"
                }`}
              >
                <div className="text-[10px] text-zinc-500 font-mono mb-1">
                  OUTCOME: {latestCycle.cycleId}
                </div>
                <div
                  className={`text-sm font-mono font-bold ${
                    latestCycle.outcome === "CONTAINED"
                      ? "text-emerald-400"
                      : "text-red-500"
                  }`}
                >
                  {latestCycle.outcome}
                </div>
                {latestCycle.outcome === "BREACHED" && (
                  <div className="text-[10px] text-red-400 font-mono mt-1">
                    Loss: {formatBytes(latestCycle.bytesExfiltrated)}
                  </div>
                )}
              </div>
            </motion.div>
          )}

          {/* Heatmap + Resilience chart */}
          <div className="h-40 flex gap-2 shrink-0">
            <div className="flex-1 rounded-lg border border-zinc-800 bg-black/40 p-2">
              <div className="text-xs text-zinc-500 font-mono mb-2">
                ANOMALY HEATMAP
              </div>
              <div className="grid grid-rows-8 gap-0.5 h-full pb-6">
                {heatmap.map((row, i) => (
                  <div key={i} className="flex gap-0.5">
                    {row.map((val, j) => (
                      <div
                        key={j}
                        className="flex-1 rounded-sm"
                        style={{
                          backgroundColor: `hsl(190, 100%, ${Math.min(val, 50)}%)`,
                        }}
                      />
                    ))}
                  </div>
                ))}
              </div>
            </div>
            <div className="flex-1 rounded-lg border border-zinc-800 bg-black/40 p-2 flex flex-col">
              <div className="text-xs text-zinc-500 font-mono mb-2">
                DEFENSE SCORE TREND
              </div>
              <div className="flex-1 min-h-0">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart
                    data={cycleHistory.map((c) => ({
                      id: c.cycleId,
                      score: Math.max(
                        0,
                        100 - c.bytesExfiltrated / (1024 * 1024 * 1024)
                      ),
                    }))}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                    <XAxis dataKey="id" hide />
                    <YAxis stroke="#a1a1aa" fontSize={10} domain={[0, 100]} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: "#0a0a0a",
                        borderColor: "#27272a",
                      }}
                    />
                    <Line
                      type="stepAfter"
                      dataKey="score"
                      stroke="#10b981"
                      strokeWidth={2}
                      dot={false}
                    />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </div>
          </div>
        </div>

        <DefenderConsole state={defender} />
      </div>

      {/* Control bar */}
      <div className="h-14 shrink-0 flex items-center px-4 gap-6 rounded-lg border border-zinc-800 bg-zinc-900/80">
        <div className="flex gap-2">
          <button
            onClick={() => setIsRunning(!isRunning)}
            className="px-3 py-1 rounded border border-zinc-700 bg-zinc-800 text-xs font-mono hover:bg-zinc-700"
          >
            {isRunning ? "PAUSE" : "PLAY"}
          </button>
          <button
            onClick={reset}
            className="px-3 py-1 rounded border border-zinc-700 bg-zinc-800 text-xs font-mono hover:bg-zinc-700"
          >
            RESET
          </button>
        </div>
        <div className="w-px h-6 bg-zinc-800" />
        <Control
          label="SPEED"
          color="text-zinc-400"
          value={speed}
          min={0.5}
          max={4}
          step={0.5}
          onChange={setSpeed}
        />
        <Control
          label="AGGRESSION"
          color="text-red-400"
          value={aggression}
          min={0}
          max={100}
          step={1}
          onChange={setAggression}
        />
        <Control
          label="SENSITIVITY"
          color="text-emerald-400"
          value={sensitivity}
          min={0}
          max={100}
          step={1}
          onChange={setSensitivity}
        />
        <div className="w-px h-6 bg-zinc-800" />
        <button
          onClick={handleExport}
          className="px-3 py-1 rounded border border-zinc-700 bg-zinc-800 text-xs font-mono hover:bg-zinc-700"
        >
          EXPORT LOG
        </button>
        <button
          onClick={runCycle}
          className="px-3 py-1 rounded bg-emerald-500 text-black text-xs font-mono hover:bg-emerald-400"
        >
          FORCE CYCLE
        </button>
      </div>
    </div>
  );
}

/* =========================================================================
 * Small helpers
 * ========================================================================= */

function SummaryCard({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex-1 rounded-lg border border-zinc-800 bg-zinc-900/80 p-3 flex flex-col justify-center relative overflow-hidden">
      <div className="text-[10px] text-zinc-500 font-mono mb-1">{label}</div>
      {children}
      <div className="absolute right-[-6px] top-1/2 -translate-y-1/2 text-zinc-700 font-mono text-xl">
        →
      </div>
    </div>
  );
}

function Control({
  label,
  color,
  value,
  min,
  max,
  step,
  onChange,
}: {
  label: string;
  color: string;
  value: number;
  min: number;
  max: number;
  step: number;
  onChange: (v: number) => void;
}) {
  return (
    <div className="flex items-center gap-3 flex-1">
      <span className={`text-xs font-mono w-24 ${color}`}>{label}</span>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(parseFloat(e.target.value))}
        className="w-32 accent-emerald-500"
      />
    </div>
  );
}
