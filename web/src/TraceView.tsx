import type { TraceLine } from "./api";

const SPONSOR: Record<string, string> = { zetaris: "Zetaris", meterless: "Meterless", nvidia: "NVIDIA" };

export default function TraceView({ lines, rounds }: { lines: TraceLine[]; rounds?: number }) {
  const shown = lines.filter((l) => !(l.agent_name === "Investigator" && l.action === "sql" && l.status === "ok" && l.output_summary === "0 rows"));
  const counts = lines.reduce<Record<string, number>>((a, l) => ((a[l.sponsor] = (a[l.sponsor] ?? 0) + 1), a), {});
  return (
    <div className="trace">
      <p className="tsum">
        {rounds ? <span>{rounds} round{rounds > 1 ? "s" : ""}</span> : null}
        {Object.entries(SPONSOR).map(([k, v]) => counts[k] ? <span key={k} className={`sp ${k}`}>{v} × {counts[k]}</span> : null)}
        <span>run {lines[0]?.run_id}</span>
      </p>
      <ol>
        {shown.map((l, i) => (
          <li key={i} className={`st-${l.status}`}>
            <div className="tl">
              <b>{l.agent_name}</b> <span className="act">{l.action}</span>
              {l.sponsor !== "none" && <span className={`sp ${l.sponsor}`}>{SPONSOR[l.sponsor] ?? l.sponsor}</span>}
              {l.target_agent && <span className="to">→ {l.target_agent}</span>}
              {l.latency_ms != null && <span className="ms">{l.latency_ms} ms</span>}
            </div>
            {l.output_summary && <div className="out">{l.output_summary}</div>}
          </li>
        ))}
      </ol>
    </div>
  );
}
