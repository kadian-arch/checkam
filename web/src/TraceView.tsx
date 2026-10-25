import type { TraceLine } from "./api";

const SPONSOR: Record<string, string> = { zetaris: "Zetaris", meterless: "Meterless", nvidia: "Nemotron" };

export default function TraceView({ lines, rounds }: { lines: TraceLine[]; rounds?: number }) {
  const counts = lines.reduce<Record<string, number>>((a, l) => ((a[l.sponsor] = (a[l.sponsor] ?? 0) + 1), a), {});
  const total = lines.length ? new Date(lines[lines.length - 1].timestamp).getTime() - new Date(lines[0].timestamp).getTime() : 0;
  return (
    <div className="trace">
      <p className="tsum">
        {rounds ? <span>{rounds} round{rounds > 1 ? "s" : ""}</span> : null}
        <span>{lines.length} steps · {(total / 1000).toFixed(1)} s</span>
        {Object.entries(SPONSOR).map(([k, v]) => counts[k] ? <span key={k} className={`sp ${k}`}>{v} × {counts[k]}</span> : null)}
        <code>run {lines[0]?.run_id}</code>
      </p>
      <ol>
        {lines.map((l, i) => (
          <li key={i} className={`st-${l.status}`}>
            <div className="tl">
              <b>{l.agent_name}</b><span className="act">{l.action}</span>
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
