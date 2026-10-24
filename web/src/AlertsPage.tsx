import { useEffect, useState } from "react";
import { api } from "./api";
import type { Dict, Lang } from "./i18n";

export default function AlertsPage({ t, lang }: { t: Dict; lang: Lang }) {
  const [alerts, setAlerts] = useState<any[] | null>(null);
  useEffect(() => { api.alerts().then((r) => setAlerts(r.alerts)).catch(() => setAlerts([])); }, []);
  const body = (a: any) => (lang === "fr" && a.body_fr) || (lang === "pcm" && a.body_pcm) || a.body_en;
  return (
    <section className="alerts">
      <h1>{t.alerts_title}</h1>
      <p className="lead">{t.alerts_intro}</p>
      {alerts === null && <p className="muted">…</p>}
      {alerts?.length === 0 && <p className="muted">{t.alerts_empty}</p>}
      {alerts?.map((a) => (
        <article key={a.id} className="alert-card">
          <div className="meta">{a.created.slice(0, 10)} · {a.numbers.length ? a.numbers.join(", ") : a.id}</div>
          <h2>{a.title}</h2>
          <p>{body(a)}</p>
        </article>
      ))}
    </section>
  );
}
