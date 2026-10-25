import { lazy, Suspense } from "react";
import Receipt from "./Receipt";
import Site from "./Site";

// the analyst portal is a separate, laptop-first app; citizens never download it
const Portal = lazy(() => import("./Portal"));

export default function App() {
  if (location.pathname.startsWith("/analyst")) {
    return <Suspense fallback={<div className="boot">CheckAm Intel</div>}><Portal /></Suspense>;
  }
  const rc = location.pathname.match(/^\/v\/(C-[0-9a-f]{8})\/?$/);
  if (rc) return <Receipt id={rc[1]} />;
  return <Site />;
}
