# Third-party code and test harnesses

`world-model/conformance/runner.ts` and `scout-intent/evals/` (runner, regression set, thresholds,
fixture registry) are copied unchanged from the Meterless open core, github.com/Meterless/Meterless
(Apache-2.0). They are the sponsor's official verification suites. Our engine implementations are in
`world-model/src/` and `scout-intent/src/`, written for CheckAm.

`h-mem/reference/` is the Meterless H-MEM reference implementation, copied unchanged from the same open
core (Apache-2.0, licence in that folder). `h-mem/conformance/` is its official conformance suite; the only
change is the default path in `runner.ts`, which points at `../reference/index.ts` where the reference sits
here. CheckAm's own code for H-MEM is `h-mem/src/server.ts` (what is remembered, by whom, and the daily
sleep cycle) and `api/checkam/adapters/memory.py` (how the agents recall it).
