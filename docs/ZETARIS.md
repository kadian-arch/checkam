# Zetaris setup for CheckAm

CheckAm reads all of its evidence from Zetaris: the Stop Arnaque 237 tables are registered as the Lightning database `STOP_ARNAQUE` and queried over JDBC (the route Zetaris recommends), with the REST API as a fallback.

## 1. Run the local platform
Use the hackathon bundle from the Zetaris cloud "Run locally" page. In its folder (Git Bash on Windows):
```bash
docker compose up -d && ./verify.sh      # expect all checks to pass
```
Endpoints: UI http://localhost:3000, REST http://localhost:8888/api/v1.0, JDBC `jdbc:zetaris:lightning@localhost:10000`.
Create an API key in the UI (user settings) for the REST fallback.

## 2. Put the data where Zetaris can read it
The driver container mounts a `customer-data` volume. Copy the five parquet files from `data/sample/` into it:
```bash
export MSYS_NO_PATHCONV=1          # Git Bash only: stops path mangling
docker exec zetaris-driver-1 mkdir -p /home/zetaris/customer-data/shared/stop_arnaque
for f in data/sample/*.parquet; do docker cp "$f" zetaris-driver-1:/home/zetaris/customer-data/shared/stop_arnaque/; done
docker exec -u 0 zetaris-driver-1 chown -R zetaris:zetaris /home/zetaris/customer-data/shared/stop_arnaque
```
The files live in a named volume, so they survive restarts. Never run `docker compose down -v`.

## 3. Register the tables
Needs Java (JDK 17+, `JAVA_HOME` set) and the JDBC driver jar from the bundle (`jdbc/ndp-jdbc-driver-*.jar`, path in `ZETARIS_JDBC_JAR`).
```bash
python api/scripts/zetaris_load.py
```
It runs, one statement per call:
```sql
CREATE LIGHTNING DATABASE STOP_ARNAQUE DESCRIBE BY "Stop Arnaque 237 v1.0, local files";
CREATE LIGHTNING FILESTORE TABLE messages FROM STOP_ARNAQUE FORMAT PARQUET
  OPTIONS (PATH "file:///home/zetaris/customer-data/shared/stop_arnaque/messages.parquet");
-- same for reports, public_alerts, genuine_messages, scam_numbers
```

## 4. What the agents ask Zetaris
| Agent | Query |
|---|---|
| Investigator | `reports` and `public_alerts` WHERE `array_contains(phone_ids, code)`; same for `domains`; scam wording from `messages`; real operator messages from `genuine_messages`; scale from `reports` grouped by scam type |
| Critic | Re-counts every number claim with its own query before accepting it |
| Seed | Reads `reports` and `public_alerts` to build the World Model campaign graph |
| Analyst dossier | Member records, `scam_numbers` history |

List columns come back from JDBC as JSON text; the adapter turns them into lists. Every query is logged in the run trace with its latency and the backend that answered.
