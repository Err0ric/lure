# Results store and dashboard

`lure store` indexes saved runs into one local DuckDB file, so you can query them across folders, targets and dates. `lure serve` puts a read-only dashboard on top: runs, transcripts, approval pages and each profile's vetting history, in a browser on your own machine.

The JSON result files stay the source of truth. The store is an index you can delete and rebuild from them at any time.

## Install

DuckDB is an optional extra, so the base install stays small:

```bash
pip install -e '.[store]'
```

Without it, everything else in Lure works, and `lure store` and `lure serve` say how to install it.

## Index and query

```bash
lure store add                      # results/, and vetting/ if it exists
lure store add results/my-run/ vetting/
lure store query "SELECT target, verdict, count(*) AS runs FROM runs GROUP BY 1, 2 ORDER BY 1, 2"
lure store query "SELECT attack_id, count(*) FROM runs WHERE verdict = 'Fail' GROUP BY 1" --csv
lure store rebuild                  # drop the file and index every folder it knew again
```

| Command | What it does |
| --- | --- |
| `lure store add [PATH...]` | Indexes run records, run manifests, `retest.json` and `decisions.jsonl` under each folder. A file indexed before with the same contents is skipped, a changed one replaces its rows, and one that is gone is dropped |
| `lure store rebuild` | Deletes the store file and indexes every folder it knew again |
| `lure store query "SQL"` | Runs SQL and prints a table, or CSV with `--csv` |

`--db FILE` picks the store file. The default, `results/lure.duckdb`, sits inside the gitignored `results/` folder.

### Tables

| Table | One row per | Main columns |
| --- | --- | --- |
| `runs` | Result record | `id`, `path`, `folder`, `attack_id`, `attack_version`, `category`, `scenario`, `severity`, `variant_id`, `target`, `judge`, `verdict`, `partial_kind`, `detected`, `exposed`, `profile`, `cost`, `started_at` (UTC), `record` (the whole record as JSON) |
| `tool_calls` | Tool call | `run_id`, `idx`, `tool`, `alias`, `gate`, `failed`, `args`, `result` |
| `techniques` | Framework ID on a run | `run_id`, `framework` (`atlas`, `attack`, `arcanum:<axis>`), `technique` |
| `exposure` | Outside domain a call reached | `run_id`, `idx`, `tool`, `domain` |
| `folders` | Profile run folder (from `manifest.json`) | `path`, `profile`, `target`, `started_at`, `manifest` |
| `retests` | `retest.json` | `folder`, `profile`, `baseline`, `regression`, `conditions` |
| `decisions` | Line of a decision log | `profile`, `decided_at`, `decision`, `decided_by`, `conditions`, `run` |

Records from older Lure versions load too; fields they lack are empty. All times are UTC.

## Browse

```bash
lure serve                          # indexes results/ (and vetting/) first
lure serve --port 9000 --no-index   # serve the store as it is
```

Then open http://127.0.0.1:8765/.

| Page | Shows |
| --- | --- |
| Runs | Every run, newest first, filterable by target, attack, category, pack, verdict and profile |
| Run | The judgment and its evidence, exposure, every tool call with its gate, and the transcript |
| Attack | One attack's verdicts by target and version |
| Profiles | Each profile: runs, run folders, the last decision, retests |
| Profile | Its run folders, decisions and retests, with each condition verified, held in Lure's test or open |
| Folder report and approval | The HTML report and approval page for a run folder, built on request and never written to disk |

Approval pages read the attack files (`--attacks-dir`, default `attacks`) and the policy (`--policy`, default `lure.yaml` if it exists), as `lure report --approval` does.

## Safety

The dashboard shows attack text by design: payloads with hidden HTML, Markdown images pointing at outside hosts, and instructions aimed at agents. It is built so that viewing them is safe.

- **Local and read-only.** It binds 127.0.0.1 only and answers GET and HEAD only. Any other method gets 405.
- **DNS rebinding.** A request whose `Host` header is not `127.0.0.1:<port>` or `localhost:<port>` is refused with 421, so a web page cannot reach the dashboard through a hostile domain name.
- **No outside requests from a page.** Every value is escaped and nothing is rendered as Markdown. Every response sends `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`: no scripts, no remote images, no outside requests. It also sends `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`, and no CORS headers.
- **No SQL from a request.** Pages use fixed queries with bound parameters.
- **A locked-down database.** Every connection turns off extension autoinstall and autoload and community and unsigned extensions. Its extension directory and repository are an empty local folder, and its configuration is locked so a statement cannot change any of that. The dashboard's connection also has external access turned off: no file or network reads from SQL.
- **`lure store query` reads only.** It runs SELECT and EXPLAIN statements, nothing else, on a read-only connection. It may read local files (`read_csv`, `read_json`), but cannot install or load an extension, write a file or change the store.

Nothing in `lure store` or `lure serve` calls a model.
