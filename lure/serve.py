"""lure serve: a local, read-only dashboard over the results store.

Pages: runs (filterable), one run (judgment, transcript, tool calls,
exposure), an attack across targets, a folder's report and approval page
(built on request, never written to disk), and each profile's vetting
history (runs, decisions, retests).

Safety: the server binds 127.0.0.1 only and answers GET and HEAD only. A
request whose Host header is not 127.0.0.1:<port> or localhost:<port> is
refused (DNS rebinding). Every page comes from a fixed query with bound
parameters; no SQL comes from a request. The store connection has external
access, extension autoinstall and autoload turned off and its configuration
locked. Transcripts and tool calls are attack text by design, so every
value is escaped, nothing is rendered as Markdown, and every response sends
a Content-Security-Policy that allows no scripts, no remote images and no
outside requests, plus nosniff, no-referrer and no CORS headers.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from jinja2 import Environment, FileSystemLoader

from lure import store

HOST = "127.0.0.1"
DEFAULT_PORT = 8765
PAGE_SIZE = 100
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
                               "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
}
# The Runs page filters: query parameter -> runs column. Fixed, never from a request.
FILTERS = {"target": "target", "attack": "attack_id", "category": "category",
           "scenario": "scenario", "verdict": "verdict", "profile": "profile",
           "folder": "folder"}
VERDICT_ORDER = ("Fail", "Partial", "Review", "Pass", "Refused", "Invalid", "Error")


class ServeError(ValueError):
    """The server cannot start as asked."""


class NotFound(Exception):
    pass


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(Path(__file__).parent / "report" / "templates"),
                      autoescape=True, trim_blocks=True, lstrip_blocks=True)
    env.filters["pretty"] = lambda v: json.dumps(v, indent=2, ensure_ascii=False, default=str)
    env.filters["q"] = lambda v: quote(str(v), safe="")
    env.filters["when"] = lambda v: v.strftime("%Y-%m-%d %H:%M UTC") if v else ""
    env.filters["money"] = lambda v: f"${v:.4f}" if isinstance(v, int | float) else ""
    return env


@dataclass
class Dashboard:
    """Fixed queries over the store, one method per page."""

    db: Path
    attacks_dir: Path = Path("attacks")
    policy_file: Path | None = None

    def _rows(self, sql: str, params: list[Any] = ()) -> list[dict[str, Any]]:
        with store.connect(self.db, read_only=True) as con:
            cursor = con.execute(sql, list(params))
            columns = [d[0] for d in cursor.description]
            return [dict(zip(columns, row, strict=True)) for row in cursor.fetchall()]

    def runs(self, filters: dict[str, str], page: int) -> dict[str, Any]:
        where, params = [], []
        for key, column in FILTERS.items():
            if filters.get(key):
                where.append(f"{column} = ?")
                params.append(filters[key])
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self._rows(f"SELECT count(*) AS n FROM runs {clause}", params)[0]["n"]
        rows = self._rows(
            "SELECT id, started_at, attack_id, attack_version, variant_id, scenario, target, "
            "verdict, partial_kind, detected, exposed, profile, folder FROM runs "
            f"{clause} ORDER BY started_at DESC NULLS LAST, id DESC LIMIT ? OFFSET ?",
            [*params, PAGE_SIZE, page * PAGE_SIZE])
        options = {key: [r["v"] for r in self._rows(
            f"SELECT DISTINCT {column} AS v FROM runs WHERE {column} IS NOT NULL ORDER BY 1")]
            for key, column in FILTERS.items() if key != "folder"}
        counts = Counter({r["verdict"]: r["n"] for r in self._rows(
            f"SELECT verdict, count(*) AS n FROM runs {clause} GROUP BY 1", params)})
        kept = {k: filters[k] for k in FILTERS if filters.get(k)}
        return {"rows": rows, "total": total, "page": page, "pages": max(1, -(-total // PAGE_SIZE)),
                "filters": kept, "options": options, "query": urlencode(kept),
                "counts": [(v, counts[v]) for v in VERDICT_ORDER if counts[v]]}

    def run(self, run_id: int) -> dict[str, Any]:
        found = self._rows("SELECT * FROM runs WHERE id = ?", [run_id])
        if not found:
            raise NotFound
        run = found[0]
        record = json.loads(run.pop("record"))
        calls = self._rows("SELECT idx, tool, alias, gate, failed, args, result FROM tool_calls "
                           "WHERE run_id = ? ORDER BY idx", [run_id])
        for c in calls:
            c["args"], c["result"] = json.loads(c["args"]), json.loads(c["result"])
        exposure = self._rows("SELECT idx, tool, domain FROM exposure WHERE run_id = ? "
                              "ORDER BY idx", [run_id])
        techniques = self._rows("SELECT framework, technique FROM techniques WHERE run_id = ? "
                                "ORDER BY framework, technique", [run_id])
        transcript = [{"role": m.get("role", ""), "text": m.get("content")
                       if isinstance(m.get("content"), str) else json.dumps(
                           m.get("content"), indent=2, ensure_ascii=False)}
                      for m in record.get("transcript") or [] if isinstance(m, dict)]
        return {"run": run, "judgment": record.get("judgment") or {}, "calls": calls,
                "exposure": exposure, "techniques": techniques, "transcript": transcript,
                "replies": record.get("replies") or [], "variant": record.get("variant")}

    def attack(self, attack_id: str) -> dict[str, Any]:
        rows = self._rows(
            "SELECT attack_version, target, verdict, count(*) AS n FROM runs WHERE attack_id = ? "
            "GROUP BY 1, 2, 3 ORDER BY 1, 2", [attack_id])
        if not rows:
            raise NotFound
        table: dict[tuple[int, str], Counter] = {}
        for r in rows:
            table.setdefault((r["attack_version"], r["target"]), Counter())[r["verdict"]] = r["n"]
        name = self._rows("SELECT attack_name, category, scenario, severity FROM runs "
                          "WHERE attack_id = ? ORDER BY attack_version DESC LIMIT 1", [attack_id])
        return {"id": attack_id, "info": name[0], "verdicts": VERDICT_ORDER,
                "table": [(v, t, c) for (v, t), c in sorted(table.items())]}

    def profiles(self) -> list[dict[str, Any]]:
        return self._rows(
            "WITH names AS (SELECT profile FROM runs WHERE profile IS NOT NULL UNION "
            "SELECT profile FROM folders WHERE profile IS NOT NULL UNION "
            "SELECT profile FROM decisions WHERE profile IS NOT NULL) "
            "SELECT n.profile, "
            "(SELECT count(*) FROM runs r WHERE r.profile = n.profile) AS runs, "
            "(SELECT count(DISTINCT folder) FROM runs r WHERE r.profile = n.profile) AS folders, "
            "(SELECT max(started_at) FROM runs r WHERE r.profile = n.profile) AS last_run, "
            "(SELECT count(*) FROM decisions d WHERE d.profile = n.profile) AS decisions, "
            "(SELECT d.decision FROM decisions d WHERE d.profile = n.profile "
            " ORDER BY d.decided_at DESC LIMIT 1) AS last_decision, "
            "(SELECT count(*) FROM retests t WHERE t.profile = n.profile) AS retests "
            "FROM names n ORDER BY last_run DESC NULLS LAST, n.profile")

    def profile(self, name: str) -> dict[str, Any]:
        folders = self._rows(
            "SELECT folder, min(started_at) AS started, any_value(target) AS target, "
            "count(*) AS runs, count(*) FILTER (verdict = 'Fail') AS fails, "
            "count(*) FILTER (verdict = 'Partial') AS partials, "
            "count(*) FILTER (exposed) AS exposed, any_value(profile_sha256) AS sha "
            "FROM runs WHERE profile = ? GROUP BY folder ORDER BY started DESC", [name])
        manifests = {r["path"] for r in self._rows(
            "SELECT path FROM folders WHERE profile = ?", [name])}
        for f in folders:
            f["profile_run"] = f["folder"] in manifests
        decisions = self._rows(
            "SELECT decided_at, decision, decided_by, conditions, run, profile_sha256 "
            "FROM decisions WHERE profile = ? ORDER BY decided_at DESC", [name])
        for d in decisions:
            d["conditions"] = json.loads(d["conditions"] or "[]")
        retests = self._rows("SELECT folder, baseline, regression, record FROM retests "
                             "WHERE profile = ? ORDER BY folder DESC", [name])
        for t in retests:
            record = json.loads(t.pop("record"))
            t["conditions"] = record.get("conditions") or []
            t["new_failures"] = record.get("new_failures") or []
            t["fixed"] = record.get("fixed") or []
        if not (folders or decisions or retests):
            raise NotFound
        approved = next((d for d in decisions if d["decision"] != "reject"), None)
        return {"name": name, "folders": folders, "decisions": decisions, "retests": retests,
                "approved": approved}

    def _folder_runs(self, folder: str):
        from lure.report.data import Run

        rows = self._rows("SELECT path, record FROM runs WHERE folder = ? ORDER BY path",
                          [folder])
        if not rows:
            raise NotFound
        return [Run(Path(r["path"]), json.loads(r["record"])) for r in rows]

    def report_html(self, folder: str) -> str:
        from lure.report.data import ReportError, build_report
        from lure.report.render import render

        runs = self._folder_runs(folder)
        try:
            return render(build_report(runs))
        except ReportError as e:
            return _message(f"No report for this folder: {e}")

    def approval_html(self, folder: str) -> str:
        from lure import policy as policy_file
        from lure.report.approval import build_approval
        from lure.report.data import ReportError, build_report
        from lure.report.render import render_approval
        from lure.rescore import attack_index

        runs = self._folder_runs(folder)
        manifest = self._rows("SELECT manifest FROM folders WHERE path = ?", [folder])
        if not manifest:
            return _message("No approval page: this folder is not a profile run (no "
                            "manifest.json). Approval pages are built for lure run --profile.")
        retest = self._rows("SELECT record FROM retests WHERE folder = ?", [folder])
        try:
            report = build_report(runs)
        except ReportError as e:
            return _message(f"No approval page for this folder: {e}")
        policy = policy_file.load(self.policy_file) if self.policy_file else policy_file.Policy()
        runs = [r for r in runs if r.record["target"] == report.target]
        gate = policy.gate_saved([(r.record, str(r.path)) for r in runs])
        attacks = attack_index(self.attacks_dir) if self.attacks_dir.is_dir() else {}
        page = build_approval(report, json.loads(manifest[0]["manifest"]), policy, gate, attacks,
                              retest=json.loads(retest[0]["record"]) if retest else None)
        return render_approval(page)


def _message(text: str) -> str:
    return _env().get_template("serve_message.html.j2").render(message=text)


class Handler(BaseHTTPRequestHandler):
    server_version = "lure-serve"
    sys_version = ""
    dashboard: Dashboard
    env: Environment

    def log_message(self, format: str, *args: Any) -> None:
        if getattr(self.server, "quiet", False):
            return
        super().log_message(format, *args)

    def _allowed_host(self) -> bool:
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _send(self, status: HTTPStatus, body: str, head: bool = False) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        if not head:
            self.wfile.write(data)

    def _refuse(self, status: HTTPStatus, text: str) -> None:
        self._send(status, f"<!doctype html><title>{status.value}</title><p>{text}</p>")

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle(head=True)

    def _not_allowed(self) -> None:
        self._refuse(HTTPStatus.METHOD_NOT_ALLOWED, "lure serve is read-only.")

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_allowed

    def _handle(self, head: bool = False) -> None:
        if not self._allowed_host():
            self._refuse(HTTPStatus.MISDIRECTED_REQUEST, "Unknown host.")
            return
        url = urlsplit(self.path)
        params = {k: v[0] for k, v in parse_qs(url.query).items() if v}
        try:
            body = self._page(url.path, params)
        except NotFound:
            self._refuse(HTTPStatus.NOT_FOUND, "Not found.")
            return
        except store.StoreError as e:
            self._refuse(HTTPStatus.SERVICE_UNAVAILABLE, str(e))
            return
        except Exception as e:  # noqa: BLE001 (a page bug must not drop the connection)
            self.log_error("error on %s: %r", url.path, e)
            self._refuse(HTTPStatus.INTERNAL_SERVER_ERROR, "This page failed to build.")
            return
        self._send(HTTPStatus.OK, body, head)

    def _render(self, template: str, **context: Any) -> str:
        return self.env.get_template(template).render(**context)

    def _page(self, path: str, params: dict[str, str]) -> str:
        d = self.dashboard
        if path in ("/", "/runs"):
            try:
                page = max(0, int(params.get("page", "1")) - 1)
            except ValueError:
                page = 0
            return self._render("serve_runs.html.j2", nav="runs", **d.runs(params, page))
        if path.startswith("/run/"):
            try:
                run_id = int(path.removeprefix("/run/"))
            except ValueError:
                raise NotFound from None
            return self._render("serve_run.html.j2", nav="runs", **d.run(run_id))
        if path.startswith("/attack/"):
            return self._render("serve_attack.html.j2", nav="runs",
                                **d.attack(path.removeprefix("/attack/")))
        if path == "/profiles":
            return self._render("serve_profiles.html.j2", nav="profiles", profiles=d.profiles())
        if path.startswith("/profile/"):
            return self._render("serve_profile.html.j2", nav="profiles",
                                **d.profile(path.removeprefix("/profile/")))
        if path == "/folder/report" and params.get("path"):
            return d.report_html(params["path"])
        if path == "/folder/approval" and params.get("path"):
            return d.approval_html(params["path"])
        raise NotFound


def make_server(dashboard: Dashboard, port: int = DEFAULT_PORT, host: str = HOST,
                quiet: bool = False) -> ThreadingHTTPServer:
    """A server on 127.0.0.1 only. port 0 picks a free port."""
    if host not in (HOST, "localhost"):
        raise ServeError(f"lure serve binds {HOST} only, not {host!r}")
    handler = type("LureHandler", (Handler,), {"dashboard": dashboard, "env": _env()})
    server = ThreadingHTTPServer((HOST, port), handler)
    server.daemon_threads = True
    server.quiet = quiet
    return server
