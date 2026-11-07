"""Email the scan result: polished HTML summary (Outlook-safe tables + inline
styles), plain-text alternative, and the Excel report attached.

Configuration (environment; every value can also come from a file via NAME_FILE,
e.g. SMTP_PASSWORD_FILE=/run/secrets/smtp_password):
  SMTP_HOST, SMTP_PORT (587), SMTP_SECURITY (starttls | ssl | none, default starttls),
  SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM, SMTP_TO (comma separated), SMTP_CC,
  SMTP_SUBJECT_PREFIX ([vulnscan]), SMTP_MAX_ATTACHMENT_MB (15)
"""
from __future__ import annotations

import html
import mimetypes
import re
import smtplib
import ssl
import time
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

from .report import vuln_url
from .util import get_secret, log

SEV_BG = {"CRITICAL": "#991B1B", "HIGH": "#DC2626", "MEDIUM": "#F59E0B", "LOW": "#FDE68A"}
SEV_FG = {"CRITICAL": "#FFFFFF", "HIGH": "#FFFFFF", "MEDIUM": "#1F2937", "LOW": "#1F2937"}
FONT = "font-family:'Segoe UI',Helvetica,Arial,sans-serif;"


class EmailConfigError(ValueError):
    pass


def config() -> dict:
    cfg = {
        "host": get_secret("SMTP_HOST"),
        "security": (get_secret("SMTP_SECURITY") or "starttls").lower(),
        "user": get_secret("SMTP_USERNAME"), "password": get_secret("SMTP_PASSWORD"),
        "from": get_secret("SMTP_FROM") or get_secret("SMTP_USERNAME"),
        "to": [a for a in re.split(r"[,;\s]+", get_secret("SMTP_TO")) if a],
        "cc": [a for a in re.split(r"[,;\s]+", get_secret("SMTP_CC")) if a],
        "prefix": get_secret("SMTP_SUBJECT_PREFIX") or "[vulnscan]",
        "max_mb": float(get_secret("SMTP_MAX_ATTACHMENT_MB") or 15),
    }
    cfg["port"] = int(get_secret("SMTP_PORT") or (465 if cfg["security"] == "ssl" else 587))
    missing = [k for k in ("host", "from") if not cfg[k]] + ([] if cfg["to"] else ["to"])
    if missing:
        raise EmailConfigError("missing SMTP setting(s): " + ", ".join(f"SMTP_{m.upper()}" for m in missing))
    if cfg["security"] not in ("starttls", "ssl", "none"):
        raise EmailConfigError("SMTP_SECURITY must be starttls, ssl or none")
    return cfg


def subject(s: dict, prefix: str) -> str:
    repos = ", ".join(s["repos"]) if len(s["repos"]) <= 3 else f"{len(s['repos'])} repositories"
    if not s["status_ok"]:
        state = "INCOMPLETE · "
    else:
        state = ""
    if s["total"] == 0:
        if not s["status_ok"]:
            return f"{prefix} SCAN INCOMPLETE · {repos}: results cannot be trusted"
        return f"{prefix} {repos}: no known vulnerabilities found"
    parts = []
    if s["kev"]:
        parts.append(f"{s['kev']} actively exploited")
    parts += [f"{s['sev']['CRITICAL']:,} critical", f"{s['sev']['HIGH']:,} high"]
    return f"{prefix} {state}{repos}: " + " · ".join(parts)


# ---------------------------------------------------------------------------
def _e(v) -> str:
    return html.escape(str(v), quote=True)


def _short(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",.;:-")
    return cut + " …"


def _tile(value, label, bg, fg="#FFFFFF") -> str:
    return (f'<td align="center" style="background:{bg};color:{fg};padding:12px 6px;border-radius:6px;{FONT}">'
            f'<div style="font-size:24px;font-weight:700;line-height:28px">{_e(value)}</div>'
            f'<div style="font-size:10px;font-weight:600;letter-spacing:.6px;opacity:.9">{_e(label)}</div></td>'
            '<td width="8" style="font-size:0">&nbsp;</td>')


def _sev_cell(n: int, sev: str) -> str:
    if not n:
        return f'<td align="right" style="padding:7px 10px;color:#9CA3AF;{FONT}font-size:13px">0</td>'
    return (f'<td align="right" style="padding:7px 10px;{FONT}font-size:13px">'
            f'<span style="background:{SEV_BG[sev]};color:{SEV_FG[sev]};padding:2px 8px;border-radius:10px;'
            f'font-weight:700">{n:,}</span></td>')


def _th(label, align="left") -> str:
    return (f'<th align="{align}" style="padding:8px 10px;background:#F3F4F6;color:#374151;font-size:11px;'
            f'text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid #E5E7EB;{FONT}">{_e(label)}</th>')


def render_html(s: dict, meta: dict, attached: bool, report_name: str) -> str:
    status = (('<div style="background:#ECFDF5;color:#065F46;border:1px solid #A7F3D0;padding:10px 14px;'
               f'border-radius:6px;{FONT}font-size:13px">✔ Scan completed for every repository and engine.</div>')
              if s["status_ok"] else
              ('<div style="background:#FEF2F2;color:#991B1B;border:1px solid #FECACA;padding:10px 14px;'
               f'border-radius:6px;{FONT}font-size:13px"><b>⚠ Scan incomplete.</b> '
               + _e("; ".join(s["problems"])) + " — see the Coverage sheet.</div>"))

    tiles = "".join([
        _tile(f"{s['total']:,}", "FINDINGS", "#1E3A5F"),
        _tile(f"{s['p1']:,}", "PRIORITY 1", "#7F1D1D"),
        _tile(s["kev"], "KNOWN EXPLOITED", "#450A0A"),
        _tile(f"{s['sev']['CRITICAL']:,}", "CRITICAL", SEV_BG["CRITICAL"]),
        _tile(f"{s['sev']['HIGH']:,}", "HIGH", SEV_BG["HIGH"]),
        _tile(s["eol"], "END-OF-LIFE", "#4B5563"),
    ])

    repo_rows = "".join(
        f'<tr style="border-bottom:1px solid #F3F4F6">'
        f'<td style="padding:7px 10px;{FONT}font-size:13px;font-weight:600;color:#111827">{_e(r["name"])}</td>'
        f'<td style="padding:7px 10px;{FONT}font-size:12px;color:#6B7280">{_e(r["revision"])}</td>'
        f'<td align="right" style="padding:7px 10px;{FONT}font-size:13px">{r["files"]:,}</td>'
        + "".join(_sev_cell(r["sev"][k], k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        + f'<td align="right" style="padding:7px 10px;{FONT}font-size:13px;font-weight:700;'
          f'color:{"#991B1B" if r["kev"] else "#9CA3AF"}">{r["kev"]}</td>'
        f'<td style="padding:7px 10px;{FONT}font-size:12px;color:{"#065F46" if r["ok"] else "#991B1B"}">'
        f'{"complete" if r["ok"] else "incomplete"}</td></tr>'
        for r in s["per_repo"])

    comp_rows = "".join(
        f'<tr style="border-bottom:1px solid #F3F4F6">'
        f'<td style="padding:7px 10px;{FONT}font-size:13px;color:#111827;font-weight:600">{_e(c["name"])}</td>'
        f'<td style="padding:7px 10px;{FONT}font-size:12px;color:#6B7280">{_e(c["version"])}</td>'
        f'<td align="right" style="padding:7px 10px;{FONT}font-size:13px">{c["vulns"]:,}</td>'
        + _sev_cell(c["critical"], "CRITICAL") + _sev_cell(c["high"], "HIGH")
        + f'<td align="right" style="padding:7px 10px;{FONT}font-size:13px;font-weight:700;'
          f'color:{"#991B1B" if c["kev"] else "#9CA3AF"}">{c["kev"]}</td>'
        f'<td align="right" style="padding:7px 10px;{FONT}font-size:13px">{c["files"]:,}</td></tr>'
        for c in s["top_components"][:10])

    kev_items = "".join(
        f'<tr><td style="padding:5px 10px;{FONT}font-size:13px;white-space:nowrap">'
        f'<a href="{_e(vuln_url(k["id"]))}" style="color:#B91C1C;font-weight:700;text-decoration:none">{_e(k["id"])}</a></td>'
        f'<td style="padding:5px 10px;{FONT}font-size:13px;color:#374151">{_e(k["component"])} {_e(k["version"])}</td>'
        f'<td style="padding:5px 10px;{FONT}font-size:12px;color:#6B7280">{_e(_short(k["title"], 120))}</td></tr>'
        for k in s["kev_list"][:15])
    kev_block = (f'<h3 style="{FONT}font-size:15px;color:#7F1D1D;margin:26px 0 8px">Actively exploited (CISA KEV)</h3>'
                 f'<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;'
                 f'background:#FEF2F2;border-radius:6px">{kev_items}</table>'
                 + (f'<p style="{FONT}font-size:12px;color:#6B7280">… and {len(s["kev_list"]) - 15} more in the report.</p>'
                    if len(s["kev_list"]) > 15 else "")) if s["kev_list"] else ""

    eol_block = ""
    if s["eol_list"]:
        eol_block = (f'<h3 style="{FONT}font-size:15px;color:#111827;margin:26px 0 8px">End-of-life components</h3>'
                     f'<p style="{FONT}font-size:13px;color:#374151;margin:0">'
                     + " · ".join(f"<b>{_e(n)}</b> <span style='color:#6B7280'>({c} files)</span>"
                                  for n, c in s["eol_list"][:10]) + "</p>")

    attach_note = (f"The full report <b>{_e(report_name)}</b> is attached."
                   if attached else
                   f"The report <b>{_e(report_name)}</b> was too large to attach; it is in the scan output folder "
                   f"(<code>{_e(meta['evidence_dir'])}</code>).")
    tools = " · ".join(f"{k} {v}" for k, v in meta["tools"].items())
    dbs = " · ".join(f"{k}: {v}" for k, v in meta["databases"].items() if "source" not in k)

    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Vulnerability scan</title></head>
<body style="margin:0;padding:0;background:#F3F4F6">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F3F4F6"><tr><td align="center" style="padding:24px 12px">
<table width="760" cellpadding="0" cellspacing="0" style="max-width:760px;width:100%;background:#FFFFFF;border-radius:10px;overflow:hidden;border:1px solid #E5E7EB">
<tr><td style="background:#1E3A5F;padding:22px 28px;{FONT}">
  <div style="color:#93C5FD;font-size:11px;font-weight:700;letter-spacing:1.2px">VULNERABILITY SCAN</div>
  <div style="color:#FFFFFF;font-size:22px;font-weight:700;margin-top:4px">{_e(", ".join(s["repos"]))}</div>
  <div style="color:#CBD5E1;font-size:12px;margin-top:6px">{_e(meta["started"])} · duration {_e(meta["duration"])} · {s["files"]:,} files scanned</div>
</td></tr>
<tr><td style="padding:22px 28px 6px">{status}</td></tr>
<tr><td style="padding:14px 28px 0"><table width="100%" cellpadding="0" cellspacing="0"><tr>{tiles}</tr></table></td></tr>
<tr><td style="padding:8px 28px 24px">
  <h3 style="{FONT}font-size:15px;color:#111827;margin:22px 0 8px">By repository</h3>
  <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #E5E7EB">
    <tr>{_th("Repository")}{_th("Rev")}{_th("Files", "right")}{_th("Critical", "right")}{_th("High", "right")}{_th("Medium", "right")}{_th("Low", "right")}{_th("KEV", "right")}{_th("Status")}</tr>
    {repo_rows}
  </table>
  {f'''<h3 style="{FONT}font-size:15px;color:#111827;margin:26px 0 8px">Highest-risk components</h3>
  <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #E5E7EB">
    <tr>{_th("Component")}{_th("Version")}{_th("Vulns", "right")}{_th("Critical", "right")}{_th("High", "right")}{_th("KEV", "right")}{_th("Files", "right")}</tr>
    {comp_rows}
  </table>''' if comp_rows else ""}
  {kev_block}
  {eol_block}
  <p style="{FONT}font-size:13px;color:#374151;margin:26px 0 0">{attach_note} Start with the <b>Summary</b> sheet,
  then filter <b>Findings</b> by <b>Priority</b> (P1 = actively exploited or critical with high exploit likelihood).</p>
</td></tr>
<tr><td style="background:#F9FAFB;border-top:1px solid #E5E7EB;padding:14px 28px;{FONT}font-size:11px;color:#6B7280;line-height:16px">
  {_e(tools)}<br>{_e(dbs)}<br>Run {_e(meta["run_id"])} · <code>{_e(meta["command"])}</code>
</td></tr>
</table></td></tr></table></body></html>"""


def render_text(s: dict, meta: dict, attached: bool, report_name: str) -> str:
    lines = [f"VULNERABILITY SCAN - {', '.join(s['repos'])}", f"{meta['started']} · duration {meta['duration']}", ""]
    lines.append("Status: " + ("complete" if s["status_ok"] else "INCOMPLETE - " + "; ".join(s["problems"])))
    lines.append(f"Findings {s['total']:,} | P1 {s['p1']:,} | KEV {s['kev']} | Critical {s['sev']['CRITICAL']:,} | "
                 f"High {s['sev']['HIGH']:,} | Medium {s['sev']['MEDIUM']:,} | End-of-life {s['eol']}")
    lines.append("")
    for r in s["per_repo"]:
        lines.append(f"  {r['name']:<16} {r['revision']:<8} crit {r['sev']['CRITICAL']:>5}  high {r['sev']['HIGH']:>5}  "
                     f"med {r['sev']['MEDIUM']:>5}  KEV {r['kev']:>3}  {'complete' if r['ok'] else 'INCOMPLETE'}")
    if s["kev_list"]:
        lines += ["", "Actively exploited (CISA KEV):"]
        lines += [f"  {k['id']}  {k['component']} {k['version']}" for k in s["kev_list"][:15]]
    lines += ["", f"Report: {report_name} " + ("(attached)" if attached else f"(in {meta['evidence_dir']})")]
    return "\n".join(lines)


def send_failure(error: str, meta: dict) -> None:
    """The scan could not produce a report at all: say so loudly (scheduled runs
    must never fail silently)."""
    cfg = config()
    repos = ", ".join(meta["repos"])
    msg = EmailMessage()
    msg["Subject"] = f"{cfg['prefix']} SCAN FAILED · {repos}"
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    if cfg["cc"]:
        msg["Cc"] = ", ".join(cfg["cc"])
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(f"SCAN FAILED - no report was produced.\n\nRepositories: {repos}\nStarted: {meta['started']}\n"
                    f"Error: {error}\n\nLog: {meta['evidence_dir']}/scan.log\nCommand: {meta['command']}\n")
    msg.add_alternative(f"""<!doctype html><html><body style="margin:0;padding:24px;background:#F3F4F6">
<table width="640" cellpadding="0" cellspacing="0" style="max-width:640px;background:#FFFFFF;border:1px solid #FECACA;border-radius:10px">
<tr><td style="background:#991B1B;padding:20px 26px;{FONT}">
<div style="color:#FECACA;font-size:11px;font-weight:700;letter-spacing:1.2px">VULNERABILITY SCAN</div>
<div style="color:#FFFFFF;font-size:22px;font-weight:700;margin-top:4px">Scan failed - no results</div>
<div style="color:#FEE2E2;font-size:12px;margin-top:6px">{_e(repos)} · {_e(meta['started'])}</div></td></tr>
<tr><td style="padding:22px 26px;{FONT}font-size:14px;color:#111827">
<p style="margin:0 0 12px">The scan stopped before it could produce a report. <b>This is not an all-clear</b> -
nothing about the current state of these repositories is known.</p>
<div style="background:#FEF2F2;border:1px solid #FECACA;border-radius:6px;padding:12px 14px;font-family:Consolas,monospace;font-size:12px;color:#7F1D1D">{_e(error)}</div>
<p style="margin:14px 0 0;font-size:12px;color:#6B7280">Log: <code>{_e(meta['evidence_dir'])}/scan.log</code><br>
Run {_e(meta['run_id'])} · <code>{_e(meta['command'])}</code></p></td></tr></table></body></html>""", subtype="html")
    _deliver(cfg, msg)
    log.info("failure notice emailed to %s", ", ".join(cfg["to"] + cfg["cc"]), extra={"stage": "email"})


def send(s: dict, meta: dict, report_path: Path) -> None:
    cfg = config()
    size_mb = report_path.stat().st_size / 1048576
    attach = size_mb <= cfg["max_mb"]
    if not attach:
        log.warning("report is %.1f MB (> SMTP_MAX_ATTACHMENT_MB=%.0f) - sending summary without attachment",
                    size_mb, cfg["max_mb"], extra={"stage": "email"})
    msg = EmailMessage()
    msg["Subject"] = subject(s, cfg["prefix"])
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"])
    if cfg["cc"]:
        msg["Cc"] = ", ".join(cfg["cc"])
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg["from"].split("@")[-1] if "@" in cfg["from"] else None)
    msg.set_content(render_text(s, meta, attach, report_path.name))
    msg.add_alternative(render_html(s, meta, attach, report_path.name), subtype="html")
    if attach:
        ctype = mimetypes.guess_type(report_path.name)[0] or "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(report_path.read_bytes(), maintype=maintype, subtype=subtype,
                           filename=report_path.name)

    _deliver(cfg, msg)
    log.info("report emailed to %s (%s)", ", ".join(cfg["to"] + cfg["cc"]),
             "with attachment" if attach else "summary only", extra={"stage": "email"})


def _deliver(cfg: dict, msg: EmailMessage) -> None:
    ctx = ssl.create_default_context()
    last_exc = None
    for attempt in range(1, 4):
        try:
            if cfg["security"] == "ssl":
                server = smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ctx, timeout=60)
            else:
                server = smtplib.SMTP(cfg["host"], cfg["port"], timeout=60)
            with server:
                server.ehlo()
                if cfg["security"] == "starttls":
                    server.starttls(context=ctx)
                    server.ehlo()
                if cfg["user"]:
                    server.login(cfg["user"], cfg["password"])
                server.send_message(msg)
            return
        except (smtplib.SMTPException, OSError) as exc:
            last_exc = exc
            log.warning("email attempt %d/3 failed: %s", attempt, exc, extra={"stage": "email"})
            if isinstance(exc, smtplib.SMTPAuthenticationError):
                break
            time.sleep(10 * attempt)
    raise RuntimeError(f"could not send email: {last_exc}")
