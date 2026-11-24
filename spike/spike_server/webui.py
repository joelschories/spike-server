"""Seite in Home Assistant (Seitenleiste „Spike“): zeigt den Kopplungscode."""
from __future__ import annotations

import html

PAGE = """<!doctype html><html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="refresh" content="15">
<title>Spike</title><style>
body{{margin:0;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Rounded",system-ui,sans-serif;background:#F7F2EA;color:#1D2A33;
display:flex;min-height:100vh;align-items:center;justify-content:center}}
.card{{background:#fff;border-radius:28px;padding:40px 36px;max-width:420px;text-align:center;box-shadow:0 10px 30px rgba(29,42,51,.08)}}
.shield{{width:72px;height:72px;border-radius:50%;background:#14A07A;color:#fff;display:flex;align-items:center;justify-content:center;
font-size:36px;margin:0 auto 18px}}
h1{{font-size:24px;margin:0 0 6px}} p{{color:#66727A;line-height:1.45;margin:0 0 22px}}
.code{{font-size:52px;font-weight:800;letter-spacing:6px;font-variant-numeric:tabular-nums;margin:6px 0}}
.small{{font-size:13px;color:#66727A}} .warn{{background:#FFF4E0;color:#A9650A;border-radius:14px;padding:12px 14px;font-size:14px;margin-top:20px}}
@media (prefers-color-scheme:dark){{body{{background:#0F1513;color:#EEF4F1}}.card{{background:#19211E}}p,.small{{color:#9DAAA4}}}}
</style></head><body><div class="card">
<div class="shield">✓</div><h1>Spike koppeln</h1>
<p>Öffne die Spike-App auf deinem iPhone oder Mac und gib diesen Code ein.</p>
<div class="code">{code}</div>
<div class="small">Gültig noch {minutes} Minuten · {paired} Gerät(e) gekoppelt</div>
{warning}
</div></body></html>"""


def render(code: str, seconds_left: int, paired: int, router_configured: bool, locked: bool) -> str:
    warning = ""
    if locked:
        warning = '<div class="warn">Zu viele falsche Versuche. Die Kopplung ist für 5 Minuten gesperrt.</div>'
    elif not router_configured:
        warning = ('<div class="warn">Demo-Modus: Trage im Reiter <b>Konfiguration</b> dieses Add-ons die '
                   'Zugangsdaten deiner FRITZ!Box ein, damit Spike dein echtes Netz sieht.</div>')
    return PAGE.format(code=html.escape(f"{code[:3]} {code[3:]}"), minutes=max(1, seconds_left // 60),
                       paired=paired, warning=warning)
