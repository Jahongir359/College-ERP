"""Render the Iceberg School app and web mockups referenced in ICEBERG_SCHOOL_APP_PLAN.md.

Each screen is plain HTML/CSS built from the brand tokens and the real logo files, rendered to PNG
with Playwright (Chromium). Sample names, times and data are fictional; amounts are left as
"[summa]" because prices are not decided.

    pip install playwright pillow          # dev machine only, not a project dependency
    python docs/plans/school-app-mockups/build_mockups.py [NAME ...]

Writes NN-name.png next to this file and overview.png (all phone screens on one sheet). Pass screen
names (e.g. ``18-web-parents``) to render only those and skip the overview.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
APP_IMG = REPO / "mobile" / "iceberg_app" / "assets" / "images"
BRAND_WEB = REPO / "docs" / "brand" / "iceberg-school" / "web"

CREST_WHITE = (APP_IMG / "brand" / "school" / "crest-white.png").as_uri()
LOGO_H_WHITE = (APP_IMG / "brand" / "school" / "logo-h-white.png").as_uri()
LOGO_H_MAROON = (BRAND_WEB / "logo-h-maroon.png").as_uri()
CREST_MAROON = (BRAND_WEB / "crest-maroon.png").as_uri()
CENTER_TILE = (APP_IMG / "logo.png").as_uri()

FONTS = (
    "https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT@9..144,500..700,50..100"
    "&family=Inter:wght@400;500;600;700;800&display=swap"
)

CSS = """
:root {
  --m: #4C0909; --m-hover: #7A1F1F; --m-deep: #2E0505; --m-soft: #F2D9D6; --m-ink: #F2B8B0;
  --tint: #F8F1F0; --bg: #FBF7F6; --border: #E8DCDA; --text: #1F1515; --muted: #5A4747;
  --gold: #C9973F; --gold-ink: #8A5A12; --gold-soft: #E9C77E; --surface: #FFFFFF;
  --ok: #17633A; --ok-bg: #E3F4EA; --late: #8A5A12; --late-bg: #FBF0D9; --abs: #A8322A; --abs-bg: #FBE6E3;
  --c-bg: #EDF3F9; --c-hi: #103A57; --c-deep: #07233A; --c-text: #06223A; --c-muted: #4C6480;
  --c-lime: #CDF163; --c-ice: #38BDF0; --c-stroke: #D2DFEC;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { width: 390px; height: 844px; overflow: hidden; font-family: Inter, sans-serif; color: var(--text);
  background: var(--bg); -webkit-font-smoothing: antialiased; position: relative; }
body.web { width: 1280px; height: 800px; }
body.dark { --bg: #140808; --surface: #1D0E0E; --tint: #251212; --border: #3A1E1E; --text: #F4E9E7;
  --muted: #BFA5A2; --ok-bg: #12301F; --ok: #7FD3A0; --late-bg: #33260F; --late: #E9C77E;
  --abs-bg: #3A1513; --abs: #F2A39A; }
.serif { font-family: Fraunces, serif; font-variation-settings: "SOFT" 100; font-weight: 600; letter-spacing: -.01em; }
.status { height: 44px; display: flex; align-items: center; justify-content: space-between; padding: 0 22px;
  font-size: 15px; font-weight: 600; }
.status .ic { display: flex; gap: 6px; align-items: center; }
.status .bat { width: 25px; height: 12px; border: 1.5px solid currentColor; border-radius: 3px; position: relative; opacity: .9 }
.status .bat::after { content: ""; position: absolute; inset: 1.5px; right: 6px; background: currentColor; border-radius: 1px; }
.on-dark { color: #fff; }
svg.i { width: 22px; height: 22px; fill: none; stroke: currentColor; stroke-width: 1.8; stroke-linecap: round; stroke-linejoin: round; flex: none; }
.pad { padding: 0 20px; }
.muted { color: var(--muted); }
.small { font-size: 13px; }
.tiny { font-size: 11.5px; }
.b { font-weight: 700; }
.row { display: flex; align-items: center; gap: 12px; }
.between { justify-content: space-between; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 24px; padding: 16px 18px;
  box-shadow: 0 1px 2px rgb(46 5 5 / .04), 0 10px 28px rgb(76 9 9 / .07); }
.pill { display: inline-flex; align-items: center; gap: 5px; padding: 5px 10px; border-radius: 999px; font-size: 12.5px; font-weight: 700; white-space: nowrap; }
.pill svg.i { width: 15px; height: 15px; stroke-width: 2.4; }
.ok { background: var(--ok-bg); color: var(--ok); }
.late { background: var(--late-bg); color: var(--late); }
.abs { background: var(--abs-bg); color: var(--abs); }
.kicker { font-size: 11.5px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; color: var(--gold-ink); }
body.dark .kicker { color: var(--gold-soft); }
.btn { display: flex; align-items: center; justify-content: center; gap: 8px; height: 52px; border-radius: 14px;
  font-weight: 700; font-size: 16px; border: 0; }
.btn-m { background: var(--m); color: #fff; box-shadow: 0 10px 22px rgb(76 9 9 / .28); }
.btn-ghost { background: var(--surface); color: var(--m); border: 1.5px solid var(--border); }
.tabbar { position: absolute; left: 0; right: 0; bottom: 0; height: 84px; background: var(--surface);
  border-top: 1px solid var(--border); display: grid; grid-template-columns: repeat(5, 1fr); padding: 8px 6px 0; }
.tab { display: grid; justify-items: center; gap: 4px; font-size: 11px; font-weight: 600; color: var(--muted); }
.tab .dot { width: 54px; height: 30px; border-radius: 999px; display: grid; place-items: center; }
.tab.on { color: var(--m); }
body.dark .tab.on { color: var(--m-ink); }
.tab.on .dot { background: var(--tint); }
.hero { background: radial-gradient(120% 90% at 100% 0%, #7A1F1F 0%, transparent 60%), linear-gradient(160deg, #5A0E0E, #2E0505);
  color: #fff; position: relative; overflow: hidden; }
.hero::after { content: ""; position: absolute; right: -40px; top: 18px; width: 190px; height: 224px;
  background: url(CREST_WHITE) no-repeat center / contain; opacity: .07; }
.chip-kid { display: flex; align-items: center; gap: 8px; padding: 6px 12px 6px 6px; border-radius: 999px;
  background: rgb(255 255 255 / .1); border: 1px solid rgb(255 255 255 / .18); font-size: 13.5px; font-weight: 600; color: #fff; }
.chip-kid.on { background: #fff; color: var(--m); border-color: var(--gold); box-shadow: 0 0 0 2px var(--gold); }
.av { width: 30px; height: 30px; border-radius: 999px; display: grid; place-items: center; font-size: 12.5px; font-weight: 800;
  background: var(--gold-soft); color: var(--m-deep); flex: none; }
.av.lg { width: 40px; height: 40px; font-size: 14px; }
.tile { width: 44px; height: 44px; border-radius: 14px; display: grid; place-items: center; background: var(--tint); color: var(--m); flex: none; }
body.dark .tile { color: var(--m-ink); }
.tile.solid { background: linear-gradient(145deg, var(--m-hover), var(--m)); color: var(--gold-soft); }
.grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.h-title { font-size: 26px; line-height: 1.15; }
.sec-t { font-size: 13px; font-weight: 800; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); margin: 18px 0 10px; }
.note { position: absolute; left: 12px; right: 12px; bottom: 92px; font-size: 11px; color: var(--muted); text-align: center; }
"""

ICONS = {
    "home": '<path d="M3 11.5 12 4l9 7.5"/><path d="M5.5 10v10h13V10"/>',
    "cal": '<rect x="3" y="5" width="18" height="16" rx="3"/><path d="M3 10h18M8 3v4m8-4v4"/>',
    "book": '<path d="M12 6.5c-2.5-1.6-5.5-2-8.5-1.6v13c3-.4 6 0 8.5 1.6 2.5-1.6 5.5-2 8.5-1.6v-13c-3-.4-6 0-8.5 1.6Z"/><path d="M12 6.5v13"/>',
    "wallet": '<path d="M3 7a2 2 0 0 1 2-2h13v4"/><rect x="3" y="7" width="18" height="13" rx="2.5"/><path d="M16 13.5h2"/>',
    "chat": '<path d="M4 5h16v11H9l-5 4Z"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c1-4 4.5-6 8-6s7 2 8 6"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "check": '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
    "x": '<path d="m6 6 12 12M18 6 6 18"/>',
    "bell": '<path d="M6 16V11a6 6 0 1 1 12 0v5l2 2H4Z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
    "chev": '<path d="m9 5 7 7-7 7"/>',
    "back": '<path d="M15 5 8 12l7 7"/>',
    "alert": '<path d="M12 3 2 20h20Z"/><path d="M12 10v4M12 17h.01"/>',
    "wifi-off": '<path d="M3 3l18 18M8.5 16.5a5 5 0 0 1 7 0M5 13a10 10 0 0 1 5-2.7M14 10.3A10 10 0 0 1 19 13M2 9.5a15 15 0 0 1 4.5-2.8M10 6.1A15 15 0 0 1 22 9.5"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c.8-3.5 3.3-5.5 6.5-5.5s5.7 2 6.5 5.5"/><path d="M16 4.6a3.5 3.5 0 0 1 0 6.8M18 14.8c1.8.8 3 2.5 3.5 5.2"/>',
    "grid": '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
    "star": '<path d="m12 3 2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1-4.4-4.3 6.1-.9Z"/>',
    "send": '<path d="M21 4 3 11l6 2 2 6 3-4 5 4Z"/><path d="m9 13 9-7"/>',
    "eye": '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.7 5.6 3.7 9s-1.2 6.4-3.7 9c-2.5-2.6-3.7-5.6-3.7-9S9.5 5.6 12 3Z"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "chart": '<path d="M4 20V10m6 10V4m6 16v-7m4 7H2"/>',
    "refresh": '<path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/>',
    "door": '<path d="M5 21V4h10v17M15 12h.01M3 21h18"/>',
    "upload": '<path d="M12 16V4m-5 5 5-5 5 5M4 20h16"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9m-4 4 3 3m-6 0 2 2"/>',
    "link": '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
}


def i(name: str, extra: str = "") -> str:
    return f'<svg class="i" viewBox="0 0 24 24" {extra}>{ICONS[name]}</svg>'


def status(dark_text: bool = True) -> str:
    cls = "" if dark_text else "on-dark"
    return (
        f'<div class="status {cls}"><span>9:41</span><span class="ic">'
        '<svg width="18" height="12" viewBox="0 0 18 12" fill="currentColor"><rect x="0" y="8" width="3" height="4" rx="1"/>'
        '<rect x="5" y="5" width="3" height="7" rx="1"/><rect x="10" y="2" width="3" height="10" rx="1"/>'
        '<rect x="15" y="0" width="3" height="12" rx="1"/></svg><span class="bat"></span></span></div>'
    )


def tabbar(items: list[tuple[str, str]], active: int) -> str:
    cells = "".join(
        f'<div class="tab{" on" if n == active else ""}"><span class="dot">{i(icon)}</span>{label}</div>'
        for n, (icon, label) in enumerate(items)
    )
    return f'<nav class="tabbar">{cells}</nav>'


PARENT_TABS = [
    ("home", "Asosiy"),
    ("cal", "Jadval"),
    ("book", "Vazifalar"),
    ("chat", "Xabarlar"),
    ("user", "Profil"),
]
TEACHER_TABS = [
    ("home", "Bugun"),
    ("users", "Sinflarim"),
    ("check", "Davomat"),
    ("chat", "Xabarlar"),
    ("user", "Profil"),
]


def page(body: str, cls: str = "") -> str:
    css = CSS.replace("CREST_WHITE", CREST_WHITE)
    return (
        f'<!doctype html><html lang="uz"><head><meta charset="utf-8"><link rel="stylesheet" href="{FONTS}">'
        f'<style>{css}</style></head><body class="{cls}">{body}</body></html>'
    )


# ---------------------------------------------------------------- screens


def s_choice() -> str:
    return page(f"""
{status()}
<div class="pad" style="padding-top:10px">
  <div class="row between">
    <img src="{CREST_MAROON}" style="height:40px" alt="">
    <div class="row" style="gap:4px;background:var(--surface);border:1px solid var(--border);border-radius:999px;padding:4px">
      <span class="pill" style="background:var(--m);color:#fff">UZ</span><span class="pill muted">RU</span><span class="pill muted">EN</span>
    </div>
  </div>
  <p class="kicker" style="margin-top:34px">Xush kelibsiz</p>
  <h1 class="serif" style="font-size:34px;line-height:1.1;margin-top:8px;color:var(--m)">Qaysi Iceberg'ga kirasiz?</h1>
  <p class="muted" style="margin-top:10px;font-size:15.5px;line-height:1.5">Tanlang — keyingi safar ilova shu yerdan ochiladi.</p>

  <div style="margin-top:28px;display:grid;gap:14px">
    <div class="hero" style="border-radius:28px;padding:22px;min-height:178px;display:grid;align-content:space-between;box-shadow:0 18px 40px rgb(76 9 9 / .28)">
      <div class="row between" style="position:relative;z-index:1">
        <img src="{CREST_WHITE}" style="height:58px" alt="">
        <span style="width:40px;height:40px;border-radius:999px;background:rgb(255 255 255 / .14);display:grid;place-items:center">{i("chev")}</span>
      </div>
      <div style="position:relative;z-index:1">
        <div class="serif" style="font-size:25px">Iceberg School</div>
        <div style="color:var(--m-soft);font-size:14px;margin-top:3px">Xususiy maktab · 1–11-sinflar</div>
        <div style="height:2px;width:46px;background:var(--gold);border-radius:2px;margin-top:12px"></div>
      </div>
    </div>
    <div style="border-radius:28px;padding:22px;min-height:178px;display:grid;align-content:space-between;color:#fff;
      background:radial-gradient(120% 90% at 100% 0%, #1B5A82 0%, transparent 60%), linear-gradient(160deg, var(--c-hi), var(--c-deep));box-shadow:0 18px 40px rgb(7 35 58 / .3)">
      <div class="row between">
        <img src="{CENTER_TILE}" style="height:58px;width:58px;border-radius:16px" alt="">
        <span style="width:40px;height:40px;border-radius:999px;background:rgb(255 255 255 / .14);display:grid;place-items:center;color:var(--c-lime)">{i("chev")}</span>
      </div>
      <div>
        <div style="font-size:23px;font-weight:800;letter-spacing:-.01em">Iceberg Study Center</div>
        <div style="color:#AFD9F2;font-size:14px;margin-top:3px">IELTS, CEFR, SAT va fan kurslari</div>
        <div style="height:2px;width:46px;background:var(--c-lime);border-radius:2px;margin-top:12px"></div>
      </div>
    </div>
  </div>
  <p class="muted small" style="text-align:center;margin-top:22px">Tanlovni kirish sahifasida o'zgartirish mumkin</p>
</div>""")


def s_login_school() -> str:
    return page(f"""
<div class="hero" style="height:300px;border-radius:0 0 36px 36px">
  {status(False)}
  <div style="display:grid;justify-items:center;gap:14px;padding-top:30px;position:relative;z-index:1">
    <div style="width:96px;height:96px;border-radius:28px;background:rgb(255 255 255 / .1);border:1px solid rgb(255 255 255 / .18);display:grid;place-items:center;box-shadow:0 0 40px rgb(201 151 63 / .25)">
      <img src="{CREST_WHITE}" style="height:62px" alt="">
    </div>
    <img src="{LOGO_H_WHITE}" style="height:44px" alt="Iceberg School">
  </div>
</div>
<div class="pad" style="margin-top:-46px;position:relative">
  <div class="card" style="padding:24px 22px;border-radius:28px">
    <h1 class="serif" style="font-size:26px">Xush kelibsiz</h1>
    <p class="muted" style="margin-top:4px">Davom etish uchun kiring</p>
    <label class="small b" style="display:block;margin-top:20px">Login ID</label>
    <div style="margin-top:7px;height:52px;border:1.5px solid var(--m-hover);border-radius:14px;background:#fff;display:flex;align-items:center;padding:0 14px;box-shadow:0 0 0 4px rgb(76 9 9 / .1)">S-24-0317<span style="width:1.5px;height:22px;background:var(--m);margin-left:2px"></span></div>
    <label class="small b" style="display:block;margin-top:14px">Parol</label>
    <div class="row between" style="margin-top:7px;height:52px;border:1.5px solid var(--border);border-radius:14px;background:#FBF8F7;padding:0 14px;color:var(--muted)">••••••••{i("eye")}</div>
    <div class="row between" style="margin-top:14px"><span class="small row" style="gap:8px"><span style="width:20px;height:20px;border-radius:6px;background:var(--m);color:#fff;display:grid;place-items:center">{i("check", 'style="width:14px;height:14px;stroke-width:3"')}</span>Eslab qolish</span><span class="small b" style="color:var(--m)">Parolni unutdingizmi?</span></div>
    <div class="btn btn-m" style="margin-top:20px">Kirish</div>
  </div>
  <p class="small muted" style="text-align:center;margin-top:20px">Iceberg School · <b style="color:var(--m)">Boshqa tanlash</b></p>
</div>""")


def s_login_center() -> str:
    return page(
        f"""
<div style="height:300px;border-radius:0 0 36px 36px;color:#fff;background:radial-gradient(120% 90% at 100% 0%, #1B5A82 0%, transparent 60%), linear-gradient(160deg, var(--c-hi), var(--c-deep))">
  {status(False)}
  <div style="display:grid;justify-items:center;gap:14px;padding-top:30px">
    <img src="{CENTER_TILE}" style="height:96px;width:96px;border-radius:28px;box-shadow:0 0 40px rgb(56 189 240 / .35)" alt="">
    <div style="font-size:22px;font-weight:800;letter-spacing:.02em">ICEBERG <span style="color:#AFD9F2;font-weight:600">Study Center</span></div>
  </div>
</div>
<div class="pad" style="margin-top:-46px;position:relative">
  <div class="card" style="padding:24px 22px;border-radius:28px;border-color:var(--c-stroke)">
    <h1 style="font-size:24px;font-weight:800;color:var(--c-text)">Xush kelibsiz</h1>
    <p style="margin-top:4px;color:var(--c-muted)">Davom etish uchun kiring</p>
    <label class="small b" style="display:block;margin-top:20px;color:var(--c-text)">Login ID</label>
    <div style="margin-top:7px;height:52px;border:1.5px solid var(--c-stroke);border-radius:14px;background:#F8FAFD"></div>
    <label class="small b" style="display:block;margin-top:14px;color:var(--c-text)">Parol</label>
    <div style="margin-top:7px;height:52px;border:1.5px solid var(--c-stroke);border-radius:14px;background:#F8FAFD"></div>
    <div class="btn" style="margin-top:22px;background:var(--c-lime);color:var(--c-deep)">Kirish</div>
  </div>
  <p class="small" style="text-align:center;margin-top:20px;color:var(--c-muted)">Iceberg Study Center · <b style="color:var(--c-hi)">Boshqa tanlash</b></p>
</div>""",
        "center",
    )


def _parent_home(dark: bool) -> str:
    return page(
        f"""
<div class="hero" style="padding-bottom:70px">
  {status(False)}
  <div class="pad" style="position:relative;z-index:1">
    <div class="row between"><img src="{LOGO_H_WHITE}" style="height:30px" alt="Iceberg School">
      <span style="position:relative">{i("bell")}<span style="position:absolute;top:-2px;right:-2px;width:9px;height:9px;border-radius:9px;background:var(--gold);border:2px solid #4C0909"></span></span></div>
    <p class="serif" style="font-size:27px;margin-top:18px">Xayrli tong!</p>
    <div class="row" style="margin-top:14px;gap:8px">
      <span class="chip-kid on"><span class="av">AK</span>Aziza · 3-A</span>
      <span class="chip-kid"><span class="av" style="background:#fff;opacity:.9">BK</span>Bobur · 7-B</span>
    </div>
  </div>
</div>
<div class="pad" style="margin-top:-52px;position:relative;display:grid;gap:12px">
  <div class="card">
    <div class="row between"><span class="kicker">Bugun · Payshanba, 24-okt</span></div>
    <div class="row between" style="margin-top:12px">
      <span class="pill ok">{i("check")}Keldi 07:52</span><span class="tiny muted">Sinf rahbari belgiladi</span>
    </div>
    <div style="height:1px;background:var(--border);margin:14px 0"></div>
    <div class="row"><span class="tile solid">{i("clock")}</span><div><div class="tiny muted">Hozir · 2-dars, 08:55–09:40</div><div class="b" style="font-size:17px">Matematika</div></div></div>
    <div class="row small muted" style="margin-top:10px;padding-left:56px">Keyin: Ona tili · 09:50</div>
  </div>
  <div class="grid2">
    <div class="card" style="padding:14px 16px"><span class="tile">{i("book")}</span><div class="b" style="margin-top:10px;font-size:22px">2</div><div class="small muted">ta vazifa · ertaga</div></div>
    <div class="card" style="padding:14px 16px"><span class="tile">{i("wallet")}</span><div class="b" style="margin-top:10px">Noyabr</div><div class="small muted">[summa] so'm</div><div class="small b" style="color:var(--gold-ink);margin-top:4px">To'lash →</div></div>
  </div>
  <div class="card row" style="padding:14px 16px"><span class="tile">{i("chat")}</span><div style="flex:1"><div class="b">Dilnoza Rahimova</div><div class="small muted">Ertaga sport kiyimi kerak bo'ladi…</div></div><span class="pill" style="background:var(--m);color:#fff">1</span></div>
  <div class="card" style="padding:14px 16px;border-left:4px solid var(--gold)"><div class="kicker">E'lon · 3-A</div><div class="b" style="margin-top:6px">Ota-onalar majlisi</div><div class="small muted">Shanba, 26-okt · 10:00 · 12-xona</div></div>
</div>
{tabbar(PARENT_TABS, 0)}""",
        "dark" if dark else "",
    )


def s_parent_home() -> str:
    return _parent_home(False)


def s_parent_home_dark() -> str:
    return _parent_home(True)


def s_timetable() -> str:
    lessons = [
        ("1", "08:00", "08:45", "Ona tili", "Gulnora Saidova", "12-xona", False, False),
        ("2", "08:55", "09:40", "Matematika", "Dilnoza Rahimova", "12-xona", True, True),
        ("3", "09:50", "10:35", "Ingliz tili", "Kamola Yusupova", "8-xona", False, False),
        ("4", "10:55", "11:40", "O'qish", "Gulnora Saidova", "Kutubxona", False, True),
        ("5", "11:50", "12:35", "Tabiiy fan", "Sherzod Aliyev", "12-xona", False, False),
        ("6", "12:45", "13:30", "Jismoniy tarbiya", "Bekzod Qodirov", "Sport zali", False, False),
    ]
    rows = ""
    for n, t1, t2, subj, teacher, room, now, hw in lessons:
        style = (
            "border:1.5px solid var(--m);box-shadow:0 10px 24px rgb(76 9 9 / .12)" if now else ""
        )
        badge = (
            '<span class="pill" style="background:var(--m);color:#fff;padding:3px 9px;font-size:11px">Hozir</span>'
            if now
            else ""
        )
        small_book = i("book", 'style="width:14px;height:14px"')
        hwb = (
            f'<span class="tiny b row" style="gap:4px;color:var(--gold-ink)">{small_book}Vazifa</span>'
            if hw
            else ""
        )
        rows += f"""<div class="card row" style="padding:12px 14px;border-radius:20px;{style}">
          <div style="width:52px;text-align:center"><div class="b" style="font-size:15px">{t1}</div><div class="tiny muted">{t2}</div></div>
          <div style="width:1px;align-self:stretch;background:var(--border)"></div>
          <div style="flex:1"><div class="row between"><span class="b">{n}. {subj}</span>{badge}</div>
          <div class="row between" style="margin-top:3px"><span class="small muted">{teacher} · {room}</span>{hwb}</div></div></div>"""
    days = "".join(
        f'<div style="display:grid;justify-items:center;gap:2px;padding:8px 0;border-radius:14px;{"background:var(--m);color:#fff" if d == "Pa" else ""}">'
        f'<span class="tiny" style="opacity:.8">{d}</span><span class="b">{n}</span></div>'
        for d, n in (("Du", 21), ("Se", 22), ("Ch", 23), ("Pa", 24), ("Ju", 25), ("Sh", 26))
    )
    return page(f"""
{status()}
<div class="pad">
  <div class="row between" style="margin-top:6px"><h1 class="serif h-title" style="color:var(--m)">Dars jadvali</h1><span class="chip-kid on" style="font-size:12.5px"><span class="av" style="width:24px;height:24px;font-size:10.5px">AK</span>Aziza · 3-A</span></div>
  <div class="card" style="margin-top:14px;padding:8px;display:grid;grid-template-columns:repeat(6,1fr);gap:4px;border-radius:20px">{days}</div>
  <div style="display:grid;gap:9px;margin-top:14px">{rows}</div>
</div>
{tabbar(PARENT_TABS, 1)}""")


def s_attendance() -> str:
    marks = {
        1: "ok",
        2: "ok",
        3: "ok",
        5: "ok",
        6: "ok",
        7: "late",
        8: "ok",
        9: "ok",
        10: "ok",
        12: "ok",
        13: "ok",
        14: "abs",
        15: "ok",
        16: "ok",
        17: "ok",
        19: "ok",
        20: "ok",
        21: "ok",
        22: "late",
        23: "ok",
        24: "ok",
    }
    cells = ""
    # October 2026 starts on a Thursday; Mon–Sat columns, Sundays skipped.
    import datetime as dt

    start = dt.date(2026, 10, 1)
    lead = start.weekday()
    cells += "<div></div>" * lead
    d = start
    while d.month == 10:
        if d.weekday() != 6:
            m = marks.get(d.day)
            color = {"ok": "var(--ok)", "late": "var(--gold)", "abs": "var(--abs)"}.get(
                m, "transparent"
            )
            today = "border:1.5px solid var(--m);" if d.day == 24 else ""
            fut = "opacity:.4;" if d.day > 24 else ""
            cells += (
                f'<div style="height:44px;border-radius:12px;display:grid;justify-items:center;align-content:center;gap:4px;{today}{fut}">'
                f'<span class="small b">{d.day}</span><span style="width:7px;height:7px;border-radius:7px;background:{color}"></span></div>'
            )
        d += dt.timedelta(days=1)
    head = "".join(
        f'<div class="tiny b muted" style="text-align:center">{x}</div>'
        for x in ("Du", "Se", "Ch", "Pa", "Ju", "Sh")
    )
    return page(f"""
{status()}
<div class="pad">
  <div class="row" style="margin-top:6px;gap:10px">{i("back")}<h1 class="serif h-title" style="color:var(--m)">Davomat</h1></div>
  <p class="small muted" style="margin:4px 0 0 34px">Aziza Karimova · 3-A</p>
  <div class="card" style="margin-top:16px">
    <div class="row between"><span>{i("back", 'style="width:18px;height:18px"')}</span><span class="b">Oktabr 2026</span><span>{i("chev", 'style="width:18px;height:18px"')}</span></div>
    <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:4px;margin-top:14px">{head}{cells}</div>
    <div class="row" style="gap:14px;margin-top:12px;flex-wrap:wrap">
      <span class="tiny row" style="gap:5px"><span style="width:8px;height:8px;border-radius:8px;background:var(--ok)"></span>Keldi</span>
      <span class="tiny row" style="gap:5px"><span style="width:8px;height:8px;border-radius:8px;background:var(--gold)"></span>Kechikdi</span>
      <span class="tiny row" style="gap:5px"><span style="width:8px;height:8px;border-radius:8px;background:var(--abs)"></span>Kelmadi</span>
    </div>
  </div>
  <p class="sec-t">1-chorak</p>
  <div class="grid2" style="grid-template-columns:repeat(3,1fr)">
    <div class="card" style="padding:12px;text-align:center"><div class="b" style="font-size:22px;color:var(--ok)">38</div><div class="tiny muted">Keldi</div></div>
    <div class="card" style="padding:12px;text-align:center"><div class="b" style="font-size:22px;color:var(--gold-ink)">2</div><div class="tiny muted">Kechikdi</div></div>
    <div class="card" style="padding:12px;text-align:center"><div class="b" style="font-size:22px;color:var(--abs)">1</div><div class="tiny muted">Kelmadi</div></div>
  </div>
  <div class="card row" style="margin-top:12px;padding:12px 14px"><span class="pill abs">{i("x")}Kelmadi</span><span class="small">14-okt · <span class="muted">Kasal (ota-ona xabar bergan)</span></span></div>
</div>
{tabbar(PARENT_TABS, 0)}""")


def s_teacher_home() -> str:
    lessons = [
        ("08:00", "Ona tili", "3-A", "12-xona", False),
        ("08:55", "Ona tili", "4-B", "14-xona", True),
        ("10:55", "O'qish", "3-A", "Kutubxona", False),
    ]
    now_pill = (
        '<span class="pill" style="background:var(--m);color:#fff;font-size:11px">Hozir</span>'
    )
    rows = "".join(
        f'<div class="card row" style="padding:12px 14px;border-radius:20px;{"border:1.5px solid var(--m)" if now else ""}">'
        f'<div class="b" style="width:52px">{t}</div><div style="flex:1"><div class="b">{s}</div><div class="small muted">{c} sinf · {r}</div></div>'
        f"{now_pill if now else i('chev')}</div>"
        for t, s, c, r, now in lessons
    )
    return page(f"""
<div class="hero" style="padding-bottom:26px;border-radius:0 0 32px 32px">
  {status(False)}
  <div class="pad" style="position:relative;z-index:1">
    <div class="row between"><img src="{LOGO_H_WHITE}" style="height:30px" alt="Iceberg School">{i("bell")}</div>
    <p class="serif" style="font-size:26px;margin-top:16px">Xayrli tong, Gulnora opa</p>
    <p style="color:var(--m-soft);font-size:14px;margin-top:4px">Payshanba, 24-oktabr · 3-A sinf rahbari</p>
  </div>
</div>
<div class="pad" style="margin-top:16px;display:grid;gap:10px">
  <div class="card" style="background:var(--late-bg);border-color:#EED9AE">
    <div class="row"><span class="tile" style="background:#fff;color:var(--late)">{i("alert")}</span><div><div class="b">3-A davomati hali olinmagan</div><div class="small muted">Ota-onalar 09:00 dan keyin xabar oladi</div></div></div>
    <div class="btn btn-m" style="margin-top:12px;height:46px">Davomatni olish</div>
  </div>
  <p class="sec-t" style="margin:8px 0 2px">Bugungi darslar</p>
  {rows}
  <div class="card row" style="padding:12px 14px"><span class="tile">{i("chat")}</span><div style="flex:1"><div class="b">2 ta yangi xabar</div><div class="small muted">Ota-onalardan</div></div>{i("chev")}</div>
</div>
{tabbar(TEACHER_TABS, 0)}""")


def _register_rows(late_sheet: bool) -> str:
    kids = [
        ("Abdullayev Jasur", "ok", ""),
        ("Aliyeva Madina", "ok", ""),
        ("Bakirov Sardor", "late", "08:12"),
        ("Ergasheva Zarina", "ok", ""),
        ("Hasanov Temur", "abs", "Kasal"),
        ("Ismoilova Nodira", "ok", ""),
        ("Karimova Aziza", "ok", ""),
        ("Mahmudov Ulug'bek", "ok", ""),
        ("Nazarova Sevara", "ok", ""),
    ]
    out = ""
    for name, st, extra in kids:
        initials = "".join(p[0] for p in name.split()[:2])
        seg = ""
        for key, label, icon in (
            ("ok", "Keldi", "check"),
            ("late", "Kechikdi", "clock"),
            ("abs", "Yo'q", "x"),
        ):
            on = key == st
            seg += (
                f'<span class="pill {key if on else ""}" style="padding:6px 9px;{"" if on else "color:var(--muted)"}">'
                f"{i(icon)}{label if on else ''}</span>"
            )
        sub = (
            f'<div class="tiny" style="color:var(--{"late" if st == "late" else "abs"})">{"Keldi " + extra if st == "late" else extra}</div>'
            if extra
            else ""
        )
        out += (
            f'<div class="row" style="padding:10px 0;border-bottom:1px solid var(--border)">'
            f'<span class="av lg">{initials}</span><div style="flex:1;min-width:0"><div class="b" style="font-size:14.5px">{name}</div>{sub}</div>'
            f'<div class="row" style="gap:2px;background:var(--tint);border-radius:999px;padding:3px">{seg}</div></div>'
        )
    return out


def s_register() -> str:
    return page(f"""
{status()}
<div class="pad">
  <div class="row between" style="margin-top:4px"><div class="row" style="gap:10px">{i("back")}<div><h1 class="serif" style="font-size:24px;color:var(--m)">Davomat · 3-A</h1><div class="small muted">Payshanba, 24-oktabr</div></div></div></div>
  <div class="row" style="gap:6px;margin-top:14px">
    <span class="pill ok">28 keldi</span><span class="pill late">1 kechikdi</span><span class="pill abs">1 yo'q</span>
  </div>
  <p class="tiny muted" style="margin-top:10px">Hammasi "Keldi" turibdi — faqat o'zgarganini bosing.</p>
  <div style="margin-top:4px">{_register_rows(False)}</div>
</div>
<div style="position:absolute;left:0;right:0;bottom:0;padding:12px 20px 30px;background:var(--surface);border-top:1px solid var(--border)">
  <div class="btn btn-m">Saqlash · 30 o'quvchi</div>
  <p class="tiny muted" style="text-align:center;margin-top:8px">Internet bo'lmasa ham saqlanadi va keyin yuboriladi</p>
</div>""")


def s_register_late() -> str:
    return page(f"""
{status()}
<div class="pad" style="opacity:.35">
  <div class="row" style="gap:10px;margin-top:4px">{i("back")}<h1 class="serif" style="font-size:24px;color:var(--m)">Davomat · 3-A</h1></div>
  <div style="margin-top:60px">{_register_rows(True)}</div>
</div>
<div style="position:absolute;inset:0;background:rgb(31 21 21 / .35)"></div>
<div style="position:absolute;left:0;right:0;bottom:0;background:var(--surface);border-radius:32px 32px 0 0;padding:12px 20px 34px">
  <div style="width:44px;height:5px;border-radius:5px;background:var(--border);margin:0 auto 16px"></div>
  <div class="row"><span class="av lg">BS</span><div><div class="b" style="font-size:17px">Bakirov Sardor</div><div class="small muted">Kechikdi — qachon keldi?</div></div></div>
  <div style="text-align:center;margin:22px 0 8px"><span class="serif" style="font-size:56px;color:var(--m)">08:12</span></div>
  <div class="row" style="justify-content:center;gap:8px">
    <span class="pill" style="background:var(--m);color:#fff;padding:8px 14px">Hozir</span><span class="pill" style="background:var(--tint);padding:8px 14px">−5 daq</span><span class="pill" style="background:var(--tint);padding:8px 14px">−10 daq</span>
  </div>
  <label class="small b" style="display:block;margin-top:18px">Izoh (ixtiyoriy)</label>
  <div style="margin-top:7px;height:48px;border:1.5px solid var(--border);border-radius:14px;background:#FBF8F7;padding:14px;color:var(--muted)" class="small">Masalan: avtobus kechikdi</div>
  <div class="btn btn-m" style="margin-top:16px">Tayyor</div>
</div>""")


def s_messages() -> str:
    bubbles = [
        (
            "them",
            "Assalomu alaykum! Ertaga jismoniy tarbiya darsi bor, Azizaga sport kiyimi kerak bo'ladi.",
            "08:31",
        ),
        ("me", "Va alaykum assalom, rahmat! Tayyorlab qo'yamiz.", "08:40"),
        ("them", "Yana eslatma: O'qish kitobi 12-betgacha o'qilsin 📖", "08:41"),
    ]
    html = ""
    for who, text, t in bubbles:
        me = who == "me"
        html += (
            f'<div style="display:flex;justify-content:{"flex-end" if me else "flex-start"}">'
            f'<div style="max-width:78%;padding:11px 14px;border-radius:20px;{"border-bottom-right-radius:6px;background:var(--m);color:#fff" if me else "border-bottom-left-radius:6px;background:var(--surface);border:1px solid var(--border)"}">'
            f'<div style="font-size:14.5px;line-height:1.45">{text}</div><div class="tiny" style="text-align:right;margin-top:4px;opacity:.7">{t}</div></div></div>'
        )
    return page(f"""
{status()}
<div class="pad" style="border-bottom:1px solid var(--border);padding-bottom:12px">
  <div class="row" style="gap:10px">{i("back")}<span class="av lg" style="background:var(--m);color:#fff">DR</span><div><div class="b">Dilnoza Rahimova</div><div class="tiny muted">3-A sinf rahbari · Matematika</div></div></div>
  <span class="pill" style="background:var(--tint);color:var(--m);margin:10px 0 0 32px">Aziza Karimova haqida</span>
</div>
<div class="pad" style="display:grid;gap:10px;margin-top:16px">
  <div class="tiny muted" style="text-align:center">Bugun</div>{html}
</div>
<div style="position:absolute;left:0;right:0;bottom:0;padding:10px 16px 30px;background:var(--surface);border-top:1px solid var(--border)" class="row">
  <div style="flex:1;height:46px;border-radius:999px;background:var(--tint);padding:0 16px;display:flex;align-items:center" class="small muted">Xabar yozing…</div>
  <span style="width:46px;height:46px;border-radius:999px;background:var(--m);color:#fff;display:grid;place-items:center">{i("send")}</span>
</div>""")


def s_payments() -> str:
    rows = [
        ("Noyabr 2026", "Kutilmoqda", "late", "15-noyabrgacha"),
        ("Oktabr 2026", "To'langan", "ok", "3-okt · Click"),
        ("Sentabr 2026", "To'langan", "ok", "2-sen · Naqd"),
        ("Avgust 2026", "To'langan", "ok", "28-avg · Payme"),
    ]
    items = "".join(
        f'<div class="card row" style="padding:14px 16px"><span class="tile">{i("wallet")}</span><div style="flex:1"><div class="b">{m}</div><div class="small muted">{note}</div></div>'
        f'<div style="text-align:right"><div class="b small">[summa]</div><span class="pill {cls}" style="margin-top:4px;font-size:11px;padding:3px 8px">{st}</span></div></div>'
        for m, st, cls, note in rows
    )
    return page(f"""
{status()}
<div class="pad">
  <h1 class="serif h-title" style="color:var(--m);margin-top:6px">To'lovlar</h1>
  <p class="small muted" style="margin-top:2px">Aziza Karimova · 3-A</p>
  <div class="hero" style="border-radius:28px;padding:20px;margin-top:14px">
    <div style="position:relative;z-index:1">
      <div class="kicker" style="color:var(--gold-soft)">To'lanishi kerak</div>
      <div class="serif" style="font-size:32px;margin-top:6px">[summa] so'm</div>
      <div style="color:var(--m-soft);font-size:14px;margin-top:2px">Noyabr · 15-noyabrgacha</div>
      <div class="btn" style="margin-top:16px;background:#fff;color:var(--m);height:48px">To'lash</div>
    </div>
  </div>
  <p class="sec-t">Tarix</p>
  <div style="display:grid;gap:10px">{items}</div>
</div>
{tabbar(PARENT_TABS, 4)}""")


def s_homework() -> str:
    groups = [
        (
            "Ertaga · Juma",
            [
                ("Matematika", "15-bet, 3–5-misollar", "Dilnoza Rahimova", True),
                ("O'qish", '"Zumrad va Qimmat" ertagi, 12-betgacha', "Gulnora Saidova", False),
            ],
        ),
        ("Dushanba", [("Ingliz tili", "Workbook p. 18, ex. 1–2", "Kamola Yusupova", False)]),
    ]
    html = ""
    for title, items in groups:
        html += f'<p class="sec-t">{title}</p><div style="display:grid;gap:10px">'
        for subj, task, teacher, file in items:
            upload = i("upload", 'style="width:14px;height:14px"')
            att = (
                f'<span class="tiny b row" style="gap:4px;color:var(--gold-ink);margin-top:8px">{upload}1 ta fayl</span>'
                if file
                else ""
            )
            html += (
                f'<div class="card" style="padding:14px 16px"><div class="row between"><span class="b">{subj}</span><span class="tiny muted">{teacher}</span></div>'
                f'<div style="margin-top:6px;font-size:14.5px;line-height:1.45">{task}</div>{att}</div>'
            )
        html += "</div>"
    return page(f"""
{status()}
<div class="pad">
  <div class="row between" style="margin-top:6px"><h1 class="serif h-title" style="color:var(--m)">Vazifalar</h1><span class="chip-kid on" style="font-size:12.5px"><span class="av" style="width:24px;height:24px;font-size:10.5px">AK</span>Aziza · 3-A</span></div>
  {html}
</div>
{tabbar(PARENT_TABS, 2)}""")


def s_grades() -> str:
    subjects = [
        ("Matematika", ["5", "4", "5", "5"], "5"),
        ("Ona tili", ["4", "4", "5"], "4"),
        ("Ingliz tili", ["5", "5"], "5"),
        ("O'qish", ["5", "5", "4"], "5"),
        ("Tabiiy fan", ["4", "3", "4"], "4"),
    ]

    def mark(v: str) -> str:
        bg = {"5": "var(--ok-bg)", "4": "var(--tint)", "3": "var(--late-bg)", "2": "var(--abs-bg)"}[
            v
        ]
        fg = {"5": "var(--ok)", "4": "var(--m)", "3": "var(--late)", "2": "var(--abs)"}[v]
        return f'<span style="width:30px;height:30px;border-radius:10px;display:grid;place-items:center;font-weight:800;background:{bg};color:{fg}">{v}</span>'

    rows = "".join(
        f'<div class="card row" style="padding:12px 14px"><div style="flex:1"><div class="b">{s}</div><div class="row" style="gap:5px;margin-top:8px">{"".join(mark(m) for m in ms)}</div></div>'
        f'<div style="text-align:center"><div class="tiny muted">Chorak</div><div class="serif" style="font-size:28px;color:var(--m)">{q}</div></div></div>'
        for s, ms, q in subjects
    )
    return page(f"""
{status()}
<div class="pad">
  <div class="row between" style="margin-top:6px"><h1 class="serif h-title" style="color:var(--m)">Baholar</h1><span class="pill" style="background:var(--gold-soft);color:var(--m-deep)">2-bosqich</span></div>
  <div class="row" style="gap:6px;margin-top:12px"><span class="pill" style="background:var(--m);color:#fff">1-chorak</span><span class="pill" style="background:var(--tint)">2-chorak</span><span class="pill" style="background:var(--tint)">Yillik</span></div>
  <div style="display:grid;gap:10px;margin-top:14px">{rows}</div>
</div>
{tabbar(PARENT_TABS, 0)}""")


def s_states() -> str:
    return page(f"""
{status()}
<div style="background:#3A2A12;color:#FBF0D9;padding:10px 20px" class="row small">{i("wifi-off", 'style="width:18px;height:18px"')}<span>Internet yo'q · 08:40 dagi ma'lumotlar ko'rsatilmoqda</span></div>
<div class="pad">
  <h1 class="serif h-title" style="color:var(--m);margin-top:14px">Vazifalar</h1>
  <div class="card" style="margin-top:16px;text-align:center;padding:30px 22px;position:relative;overflow:hidden">
    <img src="{CREST_MAROON}" style="height:74px;opacity:.14;margin:0 auto" alt="">
    <div class="serif" style="font-size:21px;margin-top:12px;color:var(--m)">Bugun uy vazifasi yo'q</div>
    <p class="small muted" style="margin-top:6px">Yangi vazifa qo'shilganda shu yerda ko'rinadi va xabar keladi.</p>
  </div>
  <p class="sec-t">Xatolik holati</p>
  <div class="card" style="padding:18px">
    <div class="row"><span class="tile" style="background:var(--abs-bg);color:var(--abs)">{i("alert")}</span><div><div class="b">Ma'lumotni yuklab bo'lmadi</div><div class="small muted">Server javob bermadi. Birozdan keyin qayta urinib ko'ring.</div></div></div>
    <div class="btn btn-ghost" style="margin-top:14px;height:46px">{i("refresh", 'style="width:18px;height:18px"')}Qayta urinish</div>
  </div>
  <p class="sec-t">Yuklanmoqda</p>
  <div class="card" style="display:grid;gap:10px">
    <div style="height:14px;width:60%;border-radius:8px;background:linear-gradient(90deg,var(--tint),#F1E6E4,var(--tint))"></div>
    <div style="height:12px;width:90%;border-radius:8px;background:var(--tint)"></div>
    <div style="height:12px;width:75%;border-radius:8px;background:var(--tint)"></div>
  </div>
</div>
{tabbar(PARENT_TABS, 2)}""")


WEB_SIDEBAR = [
    ("grid", "Bosh sahifa", False),
    ("users", "Oʻquvchilar", False),
    ("user", "Xodimlar", False),
    (None, "Maktab", None),
    ("door", "Sinflar", True),
    ("cal", "Dars jadvali", False),
    ("check", "Davomat hisoboti", False),
    ("chart", "Baholar", False),
    ("users", "Ota-onalar", False),
    (None, "Moliya", None),
    ("wallet", "Toʻlovlar", False),
    (None, "Aloqa", None),
    ("chat", "Xabarlar", False),
]


def web_shell(title: str, content: str, active: str) -> str:
    nav = ""
    for icon, label, on in WEB_SIDEBAR:
        if icon is None:
            nav += f'<div class="tiny b" style="letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:16px 0 6px 12px">{label}</div>'
            continue
        on = label == active
        nav_icon = i(icon, 'style="width:19px;height:19px"')
        nav += (
            f'<div class="row" style="gap:10px;padding:9px 12px;border-radius:10px;font-size:14px;font-weight:600;'
            f'{"background:var(--tint);color:var(--m)" if on else "color:var(--text)"}">{nav_icon}{label}</div>'
        )
    return page(
        f"""
<div style="display:grid;grid-template-columns:256px 1fr;height:800px">
  <aside style="background:var(--surface);border-right:1px solid var(--border);padding:16px 14px">
    <img src="{LOGO_H_MAROON}" style="height:38px;margin:4px 0 14px 6px" alt="Iceberg School">{nav}
  </aside>
  <div>
    <header class="row between" style="height:60px;padding:0 28px;background:var(--surface);border-bottom:1px solid var(--border)">
      <div class="row" style="gap:10px;color:var(--muted)">{i("search")}<span class="small">Qidirish…</span></div>
      <div class="row" style="gap:16px"><span class="pill" style="background:var(--tint)">2026–2027 · 1-chorak</span>{i("bell")}<span class="av">SA</span></div>
    </header>
    <main style="padding:24px 28px">{content}</main>
  </div>
</div>""",
        "web",
    )


def w_classes() -> str:
    data = [
        ("1-A", "Malika Tursunova", 24, 26, "23 / 0 / 1"),
        ("2-A", "Nargiza Olimova", 22, 26, "21 / 1 / 0"),
        ("3-A", "Gulnora Saidova", 30, 30, "28 / 1 / 1"),
        ("4-B", "Shahnoza Ergasheva", 27, 30, "olinmagan"),
        ("5-A", "Sherzod Aliyev", 25, 30, "25 / 0 / 0"),
        ("7-B", "Dilnoza Rahimova", 29, 30, "27 / 2 / 0"),
        ("9-A", "Bekzod Qodirov", 23, 28, "22 / 0 / 1"),
        ("11-A", "Kamola Yusupova", 18, 24, "18 / 0 / 0"),
    ]
    late_pill = '<span class="pill late">Olinmagan</span>'
    rows = "".join(
        f'<tr style="border-top:1px solid var(--border)"><td style="padding:12px 14px" class="b">{c}</td><td>{t}</td><td>{n} / {cap}</td>'
        f"<td>{late_pill if a == 'olinmagan' else '<span class=small>' + a + '</span>'}</td>"
        f'<td style="text-align:right;padding-right:14px;color:var(--m)" class="small b">Ochish →</td></tr>'
        for c, t, n, cap, a in data
    )
    content = f"""
<div class="row between"><div><p class="kicker">Maktab</p><h1 class="serif" style="font-size:30px;color:var(--m);margin-top:4px">Sinflar</h1></div>
  <div class="row" style="gap:10px"><div class="btn btn-ghost" style="height:44px;padding:0 16px">CSV yuklash</div><div class="btn btn-m" style="height:44px;padding:0 18px">{i("plus")}Yangi sinf</div></div></div>
<div class="row" style="gap:12px;margin-top:18px">
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Sinflar</div><div class="b" style="font-size:26px">8</div></div>
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">O'quvchilar</div><div class="b" style="font-size:26px">198</div></div>
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Bugun davomat olingan</div><div class="b" style="font-size:26px">7 / 8</div></div>
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Ota-onalar ulangan</div><div class="b" style="font-size:26px">172</div></div>
</div>
<div class="card" style="margin-top:16px;padding:0;overflow:hidden">
  <table style="width:100%;border-collapse:collapse;font-size:14px">
    <thead><tr style="background:var(--tint);text-align:left" class="small muted"><th style="padding:11px 14px">Sinf</th><th>Sinf rahbari</th><th>O'quvchilar</th><th>Bugungi davomat (keldi / kech / yo'q)</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
    return web_shell("Sinflar", content, "Sinflar")


TEACHER_OF = {
    "Ingliz tili": "Kamola Yusupova",
    "Ona tili": "Gulnora Saidova",
    "O'qish": "Gulnora Saidova",
    "Matematika": "Dilnoza Rahimova",
    "Tabiiy fan": "Sherzod Aliyev",
    "Jismoniy t.": "Bekzod Qodirov",
    "Musiqa": "Lola Karimova",
    "Tasviriy san'at": "Lola Karimova",
    "Tarbiya": "Gulnora Saidova",
}


def w_timetable() -> str:
    days = ["Dushanba", "Seshanba", "Chorshanba", "Payshanba", "Juma", "Shanba"]
    subj = [
        ["Ona tili", "Matematika", "Ingliz tili", "O'qish", "Tabiiy fan"],
        ["Matematika", "Ona tili", "Musiqa", "Ingliz tili", "Jismoniy t."],
        ["Ona tili", "Matematika", "O'qish", "Tasviriy san'at", ""],
        ["Ona tili", "Matematika", "Ingliz tili", "O'qish", "Tabiiy fan"],
        ["Matematika", "Ona tili", "Ingliz tili", "Jismoniy t.", ""],
        ["O'qish", "Matematika", "Tarbiya", "", ""],
    ]
    times = ["08:00", "08:55", "09:50", "10:55", "11:50"]
    head = "".join(f'<div class="small b muted" style="padding:8px 10px">{d}</div>' for d in days)
    cells = ""
    for p, t in enumerate(times):
        cells += f'<div class="small b muted" style="padding:10px 8px">{p + 1}<div class="tiny">{t}</div></div>'
        for d in range(6):
            s = subj[d][p]
            clash = d == 1 and p == 3
            style = (
                "background:var(--abs-bg);border:1.5px solid var(--abs)"
                if clash
                else "background:var(--surface);border:1px solid var(--border)"
                if s
                else "border:1.5px dashed var(--border)"
            )
            teacher = TEACHER_OF.get(s, "—")
            inner = (
                f'<div class="b small">{s}</div><div class="tiny muted">{teacher}</div>'
                if s
                else '<div class="tiny muted" style="text-align:center">+ dars</div>'
            )
            if clash:
                inner += '<div class="tiny b" style="color:var(--abs);margin-top:2px">Ustoz band: 4-B</div>'
            cells += f'<div style="border-radius:12px;padding:8px 10px;min-height:62px;{style}">{inner}</div>'
    content = f"""
<div class="row between"><div><p class="kicker">Maktab · 3-A</p><h1 class="serif" style="font-size:30px;color:var(--m);margin-top:4px">Dars jadvali</h1></div>
  <div class="row" style="gap:10px"><span class="pill" style="background:var(--surface);border:1px solid var(--border);padding:10px 14px">Sinf: 3-A ▾</span><div class="btn btn-m" style="height:44px;padding:0 18px">Saqlash</div></div></div>
<div class="card" style="margin-top:16px;padding:14px">
  <div style="display:grid;grid-template-columns:70px repeat(6,1fr);gap:8px">
    <div></div>{head}{cells}
  </div>
</div>
<p class="small muted" style="margin-top:10px">Qizil katak — to'qnashuv: o'qituvchi yoki xona shu vaqtda band. Saqlashdan oldin tuzatiladi.</p>"""
    return web_shell("Dars jadvali", content, "Dars jadvali")


def _star() -> str:
    icon = i("star", 'style="width:13px;height:13px;fill:currentColor"')
    return f'<span style="color:var(--gold-ink);display:inline-flex">{icon}</span>'


def _kid(label: str, primary: bool = False, other: bool = False) -> str:
    style = (
        "border:1px dashed var(--border);color:var(--muted)" if other else "background:var(--tint)"
    )
    return f'<span class="pill" style="{style};font-weight:600">{_star() if primary else ""}{label}</span>'


def _field(label: str, value: str, hint: str = "", muted: bool = False) -> str:
    colour = "var(--muted)" if muted else "var(--text)"
    note = f'<div class="tiny muted" style="margin-top:4px">{hint}</div>' if hint else ""
    return (
        f'<div><div class="tiny b muted" style="margin-bottom:5px">{label}</div>'
        f'<div style="height:40px;border:1px solid var(--border);border-radius:10px;padding:0 12px;display:flex;'
        f'align-items:center;font-size:14px;color:{colour};background:var(--surface)">{value}</div>{note}</div>'
    )


def _toggle(on: bool) -> str:
    bg = "var(--m)" if on else "var(--border)"
    side = "right" if on else "left"
    return (
        f'<span style="width:34px;height:20px;border-radius:999px;background:{bg};position:relative;display:inline-block">'
        f'<span style="position:absolute;top:3px;{side}:3px;width:14px;height:14px;border-radius:999px;background:#fff"></span></span>'
    )


def w_parents() -> str:
    # (name, login ID, phone, [(child label, primary contact, child in another branch)])
    data = [
        (
            "Nodira Karimova",
            "PR503",
            "+998 90 111 22 33",
            [("Aziz · 3-A", True, False), ("Madina · 7-B", False, False)],
        ),
        (
            "Rustam Karimov",
            "PR504",
            "+998 93 444 55 66",
            [("Aziz · 3-A", False, False), ("Madina · 7-B", True, False)],
        ),
        ("Feruza Nazarova", "PR507", "+998 91 222 77 88", [("Sardor · 1-A", True, False)]),
        (
            "Jamshid Usmonov",
            "PR509",
            "+998 97 333 10 20",
            [("Laylo · 11-A", True, False), ("+1 boshqa filialda", False, True)],
        ),
        ("Mohira Saidova", "PR511", "+998 99 555 40 41", [("Otabek · 5-A", True, False)]),
        ("Ulugʻbek Tojiyev", "PR512", "+998 94 666 70 71", [("Diyora · 9-A", False, False)]),
    ]
    rows = "".join(
        f'<tr style="border-top:1px solid var(--border)"><td style="padding:11px 14px"><div class="b">{name}</div>'
        f'<div class="tiny muted">{login}</div></td><td class="small">{phone}</td>'
        f'<td><div class="row" style="gap:6px;flex-wrap:wrap;padding:6px 0">{"".join(_kid(*k) for k in kids)}</div></td>'
        f'<td style="text-align:right;padding-right:14px;color:var(--m)" class="small b">Ochish →</td></tr>'
        for name, login, phone, kids in data
    )
    link_icon = i("link", 'style="width:18px;height:18px"')
    search_icon = i("search", 'style="width:18px;height:18px"')
    close_icon = i("x", 'style="width:18px;height:18px"')
    tick = i("check", 'style="width:13px;height:13px;stroke-width:3"')
    content = f"""
<div class="row between"><div><p class="kicker">Maktab</p><h1 class="serif" style="font-size:30px;color:var(--m);margin-top:4px">Ota-onalar</h1></div>
  <div class="row" style="gap:10px"><div class="btn btn-ghost" style="height:44px;padding:0 16px">{link_icon}Login ID orqali ulash</div><div class="btn btn-m" style="height:44px;padding:0 18px">{i("plus")}Yangi ota-ona</div></div></div>
<div style="display:grid;grid-template-columns:1fr 330px;gap:16px;margin-top:16px;align-items:start">
  <div>
    <div class="row" style="gap:10px">
      <div class="row" style="flex:1;gap:8px;height:42px;padding:0 14px;border:1px solid var(--border);border-radius:12px;background:var(--surface);color:var(--muted)">{search_icon}<span class="small">Ism, login ID yoki telefon…</span></div>
      <span class="pill" style="background:var(--surface);border:1px solid var(--border);padding:11px 14px">Sinf: hammasi ▾</span>
    </div>
    <div class="card" style="margin-top:12px;padding:0;overflow:hidden">
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <thead><tr style="background:var(--tint);text-align:left" class="small muted"><th style="padding:11px 14px">Ota-ona</th><th>Telefon</th><th>Farzandlari</th><th></th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    <p class="small muted row" style="gap:6px;margin-top:10px">{_star()} farzand boʻyicha asosiy aloqa · punktir — boshqa filialdagi farzand (nomi koʻrsatilmaydi)</p>
  </div>
  <div class="card" style="padding:18px;display:grid;gap:12px">
    <div class="row between"><div class="b" style="font-size:17px;color:var(--m)">Yangi ota-ona</div><span class="muted">{close_icon}</span></div>
    <div class="grid2" style="gap:10px">{_field("Ism", "Zarina")}{_field("Familiya", "Hamidova")}</div>
    {_field("Telefon raqami", "+998 90 777 88 99", "Bitta raqam — bitta ota-ona")}
    {_field("Parol", "••••••••", "Login ID avtomatik beriladi: PR513")}
    <div class="tiny b" style="letter-spacing:.1em;text-transform:uppercase;color:var(--gold-ink);margin-top:4px">Birinchi farzand</div>
    {_field("Farzand", "Hamidov Sanjar · 4-B ▾")}
    {_field("Qarindoshlik", "Onasi ▾")}
    <div class="row small" style="gap:8px"><span style="width:18px;height:18px;border-radius:5px;background:var(--m);color:#fff;display:grid;place-items:center">{tick}</span>Farzand boʻyicha asosiy aloqa</div>
    <div class="btn btn-m" style="height:44px">Saqlash</div>
  </div>
</div>"""
    return web_shell("Ota-onalar", content, "Ota-onalar")


def w_parent_page() -> str:
    links = [("Aziz Karimov", "3-A", "Onasi", True), ("Madina Karimova", "7-B", "Onasi", False)]
    rows = "".join(
        f'<tr style="border-top:1px solid var(--border)"><td style="padding:12px 14px" class="b">{name}</td><td>{cls}</td>'
        f'<td><span class="pill" style="background:var(--surface);border:1px solid var(--border)">{rel} ▾</span></td>'
        f"<td>{_toggle(primary)}</td>"
        f'<td style="text-align:right;padding-right:14px;color:var(--abs)" class="small b">Uzish</td></tr>'
        for name, cls, rel, primary in links
    )
    key_icon = i("key", 'style="width:18px;height:18px"')
    link_icon = i("link", 'style="width:18px;height:18px"')
    content = f"""
<div class="row between"><div><p class="kicker">Maktab · Ota-onalar</p><h1 class="serif" style="font-size:30px;color:var(--m);margin-top:4px">Nodira Karimova</h1></div>
  <div class="row" style="gap:10px"><div class="btn btn-ghost" style="height:44px;padding:0 16px">{key_icon}Parolni tiklash</div><div class="btn btn-ghost" style="height:44px;padding:0 16px;color:var(--abs)">Oʻchirish</div></div></div>
<div style="display:grid;grid-template-columns:290px 1fr;gap:16px;margin-top:18px;align-items:start">
  <div class="card" style="padding:18px;display:grid;gap:12px">
    <div class="row" style="gap:12px"><span class="av lg">NK</span><div><div class="b">Nodira Karimova</div><div class="small muted">Login ID: PR503</div></div></div>
    {_field("Ism", "Nodira")}
    {_field("Familiya", "Karimova")}
    {_field("Telefon raqami", "+998 90 111 22 33")}
    <div class="btn btn-m" style="height:44px">Saqlash</div>
    <div class="tiny muted">“Parolni tiklash” yangi vaqtinchalik parol beradi; uni ota-onaga topshiring.</div>
  </div>
  <div style="display:grid;gap:16px">
    <div class="card" style="padding:0;overflow:hidden">
      <div class="b" style="font-size:17px;color:var(--m);padding:14px 16px">Farzandlari</div>
      <table style="width:100%;border-collapse:collapse;font-size:14px">
        <thead><tr style="background:var(--tint);text-align:left" class="small muted"><th style="padding:10px 14px">Farzand</th><th>Sinf</th><th>Qarindoshlik</th><th>Asosiy aloqa</th><th></th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <div class="row" style="gap:10px;padding:12px 16px;border-top:1px solid var(--border);background:var(--bg);align-items:end">
        <div style="flex:1">{_field("Farzand ulash", "Oʻquvchini tanlang ▾", muted=True)}</div>
        <div style="width:150px">{_field("Qarindoshlik", "Vasiy ▾")}</div>
        <div class="btn btn-m" style="height:40px;padding:0 18px">Ulash</div>
      </div>
    </div>
    <div class="card" style="padding:16px 18px;border-color:var(--gold-soft)">
      <div class="row" style="gap:12px"><span class="tile" style="width:38px;height:38px;border-radius:11px">{link_icon}</span>
        <div><div class="b">Ota-ona boshqa filialda roʻyxatdan oʻtganmi?</div><div class="small muted">Yangi akkaunt ochmang: login ID va telefon raqami mos kelsa, farzand shu ota-onaga ulanadi.</div></div></div>
      <div class="row" style="gap:10px;margin-top:12px;align-items:end">
        <div style="width:120px">{_field("Login ID", "PR488")}</div>
        <div style="flex:1">{_field("Telefon raqami", "+998 95 123 00 11")}</div>
        <div style="flex:1">{_field("Farzand", "Karimov Aziz · 3-A ▾")}</div>
        <div class="btn btn-ghost" style="height:40px;padding:0 18px">Ulash</div>
      </div>
      <div class="tiny muted" style="margin-top:8px">Mos kelmasa — faqat “Ota-ona topilmadi”; boshqa filial maʼlumotlari koʻrsatilmaydi.</div>
    </div>
  </div>
</div>"""
    return web_shell("Ota-onalar", content, "Ota-onalar")


def _bar(rate: int) -> str:
    return (
        '<div class="row" style="gap:8px"><span style="flex:1;height:6px;border-radius:999px;background:var(--tint);'
        f'overflow:hidden;display:block"><span style="display:block;height:6px;width:{rate}%;background:var(--m)"></span></span>'
        f'<span class="tiny b" style="width:34px;text-align:right">{rate}%</span></div>'
    )


def w_register_report() -> str:
    # Same classes, teachers and counts as screen 16. (class, homeroom, pupils, taken at, present, late, absent)
    data = [
        ("1-A", "Malika Tursunova", 24, "08:09", 23, 0, 1),
        ("2-A", "Nargiza Olimova", 22, "08:11", 21, 1, 0),
        ("3-A", "Gulnora Saidova", 30, "08:14", 28, 1, 1),
        ("4-B", "Shahnoza Ergasheva", 27, None, 0, 0, 0),
        ("5-A", "Sherzod Aliyev", 25, "08:06", 25, 0, 0),
        ("7-B", "Dilnoza Rahimova", 29, "08:21", 27, 2, 0),
        ("9-A", "Bekzod Qodirov", 23, "08:10", 22, 0, 1),
        ("11-A", "Kamola Yusupova", 18, "08:16", 18, 0, 0),
    ]
    rows = ""
    for c, teacher, n, at, pres, late, absent in data:
        if at is None:
            state = '<span class="pill late">Olinmagan</span>'
            counts = '<td class="muted">—</td><td class="muted">—</td><td class="muted">—</td><td class="tiny muted">—</td>'
        else:
            state = f'<span class="pill ok">{i("check")}{at}</span>'
            counts = (
                f'<td class="b">{pres}</td><td class="b" style="color:var(--late)">{late or "–"}</td>'
                f'<td class="b" style="color:var(--abs)">{absent or "–"}</td>'
                f'<td style="width:120px;padding-right:14px">{_bar(round((pres + late) * 100 / n))}</td>'
            )
        rows += (
            f'<tr style="border-top:1px solid var(--border)"><td style="padding:11px 14px" class="b">{c}</td>'
            f'<td class="small">{teacher}</td><td class="small">{n}</td><td>{state}</td>{counts}</tr>'
        )
    # (pupil, class, status, arrival time, note)
    marks = [
        ("Sardor Nazarov", "1-A", "abs", "", "Kasal, onasi xabar berdi"),
        ("Bekzod Aliyev", "3-A", "abs", "", ""),
        ("Diyora Tojiyeva", "9-A", "abs", "", "Oilaviy sabab"),
        ("Aziz Karimov", "3-A", "late", "08:12", "Avtobus"),
        ("Jasur Toshev", "7-B", "late", "08:20", ""),
        ("Madina Karimova", "7-B", "late", "08:05", ""),
        ("Shoira Valiyeva", "2-A", "late", "08:25", "Shifokorda edi"),
    ]
    sent = i("send", 'style="width:12px;height:12px"')
    items = "".join(
        f'<div style="padding:10px 0;border-top:1px solid var(--border)"><div class="row between">'
        f'<div><div class="b small">{name}</div><div class="tiny muted">{cls}{" · " + note if note else ""}</div></div>'
        f'<span class="pill {st}">{"Kelmadi" if st == "abs" else "Kechikdi " + at}</span></div></div>'
        for name, cls, st, at, note in marks
    )
    download = i("upload", 'style="width:18px;height:18px;transform:rotate(180deg)"')
    content = f"""
<div class="row between"><div><p class="kicker">Maktab</p><h1 class="serif" style="font-size:30px;color:var(--m);margin-top:4px">Davomat hisoboti</h1></div>
  <div class="row" style="gap:10px">
    <span class="pill" style="background:var(--surface);border:1px solid var(--border);padding:11px 14px">{i("cal", 'style="width:16px;height:16px"')}28-oktabr, chorshanba ▾</span>
    <span class="pill" style="background:var(--surface);border:1px solid var(--border);padding:11px 14px">Sinf: hammasi ▾</span>
    <div class="btn btn-ghost" style="height:44px;padding:0 16px">{download}CSV yuklab olish</div>
  </div></div>
<div class="row" style="gap:12px;margin-top:16px">
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Davomat olingan</div><div class="b" style="font-size:26px">7 / 8 <span class="small muted">sinf</span></div></div>
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Keldi</div><div class="b" style="font-size:26px;color:var(--ok)">164</div></div>
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Kechikdi</div><div class="b" style="font-size:26px;color:var(--late)">4</div></div>
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Kelmadi</div><div class="b" style="font-size:26px;color:var(--abs)">3</div></div>
  <div class="card" style="flex:1;padding:14px 18px"><div class="small muted">Davomat</div><div class="b" style="font-size:26px">98%</div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 330px;gap:16px;margin-top:16px;align-items:start">
  <div>
    <style>.rr th, .rr td {{ padding-right: 12px; white-space: nowrap; }}</style>
    <div class="card" style="padding:0;overflow:hidden">
      <table class="rr" style="width:100%;border-collapse:collapse;font-size:14px">
        <thead><tr style="background:var(--tint);text-align:left" class="small muted"><th style="padding:11px 14px">Sinf</th><th>Sinf rahbari</th><th>Oʻquvchi</th><th>Olindi</th><th>Keldi</th><th>Kech</th><th>Yoʻq</th><th>Kelganlar</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
    <p class="small muted" style="margin-top:10px">Olinmagan — sinf rahbari bugungi davomatni hali saqlamagan. Davomatni oʻqituvchi ilovada oladi; bu sahifa faqat koʻrish uchun.</p>
  </div>
  <div class="card" style="padding:16px 18px">
    <div class="row between" style="margin-bottom:6px"><div class="b" style="font-size:17px;color:var(--m)">Kelmagan va kechikkanlar</div><span class="tiny b muted">7</span></div>
    <div class="tiny row" style="gap:5px;color:var(--muted);margin-bottom:8px">{sent}Har birining ota-onasiga ilovada xabar yuborildi</div>
    {items}
  </div>
</div>"""
    return web_shell("Davomat hisoboti", content, "Davomat hisoboti")


SCREENS = [
    ("01-choice", "Tanlov · Choice", s_choice),
    ("02-login-school", "Kirish · School", s_login_school),
    ("03-login-study-center", "Kirish · Study Center", s_login_center),
    ("04-parent-home", "Ota-ona · Asosiy", s_parent_home),
    ("05-parent-home-dark", "Ota-ona · Dark", s_parent_home_dark),
    ("06-timetable", "Dars jadvali", s_timetable),
    ("07-attendance", "Davomat", s_attendance),
    ("08-homework", "Vazifalar", s_homework),
    ("09-payments", "To'lovlar", s_payments),
    ("10-messages", "Xabarlar", s_messages),
    ("11-teacher-home", "O'qituvchi · Bugun", s_teacher_home),
    ("12-register", "Davomat olish", s_register),
    ("13-register-late", "Kechikdi · vaqt", s_register_late),
    ("14-grades-r2", "Baholar (2-bosqich)", s_grades),
    ("15-states", "Bo'sh / xato / offline", s_states),
]
WEB_SCREENS = [
    ("16-web-classes", "Web · Sinflar", w_classes),
    ("17-web-timetable", "Web · Dars jadvali", w_timetable),
    ("18-web-parents", "Web · Ota-onalar", w_parents),
    ("18b-web-parent-page", "Web · Ota-ona sahifasi", w_parent_page),
    ("19-web-register-report", "Web · Davomat hisoboti", w_register_report),
]


def main(only: list[str]) -> None:
    from PIL import Image, ImageDraw, ImageFont
    from playwright.sync_api import sync_playwright

    exe = os.environ.get("CHROMIUM_PATH")
    proxy = os.environ.get("HTTPS_PROXY")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=exe or None,
            proxy={"server": proxy, "bypass": "127.0.0.1,localhost"} if proxy else None,
            args=["--allow-file-access-from-files"],
        )
        for items, (w, h) in ((SCREENS, (390, 844)), (WEB_SCREENS, (1280, 800))):
            ctx = browser.new_context(viewport={"width": w, "height": h}, device_scale_factor=2)
            pg = ctx.new_page()
            for name, _label, fn in items:
                if only and name not in only:
                    continue
                html_path = HERE / f".{name}.html"
                html_path.write_text(fn(), encoding="utf-8")
                pg.goto(html_path.as_uri())
                pg.wait_for_timeout(700)
                out = HERE / f"{name}.png"
                pg.screenshot(path=str(out))
                html_path.unlink()
                im = Image.open(out)
                im = im.resize((im.width * 3 // 4, im.height * 3 // 4), Image.LANCZOS)
                im.save(out, optimize=True)
                print("wrote", out.name, im.size)
            ctx.close()
        browser.close()
    if only:
        return

    # Overview sheet: phone screens in rows of 5 with labels.
    tiles = [(label, Image.open(HERE / f"{name}.png")) for name, label, _ in SCREENS]
    tw, th = 292, 633
    cols, gap, label_h = 5, 28, 40
    rows = -(-len(tiles) // cols)
    sheet = Image.new(
        "RGB",
        (cols * tw + (cols + 1) * gap, rows * (th + label_h) + (rows + 1) * gap),
        (245, 236, 223),
    )
    draw = ImageDraw.Draw(sheet)
    try:
        font = ImageFont.truetype(
            str(REPO / "mobile/iceberg_app/assets/fonts/Inter-SemiBold.ttf"), 20
        )
    except OSError:
        font = ImageFont.load_default()
    for n, (label, im) in enumerate(tiles):
        r, c = divmod(n, cols)
        x = gap + c * (tw + gap)
        y = gap + r * (th + label_h + gap)
        draw.text((x + 4, y), label, fill=(76, 9, 9), font=font)
        sheet.paste(im.resize((tw, th), Image.LANCZOS), (x, y + label_h))
    sheet.save(HERE / "overview.png", optimize=True)
    print("wrote overview.png", sheet.size)


# ---------------------------------------------------------------- PD.5: teacher grade entry (Release 2)
# Built on the P2.4 marks API (school/marks/: value 2–5, kind lesson/test/exam, one mark per pupil,
# subject, date and kind) and the P2.5 term grades API (school/term-grades/: quarter or year grade,
# null = "not graded"; the suggestion is school.suggested_grade, the average rounded half up).

GRADE_PUPILS = [
    ("Abdullayev Jasur", ["5", "4", "5"], "5"),
    ("Aliyeva Madina", ["4", "4", "5"], "4"),
    ("Bakirov Sardor", ["3", "4"], "4"),
    ("Ergasheva Zarina", ["5", "5"], "5"),
    ("Hasanov Temur", [], None),
    ("Ismoilova Nodira", ["4", "3", "4"], "4"),
    ("Karimova Aziza", ["5"], "5"),
    ("Mahmudov Ulugʻbek", ["2", "3"], "3"),
]


def _mark_chip(v: str, size: int = 30, on: bool = True) -> str:
    bg = {"5": "var(--ok-bg)", "4": "var(--tint)", "3": "var(--late-bg)", "2": "var(--abs-bg)"}[v]
    fg = {"5": "var(--ok)", "4": "var(--m)", "3": "var(--late)", "2": "var(--abs)"}[v]
    if not on:
        bg, fg = "transparent", "var(--muted)"
    ring = f"box-shadow:0 0 0 2px {fg};" if on and size > 30 else ""
    return (
        f'<span style="width:{size}px;height:{size}px;border-radius:{size // 3}px;display:grid;place-items:center;'
        f'font-weight:800;font-size:{15 if size > 30 else 13}px;background:{bg};color:{fg};{ring}">{v}</span>'
    )


def _initials(name: str) -> str:
    return "".join(p[0] for p in name.split()[:2])


def s_grade_entry() -> str:
    # Marks for one date and kind; each pupil gets 2–5 or nothing (tap again to clear).
    today = {
        "Abdullayev Jasur": "5",
        "Aliyeva Madina": "4",
        "Bakirov Sardor": "",
        "Ergasheva Zarina": "5",
        "Hasanov Temur": "",
        "Ismoilova Nodira": "3",
        "Karimova Aziza": "",
        "Mahmudov Ulugʻbek": "4",
    }
    rows = ""
    for name, _old, _q in GRADE_PUPILS:
        pick = today[name]
        absent = name == "Hasanov Temur"
        sub = (
            '<div class="tiny" style="color:var(--abs)">Bugun yoʻq (davomat)</div>'
            if absent
            else ('<div class="tiny muted">Baho qoʻyilmagan</div>' if not pick else "")
        )
        chips = "".join(_mark_chip(v, 36, on=(v == pick)) for v in ("2", "3", "4", "5"))
        rows += (
            f'<div class="row" style="padding:9px 0;border-bottom:1px solid var(--border);{"opacity:.55" if absent else ""}">'
            f'<span class="av lg">{_initials(name)}</span><div style="flex:1;min-width:0"><div class="b" style="font-size:14.5px">{name}</div>{sub}</div>'
            f'<div class="row" style="gap:4px;background:var(--tint);border-radius:14px;padding:3px">{chips}</div></div>'
        )
    kinds = "".join(
        f'<span class="pill" style="{"background:var(--m);color:#fff" if on else "background:var(--tint)"};padding:7px 12px">{label}</span>'
        for label, on in (("Dars", True), ("Nazorat ishi", False), ("Imtihon", False))
    )
    return page(f"""
{status()}
<div class="pad">
  <div class="row" style="gap:10px;margin-top:4px">{i("back")}<div><h1 class="serif" style="font-size:24px;color:var(--m)">Baholash</h1><div class="small muted">2-chorak · Payshanba, 24-oktabr</div></div></div>
  <div class="card row" style="margin-top:12px;padding:10px 14px;border-radius:16px"><span class="tile" style="width:36px;height:36px;border-radius:11px">{i("book")}</span>
    <div style="flex:1"><div class="b">3-A · Ona tili</div><div class="tiny muted">Sinf va fan · 30 oʻquvchi</div></div>{i("chev", 'style="transform:rotate(90deg)"')}</div>
  <div class="row" style="gap:6px;margin-top:10px">{kinds}</div>
  <p class="tiny muted" style="margin-top:10px">Bahoni bosing; qayta bossangiz oʻchadi. Faqat qoʻyilgan baholar saqlanadi.</p>
  <div style="margin-top:2px">{rows}</div>
</div>
<div style="position:absolute;left:0;right:0;bottom:0;padding:12px 20px 30px;background:var(--surface);border-top:1px solid var(--border)">
  <div class="btn btn-m">Saqlash · 5 ta baho</div>
  <p class="tiny muted" style="text-align:center;margin-top:8px">Ota-onalar va oʻquvchi bahoni ilovada koʻradi</p>
</div>""")


def s_quarter_grades() -> str:
    from decimal import ROUND_HALF_UP, Decimal

    def suggestion(marks: list[str]) -> tuple[str, str]:
        avg = Decimal(sum(int(m) for m in marks)) / len(marks)
        grade = int(avg.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
        return f"{avg.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)}".replace(".", ","), str(
            grade
        )

    # Confirmed, waiting for confirmation, changed by the teacher, and not graded.
    confirmed = {"Abdullayev Jasur", "Aliyeva Madina", "Ergasheva Zarina"}
    tick = i("check", 'style="width:12px;height:12px;stroke-width:3"')
    changed = {"Bakirov Sardor": "3"}
    rows = ""
    for name, marks, _q in GRADE_PUPILS:
        marks_html = (
            "".join(_mark_chip(m, 22) for m in marks)
            if marks
            else '<span class="tiny muted">Baho yoʻq</span>'
        )
        if not marks:
            right = '<span class="pill" style="background:var(--tint);color:var(--muted)">Baholanmadi</span>'
            info = '<div class="tiny muted">Chorakda baho yoʻq · taklif yoʻq</div>'
        else:
            avg, grade = suggestion(marks)
            info = f'<div class="tiny muted">Oʻrtacha {avg} → taklif <b style="color:var(--text)">{grade}</b></div>'
            if name in confirmed:
                right = (
                    f'<div style="text-align:center"><span class="serif" style="font-size:26px;color:var(--m)">{grade}</span>'
                    f'<div class="tiny" style="color:var(--ok);font-weight:700">{tick} Tasdiqlandi</div></div>'
                )
            elif name in changed:
                right = (
                    f'<div style="text-align:center"><span class="serif" style="font-size:26px;color:var(--m)">{changed[name]}</span>'
                    '<div class="tiny" style="color:var(--late);font-weight:700">Oʻzgartirildi</div></div>'
                )
            else:
                right = (
                    f'<div class="row" style="gap:6px"><span style="width:38px;height:38px;border-radius:12px;display:grid;place-items:center;'
                    f'border:1.5px dashed var(--gold);color:var(--gold-ink);font-weight:800;font-size:16px">{grade}</span>'
                    f'<span class="pill" style="background:var(--m);color:#fff;padding:7px 10px">{i("check")}</span></div>'
                )
        rows += (
            '<div class="row" style="padding:10px 0;border-bottom:1px solid var(--border)">'
            f'<div style="flex:1;min-width:0"><div class="b" style="font-size:14.5px">{name}</div>'
            f'<div class="row" style="gap:3px;margin:5px 0 3px">{marks_html}</div>{info}</div>{right}</div>'
        )
    tabs = "".join(
        f'<span class="pill" style="{"background:var(--m);color:#fff" if on else "background:var(--tint)"}">{t}</span>'
        for t, on in (
            ("1-ch.", False),
            ("2-chorak", True),
            ("3-ch.", False),
            ("4-ch.", False),
            ("Yillik", False),
        )
    )
    return page(f"""
{status()}
<div class="pad">
  <div class="row" style="gap:10px;margin-top:4px">{i("back")}<div><h1 class="serif" style="font-size:24px;color:var(--m)">Chorak baholari</h1><div class="small muted">3-A · Ona tili</div></div></div>
  <div class="row" style="gap:5px;margin-top:12px">{tabs}</div>
  <div class="card row" style="margin-top:12px;padding:10px 14px;border-radius:16px;background:var(--tint);border-color:var(--tint);box-shadow:none">
    <span style="width:30px;height:30px;border-radius:10px;display:grid;place-items:center;border:1.5px dashed var(--gold);color:var(--gold-ink);font-weight:800">4</span>
    <div class="tiny" style="flex:1"><b>Taklif</b> — chorakdagi baholar oʻrtachasi, 0,5 dan yuqorisi yuqoriga yaxlitlanadi. Siz tasdiqlaysiz yoki oʻzgartirasiz.</div></div>
  <div style="margin-top:4px">{rows}</div>
</div>
<div style="position:absolute;left:0;right:0;bottom:0;padding:12px 20px 30px;background:var(--surface);border-top:1px solid var(--border);display:grid;gap:8px">
  <div class="btn btn-ghost" style="height:46px">Qolgan 3 tasini taklif boʻyicha tasdiqlash</div>
  <div class="btn btn-m">Saqlash · 2-chorak</div>
</div>""")


SCREENS += [
    ("20-grade-entry", "Baholash (2-bosqich)", s_grade_entry),
    ("20b-quarter-grades", "Chorak baholari (2-bosqich)", s_quarter_grades),
]


# ---------------------------------------------------------------- P3.9: Study Center admin shell (D18)
# The same web shell as 16–19 in the Study Center palette: navy #103A57 / #07233A, lime #CDF163 for
# the primary action, ice #38BDF0 for highlights, stroke #D2DFEC, the Iceberg mountain logo.
# The page re-points the shared tokens (--m, --tint, --border …) at the Study Center ones, the same
# way the live brand CSS does it, so cards, pills and tables are the School components unchanged.

CENTER_VARS = (
    "--m:var(--c-hi);--m-hover:#1B5A82;--m-deep:var(--c-deep);--tint:var(--c-bg);--bg:#F6F9FC;"
    "--border:var(--c-stroke);--text:var(--c-text);--muted:var(--c-muted);--gold-soft:var(--c-lime);"
    "--gold-ink:#1B5A82"
)

CENTER_SIDEBAR = [
    ("grid", "Bosh sahifa"),
    ("users", "Oʻquvchilar"),
    ("user", "Xodimlar"),
    (None, "Oʻquv jarayoni"),
    ("door", "Guruhlar"),
    ("book", "Kurslar"),
    ("check", "Davomat"),
    ("globe", "Lugʻat"),
    ("star", "Reyting"),
    (None, "Moliya"),
    ("wallet", "Toʻlovlar"),
    (None, "Aloqa"),
    ("chat", "Xabarlar"),
    ("send", "Arizalar"),
    (None, "Tizim"),
    ("key", "Filiallar va adminlar"),
]


def web_shell_center(content: str, active: str) -> str:
    nav = ""
    for icon, label in CENTER_SIDEBAR:
        if icon is None:
            nav += f'<div class="tiny b" style="letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:14px 0 6px 12px">{label}</div>'
            continue
        on = label == active
        nav_icon = i(icon, 'style="width:19px;height:19px"')
        badge = (
            '<span style="margin-left:auto;font-size:11px;font-weight:800;padding:2px 7px;border-radius:999px;background:var(--c-lime);color:var(--c-deep)">3</span>'
            if label == "Arizalar"
            else ""
        )
        nav += (
            f'<div class="row" style="gap:10px;padding:8px 12px;border-radius:10px;font-size:14px;font-weight:600;'
            f'{"background:var(--tint);color:var(--m);box-shadow:inset 3px 0 0 var(--c-ice)" if on else "color:var(--text)"}">{nav_icon}{label}{badge}</div>'
        )
    return page(
        f"""
<div style="display:grid;grid-template-columns:256px 1fr;height:800px;{CENTER_VARS};background:var(--bg)">
  <aside style="background:var(--surface);border-right:1px solid var(--border);padding:16px 14px">
    <div class="row" style="gap:10px;margin:2px 0 12px 4px"><img src="{CENTER_TILE}" style="height:38px;width:38px;border-radius:11px" alt="">
      <div style="font-size:15px;font-weight:800;letter-spacing:.02em;color:var(--c-deep);line-height:1.1">ICEBERG<div style="font-size:12.5px;font-weight:600;letter-spacing:0;color:var(--muted)">Study Center</div></div></div>{nav}
  </aside>
  <div>
    <header class="row between" style="height:60px;padding:0 28px;background:var(--surface);border-bottom:1px solid var(--border)">
      <div class="row" style="gap:10px;color:var(--muted)">{i("search")}<span class="small">Qidirish…</span></div>
      <div class="row" style="gap:16px"><span class="pill" style="background:var(--tint);color:var(--m)">Chilonzor filiali</span>{i("bell")}<span class="av" style="background:var(--c-lime);color:var(--c-deep)">SA</span></div>
    </header>
    <main style="padding:24px 28px">{content}</main>
  </div>
</div>""",
        "web",
    )


def _c_title(kicker: str, title: str, actions: str) -> str:
    return (
        f'<div class="row between"><div><p class="kicker">{kicker}</p>'
        f'<h1 style="font-size:30px;font-weight:800;letter-spacing:-.02em;color:var(--c-deep);margin-top:4px">{title}</h1></div>'
        f'<div class="row" style="gap:10px">{actions}</div></div>'
    )


C_BTN_LIME = (
    "background:var(--c-lime);color:var(--c-deep);box-shadow:0 10px 22px rgb(7 35 58 / .16)"
)


def _c_stats(items: list[tuple[str, str, str]]) -> str:
    cards = "".join(
        f'<div class="card" style="flex:1;padding:14px 18px"><div class="small muted">{label}</div>'
        f'<div class="row" style="gap:8px;align-items:baseline"><div class="b" style="font-size:26px;color:var(--c-deep)">{value}</div>'
        f'<span class="tiny b" style="color:#1B7FB0">{note}</span></div></div>'
        for label, value, note in items
    )
    return f'<div class="row" style="gap:12px;margin-top:18px">{cards}</div>'


def w_center_students() -> str:
    data = [
        ("Abdullayeva Madina", "S-24-0112", "IELTS 6.5 · Tong", "+998 90 ··· 12 45", "paid"),
        ("Bakirov Sardor", "S-24-0187", "CEFR B2 · Kechki", "+998 93 ··· 08 71", "debt"),
        ("Ergasheva Zarina", "S-24-0203", "SAT Math · Shanba", "+998 97 ··· 55 10", "paid"),
        ("Hasanov Temur", "S-24-0219", "IELTS 5.5 · Kechki", "+998 99 ··· 40 02", "due"),
        ("Ismoilova Nodira", "S-24-0230", "General English A2", "+998 90 ··· 77 19", "paid"),
        ("Karimov Aziz", "S-24-0244", "CEFR B1 · Tong", "+998 94 ··· 63 88", "paid"),
        ("Mahmudov Ulugʻbek", "S-24-0251", "IELTS 7.0 · Intensiv", "+998 91 ··· 20 36", "debt"),
        ("Yoʻldosheva Kamola", "S-24-0266", "Kimyo · Abituriyent", "+998 88 ··· 14 50", "paid"),
    ]
    pills = {
        "paid": '<span class="pill ok">Toʻlangan</span>',
        "debt": '<span class="pill abs">Qarzdor</span>',
        "due": '<span class="pill late">Muddat yaqin</span>',
    }
    rows = "".join(
        f'<tr style="border-top:1px solid var(--border)"><td style="padding:11px 14px"><div class="row" style="gap:10px">'
        f'<span class="av" style="background:var(--tint);color:var(--m)">{_initials(n)}</span><span class="b">{n}</span></div></td>'
        f'<td class="small muted">{lid}</td><td>{g}</td><td class="small">{ph}</td><td>{pills[st]}</td>'
        f'<td style="text-align:right;padding-right:14px;color:var(--m)" class="small b">Ochish →</td></tr>'
        for n, lid, g, ph, st in data
    )
    up = i("upload", 'style="width:18px;height:18px"')
    actions = (
        f'<div class="btn btn-ghost" style="height:44px;padding:0 16px">{up}Excel yuklash</div>'
        f'<div class="btn" style="height:44px;padding:0 18px;{C_BTN_LIME}">{i("plus")}Yangi oʻquvchi</div>'
    )
    content = f"""
{_c_title("Odamlar", "Oʻquvchilar", actions)}
{_c_stats([("Jami oʻquvchilar", "412", "+18 bu oy"), ("Faol guruhlarda", "389", "94%"), ("Qarzdorlar", "23", ""), ("Bugun darsda", "176", "")])}
<div class="row" style="gap:10px;margin-top:16px">
  <div class="row" style="flex:1;gap:10px;height:44px;padding:0 14px;border:1px solid var(--border);border-radius:12px;background:var(--surface);color:var(--muted)">{i("search")}<span class="small">Ism, telefon yoki login ID</span></div>
  <div class="row small b" style="height:44px;padding:0 14px;border:1px solid var(--border);border-radius:12px;background:var(--surface)">Guruh: hammasi {i("chev", 'style="width:16px;height:16px;transform:rotate(90deg)"')}</div>
  <div class="row small b" style="height:44px;padding:0 14px;border:1px solid var(--border);border-radius:12px;background:var(--surface)">Toʻlov: hammasi {i("chev", 'style="width:16px;height:16px;transform:rotate(90deg)"')}</div>
</div>
<div class="card" style="margin-top:14px;padding:0;overflow:hidden">
  <table style="width:100%;border-collapse:collapse;font-size:14px">
    <thead><tr style="background:var(--tint);text-align:left" class="small muted"><th style="padding:11px 14px">Oʻquvchi</th><th>Login ID</th><th>Guruh</th><th>Telefon</th><th>Toʻlov</th><th></th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
    return web_shell_center(content, "Oʻquvchilar")


def w_center_home() -> str:
    months = [("May", 58), ("Iyn", 64), ("Iyl", 52), ("Avg", 70), ("Sen", 86), ("Okt", 94)]
    bars = "".join(
        f'<div style="display:grid;justify-items:center;gap:6px;flex:1"><div style="width:34px;height:{h * 2.3:.0f}px;border-radius:10px 10px 4px 4px;'
        f'background:{"var(--c-hi)" if n == len(months) - 1 else "#BFDDF0"}"></div><span class="tiny muted">{m}</span></div>'
        for n, (m, h) in enumerate(months)
    )
    lessons = [
        ("09:00", "IELTS 6.5 · Tong", "Kamola Yusupova", "14 / 16", True),
        ("11:00", "CEFR B1 · Tong", "Sherzod Aliyev", "12 / 12", True),
        ("14:00", "SAT Math · Shanba", "Bekzod Qodirov", "—", False),
        ("16:30", "IELTS 5.5 · Kechki", "Nargiza Olimova", "—", False),
        ("18:30", "CEFR B2 · Kechki", "Dilnoza Rahimova", "—", False),
    ]

    def _state(a: str, done: bool) -> str:
        if done:
            return f'<span class="pill ok">{i("check")}{a}</span>'
        return '<span class="small muted">Kutilmoqda</span>'

    rows = "".join(
        f'<div class="row" style="padding:10px 0;border-top:1px solid var(--border)"><span class="pill" style="background:var(--tint);color:var(--m);width:62px;justify-content:center">{t}</span>'
        f'<div style="flex:1;min-width:0"><div class="b" style="font-size:14px">{g}</div><div class="tiny muted">{tch}</div></div>'
        f"{state}</div>"
        for t, g, tch, a, done in lessons
        for state in [_state(a, done)]
    )
    leads = [
        ("Olimov Jamshid", "IELTS", "Bugun 10:12"),
        ("Saidova Laylo", "SAT", "Bugun 09:40"),
        ("Qodirov Aziz", "CEFR", "Kecha 18:05"),
    ]
    lead_rows = "".join(
        f'<div class="row" style="padding:9px 0;border-top:1px solid var(--border)"><span class="av" style="background:var(--tint);color:var(--m)">{_initials(n)}</span>'
        f'<div style="flex:1"><div class="b" style="font-size:14px">{n}</div><div class="tiny muted">{c} · {w}</div></div>'
        f'<span class="small b" style="color:var(--m)">Qoʻngʻiroq →</span></div>'
        for n, c, w in leads
    )
    content = f"""
{_c_title("Bosh sahifa", "Xayrli tong, Sardor", f'<div class="btn btn-ghost" style="height:44px;padding:0 16px">Hisobot</div><div class="btn" style="height:44px;padding:0 18px;{C_BTN_LIME}">{i("plus")}Yangi oʻquvchi</div>')}
{_c_stats([("Oʻquvchilar", "412", "+18"), ("Guruhlar", "36", ""), ("Bugungi darslar", "14", "2 tugadi"), ("Oktabr toʻlovlari", "[summa]", "82%")])}
<div style="display:grid;grid-template-columns:1.25fr 1fr;gap:14px;margin-top:16px">
  <div class="card" style="padding:18px 20px">
    <div class="row between"><div class="b" style="color:var(--c-deep)">Toʻlovlar · 6 oy</div><span class="tiny muted">soʻm</span></div>
    <div class="row" style="align-items:flex-end;height:250px;margin-top:20px;gap:8px">{bars}</div>
  </div>
  <div class="card" style="padding:18px 20px">
    <div class="row between"><div class="b" style="color:var(--c-deep)">Bugungi darslar</div><span class="small b" style="color:var(--m)">Davomat →</span></div>
    <div style="margin-top:8px">{rows}</div>
  </div>
</div>
<div style="display:grid;grid-template-columns:1.25fr 1fr;gap:14px;margin-top:14px;align-items:start">
  <div class="card row" style="padding:16px 20px;gap:14px;background:var(--c-deep);border-color:var(--c-deep);color:#fff">
    <span class="tile" style="background:rgb(255 255 255 / .1);color:var(--c-lime)">{i("alert")}</span>
    <div style="flex:1"><div class="b">23 ta oʻquvchining toʻlovi kechikkan</div><div class="small" style="color:#AFD9F2">Eslatma yuborish yoki roʻyxatni koʻrish</div></div>
    <div class="btn" style="height:40px;padding:0 14px;font-size:14px;{C_BTN_LIME}">Koʻrish</div>
  </div>
  <div class="card" style="padding:14px 20px">
    <div class="row between"><div class="b" style="color:var(--c-deep)">Yangi arizalar</div><span class="pill" style="background:var(--c-lime);color:var(--c-deep)">3</span></div>
    {lead_rows}
  </div>
</div>"""
    return web_shell_center(content, "Bosh sahifa")


WEB_SCREENS += [
    ("16c-web-center-students", "Web · Study Center · Oʻquvchilar", w_center_students),
    ("16d-web-center-home", "Web · Study Center · Bosh sahifa", w_center_home),
]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
