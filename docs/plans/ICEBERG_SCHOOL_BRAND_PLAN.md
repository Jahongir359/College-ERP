# Iceberg School Brand — Build Plan and Agent Guide

Document date: 2026-10-23
Status: **Phases 1, 3 and 4a done; Phase 2 mostly done (screenshots + remaining colours open); Phase 5
in progress. All of it is merged on `feat/school-brand-phase-5`.** See sections 11 and 13.

> **Ownership split (avoid merge conflicts):** Phase 3 owns the sign-in and account-recovery pages —
> `main_app/login.html`, `registration/*.html`, `password_recovery.py` and
> `static/dist/css/brand-school-auth.css`. Phase 2 owns everything else in the ERP (`base.html`,
> `entry.html`, `error.html`, `download.html`, the ERP templates and `brand-school.css`). Phase 2
> must **not** add `data-brand` or a stylesheet link to `login.html` / `erpnext_base.html` — Phase 3
> already did — and should leave `brand-school.css` section 4 ("login") empty or delete it.
Decision (owner, 2026-10-23): **one shared domain** for the Learning Center and the School — no
separate School domain. Section 8.1 explains how visitors still land on the right brand's pages.
Owner: Jahongir
Design reference (canvas, private to the owner): https://claude.ai/artifact/9KE5AjoJ59UQJu22Z656gB
Brand assets in repo: `docs/brand/iceberg-school/`

This file is written so that **any AI agent or developer** can pick up the work cold. Read it fully
before touching code. Update the **Progress log** (section 13) at the end of every work session.

---

## 1. Goal in one paragraph

Iceberg runs two institutions: the existing **Iceberg Learning Center** (language/test-prep center —
the brand this repo already ships) and the new **Iceberg School** (a private K-11 school, maroon crest
logo). Both must run on **this same ERP** (Django web + Flutter app + REST API). The School gets the
same screens, layouts, components, typeface and behavior as the Learning Center; only the **brand
layer** changes (colors, logo, name, a few words like "Classes" vs "Groups"). On top of that, the School
gets a small **public website** (Home + Admissions) whose enquiry form feeds the existing
Registration Leads screen.

## 2. Can this be built without breaking anything? — Yes, if these rules hold

The whole plan is designed around one safety property:

> **When the brand is `center` (the default), every page, API response and app screen must be
> byte-for-byte or pixel-for-pixel what it is today.**

That is achieved by:

1. **Additive only.** New model field with a default, new files, new URL prefixes. No renames, no
   deletions, no changed defaults, no edits to existing migrations.
2. **Scoped CSS.** Every School style lives in one new stylesheet and every rule is prefixed with
   `html[data-brand="school"]`. Learning Center pages never match those selectors.
3. **Fallback values.** Where an existing hard-coded color must become a variable, write
   `var(--brand-x, <the exact old hex>)` so the Learning Center renders exactly as before.
4. **Feature flag.** `SCHOOL_BRAND_ENABLED` (env, default `False`). While off, brand resolution always
   returns `center`, so production is unaffected even after merge.
5. **Small phases, each its own PR, each green in CI** (section 10) before the next starts.

## 3. Non-negotiable rules for agents

1. **Edit under `backend/` only.** The repo root `main_app/`, `college_management_system/`,
   `manage.py`, `requirements.txt`, `runtime.txt` are **symlinks into `backend/`** that keep the
   DigitalOcean build working (`.do/app.yaml`). Never delete, replace or "fix" these symlinks.
2. **Do not change the Learning Center look.** No edits to existing color values in
   `iceberg.css`, `iceberg-bold.css`, `erpnext-style.css`, `admin-dashboard-2026.css` or the Flutter
   `IceColors` / `IceTokens` defaults. Add, don't modify.
3. **Default brand is `center` everywhere** — model default, resolver fallback, API fallback, Flutter
   fallback. A missing/unknown brand value must resolve to `center`, never raise.
4. **Branch scoping stays in `main_app/branching.py`.** Do not re-implement branch filtering in
   views. Brand resolution is a separate module (`main_app/branding.py`) and must not change who can
   see what.
5. **Migrations:** only additive (`AddField` with default). Next number is **0040** (latest existing is
   `0039_alter_attendancereport_student_and_more.py`). Run `makemigrations` — never hand-write a
   migration that alters existing columns.
6. **No new frontend frameworks.** Web stays Django templates + the existing CSS/vanilla JS.
   Flutter stays Riverpod + go_router.
7. **i18n:** every new user-facing string must exist in Uzbek, Russian and English — Django templates
   follow the existing pattern in the template you are editing; Flutter uses `lib/core/i18n/strings.dart`.
8. **Never hard-code new brand hexes in templates.** Use the CSS variables from section 5.
9. **Run the full check list (section 10) before every commit.** Baseline on 2026-10-23: `133 tests OK`,
   `check` clean, `makemigrations --check` clean.
10. **Commit / push only when the owner asks.** Branch off `main` (e.g. `feat/school-brand-phase-1`).
11. Do not delete or rewrite this file; append to the Progress log instead.

## 4. What exists today (facts, verified 2026-10-23)

| Area | Where | Notes |
|---|---|---|
| Django project | `backend/college_management_system/` | Django 5.2, settings in `settings.py` |
| Main app | `backend/main_app/` | models, views, API, templates, static |
| Roles | `models.py` `CustomUser.USER_TYPE` | `"1"` Admin/HOD, `"2"` Staff, `"3"` Student. **No parent role.** |
| Branches | `models.py` `class Branch` (name, address, timestamps) | `Group.branch`, `Student.branch`, `Staff.branch` FKs; `Admin.branches` M2M + `is_super_admin` |
| Effective branch | `Student.effective_branch`, `Staff.effective_branch` | explicit branch, else first active group's branch, else `None` |
| Branch access rules | `main_app/branching.py` | single source of truth — don't duplicate |
| Branch admin UI | `hod_views.py` `manage_branch`, `add_branch`, `edit_branch`; `forms.py` `BranchForm` (fields `name`, `address`); templates `hod_template/add_branch.html`, `manage_branch.html` | |
| Context processors | `main_app/context_processors.py` | `notification_count`, `student_theme`; registered in `settings.py` `TEMPLATES[0]["OPTIONS"]["context_processors"]` |
| Main layout | `templates/main_app/base.html` | 90 templates extend it. Loads Inter + CSS stack (lines ~38–64), then an inline `<style>` with `!important` overrides (~lines 66–166), then `{% block custom_css %}`. Theme bootstrap script sets `data-theme` on `<html>` (~line 170). |
| Standalone pages (do not extend base) | `main_app/login.html`, `main_app/entry.html`, `main_app/error.html`, `main_app/download.html`, `registration/erpnext_base.html` (password reset flow) | each needs its own `data-brand` hook |
| Login | `views.login_page` at `/` and `/login/` (`main_app/urls.py`) | `/` is the login page — **do not change what `/` does** |
| Leads | `models.RegistrationLead` (has `branch` CharField, `program`, `source`), receiver `public_views.registration_leads_receiver` at `/public/registration-leads/` (token-protected via `REGISTRATION_LEADS_API_TOKEN`), admin screen `hod_template/manage_registration_leads.html`, API `api/admin/leads/` | School website enquiries should land here |
| API identity | `GET /api/me/` → `MeSerializer` (`api/views/auth.py`, `api/serializers.py`) | admins get `is_super_admin`, `branch_ids`; students get `branch_name` |
| Static files | WhiteNoise + `NonStrictManifestStaticFilesStorage` | new static files must survive `collectstatic`; reference with `{% static %}` |
| Flutter app | `mobile/iceberg_app/` | theme in `lib/core/theme/app_theme.dart` (`IceColors`, `AppTheme.light/dark`) and `lib/core/theme/ice_tokens.dart` (`IceTokens` ThemeExtension, `IceAccents`, `context.ice`); settings `lib/core/settings/app_settings.dart` (theme mode, accent, language). Font Inter is bundled. |
| Flutter web build | `web/flutter_web/`, served by `flutter_view.flutter_app` at `/app/` | |
| CI | `.github/workflows/django.yml` | ruff check + ruff format --check, `manage.py check`, `makemigrations --check --dry-run`, `collectstatic --dry-run`, `manage.py test` |
| Hard-coded colors | 111 templates / 1,277 hex literals in templates; 15k lines of CSS | biggest offenders: `#0C1F45` (73× in 28 templates), `#06B6D4` (46× in 22), `#0891B2` (30× in 14), `#0B4F8A`, `#071A52`, `#00CFE8` |

## 5. Design specification

### 5.1 Shared by both brands (already true in the repo — keep it)

- **Typeface:** Inter 400/500/600/700/800 (Google Fonts on web, bundled TTFs in Flutter). Do **not**
  introduce Montserrat into the ERP; the logo artwork already contains its own lettering.
- **Radii:** 8–10 px nav items/chips · 13 px inputs and buttons · 22 px login card · 24 px cards/panels
  · 26 px logo tile · Flutter `r=24`, `rSm=14`, `rLg=32`.
- **Layout:** 256 px sidebar, 60 px top bar, same section order (Overview, People, Academic
  Management, Groups/Classes & Enrollments, Attendance, Finance, Communication).
- **Login composition:** floating 148 px logo tile above a 390 px white card, "Welcome back /
  Sign in to continue", username + password (13 px radius, 1.5 px border), remember me, forgot
  password, full-width primary button.
- **Languages:** UZ / RU / EN switcher wherever it exists today.
- **Symbol:** both logos contain the same faceted iceberg mountain. That is the family link.

### 5.2 Brand tokens

Use these CSS custom properties. They are **new names** (prefix `--brand-`) so nothing existing is
overwritten for the Learning Center.

| Token | Learning Center (`center`) — current | Iceberg School (`school`) |
|---|---|---|
| `--brand-primary` | `#06343A` | `#4C0909` |
| `--brand-primary-hover` | `#0E6873` | `#7A1F1F` |
| `--brand-primary-deep` | `#03181C` | `#2E0505` |
| `--brand-on-primary` | `#FFFFFF` | `#FFFFFF` |
| `--brand-on-primary-soft` | `#A8D4D9` | `#F2D9D6` |
| `--brand-accent` (CTA fill) | `#DFFF2F` (lime) | `#4C0909` (maroon; the school has no neon accent) |
| `--brand-accent-ink` (text on accent) | `#06343A` | `#FFFFFF` |
| `--brand-tint` (active nav bg, badges) | `#EEF5F6` | `#F8F1F0` |
| `--brand-bg` (page canvas) | `#F4FAFB` | `#FBF7F6` |
| `--brand-auth-bg` (login canvas) | `#EEF3F6` | `#F6EFEE` |
| `--brand-border` | `#D4E4E6` | `#E8DCDA` |
| `--brand-input-bg` | `#F8FAFD` | `#FBF8F7` |
| `--brand-text` | `#06343A` | `#1F1515` |
| `--brand-muted` | `#5A7A7E` | `#5A4747` |
| `--brand-glow` (logo tile shadow) | `rgba(6,182,212,.22)` | `rgba(76,9,9,.25)` |
The public website adds its own warm tokens (gold, cream, paper) and the Fraunces heading font in
ICEBERG_WEB's `static/brand/tokens.json`; the ERP and the app keep the values above and Inter.

School **dark mode** (`html[data-brand="school"][data-theme="dark"]`):
`--brand-bg #140808`, surface `#1D0E0E`, surface-2 `#251212`, border `#3A1E1E`, text `#F4E9E7`,
muted `#BFA5A2`, primary (for fills) `#8E2A2A`, primary-ink (links/icons on dark) `#F2B8B0`,
tint `#2A1414`. Check 4.5:1 contrast for body text before shipping.

Semantic colors (success / warning / danger / info) are **shared** — keep the existing values.

Canonical maroon is **`#4C0909`** (sampled from the transparent logo files). The two square
"on-white/on-maroon" originals use a slightly different `#4E0000`; treat that as artwork-only.

### 5.3 Wording differences

| Concept | `center` | `school` |
|---|---|---|
| Institution name | Iceberg Learning Center (existing templates say "Iceberg Study Center" — leave those as they are for center) | Iceberg School |
| Short name under wordmark | Learning Center | School |
| Group noun | Group / Groups | Class / Classes |
| Level noun | Level | Grade |

Implement these as fields on the brand config (section 6.2), not as `if` chains in templates.

### 5.4 Logo assets

Originals (full resolution) in `docs/brand/iceberg-school/original/`:

| File | Use |
|---|---|
| `horizontal-maroon-transparent.png` | horizontal lockup on light backgrounds |
| `horizontal-white-transparent.png` | horizontal lockup on maroon/dark backgrounds |
| `vertical-maroon-transparent.png` | stacked lockup on light |
| `vertical-white-transparent.png` | stacked lockup on maroon/dark |
| `horizontal-maroon-on-white.png`, `horizontal-white-on-maroon.png`, `vertical-maroon-on-white.png`, `vertical-white-on-maroon.png` | social/print only (opaque backgrounds) |

Web-ready crops (trimmed, resized) in `docs/brand/iceberg-school/web/`:
`logo-h-maroon.png` (900 w), `logo-h-white.png` (900 w), `logo-v-maroon.png` (600 w),
`logo-v-white.png` (600 w), `crest-maroon.png` (360 w, shield only), `crest-white.png` (360 w).

Phase 2 copies the web crops to `backend/main_app/static/dist/img/brand/school/` (same file names).
The Learning Center keeps `static/dist/img/logo.png` (640×640 dark square) and
`static/dist/img/iceberg-wordmark.png`.

Logo rules: crest-white on a maroon tile with ~18% padding is the School's "app icon" equivalent of
the Learning Center's `logo.png` tile. Never recolor the crest, never place the maroon logo on a
maroon background, keep clear space ≥ the width of the crest's inner border.

### 5.5 Screens in the design reference

The canvas (link at top) contains: *One system, two brands* (token sheet), *School website — Home*,
*School website — Admissions*, *ERP — Sign in*, *ERP — Admin dashboard*, *App — Student home*
(School and Learning Center). The ERP screens have a **brand** switch in the canvas Tweaks panel that
shows the same screen in both brands. If you can't open the canvas, sections 5.1–5.3 and 8 describe
everything needed.

## 6. Architecture

### 6.1 Data model (Phase 1)

Add to `Branch` in `backend/main_app/models.py`:

```python
class Branch(models.Model):
    BRAND_CENTER = "center"
    BRAND_SCHOOL = "school"
    BRAND_CHOICES = [
        (BRAND_CENTER, "Iceberg Learning Center"),
        (BRAND_SCHOOL, "Iceberg School"),
    ]
    name = ...  # unchanged
    address = ...  # unchanged
    brand = models.CharField(
        max_length=20,
        choices=BRAND_CHOICES,
        default=BRAND_CENTER,
        help_text="Which Iceberg brand this branch's users see.",
    )
```

Then `python manage.py makemigrations main_app --name branch_brand` → expect
`0040_branch_brand.py` containing a single `AddField`. Every existing branch becomes `center` — no
visual change.

Add `"brand"` to `BranchForm.Meta.fields` and render it in `add_branch.html` / the edit form as a
select. Show the brand as a small badge in `manage_branch.html`.

### 6.2 Brand registry and resolver — `backend/main_app/branding.py` (built in Phase 1)

Responsibilities: one place that knows (a) the static config of each brand and (b) which brand the
current request should see.

> **Implemented.** The real file is the source of truth; the sketch below shows the intent. Public
> helpers: `BRANDS`, `get_brand(key)`, `is_valid_brand(key)`, `resolve_brand_key(request)`,
> `brand_for_user(user, session=None)`, `brand_key_for_user(user)` (no request — used by the API login
> response), constants `CENTER`, `SCHOOL`, `SCHOOL_PATH_PREFIX = "/school/"`,
> `BRAND_COOKIE = "iceberg_brand"`, `SESSION_KEY = "active_brand"`.

```python
"""Brand resolution: which Iceberg brand (Learning Center / School) a request sees.

Brand affects presentation only. It never grants or removes access — that is
branching.py's job.
"""
from dataclasses import dataclass

from django.conf import settings

from .models import Branch

CENTER = Branch.BRAND_CENTER
SCHOOL = Branch.BRAND_SCHOOL


@dataclass(frozen=True)
class BrandConfig:
    key: str
    name: str
    short_name: str
    group_noun: str
    group_noun_plural: str
    level_noun: str
    logo_tile: str          # static path for the square tile on login / navbar
    logo_on_dark: str       # static path, horizontal lockup for dark backgrounds
    logo_on_light: str      # static path, horizontal lockup for light backgrounds
    theme_color: str        # <meta name="theme-color">


BRANDS = {
    CENTER: BrandConfig(
        key=CENTER,
        name="Iceberg Study Center",   # matches existing template copy — do not change for center
        short_name="Learning Center",
        group_noun="Group", group_noun_plural="Groups", level_noun="Level",
        logo_tile="dist/img/logo.png",
        logo_on_dark="dist/img/iceberg-wordmark.png",
        logo_on_light="dist/img/logo.png",
        theme_color="#0C1F45",          # current value in login.html
    ),
    SCHOOL: BrandConfig(
        key=SCHOOL,
        name="Iceberg School",
        short_name="School",
        group_noun="Class", group_noun_plural="Classes", level_noun="Grade",
        logo_tile="dist/img/brand/school/crest-white.png",
        logo_on_dark="dist/img/brand/school/logo-h-white.png",
        logo_on_light="dist/img/brand/school/logo-h-maroon.png",
        theme_color="#4C0909",
    ),
}


def get_brand(key):
    return BRANDS.get(key or CENTER, BRANDS[CENTER])


def resolve_brand_key(request):
    """Return "center" or "school" for this request. Never raises."""
    if not getattr(settings, "SCHOOL_BRAND_ENABLED", False):
        return CENTER
    try:
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            return _brand_for_user(user, request)
        return _brand_for_anonymous(request)
    except Exception:  # presentation must never break a page
        return CENTER
```

Resolution order (implement exactly, and unit-test each line):

1. **Flag off** → `center`.
2. **Path starts with `/school/`** (public School pages, any visitor) → `school`.
3. **Student** (`user_type == "3"`): `student.effective_branch.brand`, else `center`.
4. **Staff** (`"2"`): `staff.effective_branch.brand`, else `center`.
5. **Admin** (`"1"`):
   - branch admin (not super): if **all** assigned branches share one brand → that brand; mixed or
     none → `center`.
   - super admin: `request.session["active_brand"]` if valid, else `center`. (Optional later: a
     brand switcher in the top bar that sets this session key. It changes **presentation only**.)
   - Signed-in users **ignore** `?brand=` and the cookie — their branch decides.
6. **Anonymous** (login, password reset):
   - `?brand=school` (the School site links to `/login/?brand=school`), else the `iceberg_brand`
     cookie (Phase 3/4 sets it on School pages); only values in `BRANDS` are accepted.
   - else `center`.
7. Any exception → logged, `center`. The result is cached on `request._iceberg_brand`.

Because both brands share **one domain**, there is no host-based mapping (the earlier
`BRAND_HOSTS` idea was dropped).

Setting (added in `settings.py` next to `REGISTRATION_LEADS_API_TOKEN`, documented in
`/.env.example`):

```python
SCHOOL_BRAND_ENABLED = os.environ.get("SCHOOL_BRAND_ENABLED", "False").strip().lower() in ("1", "true", "yes")
```

### 6.3 Context processor (done in Phase 1)

In `context_processors.py`:

```python
def brand(request):
    from .branding import get_brand, resolve_brand_key
    return {"brand": get_brand(resolve_brand_key(request))}
```

Register `"main_app.context_processors.brand"` **after** `student_theme`. Cache the result on the
request (`request._iceberg_brand`) if you call it more than once per request.

### 6.4 API (done in Phase 1)

- `MeSerializer` has read-only `brand` and `brand_name`. Used by `GET/PATCH /api/v1/me/` and the
  `user` object in the `POST /api/v1/auth/login/` response (there `request.user` is still anonymous,
  so it uses `brand_key_for_user`). Clients that don't know the fields ignore them.
- `BranchSerializer` (`GET /api/v1/admin/branches/`) includes `brand`.
- `admin_views.BranchListView` / `BranchDetailView` (`/api/v1/admin/branches-manage/…`) return
  `brand`; `POST` accepts an optional `brand` (default `center`, invalid → 400); `PATCH` with `brand`
  is **super-admin only** (403 otherwise), invalid → 400.
- The web `BranchForm` has a `brand` select, disabled unless the user is a super admin
  (`edit_branch` passes `can_set_brand=branching.is_super_admin(user)`; `add_branch` is super-admin
  only already). `manage_branch.html` shows an "Iceberg School" badge/chip on School branches only.
- Never return anything other than `"center"` or `"school"`.

## 7. Web (Django templates) implementation

### 7.1 Hook the brand onto `<html>`

In each of these files add `data-brand="{{ brand.key|default:'center' }}"` to the `<html>` tag:
`main_app/base.html`, `main_app/entry.html`, `main_app/error.html`, `main_app/download.html`.
(`main_app/login.html` and `registration/erpnext_base.html` were done in Phase 3 — see 7.6.) (Templates that `extends` these get it
for free.) For center the attribute is `center`, and no stylesheet targets `center`, so nothing changes.

### 7.2 New stylesheet `backend/main_app/static/dist/css/brand-school.css`

- Load it in every file from 7.1, **after** the inline `<style>` block in `base.html` (i.e. right
  before `{% block custom_css %}`) because that inline block uses `!important`. Load it only when
  `brand.key == "school"`:
  `{% if brand.key == "school" %}<link rel="stylesheet" href="{% static 'dist/css/brand-school.css' %}">{% endif %}`
- **Every selector starts with `html[data-brand="school"]`.** No exceptions. This is the safety net.
- Structure the file in this order:
  1. Token block: set the `--brand-*` values from 5.2, **and** re-point the existing variables so
     current CSS picks up the school palette without edits:
     `--navy, --navy-mid, --navy-light, --navy-deep, --lime, --lime-deep, --lime-text, --cyan,
     --cyan-dk, --cyan-light, --bg, --bg-blue, --surface-2, --border, --border-dk, --text,
     --text-muted, --text-sub, --primary-color, --ice-*` (all aliases in `iceberg.css` `:root`),
     and the admin-dashboard scope `html[data-brand="school"] .admin-dashboard { --ib-navy …
     --ib-ocean … --ib-cyan … --ib-ice … --ib-text … }`.
  2. Dark-mode token block (`html[data-brand="school"][data-theme="dark"]`, and `.dark-mode`).
  3. Component overrides for selectors that use hard-coded hexes (see 7.3).
  4. Login page overrides (logo tile glow, button gradient `#1B52E0→#1840C4` becomes solid
     `var(--brand-primary)`, input focus border `#06B6D4` becomes `var(--brand-primary-hover)`).

Mapping of old hard-coded colors → school replacements (use for both 7.2 overrides and 7.3):

| Existing hex (center) | Role | School value |
|---|---|---|
| `#06343A`, `#0C1F45`, `#071A52`, `#071833`, `#03181C` | primary / navy / headings | `#4C0909` (deep variants → `#2E0505`) |
| `#0E6873`, `#0B4F8A`, `#1E8C98`, `#1B52E0`, `#1840C4` | hover / secondary / buttons | `#7A1F1F` |
| `#06B6D4`, `#0891B2`, `#00CFE8`, `#4DD9E8` | cyan accent, focus rings, chart accent | `#A33A3A` (accent), focus ring `rgba(76,9,9,.35)` |
| `#DFFF2F`, `#B8D900` | lime CTA | `#4C0909` fill + white text |
| `#3D5C00` | lime-on-white ink | `#4C0909` |
| `#EEF5F6`, `#E4F7FA`, `#EAF8FF`, `#E4F0F2`, `#EEF3FB` | tints / auth canvas | `#F8F1F0` / `#F6EFEE` |
| `#F4FAFB`, `#F8FAFD` | page bg / input bg | `#FBF7F6` / `#FBF8F7` |
| `#D4E4E6`, `#DCEAEC`, `#B4D0D3`, `#dbe3ef` | borders | `#E8DCDA` / `#D9C7C4` |
| `#5A7A7E`, `#3D5C60`, `#8FA8AB`, `#667085`, `#64748B` | muted text | `#5A4747` / `#7A6363` |

Charts: keep chart series colors semantic (present = green, absent = red), but replace the
cyan/teal **brand** series with `#4C0909`, `#A33A3A`, `#D9A5A0` for school.

### 7.3 Hard-coded colors inside templates

Many templates contain inline `style="…#0C1F45…"` or `<style>` blocks. Handle them **incrementally,
one template per commit**, never with a repo-wide sed:

1. Find them: `grep -rnoiE "#(0C1F45|06B6D4|0891B2|0B4F8A|071A52|00CFE8|06343A|0E6873|DFFF2F)" backend/main_app/templates | sort | uniq -c | sort -rn`
2. Preferred fix: in a `<style>` block, change `color: #0C1F45` → `color: var(--brand-primary, #0C1F45)`.
   The fallback is the **old exact value**, so center is unchanged (center does not define
   `--brand-primary` anywhere, or defines it to the same value).
3. Inline `style=""` attributes: same `var(--brand-…, <old hex>)` pattern, or move to a class.
4. Do the highest-traffic screens first: `login.html`, `base.html`, `erpnext_sidebar.html`,
   `hod_template/home_content.html`, `staff_template/erpnext_staff_home.html`, student home and
   profile templates, `manage_registration_leads.html`, invoice/payment screens, `payment_receipt.html`.
5. After each template: load it as center and as school (see 10.2) and compare.

### 7.4 Logos, titles, meta

- Replace `{% static 'dist/img/logo.png' %}` in `login.html` (logo tile) with
  `{% static brand.logo_tile %}`; give the school tile `background: var(--brand-primary)` and ~18%
  padding (via `brand-school.css`, not inline).
- Sidebar / navbar wordmarks: use `brand.logo_on_dark` / `brand.logo_on_light` matching the
  background.
- `<title>`, `og:title`, `twitter:title` blocks default to `{{ brand.name }}`. For center
  `brand.name` is "Iceberg Study Center" — identical to today.
- `<meta name="theme-color">` → `{{ brand.theme_color }}`.
- `alt` text → `{{ brand.name }}`.
- Favicons, `manifest.json` and the installed PWA/TWA app stay Learning Center: with one shared
  domain there is one installable web app per origin. Inside the app the School user still sees the
  School brand after sign-in. Public School pages (8.1) set their own favicon `<link>` tags to the
  crest so browser tabs and search results show the School icon.

### 7.5 Wording

Replace literal "Group"/"Groups" in **labels only** (never in URLs, model names, form field names or
API keys) with `{{ brand.group_noun }}` / `{{ brand.group_noun_plural }}`. Do this screen by screen
together with translations.


### 7.6 Sign-in and account recovery (Phase 3 — done)

- `main_app/login.html` and `registration/erpnext_base.html` carry
  `data-brand="{{ brand.key|default:'center' }}"` and, **only for School**, link
  `static/dist/css/brand-school-auth.css` right before `</head>` (after the inline `<style>`).
- All School-specific markup is inside `{% if brand.key == "school" %}…{% else %}<original>{% endif %}`,
  so Learning Center output is unchanged apart from the `data-brand="center"` attribute.
  School differences: title "Iceberg School — Sign In", `theme-color` `#4C0909`, `og:site_name`/`og:title`,
  crest tile (`brand.logo_tile`), "Sign in to Iceberg School", footer "© Iceberg School · Iceberg
  Learning Center sign-in" (link to `/login/?brand=center`), recovery header "ICEBERG / SCHOOL" with the
  crest in the brand mark.
- `brand-school-auth.css`: every selector starts with `html[data-brand="school"]`; tokens use
  `var(--brand-*, <School hex>)` so it works with or without Phase 2's `brand-school.css`. It re-points the
  recovery template's `:root` variables (`--primary`, `--secondary`, `--cyan`, …) and overrides the login
  page's hard-coded cyan/blue (logo glow, focus ring, button gradient, links), including the
  `platform-apple` / `platform-other` variants and `prefers-color-scheme: dark`.
- `main_app/middleware.py` → `BrandCookieMiddleware` (registered after `LoginCheckMiddleWare`): when the
  flag is on, sets `iceberg_brand` (1 year, HttpOnly, SameSite=Lax, Secure like the session cookie) if a
  visitor used `?brand=`, is on `/school/`, or is signed in (their branch's brand). It never touches
  `/api/`, `/static/`, `/media/`, `/app`, `/admin/`, `/download/`, never raises, and does nothing when the
  flag is off. Effect: a School user who logs out sees the School sign-in next time.
- `password_recovery.py`: `_send_code_email(..., brand_name)`; subject is
  "Iceberg School — Password Reset Code" for School users (unchanged for the Learning Center).
- Not changed: Django's built-in `accounts/password_reset/` email (`registration/password_reset_email.html`)
  still says "College ERP" — legacy, separate from the code-based flow; fix when convenient.

## 8. School public website (Phase 4)

> **Superseded (2026-10-23).** The School website will live in the **existing iceberglc.com website
> codebase** (owned by the owner) at `iceberglc.com/school`, connected to this ERP through the existing
> lead endpoint; that site also moves onto the shared Iceberg design system. The full plan is
> [`ICEBERG_SCHOOL_WEBSITE_PLAN.md`](https://github.com/Jahongir359/ICEBERG_WEB/blob/main/docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md). The Django-hosted design below
> is kept for reference only — **do not build it**, and do not add `/school/` to
> `LoginCheckMiddleWare`. Section 8.1 (search) still applies, in the website repo.

Do **not** touch `/` (it is the ERP login). Serve the site under `/school/`:

| URL | Name | Template |
|---|---|---|
| `/school/` | `school_home` | `templates/site/school/home.html` |
| `/school/admissions/` | `school_admissions` | `templates/site/school/admissions.html` |
| `/school/admissions/thanks/` | `school_admissions_thanks` | `templates/site/school/thanks.html` |

- New view module `backend/main_app/site_views.py`; add paths in `main_app/urls.py` in a clearly
  commented block. These views are public (no login decorators). **Required:**
  `main_app/middleware.py` → `LoginCheckMiddleWare` redirects every anonymous request that is not
  on its allow-list to the login page. Add `or request.path.startswith("/school/")` to the anonymous
  allow-list (next to the `/public/registration-leads` and `/download/` entries, ~lines 59–78), with
  a comment, and add a test that an anonymous GET of `/school/` returns 200 (not a 302 to `/login/`).
- `templates/site/school/base.html` is standalone (does not extend the ERP `base.html`), uses Inter,
  sets `<html data-brand="school">`, sets the `brand=school` cookie (so "Portal login" opens the
  school-branded login), and links `brand-school.css` **plus** a new `site-school.css` for
  marketing layout.
- Content structure (from the canvas):
  - **Home:** maroon header with `logo-h-white.png` + nav (About, Programs, Admissions, News,
    EN/UZ/RU, "Portal login" → `/login/?brand=school`); hero "What you see is the tip. We build what
    lies beneath." with Apply + Book a tour; three pillars from the crest (Aim high — mountain;
    Grow whole — child; Read deeply — book); Programs (Primary / Middle / High with grade ranges);
    key numbers; "School life in your pocket" app section; News & events; Admissions CTA band;
    footer (address, links, "Part of the Iceberg family · Iceberg Learning Center").
  - **Admissions:** 4 steps (Enquiry → Visit → Assessment → Offer), enquiry form, tuition panel,
    FAQ.
  - Anything in `[brackets]` in the canvas is a placeholder the owner must supply (grade ranges,
    prices, founding year, phone, address, photos). **Never invent these facts.** Make them
    editable — simplest: a `SCHOOL_SITE` dict in settings or a small admin-editable model later.
- **Enquiry form → RegistrationLead** (no token needed because it's a same-origin Django form):
  - Django `Form` with: parent full name (required), phone (required, `+998` format), child full
    name, child date of birth, grade applying for (1–11 select), preferred language (uz/ru/en),
    message, consent checkbox (required), and a hidden honeypot field.
  - CSRF protected (normal Django form). Throttle by IP with the cache: max 5 submissions / 10 min.
  - On valid POST create `RegistrationLead(full_name=parent, phone=…, program=f"Grade {n}",
    branch=<the School branch name>, source="school-website", message=<child name, DOB, language,
    message>, raw_payload=<cleaned data>, remote_addr, user_agent)` then redirect to the thanks page.
  - Leads then show in the existing **Registration leads** admin screen with no changes there.
- Tests: GET pages 200 anonymously; valid POST creates exactly one lead with `source="school-website"`;
  honeypot filled → no lead; missing consent → form error; throttle → 429 or form error; `/` still
  renders the login page.

### 8.1 Landing people on the page they searched for (shared domain)

Owner requirement: someone who searches "Iceberg School" must land on School pages; someone who
searches "Iceberg Learning Center" / "Iceberg IELTS" must land on Learning Center pages — on the
**same domain**. This is fully possible; search engines rank **URLs**, not domains, so each brand
needs its own URLs with its own clearly different signals. Do all of the following:

1. **Separate URL space.** All public School pages live under `/school/` (`/school/`,
   `/school/admissions/`, later `/school/about/`, `/school/news/…`). Learning Center URLs are never
   changed or redirected. Never serve School content on a Learning Center URL or vice versa.
2. **Unique titles and descriptions per page** (in the page's language):
   - `<title>Iceberg School — Private School in [Namangan], Grades [1–11]</title>`
   - `<meta name="description" content="Iceberg School is a private school in [Namangan] …">`
   - Learning Center pages keep their own titles; never reuse the same title/description across
     brands.
   - First `<h1>` on School pages contains "Iceberg School".
3. **Canonical URL** on every page: `<link rel="canonical" href="https://<domain>/school/…">`.
4. **Open Graph / social** per brand: `og:site_name` = "Iceberg School", `og:image` = a School
   image (1200×630 made from `logo-h-white.png` on `#4C0909`; save as
   `static/dist/img/brand/school/og-image.png`). The Learning Center keeps
   `infra/public/og-image.png`.
5. **Structured data (JSON-LD)** in the School base template:
   ```json
   {"@context":"https://schema.org","@type":"School","name":"Iceberg School",
    "url":"https://<domain>/school/","logo":"https://<domain>/static/dist/img/brand/school/logo-v-maroon.png",
    "address":{"@type":"PostalAddress","streetAddress":"[ADDRESS]","addressLocality":"[Namangan]","addressCountry":"UZ"},
    "telephone":"[PHONE]",
    "parentOrganization":{"@type":"Organization","name":"Iceberg"},
    "sameAs":["[School Instagram URL]","[School Telegram URL]"]}
   ```
   The Learning Center pages get their own block with `"@type":"EducationalOrganization"`,
   `"name":"Iceberg Learning Center"`. Distinct names + types is what lets Google show them as two
   separate results/knowledge panels.
6. **Languages.** Give each language version of a public School page its own URL
   (e.g. `/school/` = Uzbek default, `/school/ru/`, `/school/en/`) and add
   `<link rel="alternate" hreflang="uz|ru|en|x-default" …>` on each. Cookie-only language switching
   is invisible to search engines.
7. **Sitemap + robots.** Add a `sitemap.xml` (Django `django.contrib.sitemaps`, or a static file)
   listing every public School URL (and any public Learning Center URLs), and add
   `Sitemap: https://<domain>/sitemap.xml` to `infra/public/robots.txt`. Keep `/admin/` and `/api/`
   disallowed. The ERP login (`/`, `/login/`) can stay indexable as it is today.
8. **Cross-links, not redirects.** School header/footer: "Looking for language courses? → Iceberg
   Learning Center"; Learning Center footer: "Iceberg School →". **Never** auto-redirect visitors by
   cookie, IP or guess — that confuses people and search engines (cloaking). The `iceberg_brand`
   cookie only styles the login page.
9. **Portal login from School pages** → `/login/?brand=school` (styled School, Phase 3). After
   sign-in, the user's branch decides the brand, whatever the link was.
10. **Owner tasks outside the code:** in Google Search Console, verify the domain and submit the
    sitemap; create a **separate Google Business Profile** for Iceberg School whose website is
    `https://<domain>/school/`; use the `/school/` URL in School social bios and ads.
11. **Where the School pages are hosted.** `.env.example` shows the Learning Center's public
    website is a separate site at `iceberglc.com` (it posts leads to this ERP at
    `app.iceberglc.com/public/registration-leads/`), while this repo is the ERP at
    `app.iceberglc.com`. Two valid options — **owner must choose before Phase 4**:
    - **A (recommended for search):** build the School pages inside the `iceberglc.com` website
      codebase at `iceberglc.com/school/…`, applying points 1–10 there, and post the enquiry form to
      the existing lead receiver with `source="school-website"` and `branch="<School branch name>"`.
      This repo then only does the portal branding (Phases 1–3, 5).
    - **B:** build them in this Django app at `app.iceberglc.com/school/…` as described in section 8.
      Points 1–10 still apply. Works, but `app.` is the ERP subdomain, so the School site lives next
      to the login rather than next to the Learning Center's public site.
    - **Decided 2026-10-23:** option **A** — the owner runs iceberglc.com and its code, so the School
      pages go into that codebase at `iceberglc.com/school`, and the site adopts the shared design
      system — see [`ICEBERG_SCHOOL_WEBSITE_PLAN.md`](https://github.com/Jahongir359/ICEBERG_WEB/blob/main/docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md). Option B is dropped.

## 9. Flutter app (Phase 5)

Flutter is **not installed in the codespace**; this phase needs a machine with Flutter (version per
`pubspec.yaml`, SDK `^3.8.1`) or CI (`.github/workflows/firebase-distribute.yml`).

1. Copy `docs/brand/iceberg-school/web/crest-white.png` and `logo-h-white.png` to
   `mobile/iceberg_app/assets/images/brand/school/` and register them in `pubspec.yaml` `assets:`.
2. New file `lib/core/theme/brand.dart`:
   `enum IceBrand { center, school }` with `fromApi(String?)` (unknown/null → `center`) and a
   `BrandPalette` (primary, primaryHover, tint, bg, border, text, muted, accent, onAccent) using the
   values in 5.2.
3. `IceTokens.light/dark` get an optional `brand` parameter; when `school`, swap `accent`,
   `accentInk`, `onAccent`, `mint` and card gradient colors to the maroon palette. Do not change the
   defaults (center).
4. `AppTheme.light()/dark()` accept the brand and use `BrandPalette.primary` where they currently use
   `IceColors.navy/navyDeep` for primary surfaces. Keep `IceColors` constants untouched.
5. Brand source: the `brand` field from `/api/me/`. Store it in a Riverpod provider
   (`brandProvider`) fed by the auth/me response, persist last value in `shared_preferences`
   (`ice_brand`) so the login screen after logout shows the last brand. **Users cannot choose the
   brand** — it is not an appearance setting.
6. Labels: add `groupNoun` / `levelNoun` helpers to `strings.dart` keyed by brand and language.
7. Logo widgets: wherever `assets/images/logo.png` or `iceberg-wordmark.png` is shown, pick by
   brand.
8. Rebuild Flutter web into `web/flutter_web/` only via the existing deploy flow
   (the `Dockerfile` / CI) — don't hand-edit build output.
9. `flutter analyze` and `flutter test` must pass.

## 10. Verification

### 10.1 Commands (run from `backend/`, all must pass before every commit)

```bash
python -m ruff check .
python -m ruff format --check .
python manage.py check
python manage.py makemigrations --check --dry-run   # after Phase 1 is committed
python manage.py collectstatic --noinput --dry-run -v 0
python manage.py test
```

Baseline 2026-10-23: 133 tests, all OK.

### 10.2 Visual regression (each web phase)

1. Run `python manage.py runserver` with `SCHOOL_BRAND_ENABLED=False` and capture these pages as
   admin, staff and student: login, dashboard, manage students, group detail, attendance,
   invoices/payments, registration leads, profile, notifications, messages, password reset.
2. Repeat with `SCHOOL_BRAND_ENABLED=True` for a user in a `center` branch → screenshots must match
   step 1.
3. Repeat for a user in a `school` branch → every brand surface is maroon; no teal/cyan/lime left
   on primary surfaces; text contrast ≥ 4.5:1; dark mode works.

### 10.3 Required new tests (now in `backend/main_app/tests/test_branding.py` and its siblings)

- `Branch.brand` defaults to `center`; migration applies.
- Resolver: flag off → center for every user type; student/staff/admin/super-admin/anonymous cases
  from 6.2; unknown cookie/host value → center; exception inside → center.
- Context processor puts `brand` in context; `base.html` renders `data-brand="center"` by default and
  `data-brand="school"` for a school student; `brand-school.css` link only present for school.
- `/api/me/` includes `brand` and it is `center` when flag off.
- Branch form saves `brand`.
- Website tests from section 8.
- Branch scoping regression: a school-branch admin still sees only their branches (brand must not
  widen access).

## 11. Phases and task checklist

Tick boxes as you finish. One PR per phase.

**Phase 0 — Assets and plan** ✅
- [x] Originals and web crops in `docs/brand/iceberg-school/`
- [x] This plan, `AGENTS.md`, `CLAUDE.md`

**Phase 1 — Backend plumbing (no visual change)** ✅ (branch `feat/school-brand-phase-1`)
- [x] `Branch.brand` field + migration `0040_branch_brand` (single `AddField`, default `center`)
- [x] `BranchForm` brand select (super-admin only) + "Iceberg School" label in `manage_branch.html`
- [x] `settings.py`: `SCHOOL_BRAND_ENABLED`; `.env.example` documented (no `BRAND_HOSTS` — shared domain)
- [x] `main_app/branding.py` (registry + resolver)
- [x] `context_processors.brand` registered (after `student_theme`)
- [x] `MeSerializer.brand/brand_name` (incl. login response), `BranchSerializer.brand`,
      branches-manage API returns/accepts `brand` (change = super admin only)
- [x] Tests: `main_app/tests_branding.py` (20 tests); full suite 153 OK; ruff/check/migrations/collectstatic green
- [x] Web crops copied to `static/dist/img/brand/school/` (so `BRANDS` static paths resolve)

**Phase 2 — Web brand layer**
- [x] Copy web crops to `static/dist/img/brand/school/` (done in Phase 1)
- [x] `data-brand` on the six root templates
- [x] `static/dist/css/brand-school.css` (tokens, dark tokens, overrides)
- [x] Conditional `<link>` in the six root templates, after base.html's inline `<style>`
- [x] Logos / titles / theme-color via `brand`
- [ ] Hard-coded colors converted in priority templates (7.3 list), one per commit — base, admin/staff/student home done; `login.html` left for Phase 3; rgba() literals not yet
- [ ] Visual regression 10.2 passed — HTML-level check done (center byte-identical on 19 pages); screenshots pending (no browser in codespace)

**Phase 3 — Login and auth pages** ✅ (branch `feat/school-brand-phase-3`, see 7.6)
- [x] School login look (tile, glow, button, focus, dark mode) via its own `brand-school-auth.css`
- [x] `?brand=school` + cookie resolution for anonymous pages (resolver done in Phase 1)
- [x] `BrandCookieMiddleware` sets/refreshes the `iceberg_brand` cookie (?brand=, /school/, signed-in users)
- [x] Password-recovery pages (`registration/erpnext_base.html` and children) branded
- [x] Reset-code email subject uses the user's brand name
- [x] Tests `tests_brand_auth.py` (16); screenshots checked (light, dark, phone)

**Phase 4 — School website** → in the iceberglc.com codebase; checklist 4a–4e lives in
[`ICEBERG_SCHOOL_WEBSITE_PLAN.md`](https://github.com/Jahongir359/ICEBERG_WEB/blob/main/docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md) section 10. Only **4a** happens in
this repo:
- [x] Lead receiver refuses requests when `REGISTRATION_LEADS_API_TOKEN` is unset in production (+ test,
      deploy check W002) — confirm the production token before deploying
- [ ] School branch created in the ERP; exact name shared with the website (`SCHOOL_BRANCH_NAME`)

**Phase 5 — Flutter**
- [x] Assets + `brand.dart` + `IceTokens`/`AppTheme` brand parameter
- [x] `brandProvider` from `/api/me/`, persisted
- [x] Wording + logos by brand
- [x] `flutter analyze` (no errors or warnings; 13 deprecation infos in older screens), `flutter test`, `flutter build web --release` — verified 2026-10-23 with Flutter 3.47.7 / Dart 3.13.5

**Phase 6 — Rollout**
- [ ] Staging: `SCHOOL_BRAND_ENABLED=True`, create "Iceberg School" branch with `brand=school`,
      assign test admin/staff/student, run 10.2
- [ ] Owner sign-off
- [ ] Production: set env var; create the school branch; move school users/groups into it

## 12. Open questions for the owner (ask before the phase that needs them)

1. ~~Will the School use its own domain?~~ **Answered 2026-10-23: no — same domain as the Learning
   Center.** ~~Where do the School pages live?~~ **Answered 2026-10-23: in the existing iceberglc.com
   codebase** (owner runs it), at `iceberglc.com/school`. Remaining website questions: [website plan](https://github.com/Jahongir359/ICEBERG_WEB/blob/main/docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md) section 11 (in ICEBERG_WEB).
2. Same database/organization as the Learning Center (one ERP, School = branch with `brand=school`)?
   This plan assumes **yes**.
3. One mobile app for both brands (brand chosen by login, as planned) or a separate School app in
   the stores? (Phase 5)
4. Grade structure (1–4 / 5–9 / 10–11?), class size, tuition, sibling discount, founding year, phone,
   address, real photos. (Phase 4)
5. Should super admins get a brand switcher in the top bar? (Phase 2, optional)
6. Does the School need a parent role? (Not in this plan — the ERP has Admin/Staff/Student only. It
   would be a separate, larger project touching `CustomUser.USER_TYPE`, `branching.py` and the API.)

## 13. Progress log

Append one entry per work session: date, agent/person, phase, what changed (files), test result,
what's next. Newest at the bottom.

- **2026-10-23 — Claude (Opus 5.5) — Phase 0.** Added `docs/brand/iceberg-school/` (8 originals +
  6 web crops), this plan, root `AGENTS.md` and `CLAUDE.md`. No application code changed. Baseline:
  `manage.py test` 133 OK, `check` clean, no pending migrations. Next: Phase 1.
- **2026-10-23 — Claude (Opus 5.5) — Phase 1.** Owner decided: same domain for both brands, and
  visitors must land on the right brand's pages → added section 8.1, dropped `BRAND_HOSTS`, resolver
  uses the `/school/` path, `?brand=` and the `iceberg_brand` cookie. Branch `feat/school-brand-phase-1`.
  Changed: `models.py` (`Branch.brand`), `migrations/0040_branch_brand.py`, new `branding.py`,
  `context_processors.py` (`brand`), `settings.py` (`SCHOOL_BRAND_ENABLED`, context processor),
  `.env.example`, `forms.py` (`BranchForm`), `hod_views.py` (`add_branch`/`edit_branch`),
  `hod_template/manage_branch.html`, `api/serializers.py` (`MeSerializer`, `BranchSerializer`),
  `api/admin_views.py` (branches-manage list/detail/create/patch), new `tests_branding.py`,
  `static/dist/img/brand/school/*.png`. Results: ruff check/format clean, `check` clean,
  `makemigrations --check` clean, collectstatic dry-run OK, **153 tests OK** (133 old + 20 new).
  No template uses `brand` yet, so with the flag off or on, Learning Center pages render as before.
  Committed as `26a9d46` (docs) and `7d91fb9` (code). Phase 2 then started in a separate worktree.
- **2026-10-23 — Claude (Opus 5.5) — Phase 2 (web brand layer).** Branch `feat/school-brand-phase-2`
  (off `feat/school-brand-phase-1`), worktree `/workspaces/College-ERP-phase2`. Changed:
  new `static/dist/css/brand-school.css` (every selector `html[data-brand="school"]`; light + dark
  tokens re-point `--navy/--cyan/--lime/--ice-*/--ib-*/--app-*` and profile-hub's
  `--brand-navy/ocean/cyan/ice`; overrides for sidebar, navbar badge, buttons, focus, badges,
  hero/cover banners, loaders; login section reserved for Phase 3). `branding.py`: added
  `display_name` / `mark` fields holding the exact strings center templates already render.
  Six root templates (`base`, `login`, `entry`, `error`, `download`, `registration/erpnext_base`):
  `data-brand`, conditional school `<link>` after the last inline `<style>`, title / og / twitter /
  theme-color / logo / footer via `brand` with `|default:"<old text>"`. 26 child `{% block title %}`
  "— Iceberg Study Center" → `brand.name`. Colors wrapped as `var(--brand-*, <old hex>)` in
  `base.html`, `staff_template/erpnext_staff_home.html`, `student_template/erpnext_student_home.html`;
  chart colors in admin/staff/student dashboards read `--brand-*` at runtime with the old value as
  fallback. Note: base.html's theme-color stays `#06343A` for center (BrandConfig center value is
  login's `#0C1F45`), so it's switched with `{% if %}`. New tests `tests_brand_assets.py` (5: every
  selector scoped, tokens, logos) and `tests_brand_web.py` (10: center unchanged flag on/off, school
  student/teacher/admin, mixed admin → center, login / recovery / 404 / download hooks).
  Verification: rendered 19 pages (login, recovery, download, 404, 8 branch-admin, 3 teacher,
  4 student) before and after with flag off and on for a center branch — identical apart from
  `data-brand="center"` and the behaviour-neutral `var()` / `brandColor()` fallbacks. ruff, check,
  makemigrations --check, collectstatic dry-run clean; **168 tests OK**. Committed on
  `feat/school-brand-phase-2` (stylesheet, template hooks, then one commit per colour-converted
  template; suite green after each); not pushed. Next: screenshots for 10.2 (needs a browser), remaining color conversion in other
  templates (incl. rgba literals), then Phase 3 — which another session has started
  (`BrandCookieMiddleware`), so coordinate edits to `login.html` and `registration/*`.
- **2026-10-23 — Claude (Opus 5.5) — Phase 3.** Owner: Phase 2 is being done in parallel on
  `feat/school-brand-phase-2` (worktree `/workspaces/College-ERP-phase2`); do Phase 3. Branch
  `feat/school-brand-phase-3` from `feat/school-brand-phase-1`. To avoid conflicts with Phase 2's
  uncommitted `brand-school.css`, Phase 3 uses its own `brand-school-auth.css` and owns the auth
  templates (ownership note at the top). Changed: `templates/main_app/login.html`,
  `templates/registration/erpnext_base.html`, new `static/dist/css/brand-school-auth.css`,
  `middleware.py` (`BrandCookieMiddleware`), `settings.py` (register it), `password_recovery.py`
  (email subject), new `tests_brand_auth.py`, this plan (7.1, 7.6, checklist). Results: ruff/format
  clean, `check` clean, no migrations, collectstatic OK, **169 tests OK** (153 + 16). Screenshots via
  Playwright of School/Center login and School recovery in light, dark and phone width look right.
  (Installed Playwright + Chromium and its apt dependencies in the codespace for this — not in the repo.)
  Not committed yet. Next: merge order Phase 1 → 2 → 3 (expect only trivial conflicts in this plan file
  and `settings.py`); then Phase 4 once the owner picks hosting option A or B (8.1 point 11).
- **2026-10-23 — Claude (Opus 5.5) — Website decision (planning only).** Owner asked: new repo for the
  website, or this repo? Checked: the LC public site (iceberglc.com, Namangan, Cloudflare, server-rendered)
  comes from a codebase not visible in the owner's GitHub accounts; this repo is only the ERP
  (app.iceberglc.com). Decision documented: **new repo `iceberg-website`**, School at
  `iceberglc.com/school/` through a Cloudflare Worker route, enquiry form → existing ERP lead endpoint
  server-side. Added `docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md` and `docs/brand/iceberg-school/tokens.json`
  (brand tokens as JSON for the website). Section 8 marked superseded; Phase 4 checklist moved;
  "Tashkent" placeholders corrected to [Namangan]. Found: the lead endpoint accepts posts when its token
  is unset — fix listed as 4a. No code changed. Next: owner answers website plan section 11.
- **2026-10-23 — Claude (Opus 5.5) — Website decision revised.** Owner runs iceberglc.com and its code
  and is happy to change its design/code to fit this plan. Website plan rewritten: School pages go into
  that codebase at `iceberglc.com/school` (new-repo idea kept only as appendix A), the site moves onto
  the shared design system (`data-brand` + `tokens.json`, real CSS build, real languages), and the School
  form reuses its `/api/register`. Found from the live site: its form sends branch codes (`main`,
  `gayrat`), which won't match ERP branch names → branch admins can't see website leads; fix listed in
  4b. Open owner decision: which Learning Center palette is canonical (website navy+blue vs ERP
  teal+lime). Waiting for access to the website code.

- **2026-10-23 — Claude (Opus 5.5) — Phase 4a + merge note.** Branch `feat/school-brand-phase-4a`
  (from phase-3). `public_views.registration_leads_receiver` now returns 503 + logs an error when
  `REGISTRATION_LEADS_API_TOKEN` is empty and `DEBUG` is off; new deploy check `main_app.W002`; existing
  empty-token test now runs with `DEBUG=True`; 2 new tests. **171 tests OK.** Deploy prerequisite:
  production must have the token set. **Merge note:** `feat/school-brand-phase-2` also edited
  `main_app/login.html` and `registration/erpnext_base.html` (and adds `brand.mark` /
  `brand.display_name`), so merging Phase 2 and Phase 3 will conflict in those two templates. Resolve by
  keeping Phase 3's School-only `{% if brand.key == "school" %}` blocks and `brand-school-auth.css` link,
  and Phase 2's new `BrandConfig` fields where they don't change Learning Center output; re-run
  `tests_brand_auth.py` and `tests_brand_web.py` after resolving.
- **2026-10-23 — Claude (Opus 5.5) — Phase 5 (in progress) + website guide.** Branch
  `feat/school-brand-phase-5`. Flutter brand layer committed as work in progress: new
  `lib/core/theme/brand.dart` (`IceBrand`, `SchoolColors`, brand-aware colour getters) and
  `brand_provider.dart` (brand from the signed-in user's `brand`, last brand persisted for
  splash/login), `IceUser.brand`, `buildIceTheme(brand:)`, app title by brand, "Class"/"My Class"
  strings, shells/widgets switched from fixed `IceColors` to brand getters, School logo assets.
  **Not yet verified:** `flutter analyze` / `flutter test` / build (Flutter isn't installed in the
  codespace) — Phase 5 checklist stays open until they pass. Website plan finished: sections 4.1, 8, 9,
  11, 12 reconciled with the owner's "re-skin the LC site onto the shared design system" decision
  (shared layout + `/static/brand/tokens.css` instead of a School-only layout; LC URLs/copy/SEO kept),
  question 7 (order: re-skin first or School first) added, and a ready-to-copy website `AGENTS.md`
  template added as `docs/plans/ICEBERG_WEBSITE_AGENTS.md`. No backend code changed.
- **2026-10-23 — Claude (Opus 5.5) — Merged Phase 2 into `feat/school-brand-phase-5`.** Owner asked to
  bring Phase 2 in so one branch carries Phases 1–5. Conflicts only in `login.html`,
  `registration/erpnext_base.html` and this log; resolved per the Phase 4a merge note (Phase 3's
  School-only blocks and `brand-school-auth.css` link kept on the auth pages; Phase 2's other changes,
  e.g. `brand.mark` in the recovery title, kept).
- **2026-10-23 — Claude (Opus 5.5) — Phase 4b started (website repo).** The iceberglc.com code is
  `Jahongir359/ICEBERG_WEB` (Flask templates → static HTML on Cloudflare Pages). Finding: its live
  `/api/register` (Cloudflare Pages Function) stored leads only in Google Sheets and never called the
  ERP. ICEBERG_WEB branch `feat/erp-lead-forwarding`: best-effort ERP copy after Sheets succeeds (off
  until the Cloudflare secrets are set), `erp_branch_name` mapping (Flask route too), Apps Script reports
  duplicates, root `AGENTS.md`/`CLAUDE.md` filled from the template, website plan copied to its
  `docs/plans/`. Tests there: Flask 8 OK, Node 19 OK, static build check OK. Website plan sections 2.1,
  10 and 11 updated. No ERP code changed. Next: owner supplies ERP branch names + Cloudflare secrets,
  answers website plan questions 6–7 (palette, order); Phase 5 still needs a Flutter machine.
- **2026-10-23 — Claude (Opus 5.5) — Phase 4b re-skin (website repo).** Owner agreed to the plan's
  recommendations: Learning Center palette teal + lime, re-skin before School pages, School accent solid
  maroon. ICEBERG_WEB branch `feat/design-system-foundation` (stacked on `feat/erp-lead-forwarding`):
  `static/brand/tokens.json` + generated `tokens.css`, compiled Tailwind replaces the CDN script, Inter
  replaces Sora/Fraunces, `style.css` and page styles use `--brand-*`, `<html data-brand="center">`.
  All 7 LC pages: same URLs, copy and layout; before/after screenshots at 1280 px and 390 px checked.
  Build check now fails on the Tailwind CDN, missing `data-brand` or stale `tokens.css`. Flask tests OK,
  Node tests OK, static build check OK. Next: 4c School pages on the shared layout.
- **2026-10-23 — Claude (Opus 5.5) — Phase 4c/4d: one School-first website.** Owner: the site is mainly
  for Iceberg School; the Learning Center becomes a courses section. Website plan section 0 records the
  new URL structure. ICEBERG_WEB branch `feat/school-site` (stacked on `feat/design-system-foundation`):
  new `templates/site/*` (home with animated iceberg hero, about, programs, admissions + thanks, courses,
  news, contact, register), `static/css/site.css` (brand tokens only, mobile first), `site.js` (menu,
  dock, reveal), crest favicons/OG image, `config/school.json` placeholders, 301s for `/our_programs` and
  `/questions`, School enquiry through `/api/register` → Sheets → ERP (`source=school-website`,
  `program="Grade N"`, branch `SCHOOL_BRANCH_NAME`). Flask 18 tests OK, Node 25 OK, static build check OK;
  every page checked at 390 px and 1280 px. Next: owner fills School facts and reviews copy; deploy.
- **2026-10-23 — Claude (Opus 5.5) — Website design pass (website repo).** Owner asked for more warmth:
  cream/paper backgrounds, gold accents (new `tokens.json` school keys `gold`, `goldInk`, `goldSoft`,
  `cream`, `paper`), Fraunces serif headings on the website only, light heroes with curved edges, team
  and leader photos, word-rise headline, card hover, course marquee, page view transitions. Home hero
  shows the owner's school poster uncropped ("ICEBERG MAKTABI"); About page has the leader's welcome
  (name/role/message placeholders in `config/school.json`). Programs hero: the crest mountain drawing
  itself with the grade stages as the way up. Website PRs opened stacked: `feat/erp-lead-forwarding` →
  `feat/design-system-foundation` → `feat/school-site`. Open owner items: School facts and leader text in
  `config/school.json`, "Iceberg Maktabi" vs "Iceberg School" naming in Uzbek copy, Cloudflare secrets,
  Apps Script redeploy, ERP branch names; Phase 5 (Flutter) still needs `flutter analyze`/`test`.
- **2026-10-23 — Claude (Opus 5.5) — Phase 5 verified.** Installed Flutter 3.47.7 in the session container
  (not the repo). On `feat/school-brand-phase-5`: `flutter analyze` 0 errors/warnings (13 `deprecated_member_use`
  infos in pre-existing screens: `cacheExtent`, `value`), `flutter test` OK (only a placeholder test exists),
  `flutter build web --release` compiles. Django CI suite: ruff/format clean, `check` clean, no pending
  migrations, collectstatic OK, **186 tests OK**. No code changed.
- **2026-10-23 — Claude (Opus 5.5) — Website material moved out of this repo.** Owner: website designs
  belong in the website repo. Removed `docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md`,
  `docs/plans/ICEBERG_WEBSITE_AGENTS.md` and the website-only tokens (gold, goldInk, goldSoft, cream,
  paper, Fraunces) from `docs/brand/iceberg-school/tokens.json`. They now live only in
  [ICEBERG_WEB](https://github.com/Jahongir359/ICEBERG_WEB) (`docs/plans/`, `AGENTS.md`, `static/brand/tokens.json`). Older log entries
  above mention those files by their former paths here.

