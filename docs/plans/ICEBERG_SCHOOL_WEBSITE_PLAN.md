# Iceberg School Website — Decision and Build Plan

Document date: 2026-10-23 (revised the same day — see section 1)
Status: **Decided — build the School pages inside the existing iceberglc.com website codebase, and
move that site onto the shared Iceberg design system (owner OK'd changing its design and code).
Codebase found: **`Jahongir359/ICEBERG_WEB`** (Flask templates rendered to static HTML on Cloudflare
Pages). Phase 4b started there on 2026-10-23 — see section 2.1 and the checklist.**
Owner: Jahongir
Related: [`ICEBERG_SCHOOL_BRAND_PLAN.md`](ICEBERG_SCHOOL_BRAND_PLAN.md) (ERP side, Phases 1–6). This
document defines **Phase 4** and replaces that plan's section 8 (Django-hosted site — not built).
Design reference (canvas, private to the owner): https://claude.ai/artifact/9KE5AjoJ59UQJu22Z656gB

Written so any AI agent or developer can execute it without prior context. When work starts in the
website repo, copy [`ICEBERG_WEBSITE_AGENTS.md`](ICEBERG_WEBSITE_AGENTS.md) into it as its `AGENTS.md`
(and this plan into its `docs/`) — that file is the website agent's short guide and points back here.

---

## 1. Decision

**Where does the Iceberg School public website live?**
→ **In the existing iceberglc.com website codebase**, under the URL prefix **`/school/`**.

History: the first version of this plan recommended a brand-new repo (`iceberg-website`) routed in
with a Cloudflare Worker, because we could not find the iceberglc.com code. The owner then confirmed
(2026-10-23) that **they run the iceberglc.com domain and its code**. With that, adding the School to
the existing site is clearly better:

| | **Add to the existing iceberglc.com code** (chosen) | New separate repo (fallback, appendix A) | Inside this ERP repo (rejected) |
|---|---|---|---|
| URL | `iceberglc.com/school/…` | `iceberglc.com/school/…` via a Worker | `app.iceberglc.com/school/…` |
| Extra infrastructure | **None** | Cloudflare Pages project + Worker route | None |
| Search | Best: same site, internal links from the LC pages, one sitemap | Good, but the LC site still has to link in | Weakest (app subdomain) |
| Lead form | **Reuse the site's existing `/api/register` flow** (Turnstile, UTM, Telegram fallback) | Rebuild the same thing | Direct DB |
| Deploys | One website deploy for both brands | Two website deploys | Every text change = ERP deploy |
| Risk to the ERP | None | None | High |

Rejected for the ERP repo: wrong subdomain for search, couples marketing edits to ERP deploys, and
adds public pages to the app holding student data.

## 2. What we know about the existing site (observed from the live site, 2026-10-23)

These are observations from outside. **Verify each against the real code before building.**

| Observation | Detail |
|---|---|
| Domain / proxy | `iceberglc.com`, Cloudflare in front (`server: cloudflare`) |
| Pages | `/`, `/about`, `/our_programs`, `/news`, `/questions`, `/contact`, `/register`; custom Uzbek 404 page (`Sahifa topilmadi \| ICEBERG`, `noindex`) |
| Rendering | Server-rendered HTML, `lang="uz"`; assets under `/static/` (`/static/css/style.css`, `/static/img/logo2.png`) |
| CSS / icons | Tailwind via `https://cdn.tailwindcss.com` (the CDN "play" build), Font Awesome 6.4 from cdnjs |
| Languages | UZ/RU/EN switcher uses the **Google Translate widget** — only the Uzbek HTML exists for search engines |
| SEO | `<title>`, description, `robots: index, follow`, canonical, OG/Twitter, JSON-LD `WebSite`, `robots.txt` (disallows `/admin`, `/portal`, `/students`, `/contacts_list`; `Sitemap: https://iceberglc.com/sitemap.xml`), `sitemap.xml` with the 7 pages |
| Brand on the LC site | theme-color `#0d2a50`, OG name "ICEBERG O'quv Markazi", **Namangan** |
| Lead form | `/register`: `<form action="/api/register" method="post" data-static-lead-form="register" data-turnstile-sitekey="…" data-telegram-url="https://t.me/iceberg_qabulxona">` with fields `student_name`, `student_phone`, `course` (ielts, english, sat, mathematics, chemistry, biology), `preferred_branch` (`main` "Asosiy filial", `gayrat` "G'ayrat filiali", `unknown`), `utm_source`, `utm_medium`, `utm_campaign`. `GET /api/register` → 405 (POST only). |
| Other paths | `/admin`, `/portal`, `/students`, `/contacts_list` exist behind robots disallow (the site has its own admin) |

### 2.1 Confirmed from the code (`Jahongir359/ICEBERG_WEB`, 2026-10-23)

- **Framework:** Flask (`app.py`) + Jinja templates. The live site is **static HTML** rendered from those
  templates by `scripts/build_firebase.py` and served by **Cloudflare Pages** (`wrangler.toml`, build
  `scripts/build_cloudflare.sh`). Flask itself (SQLite admin, Telegram) runs only on an alternative host,
  if at all — Railway/Render/DigitalOcean/Firebase recipes all exist; the owner must confirm.
- **`/api/register` is a Cloudflare Pages Function** (`functions/api/register.js`): Turnstile → **Google
  Sheets via Apps Script** (`google-apps-script/Code.gs`). It did **not** call the ERP at all — the
  earlier guess was wrong. Only the Flask `/register` route posts to the ERP (`REGISTRATION_LEADS_API_URL`).
  So Learning Center website leads have not been reaching the ERP from the live site.
- **Fixed in 4b (branch `feat/erp-lead-forwarding` in ICEBERG_WEB):** after Sheets stores a lead, the
  function also posts it to the ERP receiver when the Cloudflare secrets `REGISTRATION_LEADS_API_URL` and
  `REGISTRATION_LEADS_API_TOKEN` are set (best-effort, 8 s timeout, no redirects, never fails the
  visitor; Sheets duplicates are not re-sent). Branch codes map to ERP names through `erp_branch_name` in
  `config/registration.json` (empty until the owner supplies the names → the code is sent;
  `unknown` → empty). The Flask route uses the same mapping.
- Programs/branches live in `config/registration.json`; the site's guide is its root `AGENTS.md`.

### ⚠ Check this now (affects the Learning Center today)

The ERP shows a lead to a **branch admin** only when `lead.branch` equals one of their branch
**names** (case-insensitive; `branching.filter_registration_leads_for_user`). The form sends codes
(`main`, `gayrat`, `unknown`). Unless `/api/register` translates them into the exact ERP branch names,
**branch admins never see website leads — only super admins do.** Fix in the website handler: map each
code to the exact ERP branch name (keep the map in one config object), and send `unknown` as empty.

## 3. Target shape

```
iceberglc.com/                 Learning Center pages (unchanged, + a link to the School)
iceberglc.com/school/          Iceberg School home
iceberglc.com/school/about     About
iceberglc.com/school/programs  Primary / Middle / High
iceberglc.com/school/admissions        4 steps + enquiry form + tuition + FAQ
iceberglc.com/school/admissions/thanks after a successful enquiry
iceberglc.com/school/news      (optional at launch)
iceberglc.com/school/contact   address, map, phone, Telegram

POST iceberglc.com/api/register   (existing) — accepts the School form too (section 6)
        └─▶ app.iceberglc.com/public/registration-leads/  (ERP, existing)
              └─▶ RegistrationLead(source="school-website", branch="<ERP School branch name>")

"Portal login" on School pages ─▶ https://app.iceberglc.com/login/?brand=school   (ERP Phase 3, done)
```

Follow the site's existing URL style (it uses no trailing slash: `/about`, `/our_programs`). Use
`/school` + `/school/<page>` in the same style; make `/school/` redirect to `/school` (or the
reverse) so only one URL is indexed.

## 4. How to build it inside the existing codebase

**Owner direction (2026-10-23): the iceberglc.com design and code may be changed to fit this plan.**
So the website does not just bolt School pages on — it moves to the **same Iceberg design system as
the ERP**: one set of components and layouts, Inter, the shared radii, and a brand layer chosen by
`<html data-brand="center|school">` exactly like the ERP (`brand-school.css` pattern). Learning Center
pages render with `data-brand="center"`, School pages with `data-brand="school"`.

### 4.0 Website foundation (do first, before School pages)

1. **Real CSS build.** Replace the Tailwind CDN "play" script with either a proper Tailwind build
   (config `theme.extend.colors` generated from `tokens.json`, colours referenced as CSS variables so
   `data-brand` can switch them) or plain CSS with custom properties. Same visual result, faster pages.
2. **Tokens.** One `/static/brand/tokens.css` generated from `tokens.json`:
   `html[data-brand="center"] { --brand-primary: …; … }` and
   `html[data-brand="school"] { --brand-primary: #4C0909; … }`. Components use only `var(--brand-*)`.
3. **Shared layout + components.** One base layout that takes `brand` (name, logos, nav, footer,
   theme-color, JSON-LD, Portal-login URL); shared header, footer, buttons, cards, form fields, FAQ,
   steps, news cards. LC and School pages differ only in content and brand.
4. **Real languages.** Replace the Google Translate widget with real `/ru/…` and `/en/…` pages (or
   `?lang=` only if the framework can't route) plus `hreflang` — for both brands. Uzbek stays the
   default. Can ship Uzbek-only first and add translations page by page.
5. **Font.** Inter on all pages (matches the ERP and the app).
6. **Keep URLs.** Existing LC URLs (`/about`, `/our_programs`, …) must not change; if a page moves,
   add a 301 redirect. Keep `/register` and `/api/register` working throughout.

### 4.0.1 Learning Center palette — owner decision needed

The Learning Center has three palettes today: the website (navy `#0d2a50`, blue `#3ba3ff`), the ERP's
`iceberg.css` (teal `#06343A`, lime `#DFFF2F` — what `tokens.json` "center" holds), and many ERP
templates (navy `#0C1F45`, cyan `#06B6D4`). Pick **one** for "center":
- **Teal + lime** (ERP design-system tokens; the canvas "One system, two brands" board), or
- **Navy + blue** (what website visitors know today) — then update `tokens.json` "center" and the ERP
  follows during Phase 2-style cleanup.
Until decided, the website keeps its current LC colours and only the School uses the new tokens.

### 4.1 School pages

Adapt to the real framework once the code is visible. Build these on top of the 4.0 foundation.

1. **Shared layout, School brand.** School pages use the shared base layout from 4.0 with
   `brand = school` (`<html data-brand="school">`): School name, logos, nav, footer, theme-color
   `#4C0909`, JSON-LD and Portal-login URL come from the brand object, never from LC values. Put
   School page templates in their own folder (e.g. `templates/school/` or `pages/school/`).
   *If the owner wants the School live before 4.0 is finished:* a temporary `school` layout that
   reuses only the plumbing (static files, analytics, Turnstile, 404) is acceptable, but it must use
   the same component markup and `var(--brand-*)` names so it folds into the shared layout later.
2. **Brand values from `tokens.json`.** Copy `docs/brand/iceberg-school/tokens.json` (this ERP repo
   is the source of truth) to `/static/brand/tokens.json` and generate `/static/brand/tokens.css` from
   it (4.0 step 2). Copy the logo crops from `docs/brand/iceberg-school/web/` into
   `/static/school/img/`. Never hard-code hexes in templates or page CSS — only `var(--brand-*)`.
3. **Typography.** **Inter** on every page (4.0 step 5), self-hosted or from Google Fonts with
   `display=swap`.
4. **CSS.** Use the 4.0 build. School-only styles (if any) go in `/static/school/css/school.css` and
   still use only `var(--brand-*)`. Never add a second Tailwind CDN script.
5. **Pages and content** — from the canvas design:
   - *Header:* maroon bar, `logo-h-white.png`, nav (About, Programs, Admissions, News, Contact),
     language switcher, **Portal login** → `https://app.iceberglc.com/login/?brand=school`.
   - *Home:* hero "What you see is the tip. We build what lies beneath." (translate to Uzbek
     first), Apply + Book a tour; three pillars from the crest (Aim high — mountain, Grow whole —
     child, Read deeply — book); Primary / Middle / High cards; key numbers (placeholders until the
     owner confirms); "School life in your pocket" app section (link to
     `https://app.iceberglc.com/download/`); news; admissions CTA band.
   - *Admissions:* 4 steps (Enquiry → Visit → Assessment → Offer), enquiry form (section 6), tuition
     panel, FAQ.
   - *Footer:* address, phone, Telegram/Instagram, links, "Part of the Iceberg family · Iceberg
     Learning Center" → `/`.
   - Any `[BRACKETED]` text in the design is a placeholder. **Never invent** grades, prices, numbers
     or results — leave visible placeholders until the owner supplies them.
6. **Link the brands together.** Add an "Iceberg School" link to the LC header or footer (this
   internal link matters for search) and "Iceberg Learning Center" on School pages. No automatic
   redirects between brands.
7. **Languages.** Same scheme as 4.0 step 4. Launch with **real Uzbek pages**; add real Russian and
   English pages with `hreflang` when the translations exist (use the same URL pattern as the LC pages,
   e.g. `/ru/school/…` if LC uses `/ru/about`). Until then the Google Translate widget may stay for
   visitors. Owner to confirm (section 11).

## 5. Search setup (people searching "Iceberg School" land on School pages)

On every School page:
- `<title>` and `<meta name="description">` unique per page and School-specific, e.g.
  `Iceberg School — xususiy maktab, Namangan | [1–11]-sinflar` (confirm wording with the owner).
- One `<h1>` containing "Iceberg School".
- `<link rel="canonical" href="https://iceberglc.com/school/…">`.
- OG/Twitter tags: `og:site_name` "Iceberg School", School `og:image` (1200×630, white horizontal logo
  on `#4C0909`; save as `/static/school/img/og-image.png`), theme-color `#4C0909`, crest favicon.
- JSON-LD:
  ```json
  {"@context":"https://schema.org","@type":"School","name":"Iceberg School",
   "url":"https://iceberglc.com/school","logo":"https://iceberglc.com/static/school/img/logo-v-maroon.png",
   "address":{"@type":"PostalAddress","streetAddress":"[ADDRESS]","addressLocality":"Namangan","addressCountry":"UZ"},
   "telephone":"[PHONE]","sameAs":["[INSTAGRAM]","[TELEGRAM]"],
   "parentOrganization":{"@type":"Organization","name":"ICEBERG","url":"https://iceberglc.com"}}
  ```
  (Optionally give the LC home page its own `EducationalOrganization` block alongside the existing
  `WebSite` block, so the two institutions are clearly separate entities.)

Site-wide:
- Add every public School URL to `sitemap.xml` (the existing `robots.txt` already points to it).
- Keep School admin/private paths out of the sitemap and under the existing robots disallows.
- Owner: in Google Search Console, re-submit the sitemap and use URL Inspection on `/school`;
  create a separate **Google Business Profile** for Iceberg School with website
  `https://iceberglc.com/school`; use that URL in School social bios and ads.

## 6. Enquiry form → ERP (reuse `/api/register`)

Reuse the existing handler instead of building a second one — it already has Turnstile, UTM capture
and the Telegram fallback. Add a form type:

- School form markup: same `action="/api/register"`, same Turnstile sitekey, but
  `data-static-lead-form="school-enquiry"` and a hidden `form_type=school-enquiry` field.
- Fields: `parent_name` (required), `parent_phone` (required, `+998…`), `child_name`,
  `child_birth_date`, `grade` (1–11 select), `language` (uz/ru/en), `message`, `consent` (required
  checkbox), honeypot (hidden, must stay empty), `utm_*` (existing hidden fields).
- In the handler, when `form_type == "school-enquiry"` build this JSON for the ERP:

| JSON key → ERP | Value |
|---|---|
| `full_name` | parent's name |
| `phone` | parent's phone (normalised `+998XXXXXXXXX`) |
| `program` | `"Grade " + grade` |
| `branch` | **exact ERP School branch name** from config (`SCHOOL_BRANCH_NAME`) |
| `source` | `"school-website"` |
| `message` | `"Child: <name> · DOB: <date> · Language: <uz/ru/en>\n<message>"` |
| `utm_source`, `utm_medium`, `utm_campaign` | pass through |
| `referrer` | the School page URL |

- Headers: `Authorization: Bearer <REGISTRATION_LEADS_API_TOKEN>` (server-side secret only — never in
  page JavaScript).
- ERP replies `201 {"status":"ok","lead_id":n}` → redirect to `/school/admissions/thanks`; `400` → show
  form errors; `401`/5xx/network → log, keep the visitor's input, show the phone + Telegram fallback
  (the existing `data-telegram-url` pattern). Rate-limit the endpoint with a Cloudflare rule
  (e.g. 5 POSTs / 10 min / IP) if it isn't already.
- Result in the ERP: the lead appears in **Registration leads** with source `school-website`, visible to
  super admins and to admins of the School branch.

## 7. ERP-side work (this repo) — Phase 4a

1. **Harden the lead receiver.** Today, if `REGISTRATION_LEADS_API_TOKEN` is empty, the endpoint
   accepts unauthenticated posts. When `DEBUG` is off and the token is empty → respond `503` and log an
   error. Add a test. Confirm production has a strong token (owner).
2. **Create the School branch** in the ERP (Manage Branches → brand "Iceberg School"). Its exact
   name is the website's `SCHOOL_BRANCH_NAME`.
3. **Confirm LC branch names** match what the website sends (section 2 warning) — list the ERP
   branch names so the website's code→name map can be written.
4. No `/school/` routes in the ERP and no `LoginCheckMiddleWare` change.

## 8. Shared brand between the two repos

| Asset | Source of truth (this repo) | Copy in the website |
|---|---|---|
| Colours, font, radii (both brands) | `docs/brand/iceberg-school/tokens.json` | `/static/brand/tokens.json` → generated `/static/brand/tokens.css` |
| School logos | `docs/brand/iceberg-school/web/*.png` (originals in `original/`) | `/static/school/img/` |
| Design | canvas (link at top), ERP brand plan section 5 | — |

When a brand value changes: update `tokens.json` here, then copy it to the website.

## 9. Verification before launch

- Every School page: 200, one `<h1>`, unique title/description, canonical, OG, JSON-LD validates in
  Google's Rich Results Test.
- Lighthouse (mobile) on `/school` and `/school/admissions`: Performance ≥ 90, SEO = 100,
  Accessibility ≥ 95.
- Enquiry end-to-end on staging/preview: submit → lead in ERP with `source = school-website`, correct
  `program`, visible to a School branch admin; failure path shows the phone/Telegram fallback.
- LC pages: same URLs, same copy, same SEO tags (title, description, canonical, JSON-LD); visual
  changes only from the agreed re-skin (before/after screenshots of every LC page, desktop + 390 px,
  shown to the owner). `/register` still works and LC leads still arrive.
- `sitemap.xml` lists School URLs; `robots.txt` unchanged.
- Phone width (390 px) and desktop checked; no horizontal scroll.

## 10. Phases and checklist (Phase 4 of the brand plan)

**4a — ERP (this repo)**
- [x] Lead receiver refuses requests (503 + error log) when the token is unset outside DEBUG; deploy
      check `main_app.W002`; tests (branch `feat/school-brand-phase-4a`).
      **Before deploying it: confirm production has `REGISTRATION_LEADS_API_TOKEN` set** (otherwise
      Learning Center website leads would start failing).
- [ ] School branch created; exact name → `SCHOOL_BRANCH_NAME`
- [ ] LC branch names listed for the website's code→name map

**4b — Website: foundations (iceberglc.com repo)**
- [x] Read the code; confirm section 2 observations; record the framework/hosting in the repo's
      `AGENTS.md` (section 2.1; ICEBERG_WEB `AGENTS.md` + `CLAUDE.md` + copy of this plan)
- [x] `/api/register` copies leads to the ERP + branch code→name mapping (section 2.1)
- [ ] Owner: set the two Cloudflare secrets, fill `erp_branch_name`, redeploy Apps Script
      (receiver `2026-10-23.1` reports duplicates)
- [ ] Owner picks the Learning Center palette (4.0.1); update `tokens.json` if needed
- [ ] 4.0 foundation: real CSS build, `tokens.css` with `data-brand`, shared layout/components,
      Inter — LC pages re-skinned with no URL changes (screenshot each LC page before/after)
- [ ] Real `/ru/`, `/en/` pages + `hreflang` (can follow launch)
- [ ] School logos/favicons/OG image in `/static/school/`

**4c — Website: School pages**
- [ ] Home, About, Programs, Admissions (+ thanks), Contact; News optional
- [ ] Uzbek copy first; placeholders for unknown facts
- [ ] Links: LC → School and School → LC; Portal login → `app.iceberglc.com/login/?brand=school`

**4d — Website: enquiry**
- [ ] `school-enquiry` form + handler branch in `/api/register` (section 6)
- [ ] `SCHOOL_BRANCH_NAME` in the website's config/secrets
- [ ] End-to-end test into the ERP

**4e — Search + launch**
- [ ] Section 5 on every page; sitemap updated
- [ ] Section 9 checks pass
- [ ] Deploy; Search Console + Google Business Profile (owner)
- [ ] ERP `SCHOOL_BRAND_ENABLED=True` once Phases 2–3 are merged (so "Portal login" shows the School look)

## 11. What the agent needs from the owner

1. ~~**Access to the iceberglc.com code**~~ **Found: `Jahongir359/ICEBERG_WEB`.** — the GitHub repo URL (and add the agent's account), or clone
   it into this codespace next to `College-ERP` (e.g. `/workspaces/iceberglc-website`).
2. ~~How it is hosted~~ **Cloudflare Pages; secrets in Pages settings (section 2.1).** Still open: is any
   Flask host (Railway/Render/DigitalOcean) live, or can those recipes be retired? Where its secrets live
   (`REGISTRATION_LEADS_API_TOKEN`, Turnstile secret).
3. School facts: address (Namangan?), grades, phone, Telegram/Instagram, tuition, founding year,
   photos.
4. Languages at launch: Uzbek only first, then real Russian/English pages (recommended), or keep the
   Google Translate widget for now?
5. Exact ERP branch names (LC branches + the new School branch).
6. Learning Center palette for the shared design system: teal + lime, or the website's navy + blue
   (section 4.0.1)?
7. Order: re-skin the LC site first and then add the School (recommended — one design system from day
   one), or ship the School first on a temporary layout (4.1 point 1)?

## 12. Agent rules for working in the website repo

- The ERP is `College-ERP` (app.iceberglc.com). Never add ERP logic to the website and never call the
  ERP from browser JavaScript — only from the server-side form handler.
- Learning Center pages may be re-skinned onto the shared design system (4.0), but their URLs, copy
  and SEO tags stay; any moved URL gets a 301. Screenshot before/after and show the owner.
- Brand files in `/static/brand/` and `/static/school/img/` are copies — change them in the ERP repo.
- Every School page has the section 5 tags; every new string is in Uzbek first.
- Never invent facts; use `[PLACEHOLDER]` until the owner provides them.
- Secrets only in the hosting provider's settings, never in the repo.
- Commit/push only when the owner asks; branch first; messages `type(scope): summary`.

---

## Appendix A — Fallback: a separate `iceberg-website` repo

Use only if the School must be deployed independently of the LC site.

- Astro (static), Cloudflare Pages project `iceberg-website`, `base: "/school"`.
- Cloudflare Worker `school-router` on `iceberglc.com/school*` and `www.iceberglc.com/school*`:
  ```ts
  export default {
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const upstream = new URL(url.pathname + url.search, "https://iceberg-website.pages.dev");
      const response = await fetch(new Request(upstream, request));
      return new Response(response.body, response);
    },
  };
  ```
- `*.pages.dev` responses send `X-Robots-Tag: noindex`; canonicals point to `iceberglc.com/school/…`.
- Enquiry via a Pages Function `functions/school/api/enquiry.ts` doing section 6's mapping with the ERP
  token as a Pages secret, Turnstile + honeypot + rate-limit rule.
- LC site still needs the School link and a sitemap entry (`Sitemap:` line for
  `/school/sitemap-index.xml`).
