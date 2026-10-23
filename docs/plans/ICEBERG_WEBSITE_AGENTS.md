# AGENTS.md — guide for AI agents working on the iceberglc.com website

> **Template.** Lives in the ERP repo (`College-ERP/docs/plans/ICEBERG_WEBSITE_AGENTS.md`). Copy it into
> the root of the iceberglc.com website repo as `AGENTS.md` (and `CLAUDE.md` containing `@AGENTS.md`),
> copy `ICEBERG_SCHOOL_WEBSITE_PLAN.md` into that repo's `docs/plans/`, then fill in every `[TODO]`
> after reading the code. Delete this note once copied.

Read this first, then [`docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md`](docs/plans/ICEBERG_SCHOOL_WEBSITE_PLAN.md).

## What this site is

The public website for two brands on one domain:

| Brand | URLs | `data-brand` | Look |
|---|---|---|---|
| **ICEBERG Learning Center** (language/exam courses, Namangan) | `iceberglc.com/`, `/about`, `/our_programs`, `/news`, `/questions`, `/contact`, `/register` | `center` | palette per plan 4.0.1 |
| **Iceberg School** (private school) | `iceberglc.com/school`, `/school/about`, `/school/programs`, `/school/admissions`, `/school/admissions/thanks`, `/school/contact`, `/school/news` | `school` | maroon `#4C0909`, crest logo |

The staff/student portal is a separate app — the ERP at `app.iceberglc.com` (repo `College-ERP`).
This site only links to it (`https://app.iceberglc.com/login/?brand=school` from School pages) and
sends enquiries to it from the server.

## Active initiative

Move the site onto the shared Iceberg design system and add the School pages — plan section 10,
phases **4b → 4e**. Tick the checklist there and add a dated line to its progress notes each session.

## Stack and layout  `[TODO — fill in after reading the code]`

| Item | Value |
|---|---|
| Framework / language | `[TODO]` |
| Hosting / deploy | `[TODO]` (Cloudflare is in front of the domain) |
| Templates / pages folder | `[TODO]` |
| Static files | `/static/` (`[TODO]` folder in the repo) |
| Lead handler (`POST /api/register`) | `[TODO]` file |
| Secrets live in | `[TODO]` (hosting provider settings — never in the repo) |

## Commands  `[TODO]`

```bash
# install, run locally, build CSS, test, lint — fill in the real commands
```

All of them must pass before a commit.

## Brand rules

- **Brand files are copies.** Source of truth is the ERP repo: `docs/brand/iceberg-school/tokens.json`
  (colours/font/radii for both brands) and `docs/brand/iceberg-school/web/*.png` (School logos). Here
  they live in `/static/brand/tokens.json`, `/static/brand/tokens.css` (generated) and
  `/static/school/img/`. To change a colour, change `tokens.json` in the ERP repo first, then copy.
- Pages and components use only `var(--brand-*)` — no hex values in templates or page CSS.
- One shared base layout takes a `brand` (name, logos, nav, footer, theme-color, JSON-LD, Portal URL)
  and sets `<html data-brand="…">`. LC and School pages differ only in content and brand.
- Font: Inter on every page.
- No automatic redirects between brands; each links to the other (LC → "Iceberg School",
  School → "Part of the Iceberg family · Iceberg Learning Center").

## Content rules

- Uzbek first; Russian and English as real pages with `hreflang` (plan 4.0 step 4). No new string
  ships without its Uzbek text.
- **Never invent facts** — grades, prices, numbers, results, addresses, phones. Use a visible
  `[PLACEHOLDER]` until the owner supplies them.
- Every page: unique `<title>` and description, one `<h1>`, canonical on `https://iceberglc.com/…`,
  OG/Twitter tags, the right JSON-LD (School pages: `School`, plan section 5). Public URLs go in
  `sitemap.xml`; don't loosen `robots.txt`.
- Existing LC URLs never change; if a page must move, add a 301. `/register` and `/api/register`
  keep working throughout.

## Lead form → ERP

- Browser posts only to this site's `/api/register`. Only the server handler calls the ERP
  (`POST https://app.iceberglc.com/public/registration-leads/`, `Authorization: Bearer
  $REGISTRATION_LEADS_API_TOKEN`). Never call the ERP or expose the token from browser JavaScript.
- Branch codes from the LC form (`main`, `gayrat`) must be mapped to the **exact ERP branch names**
  in one config object; `unknown` → empty. Otherwise branch admins can't see the leads.
- School enquiries: `form_type=school-enquiry`, mapped as in plan section 6, `source="school-website"`,
  `branch=$SCHOOL_BRANCH_NAME`. Keep Turnstile, honeypot, UTM fields and the Telegram fallback.

## Working conventions

- Small, focused changes; match the surrounding code style; don't reformat untouched files.
- Screenshot every LC page before and after the re-skin (desktop and 390 px) and show the owner.
- Before a release, run plan section 9 (Lighthouse, Rich Results, end-to-end enquiry into the ERP).
- Commit messages: `type(scope): summary` — e.g. `feat(school): add admissions page`,
  `fix(leads): map branch codes to ERP names`, `style(brand): generate tokens.css`.
- Commit or push only when the owner asks; branch off the main branch first.
- Secrets only in the hosting provider's settings; never commit real values.
