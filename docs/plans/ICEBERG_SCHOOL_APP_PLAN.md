# Iceberg School App — Build Plan, Task Checklist and Agent Guide

Make the ERP and the Flutter app work for **Iceberg School** (private school, grades 1–11) next to the
**Iceberg Study Center** (the existing Learning Center), in **one app** on Google Play and the App
Store, with little to no errors.

This plan continues [`ICEBERG_SCHOOL_BRAND_PLAN.md`](ICEBERG_SCHOOL_BRAND_PLAN.md) (brand layer,
phases 1–5, done). That plan covers *how School looks*; this plan covers *what School does*.

---

## 0. How to use this plan (read first — every agent, every session)

1. Read `AGENTS.md`, then this section, then the **Status board** (section 1).
2. **Trust ticks.** A task marked `[x]` was finished, merged and verified as described in section 0.2.
   Do **not** re-check or redo it. Only reopen a `[x]` task if your own change breaks it or you can
   show it is broken (then follow 0.3).
3. Pick the **first open task in the earliest open phase** whose "Needs" are all `[x]`. Tasks inside
   a phase may run in parallel only when their "Needs" allow it.
4. **Claim** it before starting: change `[ ]` to `[~]` and add `— claimed YYYY-MM-DD, branch <name>`.
   Commit and push that one-line change first, so no other agent starts the same task. A claim older
   than 3 days with no linked PR may be taken over (say so in the Progress log).
5. Do the work on its own branch off `main` (`feat/school-<task-id>-<slug>`), one task per PR where
   possible. Small tasks in the same phase may share a PR; tick each one separately.
6. Before opening the PR, meet the **Definition of done** (0.1) and run the task's **Verify** steps.
7. In the **same PR**, mark the task done (0.2), update the Status board and add a Progress log line.
8. If a task needs an owner decision that is still open in section 2, stop and ask the owner; do not
   guess. Record the answer in section 2 with the date.

### 0.1 Definition of done (applies to every task)

A task is done only when **all** of these hold:

- [ ] The task's own **Done when** list is met and its **Verify** steps pass.
- [ ] Backend checks pass (run from `backend/`, same as CI):
      `python -m ruff check .` · `python -m ruff format --check .` · `python manage.py check` ·
      `python manage.py makemigrations --check --dry-run` · `python manage.py collectstatic --noinput --dry-run -v 0` ·
      `python manage.py test` (full suite, not only the new tests).
- [ ] App checks pass when `mobile/` changed (from `mobile/iceberg_app/`, Flutter **3.47.7**):
      `flutter analyze --no-fatal-infos` (0 errors, 0 warnings) · `flutter test` ·
      `flutter build web --release --base-href /app/`.
- [ ] **Tests added** for the new behaviour, including **access tests** for every new endpoint or
      page: the right role gets it, every other role and another branch's user gets 403/404, and a
      parent never sees another family's child (section 6.2).
- [ ] Branch scoping goes through `backend/main_app/branching.py` only (new `filter_*`/`user_can_*`
      helpers there). No inline branch filters in views, serializers or forms.
- [ ] Migrations are **additive** and generated with `makemigrations` (new models, new nullable or
      defaulted fields). No renames, no drops, no data loss. A data migration, if any, is reversible.
- [ ] Learning Center unchanged: the existing suite passes, and Study Center users see no new School
      screens, wording or fields.
- [ ] Every new user-facing string exists in **Uzbek, Russian and English** (web templates and
      `mobile/iceberg_app/lib/core/i18n/strings.dart`).
- [ ] Docs updated where behaviour changed (this plan; `docs/DEPLOYMENT.md` for env vars;
      `.env.example` for new settings).
- [ ] CI green on the PR (Django CI and Flutter CI). The "Workers Builds: college-erp" check is a
      known Cloudflare misconfiguration (task P0.3) and does not block.

### 0.2 How to mark a task done

In the PR that completes the task, change the line to:

```
- [x] **S1.2** Classes on groups — done 2026-11-02, PR #41; verified: full suite 214 OK, access tests ClassAccessTests
```

- Use the date the PR is merged (or opened, then correct it after merge if it changed).
- Name the PR and the test classes or commands that prove it.
- Update the phase line in the Status board (`3/6 done`) and, when the last task of a phase is ticked,
  set the phase to **Done** with the date.
- Add one line to the Progress log (section 9): date, task IDs, PR, anything the next agent must know.

### 0.3 If a done task turns out broken

Change `[x]` back to `[ ]`, append `— reopened YYYY-MM-DD: <what is broken, how to reproduce>`, and log
it. Fix it like any other task. Never silently "fix" another task's code without reopening it.

### 0.4 Legend

`[ ]` open · `[~]` claimed / in progress · `[x]` done (see 0.2) · `[-]` dropped (with reason) ·
**Owner** = needs the owner (not code) · **Needs** = tasks that must be `[x]` first.

---

## 1. Status board

| Phase | What | Status |
|---|---|---|
| P0 | Foundations: hosting, domain, open PRs merged, staging | Open — 0/7 |
| P1 | ERP school data model: years and quarters, classes, subjects, parents | Open — 0/8 |
| P2 | ERP school features: timetable, register, gradebook, parent messages, push | Open — 0/8 |
| P3 | Web screens for admins and teachers | Open — 0/6 |
| P4 | App: choice screen, parent role, School screens | Open — 0/10 |
| P5 | Store readiness (Android and iPhone builds, listings, policies) | Open — 0/9 |
| P6 | Pilot and quality | Open — 0/6 |
| P7 | Release to Google Play and the App Store | Open — 0/5 |

**Release 1 (first store version)** = P0, P1, P2.1–P2.3 + P2.6–P2.8, P3.1–P3.4, P4 (without P4.7),
P5, P6, P7. **Release 2 (store update)** = gradebook (P2.4–P2.5, P3.5, P4.7) and report cards.
Owner decision D2 may move the gradebook into Release 1.

---

## 2. Decisions

| # | Decision | Status |
|---|---|---|
| D1 | **One app** for both. First screen asks: Iceberg School or Iceberg Study Center. The account's branch decides after login (section 5.1). | Decided 2026-10-23 (owner) |
| D2 | Attendance: **daily register** by the homeroom teacher in Release 1 (with arrival time); marks per lesson later. | Proposed — confirm with owner |
| D3 | Grades: marks **2–5** per subject per date, **quarter** (chorak) and **year** grades; report card later. | Proposed — confirm with owner |
| D4 | Parent is a **new role** `user_type "4"`, linked to one or more children; one login sees all their children (School and Study Center). | Proposed — confirm with owner |
| D5 | A school **class** (7-B) is a `Group` with `kind="class"`, so attendance, homework, chat and invoices keep working. | Proposed (technical) |
| D6 | The academic year reuses the existing `Session` model (add `name`, `is_current`); quarters are a new `Term` model. | Proposed (technical) |
| D7 | Choice-screen label for the Learning Center: "Iceberg Study Center" or "ICEBERG o'quv markazi"? | **Open — ask owner** |
| D8 | Store accounts: organisation (needs a free D-U-N-S number, 1–2 weeks) or personal? | **Open — ask owner** (recommend organisation) |
| D9 | Hosting for the ERP (DigitalOcean is stopped): Cloudflare Containers + Neon + R2, a VPS, or other. | **Open — ask owner** |
| D10 | Target date when parents start using the app (sets what moves to Release 2). | **Open — ask owner** |
| D11 | Who sees the leaderboard, vocabulary and flashcards: Study Center only (proposed), or School too? | Proposed — confirm with owner |

Record each answer here with the date before starting the task that depends on it.

---

## 3. Facts about the code today (verified 2026-10-23 on `feat/school-brand-phase-5`)

- **Roles**: `CustomUser.user_type` `"1"` admin, `"2"` staff, `"3"` student (`max_length=1`).
  `main_app/middleware.py` `LoginCheckMiddleWare` routes by role and **logs out any unknown
  `user_type`** — a parent role must be added there first (P1.5).
- **API** (`/api/v1/`, DRF + SimpleJWT): 83 routes in `main_app/api/urls.py`; permissions in
  `main_app/api/permissions.py` (`IsAdmin`, `IsTeacher`, `IsStudent`, `IsAdminOrTeacher`).
- **App ↔ API**: all 47 API paths the app calls exist (checked by resolving them with Django). The app
  serves students and staff; admins see a "coming soon" screen; there is no parent role.
- **Course model**: `Student.course` (one course), `Group` (course, teacher, branch, `room`, free-text
  `schedule`, `monthly_fee`), `Enrollment` (student ↔ group), `Subject` (course + one staff).
- **Attendance**: `Attendance` = one group + one date; `AttendanceReport` = student + status
  (absent, present, late). No time of arrival, no per-lesson marks.
- **Results**: `StudentResult` = one per student per group (`test` ≤ 40, `exam` ≤ 60). No gradebook.
- **Academic year**: `Session(start_year, end_year)` exists (admin endpoints `admin/sessions/`), no terms.
- **Payments**: `Invoice` (student, group, `period` = first day of month) and `Payment` — fit a school.
- **Chat**: `ChatThread` is one per group (students and teacher). No teacher ↔ parent threads.
- **Push**: `CustomUser.fcm_token` is stored (`api/v1/me/fcm-token/`), but sending was removed with the
  legacy FCM API (PR #26). In-app notifications work; phone push does not.
- **Brand**: `Branch.brand` (`center`/`school`), `main_app/branding.py`, flag `SCHOOL_BRAND_ENABLED`;
  app: `lib/core/theme/brand.dart`, `brand_provider.dart`. Time zone `Asia/Tashkent`.
- **App code**: 59 Dart files (~22k lines), `lib/core/router/app_router.dart`,
  `lib/features/{auth,staff,student}`, `lib/shared`. Largest file:
  `lib/features/staff/screens/staff_feature_screens.dart` (~2,200 lines). One placeholder test.
- **Open PRs at the time of writing**: #26 security fixes → #27 School brand (base #26) → #28 build
  cleanup (Docker builds the web app, CI split by area, download-page fix).

---

## 4. Architecture

### 4.1 Data model (P1, P2) — all additive

```
Session (academic year)   + name "2026–2027", is_current (one per branch at most)
Term (quarter)            session, number 1–4, name, start_date, end_date
Group                     + kind ("course" default | "class"), grade_level 1–11, letter "B",
                            session (FK, null), homeroom = existing `teacher`
ClassSubject              group(kind=class), subject, teacher (Staff), weekly_hours
Subject                   unchanged; school subjects belong to one "Iceberg School" Course per
                            school branch (created in P1.3), so Subject.course stays required
Parent (profile)          admin OneToOne CustomUser(user_type "4"), phone, relation
ParentChild               parent, student, relation ("mother", "father", "guardian"), is_primary
BellPeriod                branch, number, start_time, end_time
Lesson (timetable)        group(kind=class), weekday 1–6, period, class_subject, room, valid_from/to
AttendanceReport          + arrival_time (null), + note
Mark (gradebook)          student, class_subject, date, value 2–5, kind ("lesson","test","exam"), comment, given_by
TermGrade                 student, class_subject, term, value 2–5 (null = not graded), final for year = term NULL
ChatThread                + kind ("group" default | "parent"), + student (for parent threads)
```

Rules: a student is in **at most one active class per session** (DB constraint on Enrollment via
`group.kind`/session in `clean()` + a test). School objects live in a branch whose `brand="school"`.

### 4.2 Access rules (all in `branching.py`)

| Who | Sees |
|---|---|
| Super admin | everything |
| Branch admin | their branches' classes, timetables, marks, parents |
| Teacher | classes where they are homeroom teacher or teach a `ClassSubject`; marks only for their subjects; register only for homeroom classes |
| Student | own class, own timetable, own marks and attendance |
| Parent | **only their linked children's** data, read-only, plus messaging their children's teachers and paying invoices |

New helpers: `filter_classes_for_user`, `filter_marks_for_user`, `filter_lessons_for_user`,
`filter_parents_for_user`, `children_for_parent`, `user_can_access_student`.

### 4.3 API additions (P2–P4)

```
GET  me/                         + role "parent", children [{id, name, class, brand}]
GET  school/classes/             teacher/admin: my classes
GET  school/timetable/?student=  week view (student, parent with child id, teacher: own lessons)
GET  school/register/<group>/<date>/   POST same: homeroom teacher saves daily register
GET  school/marks/?student=&term=      POST school/marks/ teacher (own ClassSubject only)
GET  school/term-grades/?student=      POST teacher/admin
GET  school/calendar/                   current session, terms, holidays
GET  parent/children/                   parent: children + today summary
GET/POST messages/parent/<thread>/      teacher ↔ parent threads
```
Existing endpoints that parents also need (`assignments/`, `invoices/`, `notifications/`,
`student/attendance/summary/`) accept `?student=<id>` for parents, checked by `user_can_access_student`.

### 4.4 App structure (P4)

```
/choose            first launch: School | Study Center (sets LastBrandNotifier before login)
/login             branded by the choice; "change" link back to /choose
/parent/*          parent shell: child switcher + Home, Timetable, Attendance, Homework, Grades, Payments, Messages
/student/*         existing; School students get Timetable/Grades tabs, Study Center keeps Vocabulary/Leaderboard
/staff/*           existing; School teachers get Register, Gradebook, My classes
```

---

## 5. Product rules

### 5.1 The choice screen and the brand

- First launch shows two cards (School: maroon crest; Study Center: teal). The choice brands the
  login screen and is remembered.
- After login the **account decides**: the brand of the user's branch (a parent: of the selected
  child). If it differs from the choice, the app switches and shows one short notice. Nobody is stuck.
- A parent with children in both shows both in the child switcher; the theme follows the child.

### 5.2 What each brand shows

| Feature | School | Study Center |
|---|---|---|
| Timetable, register, gradebook, term grades | yes | no |
| Parent role | yes | yes (attendance, payments) |
| Vocabulary, flashcards, leaderboard | no (D11) | yes |
| Homework, payments, notifications, messages, library | yes | yes |

---

## 6. Quality rules ("little to no errors")

### 6.1 Every PR

- Small and single-purpose; never mix a feature with refactors elsewhere.
- Full checks of 0.1; screenshots of changed screens (phone width first) in the PR.

### 6.2 Access matrix tests (required for every new endpoint/page)

For each endpoint: admin (own branch) 200, admin (other branch) 403/404, teacher (own class) 200,
teacher (other class) 403/404, student (self) 200, student (other) 403/404, **parent (own child) 200,
parent (other child) 403/404**, anonymous 401. Write them as one table-driven test class per endpoint.

### 6.3 Data integrity

- DB constraints for: one active class per student per session; one register per class per date; one
  mark value 2–5; one term grade per student/subject/term; parent ↔ child unique.
- All dates in `Asia/Tashkent`; never compare naive datetimes.

### 6.4 App

- No screen without loading, empty and error states.
- Widget tests for every new screen and for the router redirects (choice → login → role shell).
- Crash reporting enabled before the pilot (P5.6).

---

## 7. Phases and task checklist

### P0 — Foundations

- [ ] **P0.1** **Owner** — Answer D7–D10 in section 2.
- [ ] **P0.2** Merge open PRs in order #26 → #27 → #28; resolve conflicts with merge commits.
      Done when: `main` contains all three; CI green on `main`. Needs: owner approval.
- [ ] **P0.3** **Owner** — In Cloudflare remove the `college-erp` Worker from `app.iceberglc.com`,
      disconnect its Git build and delete it; restore the `app` DNS record to the ERP host.
      Done when: `https://app.iceberglc.com/login/` shows the ERP login (not "Hello world").
- [ ] **P0.4** Deploy the ERP on the host chosen in D9 from the `Dockerfile` (#28): database, media
      storage (R2/Spaces), env vars per `docs/DEPLOYMENT.md`, `MIGRATE_ON_START` or pre-deploy job.
      Done when: `/login/`, `/app/`, `/download/`, `/api/v1/me/` (401) respond on the production URL;
      a test login works. Needs: P0.1 (D9), P0.2.
- [ ] **P0.5** A **staging** instance (same image, separate database) with `SCHOOL_BRAND_ENABLED=True`.
      Done when: staging URL works and is written in `docs/DEPLOYMENT.md`. Needs: P0.4.
- [ ] **P0.6** Demo data command `python manage.py seed_school_demo` (one school branch, classes 1-A,
      7-B, 11-A, teachers, students, parents, a week of timetable, marks, invoices). Re-runnable,
      refuses to run when `DEBUG=False` unless `--force`. Done when: command + test; staging seeded.
      Needs: P1.1–P1.6 (write it at the end of P1; tick it then).
- [ ] **P0.7** Backups: daily database backup with a tested restore, written in `docs/DEPLOYMENT.md`.
      Needs: P0.4.

### P1 — ERP school data model

- [ ] **P1.1** Academic year and quarters: `Session.name`, `Session.is_current`, `Term` model, admin
      CRUD in the existing session pages and `admin/sessions/` API. Done when: migration, model tests,
      only one current session per branch (constraint). Needs: P0.2.
- [ ] **P1.2** Classes on groups: `Group.kind`, `grade_level`, `letter`, `session` + validation (class
      needs grade 1–11 and letter; one active class per student per session). Course groups unchanged.
      Done when: migration, tests for both kinds, existing group pages still work for courses.
- [ ] **P1.3** School subjects per class: `ClassSubject`; one "Iceberg School" `Course` per school
      branch holds the school `Subject`s (seed the standard subject list as editable data). Done when: model, admin API, tests; a class lists its subjects and
      teachers.
- [ ] **P1.4** Parent model: `user_type "4"` (`USER_TYPE` choices), `Parent` profile, `ParentChild`
      link, post-save profile creation like other roles. Done when: migration, tests.
- [ ] **P1.5** Parent role everywhere it is checked: `LoginCheckMiddleWare` (parent allowed only on
      parent pages and the API), `api/permissions.py` `IsParent`, `branching.py` helpers
      (`children_for_parent`, `user_can_access_student`), login redirect. Done when: a parent can log
      in on web and API without being logged out; access tests (6.2) for existing student endpoints
      with `?student=`.
- [ ] **P1.6** `me/` and login response include `role` and `children` (id, name, class, branch brand).
      Done when: serializer + tests; Study Center responses unchanged except the new keys.
- [ ] **P1.7** Admin tools to create parents and link children: form + API + **CSV import** (parent
      name, phone, child login ID, relation) with a dry-run preview. Done when: tests incl. bad rows.
- [ ] **P1.8** Branch scoping review: every new queryset goes through `branching.py`; add the helpers
      of 4.2 with tests. Done when: `grep` shows no inline branch filters in the new code.

### P2 — ERP school features

- [ ] **P2.1** Bell periods and timetable: `BellPeriod`, `Lesson`, clash checks (teacher, room, class
      at the same period). Done when: models, validation tests, `school/timetable/` API for each role.
      Needs: P1.2, P1.3.
- [ ] **P2.2** Daily register: homeroom teacher marks present/absent/late with arrival time and note
      for a class and date; `school/register/` API; reuses `Attendance`/`AttendanceReport` (+ fields).
      Done when: tests incl. "only homeroom teacher of that class", one register per date. Needs: P1.2.
- [ ] **P2.3** Parent notification when a child is marked absent or late (in-app now; push after
      P2.8). Done when: test that exactly the linked parents get it.
- [ ] **P2.4** Gradebook: `Mark` (2–5) by subject teacher; `school/marks/` API. Done when: tests incl.
      teacher limited to own `ClassSubject`, values outside 2–5 rejected. Needs: P1.3. (Release 2 unless D2/D3 say otherwise.)
- [ ] **P2.5** Term and year grades: `TermGrade`, average helper (shown as a suggestion, teacher
      confirms). Done when: tests. Needs: P2.4, P1.1. (Release 2.)
- [ ] **P2.6** Teacher ↔ parent messaging: `ChatThread.kind="parent"` per student and teacher;
      reuses the chat UI and read states. Done when: access tests (parent only own child's threads).
- [ ] **P2.7** Parents can see and pay invoices of their children (existing invoice API with
      `?student=`); class announcements reach parents (stories/notifications target parents of a
      class). Done when: tests.
- [ ] **P2.8** Push notifications with FCM HTTP v1 (service-account credentials via env vars, never
      committed): send for notifications, absence, new message. Done when: unit tests with the sender
      mocked; a real push received on a test phone on staging; documented in `docs/DEPLOYMENT.md`.

### P3 — Web screens (admins and teachers)

- [ ] **P3.1** Admin: classes (create 7-B, homeroom teacher, students), subjects per class, current
      session and quarters. Needs: P1.1–P1.3.
- [ ] **P3.2** Admin: bell periods and timetable editor (week grid, clash errors shown inline).
      Needs: P2.1.
- [ ] **P3.3** Admin: parents list, link children, CSV import screen. Needs: P1.7.
- [ ] **P3.4** Teacher: daily register page for homeroom classes (phone-friendly). Needs: P2.2.
- [ ] **P3.5** Teacher: gradebook page (class × dates grid for one subject) and term grades. Needs:
      P2.4, P2.5. (Release 2.)
- [ ] **P3.6** All School pages branded (`data-brand="school"`), in uz/ru/en, screenshots at 390 px and
      desktop in the PR.

### P4 — App

- [ ] **P4.1** Split oversized files before adding features (`staff_feature_screens.dart` and any file
      over ~800 lines) — no behaviour change; analyze/test/build green. Do this first in P4.
- [ ] **P4.2** Choice screen `/choose` + router redirects (first launch → choose → login; change link
      on login) + widget tests for the redirects. Wording per D7.
- [ ] **P4.3** Brand from the account after login (5.1) incl. the one-time notice; tests.
- [ ] **P4.4** Parent shell with child switcher; Home shows today: attendance, lessons, homework due,
      unpaid invoice. Needs: P1.6.
- [ ] **P4.5** Timetable screen (student, parent, teacher views). Needs: P2.1.
- [ ] **P4.6** Teacher register screen (fast: everyone present by default, tap to change). Needs: P2.2.
- [ ] **P4.7** Grades screens (marks list, term grades) for student/parent; gradebook entry for
      teachers. Needs: P2.4, P2.5. (Release 2.)
- [ ] **P4.8** Parent: homework, payments, messages with teachers, notifications. Needs: P2.6, P2.7.
- [ ] **P4.9** Hide Study Center-only features for School users per D11 (navigation by brand).
- [ ] **P4.10** Strings for every new screen in uz/ru/en; empty, loading and error states; widget tests
      for each new screen.

### P5 — Store readiness

- [ ] **P5.1** **Owner** — Google Play developer account and Apple Developer Program (per D8);
      invite the build account; create the App Store Connect API key and Play service account.
- [ ] **P5.2** App identity: store name, final icons (School and Study Center both recognisable in one
      icon), splash, version scheme (`pubspec.yaml` `version`), bundle IDs kept
      (`uz.iceberg.iceberg_app` / `uz.iceberg.icebergApp`).
- [ ] **P5.3** Android release signing: upload keystore in GitHub secrets (never committed), CI job that
      builds a signed **AAB** on tags and uploads to Play internal testing. Done when: an AAB appears in
      Play Console internal testing from CI.
- [ ] **P5.4** iPhone build without a Mac: CI on a macOS runner (GitHub Actions or Codemagic) with
      automatic signing via the App Store Connect API key; uploads to TestFlight. Done when: a build
      appears in TestFlight from CI.
- [ ] **P5.5** Privacy policy and terms pages on iceberglc.com (repo ICEBERG_WEB) in uz/ru/en; links in
      the app and store listings; account-deletion request path (in-app link + web form) as stores
      require.
- [ ] **P5.6** Crash reporting (e.g. Firebase Crashlytics) and basic analytics off by default for
      children; documented.
- [ ] **P5.7** Store listings in uz/ru/en: description, screenshots (phone and tablet), category
      Education, content rating questionnaire, Google data-safety form, Apple privacy labels.
- [ ] **P5.8** Review accounts on production: one teacher, one student, one parent with demo data,
      written in the store review notes (not in the repo).
- [ ] **P5.9** Push setup on devices: Android notification permission (13+), iOS APNs key in Firebase.
      Needs: P2.8.

### P6 — Pilot and quality

- [ ] **P6.1** Written test scripts for admin, homeroom teacher, subject teacher, parent, student
      (`docs/plans/school_app_test_scripts.md`), each step with the expected result.
- [ ] **P6.2** Run the scripts on staging on a real Android phone and a real iPhone (via TestFlight);
      log every bug as a GitHub issue with steps.
- [ ] **P6.3** Pilot with a few real teachers and parents for at least one week on staging or
      production (owner chooses).
- [ ] **P6.4** Fix all blocker and major bugs from P6.2–P6.3; each fix with a regression test.
- [ ] **P6.5** Load check: 300 users opening Home within a minute — p95 under 1 s on the chosen host.
- [ ] **P6.6** **Owner** sign-off on the pilot.

### P7 — Release

- [ ] **P7.1** Google Play: internal → closed testing (12 testers for 14 days if the account is
      personal) → production.
- [ ] **P7.2** App Store: TestFlight → submit for review with review notes and demo accounts → release.
- [ ] **P7.3** Website: "Ilovani yuklab olish" links to the store pages (ICEBERG_WEB `config/school.json`
      `app_url` and the download page).
- [ ] **P7.4** Production `SCHOOL_BRAND_ENABLED=True`, school branch, classes, parents imported.
- [ ] **P7.5** First-week watch: crash-free rate, error logs, support messages; fixes released as
      updates.

---

## 8. Risks and how this plan handles them

| Risk | Handling |
|---|---|
| Parent sees another family's data | Access-matrix tests on every endpoint (6.2); all scoping in `branching.py` |
| New role logged out or blocked by old code | P1.5 updates middleware, permissions and redirects first, with tests |
| Learning Center breaks | Additive migrations; `kind="course"` default; full suite on every PR |
| Store rejection | Demo accounts, privacy policy, deletion path, complete listings (P5) before submitting |
| Server down during review or pilot | Hosting first (P0), backups (P0.7), staging separate from production |
| Two agents doing the same task | Claim protocol (section 0, step 4) |

---

## 9. Progress log

Newest first. One line per session: date — tasks — PR — note for the next agent.

- 2026-10-23 — plan written (no tasks started). Next: owner answers D2–D4, D7–D11; then P0.2.
