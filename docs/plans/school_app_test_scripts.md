# Iceberg School — test scripts (plan task P6.1)

Step-by-step checks for the five School roles: **admin**, **homeroom teacher**, **subject teacher**,
**parent** and **student**. Each step says what to do and what you should see. P6.2 runs these on
staging on a real Android phone and a real iPhone and logs every failed step as a GitHub issue
(title `P6.2: <script id> <step>`, with the steps, what you saw, a screenshot, phone and app version).

Written 2026-10-30 against `main` at `4d5ef6f` plus the open PRs. Update a step when its feature
changes.

## How to read the steps

Every step has a **status tag**. Run only the steps whose tag is ready; skip the others and note
"not built" in the run log.

| Tag | Meaning |
|---|---|
| *(none)* | On `main` now. Must pass. |
| **[PR #57]**, **[PR #58]** | Built in an open PR. Run once that PR is merged (or on a build of its branch). |
| **[P4.5]** etc. | Task not built yet. The expected result is the agreed design (plan section 6, mockup number given). |
| **[R2]** | Release 2 (marks and grades screens). The server side is on `main`; the app screens are not. |

Open PRs referenced: **#57** push notifications (P2.8), **#58** parent login letters and the
first-login password change (PL.1, draft until P4.3 ships).

Run every script in **Uzbek**. Then repeat the steps marked 🌐 in **Russian** and **English** to
check the language: every label is translated, with no English left in uz/ru, and Uzbek uses the
letter ʻ (Oʻquvchilar, not O'quvchilar).

Messages in the Expected column are quoted in English, as in the code; in Uzbek or Russian you see
their translation (a message still in English there is a bug).

## Setup (once per staging database)

1. On the staging server (`DEBUG=False`):
   `python manage.py seed_school_demo --force` (add `--password <pw>` to use another password than
   `Demo12345!`). Expected output ends with `"Iceberg School (demo)" ready` and
   `Added: 6 teachers, 3 classes, 32 class subjects, 12 students, 12 parents, 13 parent links,
   4 quarters, 12 invoices, 4 payments, 6 bell periods, 70 timetable lessons.` Running it again adds
   nothing and changes no password.
2. `SCHOOL_BRAND_ENABLED=True` on staging.
3. The demo has **no admin login**. As a super admin, open **Admins** and add a branch admin
   (e.g. `qa-admin@demo.iceberg.internal`) with only the branch **Iceberg School (demo)**. Script A
   uses this branch admin unless a step says *super admin*.
4. Install the app on both phones from the staging build. When **[PR #57]** is merged, also do
   P5.9 (notification permission on Android 13+, APNs key for iOS).

### Demo accounts

All passwords are `Demo12345!` unless changed in step 1. Login IDs are typed exactly as shown.

| Role | Login | Who | Notes |
|---|---|---|---|
| Homeroom teacher | `DEMO-TC02` | Jasur Karimov | Homeroom **7-B**; teaches Algebra and Geometry in 7-B and 11-A |
| Homeroom teacher | `DEMO-TC01` | Nodira Usmonova | Homeroom **1-A** (most 1-A subjects) |
| Homeroom teacher | `DEMO-TC03` | Gulnora Rahimova | Homeroom **11-A**; Uzbek, literature, Russian in 7-B |
| Subject teacher | `DEMO-TC04` | Sardor Aliyev | English in 1-A, 7-B and 11-A; no class of his own |
| Subject teacher | `DEMO-TC05` | Dilfuza Tosheva | Sciences in 7-B and 11-A |
| Subject teacher | `DEMO-TC06` | Bekzod Yusupov | History, PE, informatics |
| Parent | `DEMO-PR01` | Dilnoza Karimova | **Two children**: Aziz (1-A) and Malika (7-B); main contact for both |
| Parent | `DEMO-PR02` | Rustam Karimov | Aziz's father, **not** main contact (Aziz has two parents) |
| Parent | `DEMO-PR08` | Akmal Saidov | Guardian of Otabek (7-B) |
| Student | `DEMO-IC05` | Malika Karimova | 7-B |
| Student | `DEMO-IC08` | Otabek Saidov | 7-B |
| Student | `DEMO-IC01` | Aziz Karimov | 1-A (4 lessons a day) |

Classes: **1-A** (Aziz, Madina, Temur, Sevara), **7-B** (Malika, Javohir, Shahzoda, Otabek),
**11-A** (Kamola, Doniyor, Nilufar, Sherzod). Bell times: 1) 08:00–08:45, 2) 08:55–09:40,
3) 09:50–10:35, 4) 10:55–11:40, 5) 11:50–12:35, 6) 12:45–13:30, Monday to Saturday. Quarters
2026–27: 1st 2 Sep–3 Nov, 2nd 10 Nov–26 Dec, 3rd 11 Jan–18 Mar, 4th 30 Mar–25 May (breaks between).

**Order matters:** run **A** (admin), then **T** (homeroom teacher), then **S** (subject teacher),
then **P** (parent), then **St** (student). P and St check what T and S saved. Note the date and time
of each register save in the run log.

---

## A — Admin (web ERP)

Admins work only on the web (D15). Desktop browser first, then repeat A1–A3 at phone width (390 px).

### A1 Sign-in, language, menu

| # | Do | Expected |
|---|---|---|
| A1.1 | Open the staging URL `/`. Switch the language to **UZ** on the sign-in page. | The sign-in page is in Uzbek. 🌐 |
| A1.2 | Sign in as the branch admin. | Dashboard opens in Uzbek (the choice is remembered on the account). The sidebar has a **Maktab** section: Sinflar, Dars jadvali, Qoʻngʻiroqlar, Ota-onalar, Oʻquv yili. |
| A1.3 | Sign out. Sign in as an admin of a Study Center branch only. | No **Maktab** section; the Study Center menu is unchanged. |
| A1.4 | Switch to **RU**, then **EN** in the header. | Menu and the current School page change language at once, and stay after sign-out and sign-in. 🌐 |

### A2 Classes (Sinflar), screen 16

| # | Do | Expected |
|---|---|---|
| A2.1 | **Maktab → Sinflar**. | Year 2026–2027. Rows 1-A (Nodira Usmonova), 7-B (Jasur Karimov), 11-A (Gulnora Rahimova), each with 4 pupils. Stats: 3 classes, 12 pupils, 12 pupils with a parent linked. No "CSV yuklash" button (Release 2). |
| A2.2 | Type `7` in the search box. | Only 7-B stays. |
| A2.3 | Open **7-B**. | Header shows the branch, year, homeroom teacher. Students: Malika, Javohir, Shahzoda, Otabek, each with a parents count. Subjects: 12, with teacher and hours a week; total hours shown. |
| A2.4 | Try to add **Madina Rasulova** (1-A) to 7-B. | Not possible: she is either not offered in the list or refused, because a pupil is in one class per year. |
| A2.5 | Create a new pupil in Oʻquvchilar for the demo branch, then add them to 7-B. | Added; the count goes to 5. |
| A2.6 | Remove that pupil from 7-B (confirm). | Gone from the list; count back to 4. |
| A2.7 | In 7-B, change **Ingliz tili** teacher from Sardor Aliyev to Jasur Karimov, Save. | Refused with "Jasur Karimov already teaches … at that time (…, period …)" if any English lesson in 7-B is at a time Jasur already teaches; otherwise saved. Put it back to Sardor Aliyev. |
| A2.8 | **Yangi sinf** → grade 7, letter B, demo branch. | Refused: 7-B already exists for this branch and year. |
| A2.9 | **Yangi sinf** → grade 5, letter A, homeroom Dilfuza Tosheva, Save. Then delete or leave it (note it in the log). | Class 5-A created, empty, opens its page. |
| A2.10 | Change the browser URL to the id of a class of **another branch** (ask a super admin for one). | 404 page. |

### A3 Academic year (Oʻquv yili)

| # | Do | Expected |
|---|---|---|
| A3.1 | As the **branch admin**, open **Oʻquv yili**. | 2026–2027 current, with 4 quarters and their dates. Read-only (no add or edit buttons). |
| A3.2 | As a **super admin**, add a 5th test quarter overlapping the 2nd. | Refused (overlap). Cancel. |
| A3.3 | As a super admin, edit 1-chorak's end date to 4 Nov and back to 3 Nov. | Saved both times. |

### A4 Bell times (Qoʻngʻiroqlar)

| # | Do | Expected |
|---|---|---|
| A4.1 | Open **Qoʻngʻiroqlar**. | The demo branch has periods 1–6 with the times listed in Setup. |
| A4.2 | Add period 7 at 13:20–14:05. | Refused: overlaps period 6. |
| A4.3 | Add period 7 at 13:40–14:25. | "Period 7 saved." |
| A4.4 | Delete period 1. | Refused: "Lessons use this period. Move or delete them first." |
| A4.5 | Delete period 7. | "Period 7 deleted." |

### A5 Timetable editor (Dars jadvali), screen 17

| # | Do | Expected |
|---|---|---|
| A5.1 | **Dars jadvali**, class **7-B**. | Grid Monday–Saturday × periods 1–6, each cell a subject (or empty). Under the grid, lessons a week per subject equal its hours (none red). |
| A5.2 | Find a cell where 11-A has **Algebra** (Jasur Karimov). In 7-B, put **Algebra** in the same day and period. Save. | Nothing is saved. "Nothing was saved: fix the red cells first." The cell is red and names the clash (teacher busy, 11-A). |
| A5.3 | Put the cell back. Change one 7-B lesson to another free subject, set **Changes apply from** to next Monday, Save. | "Timetable of 7-B saved." Hours-a-week under the grid turn red for the two changed subjects (one more, one less). |
| A5.4 | Undo A5.3 the same way (same date). | Saved; no red counts. |
| A5.5 | Set **Changes apply from** to a date outside 2026–27. | "The date must be inside the class's academic year." |

### A6 Parents (Ota-onalar), screens 18 and 18b

| # | Do | Expected |
|---|---|---|
| A6.1 | **Ota-onalar**. | 12 parents with login ID (DEMO-PR01…12), phone, children chips "Name · class"; ★ on the main contact. Dilnoza Karimova has **Aziz · 1-A** and **Malika · 7-B**, both ★; Rustam Karimov has Aziz · 1-A without ★. 🌐 |
| A6.2 | Search `Karim`, then `PR08`, then `01 02`. | 2 parents (Dilnoza, Rustam); Akmal Saidov; Rustam Karimov. |
| A6.3 | Class filter **7-B**. | Only parents with a child in 7-B (Dilnoza, Ulugʻbek, Mohira, Akmal). |
| A6.4 | Right panel **Yangi ota-ona**: name Test, surname Ota, phone `+998 00 000 09 99`, password `Test-pass-2026`, first child Otabek Saidov, Qarindoshlik Otasi, main contact ticked. Save. | Redirects to the new parent's page; message "Parent … created. Login ID: PR5xx". Otabek's main contact moves to the new parent (Akmal loses the ★). |
| A6.5 | Create another parent with phone `+998 00 000 01 08` (Akmal's). | Refused: "Parent DEMO-PR08 already uses this phone number…" (named because the admin can see him). |
| A6.6 | On the new parent's page change the surname, Save. | "Saved."; the password still works (sign in with it later in P1). |
| A6.7 | **Farzand ulash**: link Javohir Toshmatov as Vasiy. Then change his relation to Otasi and tick main contact, Save on that row. | Linked; then saved. Only one main contact per child. |
| A6.8 | **Uzish** Javohir (confirm). | Gone from the list; parent stays. |
| A6.9 | **Parolni tiklash** (confirm). | A green box shows a 10-character password **once**. Reload the page: it is gone. |
| A6.10 | Panel **Login ID orqali ulash** (list page): login `DEMO-PR03`, phone `+998 00 000 09 09`, child Sevara, Save. | Only "Parent not found. Check the login ID and the phone number." No name or data of PR03. |
| A6.11 | Same with the right phone `+998 00 000 01 03`. | Linked; opens Zarina Rasulova's page with Sevara added. Unlink Sevara again. |
| A6.12 | **Oʻchirish** the test parent (confirm). | "Parent … deleted."; back on the list; Otabek's children chip has no ★ until A6.13. |
| A6.13 | Open Akmal Saidov, tick main contact for Otabek, Save. | ★ back on Otabek · 7-B. |
| A6.14 | Phone width (390 px). | Table scrolls sideways; nothing is cut off; the form is below the list. |

### A7 Login letters **[PR #58]** (PL.1)

| # | Do | Expected |
|---|---|---|
| A7.1 | Parent page of Zarina Rasulova → language **UZ** → **Kirish xatini chop etish** (confirm). | New tab: one A4 letter in Uzbek with the School logo, branch and date, "Hurmatli Zarina Rasulova…", child Madina Rasulova — 1-A, a QR code and its link (`/download/` until `APP_DOWNLOAD_URL` is set), login ID DEMO-PR03 and a **new** temporary password. |
| A7.2 | Print preview. | One page; the toolbar is not printed. |
| A7.3 | Scan the QR with a phone. | Opens the download page (or the `APP_DOWNLOAD_URL` page). |
| A7.4 | Same with **RU**. | The letter is in Russian. 🌐 |
| A7.5 | List page, class filter **1-A**. | Bar: "N parents in 1-A have not signed in yet." with **Kirish xatlarini chop etish**. Parents who already signed in (e.g. after P1) are not counted. |
| A7.6 | Print the 1-A letters. | One letter per parent who never signed in, each with its own password; parents who signed in keep their password. |

### A8 Register report **[P3.7]** (screen 19)

| # | Do | Expected |
|---|---|---|
| A8.1 | After T2, open the register report for today. | 7-B taken (time, Jasur Karimov), counts present/late/absent and rate; 1-A and 11-A not taken. The list shows Otabek late with his arrival time and note, and Shahzoda absent. |
| A8.2 | Filter class 7-B; **CSV**. | The file has the same rows. |
| A8.3 | As a teacher, open the report URL. | No page (sent to their home). |

### A9 Announcements and payments

| # | Do | Expected |
|---|---|---|
| A9.1 | **Stories**: add a story for the group **7-B**, and one school-wide. | Saved. Parents of 7-B pupils and 7-B pupils see both in the app (checked in P5.3, St1.6); parents of 1-A only see the school-wide one. |
| A9.2 | **Payments** (Moliya → Toʻlovlar), this month, demo branch. | 12 invoices of 3,000,000 soʻm: 3 paid, 1 partly paid, 8 unpaid. |
| A9.3 | Record a payment of 3,000,000 for **Otabek Saidov**'s invoice (the seed already paid Malika's, Aziz's and Kamola's, and half of Javohir's). | Invoice paid; receipt available. Checked by the parent in P5.4. |
| A9.4 | Look for a way to send a notification to **parents** on the web. | **Gap:** not on the web today. Parents can be targeted only through the admin API (`target="parents"`, P2.7). Log it as an issue for the owner to decide. |

---

## T — Homeroom teacher (app)

Sign in as `DEMO-TC02` (Jasur Karimov, homeroom 7-B). Run on a school day inside a quarter (not Sunday,
not a break). Note the date.

### T1 Sign-in and home

| # | Do | Expected |
|---|---|---|
| T1.1 | First launch. **[P4.2]** | Choice screen (screen 1): language switch, two cards Iceberg School / Study Center. Pick **Iceberg School**. |
| T1.2 | Sign in with `DEMO-TC02`. | The app is maroon (School brand) **[P4.3]**; texts in Uzbek (P4.13 on `main`: no English left on the existing screens, readable on maroon). 🌐 |
| T1.3 | Wrong password once. | Clear error, still on the login screen; no lock after one try. |
| T1.4 | Home (screen 11). **[P4.6]** | Today's lessons with times; a banner "7-B register not taken" until T2.4. |
| T1.5 | Tabs. **[P4.9]** | Bugun · Sinflarim · Davomat · Xabarlar · Profil. No Study Center-only tabs (vocabulary, leaderboard, library, leave requests, feedback). |

### T2 Daily register (screens 12–13) **[P4.6]**

The server rules are on `main` (P2.2); only the screen is missing.

| # | Do | Expected |
|---|---|---|
| T2.1 | Open the register for **7-B**, today. | All 4 pupils listed as **present** by default; date and class in the header. No "works offline" footer (dropped, D16). |
| T2.2 | Tap **Otabek** → Late. | Asks the arrival time, default now; set 08:20, note "avtobus". |
| T2.3 | Tap **Shahzoda** twice → Absent. | Absent. |
| T2.4 | **Saqlash**. | Confirmation with counts: 2 present, 1 late, 1 absent. The home banner disappears. Write down the time. |
| T2.5 | Open it again and save without changes. | Same counts. **No new notice** reaches the parents (checked in P3.3). |
| T2.6 | Change Shahzoda from absent to late (08:40), save. | Saved; her parent gets **one** new notice (late). |
| T2.7 | Pick **tomorrow**. | Not allowed (no future dates). |
| T2.8 | Pick **yesterday**, mark Javohir absent, save; then set him back to present, save. | Both saved (past days can be corrected). Going back to present sends no notice. |
| T2.9 | Open the register of **11-A** (Jasur teaches Algebra there). | Read-only: he can see it but not save (only the homeroom teacher saves). |
| T2.10 | Airplane mode, change a mark, save. | Clear "not saved, try again" error; nothing lost on screen (P4.10). |

### T3 Timetable **[P4.5]** (screen 6)

| # | Do | Expected |
|---|---|---|
| T3.1 | Open **Jadval** (or Sinflarim → timetable). | His own lessons Monday–Saturday: Algebra and Geometry in 7-B and 11-A with times and rooms; today selected; the current lesson highlighted. |
| T3.2 | Swipe to next week. | Next week's lessons (same unless A5.3 changed them from that date). |

### T4 Messages with parents **[P4.8]** (screen 10)

| # | Do | Expected |
|---|---|---|
| T4.1 | **Xabarlar** → new message about **Malika** (7-B). | Lists his students who have a parent; opens the thread with Malika's parents (Dilnoza Karimova). |
| T4.2 | Send "Assalomu alaykum, ertaga ota-onalar majlisi." | Sent; appears in the thread with time. The parent sees it in P6. **[PR #57]**: parent's phone gets a push. |
| T4.3 | Try to message about a pupil of 1-A (not his class or subject). | Not offered. |

### T5 Marks for his subject **[R2]** **[P4.7]**

| # | Do | Expected |
|---|---|---|
| T5.1 | Gradebook → **Algebra 7-B**, today's lesson. | The 4 pupils with 2·3·4·5 buttons. |
| T5.2 | Give Malika 5, Otabek 4, save. | Saved; visible to Malika (St3) and her parent (P7). |
| T5.3 | Try marks for **Ingliz tili 7-B**. | Not offered (only his own subjects). |
| T5.4 | Pick a date in the autumn break (4–9 Nov) or tomorrow. | Refused (between quarters / future). |
| T5.5 | Quarter grade for Algebra 7-B. | Shows a suggested grade from the quarter's marks (average, half rounds up); he confirms or changes it. |

---

## S — Subject teacher (app)

Sign in as `DEMO-TC04` (Sardor Aliyev, English in 1-A, 7-B and 11-A; no class of his own).

| # | Do | Expected |
|---|---|---|
| S1.1 | Sign in (as T1.1–T1.2). | School brand, Uzbek. 🌐 |
| S1.2 | Home. **[P4.6]** | Today's English lessons; **no** "register not taken" banner (he is no homeroom teacher). |
| S1.3 | Open the 7-B register (if the app offers it). **[P4.6]** | Read-only, with T2's marks; no Save. |
| S1.4 | Timetable. **[P4.5]** | His English lessons in all three classes, no clashes. |
| S1.5 | Marks for **Ingliz tili 7-B**: Javohir 3, Shahzoda 5. **[R2] [P4.7]** | Saved. He doesn't see Jasur's Algebra marks. |
| S1.6 | Value outside 2–5 (if the screen lets you type). **[R2] [P4.7]** | Refused. |
| S1.7 | Message Otabek's parent (Akmal Saidov). **[P4.8]** | Allowed (subject teachers may message their pupils' parents). |
| S1.8 | Look for Algebra in his gradebook. **[R2]** | Not there. |

---

## P — Parent (app)

Sign in as `DEMO-PR01` (Dilnoza Karimova, two children). Parents use **only the app** (phone, or a
browser at `/app/`).

### P1 Sign-in

| # | Do | Expected |
|---|---|---|
| P1.1 | In a browser, sign in on the ERP page `/` as `DEMO-PR01`. | Sent to `/app/` (the app in the browser), never to an ERP page. |
| P1.2 | **On `main` today:** sign in in the app. | A "Coming soon" screen in the School brand and the user's language (parent screens not built yet). |
| P1.3 | **[P4.2] [P4.3]** First launch → Iceberg School → sign in. | School brand; Home (P2). |
| P1.4 | **[PR #58] + [P4.3]** Sign in as the parent whose password the office set in A6.4 (or one from A7). | The app asks to **choose your own password** before anything else. Until then nothing else opens. After choosing, Home opens; the old temporary password no longer works. |
| P1.5 | "Parolni unutdingizmi?" on the login screen. **[PL.2]** (no such link on `main` today) | Explains: ask the school office (SMS reset comes with PL.2). |

### P2 Home and child switcher **[P4.4]** (screens 4–5)

| # | Do | Expected |
|---|---|---|
| P2.1 | Home. | Child chips **Aziz · 1-A** and **Malika · 7-B**. Today card for the selected child: arrival status and time, current or next lesson; homework due; payment due; latest announcement; unread messages. |
| P2.2 | Switch to **Malika** after T2. | Today: present (or late/absent as T2 saved). |
| P2.3 | Dark mode on the phone. | Home readable in dark (screen 5). |
| P2.4 | Tabs. | Asosiy · Jadval · Vazifalar · Xabarlar · Profil (attendance and payments open from Home and Profil). |

### P3 Attendance and notices (screen 7)

| # | Do | Expected |
|---|---|---|
| P3.1 | After T2.4, open notifications. **[P4.8]** | For Malika: no notice (she was present). Sign in as `DEMO-PR08` (Otabek's guardian): **one** notice "Otabek … late …" with the time. Sign in as the parent of Shahzoda (`DEMO-PR07`): one "absent" notice. |
| P3.2 | **[PR #57]** with the app closed. | The phone shows a push for each notice in P3.1, and tapping it opens the app. |
| P3.3 | After T2.5 (re-save, no change). | No new notice or push. After T2.6, `DEMO-PR07` gets one new "late" notice. |
| P3.4 | Attendance calendar for Otabek. **[P4.4]** | Today marked late with 08:20 and the note; quarter totals (present, late, absent) match. |

### P4 Timetable **[P4.5]**

| # | Do | Expected |
|---|---|---|
| P4.1 | **Jadval**, child Aziz (1-A). | Monday–Saturday, **4 lessons a day** (1-A), with times, subject, teacher, room; today selected. |
| P4.2 | Switch to Malika (7-B). | Up to 6 lessons a day, 7-B's subjects. |

### P5 Homework, announcements, payments **[P4.8]** (screens 8–9)

| # | Do | Expected |
|---|---|---|
| P5.1 | **Vazifalar**. | Homework of the selected child by due date (empty state with a helpful sentence if none). |
| P5.2 | Other family's data: look for any pupil other than Aziz and Malika anywhere in the app. | Never shown. |
| P5.3 | Announcements after A9.1. | `DEMO-PR01` sees the 7-B story (Malika) and the school-wide one. `DEMO-PR03` (1-A only) sees only the school-wide one. |
| P5.4 | Payments, child Malika. Then sign in as `DEMO-PR08`, child Otabek. | Malika: this month's invoice of 3,000,000 soʻm, paid (seed). Otabek: paid with a receipt after A9.3. No online "Toʻlash" button yet (P8). |

### P6 Messages with teachers **[P4.8]** (screen 10)

| # | Do | Expected |
|---|---|---|
| P6.1 | **Xabarlar** → new message, child Malika. | Teachers of 7-B with their subjects, **homeroom first** (Jasur Karimov). |
| P6.2 | Open the thread with Jasur Karimov after T4.2. | His message is there; reply "Rahmat, boraman." It reaches him (T4). |
| P6.3 | Sign in as `DEMO-PR02` (Aziz's father). | He sees the same Aziz threads as `DEMO-PR01` (one thread per child and teacher, shared by both parents), but nothing about Malika. |
| P6.4 | **[PR #57]** App closed, teacher replies. | Push on the parent's phone. |

### P7 Grades **[R2] [P4.7]** (screen 14)

| # | Do | Expected |
|---|---|---|
| P7.1 | Baholar, child Malika. | Algebra 5 (from T5.2); tabs 1–4-chorak and Yillik; only confirmed quarter grades, never the suggestion. |

---

## St — Student (app)

Sign in as `DEMO-IC05` (Malika, 7-B), then `DEMO-IC08` (Otabek) where noted.

| # | Do | Expected |
|---|---|---|
| St1.1 | Sign in (choice → School → login). **[P4.2] [P4.3]** | School brand; Uzbek. On `main` today the existing student home opens and is readable on maroon in uz/ru (P4.13). 🌐 |
| St1.2 | Tabs. **[P4.9]** | Asosiy · Jadval · Vazifalar · Baholar (R2) · Profil; no Study Center-only tabs. |
| St1.3 | Attendance as `DEMO-IC08` after T2.4. | Today **late** in the attendance calendar (on `main`). Arrival 08:20 and note "avtobus" are in the API but not shown on the screen yet **[P4.4]**. |
| St1.4 | Timetable. **[P4.5]** | 7-B's week, today selected. |
| St1.5 | Marks. **[R2] [P4.7]** | Malika: Algebra 5 (T5.2); she doesn't see other pupils' marks. |
| St1.6 | Stories after A9.1. | The 7-B story and the school-wide one. |
| St1.7 | Look for the class register or parent messages. | Not available to students. |
| St1.8 | Change password in Profil (old → new, twice). | Saved; the new password works at the next sign-in. |

---

## X — Cross-checks after all scripts

| # | Do | Expected |
|---|---|---|
| X1 | Sign out and in again on each phone. | Language is remembered; no crash. Brand remembered **[P4.2] [P4.3]**. |
| X2 | Airplane mode, open any screen that loads data. | On `main`: "Internet aloqasi yoʻq" (no internet connection) with **Qayta urinish**; after reconnecting, tapping it loads the screen. The same on every new School screen **[P4.10]**. |
| X3 | A Study Center student and teacher sign in. | Study Center look and tabs, unchanged by the School work. |
| X4 | Time a parent's Home opening on a mid-range Android on mobile data. | Under ~2 s after sign-in (P6.5 measures the server side properly). |
