# ICEBERG Study Center ERP — Frontend Deep Analysis

**Document Version**: 2026-06  
**Platform**: ICEBERG Study Center (English Teaching Center ERP, Uzbekistan)  
**Backend**: Django 5.2 LTS + Django REST Framework + JWT (simplejwt)  
**Frontend Stack**: Bootstrap 5, FontAwesome, Chart.js, jQuery, custom CSS design system  
**Currency**: UZS soʻm (Uzbekistani sum)  
**Deployment**: DigitalOcean Spaces (media), WhiteNoise (static files)

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Design System & CSS Tokens](#2-design-system--css-tokens)
3. [CSS File Inventory & Layer System](#3-css-file-inventory--layer-system)
4. [JavaScript File Inventory & Behaviors](#4-javascript-file-inventory--behaviors)
5. [Template Inheritance & Shell Architecture](#5-template-inheritance--shell-architecture)
6. [Navigation Structure](#6-navigation-structure)
7. [Full URL Route Reference](#7-full-url-route-reference)
8. [REST API Endpoint Reference](#8-rest-api-endpoint-reference)
9. [Authentication & Access Control](#9-authentication--access-control)
10. [Feature Catalog & Special Behaviors](#10-feature-catalog--special-behaviors)
11. [Role-Based Feature Matrix](#11-role-based-feature-matrix)
12. [Known Bugs & Inconsistencies](#12-known-bugs--inconsistencies)
13. [Data Models Reference](#13-data-models-reference)
14. [Visual Browser Study (Live Testing)](#14-visual-browser-study-live-testing)
15. [Gap-Closure Addendum — AJAX & Utility Endpoint Reference](#15-gap-closure-addendum--ajax--utility-endpoint-reference)

---

## 1. System Architecture Overview

### 1.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ICEBERG Study Center ERP                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Browser / PWA Client                                             │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Bootstrap 5 + FontAwesome + Chart.js + jQuery             │  │
│  │  Custom CSS Design System (iceberg.css + layers)           │  │
│  │  Service Worker (/sw.js) — PWA offline support             │  │
│  │  Firebase FCM — push notifications                         │  │
│  └────────────────────────────────────────────────────────────┘  │
│                           │ HTTP/HTTPS                            │
│  Django 5.2 LTS Server                                            │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  LoginCheckMiddleWare — auth/role redirect                 │  │
│  │                                                            │  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │  │
│  │  │  hod_views   │  │ staff_views  │  │student_views │    │  │
│  │  │  (Admin)     │  │  (Teacher)   │  │              │    │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘    │  │
│  │  ┌──────────────┐  ┌──────────────┐                       │  │
│  │  │ public_views │  │  api_views   │ ← DRF + JWT           │  │
│  │  └──────────────┘  └──────────────┘                       │  │
│  │                                                            │  │
│  │  Django ORM → PostgreSQL / SQLite                          │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                   │
│  Static Files → WhiteNoise                                        │
│  Media Files  → DigitalOcean Spaces (S3-compatible)               │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Three-Role System

The entire ERP is built around three user types stored in `CustomUser.user_type`:

| user_type value | Role | Description |
|---|---|---|
| `"1"` | HOD / Admin | School manager; full system access; can be super admin (all branches) or branch-scoped admin |
| `"2"` | Staff / Teacher | Teaching staff; scoped to assigned groups/branches |
| `"3"` | Student | Learner; scoped to own data, own enrolled groups |

### 1.3 Multi-Branch Architecture

- **SuperAdmin** (Admin with `is_superuser=True` or no branch restriction): sees all branches
- **Branch Admin**: scoped to one or more assigned branches
- **Staff**: sees groups assigned to them within their branch
- **Student**: sees only their own enrollment data

Branch scoping is enforced at the view level via `user_can_access_group()` helper and via `IsAdmin`, `IsTeacher`, `IsStudent` DRF permission classes.

### 1.4 Request/Response Flow

```
User opens URL
      │
      ▼
LoginCheckMiddleWare
      │
      ├─ Not authenticated? → /login/
      │
      ├─ Wrong role for URL? → redirect to correct home
      │    e.g., student accessing /admin/home/ → /student/home/
      │
      └─ Authenticated + correct role
             │
             ▼
         View function
             │
             ├─ @admin_only / @staff_only / @student_only decorator check
             │
             ▼
         Template render (server-side) OR JSON response (API)
             │
             ▼
         base.html shell (navbar + sidebar + bottom nav + scripts)
```

### 1.5 PWA & Mobile Support

- **Service Worker**: registered at `/sw.js` — caches static assets for offline use
- **Firebase Cloud Messaging**: `fcm_token` stored on `CustomUser`; push notifications delivered via FCM
- **Platform Detection**: `platform-detect.js` runs before paint; adds `html.platform-apple`, `html.platform-android`, or `html.platform-other` class
- **iOS**: gets liquid glass UI with `backdrop-filter: blur()` effects
- **Android**: gets solid surface look (no backdrop-filter for performance)
- **Bottom Navigation**: 4-tab fixed bottom nav for all roles on mobile

---

## 2. Design System & CSS Tokens

### 2.1 Core Design Tokens (iceberg.css)

All tokens are defined as CSS custom properties on `:root` and overridden under `[data-theme="dark"]`.

#### Color Palette — Brand

```css
:root {
  --navy:       #06343A;   /* Primary brand — deep teal-black; navbar, sidebar, headings */
  --navy-mid:   #0E6873;   /* Hover state for navy elements */
  --navy-light: #1E8C98;   /* Lighter teal accent; icons, borders */
  --navy-deep:  #03181C;   /* Hero gradient floor / darkest navy for gradients */

  --lime:       #DFFF2F;   /* Primary CTA / active accent; sidebar active, primary buttons */
  --lime-deep:  #B8D900;   /* Lime hover state */

  --cyan:       #00CFE8;   /* Secondary accent; charts, highlights */
}
```

#### Color Palette — Semantic

```css
:root {
  --success:    #22C55E;   /* Green — attendance present, payment paid */
  --warning:    #F59E0B;   /* Amber — pending states, overdue */
  --danger:     #EF4444;   /* Red — absent, delete, errors */
  --info:       #3B82F6;   /* Blue — info badges, informational notices */
}
```

#### Color Palette — Leaderboard Medals

```css
:root {
  --gold:   #F59E0B;   /* 1st place */
  --silver: #94A3B8;   /* 2nd place */
  --bronze: #B45309;   /* 3rd place */
}
```

#### Color Palette — Surfaces & Text

```css
:root {
  --bg:         #F4FAFB;   /* Page background — very light teal-white */
  --surface:    #FFFFFF;   /* Card/panel background */
  --surface-2:  #EEF5F6;   /* Secondary surface — zebra rows, input backgrounds */
  --border:     #D4E4E6;   /* Border color — cards, table borders, dividers */

  --text:       #06343A;   /* Primary text — same as --navy for consistency */
  --text-muted: #5A7A7E;   /* Muted text — labels, secondary info */
  --text-light: #8FA8AB;   /* Light text — placeholders, tertiary info */
}
```

### 2.2 Typography Tokens

```css
:root {
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;

  /* Font Sizes */
  --fs-display: 28px;   /* Hero numbers, big stats */
  --fs-h1:      21px;   /* Page titles */
  --fs-h2:      16px;   /* Section headings */
  --fs-h3:      14px;   /* Card headings, sub-sections */
  --fs-body:    13px;   /* Default body text */
  --fs-sm:      12px;   /* Small text, table cells */
  --fs-xs:      11px;   /* Badge text, captions */
}
```

### 2.3 Layout Tokens

```css
:root {
  --sidebar-width:  256px;   /* Desktop sidebar width */
  --navbar-height:  60px;    /* Top navbar height */
}
```

### 2.4 Border Radius Tokens

```css
:root {
  --radius-sm:  6px;    /* Small elements — badges, tags, table cells */
  --radius-md:  10px;   /* Cards, buttons, inputs */
  --radius-lg:  14px;   /* Large cards, modals */
  --radius-xl:  20px;   /* Hero cards, featured elements */
}
```

### 2.5 Dark Mode

Dark mode is implemented via two mechanisms:

**Admins & Staff**: `localStorage` key `ice_ui_theme`
- Value `"dark"` → adds `data-theme="dark"` to `<html>`
- Value `"light"` or absent → light mode

**Students**: DB-stored theme preference (on `Student` model or `CustomUser`)
- Server renders `data-theme="dark"` on `<html>` directly based on DB value
- Allows consistent theme across devices

Dark mode overrides in `iceberg.css`:

```css
[data-theme="dark"] {
  --bg:         #0D1F22;
  --surface:    #122428;
  --surface-2:  #172D31;
  --border:     #1E3A3F;
  --text:       #E8F4F5;
  --text-muted: #7AABAF;
  --text-light: #4A7A7E;
  /* navy/lime/cyan brand colors remain the same */
}
```

Chart.js charts re-initialize on theme toggle via `recreateAllCharts()` function called from `profile-hub.js`.

### 2.6 Platform-Specific Visual Themes

Controlled by classes added to `<html>` by `platform-detect.js`:

| Platform Class | Visual Treatment |
|---|---|
| `html.platform-apple` | Liquid glass UI: `backdrop-filter: blur(20px) saturate(180%)` on sidebar, navbar, cards |
| `html.platform-android` | Solid surfaces, no backdrop-filter, slightly more opaque backgrounds |
| `html.platform-other` | Default desktop styling |

`mobile-adaptive.css` implements the actual glass/solid theme switching:

```css
/* iOS liquid glass */
html.platform-apple .sidebar {
  background: rgba(6, 52, 58, 0.85);
  backdrop-filter: blur(20px) saturate(180%);
  -webkit-backdrop-filter: blur(20px) saturate(180%);
}

/* Android solid */
html.platform-android .sidebar {
  background: var(--navy);
  backdrop-filter: none;
}
```

### 2.7 Component Visual Specifications

#### Sidebar Active Item

```css
.sidebar-item.active {
  background: var(--lime);
  color: var(--navy);
  border-radius: var(--radius-md);
  font-weight: 600;
}
```

#### Primary Button

```css
.btn-primary {
  background: var(--lime);
  color: var(--navy);
  border: none;
  border-radius: var(--radius-md);
  font-weight: 600;
  font-size: var(--fs-body);
}
.btn-primary:hover {
  background: var(--lime-deep);
}
```

#### Stat Cards (Dashboard)

- Background: `var(--surface)`
- Border: `1px solid var(--border)`
- Border radius: `var(--radius-lg)`
- Icon background: tinted with brand colors
- Number: `var(--fs-display)`, `font-weight: 700`, color: `var(--navy)`
- Animated count-up on page load via `iceberg-interactive.js`

#### Table Styles

- Header: `background: var(--surface-2)`, text `var(--text-muted)`, uppercase, `var(--fs-xs)`
- Rows: hover → `background: var(--surface-2)` with smooth transition
- Mobile: JS-powered card reflow (see `responsive-tables.js`)

---

## 3. CSS File Inventory & Layer System

The CSS is loaded in a deliberate cascade order. Later files override earlier ones.

### 3.1 Layer 0 — Base Layout

#### `erpnext-style.css`

**Purpose**: Base layout grid — navbar, sidebar, main content area.

Key rules:
```css
.main-layout {
  display: grid;
  grid-template-columns: var(--sidebar-width) 1fr;
  grid-template-rows: var(--navbar-height) 1fr;
  min-height: 100vh;
}
.navbar {
  grid-column: 1 / -1;
  height: var(--navbar-height);
  position: sticky;
  top: 0;
  z-index: 100;
}
.sidebar {
  width: var(--sidebar-width);
  height: calc(100vh - var(--navbar-height));
  position: sticky;
  top: var(--navbar-height);
  overflow-y: auto;
}
.main-content {
  padding: 24px;
  overflow-x: hidden;
}
```

### 3.2 Layer 1 — Base Components

#### `storefront-ui.css`

**Purpose**: Base card and button styles. These are overridden by `iceberg.css`.

Provides:
- `.card` base styles
- `.btn` base styles
- Form control base styles
- Alert and badge base styles

### 3.3 Layer 2 — Main Design System (CRITICAL)

#### `iceberg.css`

**Purpose**: THE main design system v2. Defines all CSS variables, overrides Bootstrap, implements component styles, dark mode.

Key sections:
1. `:root` CSS custom properties (all tokens from Section 2)
2. `[data-theme="dark"]` overrides
3. `.navbar` brand-colored navbar (`background: var(--navy)`)
4. `.sidebar` styles with nav sections and item hover/active states
5. `.card` overrides — uses `--surface`, `--border`, `--radius-lg`
6. `.btn-primary` / `.btn-outline-primary` with lime colors
7. `.badge` variants using semantic color tokens
8. Table styles with hover transitions
9. Form styles — inputs with `--border`, focus `--navy-light`
10. Page title styles using `--fs-h1`
11. Stat card component (`.stat-card`, `.stat-number`, `.stat-icon`)
12. `.sidebar-section-label` uppercase `--fs-xs` section headers

### 3.4 Layer 3 — Bold Animations

#### `iceberg-bold.css`

**Purpose**: Animated backgrounds, gradient titles, table interactivity enhancements.

Key features:
- `@keyframes iceContentIn` — fade-in animation (0.2s ease-out) applied to `.main-content`
- Gradient text titles using `background-clip: text; -webkit-text-fill-color: transparent`
- Table row enter animation — rows slide up on load
- Stat counter shimmer effect
- Hero section animated gradient background (`@keyframes gradientShift`)

### 3.5 Layer 4 — Mobile Adaptive

#### `mobile-adaptive.css`

**Purpose**: Safe areas for notched phones, table→card reflow on small screens, platform-specific glass/solid theming.

Key features:
```css
/* Safe area for notched phones (iOS) */
.bottom-nav {
  padding-bottom: env(safe-area-inset-bottom);
}
.main-content {
  padding-bottom: calc(80px + env(safe-area-inset-bottom));
}

/* Table → card reflow at 768px */
@media (max-width: 768px) {
  table, thead, tbody, th, td, tr {
    display: block;
  }
  td::before {
    content: attr(data-label);
    font-weight: 600;
    color: var(--text-muted);
  }
}
```

Platform theming (as described in Section 2.6).

### 3.6 Layer 5 — Bottom Navigation

#### `glowing-bottom-nav.css`

**Purpose**: Styles for the fixed bottom navigation bar on mobile.

Key rules:
```css
.bottom-nav {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  height: 64px;
  background: var(--navy);
  display: flex;
  z-index: 200;
}
.bottom-nav-item.active {
  color: var(--lime);
  filter: drop-shadow(0 0 8px var(--lime));
}
.bottom-nav-badge {
  background: var(--danger);
}
```

### 3.7 Layer 6 — Mobile Polish

#### `iceberg-mobile-polish.css`

**Purpose**: Final mobile UX polish layer — touch target sizes, scroll momentum, input zoom prevention.

Key rules:
```css
/* Prevent iOS zoom on input focus */
input, select, textarea {
  font-size: 16px !important;
}
/* Touch targets minimum 44px */
.btn, .nav-link, .sidebar-item {
  min-height: 44px;
}
/* Momentum scrolling */
.sidebar, .main-content {
  -webkit-overflow-scrolling: touch;
}
```

### 3.8 Layer 7 — Interactions

#### `interactions.css`

**Purpose**: Press/hover/focus utility classes, button loading spinners, skeleton shimmer.

Key classes:
```css
.press-scale {
  transition: transform 0.1s ease;
}
.press-scale:active {
  transform: scale(0.96);
}
.skeleton {
  background: linear-gradient(90deg, var(--surface-2) 25%, var(--border) 50%, var(--surface-2) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
}
@keyframes shimmer {
  0%   { background-position: -200% 0; }
  100% { background-position:  200% 0; }
}
```

### 3.9 Layer 8 — Page Loader

#### `loading.css`

**Purpose**: Page progress bar at top of viewport, full-page loader overlay.

Key rules:
```css
#page-progress-bar {
  position: fixed;
  top: 0;
  left: 0;
  height: 3px;
  background: var(--lime);
  z-index: 9999;
  transition: width 0.3s ease;
}
.page-loader {
  position: fixed;
  inset: 0;
  background: var(--bg);
  z-index: 9998;
  display: flex;
  align-items: center;
  justify-content: center;
}
```

### 3.10 Layer 9 — Reliability States

#### `iceberg-reliability.css`

**Purpose**: Error state styles — empty states, error cards, connection lost banners.

Key components:
- `.empty-state` — centered icon + message when no data
- `.error-card` — red-bordered card for error display
- `.offline-banner` — top-of-page "You are offline" notice

### 3.11 Layer 10 — Icon Animations

#### `animated-icons.css`

**Purpose**: CSS animation classes for FontAwesome icons and SVG icons.

```css
.icon-pulse  { animation: pulse 2s infinite; }
.icon-spin   { animation: spin 1s linear infinite; }
.icon-bounce { animation: bounce 0.6s ease infinite alternate; }
.icon-shake  { animation: shake 0.5s ease; }
```

### 3.12 Layer 11 — Logout Animation

#### `animated-logout.css`

**Purpose**: Styles for the animated logout button component. Used with `animated-logout.js` and `main_app/includes/animated_logout_button.html`.

### 3.13 Feature-Specific CSS Files

#### `admin-dashboard-2026.css`

**Purpose**: Admin home dashboard 2026 redesign.

Provides:
- Dashboard hero section with gradient background
- Stat card grid (2×2 on mobile, 4×1 on desktop)
- Quick action buttons grid
- Recent activity feed styles
- Chart container sizing

#### `admin-manage-mobile.css`

**Purpose**: Admin manage pages mobile optimizations.

Adjusts:
- Action button placement for mobile
- Table overflow handling on narrow screens
- Filter/search bar mobile layout

#### `notifications.css`

**Purpose**: Notification list and notification bell badge styles.

```css
.notification-badge {
  background: var(--danger);
  color: #fff;
  border-radius: 50%;
  font-size: var(--fs-xs);
  min-width: 18px;
  height: 18px;
}
.notification-item.unread {
  background: var(--surface-2);
  border-left: 3px solid var(--lime);
}
```

#### `profile-hub.css`

**Purpose**: Profile & Settings hub page styles.

Sections:
- Avatar picker grid (24 emoji stickers)
- Theme picker toggle buttons (light/dark)
- Profile form card layout
- Password change section

#### `staff-modern.css`

**Purpose**: Staff-specific page styles.

Key additions:
- Take attendance page — student list with present/absent toggle
- Assignment grading table styles
- Vocabulary day management styles
- Staff payments table

#### `student-modern.css`

**Purpose**: Student-specific page styles.

Key additions:
- Attendance visualization (circular progress, calendar heatmap)
- Leaderboard page styles (rank cards with medal colors)
- Vocabulary flashcard styles
- Progress page chart containers
- Story card carousel (Instagram-style)

---

## 4. JavaScript File Inventory & Behaviors

### 4.1 Critical Path JS (Must Load Before Paint)

#### `platform-detect.js`

**Load order**: `<head>` — BEFORE any CSS or other scripts  
**Purpose**: Detect platform and add class to `<html>` before first paint to prevent FOUC.

```javascript
(function() {
  const ua = navigator.userAgent;
  const html = document.documentElement;

  if (/iPad|iPhone|iPod/.test(ua)) {
    html.classList.add('platform-apple');
  } else if (/Android/.test(ua)) {
    html.classList.add('platform-android');
  } else {
    html.classList.add('platform-other');
  }

  // Also restore theme before paint
  const theme = localStorage.getItem('ice_ui_theme');
  if (theme === 'dark') {
    html.setAttribute('data-theme', 'dark');
  }
})();
```

### 4.2 Security & Infrastructure JS

#### `csrf-setup.js`

**Purpose**: Configure jQuery AJAX to always send Django CSRF token.

```javascript
function getCookie(name) { /* reads csrftoken cookie */ }

$.ajaxSetup({
  beforeSend: function(xhr, settings) {
    if (!(/^(GET|HEAD|OPTIONS|TRACE)$/.test(settings.type)) && !this.crossDomain) {
      xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
    }
  }
});
```

### 4.3 Core Interactive JS

#### `iceberg-interactive.js`

**Purpose**: Three main behaviors — table search/sort, stat count-up animation, scroll reveal.

**Table Search**:
```javascript
document.querySelectorAll('[data-table-search]').forEach(input => {
  input.addEventListener('input', function() {
    const query = this.value.toLowerCase();
    const tableId = this.dataset.tableSearch;
    document.querySelectorAll(`#${tableId} tbody tr`).forEach(row => {
      row.style.display = row.textContent.toLowerCase().includes(query) ? '' : 'none';
    });
  });
});
```

**Stat Count-Up**:
```javascript
function animateCountUp(el) {
  const target = parseInt(el.dataset.value || el.textContent);
  const duration = 1200;
  // requestAnimationFrame loop easing to target
}
document.querySelectorAll('.stat-number').forEach(animateCountUp);
```

**Scroll Reveal**:
```javascript
const observer = new IntersectionObserver((entries) => {
  entries.forEach(entry => {
    if (entry.isIntersecting) entry.target.classList.add('revealed');
  });
}, { threshold: 0.1 });
document.querySelectorAll('[data-reveal]').forEach(el => observer.observe(el));
```

#### `responsive-tables.js`

**Purpose**: Inject `data-label` attributes on `<td>` elements based on corresponding `<th>` text, enabling CSS-only mobile card reflow.

```javascript
document.querySelectorAll('table.responsive').forEach(table => {
  const headers = Array.from(table.querySelectorAll('thead th'))
    .map(th => th.textContent.trim());
  table.querySelectorAll('tbody tr').forEach(row => {
    row.querySelectorAll('td').forEach((td, i) => {
      if (headers[i]) td.setAttribute('data-label', headers[i]);
    });
  });
});
```

Mobile CSS then uses `td::before { content: attr(data-label); }`.

### 4.4 Mobile UX JS

#### `iceberg-mobile-polish.js`

**Purpose**: Mobile UX enhancements — touch feedback, scroll behavior, sidebar auto-close.

Key behaviors:
1. **Touch feedback**: Adds `.touch-active` class on `touchstart`, removes on `touchend`/`touchcancel`
2. **Scroll behavior**: Monitors scroll direction; hides bottom nav on scroll-down, shows on scroll-up
3. **Sidebar auto-close**: Closes sidebar drawer on overlay tap on mobile

```javascript
// Sidebar auto-close
document.querySelector('.sidebar-overlay')?.addEventListener('click', () => {
  document.body.classList.remove('sidebar-open');
});

// Scroll direction detection for bottom nav hide/show
let lastScrollY = 0;
window.addEventListener('scroll', () => {
  const currentY = window.scrollY;
  const bottomNav = document.querySelector('.bottom-nav');
  if (bottomNav) {
    bottomNav.style.transform = currentY > lastScrollY && currentY > 100
      ? 'translateY(100%)' : 'translateY(0)';
  }
  lastScrollY = currentY;
}, { passive: true });
```

#### `glowing-bottom-nav.js`

**Purpose**: Bottom navigation active state management and unread badge updates.

```javascript
// Set active tab based on current URL
const currentPath = window.location.pathname;
document.querySelectorAll('.bottom-nav-item').forEach(item => {
  if (item.getAttribute('href') === currentPath) {
    item.classList.add('active');
  }
});

// Fetch unread count and update badge
function updateMessageBadge() {
  fetch('/api/v1/notifications/?unread=1')
    .then(r => r.json())
    .then(data => {
      const badge = document.querySelector('.bottom-nav-badge');
      if (badge) badge.textContent = data.count || '';
    });
}
```

### 4.5 Page Lifecycle JS

#### `loading.js`

**Purpose**: Page progress bar and delayed page loader.

```javascript
const bar = document.getElementById('page-progress-bar');
let progress = 0;
const interval = setInterval(() => {
  progress += Math.random() * 15;
  if (progress >= 90) { clearInterval(interval); progress = 90; }
  bar.style.width = progress + '%';
}, 200);

window.addEventListener('load', () => {
  clearInterval(interval);
  bar.style.width = '100%';
  setTimeout(() => bar.style.opacity = '0', 300);
  setTimeout(() => {
    document.querySelector('.page-loader')?.classList.add('hidden');
  }, 500);
});
```

#### `animated-logout.js`

**Purpose**: Shows logout animation then programmatically submits hidden POST form with CSRF token. JS-optional (form degrades gracefully).

```javascript
document.querySelector('.logout-btn-animated')?.addEventListener('click', function(e) {
  e.preventDefault();
  this.classList.add('logging-out');
  setTimeout(() => {
    document.querySelector('#logout-form').submit();
  }, 600);
});
```

### 4.6 Safety & Utility JS

#### `safe-actions.js`

**Purpose**: Intercepts `data-confirm` links and form submissions; shows `confirm()` dialog before proceeding.

```javascript
document.querySelectorAll('[data-confirm]').forEach(el => {
  el.addEventListener('click', function(e) {
    const msg = this.dataset.confirm || 'Are you sure?';
    if (!confirm(msg)) e.preventDefault();
  });
});
```

#### `trend-chart.js`

**Purpose**: Chart.js helper wrappers for trend/sparkline charts on dashboards.

```javascript
function createTrendChart(canvasId, labels, data, options = {}) {
  return new Chart(document.getElementById(canvasId), {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data,
        borderColor: getComputedStyle(document.documentElement)
          .getPropertyValue('--cyan').trim(),
        backgroundColor: 'rgba(0, 207, 232, 0.1)',
        tension: 0.4,
        fill: true,
      }]
    },
    options: {
      responsive: true,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: 'var(--border)' } },
        y: { grid: { color: 'var(--border)' } }
      },
      ...options
    }
  });
}
```

### 4.7 Admin-Specific JS

#### `admin-manage-mobile.js`

**Purpose**: Mobile-specific behavior for admin manage pages.

Behaviors:
- Collapses action columns on mobile, replacing with "..." dropdown menu
- Stacks filter controls vertically on narrow screens
- Touch-friendly row selection

### 4.8 Profile & Settings JS

#### `profile-hub.js`

**Purpose**: Profile Hub page interactions — theme picker, avatar picker, real-time preview.

```javascript
// Theme picker
document.querySelectorAll('[data-theme-pick]').forEach(btn => {
  btn.addEventListener('click', function() {
    const theme = this.dataset.themePick;
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('ice_ui_theme', theme);
    // For students: also POST to /api/v1/me/ to save in DB
    if (typeof recreateAllCharts === 'function') recreateAllCharts();
  });
});

// Avatar picker (24 emoji stickers)
document.querySelectorAll('.avatar-sticker').forEach(sticker => {
  sticker.addEventListener('click', function() {
    document.querySelectorAll('.avatar-sticker').forEach(s => s.classList.remove('selected'));
    this.classList.add('selected');
    document.querySelector('#avatar-input').value = this.dataset.avatar;
  });
});
```

---

## 5. Template Inheritance & Shell Architecture

### 5.1 Template Hierarchy

```
base.html (main shell — all authenticated templates extend this)
│
├── HOD Templates (hod_template/)
│   ├── home_content.html            (admin dashboard)
│   ├── manage_student.html
│   ├── add_student_template.html
│   ├── edit_student_template.html
│   ├── manage_staff.html
│   ├── add_staff_template.html
│   ├── edit_staff_template.html
│   ├── manage_admin.html
│   ├── add_admin_template.html
│   ├── manage_course.html
│   ├── add_course_template.html
│   ├── edit_course_template.html
│   ├── manage_subject.html
│   ├── add_subject_template.html
│   ├── edit_subject_template.html
│   ├── manage_session.html
│   ├── add_session_template.html
│   ├── edit_session_template.html
│   ├── manage_branch.html (manage_branch.html)
│   ├── add_branch.html
│   ├── manage_group.html
│   ├── add_group.html
│   ├── group_detail.html
│   ├── manage_enrollment.html
│   ├── add_enrollment.html
│   ├── admin_view_attendance.html
│   ├── admin_view_profile.html
│   ├── staff_feedback_template.html
│   ├── staff_leave_view.html
│   ├── staff_notification.html
│   ├── student_feedback_template.html
│   ├── student_leave_view.html
│   ├── student_notification.html
│   ├── manage_registration_leads.html
│   ├── add_invoice.html
│   ├── generate_invoices.html
│   ├── manage_payments.html
│   ├── record_payment.html
│   ├── admin_leaderboard_settings.html
│   ├── admin_manage_seasons.html
│   ├── manage_vocabulary_days.html
│   ├── manage_stories.html
│   └── story_form.html
│
├── Staff Templates (staff_template/)
│   ├── erpnext_staff_home.html
│   ├── staff_view_profile.html
│   ├── staff_take_attendance.html
│   ├── staff_update_attendance.html
│   ├── staff_add_result.html
│   ├── edit_student_result.html
│   ├── staff_result_files.html
│   ├── upload_result_file.html
│   ├── staff_assignments.html
│   ├── add_assignment.html
│   ├── view_submissions.html
│   ├── staff_payments.html
│   ├── staff_vocabulary_days.html
│   ├── add_vocabulary_day.html
│   ├── staff_vocabulary_day_detail.html
│   ├── staff_apply_leave.html
│   ├── staff_feedback.html
│   ├── staff_view_notification.html
│   ├── staff_story_form.html
│   ├── add_book.html
│   ├── issue_book.html
│   └── view_issued_book.html
│
├── Student Templates (student_template/)
│   ├── erpnext_student_home.html
│   ├── student_view_profile.html
│   ├── student_view_attendance.html
│   ├── student_view_result.html
│   ├── student_result_files.html
│   ├── student_assignments.html
│   ├── submit_assignment.html
│   ├── student_payments.html
│   ├── vocabulary_day_list.html
│   ├── vocabulary_day_detail.html
│   ├── vocabulary_day_flashcard.html
│   ├── vocabulary_day_quiz.html
│   ├── student_progress.html
│   ├── leaderboard.html
│   ├── leaderboard_history.html
│   ├── leaderboard_season.html
│   ├── student_apply_leave.html
│   ├── student_feedback.html
│   ├── student_view_notification.html
│   └── view_books.html
│
└── Shared Templates (main_app/)
    ├── messages.html         (group chat)
    ├── profile_hub.html      (profile settings)
    ├── payment_receipt.html
    └── error.html

registration/erpnext_base.html (auth pages — simpler shell, no sidebar)
├── forgot_password.html
├── verify_reset_code.html
├── reset_password.html
├── password_reset_done.html
├── password_reset_confirm.html
└── password_reset_complete.html

Standalone (no base extension):
├── login.html     (fully custom, no sidebar/navbar)
└── entry.html     (landing page)
```

### 5.2 base.html — Shell Structure

The `base.html` provides the full application shell. Every authenticated page extends it.

```html
<!DOCTYPE html>
<html lang="en" data-theme="{{ theme }}">
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <!-- OpenGraph tags for link previews -->
  <meta property="og:title" content="ICEBERG Study Center">
  <meta property="og:image" content="...">
  <meta name="twitter:card" content="summary_large_image">
  {% block head %}{% endblock %}
</head>
<body>
  <!-- Platform detection: inline, synchronous, BEFORE DOM -->
  <script src="{% static 'js/platform-detect.js' %}"></script>

  <!-- Page Loader overlay -->
  <div class="page-loader">...</div>
  <div id="page-progress-bar"></div>

  <!-- Navbar -->
  <nav class="navbar">
    <div class="navbar-brand">ICEBERG</div>
    <div class="navbar-actions">
      <!-- Notification bell (→ /messages/ for admin; notification page for others) -->
      <!-- Theme toggle button -->
      <!-- Profile avatar/dropdown -->
      {% include 'main_app/includes/animated_logout_button.html' %}
    </div>
  </nav>

  <div class="main-layout">
    {% include 'main_app/erpnext_sidebar.html' %}
    <main class="main-content">
      {% if messages %}
        {% for message in messages %}
          <div class="alert alert-{{ message.tags }}">{{ message }}</div>
        {% endfor %}
      {% endif %}
      {% block content %}{% endblock %}
    </main>
  </div>

  <!-- Bottom navigation (mobile) -->
  {% include 'main_app/partials/glowing_bottom_nav.html' %}

  <!-- Core scripts -->
  <script src="{% static 'js/csrf-setup.js' %}"></script>
  <script src="{% static 'js/loading.js' %}"></script>
  <script src="{% static 'js/iceberg-interactive.js' %}"></script>
  <script src="{% static 'js/responsive-tables.js' %}"></script>
  <script src="{% static 'js/iceberg-mobile-polish.js' %}"></script>
  <script src="{% static 'js/glowing-bottom-nav.js' %}"></script>
  <script src="{% static 'js/safe-actions.js' %}"></script>
  <script src="{% static 'js/animated-logout.js' %}"></script>

  <!-- Service Worker registration -->
  <script>
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('/sw.js');
    }
  </script>
  {% block scripts %}{% endblock %}
</body>
</html>
```

### 5.3 registration/erpnext_base.html — Auth Shell

Simpler shell for unauthenticated pages (forgot password flow, password reset).

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <!-- Minimal CSS — no sidebar, no navbar brand colors -->
  <!-- Uses iceberg.css for visual consistency -->
</head>
<body class="auth-page">
  <div class="auth-container">
    <div class="auth-card">
      <div class="auth-logo">ICEBERG</div>
      {% block content %}{% endblock %}
    </div>
  </div>
</body>
</html>
```

### 5.4 login.html — Standalone Login Page

Does NOT extend any base template. Fully custom standalone page.

Features:
- Full-page gradient background (`var(--navy-deep)` → `var(--navy)`)
- Centered login card with glass effect on iOS
- `identifier` field (accepts email for admin, login_id for staff/student)
- `password` field
- "Remember me" checkbox
- Error messages from Django `messages` framework
- Missing link to `/forgot-password/` (see Bug #2)
- No navbar, no sidebar, no bottom nav

### 5.5 Sidebar Partial — erpnext_sidebar.html

Included by `base.html`. Contains conditional navigation blocks based on `request.user.user_type`.

```html
<aside class="sidebar {% if sidebar_collapsed %}collapsed{% endif %}">
  <div class="sidebar-header">
    <img src="..." alt="ICEBERG Logo">
    <button class="sidebar-toggle">...</button>
  </div>
  <nav class="sidebar-nav">
    {% if request.user.user_type == '1' %}
      <!-- Admin navigation (see Section 6.1) -->
    {% elif request.user.user_type == '2' %}
      <!-- Staff navigation (see Section 6.2) -->
    {% elif request.user.user_type == '3' %}
      <!-- Student navigation (see Section 6.3) -->
    {% endif %}
  </nav>
  {% include 'main_app/includes/profile_settings_row.html' %}
</aside>
```

Sidebar collapses on desktop — state stored in `localStorage` as `ice_sidebar_collapsed`.

### 5.6 Bottom Nav Partial — glowing_bottom_nav.html

```html
<nav class="bottom-nav">
  {% if request.user.user_type == '1' %}
    <!-- Admin: Home | People | Chat | Profile -->
  {% elif request.user.user_type == '2' %}
    <!-- Staff: Home | Attendance | Scores | Profile -->
  {% elif request.user.user_type == '3' %}
    <!-- Student: Home | Attendance | Results | Profile -->
  {% endif %}
</nav>
```

### 5.7 Includes / Partials Reference

| Partial Path | Purpose |
|---|---|
| `main_app/erpnext_sidebar.html` | Sidebar navigation (included by base.html) |
| `main_app/partials/glowing_bottom_nav.html` | Bottom nav bar (included by base.html) |
| `main_app/includes/animated_logout_button.html` | Logout button with animation |
| `main_app/includes/profile_settings_row.html` | Profile row at bottom of sidebar |
| `staff_template/includes/library_tabs.html` | Library tabbed navigation (staff pages) |

---

## 6. Navigation Structure

### 6.1 Admin Sidebar Navigation (user_type = "1")

```
OVERVIEW
  ├── Dashboard                    /admin/home/
  └── Profile & Settings           /profile-hub/

PEOPLE
  ├── Students                     /student/manage/
  ├── Teachers                     /staff/manage/
  └── Admins                       /admin/manage/

ACADEMIC MANAGEMENT
  ├── Groups & Enrollments         /group/manage/
  ├── Branches                     /branch/manage/
  ├── Courses                      /course/manage/
  └── Attendance                   /admin/view-attendance/

FINANCE
  └── Payments                     /admin/payments/

VOCABULARY & CONTENT
  ├── Vocabulary                   /manage-vocabulary-days/
  ├── Leaderboard                  /leaderboard/admin/settings/
  └── Stories                      /stories/manage/

COMMUNICATION
  ├── Messages                     /messages/
  ├── Leads                        /manage-registration-leads/
  ├── Student Feedback             /admin/view-student-feedback/
  └── Teacher Feedback             /admin/view-staff-feedback/

REQUESTS
  ├── Student Leave                /admin/view-student-leave/
  └── Teacher Leave                /admin/view-staff-leave/
```

### 6.2 Staff Sidebar Navigation (user_type = "2")

```
HOME
  ├── Dashboard                    /staff/home/
  └── Profile & Settings           /profile-hub/

TEACHING
  ├── Take Attendance              /staff/take-attendance/
  ├── Update Attendance            /staff/update-attendance/
  ├── Scores                       /staff/add-result/
  ├── Result Files                 /staff/result-files/
  ├── Assignments                  /staff/assignments/
  ├── Payments                     /staff/payments/
  ├── Vocabulary                   /staff/vocabulary-days/
  ├── Stories                      /staff/stories/create/
  └── Library                      /staff/book/issued/

COMMUNICATION
  ├── Messages                     /messages/
  ├── Notifications                /staff/view-notification/
  ├── Leave                        /staff/apply-leave/
  └── Feedback                     /staff/feedback/
```

### 6.3 Student Sidebar Navigation (user_type = "3")

```
HOME
  ├── Dashboard                    /student/home/
  └── Profile & Settings           /profile-hub/

STUDY
  ├── Attendance                   /student/view-attendance/
  ├── Scores                       /student/view-result/
  ├── Result Files                 /student/result-files/
  ├── Assignments                  /student/assignments/
  ├── Vocabulary                   /student/vocabulary-days/
  ├── Progress                     /student/progress/
  ├── Payments                     /student/payments/
  ├── Leaderboard                  /student/leaderboard/
  └── Library                      /student/books/

COMMUNICATION
  ├── Messages                     /messages/
  ├── Notifications                /student/view-notification/
  ├── Leave                        /student/apply-leave/
  └── Feedback                     /student/feedback/
```

### 6.4 Bottom Navigation (Per Role)

| Role | Tab 1 | Tab 2 | Tab 3 | Tab 4 |
|---|---|---|---|---|
| Admin | Home (`/admin/home/`) | People (`/student/manage/`) | Chat (`/messages/`) | Profile (`/profile-hub/`) |
| Staff | Home (`/staff/home/`) | Attendance (`/staff/take-attendance/`) | Scores (`/staff/add-result/`) | Profile (`/profile-hub/`) |
| Student | Home (`/student/home/`) | Attendance (`/student/view-attendance/`) | Results (`/student/view-result/`) | Profile (`/profile-hub/`) |

Icons: FontAwesome icons. Active item glows with `var(--lime)` and `drop-shadow(0 0 8px var(--lime))`. Unread message dot appears on Chat tab when unread messages exist.

---

## 7. Full URL Route Reference

### 7.1 Admin / HOD Routes

| Method | URL Pattern | View Function | Template |
|---|---|---|---|
| GET/POST | `/admin/home/` | `admin_home` | `home_content.html` |
| GET/POST | `/admin/add/` | `add_admin` | `add_admin_template.html` |
| GET | `/admin/manage/` | `manage_admin` | `manage_admin.html` |
| GET/POST | `/admin/delete/<int:admin_id>/` | `delete_admin` | — (redirect) |
| GET/POST | `/student/add/` | `add_student` | `add_student_template.html` |
| GET | `/student/manage/` | `manage_student` | `manage_student.html` |
| GET/POST | `/student/edit/<int:student_id>/` | `edit_student` | `edit_student_template.html` |
| GET/POST | `/student/delete/<int:student_id>/` | `delete_student` | — (redirect) |
| GET/POST | `/staff/add/` | `add_staff` | `add_staff_template.html` |
| GET | `/staff/manage/` | `manage_staff` | `manage_staff.html` |
| GET/POST | `/staff/edit/<int:staff_id>/` | `edit_staff` | `edit_staff_template.html` |
| GET/POST | `/staff/delete/<int:staff_id>/` | `delete_staff` | — (redirect) |
| GET/POST | `/course/add/` | `add_course` | `add_course_template.html` |
| GET | `/course/manage/` | `manage_course` | `manage_course.html` |
| GET/POST | `/course/edit/<int:course_id>/` | `edit_course` | `edit_course_template.html` |
| GET/POST | `/course/delete/<int:course_id>/` | `delete_course` | — (redirect) |
| GET/POST | `/subject/add/` | `add_subject` | `add_subject_template.html` |
| GET | `/subject/manage/` | `manage_subject` | `manage_subject.html` |
| GET/POST | `/subject/edit/<int:subject_id>/` | `edit_subject` | `edit_subject_template.html` |
| GET/POST | `/subject/delete/<int:subject_id>/` | `delete_subject` | — (redirect) |
| GET/POST | `/add_session/` | `add_session` | `add_session_template.html` |
| GET | `/session/manage/` | `manage_session` | `manage_session.html` |
| GET/POST | `/session/edit/<int:session_id>/` | `edit_session` | `edit_session_template.html` |
| GET/POST | `/session/delete/<int:session_id>/` | `delete_session` | — (redirect) |
| GET/POST | `/branch/add/` | `add_branch` | `add_branch.html` |
| GET | `/branch/manage/` | `manage_branch` | `manage_branch.html` |
| GET/POST | `/branch/edit/<int:branch_id>` (no trailing slash) | `edit_branch` | — |
| GET/POST | `/branch/delete/<int:branch_id>` (no trailing slash) | `delete_branch` | — (redirect) |
| GET/POST | `/group/add/` | `add_group` | `add_group.html` |
| GET | `/group/manage/` | `manage_group` | `manage_group.html` |
| GET | `/group/<int:pk>/` | `group_detail` | `group_detail.html` |
| GET/POST | `/group/archive/<int:pk>/` | `archive_group` | — (redirect) |
| GET/POST | `/group/unarchive/<int:pk>/` | `unarchive_group` | — (redirect) |
| GET/POST | `/group/delete/<int:pk>/` | `delete_group` | — (redirect) |
| GET/POST | `/enrollment/add/` | `add_enrollment` | `add_enrollment.html` |
| GET | `/enrollment/manage/` | `manage_enrollment` | `manage_enrollment.html` |
| GET/POST | `/enrollment/delete/<int:pk>/` | `delete_enrollment` | — (redirect) |
| GET | `/admin/view-attendance/` | `admin_view_attendance` | `admin_view_attendance.html` |
| GET | `/admin/view-profile/` | `admin_view_profile` | `admin_view_profile.html` |
| GET | `/admin/view-student-leave/` | `view_student_leave` | `student_leave_view.html` |
| GET/POST | `/admin/student-leave/approve/<int:pk>/` | `approve_student_leave` | — (redirect) |
| GET/POST | `/admin/student-leave/disapprove/<int:pk>/` | `disapprove_student_leave` | — (redirect) |
| GET | `/admin/view-staff-leave/` | `view_staff_leave` | `staff_leave_view.html` |
| GET/POST | `/admin/staff-leave/approve/<int:pk>/` | `approve_staff_leave` | — (redirect) |
| GET/POST | `/admin/staff-leave/disapprove/<int:pk>/` | `disapprove_staff_leave` | — (redirect) |
| GET | `/admin/view-student-feedback/` | `student_feedback_message` | `student_feedback_template.html` |
| GET/POST | `/admin/student-feedback/reply/<int:pk>/` | `student_feedback_reply` | — (redirect) |
| GET | `/admin/view-staff-feedback/` | `staff_feedback_message` | `staff_feedback_template.html` |
| GET/POST | `/admin/staff-feedback/reply/<int:pk>/` | `staff_feedback_reply` | — (redirect) |
| POST | `/admin/send-student-notification/` | `send_student_notification` | `student_notification.html` |
| POST | `/admin/send-staff-notification/` | `send_staff_notification` | `staff_notification.html` |
| GET | `/manage-registration-leads/` | `manage_registration_leads` | `manage_registration_leads.html` |
| GET/POST | `/manage-registration-leads/<int:pk>/update/` | `update_registration_lead` | — |
| GET | `/admin/payments/` | `admin_payments` | `manage_payments.html` |
| GET/POST | `/admin/payments/invoice/add/` | `add_invoice` | `add_invoice.html` |
| GET/POST | `/admin/payments/generate/` | `generate_invoices` | `generate_invoices.html` |
| GET/POST | `/admin/payments/record/<int:invoice_id>/` | `record_payment` | `record_payment.html` |
| GET | `/admin/payments/receipt/<int:payment_id>/` | `payment_receipt` | `payment_receipt.html` |
| GET | `/leaderboard/admin/settings/` | `admin_leaderboard_settings` | `admin_leaderboard_settings.html` |
| GET | `/leaderboard/admin/seasons/` | `admin_manage_seasons` | `admin_manage_seasons.html` |
| GET/POST | `/leaderboard/admin/seasons/capture/` | `capture_leaderboard_snapshot` | — |
| GET | `/manage-vocabulary-days/` | `manage_vocabulary_days` | `manage_vocabulary_days.html` |
| GET | `/stories/manage/` | `manage_stories` | `manage_stories.html` |
| GET/POST | `/stories/add/` | `admin_add_story` | `story_form.html` |
| GET/POST | `/stories/<int:pk>/edit/` | `admin_edit_story` | `story_form.html` |
| GET/POST | `/stories/<int:pk>/delete/` | `admin_delete_story` | — (redirect) |

### 7.2 Staff Routes

| Method | URL Pattern | View Function | Template |
|---|---|---|---|
| GET | `/staff/home/` | `staff_home` | `erpnext_staff_home.html` |
| GET | `/staff/view/profile/` | `staff_view_profile` | `staff_view_profile.html` |
| GET/POST | `/staff/take-attendance/` | `staff_take_attendance` | `staff_take_attendance.html` |
| GET/POST | `/staff/update-attendance/` | `staff_update_attendance` | `staff_update_attendance.html` |
| GET/POST | `/staff/add-result/` | `staff_add_result` | `staff_add_result.html` |
| GET/POST | `/staff/edit-student-result/<int:pk>/` | `edit_student_result` | `edit_student_result.html` |
| GET | `/staff/result-files/` | `staff_result_files` | `staff_result_files.html` |
| GET/POST | `/staff/result-file/upload/` | `upload_result_file` | `upload_result_file.html` |
| GET | `/staff/assignments/` | `staff_assignments` | `staff_assignments.html` |
| GET/POST | `/staff/assignment/add/` | `add_assignment` | `add_assignment.html` |
| GET | `/staff/assignment/<int:pk>/submissions/` | `view_submissions` | `view_submissions.html` |
| GET/POST | `/staff/assignment/<int:pk>/grade/<int:sub_id>/` | `grade_submission` | — |
| GET | `/staff/payments/` | `staff_payments` | `staff_payments.html` |
| GET | `/staff/vocabulary-days/` | `staff_vocabulary_days` | `staff_vocabulary_days.html` |
| GET | `/staff/vocabulary-day/<int:pk>/` | `staff_vocabulary_day_detail` | `staff_vocabulary_day_detail.html` |
| GET/POST | `/staff/vocabulary-days/add/` | `add_vocabulary_day` | `add_vocabulary_day.html` |
| GET/POST | `/staff/apply-leave/` | `staff_apply_leave` | `staff_apply_leave.html` |
| GET | `/staff/view-notification/` | `staff_view_notification` | `staff_view_notification.html` |
| GET/POST | `/staff/feedback/` | `staff_feedback` | `staff_feedback.html` |
| GET/POST | `/staff/stories/create/` | `staff_create_story` | `staff_story_form.html` |
| GET/POST | `/staff/book/add/` | `add_book` | `add_book.html` |
| GET/POST | `/staff/book/issue/` | `issue_book` | `issue_book.html` |
| GET | `/staff/book/issued/` | `view_issued_book` | `view_issued_book.html` |

### 7.3 Student Routes

| Method | URL Pattern | View Function | Template |
|---|---|---|---|
| GET | `/student/home/` | `student_home` | `erpnext_student_home.html` |
| GET | `/student/view/profile/` | `student_view_profile` | `student_view_profile.html` |
| GET | `/student/view-attendance/` | `student_view_attendance` | `student_view_attendance.html` |
| GET | `/student/view-result/` | `student_view_result` | `student_view_result.html` |
| GET | `/student/result-files/` | `student_result_files` | `student_result_files.html` |
| GET | `/student/assignments/` | `student_assignments` | `student_assignments.html` |
| GET/POST | `/student/assignment/<int:pk>/submit/` | `submit_assignment` | `submit_assignment.html` |
| GET | `/student/payments/` | `student_payments` | `student_payments.html` |
| GET | `/student/payments/receipt/<int:pk>/` | `student_payment_receipt` | `payment_receipt.html` |
| GET | `/student/vocabulary-days/` | `vocabulary_day_list` | `vocabulary_day_list.html` |
| GET | `/student/vocabulary-day/<int:pk>/` | `vocabulary_day_detail` | `vocabulary_day_detail.html` |
| GET | `/student/vocabulary-day/<int:pk>/flashcard/` | `vocabulary_day_flashcard` | `vocabulary_day_flashcard.html` |
| GET | `/student/vocabulary-day/<int:pk>/quiz/` | `vocabulary_day_quiz` | `vocabulary_day_quiz.html` |
| POST | `/student/vocabulary-day/<int:pk>/complete/` | `mark_vocabulary_day_complete` | — |
| POST | `/student/vocabulary-day/<int:pk>/quiz-result/` | `save_quiz_result` | — |
| GET | `/student/progress/` | `student_progress` | `student_progress.html` |
| GET | `/student/leaderboard/` | `student_leaderboard` | `leaderboard.html` |
| GET | `/student/leaderboard/history/` | `leaderboard_history` | `leaderboard_history.html` |
| GET | `/student/leaderboard/season/<int:pk>/` | `leaderboard_season` | `leaderboard_season.html` |
| GET/POST | `/student/apply-leave/` | `student_apply_leave` | `student_apply_leave.html` |
| GET/POST | `/student/feedback/` | `student_feedback` | `student_feedback.html` |
| GET | `/student/view-notification/` | `student_view_notification` | `student_view_notification.html` |
| GET | `/student/books/` | `view_books` | `view_books.html` |
| POST | `/student/book/return/<int:loan_id>/` | `return_book` | — |

### 7.4 Public / Shared Routes

| Method | URL Pattern | View Function | Template | Auth Required |
|---|---|---|---|---|
| GET | `/` | `entry_page` | `entry.html` | No |
| GET | `/login/` | `login_page` | `login.html` | No |
| POST | `/login/` | `user_login` | — | No |
| GET/POST | `/logout/` | `user_logout` | — | Yes |
| GET | `/profile-hub/` | `profile_hub` | `profile_hub.html` | Yes (all roles) |
| GET | `/messages/` | `messages_view` | `messages.html` | Yes (all roles) |
| GET | `/messages/<int:group_id>/` | `group_chat` | `messages.html` | Yes (all roles) |
| POST | `/messages/<int:group_id>/send/` | `send_message` | — | Yes (all roles) |
| GET/POST | `/forgot-password/` | `forgot_password` | `forgot_password.html` | No |
| GET/POST | `/verify-reset-code/` | `verify_reset_code` | `verify_reset_code.html` | No |
| GET/POST | `/reset-password/` | `reset_password` | `reset_password.html` | No |
| GET | `/password-reset-success/` | `password_reset_success` | — | No |
| GET | `/health/` | health check | — | No |
| POST | `/public/registration-leads` | `registration_lead_webhook` | — | No (public webhook) |

---

## 8. REST API Endpoint Reference

Base prefix: `/api/v1/`

### 8.1 Authentication

| Method | Endpoint | Auth | Request Body | Response |
|---|---|---|---|---|
| POST | `/api/v1/auth/login/` | None | `{identifier, password}` | `{access, refresh, user}` |
| POST | `/api/v1/auth/logout/` | JWT | `{refresh}` | 200 OK |
| POST | `/api/v1/auth/token/refresh/` | None | `{refresh}` | `{access}` |

**Login identifier rules**:
- Admins: use email address
- Staff: use `login_id` (format: `TC{MMDD}{NN}`, e.g. `TC060101`)
- Students: use `login_id` (format: `IC{MMDD}{NN}`, e.g. `IC052401`)

### 8.2 Profile (All Roles)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/me/` | JWT | Own profile (MeSerializer) |
| PATCH | `/api/v1/me/` | JWT | Update profile |
| POST | `/api/v1/me/change-password/` | JWT | Change password: `{old_password, new_password, confirm_password}` |
| POST | `/api/v1/me/fcm-token/` | JWT | Update FCM push token: `{token}` |

**MeSerializer fields**: `id, email, login_id, first_name, last_name, user_type, gender, date_of_birth, profile_pic_url, address, role_profile`

### 8.3 Courses & Groups

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/courses/` | JWT | List active courses |
| GET | `/api/v1/groups/` | JWT | List groups (branch-scoped) |
| GET | `/api/v1/groups/{pk}/` | JWT | Group detail + `enrolled_students` |

### 8.4 Attendance

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/attendance/` | JWT | Student: own records. Admin/Teacher: by `group_id`, `date` |
| POST | `/api/v1/attendance/` | JWT (IsAdminOrTeacher) | Save: `{group_id, date, records: [{student_id, status}]}` |

Status values: `"P"` = Present, `"A"` = Absent, `"L"` = Late.

### 8.5 Results

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/results/` | JWT | Results (branch-scoped) |
| POST | `/api/v1/results/` | JWT (IsAdminOrTeacher) | Create/update: `{student_id, group_id, test, exam, comment}` |

### 8.6 Assignments

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/assignments/` | JWT | List assignments |
| POST | `/api/v1/assignments/` | JWT (IsAdminOrTeacher) | Create assignment |
| GET | `/api/v1/assignments/{pk}/` | JWT | Detail + `my_submission` for student |
| POST | `/api/v1/assignments/{pk}/submit/` | JWT (IsStudent) | Submit: `{file, note}` |

### 8.7 Notifications

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/notifications/` | JWT | List (filter: `category`, `unread=1`) |
| POST | `/api/v1/notifications/mark-all-read/` | JWT | Mark all read |
| POST | `/api/v1/notifications/{pk}/read/` | JWT | Mark one read |

### 8.8 Leave

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/leave/` | JWT | Own (student/staff) or all (admin, filter: `type=student\|staff`, `status`) |
| POST | `/api/v1/leave/` | JWT | Create leave request |
| PATCH | `/api/v1/leave/{pk}/` | JWT (IsAdmin) | Approve (`status=1`) or reject (`status=-1`) |

### 8.9 Feedback

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/feedback/` | JWT | Own (student/staff) or all (admin, filter: `type=student\|staff`) |
| POST | `/api/v1/feedback/` | JWT | Submit feedback |
| PATCH | `/api/v1/feedback/{pk}/` | JWT (IsAdmin) | Add admin reply |

### 8.10 Invoices

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/invoices/` | JWT | Student: own. Admin: all |
| GET | `/api/v1/invoices/{pk}/` | JWT | Invoice detail |

### 8.11 Dashboard

| Method | Endpoint | Auth | Response |
|---|---|---|---|
| GET | `/api/v1/student/home/` | JWT (IsStudent) | `{attendance_percentage, total_subjects, average_score, enrolled_groups, notices, stories}` |
| GET | `/api/v1/admin/home/` | JWT (IsAdmin) | `{total_students, total_staff, total_groups, avg_attendance, new_leads, total_branches}` |
| GET | `/api/v1/stats/` | JWT (IsAdminOrTeacher) | Staff/admin stats |

### 8.12 Admin User Management APIs

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/admin/stats/` | JWT (IsAdmin) | Total student/staff/group counts |
| GET/POST | `/api/v1/admin/users/` | JWT (IsAdmin) | List users |
| GET | `/api/v1/admin/groups/` | JWT (IsAdmin) | List groups |
| POST/DELETE | `/api/v1/admin/enroll/` | JWT (IsAdmin) | Enroll/unenroll student |
| GET/POST | `/api/v1/admin/students/` | JWT (IsAdmin) | List/create students |
| GET/PATCH | `/api/v1/admin/students/{pk}/` | JWT (IsAdmin) | Student detail/update |
| GET/POST | `/api/v1/admin/staff/` | JWT (IsAdmin) | List/create staff |
| GET/PATCH | `/api/v1/admin/staff/{pk}/` | JWT (IsAdmin) | Staff detail/update |
| GET/POST | `/api/v1/admin/leads/` | JWT (IsAdmin) | List/create registration leads |
| PATCH | `/api/v1/admin/leads/{pk}/` | JWT (IsAdmin) | Update lead status |
| GET | `/api/v1/admin/branches/` | JWT (IsAdmin) | List branches |

### 8.13 Admin CRUD APIs (admin_views.py)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET/POST | `/api/v1/admin/branches-manage/` | JWT (IsAdmin) | List/create branches |
| GET/PATCH/DELETE | `/api/v1/admin/branches-manage/{pk}/` | JWT (IsAdmin) | Branch CRUD |
| GET/POST | `/api/v1/admin/courses/` | JWT (IsAdmin) | List/create courses |
| GET/PATCH/DELETE | `/api/v1/admin/courses/{pk}/` | JWT (IsAdmin) | Course CRUD |
| GET/POST | `/api/v1/admin/sessions/` | JWT (IsAdmin) | List/create sessions |
| GET/PATCH/DELETE | `/api/v1/admin/sessions/{pk}/` | JWT (IsAdmin) | Session CRUD |
| GET/POST | `/api/v1/admin/subjects/` | JWT (IsAdmin) | List/create subjects |
| GET/PATCH/DELETE | `/api/v1/admin/subjects/{pk}/` | JWT (IsAdmin) | Subject CRUD |
| GET | `/api/v1/admin/groups/{pk}/` | JWT (IsAdmin) | Group detail + enrolled students |
| GET/POST | `/api/v1/admin/enrollments/` | JWT (IsAdmin) | List/create enrollments |
| GET | `/api/v1/admin/leave-requests/` | JWT (IsAdmin) | All leave requests |
| PATCH | `/api/v1/admin/leave-requests/{pk}/` | JWT (IsAdmin) | Approve/reject leave |
| GET | `/api/v1/admin/attendance-report/` | JWT (IsAdmin) | Attendance report |
| GET/POST | `/api/v1/admin/stories/` | JWT (IsAdmin) | List/create stories |
| GET/PATCH/DELETE | `/api/v1/admin/stories/{pk}/` | JWT (IsAdmin) | Story CRUD |
| POST | `/api/v1/admin/send-notification/` | JWT (IsAdmin) | Broadcast notification |
| GET | `/api/v1/admin/invoices-manage/` | JWT (IsAdmin) | All invoices |
| POST | `/api/v1/admin/invoices-manage/{pk}/pay/` | JWT (IsAdmin) | Record payment |

### 8.14 Vocabulary (Student)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/vocabulary/` | JWT (IsStudent) | Released vocabulary days for enrolled groups |
| GET | `/api/v1/vocabulary/{pk}/` | JWT (IsStudent) | Day detail + words |
| POST | `/api/v1/vocabulary/{pk}/complete/` | JWT (IsStudent) | Mark day complete |
| GET | `/api/v1/vocabulary/{pk}/quiz/` | JWT (IsStudent) | Quiz questions |
| POST | `/api/v1/vocabulary/{pk}/quiz-result/` | JWT (IsStudent) | Save quiz result: `{score, total}` |

### 8.15 Staff Vocabulary Management

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/staff/vocabulary/` | JWT (IsTeacher) | Teacher's vocabulary days |
| POST | `/api/v1/staff/vocabulary/create/` | JWT (IsTeacher) | Create vocabulary day |
| GET/PATCH/DELETE | `/api/v1/staff/vocabulary/{pk}/` | JWT (IsTeacher) | Day CRUD |
| GET/POST | `/api/v1/staff/vocabulary/{pk}/words/` | JWT (IsTeacher) | List/add words |
| DELETE | `/api/v1/staff/vocabulary/{pk}/words/{word_pk}/` | JWT (IsTeacher) | Delete word |

### 8.16 Student Progress

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/student/progress/` | JWT (IsStudent) | Progress data (attendance %, quiz scores, assignments) |

### 8.17 Stories

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/stories/` | JWT | List active stories |
| POST | `/api/v1/stories/create/` | JWT (IsAdminOrTeacher) | Create story |
| GET/DELETE | `/api/v1/stories/{pk}/` | JWT | Story detail/delete |

### 8.18 Leaderboard

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/v1/leaderboard/` | JWT | Active season + entries |

### 8.19 File Upload

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/v1/upload/` | JWT (IsAdminOrTeacher) | Upload result file: `{file, group_id, student_id, title, description}` |

**Note**: See Bug #3 — admin uploads via this endpoint cause `IntegrityError` because `ResultFile.uploaded_by` is non-nullable FK to `Staff`.

---

## 9. Authentication & Access Control

### 9.1 Web Login Flow

```
POST /login/
  form fields: identifier, password

EmailBackend.authenticate():
  1. Try CustomUser.objects.get(email=identifier)
  2. If not found: try CustomUser.objects.get(login_id=identifier)
  3. Check password hash
  4. Check is_active
  5. Return user or None

LoginCheckMiddleWare:
  - Unauthenticated → /login/
  - user_type '1' accessing /student/* or /staff/* → /admin/home/
  - user_type '2' accessing /admin/* or /student/* → /staff/home/
  - user_type '3' accessing /admin/* or /staff/* → /student/home/
```

### 9.2 Login ID Format

| Role | Format | Example | Generation Logic |
|---|---|---|---|
| Student | `IC{MMDD}{NN}` | `IC052401` | DOB-based (MM=05, DD=24), NN=01 for first student that day |
| Teacher | `TC{MMDD}{NN}` | `TC060101` | DOB-based (MM=06, DD=01), NN=01 for first teacher that day |
| Admin | Email | `admin@iceberg.uz` | Email-based login, no login_id |

Fallback: sequential suffix if DOB unavailable or collision.

### 9.3 Role-Based Access Decorators

```python
@admin_only   # user_type must be '1'; else redirect to login
@staff_only   # user_type must be '2'; else redirect to login
@student_only # user_type must be '3'; else redirect to login
```

### 9.4 API Permission Classes (DRF)

```python
class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.user_type == '1'

class IsTeacher(BasePermission):
    def has_permission(self, request, view):
        return request.user.user_type == '2'

class IsStudent(BasePermission):
    def has_permission(self, request, view):
        return request.user.user_type == '3'

class IsAdminOrTeacher(BasePermission):
    def has_permission(self, request, view):
        return request.user.user_type in ('1', '2')
```

### 9.5 Branch-Level Access Control

```python
def user_can_access_group(user, group):
    if user.user_type == '1':  # Admin
        admin = Admin.objects.get(admin=user)
        if admin.is_super_admin:
            return True
        return group.branch in admin.branches.all()
    elif user.user_type == '2':  # Staff
        staff = Staff.objects.get(staff=user)
        return group in staff.groups.all()
    elif user.user_type == '3':  # Student
        student = Student.objects.get(student=user)
        return Enrollment.objects.filter(student=student, group=group).exists()
    return False
```

### 9.6 Password Reset Flow

Multi-step OTP flow:
```
/forgot-password/  → User enters email
        ↓
  PasswordResetCode created (6-digit code, TTL 15 min)
  Code sent via email
        ↓
/verify-reset-code/ → User enters 6-digit code
        ↓
/reset-password/    → User enters new password (code verified in session)
        ↓
/password-reset-success/
```

### 9.7 Rate Limiting

Login rate limiting is implemented. On too many failed attempts, Django raises `PermissionDenied` → displayed as "Account temporarily locked".

### 9.8 JWT Authentication (API)

```
POST /api/v1/auth/login/ → {access: "...", refresh: "..."}

All subsequent API calls:
  Authorization: Bearer <access_token>

Token refresh:
  POST /api/v1/auth/token/refresh/ → {access: "..."}

Logout (blacklists refresh token):
  POST /api/v1/auth/logout/ with {refresh: "..."}
```

Access token lifetime: ~15 min (simplejwt default).
Refresh token lifetime: ~7 days.
Blacklist: `simplejwt.token_blacklist` app installed.

---

## 10. Feature Catalog & Special Behaviors

### 10.1 Platform Detection & Theming

**Implementation**:
1. `platform-detect.js` runs synchronously in `<head>` before any render
2. Reads `navigator.userAgent` → adds class to `<html>`
3. Also reads `localStorage['ice_ui_theme']` and sets `data-theme` before CSS loads (prevents FOUC)
4. `mobile-adaptive.css` applies different visual treatments per platform class

**iOS liquid glass effect**:
```css
html.platform-apple .navbar,
html.platform-apple .sidebar {
  background: rgba(6, 52, 58, 0.85);
  backdrop-filter: blur(20px) saturate(180%);
}
```

### 10.2 Dark/Light Theme

**Storage**:
- Admin/Staff: `localStorage['ice_ui_theme']` = `"dark"` | `"light"`
- Students: DB field → server renders `data-theme` on `<html>`, preventing flash

**Toggle mechanism** (`profile-hub.js`):
1. Click theme button
2. Update `html[data-theme]` attribute
3. Update `localStorage` (admin/staff) or POST to `/api/v1/me/` (student)
4. Call `recreateAllCharts()` to re-render charts with new colors

### 10.3 Service Worker / PWA

- Registered at `/sw.js`
- Caches static CSS, JS, fonts, images
- Offline fallback page served from cache
- FCM registration done after SW install

### 10.4 Firebase Cloud Messaging

- `fcm_token` stored on `CustomUser`
- Updated via `POST /api/v1/me/fcm-token/`
- Push notifications delivered when app is in background/closed

### 10.5 Chart.js Integration

Charts appear on:
- **Admin dashboard** (`home_content.html`): enrollment trend, attendance bar chart
- **Staff dashboard** (`erpnext_staff_home.html`): group attendance sparklines
- **Student progress** (`student_progress.html`): attendance % line chart, quiz score trend
- **Student leaderboard** (`leaderboard.html`): score breakdown bar chart

Helper: `trend-chart.js` exports `createTrendChart(canvasId, labels, data)`.
On theme toggle, `recreateAllCharts()` updates all `Chart.instances`.

### 10.6 Sidebar Collapse

**Desktop**: Toggle button collapses to icon-only (~60px). State saved in `localStorage['ice_sidebar_collapsed']`.

**Mobile**: Sidebar is off-screen by default. Hamburger button adds `.sidebar-open` to `body`. Overlay tap closes it.

### 10.7 Responsive Tables → Card Reflow

Two-step process:
1. **JS** (`responsive-tables.js`): Injects `data-label` on every `<td>` from `<th>` text
2. **CSS** (`mobile-adaptive.css`): At `max-width: 768px`, `<td>` becomes block with `::before { content: attr(data-label) }`

Result: tables become stacked label+value cards on mobile without template changes.

### 10.8 Avatar Stickers

24 emoji avatars with colored circular backgrounds in the sidebar profile row and profile hub. Selected avatar stored on `CustomUser`.

### 10.9 Vocabulary System

**Model chain**:
```
VocabularyDay (created by teacher, scoped to groups)
  └── VocabularyDayWord (word + translation + optional image)
       └── VocabularyDayCompletion (student has_studied)
VocabularyQuizResult (student score per VocabularyDay)
```

**Student flow**:
1. `/student/vocabulary-days/` — list released days
2. `/student/vocabulary-day/{pk}/` — word list (study mode)
3. `/student/vocabulary-day/{pk}/flashcard/` — flashcard mode (CSS flip animation)
4. `/student/vocabulary-day/{pk}/quiz/` — multiple choice quiz
5. `POST .../quiz-result/` — saves `{score, total}`
6. `POST .../complete/` — marks as complete

**Flashcard flip animation**:
```css
.flashcard-inner {
  transition: transform 0.6s;
  transform-style: preserve-3d;
}
.flashcard.flipped .flashcard-inner {
  transform: rotateY(180deg);
}
```

### 10.10 Leaderboard System

**Models**: `LeaderboardSettings` (singleton pk=1), `LeaderboardSeason`, `LeaderboardSnapshot`

**Score calculation**: Weighted sum of attendance, homework, quizzes, results using configurable weights.

**Admin workflow**:
1. `/leaderboard/admin/settings/` — configure weights, set active season
2. `/leaderboard/admin/seasons/` — manage seasons
3. `POST /leaderboard/admin/seasons/capture/` — capture current snapshot

**Student views**: current season → history → specific season.
**Medal colors**: 1st=`--gold`, 2nd=`--silver`, 3rd=`--bronze`.

### 10.11 Stories (Instagram-Style)

**Model**: `DashboardStory` — `target_groups` (M2M to Group), shown on student dashboard for enrolled groups. Horizontal scrollable story card row at top of student dashboard.

### 10.12 Payment System

**Currency**: UZS soʻm (all monetary amounts in soʻm).

**Models**: `Invoice` (amount, due_date, status) → `Payment` (amount_paid, paid_date, receipt_number)

**Admin workflow**: Generate invoices (bulk or individual) → Record payment → Print receipt.
**Student view**: Invoice cards + payment history + receipt links.

### 10.13 Library System

**Model**: `Loan` — 14-day loan period, overdue fine calculated at 5/day (⚠️ displayed as ₹5 — Bug #7).

**Staff**: Add Book → Issue Book → View Issued Books
**Student**: View loans at `/student/books/` → `POST /student/book/return/{loan_id}/`

### 10.14 Group Chat

**Models**: `ChatThread` (one per Group) + `ChatMessage` (text + attachments) + `ChatReadState` (for unread counts)

**Unread dot**: Bottom nav Chat tab shows red dot when `ChatMessage.created_at > ChatReadState.last_read_at`.

### 10.15 Registration Leads Webhook

**Endpoint**: `POST /public/registration-leads` — no auth required. Receives leads from external marketing forms.

**Model**: `RegistrationLead` — `branch` field is a free-text `CharField`, not FK (see Bug #6).

### 10.16 OpenGraph / Twitter Card Meta Tags

All pages output via `base.html`:
```html
<meta property="og:title" content="ICEBERG Study Center">
<meta property="og:image" content="{{ og_image_url }}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary_large_image">
```

### 10.17 Animated Page Transitions

```css
@keyframes iceContentIn {
  from { opacity: 0; transform: translateY(8px); }
  to   { opacity: 1; transform: translateY(0); }
}
.main-content { animation: iceContentIn 0.2s ease-out; }
```

### 10.18 Safe Actions (Destructive Confirmation)

```html
<a href="/student/delete/5/" data-confirm="Delete this student? This cannot be undone.">Delete</a>
```

`safe-actions.js` intercepts click and shows `confirm()` dialog.

### 10.19 Animated Logout

`animated_logout_button.html` partial: button + hidden `<form method="POST" action="/logout/">`.
`animated-logout.js`: animation → form submit (600ms delay).
JS-optional: form submits normally without JS.

---

## 11. Role-Based Feature Matrix

### 11.1 Complete Feature Access Matrix

| Feature | Admin (1) | Staff (2) | Student (3) |
|---|---|---|---|
| **Dashboard** | Admin home | Staff home | Student home |
| **Profile & Settings** | `/profile-hub/` | `/profile-hub/` | `/profile-hub/` |
| **Theme Toggle** | localStorage | localStorage | DB-stored |
| **Dark Mode** | Yes | Yes | Yes |
| **Manage Students** | Full CRUD | View own groups | Own profile |
| **Manage Staff** | Full CRUD | Own profile | No |
| **Manage Admins** | Full CRUD | No | No |
| **Manage Courses** | Full CRUD | No | No |
| **Manage Subjects** | Full CRUD | No | No |
| **Manage Sessions** | Full CRUD | No | No |
| **Manage Branches** | Full CRUD | No | No |
| **Manage Groups** | Full CRUD + archive | Assigned groups | No |
| **Manage Enrollments** | Full CRUD | No | No |
| **Attendance — Take** | View all | Take (own groups) | No |
| **Attendance — Update** | Edit all | Edit (own groups) | No |
| **Attendance — View** | All groups | Own groups | Own record |
| **Scores/Results** | View all | Add/edit (own groups) | View own |
| **Result Files** | View all | Upload/manage | View own |
| **Assignments** | View all | Create/grade | Submit/view own |
| **Payments** | Full management | Read-only (own groups) | View own invoices |
| **Vocabulary Days** | Manage all | Create/edit (own groups) | Study/quiz |
| **Vocabulary Flashcards** | No | No | Yes |
| **Vocabulary Quiz** | No | No | Yes |
| **Leaderboard — View** | Settings/manage | No | Yes |
| **Leaderboard — Configure** | Yes | No | No |
| **Stories — View** | Admin manage | Create for groups | Dashboard carousel |
| **Stories — Create** | Yes | Yes | No |
| **Library — Add Books** | No | Yes | No |
| **Library — Issue Books** | No | Yes | No |
| **Library — View/Return** | No | View all | Own loans |
| **Chat/Messages** | All groups | Own groups | Enrolled groups |
| **Notifications — Send** | Yes (to students/staff) | No | No |
| **Notifications — Receive** | Limited (Bug #1) | Yes | Yes |
| **Leave — Submit** | No | Yes | Yes |
| **Leave — Approve** | Yes | No | No |
| **Feedback — Submit** | No | Yes | Yes |
| **Feedback — Reply** | Yes | No | No |
| **Registration Leads** | Manage | No | No |
| **Student Progress** | No | No | Yes |
| **Branch Access** | All (super) or assigned | Assigned groups | Own data |

### 11.2 Dashboard Stats by Role

**Admin Dashboard** (`/api/v1/admin/home/`):
- Total students, staff, groups count
- Average attendance percentage
- New registration leads count
- Total branches
- Enrollment trend chart (last 6 months)
- Top groups by attendance

**Staff Dashboard** (`/api/v1/stats/`):
- Assigned groups count
- Total students in groups
- Attendance taken today per group
- Pending assignment submissions

**Student Dashboard** (`/api/v1/student/home/`):
- Attendance percentage (this month)
- Total subjects enrolled
- Average score (test + exam average)
- Enrolled groups count
- Notices/notifications
- Stories carousel
- Upcoming vocabulary days

---

## 12. Known Bugs & Inconsistencies

### Bug #1 — Admin Notification Page Missing

**Severity**: Medium  
**Description**: Admin has no dedicated notification page. The notification bell in the navbar for `user_type == '1'` links to `/messages/` (the chat page) rather than a notification-specific page.  
**Impact**: Admins cannot view system notifications; redirected to chat instead.  
**Fix**: Create `admin_view_notification` view + template, add URL at `/admin/view-notification/`, wire up navbar bell.

### Bug #2 — Login Page Missing Password Reset Link

**Severity**: Low (UX inconsistency)  
**Description**: The login page shows "Contact admin to reset your password" — however, a full self-service password reset flow EXISTS at `/forgot-password/`. The login page simply does not link to it.  
**Impact**: Users who forget passwords unnecessarily contact admin.  
**Fix**: Replace "Contact admin" text with `<a href="/forgot-password/">Forgot your password?</a>`.

### Bug #3 — Admin ResultFile Upload IntegrityError

**Severity**: High (data integrity)  
**Description**: When `user_type == '1'` (Admin) uploads via `POST /api/v1/upload/`, the view sets `staff = None`. However, `ResultFile.uploaded_by` is `ForeignKey(Staff, on_delete=CASCADE)` with `null=False`. Saving causes `IntegrityError`.  
**Impact**: Admins cannot upload result files via API — 500 error.  
**Fix options**:
- Make `uploaded_by` nullable: `ForeignKey(Staff, null=True, blank=True)`
- Use `GenericForeignKey` to support both Admin and Staff uploaders

### Bug #4 — Branch Admin Cannot Create Groups (Null Branch)

**Severity**: Medium  
**Description**: When a group is created without a branch (`branch=None`), `user_can_access_group()` returns `False` for branch admins because `None in admin.branches.all()` is always `False`.  
**Impact**: Branch admins lose access to groups they created if branch field is null.  
**Fix**: Require branch on group creation for branch admins, or handle null in `user_can_access_group()`.

### Bug #5 — LeaderboardSettings Singleton pk=1 Hardcoded

**Severity**: Low (code quality)  
**Description**: `LeaderboardSettings` is fetched using `pk=1` hardcoded. If DB is reset without fixtures, views crash with `DoesNotExist`.  
**Fix**: Use `LeaderboardSettings.objects.get_or_create(pk=1)` consistently.

### Bug #6 — RegistrationLead.branch is Free-Text CharField

**Severity**: Medium (data integrity)  
**Description**: `RegistrationLead.branch` is a `CharField`, not a `ForeignKey` to `Branch`. Branch matching in webhook handler uses case-insensitive string comparison. Typos in webhook payload result in unmatched branches.  
**Fix**: Change to `ForeignKey(Branch, null=True, blank=True)` and resolve the FK on webhook ingestion.

### Bug #7 — Library Fine Shows ₹ (Indian Rupee) Instead of soʻm

**Severity**: Low (cosmetic)  
**Description**: Overdue fine displayed as `₹5/day` (Indian Rupee) when system is in Uzbekistan and all other monetary values use UZS soʻm.  
**Fix**: Replace `₹` with `so'm` or UZS in all fine-related display text.

### Bug #8 — Story Edit/Delete Has No Branch Scoping — ✅ FIXED

**Severity**: Medium (authorization gap)  
**Description**: `edit_story` and `delete_story` in `hod_views.py` did `get_object_or_404(DashboardStory, id=story_id)` with **no branch or ownership check**. The REST API had the same class of hole: `AdminStoriesDetailView.patch` had no scoping at all, and `.delete` allowed any branch admin to delete global stories and used overlap (not subset) matching.  
**Fix applied**: New `_user_can_modify_story(user, story)` guard in both `hod_views.py` and `api/admin_views.py`: superadmin → anything; branch admin → only stories they authored OR stories whose *every* target group is within their accessible branches; global stories are modifiable only by their author or a superadmin. Verified live: cross-branch admin gets flash-error redirect (HTML) / 403 (API).

### Bug #9 — Library Endpoints Not Branch/Ownership Scoped — ✅ FIXED

**Severity**: Low–Medium  
**Description**: `view_issued_book` listed **all** loans system-wide, `return_book` let any staff member return any loan, and `issue_book`'s student dropdown offered every student in the system. `get_student_attendance` (staff) also fetched any `attendance_date_id` without verifying group ownership (the write path `update_attendance` WAS guarded; the read path was not).  
**Fix applied**: New `_library_students_for_staff(staff)` helper scopes all three lending views — branch-assigned staff see students of their branch (explicit branch, or group-derived branch for legacy null-branch records); staff without a branch fall back to students enrolled in their own groups. `get_student_attendance` now enforces `attendance.group.teacher_id == staff.id` → 403, mirroring the write path. Verified live with Django test client: owner teacher 200, other teacher 403. (Also replaced the ₹ fine symbol with so'm in the return flash message — partial Bug #7 fix.)

---

## 13. Data Models Reference

### 13.1 Core User Models

#### `CustomUser` (extends AbstractUser)

| Field | Type | Notes |
|---|---|---|
| `email` | EmailField (unique) | Primary identifier for admin login |
| `login_id` | CharField (unique, nullable) | `IC{MMDD}{NN}` students, `TC{MMDD}{NN}` teachers |
| `user_type` | CharField choices | `'1'`=Admin, `'2'`=Staff, `'3'`=Student |
| `gender` | CharField | `'M'`/`'F'`/`'O'` |
| `date_of_birth` | DateField (nullable) | Used for login_id generation |
| `profile_pic` | ImageField (nullable) | Stored on DigitalOcean Spaces |
| `address` | TextField (nullable) | |
| `fcm_token` | CharField (nullable) | Firebase push notification token |
| `theme_preference` | CharField (nullable) | `'dark'`/`'light'` — student DB-stored theme |

#### `Admin`

| Field | Type | Notes |
|---|---|---|
| `admin` | OneToOneField(CustomUser) | |
| `branches` | ManyToManyField(Branch) | Managed branches |
| `is_super_admin` | BooleanField | Super admin sees all branches |

#### `Staff`

| Field | Type | Notes |
|---|---|---|
| `staff` | OneToOneField(CustomUser) | |
| `course` | ForeignKey(Course) | Primary course taught |
| `groups` | ManyToManyField(Group) | Assigned teaching groups |
| `branch` | ForeignKey(Branch) | Primary branch |

#### `Student`

| Field | Type | Notes |
|---|---|---|
| `student` | OneToOneField(CustomUser) | |
| `branch` | ForeignKey(Branch) | Student's branch |
| `course` | ForeignKey(Course) | Enrolled course |
| `session` | ForeignKey(Session) | Academic session |

### 13.2 Academic Structure Models

#### `Session`

| Field | Type | Notes |
|---|---|---|
| `start_year` | DateField | |
| `end_year` | DateField | |

#### `Branch`

| Field | Type | Notes |
|---|---|---|
| `name` | CharField | Branch name (e.g., "Tashkent") |
| `address` | TextField (nullable) | |

#### `Course`

| Field | Type | Notes |
|---|---|---|
| `course_name` | CharField | e.g., "IELTS Preparation" |
| `created_at` | DateTimeField (auto) | |

#### `Subject`

| Field | Type | Notes |
|---|---|---|
| `subject_name` | CharField | e.g., "Reading", "Writing" |
| `course` | ForeignKey(Course) | |
| `staff` | ForeignKey(Staff) | Assigned teacher |

#### `Group`

| Field | Type | Notes |
|---|---|---|
| `name` | CharField | e.g., "IELTS-A1" |
| `course` | ForeignKey(Course) | |
| `branch` | ForeignKey(Branch, nullable) | Can be null — see Bug #4 |
| `session` | ForeignKey(Session) | |
| `is_archived` | BooleanField | Archived groups hidden from active lists |

#### `Enrollment`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `group` | ForeignKey(Group) | |
| `enrolled_at` | DateTimeField (auto) | |
| `is_active` | BooleanField | |

### 13.3 Attendance Models

#### `Attendance`

| Field | Type | Notes |
|---|---|---|
| `group` | ForeignKey(Group) | |
| `attendance_date` | DateField | |
| `created_at` | DateTimeField (auto) | |

#### `AttendanceReport`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `attendance` | ForeignKey(Attendance) | |
| `status` | BooleanField | True=Present, False=Absent |

### 13.4 Communication Models

#### `Notification`

| Field | Type | Notes |
|---|---|---|
| `user` | ForeignKey(CustomUser) | Recipient |
| `message` | TextField | |
| `category` | CharField | e.g., 'leave', 'result', 'general' |
| `is_read` | BooleanField | |
| `created_at` | DateTimeField (auto) | |

#### `LeaveReportStudent`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `date` | DateField | |
| `message` | TextField | |
| `status` | IntegerField | `0`=Pending, `1`=Approved, `-1`=Rejected |

#### `LeaveReportStaff`

| Field | Type | Notes |
|---|---|---|
| `staff` | ForeignKey(Staff) | |
| `date` | DateField | |
| `message` | TextField | |
| `status` | IntegerField | `0`=Pending, `1`=Approved, `-1`=Rejected |

#### `FeedbackStudent`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `feedback` | TextField | |
| `reply` | TextField (nullable) | Admin reply |
| `created_at` | DateTimeField (auto) | |

#### `FeedbackStaff`

| Field | Type | Notes |
|---|---|---|
| `staff` | ForeignKey(Staff) | |
| `feedback` | TextField | |
| `reply` | TextField (nullable) | Admin reply |
| `created_at` | DateTimeField (auto) | |

### 13.5 Chat Models

#### `ChatThread`

| Field | Type | Notes |
|---|---|---|
| `group` | OneToOneField(Group) | One thread per group |
| `created_at` | DateTimeField (auto) | |

#### `ChatMessage`

| Field | Type | Notes |
|---|---|---|
| `thread` | ForeignKey(ChatThread) | |
| `sender` | ForeignKey(CustomUser) | |
| `content` | TextField | Message text |
| `attachment` | FileField (nullable) | Optional file |
| `created_at` | DateTimeField (auto) | |

#### `ChatReadState`

| Field | Type | Notes |
|---|---|---|
| `user` | ForeignKey(CustomUser) | |
| `thread` | ForeignKey(ChatThread) | |
| `last_read_at` | DateTimeField | For unread count calculation |

### 13.6 Assessment Models

#### `StudentResult`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `group` | ForeignKey(Group) | |
| `subject` | ForeignKey(Subject, nullable) | |
| `test` | FloatField | Score 0–40 |
| `exam` | FloatField | Score 0–60 |
| `comment` | TextField (nullable) | Teacher comment |
| `created_at` | DateTimeField (auto) | |

#### `Assignment`

| Field | Type | Notes |
|---|---|---|
| `title` | CharField | |
| `description` | TextField | |
| `group` | ForeignKey(Group) | |
| `created_by` | ForeignKey(Staff) | |
| `due_date` | DateTimeField | |
| `file` | FileField (nullable) | Assignment brief |
| `created_at` | DateTimeField (auto) | |

#### `Submission`

| Field | Type | Notes |
|---|---|---|
| `assignment` | ForeignKey(Assignment) | |
| `student` | ForeignKey(Student) | |
| `file` | FileField | Submitted file |
| `note` | TextField (nullable) | |
| `grade` | FloatField (nullable) | Teacher grade |
| `submitted_at` | DateTimeField (auto) | |

#### `ResultFile`

| Field | Type | Notes |
|---|---|---|
| `title` | CharField | |
| `description` | TextField (nullable) | |
| `file` | FileField | |
| `group` | ForeignKey(Group) | |
| `student` | ForeignKey(Student, nullable) | Student-specific if set |
| `uploaded_by` | ForeignKey(Staff) | Non-nullable — see Bug #3 |
| `uploaded_at` | DateTimeField (auto) | |

### 13.7 Payment Models

#### `Invoice`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `group` | ForeignKey(Group, nullable) | |
| `session` | ForeignKey(Session) | |
| `amount` | DecimalField | UZS soʻm |
| `due_date` | DateField | |
| `status` | CharField | `'pending'`/`'paid'`/`'overdue'` |
| `created_at` | DateTimeField (auto) | |

#### `Payment`

| Field | Type | Notes |
|---|---|---|
| `invoice` | ForeignKey(Invoice) | |
| `amount_paid` | DecimalField | UZS soʻm |
| `paid_date` | DateField | |
| `notes` | TextField (nullable) | |
| `receipt_number` | CharField (auto-generated) | |

### 13.8 Vocabulary Models

#### `VocabularyDay`

| Field | Type | Notes |
|---|---|---|
| `title` | CharField | e.g., "Day 5 — Weather" |
| `groups` | ManyToManyField(Group) | Target groups |
| `created_by` | ForeignKey(Staff) | |
| `is_released` | BooleanField | Only released days visible to students |
| `created_at` | DateTimeField (auto) | |

#### `VocabularyDayWord`

| Field | Type | Notes |
|---|---|---|
| `day` | ForeignKey(VocabularyDay) | |
| `word` | CharField | English word |
| `translation` | CharField | Uzbek/Russian translation |
| `image` | ImageField (nullable) | Optional illustration |
| `example_sentence` | TextField (nullable) | |

#### `VocabularyDayCompletion`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `day` | ForeignKey(VocabularyDay) | |
| `completed_at` | DateTimeField (auto) | |

#### `VocabularyQuizResult`

| Field | Type | Notes |
|---|---|---|
| `student` | ForeignKey(Student) | |
| `day` | ForeignKey(VocabularyDay) | |
| `score` | IntegerField | Correct answers |
| `total` | IntegerField | Total questions |
| `taken_at` | DateTimeField (auto) | |

### 13.9 Leaderboard Models

#### `LeaderboardSettings` (singleton)

| Field | Type | Notes |
|---|---|---|
| `pk` | `1` (hardcoded) | Singleton pattern — see Bug #5 |
| `attendance_weight` | FloatField | Weight for attendance |
| `homework_weight` | FloatField | Weight for assignments |
| `quiz_weight` | FloatField | Weight for vocabulary quizzes |
| `result_weight` | FloatField | Weight for test/exam results |
| `is_active` | BooleanField | Enable/disable leaderboard |

#### `LeaderboardSeason`

| Field | Type | Notes |
|---|---|---|
| `name` | CharField | e.g., "Spring 2026" |
| `start_date` | DateField | |
| `end_date` | DateField | |
| `is_active` | BooleanField | Only one active at a time |

#### `LeaderboardSnapshot`

| Field | Type | Notes |
|---|---|---|
| `season` | ForeignKey(LeaderboardSeason) | |
| `captured_at` | DateTimeField (auto) | |
| `scores` | JSONField | `{student_id: score, ...}` |

### 13.10 Stories Model

#### `DashboardStory`

| Field | Type | Notes |
|---|---|---|
| `title` | CharField | |
| `content` | TextField | |
| `image` | ImageField (nullable) | |
| `target_groups` | ManyToManyField(Group) | Which groups see this story |
| `is_active` | BooleanField | |
| `created_by` | ForeignKey(CustomUser) | Admin or Staff |
| `created_at` | DateTimeField (auto) | |

### 13.11 Library Models

#### `Book`

| Field | Type | Notes |
|---|---|---|
| `title` | CharField | |
| `author` | CharField | |
| `isbn` | CharField (unique, nullable) | |
| `quantity` | IntegerField | Total copies |
| `available` | IntegerField | Available copies |
| `added_by` | ForeignKey(Staff) | |

#### `Loan`

| Field | Type | Notes |
|---|---|---|
| `book` | ForeignKey(Book) | |
| `student` | ForeignKey(Student) | |
| `issued_by` | ForeignKey(Staff) | |
| `issued_date` | DateField (auto today) | |
| `due_date` | DateField | issued_date + 14 days |
| `returned_date` | DateField (nullable) | |
| `fine_amount` | DecimalField | Overdue fine (displayed as ₹5/day — see Bug #7) |

### 13.12 Registration Lead Model

#### `RegistrationLead`

| Field | Type | Notes |
|---|---|---|
| `name` | CharField | Prospective student name |
| `phone` | CharField | |
| `email` | EmailField (nullable) | |
| `branch` | CharField | Free text — NOT FK (see Bug #6) |
| `status` | CharField | `'new'`/`'contacted'`/`'enrolled'`/`'rejected'` |
| `notes` | TextField (nullable) | |
| `created_at` | DateTimeField (auto) | |

### 13.13 Auth Models

#### `PasswordResetCode`

| Field | Type | Notes |
|---|---|---|
| `user` | ForeignKey(CustomUser) | |
| `code` | CharField | 6-digit OTP |
| `created_at` | DateTimeField (auto) | |
| `is_used` | BooleanField | Single-use |
| `expires_at` | DateTimeField | created_at + 15 min |

---

*End of FRONTEND_DEEP_ANALYSIS.md*  
*Document covers: 18 CSS files, 12 JS files, 100+ templates, 80+ URL routes, 50+ API endpoints, 30+ data models, 7 known bugs.*

---

## 14. Visual Browser Study (Live Testing)

**Method:** Django server run locally (`DJANGO_DEBUG=True`, port 8877). Playwright Chromium drove the real UI at desktop (1366px) and mobile (390px) widths. Logged in as all 3 roles with real test accounts (admin via email, staff via `TC052401`, student via `IC052401`). 60+ screenshots captured at `/tmp/erp_shots/`.

### 14.1 Pages Tested (all returned HTTP 200, no JS errors, no horizontal overflow)

**Admin (13 pages × 2 widths):** `/admin/home/`, `/student/manage/`, `/staff/manage/`, `/group/manage/`, `/course/manage/`, `/branch/manage/`, `/admin/manage/`, `/admin/add/`, `/admin/registration-leads/`, `/admin/payments/`, `/admin/stories/`, `/attendance/view/`, `/profile/`

**Staff (7 pages × 2 widths):** `/staff/home/`, `/staff/attendance/take/`, `/staff/result/add/`, `/staff/feedback/`, `/staff/apply/leave/`, `/staff/vocabulary-days/`, `/staff/assignments/`

**Student (7 pages × 2 widths):** `/student/home/`, `/student/view/attendance/`, `/student/view/result/`, `/student/feedback/`, `/student/apply/leave/`, `/student/vocabulary-days/`, `/student/leaderboard/`

### 14.2 Visual Observations

| Area | Observation |
|------|-------------|
| Design system | ICEBERG teal/lime rebrand is live and consistent: navy `#06343A` heroes, lime `#DFFF2F` active states, white cards on `#FAFAFA` |
| Login page | Clean centered card, iceberg logo, show-password eye icon. Works at both widths. |
| Admin dashboard | Hero "Welcome back" banner + KPI metric cards + quick actions render correctly at 1366px; sidebar with grouped sections (Overview/People/Academic/Finance/Vocabulary) |
| Mobile navigation | Sidebar collapses to hamburger; student/staff get a floating pill bottom-nav (Home/Attendance/Results-Scores/Profile) — already mobile-app-like |
| Manage Students (mobile) | Tables correctly transform into stacked cards with chips (ID, course, branch, level, status, phone) and full-width Edit/Delete buttons. Excellent mobile adaptation. |
| Empty states | Well designed everywhere tested: "No Groups Assigned" (staff attendance), "All caught up" (assignments), "No invoices for June 2026" (payments) — icon + title + helper text |
| Payments page | KPI strip (Billed/Collected/Outstanding/Overdue), month/status/branch/group filters, "Generate Invoices", "One-off Invoice", CSV buttons all render |
| Student home (mobile) | Dark hero card with avatar, greeting, leaderboard rank badge, 3 stat pills; Quick Access horizontal scroll row; performance trend section |

### 14.3 Issues Found During Live Testing

1. **🐛 Login placeholder says "Student ID"** — the identifier field placeholder reads "Student ID" with label "YOUR ID", but admins must enter an email and teachers a TC-prefixed ID. Confusing for non-students. Suggest "Email or Login ID".
2. **⚠️ Staff/student email login silently fails** — `EmailBackend` blocks email login for user_type 2/3 by design (must use login_id). The login page gives a generic error with no hint that teachers/students must use their ID. UX improvement: detect `@` + non-admin and show "Please use your Login ID".
3. **✅ RESOLVED: `ERR_CERT_AUTHORITY_INVALID` console error identified** — verified live with Playwright `requestfailed` listener: the failing resource is `https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap` (the Inter font stylesheet). It fails only because the sandbox intercepts TLS; in production Google Fonts loads normally. This is the **only** external runtime resource — Bootstrap, FontAwesome, jQuery, and AdminLTE are all bundled locally in `/static/`. The Firebase service worker (`/firebase-messaging-sw.js`) serves a no-op stub when `FIREBASE_API_KEY` env is unset, so it never causes errors.
4. **✅ django-axes lockout works** — repeated failed logins increment `AccessAttempt`; lockout message after limit. Verified live.
5. **✅ No horizontal overflow** on any real page at 390px (only Django debug 404 pages overflow, which is expected).
6. **✅ Role redirects work** — visiting another role's URL redirects to own home, as documented in Section 9.

### 14.4 Mobile Responsiveness Verdict

The Django frontend is already strongly mobile-adapted: bottom navigation pills, card-ified tables, collapsible sidebar, touch-sized buttons. The Flutter migration should preserve this bottom-nav + card pattern (it already matches the planned Flutter shell design).

---

## 15. Gap-Closure Addendum — AJAX & Utility Endpoint Reference

> Added after a completeness audit cross-checked every `urls.py` route and every
> template file against this document. This section documents the **46 endpoints**
> that Section 7 missed (mostly AJAX/JSON endpoints called by inline template JS)
> plus the 4 previously undocumented templates. With this section, every URL route
> and every template in the codebase is documented.

### 15.1 Authentication & Session Utilities

| Method | URL | View | Request | Response |
|---|---|---|---|---|
| POST | `/doLogin/` | `views.doLogin` | form: `identifier` (email or login_id; falls back to legacy `email` field), `password` | Redirect to role home on success; redirect to `/` with flash message on failure. Distinguishes "ID not found" (`id_error` tag) vs "Incorrect password" (`pw_error` tag); preserves typed ID as `?id=` query param. Has a recovery-admin fallback: if identifier == `RECOVERY_ADMIN_EMAIL` env (default `iceberg.edu.center@gmail.com`) and auth fails, re-seeds the recovery admin then retries. django-axes lockout returns "Too many failed login attempts. Please wait 15 minutes" |
| GET | `/logout_user/` | `views.logout_user` | — | Logs out, redirects to `/` |
| GET | `/accounts/login/` | Django auth fallback | — | Redirect target used by `@login_required`; lands on login page |
| GET | `/firebase-messaging-sw.js` | `views.showFirebaseJS` | — | JS service worker. If `FIREBASE_API_KEY` env unset → no-op stub comment (never breaks). Otherwise emits Firebase v7.22.1 init with env-driven config |
| GET | `/blog/` | placeholder include | — | Documented in urls.py comments only; inactive |

### 15.2 Profile & Preference AJAX (all roles)

| Method | URL | View | Request | Response |
|---|---|---|---|---|
| POST | `/profile/save-avatar/` | `views.save_avatar` | form: `avatar` = "1"–"24" or "" | `{"status":"ok","avatar":"<n>"}`; 400 `{"status":"error","message":"Invalid avatar"}` for anything else. Saves to `CustomUser.avatar` |
| POST | `/student/save-theme/` | `student_views.student_save_theme` | form: `theme` = "dark"\|"bright"\|"system" (invalid → coerced to "system") | `{"status":"ok","theme":"…"}`. Saves to `Student.theme` |
| POST | `/staff/fcmtoken/` | `staff_views.staff_fcmtoken` | form: `token` | Plain text `"True"`/`"False"`. Saves to `CustomUser.fcm_token` |
| POST | `/student/fcmtoken/` | `student_views.student_fcmtoken` | form: `token` | Same as staff version |

### 15.3 Attendance AJAX (the core take/update attendance flow)

| Method | URL | View | Request | Response |
|---|---|---|---|---|
| POST | `/get_attendance` | `views.get_attendance` | form: `group` (group id) | JSON list `[{"id": <attendance_pk>, "attendance_date": "YYYY-MM-DD"}]`. **403 `{"error":"Access denied."}` if `user_can_access_group` fails** (IDOR guard verified) |
| POST | `/staff/get_students/` | `staff_views.get_students` | form: `group` | JSON list `[{"id": <student_pk>, "name": "Last First"}]`. **Scoped to `teacher=staff` — forged group_id returns 400** |
| POST | `/staff/attendance/save/` | `staff_views.save_attendance` | form: `group`, `date` (YYYY-MM-DD), `student_ids` = JSON string `[{"id":<pk>,"status":0|1|2}]` | Plain text `"OK"` or error w/ status 400/403. Idempotent (wipes prior reports for that group+date). Statuses: 0=Absent, 1=Present, 2=Late. Auto-notifies absent/late students |
| POST | `/staff/attendance/fetch/` | `staff_views.get_student_attendance` | form: `attendance_date_id` | JSON list `[{"id":<student_pk>,"name":"Last First","status":0|1|2}]` |
| POST | `/staff/attendance/update_save/` | `staff_views.update_attendance` | form: `date` (= attendance **id**, misleading name!), `student_ids` JSON | `"OK"`. **403 if `attendance.group.teacher_id != staff.id`** (IDOR guard). Notifies only students whose status changed to non-present |
| POST | `/attendance/fetch/` | `hod_views.get_admin_attendance` | form: either `group` (returns date list) or `attendance_date_id` (returns per-student statuses `[{"status":n,"name":"…"}]`) | Branch-scoped: 403 `{"error":"Not allowed."}` on cross-branch access |

### 15.4 Results AJAX (staff)

| Method | URL | View | Request | Response |
|---|---|---|---|---|
| POST | `/staff/result/fetch/` | `staff_views.fetch_student_result` | form: `group`, `student` | JSON `{"exam":n,"test":n,"comment":"…"}` or plain `"False"` if no result. Group scoped to own teacher |
| GET/POST | `/staff/result/edit/` | `EditResultView` (own file `EditResultView.py`) | POST form: `group`, `student`, `test` (0–40), `exam` (0–60) | Renders `edit_student_result.html` with flash messages. `get_object_or_404(groups, …)` restricts to own groups |
| GET/POST | `/staff/result/upload-file/` | `staff_views.upload_result_file` | POST multipart: `group`, `student` (optional → group-wide), `title`, `description`, `file` (PDF/Word/image, max 10MB) | Renders `upload_result_file.html` with `errors` dict on validation failure |
| GET | `/staff/result/files/` | `staff_views.staff_result_files` | — | Lists own uploaded `ResultFile`s (template `staff_result_files.html`) |
| GET | `/student/result/files/` | `student_views.student_result_files` | — | Lists files for enrolled groups; personal files only if addressed to self |
| GET | `/result/download/<int:file_id>/` | `views.result_file_download` | — | Streamed file or redirect to CDN. Access: student must be enrolled (+personal file must match self), teacher only own uploads, admin unrestricted. Human-readable error page when file missing from ephemeral disk |

### 15.5 Group / Enrollment AJAX (admin)

| Method | URL | View | Request | Response |
|---|---|---|---|---|
| POST | `/enrollment/group-info/` | `hod_views.get_group_info` | form: `group_id` | JSON `{"teacher","program","schedule","enrolled_count","capacity","enrolled_ids":[…]}`. Branch-scoped 403. Used by the add-enrollment page to live-preview a group |
| GET | `/group/<int:group_id>/students/` | `hod_views.admin_group_detail` | — | HTML `group_detail.html`: active enrollments + `total_inactive` count. Branch-scoped (redirect + flash on violation) |
| GET/POST | `/group/edit/<int:group_id>` | `hod_views.edit_group` | form fields of group | Setting/changing `start_date` triggers `_notify_group_start_date` — bulk notification to all active enrolled students |
| POST | `/group/archive/<int:group_id>` / `/group/delete/<int:group_id>` | archive/delete views | — | Redirects; delete only allowed when no enrollments |

### 15.6 Messaging (group chat) — full mechanics

`/messages/` and `/messages/group/<int:group_id>/` → `messaging_views.messages_home`:

- **Thread model**: one `ChatThread` per group, auto-created (`ensure_thread_for_group`). Thread list = all groups accessible to the user (teacher: own groups; student: enrolled groups; admin: branch-scoped), sorted by last activity, each with unread count.
- **GET**: renders `main_app/messages.html` with last **120 messages** (chronological), marks thread read via `ChatReadState.update_or_create`.
- **POST** (send): form `body` (max **4000 chars**) + optional `attachment`. Attachment rules: max **10 MB**, extension whitelist (images, documents, audio, video, zip). At least one of body/attachment required. On success redirects to `#latest` anchor.
- **403** via `PermissionDenied` if group not in user's accessible set.

### 15.7 Library (staff-only feature)

| Method | URL | View | Notes |
|---|---|---|---|
| GET/POST | `/staff/addbook/` | `add_book` | `BookForm`; template `add_book.html` |
| GET/POST | `/staff/issue_book/` | `issue_book` | `IssueBookForm` (validates against active loans); creates `Loan` with auto due date |
| GET | `/staff/view_issued_book/` | `view_issued_book` | All loans, active first; fine computed by `Loan.fine_amount` property |
| POST | `/staff/return_book/<int:loan_id>/` | `return_book` | Sets `returned_on=today`; flash shows fine if overdue |
| GET | `/student/viewbooks/` | `student_views.view_books` | Read-only catalog for students (template `view_books.html`) |

### 15.8 Stories (admin + staff)

| Method | URL | View | Notes |
|---|---|---|---|
| GET | `/admin/stories/` | `manage_stories` | Branch admins see: global stories (no target group) + stories targeting their groups + own-authored. Superadmin sees all |
| GET/POST | `/admin/stories/add/` | `add_story` | `DashboardStoryForm` (POST + FILES); sets `created_by`; template `story_form.html`; passes `storage_ok` flag (S3 health) |
| GET/POST | `/admin/stories/<int:story_id>/edit/` | `edit_story` | Same form with instance |
| POST | `/admin/stories/<int:story_id>/delete/` | `delete_story` | `require_POST`; no branch check (⚠️ any admin can delete any story — see bug list) |
| GET/POST | `/staff/stories/post/` | `staff_create_story` | Staff version, template `staff_story_form.html` |

### 15.9 Misc admin routes

| Method | URL | View | Notes |
|---|---|---|---|
| GET | `/admin/vocabulary-days/` | `manage_vocabulary_days` | Branch-scoped read-only list with word/completion counts |
| GET/POST | `/admin/leaderboard/seasons/` | `admin_manage_seasons` | Season CRUD for leaderboard |
| GET | `/admin_notify_staff`, `/admin_notify_student` | redirect shims | Both redirect to `/messages/` (legacy URLs kept alive) |
| POST | `/admin/send-student-notification/` | `send_student_notification` | form: `id` (admin user id!), `message`. Creates `Notification` + fires FCM via legacy `fcm.googleapis.com/fcm/send` with `FCM_SERVER_KEY` env |
| GET | `/health/` | `views.health` | `{"status":"ok","db":true}` or 503 — load balancer probe |

### 15.10 Error pages

Custom branded handlers in `views.py` registered for 400/403/404/500 — all render `main_app/error.html` with `error_code`, `error_title`, `error_message` context. (404 verified live in Section 14.)

### 15.11 Previously Undocumented Templates (4)

| Template | Purpose |
|---|---|
| `main_app/form_template.html` | Generic include: renders any Django form as `pf-field` rows with label, errors, help text, and a submit button (`button_text` context var, default "Submit"). Used by simple add/edit pages |
| `registration/password_reset_form.html` | "Forgot password?" email entry form (extends `erpnext_base.html`); posts to Django's built-in `PasswordResetView` |
| `registration/password_reset_email.html` | Plain-text email body with `{{protocol}}://{{domain}}/reset/<uidb64>/<token>/` link; 24h expiry notice |
| `registration/password_reset_success.html` | Success confirmation with "Sign in now" button |

### 15.12 External Dependencies (verified live)

The **only** external network request the frontend makes at page load is Google Fonts
(`fonts.googleapis.com/css2?family=Inter` + `fonts.gstatic.com` preconnect). All other
assets (Bootstrap 4, FontAwesome 5, jQuery, AdminLTE 3, Chart.js) are vendored under
`main_app/static/`. Firebase scripts are only referenced from the service worker, which
serves a no-op stub unless `FIREBASE_*` env vars are configured. **Implication for
Flutter:** the app needs zero external web assets; bundle the Inter font family locally.
