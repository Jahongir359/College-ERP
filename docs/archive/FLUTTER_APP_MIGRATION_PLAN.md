# ICEBERG Study Center ERP — Flutter App Migration Plan

**Document Version**: 2026-06  
**Source System**: Django 5.2 LTS (see FRONTEND_DEEP_ANALYSIS.md)  
**Target**: Flutter (mobile-first, also Flutter Web)  
**Backend API Base**: `/api/v1/` (Django REST Framework + simplejwt)  
**Currency**: UZS soʻm  
**Language**: English UI (Uzbek user names/data)

---

## Table of Contents

1. [Migration Strategy & Goals](#1-migration-strategy--goals)
2. [Flutter Project Architecture](#2-flutter-project-architecture)
3. [Design System — Dart/Flutter Translation](#3-design-system--dartflutter-translation)
4. [Authentication & Token Management](#4-authentication--token-management)
5. [Role-Based Navigation Architecture](#5-role-based-navigation-architecture)
6. [Complete Screen Inventory](#6-complete-screen-inventory)
7. [Dart Data Models](#7-dart-data-models)
8. [API Service Layer](#8-api-service-layer)
9. [State Management Architecture](#9-state-management-architecture)
10. [Feature Implementation Details](#10-feature-implementation-details)
11. [Migration Phases & Priorities](#11-migration-phases--priorities)

---

## 1. Migration Strategy & Goals

### 1.1 Why Flutter

The Django frontend is a server-rendered HTML application. The goal is to migrate to Flutter to achieve:

1. **Native mobile experience** — iOS and Android apps from one codebase
2. **Offline support** — attendance and vocab can be cached
3. **Push notifications** — Firebase FCM already integrated in backend (`fcm_token` on `CustomUser`)
4. **Richer interactions** — vocabulary flashcard animations, real-time attendance toggles, progress charts

### 1.2 Migration Approach

**API-first**: All functionality consumes the existing `/api/v1/` endpoints. Where endpoints don't exist yet, they must be built before the Flutter screen can be completed (see Section 11.3 for the gap list).

**Feature parity + enhancements**: Match every Django page. Where the Django implementation is weak (e.g., no flashcard flashcard animation, no real-time attendance toggle), the Flutter version improves it.

**Roles preserved exactly**: `user_type '1'` = Admin/HOD, `user_type '2'` = Staff/Teacher, `user_type '3'` = Student. Super admin is `user_type '1'` with `is_super_admin=True`.

### 1.3 Platforms

| Platform | Status | Notes |
|---|---|---|
| Android | Primary | Release APK + Play Store |
| iOS | Secondary | Same codebase, future App Store |
| Flutter Web | Tertiary | CanvasKit renderer, admin-heavy use |

### 1.4 Key Decisions

- **State management**: `flutter_riverpod` (AsyncNotifier pattern)
- **Navigation**: `go_router` with role-based redirect guards
- **HTTP**: `dio` with JWT interceptor for auto-refresh
- **Token storage**: `flutter_secure_storage` (native) / localStorage fallback (web)
- **Charts**: `fl_chart`
- **File picker**: `file_picker`
- **Push notifications**: `firebase_messaging` (FCM already configured on backend)
- **Fonts**: Google Fonts Inter (matches Django `--font-sans`)

---

## 2. Flutter Project Architecture

### 2.1 Folder Structure

```
lib/
├── main.dart                          # App entry, ProviderScope, Firebase init
│
├── core/
│   ├── api/
│   │   ├── api_client.dart            # Dio instance + base URL + JWT interceptor
│   │   ├── api_providers.dart         # Riverpod provider for ApiClient
│   │   └── api_exceptions.dart        # ApiException, NetworkException, etc.
│   │
│   ├── auth/
│   │   ├── auth_state.dart            # AuthState enum + AuthUser model
│   │   ├── auth_notifier.dart         # AsyncNotifier: login, logout, refresh
│   │   └── token_storage.dart         # flutter_secure_storage wrapper
│   │
│   ├── router/
│   │   ├── app_router.dart            # GoRouter: all routes + redirect guards
│   │   └── route_names.dart           # Route name constants
│   │
│   ├── theme/
│   │   ├── ice_colors.dart            # All color tokens (matches iceberg.css)
│   │   ├── ice_theme.dart             # ThemeData light + dark
│   │   └── ice_typography.dart        # TextStyles using Inter
│   │
│   └── utils/
│       ├── currency_formatter.dart    # UZS soʻm formatting
│       ├── date_formatter.dart        # DD MMM YYYY + ISO conversion
│       ├── login_id_parser.dart       # IC/TC prefix parsing
│       └── validators.dart            # Common form validators
│
├── features/
│   ├── auth/
│   │   ├── data/
│   │   │   └── auth_repository.dart   # login(), logout(), refreshToken()
│   │   └── screens/
│   │       ├── login_screen.dart
│   │       └── forgot_password_screen.dart
│   │
│   ├── student/
│   │   ├── data/
│   │   │   ├── student_repository.dart
│   │   │   └── student_providers.dart
│   │   ├── models/
│   │   │   └── student_models.dart    # StudentResult, AttendanceRecord, etc.
│   │   └── screens/
│   │       ├── student_home_screen.dart
│   │       ├── student_attendance_screen.dart
│   │       ├── student_results_screen.dart
│   │       ├── student_result_files_screen.dart
│   │       ├── student_assignments_screen.dart
│   │       ├── student_payments_screen.dart
│   │       ├── student_leaderboard_screen.dart
│   │       ├── student_progress_screen.dart
│   │       ├── student_vocabulary_list_screen.dart
│   │       ├── student_vocabulary_detail_screen.dart
│   │       ├── student_flashcard_screen.dart
│   │       ├── student_quiz_screen.dart
│   │       ├── student_leave_screen.dart
│   │       ├── student_feedback_screen.dart
│   │       ├── student_notifications_screen.dart
│   │       ├── student_books_screen.dart
│   │       └── student_more_screen.dart
│   │
│   ├── staff/
│   │   ├── data/
│   │   │   ├── staff_repository.dart
│   │   │   └── staff_providers.dart
│   │   ├── models/
│   │   │   └── staff_models.dart
│   │   └── screens/
│   │       ├── staff_home_screen.dart
│   │       ├── staff_classes_screen.dart
│   │       ├── staff_take_attendance_screen.dart
│   │       ├── staff_update_attendance_screen.dart
│   │       ├── staff_results_screen.dart
│   │       ├── staff_result_files_screen.dart
│   │       ├── staff_assignments_screen.dart
│   │       ├── staff_vocabulary_list_screen.dart
│   │       ├── staff_vocabulary_detail_screen.dart
│   │       ├── staff_leave_screen.dart
│   │       ├── staff_feedback_screen.dart
│   │       ├── staff_payments_screen.dart
│   │       ├── staff_notifications_screen.dart
│   │       └── staff_more_screen.dart
│   │
│   ├── admin/
│   │   ├── data/
│   │   │   ├── admin_repository.dart
│   │   │   └── admin_providers.dart
│   │   ├── models/
│   │   │   └── admin_models.dart
│   │   └── screens/
│   │       ├── admin_home_screen.dart
│   │       ├── admin_students_screen.dart
│   │       ├── admin_add_student_screen.dart
│   │       ├── admin_edit_student_screen.dart
│   │       ├── admin_staff_screen.dart
│   │       ├── admin_add_staff_screen.dart
│   │       ├── admin_edit_staff_screen.dart
│   │       ├── admin_groups_screen.dart
│   │       ├── admin_group_detail_screen.dart
│   │       ├── admin_add_group_screen.dart
│   │       ├── admin_courses_screen.dart
│   │       ├── admin_subjects_screen.dart
│   │       ├── admin_sessions_screen.dart
│   │       ├── admin_branches_screen.dart
│   │       ├── admin_enrollment_screen.dart
│   │       ├── admin_admins_screen.dart
│   │       ├── admin_leave_screen.dart
│   │       ├── admin_attendance_screen.dart
│   │       ├── admin_payments_screen.dart
│   │       ├── admin_stories_screen.dart
│   │       ├── admin_leads_screen.dart
│   │       ├── admin_send_notification_screen.dart
│   │       ├── admin_leaderboard_settings_screen.dart
│   │       ├── admin_vocabulary_screen.dart
│   │       └── admin_more_screen.dart
│   │
│   └── superadmin/
│       └── screens/
│           ├── superadmin_home_screen.dart
│           ├── superadmin_analytics_screen.dart
│           └── superadmin_more_screen.dart
│
├── shared/
│   ├── screens/
│   │   ├── profile_hub_screen.dart    # All roles — avatar, theme, password
│   │   ├── messages_screen.dart       # Group chat — all roles
│   │   └── notifications_screen.dart  # All roles
│   │
│   └── widgets/
│       ├── ice_app_bar.dart           # Standard branded AppBar
│       ├── ice_bottom_nav.dart        # Role-specific 4-tab bottom nav
│       ├── ice_sidebar.dart           # Desktop/tablet sidebar
│       ├── ice_kpi_card.dart          # Stat card with count-up
│       ├── ice_status_badge.dart      # Colored status chip
│       ├── ice_empty_state.dart       # Empty list placeholder
│       ├── ice_error_state.dart       # Error with retry button
│       ├── ice_skeleton.dart          # Shimmer skeleton loader
│       ├── ice_confirm_dialog.dart    # Delete/dangerous action confirm
│       ├── ice_data_table.dart        # Desktop sortable data table
│       ├── ice_chart_card.dart        # fl_chart wrapper card
│       ├── ice_story_strip.dart       # Horizontal story scroll
│       ├── ice_avatar.dart            # Emoji avatar display
│       └── ice_currency_text.dart     # UZS formatted Text widget
│
└── l10n/                              # Future: Uzbek localization
```

### 2.2 Key Dependencies (pubspec.yaml additions)

```yaml
dependencies:
  flutter:
    sdk: flutter
  
  # Navigation
  go_router: ^14.0.0
  
  # State management
  flutter_riverpod: ^2.5.0
  riverpod_annotation: ^2.3.0
  
  # HTTP
  dio: ^5.4.0
  
  # Secure storage
  flutter_secure_storage: ^9.0.0
  
  # Charts
  fl_chart: ^0.68.0
  
  # File operations
  file_picker: ^8.0.0
  
  # Push notifications
  firebase_messaging: ^15.0.0
  firebase_core: ^3.0.0
  
  # Images
  cached_network_image: ^3.3.0
  
  # Fonts
  google_fonts: ^6.2.0
  
  # Utility
  intl: ^0.19.0                # date + number formatting
  shimmer: ^3.0.0              # skeleton loading

dev_dependencies:
  build_runner: ^2.4.0
  riverpod_generator: ^2.4.0
  json_serializable: ^6.7.0
  flutter_lints: ^4.0.0
```

---

## 3. Design System — Dart/Flutter Translation

### 3.1 IceColors (from iceberg.css CSS tokens)

```dart
// lib/core/theme/ice_colors.dart

import 'package:flutter/material.dart';

class IceColors {
  IceColors._();

  // Brand
  static const Color navy      = Color(0xFF06343A);   // --navy
  static const Color navyMid   = Color(0xFF0E6873);   // --navy-mid
  static const Color navyLight = Color(0xFF1E8C98);   // --navy-light
  static const Color navyDeep  = Color(0xFF03181C);   // --navy-deep
  static const Color lime      = Color(0xFFDFFF2F);   // --lime  ⚠️ LOW CONTRAST on white
  static const Color limeDeep  = Color(0xFFB8D900);   // --lime-deep
  static const Color cyan      = Color(0xFF00CFE8);   // --cyan

  // Semantic
  static const Color success   = Color(0xFF22C55E);   // --success
  static const Color warning   = Color(0xFFF59E0B);   // --warning
  static const Color danger    = Color(0xFFEF4444);   // --danger
  static const Color info      = Color(0xFF3B82F6);   // --info

  // Leaderboard medals
  static const Color gold      = Color(0xFFF59E0B);   // --gold
  static const Color silver    = Color(0xFF94A3B8);   // --silver
  static const Color bronze    = Color(0xFFB45309);   // --bronze

  // Light mode surfaces
  static const Color bg        = Color(0xFFF4FAFB);   // --bg
  static const Color surface   = Color(0xFFFFFFFF);   // --surface
  static const Color surface2  = Color(0xFFEEF5F6);   // --surface-2
  static const Color border    = Color(0xFFD4E4E6);   // --border
  static const Color text      = Color(0xFF06343A);   // --text
  static const Color textMuted = Color(0xFF5A7A7E);   // --text-muted
  static const Color textLight = Color(0xFF8FA8AB);   // --text-light

  // Dark mode surfaces
  static const Color darkBg       = Color(0xFF0D1F22);  // [data-theme=dark] --bg
  static const Color darkSurface  = Color(0xFF122428);  // [data-theme=dark] --surface
  static const Color darkSurface2 = Color(0xFF172D31);  // [data-theme=dark] --surface-2
  static const Color darkBorder   = Color(0xFF1E3A3F);  // [data-theme=dark] --border
  static const Color darkText     = Color(0xFFE8F4F5);  // [data-theme=dark] --text
  static const Color darkMuted    = Color(0xFF7AABAF);  // [data-theme=dark] --text-muted

  /// Status color helper — matches Django badge logic
  static Color forStatus(String status) => switch (status.toLowerCase()) {
    'approved' || 'paid' || 'present' || 'active' || 'p' => success,
    'pending' || 'partial' || 'new' || 'contacted'        => warning,
    'rejected' || 'overdue' || 'absent' || 'a' || 'inactive' => danger,
    'late' || 'l'                                          => warning,
    _                                                      => textMuted,
  };

  /// Medal color for leaderboard rank
  static Color forRank(int rank) => switch (rank) {
    1 => gold,
    2 => silver,
    3 => bronze,
    _ => textMuted,
  };
}
```

### 3.2 Typography (Inter font, matching --fs-* tokens)

```dart
// lib/core/theme/ice_typography.dart

class IceTextStyles {
  // --fs-display: 28px
  static TextStyle get display => GoogleFonts.inter(
    fontSize: 28, fontWeight: FontWeight.w800, color: IceColors.text,
  );

  // --fs-h1: 21px
  static TextStyle get h1 => GoogleFonts.inter(
    fontSize: 21, fontWeight: FontWeight.w700, color: IceColors.text,
  );

  // --fs-h2: 16px
  static TextStyle get h2 => GoogleFonts.inter(
    fontSize: 16, fontWeight: FontWeight.w600, color: IceColors.text,
  );

  // --fs-h3: 14px
  static TextStyle get h3 => GoogleFonts.inter(
    fontSize: 14, fontWeight: FontWeight.w600, color: IceColors.text,
  );

  // --fs-body: 13px
  static TextStyle get body => GoogleFonts.inter(
    fontSize: 13, fontWeight: FontWeight.w400, color: IceColors.text,
  );

  // --fs-sm: 12px
  static TextStyle get sm => GoogleFonts.inter(
    fontSize: 12, fontWeight: FontWeight.w400, color: IceColors.textMuted,
  );

  // --fs-xs: 11px
  static TextStyle get xs => GoogleFonts.inter(
    fontSize: 11, fontWeight: FontWeight.w500, color: IceColors.textMuted,
  );
}
```

### 3.3 Border Radius Constants (matching --radius-* tokens)

```dart
// lib/core/theme/ice_theme.dart

class IceRadius {
  static const double sm = 6.0;    // --radius-sm
  static const double md = 10.0;   // --radius-md
  static const double lg = 14.0;   // --radius-lg
  static const double xl = 20.0;   // --radius-xl

  static BorderRadius get smBR  => BorderRadius.circular(sm);
  static BorderRadius get mdBR  => BorderRadius.circular(md);
  static BorderRadius get lgBR  => BorderRadius.circular(lg);
  static BorderRadius get xlBR  => BorderRadius.circular(xl);
}
```

### 3.4 Light Theme (ThemeData)

```dart
ThemeData get lightTheme => ThemeData(
  useMaterial3: true,
  colorScheme: ColorScheme.light(
    primary:    IceColors.navy,
    secondary:  IceColors.cyan,
    surface:    IceColors.surface,
    background: IceColors.bg,
    error:      IceColors.danger,
  ),
  scaffoldBackgroundColor: IceColors.bg,
  cardTheme: CardTheme(
    color: IceColors.surface,
    elevation: 0,
    shape: RoundedRectangleBorder(
      borderRadius: IceRadius.lgBR,
      side: BorderSide(color: IceColors.border),
    ),
  ),
  elevatedButtonTheme: ElevatedButtonThemeData(
    style: ElevatedButton.styleFrom(
      backgroundColor: IceColors.lime,
      foregroundColor: IceColors.navy,
      shape: RoundedRectangleBorder(borderRadius: IceRadius.mdBR),
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
      textStyle: IceTextStyles.body.copyWith(fontWeight: FontWeight.w600),
    ),
  ),
  inputDecorationTheme: InputDecorationTheme(
    filled: true,
    fillColor: IceColors.surface2,
    border: OutlineInputBorder(
      borderRadius: IceRadius.mdBR,
      borderSide: BorderSide(color: IceColors.border),
    ),
    focusedBorder: OutlineInputBorder(
      borderRadius: IceRadius.mdBR,
      borderSide: BorderSide(color: IceColors.navyLight, width: 2),
    ),
  ),
  textTheme: TextTheme(
    displayLarge:  IceTextStyles.display,
    headlineLarge: IceTextStyles.h1,
    headlineMedium: IceTextStyles.h2,
    titleMedium:   IceTextStyles.h3,
    bodyMedium:    IceTextStyles.body,
    bodySmall:     IceTextStyles.sm,
    labelSmall:    IceTextStyles.xs,
  ),
);
```

### 3.5 Dark Theme

```dart
ThemeData get darkTheme => lightTheme.copyWith(
  colorScheme: ColorScheme.dark(
    primary:    IceColors.navy,
    secondary:  IceColors.cyan,
    surface:    IceColors.darkSurface,
    background: IceColors.darkBg,
    error:      IceColors.danger,
  ),
  scaffoldBackgroundColor: IceColors.darkBg,
  cardTheme: CardTheme(
    color: IceColors.darkSurface,
    elevation: 0,
    shape: RoundedRectangleBorder(
      borderRadius: IceRadius.lgBR,
      side: BorderSide(color: IceColors.darkBorder),
    ),
  ),
);
```

### 3.6 Currency Formatter (UZS soʻm)

```dart
// lib/core/utils/currency_formatter.dart

class CurrencyFormatter {
  static String format(num amount) {
    // Output: "450 000 so'm" (space thousands separator, no decimal)
    final formatted = amount.toInt().toString().replaceAllMapped(
      RegExp(r'(\d)(?=(\d{3})+$)'),
      (m) => '${m[1]} ',
    );
    return "$formatted so'm";
  }
}
// Usage: CurrencyFormatter.format(450000) → "450 000 so'm"
```

### 3.7 Responsive Breakpoints (matching mobile-adaptive.css)

```dart
// lib/shared/widgets/adaptive_layout.dart

class IceBreakpoints {
  static const double mobile  = 768.0;    // < 768 → mobile
  static const double tablet  = 1024.0;   // 768–1024 → tablet
  static const double desktop = 1280.0;   // > 1024 → desktop (sidebar visible)
}

extension ContextBreakpoints on BuildContext {
  bool get isMobile  => MediaQuery.of(this).size.width < IceBreakpoints.mobile;
  bool get isTablet  => MediaQuery.of(this).size.width < IceBreakpoints.tablet;
  bool get isDesktop => MediaQuery.of(this).size.width >= IceBreakpoints.desktop;
}
```

---

## 4. Authentication & Token Management

### 4.1 Auth Flow

```
LoginScreen
    │
    ▼
POST /api/v1/auth/login/
  {identifier, password}
    │
    ▼
Response: {access, refresh, user}
    │
    ├── Store access token → flutter_secure_storage 'access_token'
    ├── Store refresh token → flutter_secure_storage 'refresh_token'
    │
    ▼
GET /api/v1/me/
    │
    ▼
AuthUser {id, email, login_id, user_type, is_super_admin, ...}
    │
    ▼
GoRouter redirect → role home
  user_type '1' + is_super_admin → /superadmin/home
  user_type '1'                  → /admin/home
  user_type '2'                  → /staff/home
  user_type '3'                  → /student/home
```

### 4.2 AuthUser Model

```dart
// lib/core/auth/auth_state.dart

class AuthUser {
  final int id;
  final String email;
  final String loginId;
  final String userType;        // '1', '2', '3'
  final bool isSuperAdmin;
  final String firstName;
  final String lastName;
  final String? gender;
  final String? dateOfBirth;
  final String? profilePicUrl;
  final String? address;
  final String? themePreference; // 'dark' | 'light' | null

  const AuthUser({
    required this.id,
    required this.email,
    required this.loginId,
    required this.userType,
    required this.isSuperAdmin,
    required this.firstName,
    required this.lastName,
    this.gender,
    this.dateOfBirth,
    this.profilePicUrl,
    this.address,
    this.themePreference,
  });

  // Role helpers
  bool get isAdminUser   => userType == '1' && !isSuperAdmin;
  bool get isSuperUser   => userType == '1' && isSuperAdmin;
  bool get isStaffUser   => userType == '2';
  bool get isStudentUser => userType == '3';

  String get displayName => '$firstName $lastName'.trim();

  factory AuthUser.fromJson(Map<String, dynamic> json) => AuthUser(
    id:               json['id'] as int,
    email:            json['email'] as String,
    loginId:          json['login_id'] as String? ?? '',
    userType:         json['user_type'] as String,
    isSuperAdmin:     json['is_super_admin'] as bool? ?? false,
    firstName:        json['first_name'] as String? ?? '',
    lastName:         json['last_name'] as String? ?? '',
    gender:           json['gender'] as String?,
    dateOfBirth:      json['date_of_birth'] as String?,
    profilePicUrl:    json['profile_pic_url'] as String?,
    address:          json['address'] as String?,
    themePreference:  json['theme_preference'] as String?,
  );
}
```

### 4.3 Dio JWT Interceptor

```dart
// lib/core/api/api_client.dart

class JwtInterceptor extends Interceptor {
  final TokenStorage _storage;
  final Dio _dio;

  JwtInterceptor(this._storage, this._dio);

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) async {
    final token = await _storage.getAccessToken();
    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }
    handler.next(options);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) async {
    if (err.response?.statusCode == 401) {
      // Attempt token refresh
      try {
        final refresh = await _storage.getRefreshToken();
        if (refresh == null) throw Exception('No refresh token');

        final response = await _dio.post('/api/v1/auth/token/refresh/', 
          data: {'refresh': refresh});
        final newAccess = response.data['access'] as String;
        await _storage.setAccessToken(newAccess);

        // Retry original request with new token
        err.requestOptions.headers['Authorization'] = 'Bearer $newAccess';
        final retried = await _dio.fetch(err.requestOptions);
        handler.resolve(retried);
      } catch (_) {
        // Refresh failed → clear and redirect to login
        await _storage.clear();
        // Trigger auth state rebuild → GoRouter redirects to /login
        handler.reject(err);
      }
    } else {
      handler.next(err);
    }
  }
}
```

### 4.4 Password Reset Flow (needs backend REST endpoints)

```dart
// Three-step OTP flow — endpoints need to be created on Django

// Step 1: POST /api/v1/auth/password-reset/
//   Body: {email}
//   Response: {message: "OTP sent"}

// Step 2: POST /api/v1/auth/password-reset/verify/
//   Body: {email, code}
//   Response: {reset_token}

// Step 3: POST /api/v1/auth/password-reset/confirm/
//   Body: {reset_token, new_password, confirm_password}
//   Response: {message: "Password changed"}
```

### 4.5 Login ID Format Reference (read-only in Flutter)

Login IDs are **generated by backend** — Flutter never generates them. These formats are documented for display purposes:

| Role | Format | Example | Decode |
|---|---|---|---|
| Student | `IC{MMDD}{NN}` | `IC052401` | Born May 24, student #01 that day |
| Teacher | `TC{MMDD}{NN}` | `TC060101` | Born Jun 01, teacher #01 that day |

```dart
// lib/core/utils/login_id_parser.dart
class LoginIdParser {
  static String? role(String loginId) {
    if (loginId.startsWith('IC')) return 'Student';
    if (loginId.startsWith('TC')) return 'Teacher';
    return null;
  }
}
```

---

## 5. Role-Based Navigation Architecture

### 5.1 GoRouter Configuration

```dart
// lib/core/router/app_router.dart

final appRouter = GoRouter(
  initialLocation: '/splash',
  redirect: (context, state) {
    final auth = container.read(authProvider);
    final path = state.matchedLocation;

    if (auth.isLoading) return '/splash';

    if (!auth.isAuthenticated) {
      if (path == '/login' || path == '/forgot-password') return null;
      return '/login';
    }

    // Authenticated — redirect away from login/splash
    if (path == '/login' || path == '/splash') {
      final user = auth.user!;
      if (user.isSuperUser)   return '/superadmin/home';
      if (user.isAdminUser)   return '/admin/home';
      if (user.isStaffUser)   return '/staff/home';
      return '/student/home';
    }

    // Role enforcement: block wrong-role paths
    final u = auth.user!;
    if (path.startsWith('/student') && !u.isStudentUser) {
      return u.isSuperUser ? '/superadmin/home'
           : u.isAdminUser ? '/admin/home'
           : '/staff/home';
    }
    if (path.startsWith('/staff') && !u.isStaffUser) return _roleHome(u);
    if (path.startsWith('/admin') && u.isStudentUser) return '/student/home';
    if (path.startsWith('/superadmin') && !u.isSuperUser) return _roleHome(u);

    return null;
  },
  routes: [...],
);

String _roleHome(AuthUser u) => u.isSuperUser ? '/superadmin/home'
  : u.isAdminUser ? '/admin/home' : u.isStaffUser ? '/staff/home' : '/student/home';
```

### 5.2 Complete Route Map

| Route | Screen Class | Role | Django Equivalent |
|---|---|---|---|
| `/splash` | `SplashScreen` | All | N/A |
| `/login` | `LoginScreen` | Public | `login.html` |
| `/forgot-password` | `ForgotPasswordScreen` | Public | `forgot_password.html` |
| `/profile` | `ProfileHubScreen` | All | `/profile-hub/` |
| `/messages` | `MessagesScreen` | All | `/messages/` |
| `/messages/:groupId` | `MessagesScreen` | All | `/messages/<int:group_id>/` |
| `/notifications` | `NotificationsScreen` | All | Role-specific notification pages |
| `/student/home` | `StudentHomeScreen` | Student | `/student/home/` |
| `/student/attendance` | `StudentAttendanceScreen` | Student | `/student/view-attendance/` |
| `/student/results` | `StudentResultsScreen` | Student | `/student/view-result/` |
| `/student/result-files` | `StudentResultFilesScreen` | Student | `/student/result-files/` |
| `/student/assignments` | `StudentAssignmentsScreen` | Student | `/student/assignments/` |
| `/student/assignments/:id/submit` | `SubmitAssignmentScreen` | Student | `/student/assignment/<pk>/submit/` |
| `/student/vocabulary` | `StudentVocabularyListScreen` | Student | `/student/vocabulary-days/` |
| `/student/vocabulary/:id` | `StudentVocabularyDetailScreen` | Student | `/student/vocabulary-day/<pk>/` |
| `/student/vocabulary/:id/flashcard` | `StudentFlashcardScreen` | Student | `/student/vocabulary-day/<pk>/flashcard/` |
| `/student/vocabulary/:id/quiz` | `StudentQuizScreen` | Student | `/student/vocabulary-day/<pk>/quiz/` |
| `/student/progress` | `StudentProgressScreen` | Student | `/student/progress/` |
| `/student/leaderboard` | `StudentLeaderboardScreen` | Student | `/student/leaderboard/` |
| `/student/leaderboard/history` | `LeaderboardHistoryScreen` | Student | `/student/leaderboard/history/` |
| `/student/leaderboard/season/:id` | `LeaderboardSeasonScreen` | Student | `/student/leaderboard/season/<pk>/` |
| `/student/payments` | `StudentPaymentsScreen` | Student | `/student/payments/` |
| `/student/payments/:id/receipt` | `PaymentReceiptScreen` | Student | `/student/payments/receipt/<pk>/` |
| `/student/leave` | `StudentLeaveScreen` | Student | `/student/apply-leave/` |
| `/student/feedback` | `StudentFeedbackScreen` | Student | `/student/feedback/` |
| `/student/books` | `StudentBooksScreen` | Student | `/student/books/` |
| `/student/more` | `StudentMoreScreen` | Student | N/A |
| `/staff/home` | `StaffHomeScreen` | Staff | `/staff/home/` |
| `/staff/classes` | `StaffClassesScreen` | Staff | N/A (composite view) |
| `/staff/attendance` | `StaffTakeAttendanceScreen` | Staff | `/staff/take-attendance/` |
| `/staff/attendance/update` | `StaffUpdateAttendanceScreen` | Staff | `/staff/update-attendance/` |
| `/staff/results` | `StaffResultsScreen` | Staff | `/staff/add-result/` |
| `/staff/results/:id/edit` | `StaffEditResultScreen` | Staff | `/staff/edit-student-result/<pk>/` |
| `/staff/result-files` | `StaffResultFilesScreen` | Staff | `/staff/result-files/` |
| `/staff/assignments` | `StaffAssignmentsScreen` | Staff | `/staff/assignments/` |
| `/staff/assignments/add` | `StaffAddAssignmentScreen` | Staff | `/staff/assignment/add/` |
| `/staff/assignments/:id/submissions` | `StaffSubmissionsScreen` | Staff | `/staff/assignment/<pk>/submissions/` |
| `/staff/vocabulary` | `StaffVocabularyListScreen` | Staff | `/staff/vocabulary-days/` |
| `/staff/vocabulary/:id` | `StaffVocabularyDetailScreen` | Staff | `/staff/vocabulary-day/<pk>/` |
| `/staff/vocabulary/add` | `StaffAddVocabularyScreen` | Staff | `/staff/vocabulary-day/add/` |
| `/staff/payments` | `StaffPaymentsScreen` | Staff | `/staff/payments/` |
| `/staff/leave` | `StaffLeaveScreen` | Staff | `/staff/apply-leave/` |
| `/staff/feedback` | `StaffFeedbackScreen` | Staff | `/staff/feedback/` |
| `/staff/more` | `StaffMoreScreen` | Staff | N/A |
| `/admin/home` | `AdminHomeScreen` | Admin | `/admin/home/` |
| `/admin/students` | `AdminStudentsScreen` | Admin | `/student/manage/` |
| `/admin/students/add` | `AdminAddStudentScreen` | Admin | `/student/add/` |
| `/admin/students/:id/edit` | `AdminEditStudentScreen` | Admin | `/student/edit/<pk>/` |
| `/admin/staff` | `AdminStaffScreen` | Admin | `/staff/manage/` |
| `/admin/staff/add` | `AdminAddStaffScreen` | Admin | `/staff/add/` |
| `/admin/staff/:id/edit` | `AdminEditStaffScreen` | Admin | `/staff/edit/<pk>/` |
| `/admin/groups` | `AdminGroupsScreen` | Admin | `/group/manage/` |
| `/admin/groups/add` | `AdminAddGroupScreen` | Admin | `/group/add/` |
| `/admin/groups/:id` | `AdminGroupDetailScreen` | Admin | `/group/<pk>/` |
| `/admin/groups/:id/edit` | `AdminEditGroupScreen` | Admin | — |
| `/admin/enrollment` | `AdminEnrollmentScreen` | Admin | `/enrollment/manage/` |
| `/admin/courses` | `AdminCoursesScreen` | Admin | `/course/manage/` |
| `/admin/subjects` | `AdminSubjectsScreen` | Admin | `/subject/manage/` |
| `/admin/sessions` | `AdminSessionsScreen` | Admin | `/session/manage/` |
| `/admin/branches` | `AdminBranchesScreen` | Admin | `/branch/manage/` |
| `/admin/admins` | `AdminAdminsScreen` | Admin (super) | `/admin/manage/` |
| `/admin/attendance` | `AdminAttendanceScreen` | Admin | `/admin/view-attendance/` |
| `/admin/payments` | `AdminPaymentsScreen` | Admin | `/admin/payments/` |
| `/admin/payments/:id/record` | `AdminRecordPaymentScreen` | Admin | `/admin/payments/record/<pk>/` |
| `/admin/stories` | `AdminStoriesScreen` | Admin | `/stories/manage/` |
| `/admin/stories/add` | `AdminAddStoryScreen` | Admin | `/stories/add/` |
| `/admin/stories/:id/edit` | `AdminEditStoryScreen` | Admin | `/stories/<pk>/edit/` |
| `/admin/leads` | `AdminLeadsScreen` | Admin | `/manage-registration-leads/` |
| `/admin/vocabulary` | `AdminVocabularyScreen` | Admin | `/manage-vocabulary-days/` |
| `/admin/leaderboard` | `AdminLeaderboardScreen` | Admin | `/leaderboard/admin/settings/` |
| `/admin/notify` | `AdminSendNotificationScreen` | Admin | `/admin/send-student-notification/` |
| `/admin/leave` | `AdminLeaveScreen` | Admin | `/admin/view-student-leave/` + `/admin/view-staff-leave/` |
| `/admin/more` | `AdminMoreScreen` | Admin | N/A |
| `/superadmin/home` | `SuperadminHomeScreen` | Superadmin | `/admin/home/` (with full scope) |
| `/superadmin/analytics` | `SuperadminAnalyticsScreen` | Superadmin | N/A (new feature) |
| `/superadmin/more` | `SuperadminMoreScreen` | Superadmin | N/A |

### 5.3 Bottom Navigation Per Role

**Student** (4 tabs):
```dart
const studentTabs = [
  IceNavTab(icon: Icons.home_rounded,       label: 'Home',       route: '/student/home'),
  IceNavTab(icon: Icons.check_circle,       label: 'Attendance', route: '/student/attendance'),
  IceNavTab(icon: Icons.bar_chart_rounded,  label: 'Results',    route: '/student/results'),
  IceNavTab(icon: Icons.grid_view_rounded,  label: 'More',       route: '/student/more'),
];
```

**Staff** (4 tabs):
```dart
const staffTabs = [
  IceNavTab(icon: Icons.home_rounded,       label: 'Home',       route: '/staff/home'),
  IceNavTab(icon: Icons.edit_calendar,      label: 'Attendance', route: '/staff/attendance'),
  IceNavTab(icon: Icons.grade_rounded,      label: 'Scores',     route: '/staff/results'),
  IceNavTab(icon: Icons.grid_view_rounded,  label: 'More',       route: '/staff/more'),
];
```

**Admin** (4 tabs):
```dart
const adminTabs = [
  IceNavTab(icon: Icons.home_rounded,       label: 'Home',      route: '/admin/home'),
  IceNavTab(icon: Icons.people_rounded,     label: 'Students',  route: '/admin/students'),
  IceNavTab(icon: Icons.group_rounded,      label: 'Groups',    route: '/admin/groups'),
  IceNavTab(icon: Icons.grid_view_rounded,  label: 'More',      route: '/admin/more'),
];
```

**Superadmin** (4 tabs):
```dart
const superadminTabs = [
  IceNavTab(icon: Icons.home_rounded,       label: 'Home',      route: '/superadmin/home'),
  IceNavTab(icon: Icons.account_tree,       label: 'Branches',  route: '/admin/branches'),
  IceNavTab(icon: Icons.analytics_rounded,  label: 'Analytics', route: '/superadmin/analytics'),
  IceNavTab(icon: Icons.grid_view_rounded,  label: 'More',      route: '/superadmin/more'),
];
```

Active tab glow: `BoxShadow(color: IceColors.lime, blurRadius: 12, spreadRadius: 0)` on active tab icon.

---

## 6. Complete Screen Inventory

### 6.1 Shared / Public Screens

#### `SplashScreen`

**File**: `lib/core/router/app_router.dart` (inline widget)  
**Django equiv**: N/A  
**API**: None (reads local token)  
**Behavior**: Show ICEBERG logo + animated wave. After 1.5s, auth check → GoRouter redirect fires.

---

#### `LoginScreen`

**File**: `lib/features/auth/screens/login_screen.dart`  
**Django equiv**: `login.html` (standalone, no base.html)  
**API**: `POST /api/v1/auth/login/`  
**Fields**: `identifier` (email or Login ID), `password` (obscured, toggle visibility)  
**Error handling**: Show inline Snackbar on 401 — "Invalid credentials"  
**Rate limit**: On 429 — "Account temporarily locked. Try again later."  
**UI notes**:
- Full-screen gradient background: `LinearGradient([IceColors.navyDeep, IceColors.navy])`
- Centered card with `IceRadius.xl` corners
- Logo at top of card
- "Forgot password?" `TextButton` below submit (fixes Django Bug #2)
- Submit button background: `IceColors.lime`, text: `IceColors.navy`

---

#### `ForgotPasswordScreen`

**File**: `lib/features/auth/screens/forgot_password_screen.dart`  
**Django equiv**: `forgot_password.html`, `verify_reset_code.html`, `reset_password.html`  
**API**: Needs 3 new endpoints (see Section 11.3)  
**Flow**: Email entry → OTP verification → new password → success

---

#### `ProfileHubScreen`

**File**: `lib/shared/screens/profile_hub_screen.dart`  
**Django equiv**: `/profile-hub/` (all roles)  
**API**: `GET /api/v1/me/`, `PATCH /api/v1/me/`, `POST /api/v1/me/change-password/`  

**Sections**:
1. **Avatar picker**: Grid of 24 emoji stickers. Tap to select. Save via PATCH `/api/v1/me/`
2. **Profile form**: `first_name`, `last_name`, `address` (editable). `email`, `login_id` (read-only)
3. **Theme toggle**: Light / Dark. For students → PATCH `theme_preference`. For admin/staff → `ThemeMode` in Riverpod state (equivalent of localStorage)
4. **Change password**: `old_password`, `new_password`, `confirm_password`

**Avatar stickers** (24 emojis, matching Django profile-hub.html):
```dart
const List<String> iceAvatarEmojis = [
  '🦁', '🐯', '🦊', '🐺', '🦅', '🦉', '🐬', '🦈',
  '🌟', '⚡', '🔥', '💎', '🌊', '🏆', '🎯', '🚀',
  '🍀', '🌸', '🌙', '☀️', '❄️', '🌋', '🎸', '🎭',
];
```

---

#### `MessagesScreen`

**File**: `lib/shared/screens/messages_screen.dart`  
**Django equiv**: `messages.html`  
**API**: REST chat endpoints (MISSING — see Section 11.3)  
**Layout**: Thread list (left) + message area (right) on desktop; full-screen thread list → push to message view on mobile  
**Message bubble**: Own messages right-aligned (`IceColors.navyMid` + white text). Others left-aligned (`IceColors.surface2`).  
**Unread dot**: Red dot on Messages bottom nav tab when unread count > 0.

---

#### `NotificationsScreen`

**File**: `lib/shared/screens/notifications_screen.dart`  
**Django equiv**: Role-specific notification pages  
**API**: `GET /api/v1/notifications/`, `POST /api/v1/notifications/mark-all-read/`, `POST /api/v1/notifications/{pk}/read/`  
**Category icons**:
- `attendance` → `Icons.check_circle`
- `result` → `Icons.grade`
- `announcement` → `Icons.campaign`
- `homework` → `Icons.assignment`
- `vocabulary` → `Icons.menu_book`
- `payment` → `Icons.payment`
- `general` → `Icons.notifications`

---

### 6.2 Student Screens

#### `StudentHomeScreen`

**File**: `lib/features/student/screens/student_home_screen.dart`  
**Django equiv**: `erpnext_student_home.html`  
**API**: `GET /api/v1/student/home/`  

**Required dashboard data**:
```json
{
  "student_name": "Aziz Karimov",
  "attendance_percentage": 87.5,
  "attendance_present": 21,
  "attendance_total": 24,
  "average_score": 78,
  "enrolled_groups": 2,
  "total_subjects": 4,
  "notices": [...],
  "stories": [...],
  "rank_info": {"rank": 3, "total": 45, "score": 820, "badge": "gold"}
}
```

**UI sections**:
1. **Stories strip**: `IceStoryStrip` — horizontal `ListView.builder`, story cards 80×120dp, emoji + title
2. **Hero greeting card**: "Good morning, Aziz!" with attendance ring (donut `PieChart` from fl_chart)
3. **KPI row**: Attendance %, Groups, Avg Score, Rank (scrollable horizontal)
4. **Quick actions grid**: 2×4 grid — Vocabulary, Attendance, Results, Progress, Assignments, Payments, Leave, Library
5. **Notifications strip**: Recent 3 unread notifications

---

#### `StudentVocabularyListScreen`

**File**: `lib/features/student/screens/student_vocabulary_list_screen.dart`  
**Django equiv**: `vocabulary_day_list.html`  
**API**: `GET /api/v1/vocabulary/`  

**Card data per VocabularyDay**: `{id, title, day_number, word_count, is_released, completed, quiz_score}`  
**Completion indicator**: Green checkmark badge on completed days  
**Locked state**: Grayed out card + lock icon for unreleased days  
**Navigation**: Tap → `/student/vocabulary/:id`

---

#### `StudentVocabularyDetailScreen`

**File**: `lib/features/student/screens/student_vocabulary_detail_screen.dart`  
**Django equiv**: `vocabulary_day_detail.html`  
**API**: `GET /api/v1/vocabulary/{pk}/`  

**Word card layout**:
```
┌─────────────────────────────┐
│  weather (word)             │
│  ob-havo (translation)      │
│  Example: The weather today │
│  is sunny.                  │
└─────────────────────────────┘
```

**Action buttons**:
- "Study Flashcards" → `/student/vocabulary/:id/flashcard`
- "Take Quiz" → `/student/vocabulary/:id/quiz`
- "Mark Complete" (POST `/api/v1/vocabulary/{pk}/complete/`) — shows only if not completed

---

#### `StudentFlashcardScreen`

**File**: `lib/features/student/screens/student_flashcard_screen.dart`  
**Django equiv**: `vocabulary_day_flashcard.html`  
**API**: None (uses data from detail screen)  

**3D flip animation**:
```dart
// Front: English word. Back: Translation + example
AnimatedBuilder(
  animation: _flipAnimation,
  builder: (context, child) {
    final angle = _flipAnimation.value * math.pi;
    return Transform(
      alignment: Alignment.center,
      transform: Matrix4.identity()
        ..setEntry(3, 2, 0.001)
        ..rotateY(angle),
      child: angle < math.pi / 2 ? _buildFront() : _buildBack(),
    );
  },
)
```

**Navigation**: Prev / Next arrow buttons. Swipe left/right gesture. Progress bar "3 / 10".  
**Completion**: On last card → confetti animation → offer to take quiz.

---

#### `StudentQuizScreen`

**File**: `lib/features/student/screens/student_quiz_screen.dart`  
**Django equiv**: `vocabulary_day_quiz.html`  
**API**: `GET /api/v1/vocabulary/{pk}/quiz/`, `POST /api/v1/vocabulary/{pk}/quiz-result/`  

**Quiz flow**: One question at a time. 4 option buttons. Tap → immediate green/red feedback → Next. After all questions → score screen.

**Score screen**: Show `score/total`, badge (>80% = gold star), option to retry or return to list.

**POST body**: `{score: 8, total: 10}`

---

#### `StudentAttendanceScreen`

**File**: `lib/features/student/screens/student_attendance_screen.dart`  
**Django equiv**: `student_view_attendance.html`  
**API**: `GET /api/v1/attendance/`  

**Display**: Month filter + calendar-style grid. P = green, A = red, L = amber. Monthly summary: Present N, Absent N, Attendance N%.  
**Note**: Student sees ONLY own attendance (enforced by `IsStudent` permission on backend).

---

#### `StudentResultsScreen`

**File**: `lib/features/student/screens/student_results_screen.dart`  
**Django equiv**: `student_view_result.html`  
**API**: `GET /api/v1/results/`  

**Per result card**:
- Subject name
- Test: N/40, Exam: N/60, Total: N/100
- Grade badge: A (90+), B (75-89), C (60-74), D (<60)
- Teacher comment (if any)
- Score visualization: two stacked bars (test + exam)

---

#### `StudentAssignmentsScreen`

**File**: `lib/features/student/screens/student_assignments_screen.dart`  
**Django equiv**: `student_assignments.html`  
**API**: `GET /api/v1/assignments/`  

**Status badges**: `pending` (amber), `submitted` (blue), `graded` (green), `overdue` (red)  
**Submit**: Tap "Submit" → bottom sheet with `FilePicker` + note field → `POST /api/v1/assignments/{pk}/submit/`

---

#### `StudentLeaderboardScreen`

**File**: `lib/features/student/screens/student_leaderboard_screen.dart`  
**Django equiv**: `leaderboard.html`  
**API**: `GET /api/v1/leaderboard/`  

**Top 3 podium**: 1st (gold, center/tallest), 2nd (silver, left), 3rd (bronze, right).  
**Own row**: Highlighted with `IceColors.navyLight` background.  
**Season history**: Tap "History" → `/student/leaderboard/history`

---

#### `StudentProgressScreen`

**File**: `lib/features/student/screens/student_progress_screen.dart`  
**Django equiv**: `student_progress.html`  
**API**: `GET /api/v1/student/progress/`  

**Charts** (fl_chart):
1. Attendance trend — line chart, last 8 weeks
2. Quiz scores — bar chart, last 10 quizzes
3. Vocabulary completion — step bar chart

**Summary stats**: Current streak (days), Average score, Best quiz, Overall attendance %

---

#### `StudentPaymentsScreen`

**File**: `lib/features/student/screens/student_payments_screen.dart`  
**Django equiv**: `student_payments.html`  
**API**: `GET /api/v1/invoices/`  

**Per invoice card**: Period (e.g., "May 2026"), Amount, Discount, Paid, Balance, Status badge, Due date.  
**Total balance prominent**: Red if overdue.  
**Currency**: `CurrencyFormatter.format(amount)` → "450 000 so'm"  
**Receipt**: Tap paid invoice → `/student/payments/:id/receipt`

---

#### `StudentLeaveScreen`

**File**: `lib/features/student/screens/student_leave_screen.dart`  
**Django equiv**: `student_apply_leave.html`  
**API**: `GET/POST /api/v1/leave/`  

**Statuses**: `0`=Pending (amber), `1`=Approved (green), `-1`=Rejected (red).  
**Form**: Date picker, reason textarea. POST creates `LeaveReportStudent`.

---

#### `StudentFeedbackScreen`

**File**: `lib/features/student/screens/student_feedback_screen.dart`  
**Django equiv**: `student_feedback.html`  
**API**: `GET/POST /api/v1/feedback/`  

**Thread-style display**: Student message → admin reply (indented, `IceColors.surface2` bg).

---

#### `StudentBooksScreen`

**File**: `lib/features/student/screens/student_books_screen.dart`  
**Django equiv**: `view_books.html`  
**API**: `GET /api/v1/library/loans/` (MISSING — see Section 11.3)  

**Loan card**: Book title, Author, Issued date, Due date, Status (active/overdue/returned), Fine amount (if overdue).  
**Fine display**: Use `CurrencyFormatter` — NOT `₹` symbol (fixes Django Bug #7).  
**Return button**: `POST /api/v1/library/loans/{id}/return/`

---

### 6.3 Staff Screens

#### `StaffHomeScreen`

**File**: `lib/features/staff/screens/staff_home_screen.dart`  
**Django equiv**: `erpnext_staff_home.html`  
**API**: `GET /api/v1/stats/`  

**KPI cards**: Total students (across own groups), Groups count, Attendance % (today), Pending submissions.  
**Charts**: Attendance rate line chart (last 8 weeks), using `fl_chart`.  
**Quick actions**: Take Attendance, Update Attendance, Add Results, Edit Results, Vocabulary, Messages, Assignments, Profile.

---

#### `StaffTakeAttendanceScreen`

**File**: `lib/features/staff/screens/staff_take_attendance_screen.dart`  
**Django equiv**: `staff_take_attendance.html`  
**API**: `GET /api/v1/groups/`, `GET /api/v1/attendance/?group_id=X&date=Y`, `POST /api/v1/attendance/`  

**Flow**:
1. Dropdown: select group (own groups only)
2. Date picker: select date (default today)
3. Load student list: `GET /api/v1/groups/{pk}/` → `enrolled_students`
4. Per student: 3-chip toggle (P / L / A) with color feedback
5. "Save" → `POST /api/v1/attendance/` → `{group_id, date, records: [{student_id, status}]}`

**POST body example**:
```json
{
  "group_id": 5,
  "date": "2026-06-11",
  "records": [
    {"student_id": 12, "status": "P"},
    {"student_id": 13, "status": "A"},
    {"student_id": 14, "status": "L"}
  ]
}
```

---

#### `StaffResultsScreen`

**File**: `lib/features/staff/screens/staff_results_screen.dart`  
**Django equiv**: `staff_add_result.html`  
**API**: `GET /api/v1/results/?group_id=X`, `POST /api/v1/results/`, `PATCH /api/v1/results/{pk}/`  

**Score ranges**: Test 0–40, Exam 0–60. Both validated client-side.  
**POST body**: `{student_id, group_id, test, exam, comment}`  
**IDOR note**: Backend must verify `group.teacher == request.user.staff`.

---

#### `StaffVocabularyListScreen`

**File**: `lib/features/staff/screens/staff_vocabulary_list_screen.dart`  
**Django equiv**: `staff_vocabulary_days.html`  
**API**: `GET /api/v1/staff/vocabulary/`  

**Status**: Released (green) vs Scheduled (amber) vs Draft (gray).  
**FAB**: "Add Vocabulary Day" → `/staff/vocabulary/add`

---

#### `StaffVocabularyDetailScreen`

**File**: `lib/features/staff/screens/staff_vocabulary_detail_screen.dart`  
**Django equiv**: `staff_vocabulary_day_detail.html`  
**API**: `GET/PATCH/DELETE /api/v1/staff/vocabulary/{pk}/`, `GET/POST /api/v1/staff/vocabulary/{pk}/words/`, `DELETE /api/v1/staff/vocabulary/{pk}/words/{word_pk}/`  

**Word add form**: `word`, `translation`, `example_sentence` (optional), image upload (optional).  
**Word list**: Swipe-to-delete with confirmation.

---

### 6.4 Admin Screens

#### `AdminHomeScreen`

**File**: `lib/features/admin/screens/admin_home_screen.dart`  
**Django equiv**: `home_content.html`  
**API**: `GET /api/v1/admin/home/`, `GET /api/v1/admin/stats/`  

**KPI cards** (4):
- Total Students (with week-over-week trend arrow)
- Total Staff
- Active Groups
- Average Attendance %

**Charts** (fl_chart):
- Enrollment trend line chart (last 6 months)
- Branch performance multi-line chart

**Quick actions grid** (8 buttons):
- Add Student → `/admin/students/add`
- Add Teacher → `/admin/staff/add`
- Add Group → `/admin/groups/add`
- Enroll Student → `/admin/enrollment`
- View Attendance → `/admin/attendance`
- Payments → `/admin/payments`
- Messages → `/messages`
- Leads → `/admin/leads`

---

#### `AdminStudentsScreen`

**File**: `lib/features/admin/screens/admin_students_screen.dart`  
**Django equiv**: `manage_student.html`  
**API**: `GET /api/v1/admin/students/`, `DELETE /api/v1/admin/students/{pk}/`  

**Columns** (mobile: card; desktop: data table):  
Name, Login ID, Course, Branch, Status, Actions (Edit, Delete)

**Branch scope**: Admin sees only own branch students. Super admin sees all.  
**Search**: Filter by name or login_id client-side.  
**Delete**: `IceConfirmDialog` before `DELETE /api/v1/admin/students/{pk}/`

---

#### `AdminAddStudentScreen` / `AdminEditStudentScreen`

**Files**: `lib/features/admin/screens/admin_add_student_screen.dart`, `admin_edit_student_screen.dart`  
**Django equiv**: `add_student_template.html`, `edit_student_template.html`  
**API**: `POST /api/v1/admin/students/` (add), `GET + PATCH /api/v1/admin/students/{pk}/` (edit)  

**Fields**: `first_name`, `last_name`, `email`, `date_of_birth`, `gender` (dropdown: M/F/O), `phone`, `address`, `course` (dropdown), `branch` (dropdown), `status` (dropdown), `level` (optional), `password` (add only)  
**Login ID**: Auto-generated by backend. Show in success toast: "Student created! Login ID: IC052401"

---

#### `AdminGroupsScreen`

**File**: `lib/features/admin/screens/admin_groups_screen.dart`  
**Django equiv**: `manage_group.html`  
**API**: `GET /api/v1/admin/groups/` (NEED CRUD: POST, PATCH, DELETE — see Section 11.3)  

**Card info**: Name, Course, Teacher, Branch, Schedule, Capacity/Enrolled, Monthly Fee, Archived badge.  
**Actions**: View Students → `/admin/groups/:id`, Edit → `/admin/groups/:id/edit`, Archive/Unarchive, Delete.

---

#### `AdminGroupDetailScreen`

**File**: `lib/features/admin/screens/admin_group_detail_screen.dart`  
**Django equiv**: `group_detail.html`  
**API**: `GET /api/v1/admin/groups/{pk}/`  

**Data**: Group info + `enrolled_students: [{id, name, login_id, status}]`  
**Actions**: Remove student from group (DELETE enrollment), Add enrollment button → modal.

---

#### `AdminEnrollmentScreen`

**File**: `lib/features/admin/screens/admin_enrollment_screen.dart`  
**Django equiv**: `manage_enrollment.html`, `add_enrollment.html`  
**API**: `GET /api/v1/admin/enrollments/`, `POST /api/v1/admin/enrollments/`, `DELETE /api/v1/admin/enrollments/{pk}/`  

**Add enrollment flow**: Select course → filter groups → select student → confirm. Cascading dropdowns.

---

#### `AdminPaymentsScreen`

**File**: `lib/features/admin/screens/admin_payments_screen.dart`  
**Django equiv**: `manage_payments.html`  
**API**: `GET /api/v1/admin/invoices-manage/`, `POST /api/v1/admin/invoices-manage/{pk}/pay/`  

**Filters**: Period (YYYY-MM), Group, Status.  
**Record payment modal**: `amount`, `method` (dropdown: cash/card/transfer/payme/click/uzum), `note`, `paid_on`.  
**Currency**: All amounts in UZS soʻm via `CurrencyFormatter`.

---

#### `AdminLeadsScreen`

**File**: `lib/features/admin/screens/admin_leads_screen.dart`  
**Django equiv**: `manage_registration_leads.html`  
**API**: `GET /api/v1/admin/leads/`, `PATCH /api/v1/admin/leads/{pk}/`  

**Status filter chips**: New (red dot), Contacted (amber), Enrolled (green), Rejected (gray).  
**Quick status update**: Inline dropdown per row → PATCH status.

---

#### `AdminLeaveScreen`

**File**: `lib/features/admin/screens/admin_leave_screen.dart`  
**Django equiv**: `student_leave_view.html` + `staff_leave_view.html`  
**API**: `GET /api/v1/admin/leave-requests/`, `PATCH /api/v1/admin/leave-requests/{pk}/`  

**Tabs**: Student Requests / Staff Requests.  
**PATCH body**: `{status: "1"}` (approve) or `{status: "-1"}` (reject).

---

---

## 7. Dart Data Models

All models use `fromJson` factory constructors. Use `json_serializable` or hand-write.

### 7.1 Core Models

```dart
// lib/features/student/models/student_models.dart

class Branch {
  final int id;
  final String name;
  final String? address;

  const Branch({required this.id, required this.name, this.address});

  factory Branch.fromJson(Map<String, dynamic> j) => Branch(
    id: j['id'], name: j['name'], address: j['address'],
  );
}

class Course {
  final int id;
  final String courseName;
  final bool isActive;
  final double? monthlyFee;

  const Course({required this.id, required this.courseName, required this.isActive, this.monthlyFee});

  factory Course.fromJson(Map<String, dynamic> j) => Course(
    id: j['id'], courseName: j['course_name'],
    isActive: j['is_active'] ?? true, monthlyFee: (j['monthly_fee'] as num?)?.toDouble(),
  );
}

class Group {
  final int id;
  final String name;
  final int courseId;
  final String courseName;
  final int? teacherId;
  final String? teacherName;
  final int? branchId;
  final String? branchName;
  final String? room;
  final String? schedule;
  final int capacity;
  final int enrolledCount;
  final double? monthlyFee;
  final bool isArchived;

  const Group({
    required this.id, required this.name,
    required this.courseId, required this.courseName,
    this.teacherId, this.teacherName,
    this.branchId, this.branchName,
    this.room, this.schedule,
    this.capacity = 0, this.enrolledCount = 0,
    this.monthlyFee, this.isArchived = false,
  });

  factory Group.fromJson(Map<String, dynamic> j) => Group(
    id: j['id'], name: j['name'],
    courseId: j['course_id'] ?? j['course'], courseName: j['course_name'] ?? '',
    teacherId: j['teacher_id'], teacherName: j['teacher_name'],
    branchId: j['branch_id'], branchName: j['branch_name'],
    room: j['room'], schedule: j['schedule'],
    capacity: j['capacity'] ?? 0, enrolledCount: j['enrolled_count'] ?? 0,
    monthlyFee: (j['monthly_fee'] as num?)?.toDouble(),
    isArchived: j['is_archived'] ?? false,
  );
}
```

### 7.2 Attendance Models

```dart
class AttendanceRecord {
  final int id;
  final int studentId;
  final String studentName;
  final DateTime date;
  final String status;   // 'P', 'A', 'L'

  const AttendanceRecord({
    required this.id, required this.studentId, required this.studentName,
    required this.date, required this.status,
  });

  factory AttendanceRecord.fromJson(Map<String, dynamic> j) => AttendanceRecord(
    id: j['id'], studentId: j['student_id'] ?? j['student'],
    studentName: j['student_name'] ?? '',
    date: DateTime.parse(j['date'] as String),
    status: j['status'] as String,
  );

  bool get isPresent => status == 'P';
  bool get isAbsent  => status == 'A';
  bool get isLate    => status == 'L';
}

class AttendanceSummary {
  final int present;
  final int absent;
  final int late;
  final int total;

  const AttendanceSummary({
    required this.present, required this.absent,
    required this.late, required this.total,
  });

  double get rate => total == 0 ? 0.0 : (present + late) / total * 100;

  factory AttendanceSummary.fromRecords(List<AttendanceRecord> records) {
    return AttendanceSummary(
      present: records.where((r) => r.isPresent).length,
      absent:  records.where((r) => r.isAbsent).length,
      late:    records.where((r) => r.isLate).length,
      total:   records.length,
    );
  }
}
```

### 7.3 Result Models

```dart
class StudentResult {
  final int id;
  final int studentId;
  final String? studentName;
  final int groupId;
  final String? subjectName;
  final double test;    // 0–40
  final double exam;    // 0–60
  final String? comment;

  const StudentResult({
    required this.id, required this.studentId, this.studentName,
    required this.groupId, this.subjectName,
    required this.test, required this.exam, this.comment,
  });

  double get total => test + exam;

  String get grade {
    if (total >= 90) return 'A';
    if (total >= 75) return 'B';
    if (total >= 60) return 'C';
    return 'D';
  }

  factory StudentResult.fromJson(Map<String, dynamic> j) => StudentResult(
    id: j['id'], studentId: j['student_id'] ?? j['student'],
    studentName: j['student_name'], groupId: j['group_id'] ?? j['group'],
    subjectName: j['subject_name'],
    test: (j['test'] as num).toDouble(), exam: (j['exam'] as num).toDouble(),
    comment: j['comment'],
  );
}
```

### 7.4 Vocabulary Models

```dart
class VocabularyDay {
  final int id;
  final String title;
  final int dayNumber;
  final int wordCount;
  final DateTime? releaseAt;
  final bool isReleased;
  final bool completed;
  final int? quizScore;
  final int? quizTotal;

  const VocabularyDay({
    required this.id, required this.title, required this.dayNumber,
    required this.wordCount, this.releaseAt, required this.isReleased,
    this.completed = false, this.quizScore, this.quizTotal,
  });

  factory VocabularyDay.fromJson(Map<String, dynamic> j) => VocabularyDay(
    id: j['id'], title: j['title'], dayNumber: j['day_number'] ?? 0,
    wordCount: j['word_count'] ?? 0,
    releaseAt: j['release_at'] != null ? DateTime.parse(j['release_at']) : null,
    isReleased: j['is_released'] ?? false,
    completed: j['completed'] ?? false,
    quizScore: j['quiz_score'], quizTotal: j['quiz_total'],
  );
}

class VocabularyWord {
  final int id;
  final String word;
  final String translation;
  final String? exampleSentence;
  final String? imageUrl;

  const VocabularyWord({
    required this.id, required this.word, required this.translation,
    this.exampleSentence, this.imageUrl,
  });

  factory VocabularyWord.fromJson(Map<String, dynamic> j) => VocabularyWord(
    id: j['id'], word: j['word'], translation: j['translation'],
    exampleSentence: j['example_sentence'], imageUrl: j['image_url'],
  );
}

class QuizQuestion {
  final String word;
  final List<String> options;
  final int correctIndex;

  const QuizQuestion({required this.word, required this.options, required this.correctIndex});

  factory QuizQuestion.fromJson(Map<String, dynamic> j) => QuizQuestion(
    word: j['word'], options: List<String>.from(j['options']),
    correctIndex: j['correct_index'],
  );
}
```

### 7.5 Invoice / Payment Models

```dart
class Invoice {
  final int id;
  final int studentId;
  final String? studentName;
  final String period;       // 'YYYY-MM'
  final double amount;
  final double discount;
  final double paid;
  final String status;       // 'pending', 'partial', 'paid', 'overdue'
  final DateTime? dueDate;

  const Invoice({
    required this.id, required this.studentId, this.studentName,
    required this.period, required this.amount, required this.discount,
    required this.paid, required this.status, this.dueDate,
  });

  double get balance => amount - discount - paid;
  bool get isOverdue => status == 'overdue';
  bool get isPaid    => status == 'paid';

  factory Invoice.fromJson(Map<String, dynamic> j) => Invoice(
    id: j['id'], studentId: j['student_id'] ?? j['student'],
    studentName: j['student_name'], period: j['period'] ?? '',
    amount: (j['amount'] as num).toDouble(),
    discount: (j['discount'] as num? ?? 0).toDouble(),
    paid: (j['paid'] as num? ?? 0).toDouble(),
    status: j['status'] ?? 'pending',
    dueDate: j['due_date'] != null ? DateTime.parse(j['due_date']) : null,
  );
}
```

### 7.6 Leave & Feedback Models

```dart
class LeaveRequest {
  final int id;
  final DateTime date;
  final String message;
  final int status;   // 0=pending, 1=approved, -1=rejected
  final String? adminComment;
  final DateTime createdAt;

  const LeaveRequest({
    required this.id, required this.date, required this.message,
    required this.status, this.adminComment, required this.createdAt,
  });

  String get statusLabel => switch (status) {
    1  => 'Approved',
    -1 => 'Rejected',
    _  => 'Pending',
  };

  factory LeaveRequest.fromJson(Map<String, dynamic> j) => LeaveRequest(
    id: j['id'], date: DateTime.parse(j['date']),
    message: j['message'], status: j['status'] ?? 0,
    adminComment: j['admin_comment'],
    createdAt: DateTime.parse(j['created_at']),
  );
}

class FeedbackItem {
  final int id;
  final String message;
  final String? reply;
  final DateTime? repliedAt;
  final DateTime createdAt;

  const FeedbackItem({
    required this.id, required this.message, this.reply,
    this.repliedAt, required this.createdAt,
  });

  factory FeedbackItem.fromJson(Map<String, dynamic> j) => FeedbackItem(
    id: j['id'], message: j['feedback'] ?? j['message'] ?? '',
    reply: j['reply'],
    repliedAt: j['replied_at'] != null ? DateTime.parse(j['replied_at']) : null,
    createdAt: DateTime.parse(j['created_at']),
  );
}
```

### 7.7 Leaderboard & Progress Models

```dart
class LeaderboardEntry {
  final int rank;
  final int studentId;
  final String studentName;
  final String avatarEmoji;
  final double score;
  final String? badge;

  const LeaderboardEntry({
    required this.rank, required this.studentId, required this.studentName,
    required this.avatarEmoji, required this.score, this.badge,
  });

  factory LeaderboardEntry.fromJson(Map<String, dynamic> j) => LeaderboardEntry(
    rank: j['rank'], studentId: j['student_id'],
    studentName: j['student_name'], avatarEmoji: j['avatar_emoji'] ?? '🌟',
    score: (j['score'] as num).toDouble(), badge: j['badge'],
  );
}

class ProgressData {
  final List<({String label, double rate})> attendanceTrend;
  final List<({DateTime date, int score, int total})> quizHistory;
  final List<({String dayTitle, bool completed})> vocabCompletion;

  const ProgressData({
    required this.attendanceTrend,
    required this.quizHistory,
    required this.vocabCompletion,
  });

  factory ProgressData.fromJson(Map<String, dynamic> j) => ProgressData(
    attendanceTrend: (j['attendance_trend'] as List)
      .map((e) => (label: e['month'] as String, rate: (e['rate'] as num).toDouble()))
      .toList(),
    quizHistory: (j['quiz_history'] as List)
      .map((e) => (
        date: DateTime.parse(e['date']),
        score: e['score'] as int,
        total: e['total'] as int,
      )).toList(),
    vocabCompletion: (j['vocab_completion'] as List)
      .map((e) => (dayTitle: e['day'] as String, completed: e['completed'] as bool))
      .toList(),
  );
}
```

### 7.8 Story & Notification Models

```dart
class DashboardStory {
  final int id;
  final String title;
  final String content;
  final String? imageUrl;
  final String? emoji;
  final String? bgColor;
  final bool isActive;

  const DashboardStory({
    required this.id, required this.title, required this.content,
    this.imageUrl, this.emoji, this.bgColor, required this.isActive,
  });

  factory DashboardStory.fromJson(Map<String, dynamic> j) => DashboardStory(
    id: j['id'], title: j['title'], content: j['content'] ?? '',
    imageUrl: j['image_url'], emoji: j['emoji'], bgColor: j['bg_color'],
    isActive: j['is_active'] ?? true,
  );
}

class AppNotification {
  final int id;
  final String message;
  final String category;
  final bool isRead;
  final DateTime createdAt;

  const AppNotification({
    required this.id, required this.message, required this.category,
    required this.isRead, required this.createdAt,
  });

  factory AppNotification.fromJson(Map<String, dynamic> j) => AppNotification(
    id: j['id'], message: j['message'], category: j['category'] ?? 'general',
    isRead: j['is_read'] ?? false, createdAt: DateTime.parse(j['created_at']),
  );
}
```

---

## 8. API Service Layer

### 8.1 Repository Pattern

```dart
// lib/features/student/data/student_repository.dart

class StudentRepository {
  final Dio _dio;
  const StudentRepository(this._dio);

  Future<Map<String, dynamic>> getHomeDashboard() async {
    final r = await _dio.get('/api/v1/student/home/');
    return r.data as Map<String, dynamic>;
  }

  Future<List<VocabularyDay>> getVocabularyDays() async {
    final r = await _dio.get('/api/v1/vocabulary/');
    return (r.data as List).map(VocabularyDay.fromJson).toList();
  }

  Future<VocabularyDay> getVocabularyDay(int pk) async {
    final r = await _dio.get('/api/v1/vocabulary/$pk/');
    return VocabularyDay.fromJson(r.data);
  }

  Future<List<AttendanceRecord>> getAttendance() async {
    final r = await _dio.get('/api/v1/attendance/');
    return (r.data as List).map(AttendanceRecord.fromJson).toList();
  }

  Future<List<StudentResult>> getResults() async {
    final r = await _dio.get('/api/v1/results/');
    return (r.data as List).map(StudentResult.fromJson).toList();
  }

  Future<List<Invoice>> getInvoices() async {
    final r = await _dio.get('/api/v1/invoices/');
    return (r.data as List).map(Invoice.fromJson).toList();
  }

  Future<void> submitQuizResult(int dayPk, int score, int total) async {
    await _dio.post('/api/v1/vocabulary/$dayPk/quiz-result/', data: {
      'score': score,
      'total': total,
    });
  }

  Future<void> markVocabularyComplete(int dayPk) async {
    await _dio.post('/api/v1/vocabulary/$dayPk/complete/');
  }

  Future<void> submitAssignment(int assignmentPk, {
    required List<int> fileBytes, required String fileName, String? note,
  }) async {
    final formData = FormData.fromMap({
      'file': MultipartFile.fromBytes(fileBytes, filename: fileName),
      if (note != null) 'note': note,
    });
    await _dio.post('/api/v1/assignments/$assignmentPk/submit/', data: formData);
  }

  Future<void> submitLeave(DateTime date, String message) async {
    await _dio.post('/api/v1/leave/', data: {
      'date': DateFormat('yyyy-MM-dd').format(date),
      'message': message,
    });
  }

  Future<void> submitFeedback(String message) async {
    await _dio.post('/api/v1/feedback/', data: {'feedback': message});
  }
}
```

### 8.2 Staff Repository

```dart
class StaffRepository {
  final Dio _dio;
  const StaffRepository(this._dio);

  Future<List<Group>> getOwnGroups() async {
    final r = await _dio.get('/api/v1/groups/');
    return (r.data as List).map(Group.fromJson).toList();
  }

  Future<void> saveAttendance({
    required int groupId, required String date,
    required List<Map<String, dynamic>> records,
  }) async {
    await _dio.post('/api/v1/attendance/', data: {
      'group_id': groupId, 'date': date, 'records': records,
    });
  }

  Future<void> saveResult({
    required int studentId, required int groupId,
    required double test, required double exam, String? comment,
  }) async {
    await _dio.post('/api/v1/results/', data: {
      'student_id': studentId, 'group_id': groupId,
      'test': test, 'exam': exam, if (comment != null) 'comment': comment,
    });
  }

  Future<List<VocabularyDay>> getVocabularyDays() async {
    final r = await _dio.get('/api/v1/staff/vocabulary/');
    return (r.data as List).map(VocabularyDay.fromJson).toList();
  }
}
```

### 8.3 Admin Repository

```dart
class AdminRepository {
  final Dio _dio;
  const AdminRepository(this._dio);

  Future<Map<String, dynamic>> getHomeDashboard() async {
    final r = await _dio.get('/api/v1/admin/home/');
    return r.data;
  }

  Future<List<Map<String, dynamic>>> getStudents() async {
    final r = await _dio.get('/api/v1/admin/students/');
    return List<Map<String, dynamic>>.from(r.data);
  }

  Future<void> deleteStudent(int pk) async {
    await _dio.delete('/api/v1/admin/students/$pk/');
  }

  Future<void> approveLeave(int pk) async {
    await _dio.patch('/api/v1/admin/leave-requests/$pk/', data: {'status': '1'});
  }

  Future<void> rejectLeave(int pk) async {
    await _dio.patch('/api/v1/admin/leave-requests/$pk/', data: {'status': '-1'});
  }

  Future<void> recordPayment(int invoicePk, {
    required double amount, required String method, String? note,
  }) async {
    await _dio.post('/api/v1/admin/invoices-manage/$invoicePk/pay/', data: {
      'amount': amount, 'method': method, if (note != null) 'note': note,
      'paid_on': DateFormat('yyyy-MM-dd').format(DateTime.now()),
    });
  }

  Future<void> sendNotification({
    required String title, required String body, required String target,
    int? groupId, int? branchId,
  }) async {
    await _dio.post('/api/v1/admin/send-notification/', data: {
      'title': title, 'body': body, 'target': target,
      if (groupId != null) 'group_id': groupId,
      if (branchId != null) 'branch_id': branchId,
    });
  }
}
```

---

## 9. State Management Architecture

### 9.1 Auth Provider

```dart
// lib/core/auth/auth_notifier.dart

@riverpod
class AuthNotifier extends _$AuthNotifier {
  @override
  Future<AuthState> build() async {
    final token = await ref.read(tokenStorageProvider).getAccessToken();
    if (token == null) return const AuthState.unauthenticated();

    try {
      final user = await ref.read(apiClientProvider).get('/api/v1/me/');
      return AuthState.authenticated(AuthUser.fromJson(user.data));
    } catch (_) {
      return const AuthState.unauthenticated();
    }
  }

  Future<void> login(String identifier, String password) async {
    state = const AsyncValue.loading();
    final response = await ref.read(authRepositoryProvider)
      .login(identifier, password);
    final storage = ref.read(tokenStorageProvider);
    await storage.setAccessToken(response.access);
    await storage.setRefreshToken(response.refresh);
    final me = await ref.read(apiClientProvider).get('/api/v1/me/');
    state = AsyncValue.data(AuthState.authenticated(AuthUser.fromJson(me.data)));
  }

  Future<void> logout() async {
    final refresh = await ref.read(tokenStorageProvider).getRefreshToken();
    try {
      await ref.read(apiClientProvider)
        .post('/api/v1/auth/logout/', data: {'refresh': refresh});
    } catch (_) {}
    await ref.read(tokenStorageProvider).clear();
    state = const AsyncValue.data(AuthState.unauthenticated());
  }
}
```

### 9.2 Feature Providers

```dart
// Example: student home data provider
@riverpod
Future<Map<String, dynamic>> studentHome(StudentHomeRef ref) async {
  return ref.read(studentRepositoryProvider).getHomeDashboard();
}

// Vocabulary list
@riverpod
Future<List<VocabularyDay>> vocabularyDays(VocabularyDaysRef ref) async {
  return ref.read(studentRepositoryProvider).getVocabularyDays();
}

// Vocabulary detail (with family)
@riverpod
Future<VocabularyDayDetail> vocabularyDetail(VocabularyDetailRef ref, int pk) async {
  return ref.read(studentRepositoryProvider).getVocabularyDay(pk);
}

// Attendance data
@riverpod
Future<List<AttendanceRecord>> attendance(AttendanceRef ref) async {
  return ref.read(studentRepositoryProvider).getAttendance();
}
```

### 9.3 Theme Provider (replaces localStorage for admin/staff)

```dart
@riverpod
class ThemeNotifier extends _$ThemeNotifier {
  @override
  ThemeMode build() {
    // Students: read from AuthUser.themePreference (DB-stored)
    // Admin/Staff: read from SharedPreferences 'ice_ui_theme'
    final user = ref.watch(authProvider).value?.user;
    if (user?.isStudentUser == true) {
      return user!.themePreference == 'dark' ? ThemeMode.dark : ThemeMode.light;
    }
    // For admin/staff use SharedPreferences
    return ThemeMode.light; // default, updated from prefs in init
  }

  Future<void> setTheme(ThemeMode mode) async {
    state = mode;
    final user = ref.read(authProvider).value?.user;
    if (user?.isStudentUser == true) {
      // Save to DB
      await ref.read(apiClientProvider).patch('/api/v1/me/', data: {
        'theme_preference': mode == ThemeMode.dark ? 'dark' : 'light',
      });
    } else {
      // Save to SharedPreferences
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('ice_ui_theme', mode == ThemeMode.dark ? 'dark' : 'light');
    }
  }
}
```

---

## 10. Feature Implementation Details

### 10.1 Flashcard 3D Flip Animation

```dart
class FlashcardWidget extends StatefulWidget {
  final VocabularyWord word;
  const FlashcardWidget({required this.word, super.key});

  @override
  State<FlashcardWidget> createState() => _FlashcardWidgetState();
}

class _FlashcardWidgetState extends State<FlashcardWidget>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;
  bool _showFront = true;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this, duration: const Duration(milliseconds: 600),
    );
    _animation = Tween<double>(begin: 0, end: 1).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOut),
    );
  }

  void _flip() {
    if (_showFront) {
      _controller.forward();
    } else {
      _controller.reverse();
    }
    setState(() => _showFront = !_showFront);
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: _flip,
      child: AnimatedBuilder(
        animation: _animation,
        builder: (context, _) {
          final isShowingFront = _animation.value < 0.5;
          return Transform(
            alignment: Alignment.center,
            transform: Matrix4.identity()
              ..setEntry(3, 2, 0.001)
              ..rotateY(_animation.value * 3.14159),
            child: isShowingFront
              ? _buildFront()
              : Transform(
                  alignment: Alignment.center,
                  transform: Matrix4.identity()..rotateY(3.14159),
                  child: _buildBack(),
                ),
          );
        },
      ),
    );
  }

  Widget _buildFront() => Card(
    color: IceColors.navy,
    child: Center(
      child: Text(widget.word.word, style: IceTextStyles.display.copyWith(color: IceColors.lime)),
    ),
  );

  Widget _buildBack() => Card(
    color: IceColors.navyMid,
    child: Padding(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Text(widget.word.translation, style: IceTextStyles.h1.copyWith(color: Colors.white)),
          if (widget.word.exampleSentence != null) ...[
            const SizedBox(height: 12),
            Text(widget.word.exampleSentence!, style: IceTextStyles.body.copyWith(color: IceColors.textLight)),
          ],
        ],
      ),
    ),
  );
}
```

### 10.2 Attendance Toggle Widget

```dart
class AttendanceToggle extends StatelessWidget {
  final String status;   // 'P', 'A', 'L'
  final ValueChanged<String> onChanged;

  const AttendanceToggle({required this.status, required this.onChanged, super.key});

  @override
  Widget build(BuildContext context) {
    return SegmentedButton<String>(
      segments: const [
        ButtonSegment(value: 'P', label: Text('P'), icon: Icon(Icons.check_circle)),
        ButtonSegment(value: 'L', label: Text('L'), icon: Icon(Icons.access_time)),
        ButtonSegment(value: 'A', label: Text('A'), icon: Icon(Icons.cancel)),
      ],
      selected: {status},
      onSelectionChanged: (s) => onChanged(s.first),
      style: ButtonStyle(
        backgroundColor: WidgetStateProperty.resolveWith<Color?>((states) {
          if (states.contains(WidgetState.selected)) {
            return switch (status) {
              'P' => IceColors.success,
              'L' => IceColors.warning,
              'A' => IceColors.danger,
              _   => null,
            };
          }
          return null;
        }),
      ),
    );
  }
}
```

### 10.3 UZS Currency Display Widget

```dart
// lib/shared/widgets/ice_currency_text.dart

class IceCurrencyText extends StatelessWidget {
  final num amount;
  final TextStyle? style;
  final bool showPositiveSign;

  const IceCurrencyText(this.amount, {this.style, this.showPositiveSign = false, super.key});

  @override
  Widget build(BuildContext context) {
    // Format: "450 000 so'm"
    final formatted = NumberFormat('#,##0', 'en_US')
      .format(amount.toInt())
      .replaceAll(',', ' ');    // Use space instead of comma
    final sign = showPositiveSign && amount > 0 ? '+' : '';
    return Text("$sign$formatted so'm", style: style);
  }
}
```

### 10.4 Story Strip Widget

```dart
// lib/shared/widgets/ice_story_strip.dart

class IceStoryStrip extends StatelessWidget {
  final List<DashboardStory> stories;

  const IceStoryStrip({required this.stories, super.key});

  @override
  Widget build(BuildContext context) {
    if (stories.isEmpty) return const SizedBox.shrink();
    return SizedBox(
      height: 100,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 16),
        itemCount: stories.length,
        separatorBuilder: (_, __) => const SizedBox(width: 12),
        itemBuilder: (context, i) => _StoryCard(story: stories[i]),
      ),
    );
  }
}

class _StoryCard extends StatelessWidget {
  final DashboardStory story;

  const _StoryCard({required this.story});

  @override
  Widget build(BuildContext context) {
    final bgColor = story.bgColor != null
      ? Color(int.parse('0xFF${story.bgColor!.replaceAll('#', '')}'))
      : IceColors.navyMid;

    return InkWell(
      borderRadius: IceRadius.lgBR,
      onTap: () => _showStoryDetail(context),
      child: Container(
        width: 72,
        decoration: BoxDecoration(
          color: bgColor,
          borderRadius: IceRadius.lgBR,
        ),
        padding: const EdgeInsets.all(8),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            if (story.imageUrl != null)
              CachedNetworkImage(imageUrl: story.imageUrl!, height: 40)
            else
              Text(story.emoji ?? '📖', style: const TextStyle(fontSize: 32)),
            const SizedBox(height: 4),
            Text(
              story.title,
              style: IceTextStyles.xs.copyWith(color: Colors.white),
              textAlign: TextAlign.center,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }

  void _showStoryDetail(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) => _StoryDetailSheet(story: story),
    );
  }
}
```

### 10.5 Responsive Shell

```dart
// lib/shared/widgets/adaptive_shell.dart

class AdaptiveShell extends ConsumerWidget {
  final Widget child;
  final List<IceNavTab> tabs;
  final String currentRoute;

  const AdaptiveShell({
    required this.child, required this.tabs,
    required this.currentRoute, super.key,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final width = MediaQuery.of(context).size.width;

    if (width >= IceBreakpoints.desktop) {
      // Desktop: sidebar + content
      return Scaffold(
        body: Row(
          children: [
            IceSidebar(tabs: tabs, currentRoute: currentRoute),  // 256dp wide
            Expanded(child: child),
          ],
        ),
      );
    }

    // Mobile/tablet: bottom nav
    return Scaffold(
      body: child,
      bottomNavigationBar: IceBottomNav(tabs: tabs, currentRoute: currentRoute),
    );
  }
}
```

### 10.6 Error & Loading Patterns

```dart
// lib/shared/widgets/ice_async_builder.dart

class IceAsyncBuilder<T> extends StatelessWidget {
  final AsyncValue<T> value;
  final Widget Function(T data) builder;
  final VoidCallback? onRetry;

  const IceAsyncBuilder({required this.value, required this.builder, this.onRetry, super.key});

  @override
  Widget build(BuildContext context) {
    return value.when(
      loading: () => const IceSkeleton(),
      error: (e, _) => IceErrorState(message: e.toString(), onRetry: onRetry),
      data: builder,
    );
  }
}

class IceErrorState extends StatelessWidget {
  final String message;
  final VoidCallback? onRetry;

  const IceErrorState({required this.message, this.onRetry, super.key});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.wifi_off_rounded, size: 64, color: IceColors.textLight),
            const SizedBox(height: 16),
            Text('Could not load data', style: IceTextStyles.h2),
            const SizedBox(height: 8),
            Text(message, style: IceTextStyles.sm, textAlign: TextAlign.center),
            if (onRetry != null) ...[
              const SizedBox(height: 24),
              ElevatedButton.icon(
                onPressed: onRetry,
                icon: const Icon(Icons.refresh),
                label: const Text('Retry'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
```

---

## 11. Migration Phases & Priorities

### 11.1 Phase Overview

| Phase | Scope | Status |
|---|---|---|
| Phase 0 | Foundation (auth, router, design system, API client) | Complete |
| Phase 1 | Student MVP (all student screens) | Complete |
| Phase 2 | Staff MVP (all staff screens) | Complete |
| Phase 3 | Admin screens (most built, some missing) | In Progress |
| Phase 4 | Superadmin, analytics, cross-branch | Planned |
| Phase 5 | Advanced features (chat, library, push notifications) | Planned |
| Phase 6 | Polish, accessibility, production build | Planned |

### 11.2 Phase 3 Remaining Work (Admin)

These screens are missing and must be built:

| Screen | Route | Priority | Django Equivalent |
|---|---|---|---|
| `AdminEditStudentScreen` | `/admin/students/:id/edit` | HIGH | `/student/edit/<pk>/` |
| `AdminEditStaffScreen` | `/admin/staff/:id/edit` | HIGH | `/staff/edit/<pk>/` |
| `AdminGroupDetailScreen` | `/admin/groups/:id` | HIGH | `/group/<pk>/` |
| `AdminAddGroupScreen` | `/admin/groups/add` | HIGH | `/group/add/` |
| `AdminEditGroupScreen` | `/admin/groups/:id/edit` | HIGH | — |
| `AdminEnrollmentScreen` | `/admin/enrollment` | HIGH | `/enrollment/manage/` |
| `AdminAdminsScreen` | `/admin/admins` | MEDIUM | `/admin/manage/` |

### 11.3 Backend Endpoints That Must Be Created

These REST endpoints **do not yet exist** in the Django backend. The corresponding Flutter screens cannot function without them:

#### HIGH Priority (block Phase 3 completion)

| Endpoint | Method | Purpose | Django view to model after |
|---|---|---|---|
| `/api/v1/admin/groups/` | POST | Create group | `hod_views.add_group` |
| `/api/v1/admin/groups/{pk}/` | PATCH | Edit group | `hod_views.edit_group` |
| `/api/v1/admin/groups/{pk}/` | DELETE | Delete/archive group | `hod_views.delete_group` |
| `/api/v1/admin/admins/` | GET/POST | List/create admin accounts | `hod_views.manage_admin` / `add_admin` |
| `/api/v1/admin/admins/{pk}/` | PATCH/DELETE | Edit/delete admin | `hod_views.edit_admin` / `delete_admin` |

#### HIGH Priority (block auth features)

| Endpoint | Method | Purpose | Django equivalent |
|---|---|---|---|
| `/api/v1/auth/password-reset/` | POST | Initiate OTP reset | `forgot_password` view |
| `/api/v1/auth/password-reset/verify/` | POST | Verify 6-digit OTP | `verify_reset_code` view |
| `/api/v1/auth/password-reset/confirm/` | POST | Set new password | `reset_password` view |

#### MEDIUM Priority (block Phase 5)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/chat/threads/` | GET | List chat threads (role-filtered) |
| `/api/v1/chat/threads/{pk}/messages/` | GET/POST | Paginated chat messages |
| `/api/v1/library/books/` | GET | Available books list |
| `/api/v1/library/loans/` | GET | Own active loans |
| `/api/v1/library/loans/` | POST | Issue a book (staff) |
| `/api/v1/library/loans/{pk}/return/` | POST | Return a book |

#### LOW Priority

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/admin/invoices-manage/` | POST | Create invoice manually |
| `/api/v1/admin/invoices-manage/generate/` | POST | Bulk invoice generation |
| `/api/v1/superadmin/analytics/` | GET | Cross-branch analytics |

### 11.4 Bugs to Fix in Migration (from Django Bug List)

When building Flutter screens, these Django bugs should be corrected:

| Django Bug | Flutter Fix |
|---|---|
| Bug #1: Admin no notification page | Admin notifications screen at `/notifications` — use `GET /api/v1/notifications/` |
| Bug #2: Login page missing forgot password link | LoginScreen has "Forgot password?" `TextButton` below submit |
| Bug #3: Admin ResultFile upload IntegrityError | Do not expose file upload to admin role in Flutter until backend is fixed |
| Bug #6: RegistrationLead.branch is free-text | Flutter send `branch_id` (int) if backend fixed; otherwise accept backend behavior |
| Bug #7: Library fine shows ₹ | Flutter `StudentBooksScreen` always uses `CurrencyFormatter` (so'm) |

### 11.5 Security Checklist for Flutter

**MUST implement** before production:

- [ ] All API calls include `Authorization: Bearer` header (handled by Dio interceptor)
- [ ] 401 → auto-refresh → retry once → logout (handled by `JwtInterceptor`)
- [ ] Never store password in memory beyond login form submission
- [ ] GoRouter redirect guards prevent wrong-role route access
- [ ] Frontend only renders role-appropriate UI elements
- [ ] Dropdown data always fetched from API (never hardcoded IDs the user might manipulate)
- [ ] Confirm dialogs before all DELETE operations (see `IceConfirmDialog`)
- [ ] File upload: validate file type and size client-side before sending
- [ ] Chat: backend must verify enrollment before returning thread messages
- [ ] Branch scope: dropdowns populated from `GET /api/v1/admin/branches/` (user's accessible branches only)

### 11.6 UZS Currency Rules (Applied Throughout)

```
✅ Always: "450 000 so'm"   (space thousands separator, no decimals, so'm suffix)
❌ Never:  "$450,000"       (wrong currency)
❌ Never:  "₹450"          (Indian Rupee — Django Bug #7)
❌ Never:  "450000"        (no formatting)
```

```dart
// Apply this everywhere a monetary amount is displayed:
IceCurrencyText(invoice.amount)
// or:
CurrencyFormatter.format(invoice.amount)
```

### 11.7 Attendance Status Values (Exact String Match)

```dart
// Backend expects EXACTLY these values (case-sensitive):
const String attendancePresent = 'P';
const String attendanceLate    = 'L';
const String attendanceAbsent  = 'A';

// ❌ WRONG (will fail on backend):
// 'present', 'PRESENT', '1', 1, true
```

### 11.8 Date Format Rules

```dart
// For API requests: always ISO 8601
DateFormat('yyyy-MM-dd').format(date)   // '2026-06-11'

// For display to users:
DateFormat('dd MMM yyyy').format(date)  // '11 Jun 2026'

// For period fields (invoices):
DateFormat('yyyy-MM').format(date)      // '2026-06'
```

### 11.9 Flutter Web Specific Concerns

| Concern | Mitigation |
|---|---|
| CORS errors | Backend `CORS_ALLOWED_ORIGINS` must include Flutter Web origin |
| `flutter_secure_storage` falls back to localStorage on web | Acceptable for dev; use HTTPS + short token TTL in prod |
| File download on web | Use `dart:html` `AnchorElement` with `download` attribute, not Dio download |
| File picker on web | `FilePicker` uses `<input type="file">` bridge — works in CanvasKit |
| CanvasKit initial load | ~2MB WASM download. Add loading screen in `index.html` |
| Browser back/forward | GoRouter handles this correctly; test all deep links |
| iOS safe area insets | Flutter handles these automatically via `MediaQuery.padding` |

### 11.10 Recommended Build Order for Phase 3 Completion

1. **Create backend endpoints** for group CRUD (POST/PATCH/DELETE `/api/v1/admin/groups/`)
2. **Build** `AdminEditStudentScreen` — reuse form from `AdminAddStudentScreen`, pre-populate with `GET /api/v1/admin/students/{pk}/`
3. **Build** `AdminEditStaffScreen` — same pattern as edit student
4. **Build** `AdminGroupDetailScreen` — display `GET /api/v1/admin/groups/{pk}/` enrolled students
5. **Build** `AdminAddGroupScreen` + `AdminEditGroupScreen` — cascading dropdowns: Course → filter teachers → assign branch
6. **Build** `AdminEnrollmentScreen` — select group + student → `POST /api/v1/admin/enrollments/`
7. **Create backend endpoints** for admin account management
8. **Build** `AdminAdminsScreen` — list/add/edit admin accounts (super admin only)

---

*End of FLUTTER_APP_MIGRATION_PLAN.md*

**Document summary**:
- 11 sections covering full migration blueprint
- 60+ screens mapped (route → file → API → Django equivalent)
- 15+ Dart model classes with full `fromJson` implementations
- 3 repository classes with method signatures
- Complete Riverpod state management plan
- Design system fully translated from CSS tokens to Dart constants
- 15 backend endpoints identified as missing (must be built)
- 7 Django bugs addressed with Flutter-side fixes
- Production security checklist included
