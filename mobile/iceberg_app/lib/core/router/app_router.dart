import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../auth/auth_state.dart';
import '../../features/auth/screens/login_screen.dart';
import '../../features/auth/screens/coming_soon_screen.dart';

// Student
import '../../features/student/screens/student_shell.dart';
import '../../features/student/screens/student_home_screen.dart';
import '../../features/student/screens/student_attendance_screen.dart';
import '../../features/student/screens/student_results_screen.dart';
import '../../features/student/screens/student_leave_screen.dart';
import '../../features/student/screens/student_feedback_screen.dart';
import '../../features/student/screens/student_assignments_screen.dart';
import '../../features/student/screens/student_payments_screen.dart';
import '../../features/student/screens/student_notifications_screen.dart';
import '../../features/student/screens/student_vocabulary_screen.dart';
import '../../features/student/screens/student_vocabulary_detail_screen.dart';
import '../../features/student/screens/student_flashcard_screen.dart';
import '../../features/student/screens/student_vocabulary_quiz_screen.dart';
import '../../features/student/screens/student_result_files_screen.dart';
import '../../features/student/screens/student_books_screen.dart';
import '../../features/student/screens/student_leaderboard_screen.dart';
import '../../features/student/screens/student_progress_screen.dart';
import '../../features/student/screens/student_profile_screen.dart';
import '../../features/student/screens/student_settings_screen.dart';
import '../../features/student/screens/student_messages_screen.dart';
import '../../features/student/screens/student_assignment_detail_screen.dart';
import '../../features/student/screens/student_learn_screen.dart';

// Staff
import '../../features/staff/screens/staff_shell.dart';
import '../../features/staff/screens/staff_home_screen.dart';
import '../../features/staff/screens/staff_more_screen.dart';
import '../../features/staff/screens/staff_placeholder_screens.dart';
import '../../features/staff/screens/staff_feature_screens.dart';
import '../../features/staff/screens/staff_profile_screen.dart';
import '../../features/staff/screens/register/register_screen.dart';

// Shared
import '../../shared/screens/profile_hub_screen.dart';
import '../../shared/screens/messages_screen.dart';
import '../theme/brand.dart';

/// Where the router sends [auth]'s user when they open [path]; null means stay.
/// Kept as a plain function so the role rules can be unit-tested.
String? roleRedirect(AuthState auth, String path) {
  if (auth.status == AuthStatus.loading) return '/splash';

  if (auth.status == AuthStatus.unauthenticated) {
    return path == '/login' ? null : '/login';
  }

  final user = auth.user!;

  // Admin → coming-soon wall (admin dashboard ships on the web portal).
  // Parents too, until the parent screens are built (plan phase P5).
  if (user.isAdmin || user.isParent) {
    return path == '/coming-soon' ? null : '/coming-soon';
  }

  // Staff (teachers) → teacher portal.
  if (user.isStaff) {
    if (path.startsWith('/staff')) return null;
    return '/staff/home';
  }

  // Students → student app; bounce off auth/transitional routes.
  if (path == '/login' ||
      path == '/splash' ||
      path == '/coming-soon' ||
      path.startsWith('/staff')) {
    return '/student/home';
  }

  return null;
}

/// Routing by role:
///   - Student (user_type 3) → full /student/* experience
///   - Staff   (user_type 2) → teacher portal /staff/*
///   - Admin   (user_type 1) → /coming-soon (admin web portal handles them)
///   - Parent  (user_type 4) → /coming-soon until the parent screens ship
///
/// Each role's sub-screens are nested inside the role's StatefulShellRoute
/// branches so the bottom navigation bar persists and back-navigation works.
final appRouterProvider = Provider<GoRouter>((ref) {
  final authListenable = _AuthListenable(ref);

  return GoRouter(
    refreshListenable: authListenable,
    redirect: (context, state) =>
        roleRedirect(ref.read(authProvider), state.matchedLocation),
    routes: [
      GoRoute(path: '/splash', builder: (_, __) => const _SplashScreen()),
      GoRoute(path: '/login', builder: (_, __) => const LoginScreen()),
      GoRoute(path: '/coming-soon', builder: (_, __) => const ComingSoonScreen()),

      // ── Staff shell (5 bottom-nav branches) ──────────────────────────────
      StatefulShellRoute.indexedStack(
        builder: (context, state, navigationShell) =>
            StaffShell(navigationShell: navigationShell),
        branches: [
          // 0 · Dashboard
          StatefulShellBranch(routes: [
            GoRoute(
              path: '/staff/home',
              builder: (_, __) => const StaffHomeScreen(),
            ),
          ]),
          // 1 · Attendance + update
          StatefulShellBranch(routes: [
            GoRoute(
              path: '/staff/attendance',
              builder: (_, __) => const StaffAttendanceScreen(),
              routes: [
                GoRoute(
                  path: 'update',
                  builder: (_, __) => const StaffUpdateAttendanceScreen(),
                ),
              ],
            ),
          ]),
          // 2 · Results
          StatefulShellBranch(routes: [
            GoRoute(path: '/staff/results', builder: (_, __) => const StaffResultsScreen()),
          ]),
          // 3 · Assignments
          StatefulShellBranch(routes: [
            GoRoute(path: '/staff/assignments', builder: (_, __) => const StaffAssignmentsScreen()),
          ]),
          // 4 · Profile
          StatefulShellBranch(routes: [
            GoRoute(
              path: '/staff/profile',
              builder: (_, __) => const ProfileHubScreen(),
              routes: [
                GoRoute(
                  path: 'avatar',
                  builder: (_, __) => const StaffAvatarScreen(),
                ),
              ],
            ),
          ]),
        ],
      ),
      // Staff standalone screens (pushed full-screen; each shows its own back affordance).
      GoRoute(path: '/staff/classes',       builder: (_, __) => const StaffClassesScreen()),
      GoRoute(path: '/staff/more',          builder: (_, __) => const StaffMoreScreen()),
      GoRoute(path: '/staff/vocabulary',    builder: (_, __) => const StaffVocabularyScreen()),
      GoRoute(
        path: '/staff/vocabulary/:id',
        builder: (_, state) => StaffVocabularyDetailScreen(
            vocabId: state.pathParameters['id']!),
      ),
      GoRoute(path: '/staff/leave',         builder: (_, __) => const StaffLeaveScreen()),
      GoRoute(path: '/staff/feedback',      builder: (_, __) => const StaffFeedbackScreen()),
      GoRoute(path: '/staff/payments',      builder: (_, __) => const StaffPaymentsScreen()),
      GoRoute(path: '/staff/notifications', builder: (_, __) => const StaffNotificationsScreen()),
      GoRoute(path: '/staff/settings',      builder: (_, __) => const StudentSettingsScreen()),
      GoRoute(path: '/staff/messages',      builder: (_, __) => const MessagesScreen()),
      GoRoute(
        path: '/staff/register/:id',
        builder: (_, state) => StaffRegisterScreen(
          classId: int.parse(state.pathParameters['id']!),
          day: DateTime.tryParse(state.uri.queryParameters['date'] ?? '') ??
              DateTime.now(),
        ),
      ),

      // ── Student shell (5 bottom-nav branches) ────────────────────────────
      StatefulShellRoute.indexedStack(
        builder: (context, state, navigationShell) =>
            StudentShell(navigationShell: navigationShell),
        branches: [
          // 0 · Dashboard + its drill-downs
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/student/home',
                builder: (_, __) => const StudentHomeScreen(),
              ),
              GoRoute(
                path: '/student/notifications',
                builder: (_, __) => const StudentNotificationsScreen(),
              ),
              GoRoute(
                path: '/student/messages',
                builder: (_, __) => const StudentMessagesScreen(),
                routes: [
                  GoRoute(
                    path: ':groupId',
                    builder: (_, state) => StudentChatScreen(
                      groupId:
                          int.tryParse(state.pathParameters['groupId']!) ?? 0,
                      groupName: state.uri.queryParameters['name'] ?? 'Chat',
                    ),
                  ),
                ],
              ),
              GoRoute(
                path: '/student/assignments',
                builder: (_, __) => const StudentAssignmentsScreen(),
                routes: [
                  GoRoute(
                    path: ':id',
                    builder: (_, state) => StudentAssignmentDetailScreen(
                      assignmentId:
                          int.tryParse(state.pathParameters['id']!) ?? 0,
                    ),
                  ),
                ],
              ),
            ],
          ),
          // 1 · Progress + Attendance Hub
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/student/progress',
                builder: (_, __) => const StudentProgressScreen(),
              ),
              GoRoute(
                path: '/student/attendance',
                builder: (_, __) => const StudentAttendanceScreen(),
              ),
            ],
          ),
          // 2 · Vocabulary
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/student/vocabulary',
                builder: (_, __) => const StudentVocabularyScreen(),
                routes: [
                  GoRoute(
                    path: ':id',
                    builder: (_, state) => StudentVocabularyDetailScreen(
                      vocabId: state.pathParameters['id']!,
                    ),
                    routes: [
                      GoRoute(
                        path: 'flashcards',
                        builder: (_, state) => StudentFlashcardScreen(
                          vocabId: state.pathParameters['id']!,
                        ),
                      ),
                      GoRoute(
                        path: 'learn',
                        builder: (_, state) => StudentLearnScreen(
                          vocabId: state.pathParameters['id']!,
                        ),
                      ),
                      GoRoute(
                        path: 'quiz',
                        builder: (_, state) => StudentVocabularyQuizScreen(
                          dayId:
                              int.tryParse(state.pathParameters['id'] ?? '') ??
                              0,
                          dayTitle:
                              state.uri.queryParameters['title'] ??
                              'Vocabulary Quiz',
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ],
          ),
          // 3 · Leaderboard
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/student/leaderboard',
                builder: (_, __) => const StudentLeaderboardScreen(),
              ),
            ],
          ),
          // 4 · Profile + student services
          StatefulShellBranch(
            routes: [
              GoRoute(
                path: '/student/profile',
                builder: (_, __) => const StudentProfileScreen(),
                routes: [
                  GoRoute(
                    path: 'edit',
                    builder: (_, __) => const StudentEditProfileScreen(),
                  ),
                  GoRoute(
                    path: 'avatar',
                    builder: (_, __) => const StudentAvatarScreen(),
                  ),
                ],
              ),
              GoRoute(
                path: '/student/settings',
                builder: (_, __) => const StudentSettingsScreen(),
              ),
              GoRoute(
                path: '/student/results',
                builder: (_, __) => const StudentResultsScreen(),
              ),
              GoRoute(
                path: '/student/result-files',
                builder: (_, __) => const StudentResultFilesScreen(),
              ),
              GoRoute(
                path: '/student/library',
                builder: (_, __) => const StudentBooksScreen(),
              ),
              GoRoute(
                path: '/student/books',
                builder: (_, __) => const StudentBooksScreen(),
              ),
              GoRoute(
                path: '/student/payments',
                builder: (_, __) => const StudentPaymentsScreen(),
              ),
              GoRoute(
                path: '/student/leave',
                builder: (_, __) => const StudentLeaveScreen(),
              ),
              GoRoute(
                path: '/student/feedback',
                builder: (_, __) => const StudentFeedbackScreen(),
              ),
            ],
          ),
        ],
      ),
    ],
  );
});

class _AuthListenable extends ChangeNotifier {
  _AuthListenable(Ref ref) {
    ref.listen(authProvider, (_, __) => notifyListeners());
  }
}

// ── Splash screen ──────────────────────────────────────────────────────────────

const _kNavy = Color(0xFF050F1A);
const _kCyan = Color(0xFF00CFFF);

class _SplashScreen extends StatefulWidget {
  const _SplashScreen();

  @override
  State<_SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<_SplashScreen>
    with TickerProviderStateMixin {
  // ── Controllers ────────────────────────────────────────────────────────────
  late final AnimationController _mainCtrl;   // 1800 ms one-shot sequence
  late final AnimationController _floatCtrl;  // 3200 ms continuous levitation
  late final AnimationController _glowCtrl;   // 2200 ms continuous glow breathe
  late final AnimationController _sheenCtrl;  // 560 ms one-shot sheen sweep

  // ── Sequence animations (driven by _mainCtrl) ───────────────────────────
  late final Animation<double> _logoFade;    // 0–380 ms
  late final Animation<double> _logoScale;   // 0–700 ms elasticOut
  late final Animation<double> _glowIn;      // 380–780 ms glow enters
  late final Animation<double> _ringScale;   // 640–1120 ms ripple expands
  late final Animation<double> _ringFade;    // 640–1120 ms ripple fades
  late final List<Animation<double>> _iconScales;
  late final List<Animation<double>> _iconFades;
  late final Animation<double> _tagFade;     // 1380–1720 ms
  late final Animation<Offset> _tagSlide;    // 1380–1720 ms slides up

  // ── Continuous animations ────────────────────────────────────────────────
  late final Animation<double> _floatY;      // –6 ↔ +6 px
  late final Animation<double> _glowPulse;   // 0.72 ↔ 1.0

  // Sheen sweep: 0 = left edge, 1 = right edge
  late final Animation<double> _sheenX;

  static const _icons = ['📚', '📅', '📝', '💳', '🏆', '📖'];
  static const _totalMs = 1800;

  double _t(int ms) => ms / _totalMs;

  @override
  void initState() {
    super.initState();

    _mainCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: _totalMs),
    )..forward();

    _floatCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 3200),
    );

    _glowCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2200),
    );

    _sheenCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 560),
    );

    // ── Logo fade & elastic spring pop ─────────────────────────────────────
    _logoFade = CurvedAnimation(
      parent: _mainCtrl,
      curve: Interval(_t(0), _t(380), curve: Curves.easeOut),
    );
    _logoScale = Tween<double>(begin: 0.52, end: 1.0).animate(
      CurvedAnimation(
        parent: _mainCtrl,
        curve: Interval(_t(0), _t(700), curve: Curves.elasticOut),
      ),
    );

    // ── Ambient glow enters behind logo ───────────────────────────────────
    _glowIn = CurvedAnimation(
      parent: _mainCtrl,
      curve: Interval(_t(380), _t(780), curve: Curves.easeOut),
    );

    // ── Impact ripple ring ────────────────────────────────────────────────
    _ringScale = Tween<double>(begin: 1.0, end: 2.4).animate(
      CurvedAnimation(
        parent: _mainCtrl,
        curve: Interval(_t(640), _t(1120), curve: Curves.easeOut),
      ),
    );
    _ringFade = Tween<double>(begin: 0.55, end: 0.0).animate(
      CurvedAnimation(
        parent: _mainCtrl,
        curve: Interval(_t(640), _t(1120), curve: Curves.easeIn),
      ),
    );

    // ── Feature icons stagger 82 ms apart ────────────────────────────────
    _iconScales = List.generate(_icons.length, (i) {
      final start = 900 + i * 82;
      final end = (start + 220).clamp(0, _totalMs);
      return Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(
          parent: _mainCtrl,
          curve: Interval(_t(start), _t(end), curve: Curves.easeOutBack),
        ),
      );
    });
    _iconFades = List.generate(_icons.length, (i) {
      final start = 900 + i * 82;
      final end = (start + 160).clamp(0, _totalMs);
      return CurvedAnimation(
        parent: _mainCtrl,
        curve: Interval(_t(start), _t(end), curve: Curves.easeOut),
      );
    });

    // ── Tagline slides up and fades in ────────────────────────────────────
    _tagFade = CurvedAnimation(
      parent: _mainCtrl,
      curve: Interval(_t(1380), _t(1720), curve: Curves.easeOut),
    );
    _tagSlide = Tween<Offset>(
      begin: const Offset(0, 0.5),
      end: Offset.zero,
    ).animate(
      CurvedAnimation(
        parent: _mainCtrl,
        curve: Interval(_t(1380), _t(1720), curve: Curves.easeOutCubic),
      ),
    );

    // ── Float: gentle –6 ↔ +6 px vertical ───────────────────────────────
    _floatY = Tween<double>(begin: -6.0, end: 6.0).animate(
      CurvedAnimation(parent: _floatCtrl, curve: Curves.easeInOut),
    );

    // ── Glow pulse: opacity 0.72 ↔ 1.0 ──────────────────────────────────
    _glowPulse = Tween<double>(begin: 0.72, end: 1.0).animate(
      CurvedAnimation(parent: _glowCtrl, curve: Curves.easeInOut),
    );

    // ── Sheen sweep ──────────────────────────────────────────────────────
    _sheenX = Tween<double>(begin: -1.0, end: 2.0).animate(
      CurvedAnimation(parent: _sheenCtrl, curve: Curves.easeInOut),
    );

    // Start continuous effects when logo settles; trigger sheen at 860 ms.
    _mainCtrl.addListener(() {
      final v = _mainCtrl.value;
      if (v >= _t(700) && !_floatCtrl.isAnimating) {
        _floatCtrl.repeat(reverse: true);
      }
      if (v >= _t(700) && !_glowCtrl.isAnimating) {
        _glowCtrl.repeat(reverse: true);
      }
      if (v >= _t(860) && !_sheenCtrl.isAnimating && _sheenCtrl.value == 0) {
        _sheenCtrl.forward();
      }
    });
  }

  @override
  void dispose() {
    _mainCtrl.dispose();
    _floatCtrl.dispose();
    _glowCtrl.dispose();
    _sheenCtrl.dispose();
    super.dispose();
  }

  // ── Build helpers ─────────────────────────────────────────────────────────

  Widget _buildGlowBlob() {
    return AnimatedBuilder(
      animation: Listenable.merge([_glowIn, _glowPulse]),
      builder: (_, __) => Opacity(
        opacity: _glowIn.value * _glowPulse.value,
        child: Container(
          width: 220,
          height: 220,
          decoration: const BoxDecoration(
            shape: BoxShape.circle,
            gradient: RadialGradient(
              colors: [Color(0x5500CFFF), Color(0x1500CFFF), Colors.transparent],
              stops: [0.0, 0.5, 1.0],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildRippleRing() {
    return AnimatedBuilder(
      animation: Listenable.merge([_ringScale, _ringFade]),
      builder: (_, __) => Opacity(
        opacity: _ringFade.value,
        child: Transform.scale(
          scale: _ringScale.value,
          child: Container(
            width: 200,
            height: 200,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(30),
              border: Border.all(color: _kCyan, width: 1.5),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLogoWithSheen() {
    return AnimatedBuilder(
      animation: Listenable.merge([_logoFade, _logoScale, _floatY, _sheenX]),
      builder: (_, __) => Opacity(
        opacity: _logoFade.value,
        child: Transform.translate(
          offset: Offset(0, _floatY.value),
          child: Transform.scale(
            scale: _logoScale.value,
            child: ClipRRect(
              borderRadius: BorderRadius.circular(30),
              child: SizedBox(
                width: 200,
                height: 200,
                child: Stack(
                  children: [
                    const IceBrandLogo(size: 200, radius: 30),
                    // Diagonal sheen sweep
                    Positioned.fill(
                      child: Transform.translate(
                        offset: Offset(_sheenX.value * 200, 0),
                        child: Transform.rotate(
                          angle: 0.45,
                          child: Container(
                            width: 60,
                            decoration: const BoxDecoration(
                              gradient: LinearGradient(
                                colors: [
                                  Colors.transparent,
                                  Color(0x26FFFFFF),
                                  Colors.transparent,
                                ],
                              ),
                            ),
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildBorderRing() {
    return AnimatedBuilder(
      animation: Listenable.merge([_glowIn, _glowPulse]),
      builder: (_, __) => Opacity(
        opacity: _glowIn.value * (_glowPulse.value * 0.6 + 0.4),
        child: Container(
          width: 208,
          height: 208,
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(34),
            border: Border.all(
              color: _kCyan.withValues(alpha: 0.45),
              width: 1.0,
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _kNavy,
      body: Container(
        decoration: const BoxDecoration(
          gradient: RadialGradient(
            center: Alignment(0, -0.15),
            radius: 1.2,
            colors: [Color(0xFF0E2840), Color(0xFF071629), _kNavy],
            stops: [0.0, 0.5, 1.0],
          ),
        ),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // ── Logo block: glow → ripple → logo → border ────────────────
              SizedBox(
                width: 220,
                height: 220,
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    _buildGlowBlob(),
                    _buildRippleRing(),
                    _buildBorderRing(),
                    _buildLogoWithSheen(),
                  ],
                ),
              ),
              const SizedBox(height: 48),
              // ── Feature icons staggered ───────────────────────────────────
              SizedBox(
                width: 300,
                child: AnimatedBuilder(
                  animation: _mainCtrl,
                  builder: (_, __) => Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: List.generate(
                      _icons.length,
                      (i) => Opacity(
                        opacity: _iconFades[i].value,
                        child: Transform.scale(
                          scale: _iconScales[i].value,
                          child: Text(
                            _icons[i],
                            style: const TextStyle(fontSize: 26),
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 28),
              // ── Tagline slides up ─────────────────────────────────────────
              AnimatedBuilder(
                animation: Listenable.merge([_tagFade, _tagSlide]),
                builder: (_, __) => FadeTransition(
                  opacity: _tagFade,
                  child: SlideTransition(
                    position: _tagSlide,
                    child: const Text(
                      'LEARN · TRACK · GROW',
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        letterSpacing: 3.5,
                        color: Color(0xFF7DCFE8),
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
