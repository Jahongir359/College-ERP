import 'dart:async';
import 'dart:ui' as ui;

import 'package:flutter/foundation.dart' show listEquals;
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/auth/auth_state.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../core/utils/formatters.dart';
import '../../../shared/widgets/ice_kit.dart';

part 'student_home/home_widgets.dart';

/// Student Dashboard — rank/tier hero, streak, attendance ring, quick stats,
/// performance trend, Campus Pulse stories and assignment preview.
///
/// Refreshes automatically:
///   - every 45 s while the screen is visible (background polling)
///   - whenever the app returns to the foreground from the background
class StudentHomeScreen extends ConsumerStatefulWidget {
  const StudentHomeScreen({super.key});

  @override
  ConsumerState<StudentHomeScreen> createState() => _StudentHomeScreenState();
}

class _StudentHomeScreenState extends ConsumerState<StudentHomeScreen>
    with WidgetsBindingObserver {
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _timer = Timer.periodic(const Duration(seconds: 45), (_) {
      if (mounted) ref.read(studentDashProvider.notifier).backgroundRefresh();
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && mounted) {
      ref.read(studentDashProvider.notifier).backgroundRefresh();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final dash = ref.watch(studentDashProvider);

    return dash.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.read(studentDashProvider.notifier).reload(),
      ),
      data: (d) => _Dashboard(d: d),
    );
  }
}

class _Dashboard extends ConsumerWidget {
  final Map<String, dynamic> d;
  const _Dashboard({required this.d});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider.select((a) => a.user));

    final hour = DateTime.now().hour;
    final greeting = hour < 12
        ? s('Good Morning')
        : hour < 17
            ? s('Good Afternoon')
            : s('Good Evening');

    final rank = (d['rank'] as num?)?.toInt();
    final tier = (d['tier'] as String?) ?? '';
    final streak = (d['streak_days'] as num?)?.toInt() ?? 0;
    final attendance = (d['attendance_percentage'] as num?)?.toDouble();
    final pending = (d['pending_assignments'] as num?)?.toInt() ?? 0;
    final unread = (d['unread_notifications'] as num?)?.toInt() ?? 0;
    final newWords = (d['new_vocab_words'] as num?)?.toInt() ?? 0;
    final trend = (d['performance_trend'] as List?) ?? [];
    final stories = (d['stories'] as List?) ?? [];
    final assignments = (d['assignments_preview'] as List?) ?? [];
    final classes = (d['classes'] as List?) ?? [];

    return IceRefresh(
      onRefresh: () => ref.read(studentDashProvider.notifier).reload(),
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        cacheExtent: 600,
        padding: const EdgeInsets.fromLTRB(20, 8, 20, 28),
        children: [
          // ── Rank / tier hero ───────────────────────────────────────────
          IceCard(
            hero: true,
            onTap: () => context.go('/student/leaderboard'),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // ── Avatar + greeting row (mirrors teacher header layout) ─
                Row(
                  children: [
                    GestureDetector(
                      onTap: () => context.go('/student/profile'),
                      child: Container(
                        padding: const EdgeInsets.all(3),
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          border: Border.all(
                            color: Colors.white.withValues(alpha: 0.55),
                            width: 2,
                          ),
                        ),
                        child: IceUserAvatar(
                          radius: 22,
                          photoUrl: user?.profilePicUrl,
                          emoji: user?.avatar.isNotEmpty == true
                              ? user!.avatar
                              : null,
                          fallbackText: user?.firstName.isNotEmpty == true
                              ? user!.firstName[0].toUpperCase()
                              : 'S',
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Icon(Icons.star_rounded, size: 14, color: t.onHero.accent),
                              const SizedBox(width: 4),
                              MicroLabel(
                                tier.isEmpty ? s('My standing') : tier,
                                color: t.onHero.accent,
                              ),
                            ],
                          ),
                          const SizedBox(height: 2),
                          Text(
                            '$greeting, ${user?.firstName.isNotEmpty == true ? user!.firstName : s('Student')}',
                            style: const TextStyle(
                              fontSize: 17,
                              fontWeight: FontWeight.w800,
                              color: Colors.white,
                            ),
                          ),
                        ],
                      ),
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 10, vertical: 5),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.08),
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                          color: Colors.white.withValues(alpha: 0.12),
                        ),
                      ),
                      child: Text(
                        rank != null ? '#$rank' : '—',
                        style: TextStyle(
                          fontSize: 11.5,
                          fontWeight: FontWeight.w700,
                          color: Colors.white.withValues(alpha: 0.85),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 14),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 14,
                    vertical: 11,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.06),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.08),
                    ),
                  ),
                  child: Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(7),
                        decoration: BoxDecoration(
                          color: t.onHero.accent.withValues(alpha: 0.15),
                          shape: BoxShape.circle,
                        ),
                        child: Icon(
                          Icons.local_fire_department_rounded,
                          size: 16,
                          color: t.onHero.accent,
                        ),
                      ),
                      const SizedBox(width: 10),
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            s('Current Momentum'),
                            style: TextStyle(
                              fontSize: 11,
                              fontWeight: FontWeight.w500,
                              color: Colors.white.withValues(alpha: 0.65),
                            ),
                          ),
                          Text(
                            streak > 0
                                ? '$streak-${s('Day Streak')}'
                                : s('Start your streak today'),
                            style: const TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.w800,
                              color: Colors.white,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ).animate().fadeIn(duration: 350.ms).moveY(begin: 14, end: 0),
          const SizedBox(height: 20),

          // ── Upcoming lessons ───────────────────────────────────────────
          if (classes.isNotEmpty) ...[
            SectionHeader(s('Upcoming Lessons')),
            for (var i = 0; i < classes.length && i < 4; i++) ...[
              _LessonCard(
                group: classes[i] as Map<String, dynamic>,
                highlight: i == 0,
              ).animate().fadeIn(
                    delay: Duration(milliseconds: 60 + i * 50),
                    duration: 300.ms,
                  ),
              if (i < classes.length - 1 && i < 3)
                const SizedBox(height: 10),
            ],
            const SizedBox(height: 22),
          ],

          // ── Attendance ring ────────────────────────────────────────────
          IceCard(
            onTap: () => context.go('/student/attendance'),
            child: Column(
              children: [
                Align(
                  alignment: Alignment.centerLeft,
                  child: MicroLabel(s('Attendance')),
                ),
                const SizedBox(height: 16),
                RepaintBoundary(
                 child: ProgressRing(
                  value: (attendance ?? 0) / 100,
                  size: 150,
                  strokeWidth: 12,
                  center: Text(
                    attendance != null
                        ? '${attendance.toStringAsFixed(attendance % 1 == 0 ? 0 : 1)}%'
                        : '—',
                    style: TextStyle(
                      fontSize: 30,
                      fontWeight: FontWeight.w800,
                      color: t.textHi,
                    ),
                  ),
                 )),
                const SizedBox(height: 14),
                Text(
                  s('Present'),
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w700,
                    color: t.accentInk,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  s('Target: 90%'),
                  style: TextStyle(
                    fontSize: 12.5,
                    fontWeight: FontWeight.w500,
                    color: t.textMid,
                  ),
                ),
              ],
            ),
          ).animate().fadeIn(delay: 60.ms, duration: 350.ms),
          const SizedBox(height: 14),

          // ── Quick stats ────────────────────────────────────────────────
          Row(
            children: [
              Expanded(
                child: StatCard(
                  icon: Icons.assignment_late_outlined,
                  iconColor: t.coral,
                  value: '$pending',
                  label: s('Pending Tasks'),
                  onTap: () => context.go('/student/assignments'),
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: StatCard(
                  icon: Icons.mark_email_unread_outlined,
                  iconColor: t.sky,
                  value: '$unread',
                  label: s('Unread Notifs'),
                  onTap: () => context.go('/student/notifications'),
                ),
              ),
            ],
          ).animate().fadeIn(delay: 100.ms, duration: 350.ms),
          const SizedBox(height: 14),

          IceCard(
            onTap: () => context.go('/student/vocabulary'),
            padding: const EdgeInsets.all(16),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(9),
                  decoration: BoxDecoration(
                    color: t.accentSoft,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(
                    Icons.translate_rounded,
                    size: 19,
                    color: t.accent,
                  ),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        '$newWords ${s('New')}',
                        style: TextStyle(
                          fontSize: 20,
                          fontWeight: FontWeight.w800,
                          color: t.textHi,
                        ),
                      ),
                      Text(
                        s('Vocab Words Ready'),
                        style: TextStyle(
                          fontSize: 12.5,
                          fontWeight: FontWeight.w600,
                          color: t.textMid,
                        ),
                      ),
                    ],
                  ),
                ),
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: t.accent,
                    shape: BoxShape.circle,
                  ),
                  child: Icon(
                    Icons.arrow_forward_rounded,
                    size: 20,
                    color: t.onAccent,
                  ),
                ),
              ],
            ),
          ).animate().fadeIn(delay: 140.ms, duration: 350.ms),
          const SizedBox(height: 14),

          // ── Performance trend ──────────────────────────────────────────
          IceCard(
            onTap: () => context.go('/student/progress'),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        s('Performance Trend'),
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.w800,
                          color: t.textHi,
                        ),
                      ),
                    ),
                    StatusBadge(s('Attendance'), tone: BadgeTone.neutral),
                  ],
                ),
                const SizedBox(height: 2),
                Text(
                  s('8-Week History'),
                  style: TextStyle(
                    fontSize: 12.5,
                    fontWeight: FontWeight.w500,
                    color: t.textMid,
                  ),
                ),
                const SizedBox(height: 18),
                RepaintBoundary(
                  child: ColoredBox(
                    color: t.card,
                    child: SizedBox(height: 150, child: _TrendChart(trend: trend)),
                  ),
                ),
              ],
            ),
          ).animate().fadeIn(delay: 180.ms, duration: 350.ms),
          const SizedBox(height: 22),

          // ── Campus Pulse ───────────────────────────────────────────────
          if (stories.isNotEmpty) ...[
            SectionHeader(s('Campus Pulse')),
            SizedBox(
              height: 150,
              child: ListView.separated(
                scrollDirection: Axis.horizontal,
                clipBehavior: Clip.none,
                cacheExtent: 600,
                itemCount: stories.length,
                separatorBuilder: (_, __) => const SizedBox(width: 12),
                itemBuilder: (_, i) =>
                    _PulseCard(story: stories[i] as Map<String, dynamic>),
              ),
            ),
            const SizedBox(height: 22),
          ],

          // ── Assignments preview ────────────────────────────────────────
          SectionHeader(
            s('Assignments'),
            actionLabel: s('View All'),
            onAction: () => context.go('/student/assignments'),
          ),
          if (assignments.isEmpty)
            IceCard(
              child: EmptyState(
                icon: Icons.task_alt_rounded,
                title: s('All caught up!'),
                message: s('No pending assignments right now.'),
              ),
            )
          else
            ...assignments.map(
              (a) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _AssignmentPreview(a: a as Map<String, dynamic>),
              ),
            ),
        ],
      ),
    );
  }
}
