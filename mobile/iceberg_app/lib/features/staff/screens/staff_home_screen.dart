import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/auth/auth_state.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/brand.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../core/utils/formatters.dart';
import '../../../shared/widgets/ice_kit.dart';
import 'register/register_screen.dart';

part 'staff_home/home_widgets.dart';

class StaffHomeScreen extends ConsumerStatefulWidget {
  const StaffHomeScreen({super.key});

  @override
  ConsumerState<StaffHomeScreen> createState() => _StaffHomeScreenState();
}

class _StaffHomeScreenState extends ConsumerState<StaffHomeScreen>
    with WidgetsBindingObserver {
  Timer? _timer;
  // Cache last good data so background refreshes never flash the skeleton.
  Map<String, dynamic>? _cachedStats;
  List<dynamic>? _cachedGroups;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _timer = Timer.periodic(const Duration(seconds: 45), (_) {
      if (mounted) {
        ref.invalidate(staffStatsProvider);
        ref.invalidate(staffGroupsProvider);
      }
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed && mounted) {
      ref.invalidate(staffStatsProvider);
      ref.invalidate(staffGroupsProvider);
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
    final stats = ref.watch(staffStatsProvider);
    final groups = ref.watch(staffGroupsProvider);

    // Keep a local copy of the last successful fetch so we can show stale
    // data during background refreshes instead of flashing the skeleton.
    ref.listen(staffStatsProvider, (_, next) {
      if (next.valueOrNull != null) _cachedStats = next.valueOrNull;
    });
    ref.listen(staffGroupsProvider, (_, next) {
      if (next.valueOrNull != null) _cachedGroups = next.valueOrNull;
    });

    // Show skeleton only on the very first load (no cached data yet).
    final initialLoad = _cachedStats == null && _cachedGroups == null;
    if (initialLoad && (stats.isLoading || groups.isLoading)) {
      return const PageSkeleton();
    }
    if (stats.hasError && _cachedStats == null) {
      return ErrorState(
        error: stats.error,
        onRetry: () => ref.invalidate(staffStatsProvider),
      );
    }

    return _Dashboard(
      stats: _cachedStats ?? stats.valueOrNull ?? {},
      groups: _cachedGroups ?? groups.valueOrNull ?? [],
      groupsAsync: groups,
      ref: ref,
    );
  }
}

class _Dashboard extends ConsumerWidget {
  final Map<String, dynamic> stats;
  final List<dynamic> groups;
  final AsyncValue<List<dynamic>> groupsAsync;
  final WidgetRef ref;

  const _Dashboard({
    required this.stats,
    required this.groups,
    required this.groupsAsync,
    required this.ref,
  });

  @override
  Widget build(BuildContext context, WidgetRef innerRef) {
    final t = context.ice;
    final s = innerRef.watch(stringsProvider);
    final user = innerRef.watch(authProvider).user;

    final hour = DateTime.now().hour;
    final greeting = hour < 12
        ? s('Good Morning')
        : hour < 17
            ? s('Good Afternoon')
            : s('Good Evening');

    final firstName = user?.firstName.isNotEmpty == true
        ? user!.firstName
        : s('Teacher');
    final initials = (() {
      final full =
          '${user?.firstName ?? ''} ${user?.lastName ?? ''}'.trim();
      if (full.isEmpty) return 'T';
      return full
          .split(' ')
          .where((p) => p.isNotEmpty)
          .take(2)
          .map((p) => p[0])
          .join()
          .toUpperCase();
    })();

    final totalStudents = (stats['total_students'] as num?)?.toInt() ?? 0;
    final sessionsToday = (stats['sessions_today'] as num?)?.toInt() ?? 0;
    final pendingResults = (stats['pending_results'] as num?)?.toInt() ?? 0;
    final pendingLeaves = (stats['pending_leaves'] as num?)?.toInt() ?? 0;
    final stories = innerRef.watch(storiesProvider).valueOrNull ?? [];

    return IceRefresh(
      onRefresh: () async {
        await Future.wait([
          innerRef.refresh(staffStatsProvider.future),
          innerRef.refresh(staffGroupsProvider.future),
          innerRef.refresh(storiesProvider.future),
          if (context.brand.isSchool)
            innerRef.refresh(myRegistersProvider.future),
        ]);
      },
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        cacheExtent: 600,
        padding: const EdgeInsets.fromLTRB(20, 8, 20, 28),
        children: [
          // ── Hero card ────────────────────────────────────────────────
          IceCard(
            hero: true,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    GestureDetector(
                      onTap: () => context.go('/staff/profile'),
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
                          radius: 24,
                          photoUrl: user?.profilePicUrl,
                          emoji: user?.avatar.isNotEmpty == true
                              ? user!.avatar
                              : null,
                          fallbackText: initials,
                        ),
                      ),
                    ),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          MicroLabel(
                            s('SUPERVISOR'),
                            color: t.onHero.accent,
                          ),
                          const SizedBox(height: 4),
                          Text(
                            '$greeting, $firstName',
                            style: const TextStyle(
                              fontSize: 18,
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
                        s('Staff'),
                        style: TextStyle(
                          fontSize: 11.5,
                          fontWeight: FontWeight.w700,
                          color: Colors.white.withValues(alpha: 0.85),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 14, vertical: 12),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.06),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                        color: Colors.white.withValues(alpha: 0.08)),
                  ),
                  child: Row(
                    children: [
                      Expanded(
                        child: _HeroStat(
                          value: '$totalStudents',
                          label: s('Students'),
                        ),
                      ),
                      Container(
                          width: 1,
                          height: 32,
                          color: Colors.white.withValues(alpha: 0.12)),
                      Expanded(
                        child: _HeroStat(
                          value: '$sessionsToday',
                          label: s('Sessions Today'),
                        ),
                      ),
                      Container(
                          width: 1,
                          height: 32,
                          color: Colors.white.withValues(alpha: 0.12)),
                      Expanded(
                        child: _HeroStat(
                          value: '$pendingLeaves',
                          label: s('Leave Req.'),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ).animate().fadeIn(duration: 350.ms).moveY(begin: 14, end: 0),
          const SizedBox(height: 14),

          // ── Daily register reminder (School homeroom teachers) ───────
          const RegisterReminder(),

          // ── Today's Schedule (visible on open) ────────────────────────
          SectionHeader(
            s("Today's Schedule"),
            actionLabel: s('View All'),
            onAction: () => context.push('/staff/classes'),
          ),
          groupsAsync.when(
            loading: () => const SkeletonBox(height: 80),
            error: (e, _) => ErrorState(
              error: e,
              onRetry: () => innerRef.invalidate(staffGroupsProvider),
            ),
            data: (list) {
              if (list.isEmpty) {
                return IceCard(
                  child: EmptyState(
                    icon: Icons.calendar_today_rounded,
                    title: s('No classes scheduled'),
                    message: s('Your groups will appear here once assigned.'),
                  ),
                );
              }
              final times = [
                '08:00 AM',
                '10:00 AM',
                '12:00 PM',
                '02:00 PM',
                '04:00 PM',
              ];
              return Column(
                children: [
                  for (var i = 0; i < list.length; i++) ...[
                    _ScheduleCard(
                      group: list[i] as Map<String, dynamic>,
                      time: times[i % times.length],
                      isNow: i == 0,
                      onAttendance: () => context.push('/staff/attendance'),
                    ).animate().fadeIn(
                          delay: Duration(milliseconds: 60 + i * 50),
                          duration: 300.ms,
                        ),
                    if (i < list.length - 1) const SizedBox(height: 10),
                  ],
                ],
              );
            },
          ),
          const SizedBox(height: 22),

          // ── Stat row ──────────────────────────────────────────────────
          Row(
            children: [
              Expanded(
                child: StatCard(
                  icon: Icons.pending_actions_rounded,
                  iconColor: t.amber,
                  value: '$pendingResults',
                  label: s('Pending Results'),
                  onTap: () => context.push('/staff/results'),
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: StatCard(
                  icon: Icons.beach_access_rounded,
                  iconColor: t.sky,
                  value: '$pendingLeaves',
                  label: s('Leave Requests'),
                  onTap: () => context.push('/staff/leave'),
                ),
              ),
            ],
          ).animate().fadeIn(delay: 100.ms, duration: 350.ms),
          const SizedBox(height: 14),

          // ── Quick Actions ─────────────────────────────────────────────
          SectionHeader(s('Quick Actions')),
          IceCard(
            padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 4),
            child: SingleChildScrollView(
              scrollDirection: Axis.horizontal,
              padding: const EdgeInsets.symmetric(horizontal: 8),
              child: Row(
                children: [
                  _QuickAction(
                    icon: Icons.how_to_reg_rounded,
                    label: s('Attendance'),
                    color: t.accentInk,
                    onTap: () => context.push('/staff/attendance'),
                  ),
                  _QuickAction(
                    icon: Icons.bar_chart_rounded,
                    label: s('Results'),
                    color: t.amber,
                    onTap: () => context.push('/staff/results'),
                  ),
                  _QuickAction(
                    icon: Icons.assignment_rounded,
                    label: s('Assignment'),
                    color: t.sky,
                    onTap: () => context.push('/staff/assignments'),
                  ),
                  _QuickAction(
                    icon: Icons.beach_access_rounded,
                    label: s('Leave'),
                    color: t.mint,
                    onTap: () => context.push('/staff/leave'),
                  ),
                  _QuickAction(
                    icon: Icons.chat_rounded,
                    label: s('Messages'),
                    color: t.accent,
                    onTap: () => context.push('/staff/messages'),
                  ),
                  _QuickAction(
                    icon: Icons.class_outlined,
                    label: s(context.brand.teacherGroupsKey),
                    color: t.coral,
                    onTap: () => context.push('/staff/classes'),
                  ),
                ],
              ),
            ),
          ).animate().fadeIn(delay: 140.ms, duration: 350.ms),
          const SizedBox(height: 22),

          // ── Campus Pulse ──────────────────────────────────────────────
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
        ],
      ),
    );
  }
}
