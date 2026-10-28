import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/auth/auth_state.dart';
import '../../../core/i18n/strings.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';
import '../../../core/theme/brand.dart';

part 'student_profile/edit_profile_screen.dart';
part 'student_profile/avatar_screen.dart';

String _uzs(num v) =>
    '${NumberFormat('#,###').format(v).replaceAll(',', ' ')} soʻm';

// ─────────────────────────────────────────────────────────────────────────────
// Profile tab
// ─────────────────────────────────────────────────────────────────────────────
class StudentProfileScreen extends ConsumerWidget {
  const StudentProfileScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider).user;
    final dash = ref.watch(studentDashProvider);
    final notifications = ref.watch(notificationsProvider);
    final settings = ref.watch(appSettingsProvider);

    final tier = dash.maybeWhen(
      data: (d) => (d['tier'] as String?) ?? '',
      orElse: () => '',
    );
    final balance = dash.maybeWhen(
      data: (d) => (d['balance_due'] as num?) ?? 0,
      orElse: () => 0,
    );
    final dueDate = dash.maybeWhen(
      data: (d) => DateTime.tryParse(d['balance_due_date'] ?? ''),
      orElse: () => null,
    );

    return IcePage(
      title: s('Profile'),
      onRefresh: () async {
        ref.invalidate(studentDashProvider);
        ref.invalidate(notificationsProvider);
      },
      children: [
        // ── Avatar + identity ────────────────────────────────────────────
        Center(
          child: GestureDetector(
            onTap: () => context.push('/student/profile/avatar'),
            child: Container(
              padding: const EdgeInsets.all(4),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: t.accent, width: 2),
              ),
              child: IceUserAvatar(
                radius: 44,
                photoUrl: user?.profilePicUrl,
                emoji: user?.avatar.isNotEmpty == true ? user!.avatar : null,
                fallbackText: user?.firstName.isNotEmpty == true
                    ? user!.firstName[0].toUpperCase()
                    : '?',
                bgColor: t.inset,
              ),
            ),
          ),
        ),
        const SizedBox(height: 14),
        Center(
          child: Text(
            user?.fullName ?? '',
            style: TextStyle(
              fontSize: 23,
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
        ),
        const SizedBox(height: 6),
        Center(
          child: Wrap(
            spacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Text(
                'ID ${user?.loginId ?? ''}',
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: t.textMid,
                ),
              ),
              if (tier.isNotEmpty)
                StatusBadge('★ $tier', tone: BadgeTone.accent),
            ],
          ),
        ),
        const SizedBox(height: 10),
        Center(
          child: TextButton.icon(
            onPressed: () => context.go('/student/profile/edit'),
            icon: Icon(Icons.edit_outlined, size: 16, color: t.accent),
            label: Text(
              s('Edit Profile'),
              style: TextStyle(
                color: t.accent,
                fontWeight: FontWeight.w700,
                fontSize: 13.5,
              ),
            ),
          ),
        ),
        const SizedBox(height: 8),

        // ── Balance card ─────────────────────────────────────────────────
        IceCard(
          hero: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.account_balance_rounded, size: 16, color: t.onHero.mint),
                  const SizedBox(width: 8),
                  MicroLabel(s('Tuition Balance'), color: t.onHero.mint),
                ],
              ),
              const SizedBox(height: 10),
              Text(
                balance > 0 ? _uzs(balance) : '${s('All paid')} 🎉',
                style: const TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.w800,
                  color: Colors.white,
                  letterSpacing: -0.5,
                ),
              ),
              if (balance > 0) ...[
                const SizedBox(height: 10),
                Row(
                  children: [
                    if (dueDate != null)
                      StatusBadge(
                        _dueLabel(s, dueDate),
                        tone: dueDate.isBefore(DateTime.now())
                            ? BadgeTone.coral
                            : BadgeTone.amber,
                      ),
                  ],
                ),
                const SizedBox(height: 14),
                SizedBox(
                  width: 140,
                  height: 44,
                  child: FilledButton(
                    onPressed: () => context.go('/student/payments'),
                    style: FilledButton.styleFrom(
                      backgroundColor: t.onHero.accent,
                      foregroundColor: t.onHero.onAccent,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14),
                      ),
                    ),
                    child: Text(
                      s('Pay Now'),
                      style: const TextStyle(
                        fontWeight: FontWeight.w800,
                        fontSize: 14,
                      ),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 14),

        // ── Quick cards 2×2 ──────────────────────────────────────────────
        Row(
          children: [
            Expanded(
              child: _QuickCard(
                icon: Icons.payments_outlined,
                title: s('Payments'),
                subtitle: s('History & invoices'),
                onTap: () => context.go('/student/payments'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _QuickCard(
                icon: Icons.event_busy_outlined,
                title: s('Leave Requests'),
                subtitle: s('Manage absences'),
                onTap: () => context.go('/student/leave'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: _QuickCard(
                icon: Icons.forum_outlined,
                title: s('Feedback'),
                subtitle: s('Reviews & reports'),
                onTap: () => context.go('/student/feedback'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _QuickCard(
                icon: Icons.settings_outlined,
                title: s('Settings'),
                subtitle: s('App preferences'),
                onTap: () => context.push('/student/settings'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 22),

        // ── Recent activity ──────────────────────────────────────────────
        SectionHeader(
          s('Recent Activity'),
          actionLabel: s('View All'),
          onAction: () => context.go('/student/notifications'),
        ),
        notifications.maybeWhen(
          data: (list) => list.isEmpty
              ? IceCard(
                  child: EmptyState(
                    icon: Icons.history_rounded,
                    title: s('No activity yet'),
                  ),
                )
              : Column(
                  children: list
                      .take(3)
                      .map(
                        (n) => Padding(
                          padding: const EdgeInsets.only(bottom: 10),
                          child: ActionTile(
                            icon: _categoryIcon(n['category']),
                            iconColor: t.mint,
                            title: _categoryTitle(s, n['category']),
                            subtitle: n['message'] ?? '',
                            trailing: n['is_read'] == false
                                ? StatusBadge(s('New'), tone: BadgeTone.accent)
                                : null,
                            onTap: () => context.go('/student/notifications'),
                          ),
                        ),
                      )
                      .toList(),
                ),
          orElse: () => const SkeletonBox(height: 64),
        ),
        const SizedBox(height: 16),

        // ── Appearance selector ──────────────────────────────────────────
        SectionHeader(s('Appearance')),
        IceCard(
          padding: const EdgeInsets.all(8),
          child: Column(
            children: [
              _ThemeRow(
                icon: Icons.contrast_rounded,
                label: s('System Default'),
                selected: settings.themeMode == ThemeMode.system,
                onTap: () => ref
                    .read(appSettingsProvider.notifier)
                    .setTheme(ThemeMode.system),
              ),
              _ThemeRow(
                icon: Icons.light_mode_outlined,
                label: s('Light Mode'),
                selected: settings.themeMode == ThemeMode.light,
                onTap: () => ref
                    .read(appSettingsProvider.notifier)
                    .setTheme(ThemeMode.light),
              ),
              _ThemeRow(
                icon: Icons.dark_mode_outlined,
                label: s('Dark Mode'),
                selected: settings.themeMode == ThemeMode.dark,
                onTap: () => ref
                    .read(appSettingsProvider.notifier)
                    .setTheme(ThemeMode.dark),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        IceButton(
          s('Log out'),
          secondary: true,
          icon: Icons.logout_rounded,
          onPressed: () => ref.read(authProvider.notifier).logout(),
        ),
      ],
    );
  }

  String _dueLabel(S s, DateTime due) {
    final today = DateTime.now();
    final diff = due
        .difference(DateTime(today.year, today.month, today.day))
        .inDays;
    if (diff < 0) return s('Overdue');
    if (diff == 0) return s('Due today');
    return s('Due in {n} days').replaceAll('{n}', '$diff');
  }

  IconData _categoryIcon(dynamic c) => switch (c) {
    'attendance' => Icons.event_available_rounded,
    'result' => Icons.workspace_premium_outlined,
    'announcement' => Icons.campaign_rounded,
    'homework' => Icons.assignment_outlined,
    'vocabulary' => Icons.translate_rounded,
    'payment' => Icons.payments_outlined,
    _ => Icons.notifications_none_rounded,
  };

  String _categoryTitle(S s, dynamic c) => switch (c) {
    'attendance' => s('Attendance'),
    'result' => s('Result'),
    'announcement' => s('Announcement'),
    'homework' => s('Assignment'),
    'vocabulary' => s('Vocabulary'),
    'payment' => s('Payment'),
    _ => s('Notification'),
  };
}

class _QuickCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  const _QuickCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      onTap: onTap,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(9),
            decoration: BoxDecoration(
              color: t.accentSoft,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, size: 19, color: t.accent),
          ),
          const SizedBox(height: 12),
          Text(
            title,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 14.5,
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            subtitle,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 11.5,
              fontWeight: FontWeight.w500,
              color: t.textMid,
            ),
          ),
        ],
      ),
    );
  }
}

class _ThemeRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  const _ThemeRow({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: selected ? t.accent : Colors.transparent,
          borderRadius: BorderRadius.circular(15),
        ),
        child: Row(
          children: [
            Icon(icon, size: 19, color: selected ? t.onAccent : t.textMid),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                label,
                style: TextStyle(
                  fontSize: 14.5,
                  fontWeight: FontWeight.w700,
                  color: selected ? t.onAccent : t.textHi,
                ),
              ),
            ),
            if (selected)
              Icon(
                Icons.check_circle_outline_rounded,
                size: 19,
                color: t.onAccent,
              ),
          ],
        ),
      ),
    );
  }
}
