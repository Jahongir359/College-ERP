import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api/api_providers.dart';
import '../../core/auth/auth_state.dart';
import '../../core/settings/app_settings.dart';
import '../../core/theme/brand.dart';
import '../../core/theme/ice_tokens.dart';
import 'ice_kit.dart';

// ─── Header: hamburger · ICEBERG · bell ─────────────────────────────────────
class IceHeader extends ConsumerWidget implements PreferredSizeWidget {
  const IceHeader({super.key});

  @override
  Size get preferredSize => const Size.fromHeight(56);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final user = ref.watch(authProvider).user;
    final isStudent = user?.isStudent ?? true;

    final unread = isStudent
        ? ref.watch(studentDashProvider).maybeWhen(
              data: (d) =>
                  (d['unread_notifications'] as num?)?.toInt() ?? 0,
              orElse: () => 0,
            )
        : ref.watch(notificationsProvider).maybeWhen(
              data: (list) => list.where((n) => !(n['is_read'] as bool? ?? false)).length,
              orElse: () => 0,
            );

    final notifPath = isStudent ? '/student/notifications' : '/staff/notifications';

    return AppBar(
      backgroundColor: t.bg,
      elevation: 0,
      scrolledUnderElevation: 0,
      leading: IconButton(
        icon: Icon(Icons.menu_rounded, color: t.textHi, size: 26),
        onPressed: () => Scaffold.of(context).openDrawer(),
        tooltip: 'Menu',
      ),
      centerTitle: true,
      title: Text(
        'ICEBERG',
        style: TextStyle(
          fontFamily: 'Inter',
          fontSize: 17,
          fontWeight: FontWeight.w800,
          letterSpacing: 4,
          color: t.mint,
        ),
      ),
      actions: [
        // Avatar button → taps to role profile
        Padding(
          padding: const EdgeInsets.only(left: 4),
          child: GestureDetector(
            onTap: () {
              final profilePath =
                  isStudent ? '/student/profile' : '/staff/profile';
              context.go(profilePath);
            },
            child: IceUserAvatar(
              radius: 15,
              photoUrl: user?.profilePicUrl,
              emoji:
                  user?.avatar.isNotEmpty == true ? user!.avatar : null,
              fallbackText: user?.firstName.isNotEmpty == true
                  ? user!.firstName[0].toUpperCase()
                  : '?',
            ),
          ),
        ),
        const SizedBox(width: 4),
        Padding(
          padding: const EdgeInsets.only(right: 6),
          child: IconButton(
            tooltip: 'Notifications',
            onPressed: () => context.go(notifPath),
            icon: Stack(
              clipBehavior: Clip.none,
              children: [
                Icon(
                  Icons.notifications_none_rounded,
                  color: t.textHi,
                  size: 25,
                ),
                if (unread > 0)
                  Positioned(
                    right: -1,
                    top: -1,
                    child: Container(
                      width: 9,
                      height: 9,
                      decoration: BoxDecoration(
                        color: t.coral,
                        shape: BoxShape.circle,
                        border: Border.all(color: t.bg, width: 1.5),
                      ),
                    ),
                  ),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

// ─── Bottom navigation: rounded top corners, lime circular active item ──────
class IceNavSpec {
  final IconData icon;
  final String label;
  const IceNavSpec(this.icon, this.label);
}

class IceBottomNav extends ConsumerWidget {
  final int index;
  final ValueChanged<int> onTap;
  const IceBottomNav({super.key, required this.index, required this.onTap});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final items = [
      IceNavSpec(Icons.grid_view_rounded, s('Dashboard')),
      IceNavSpec(Icons.insert_chart_outlined_rounded, s('Progress')),
      IceNavSpec(Icons.menu_book_rounded, s('Vocabulary')),
      IceNavSpec(Icons.emoji_events_outlined, s('Leaderboard')),
      IceNavSpec(Icons.person_outline_rounded, s('Profile')),
    ];

    return RepaintBoundary(
      child: Container(
      decoration: BoxDecoration(
        color: t.isDark ? const Color(0xFF0A2024) : Colors.white,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(26)),
        border: Border(top: BorderSide(color: t.stroke)),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: t.isDark ? 0.35 : 0.08),
            blurRadius: 10,
            offset: const Offset(0, -3),
          ),
        ],
      ),
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: SizedBox(
          height: 64,
          child: Row(
            children: List.generate(items.length, (i) {
              final active = i == index;
              return Expanded(
                child: GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: () {
                    HapticFeedback.selectionClick();
                    onTap(i);
                  },
                  child: active
                      ? Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            AnimatedContainer(
                              duration: const Duration(milliseconds: 220),
                              curve: Curves.easeOutBack,
                              width: 42,
                              height: 42,
                              decoration: BoxDecoration(
                                color: t.accent,
                                shape: BoxShape.circle,
                                boxShadow: [
                                  BoxShadow(
                                    color: t.accent.withValues(alpha: 0.45),
                                    blurRadius: 14,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Icon(
                                items[i].icon,
                                color: t.onAccent,
                                size: 21,
                              ),
                            ),
                          ],
                        )
                      : Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(items[i].icon, color: t.textMid, size: 22),
                            const SizedBox(height: 3),
                            Text(
                              items[i].label,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                fontSize: 10,
                                fontWeight: FontWeight.w600,
                                color: t.textLow,
                              ),
                            ),
                          ],
                        ),
                ),
              );
            }),
          ),
        ),
        ),
      ),
    ));
  }
}

// ─── Drawer: secondary destinations ─────────────────────────────────────────
class IceDrawer extends ConsumerWidget {
  const IceDrawer({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider).user;
    final isStaff = user?.isStaff ?? false;

    Widget item(IconData icon, String label, String path, {Color? color}) =>
        ListTile(
          leading: Icon(icon, color: color ?? t.textMid, size: 22),
          title: Text(
            label,
            style: TextStyle(
              color: color ?? t.textHi,
              fontWeight: FontWeight.w600,
              fontSize: 14.5,
            ),
          ),
          dense: true,
          onTap: () {
            Navigator.pop(context);
            context.go(path);
          },
        );

    final studentItems = [
      item(Icons.event_available_rounded, s('Attendance'), '/student/attendance'),
      item(Icons.assignment_outlined, s('Assignments'), '/student/assignments'),
      item(Icons.workspace_premium_outlined, s('Results'), '/student/results'),
      item(Icons.folder_open_rounded, s('Result Files'), '/student/result-files'),
      item(Icons.local_library_outlined, s('Library'), '/student/library'),
      item(Icons.payments_outlined, s('Payments'), '/student/payments'),
      item(Icons.event_busy_outlined, s('Leave Requests'), '/student/leave'),
      item(Icons.forum_outlined, s('Feedback'), '/student/feedback'),
      item(Icons.chat_bubble_outline_rounded, s('Messages'), '/student/messages'),
      item(Icons.notifications_none_rounded, s('Notifications'), '/student/notifications'),
      item(Icons.settings_outlined, s('Settings'), '/student/settings'),
    ];

    final staffItems = [
      item(Icons.event_available_rounded, s('Attendance'), '/staff/attendance'),
      item(Icons.grading_rounded, s('Results'), '/staff/results'),
      item(Icons.assignment_outlined, s('Assignments'), '/staff/assignments'),
      item(Icons.class_outlined, s(context.brand.teacherGroupsKey), '/staff/classes'),
      item(Icons.chat_bubble_outline_rounded, s('Messages'), '/staff/messages'),
      item(Icons.event_busy_outlined, s('Leave Requests'), '/staff/leave'),
      item(Icons.forum_outlined, s('Feedback'), '/staff/feedback'),
      item(Icons.payments_outlined, s('Payments'), '/staff/payments'),
      item(Icons.notifications_none_rounded, s('Notifications'), '/staff/notifications'),
      item(Icons.settings_outlined, s('Settings'), '/staff/settings'),
    ];

    return Drawer(
      backgroundColor: t.isDark ? const Color(0xFF0A2024) : Colors.white,
      child: SafeArea(
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 18, 20, 14),
              child: Row(
                children: [
                  IceUserAvatar(
                    radius: 22,
                    photoUrl: user?.profilePicUrl,
                    emoji: user?.avatar.isNotEmpty == true ? user!.avatar : null,
                    fallbackText: user?.firstName.isNotEmpty == true
                        ? user!.firstName[0].toUpperCase()
                        : '?',
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          user?.fullName ?? '',
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(
                            color: t.textHi,
                            fontWeight: FontWeight.w800,
                            fontSize: 15,
                          ),
                        ),
                        Text(
                          'ID ${user?.loginId ?? ''}',
                          style: TextStyle(
                            color: t.textMid,
                            fontWeight: FontWeight.w500,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
            Divider(color: t.stroke, height: 1),
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: 8),
                children: isStaff ? staffItems : studentItems,
              ),
            ),
            Divider(color: t.stroke, height: 1),
            ListTile(
              leading: Icon(Icons.logout_rounded, color: t.coral, size: 22),
              title: Text(
                s('Log out'),
                style: TextStyle(
                  color: t.coral,
                  fontWeight: FontWeight.w700,
                  fontSize: 14.5,
                ),
              ),
              onTap: () async {
                Navigator.pop(context);
                await ref.read(authProvider.notifier).logout();
              },
            ),
            const SizedBox(height: 6),
          ],
        ),
      ),
    );
  }
}

// ─── Page scaffolding helpers used by every screen ──────────────────────────
/// Standard page body: title row (with optional back arrow for sub-pages),
/// then the screen's scrollable content.
class IcePage extends ConsumerWidget {
  final String title;
  final String? subtitle;
  final Widget? action;
  final List<Widget> children;
  final Future<void> Function()? onRefresh;
  final bool backButton;

  const IcePage({
    super.key,
    required this.title,
    this.subtitle,
    this.action,
    required this.children,
    this.onRefresh,
    this.backButton = false,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final user = ref.watch(authProvider.select((a) => a.user));
    final homeRoute = user?.isStaff == true ? '/staff/home' : '/student/home';
    final list = ListView(
      physics: const AlwaysScrollableScrollPhysics(),
      cacheExtent: 600,
      padding: const EdgeInsets.fromLTRB(20, 8, 20, 28),
      children: [
        Row(
          children: [
            if (backButton)
              Padding(
                padding: const EdgeInsets.only(right: 10),
                child: GestureDetector(
                  onTap: () {
                    if (context.canPop()) {
                      context.pop();
                    } else {
                      context.go(homeRoute);
                    }
                  },
                  child: Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: t.inset,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      Icons.arrow_back_rounded,
                      size: 20,
                      color: t.textHi,
                    ),
                  ),
                ),
              ),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                      letterSpacing: -0.4,
                      color: t.textHi,
                    ),
                  ),
                  if (subtitle != null)
                    Padding(
                      padding: const EdgeInsets.only(top: 2),
                      child: Text(
                        subtitle!,
                        style: TextStyle(
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                          color: t.textMid,
                        ),
                      ),
                    ),
                ],
              ),
            ),
            if (action != null) action!,
          ],
        ),
        const SizedBox(height: 16),
        ...children,
      ],
    );

    if (onRefresh == null) return list;
    return RefreshIndicator(
      onRefresh: onRefresh!,
      color: t.onAccent,
      backgroundColor: t.accent,
      child: list,
    );
  }
}
