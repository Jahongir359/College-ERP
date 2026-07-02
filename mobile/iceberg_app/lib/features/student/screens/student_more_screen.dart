import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/app_theme.dart';

class StudentMoreScreen extends ConsumerWidget {
  const StudentMoreScreen({super.key});

  static const _tiles = [
    _MoreTile(icon: Icons.fact_check_rounded,      label: 'Attendance',   path: '/student/attendance'),
    _MoreTile(icon: Icons.grade_rounded,           label: 'Results',      path: '/student/results'),
    _MoreTile(icon: Icons.assignment_rounded,       label: 'Assignments',  path: '/student/assignments'),
    _MoreTile(icon: Icons.emoji_events_rounded,    label: 'Leaderboard',  path: '/student/leaderboard'),
    _MoreTile(icon: Icons.payment_rounded,         label: 'Payments',     path: '/student/payments'),
    _MoreTile(icon: Icons.beach_access_rounded,    label: 'Leave',        path: '/student/leave'),
    _MoreTile(icon: Icons.rate_review_rounded,     label: 'Feedback',     path: '/student/feedback'),
    _MoreTile(icon: Icons.notifications_rounded,   label: 'Notifications',path: '/student/notifications'),
    _MoreTile(icon: Icons.auto_stories_rounded,    label: 'Books',        path: '/student/books'),
    _MoreTile(icon: Icons.person_rounded,          label: 'Profile',      path: '/student/profile'),
    _MoreTile(icon: Icons.logout_rounded,          label: 'Logout',       path: '/login', isLogout: true),
  ];

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(stringsProvider);
    final top = MediaQuery.paddingOf(context).top;
    final cols = MediaQuery.of(context).size.width >= 600 ? 3 : 2;

    return Scaffold(
      backgroundColor: IceColors.bg,
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.fromLTRB(20, top + 20, 20, 28),
            decoration: const BoxDecoration(
              gradient: kHeroGradient,
              borderRadius: BorderRadius.vertical(bottom: Radius.circular(28)),
            ),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(s('More'),
                  style: const TextStyle(
                      color: Colors.white, fontSize: 26, fontWeight: FontWeight.w900))
                  .animate().slideX(begin: -0.1, duration: 400.ms).fadeIn(duration: 300.ms),
              const SizedBox(height: 4),
              Text(s('All your learning tools'),
                  style: TextStyle(color: Colors.white.withAlpha(160), fontSize: 13))
                  .animate(delay: 80.ms).fadeIn(),
            ]),
          ),
          Expanded(
            child: GridView.builder(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 100),
              cacheExtent: 600,
              gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: cols,
                mainAxisSpacing: 12,
                crossAxisSpacing: 12,
                childAspectRatio: 1.05,
              ),
              itemCount: _tiles.length,
              itemBuilder: (context, i) => _MoreTileWidget(_tiles[i]),
            ).animate().fadeIn(duration: 220.ms),
          ),
        ],
      ),
    );
  }
}

class _MoreTile {
  final IconData icon;
  final String label;
  final String path;
  final bool isLogout;
  const _MoreTile({
    required this.icon,
    required this.label,
    required this.path,
    this.isLogout = false,
  });
}

class _MoreTileWidget extends ConsumerWidget {
  final _MoreTile tile;
  const _MoreTileWidget(this.tile);

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(stringsProvider);
    final iconColor = tile.isLogout ? IceColors.danger : IceColors.navyDeep;
    final bgColor = tile.isLogout ? IceColors.danger.withAlpha(20) : IceColors.surface2;

    return Material(
      color: IceColors.surface,
      borderRadius: BorderRadius.circular(20),
      child: InkWell(
        borderRadius: BorderRadius.circular(20),
        onTap: () => context.go(tile.path),
        child: Container(
          decoration: BoxDecoration(
            border: Border.all(color: IceColors.border, width: 1.5),
            borderRadius: BorderRadius.circular(20),
          ),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Container(
                width: 64,
                height: 64,
                decoration: BoxDecoration(color: bgColor, shape: BoxShape.circle),
                child: Icon(tile.icon, color: iconColor, size: 28),
              ),
              const SizedBox(height: 10),
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 8),
                child: Text(
                  s(tile.label),
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color: tile.isLogout ? IceColors.danger : IceColors.text,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
