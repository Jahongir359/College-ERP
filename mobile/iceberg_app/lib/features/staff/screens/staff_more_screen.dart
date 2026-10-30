import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/auth/auth_state.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';

class StaffMoreScreen extends ConsumerWidget {
  const StaffMoreScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider.select((a) => a.user));

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

    final tiles = [
      _TileSpec(
        icon: Icons.grade_rounded,
        label: s('Results'),
        path: '/staff/results',
        color: t.amber,
      ),
      _TileSpec(
        icon: Icons.assignment_rounded,
        label: s('Assignments'),
        path: '/staff/assignments',
        color: t.sky,
      ),
      _TileSpec(
        icon: Icons.menu_book_rounded,
        label: s('Vocabulary'),
        path: '/staff/vocabulary',
        color: t.mint,
      ),
      _TileSpec(
        icon: Icons.beach_access_rounded,
        label: s('Leave'),
        path: '/staff/leave',
        color: t.accentInk,
      ),
      _TileSpec(
        icon: Icons.rate_review_rounded,
        label: s('Feedback'),
        path: '/staff/feedback',
        color: t.textMid,
      ),
      _TileSpec(
        icon: Icons.payment_rounded,
        label: s('Payments'),
        path: '/staff/payments',
        color: t.accentInk,
      ),
      _TileSpec(
        icon: Icons.notifications_rounded,
        label: s('Notifications'),
        path: '/staff/notifications',
        color: t.sky,
      ),
      _TileSpec(
        icon: Icons.settings_outlined,
        label: s('Settings'),
        path: '/staff/settings',
        color: t.textMid,
      ),
      _TileSpec(
        icon: Icons.logout_rounded,
        label: s('Log Out'),
        path: '',
        color: t.coral,
        isLogout: true,
      ),
    ];

    return ListView(
      physics: const AlwaysScrollableScrollPhysics(),
      cacheExtent: 600,
      padding: const EdgeInsets.fromLTRB(20, 8, 20, 28),
      children: [
        // ── Profile hero ──────────────────────────────────────────────
        IceCard(
          hero: true,
          child: Row(
            children: [
              Container(
                width: 58,
                height: 58,
                decoration: BoxDecoration(
                  color: t.onHero.accent.withValues(alpha: 0.18),
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: t.onHero.accent.withValues(alpha: 0.5),
                    width: 2,
                  ),
                ),
                child: Center(
                  child: Text(
                    initials,
                    style: TextStyle(
                      color: t.onHero.accent,
                      fontWeight: FontWeight.w900,
                      fontSize: 20,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      user?.fullName ?? s('Staff Member'),
                      style: const TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w800,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      'ID ${user?.loginId ?? '—'}',
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w500,
                        color: Colors.white.withValues(alpha: 0.65),
                      ),
                    ),
                  ],
                ),
              ),
              GestureDetector(
                onTap: () => context.push('/staff/profile'),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 12, vertical: 6),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(
                      color: Colors.white.withValues(alpha: 0.14),
                    ),
                  ),
                  child: Text(
                    s('Profile'),
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                      color: Colors.white,
                    ),
                  ),
                ),
              ),
            ],
          ),
        ).animate().fadeIn(duration: 300.ms).moveY(begin: 12, end: 0),
        const SizedBox(height: 22),

        // ── Grid of tools ─────────────────────────────────────────────
        SectionHeader(s('Tools & Settings')),
        GridView.builder(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 3,
            mainAxisSpacing: 12,
            crossAxisSpacing: 12,
            childAspectRatio: 1.0,
          ),
          itemCount: tiles.length,
          itemBuilder: (context, i) {
            final tile = tiles[i];
            return _MoreTileWidget(
              tile: tile,
              onTap: () {
                if (tile.isLogout) {
                  ref.read(authProvider.notifier).logout();
                } else {
                  context.push(tile.path);
                }
              },
            );
          },
        ).animate().fadeIn(duration: 220.ms),
      ],
    );
  }
}

class _TileSpec {
  final IconData icon;
  final String label;
  final String path;
  final Color color;
  final bool isLogout;

  const _TileSpec({
    required this.icon,
    required this.label,
    required this.path,
    required this.color,
    this.isLogout = false,
  });
}

class _MoreTileWidget extends StatelessWidget {
  final _TileSpec tile;
  final VoidCallback onTap;
  const _MoreTileWidget({
    required this.tile,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final iconBg = tile.color.withValues(alpha: 0.13);

    return IceCard(
      padding: EdgeInsets.zero,
      onTap: onTap,
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 52,
            height: 52,
            decoration: BoxDecoration(
              color: iconBg,
              shape: BoxShape.circle,
            ),
            child: Icon(tile.icon, color: tile.color, size: 24),
          ),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 6),
            child: Text(
              tile.label,
              textAlign: TextAlign.center,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: tile.isLogout ? t.coral : t.textHi,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
