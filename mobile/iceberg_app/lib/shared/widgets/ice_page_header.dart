import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import '../../core/theme/app_theme.dart';
import '../../core/theme/brand.dart';

/// Clean white page header. Used at the top of scrollable pages.
/// Pass [gradient] = true for the dark teal gradient variant (e.g. leaderboard).
class IcePageHeader extends StatelessWidget {
  final String title;
  final String subtitle;
  final Widget? avatar;
  final List<Widget> chips;
  final bool gradient;
  final List<Widget>? actions;

  const IcePageHeader({
    super.key,
    required this.title,
    this.subtitle = '',
    this.avatar,
    this.chips = const [],
    this.gradient = false,
    this.actions,
  });

  @override
  Widget build(BuildContext context) {
    final top = MediaQuery.paddingOf(context).top;

    if (gradient) {
      // Dark teal variant for special pages
      return Container(
        padding: EdgeInsets.fromLTRB(20, top + 16, 20, 24),
        decoration: const BoxDecoration(
          gradient: kHeroGradient,
          borderRadius: BorderRadius.vertical(bottom: Radius.circular(32)),
        ),
        child: _content(Colors.white, Colors.white70),
      );
    }

    // Default: clean white header
    return Container(
      color: Colors.white,
      padding: EdgeInsets.fromLTRB(20, top + 16, 20, 20),
      child: _content(IceColors.text, IceColors.muted),
    );
  }

  Widget _content(Color titleColor, Color subtitleColor) {
    return Builder(
      builder: (context) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        color: titleColor,
                        fontSize: 22,
                        fontWeight: FontWeight.w900,
                        letterSpacing: -0.3,
                      ),
                    ).animate().fadeIn(duration: 300.ms),
                    if (subtitle.isNotEmpty) ...[
                      const SizedBox(height: 3),
                      Text(
                        subtitle,
                        style: TextStyle(
                          color: subtitleColor,
                          fontSize: 13,
                          fontWeight: FontWeight.w500,
                        ),
                      ).animate(delay: 60.ms).fadeIn(duration: 300.ms),
                    ],
                  ],
                ),
              ),
              // The app theme gives ElevatedButton an infinite min-width (for
              // full-width form buttons); inside the header row that would
              // squeeze the title to zero, so cap it here for all actions.
              if (actions != null)
                ElevatedButtonTheme(
                  data: ElevatedButtonThemeData(
                    style: Theme.of(context).elevatedButtonTheme.style
                        ?.copyWith(
                          minimumSize: const WidgetStatePropertyAll(
                            Size(0, 42),
                          ),
                          padding: const WidgetStatePropertyAll(
                            EdgeInsets.symmetric(horizontal: 16),
                          ),
                        ),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: actions!,
                  ),
                ),
              if (avatar != null) ...[
                if (actions != null) const SizedBox(width: 8),
                avatar!
                    .animate(delay: 100.ms)
                    .scale(duration: 350.ms, curve: Curves.elasticOut),
              ],
            ],
          ),
          if (chips.isNotEmpty) ...[
            const SizedBox(height: 14),
            Wrap(spacing: 8, children: chips)
                .animate(delay: 180.ms)
                .slideY(begin: 0.2, duration: 350.ms, curve: Curves.easeOut)
                .fadeIn(duration: 300.ms),
          ],
        ],
      ),
    );
  }
}

/// Small colored chip used inside page headers.
class IceHeaderChip extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  final bool dark;

  const IceHeaderChip({
    super.key,
    required this.icon,
    required this.label,
    required this.onTap,
    this.dark = false,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: dark
              ? Colors.white.withAlpha(18)
              : context.brandPrimary.withAlpha(12),
          borderRadius: BorderRadius.circular(30),
          border: Border.all(
            color: dark ? Colors.white.withAlpha(30) : IceColors.border,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 13,
              color: dark ? context.brandHighlight : context.brandPrimary,
            ),
            const SizedBox(width: 5),
            Text(
              label,
              style: TextStyle(
                color: dark ? Colors.white : context.brandPrimary,
                fontSize: 12,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

/// Lime circle avatar with initials — used throughout the redesigned app.
class IceAvatar extends StatelessWidget {
  final String name;
  final double size;

  const IceAvatar({super.key, required this.name, this.size = 44});

  String get _initials {
    final parts = name.trim().split(' ').where((p) => p.isNotEmpty).toList();
    if (parts.isEmpty) return '?';
    if (parts.length == 1) return parts[0][0].toUpperCase();
    return '${parts[0][0]}${parts[1][0]}'.toUpperCase();
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(color: context.brandHighlight, shape: BoxShape.circle),
      alignment: Alignment.center,
      child: Text(
        _initials,
        style: TextStyle(
          color: context.brandDeep,
          fontSize: size * 0.34,
          fontWeight: FontWeight.w900,
          letterSpacing: -0.5,
        ),
      ),
    );
  }
}

/// Section header row: bold title left + optional action right.
class IceSectionHeader extends StatelessWidget {
  final String title;
  final String? actionLabel;
  final VoidCallback? onAction;

  const IceSectionHeader({
    super.key,
    required this.title,
    this.actionLabel,
    this.onAction,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 24, 16, 10),
      child: Row(
        children: [
          Expanded(
            child: Text(
              title,
              style: const TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w800,
                color: IceColors.text,
              ),
            ),
          ),
          if (actionLabel != null)
            GestureDetector(
              onTap: onAction,
              child: Text(
                actionLabel!,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: context.brandPrimary,
                ),
              ),
            ),
        ],
      ),
    );
  }
}
