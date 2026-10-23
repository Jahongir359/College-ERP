import 'package:flutter/material.dart';
import '../../core/theme/app_theme.dart';
import '../../core/theme/brand.dart';

class IceHeroCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final Widget? trailing;
  final List<Widget>? actions;
  final double borderRadius;

  const IceHeroCard({
    super.key,
    required this.title,
    required this.subtitle,
    this.trailing,
    this.actions,
    this.borderRadius = 24,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.fromLTRB(12, 10, 12, 20),
      decoration: BoxDecoration(
        gradient: kHeroGradient,
        borderRadius: BorderRadius.circular(borderRadius),
        boxShadow: [
          BoxShadow(
            color: context.brandPrimary.withValues(alpha: 0.28),
            blurRadius: 24,
            offset: const Offset(0, 8),
          ),
        ],
      ),
      child: Stack(
        children: [
          // Glow orb
          Positioned(
            right: -30,
            top: -30,
            child: Container(
              width: 160,
              height: 160,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: context.brandSecondary.withValues(alpha: 0.12),
              ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(22, 24, 22, 22),
            child: Column(
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
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 22,
                              fontWeight: FontWeight.w900,
                              letterSpacing: -0.4,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            subtitle,
                            style: TextStyle(
                              color: Colors.white.withValues(alpha: 0.7),
                              fontSize: 13,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ),
                    if (trailing != null) trailing!,
                  ],
                ),
                if (actions != null && actions!.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  Wrap(spacing: 8, runSpacing: 8, children: actions!),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
