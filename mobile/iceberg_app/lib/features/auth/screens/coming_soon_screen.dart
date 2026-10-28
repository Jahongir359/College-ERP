import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/auth/auth_state.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';

/// Shown when a staff or admin account signs in. Their dedicated mobile
/// dashboards are not part of this release — only the student app ships for
/// now — so they get a friendly "coming soon" wall and a way back to login.
class ComingSoonScreen extends ConsumerWidget {
  const ComingSoonScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Always the dark palette of the user's brand (the School gets maroon).
    final t = IceTokens.dark(brand: context.ice.brand).onHero;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider).user;
    final message = user == null
        ? s('This app is still under construction.')
        : user.isSuperAdmin
        ? s('The super-admin app is still under construction.')
        : user.isAdmin
        ? s('The admin app is still under construction.')
        : user.isStaff
        ? s('The teacher app is still under construction.')
        : user.isParent
        ? s('The parent app is still under construction.')
        : s('This app is still under construction.');

    return Scaffold(
      backgroundColor: t.bg,
      body: Container(
        width: double.infinity,
        decoration: BoxDecoration(gradient: t.heroGradient),
        child: SafeArea(
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 28),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 104,
                      height: 104,
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.06),
                        borderRadius: BorderRadius.circular(30),
                        border: Border.all(
                          color: t.accent.withValues(alpha: 0.4),
                        ),
                      ),
                      alignment: Alignment.center,
                      child: Icon(
                        Icons.rocket_launch_rounded,
                        size: 52,
                        color: t.accent,
                      ),
                    ).animate().scale(
                      duration: 420.ms,
                      curve: Curves.easeOutBack,
                    ),
                    const SizedBox(height: 28),
                    Text(
                      'ICEBERG',
                      style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 6,
                        color: t.mint,
                      ),
                    ),
                    const SizedBox(height: 14),
                    Text(
                      s('Coming Soon'),
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 30,
                        fontWeight: FontWeight.w800,
                        letterSpacing: -0.5,
                        color: Colors.white,
                      ),
                    ).animate().fadeIn(delay: 100.ms).moveY(begin: 12, end: 0),
                    const SizedBox(height: 12),
                    Text(
                      '$message ${s('For now, only the student experience is available on mobile.')}'
                      '\n\n${s('Please use the web portal for staff and admin tasks.')}',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 14.5,
                        height: 1.55,
                        fontWeight: FontWeight.w500,
                        color: Colors.white.withValues(alpha: 0.72),
                      ),
                    ).animate().fadeIn(delay: 180.ms),
                    const SizedBox(height: 36),
                    SizedBox(
                      width: double.infinity,
                      height: 54,
                      child: FilledButton.icon(
                        onPressed: () async {
                          await ref.read(authProvider.notifier).logout();
                          if (context.mounted) context.go('/login');
                        },
                        style: FilledButton.styleFrom(
                          backgroundColor: t.accent,
                          foregroundColor: t.onAccent,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                          ),
                          textStyle: const TextStyle(
                            fontFamily: 'Inter',
                            fontSize: 15,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                        icon: const Icon(Icons.arrow_back_rounded, size: 20),
                        label: Text(s('Back to login')),
                      ),
                    ).animate().fadeIn(delay: 260.ms).moveY(begin: 10, end: 0),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
