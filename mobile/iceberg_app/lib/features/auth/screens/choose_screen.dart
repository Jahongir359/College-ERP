import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/settings/app_settings.dart';
import '../../../core/theme/brand.dart';
import '../../../core/theme/brand_provider.dart';

/// First launch: Iceberg School or Iceberg Study Center (plan 5.1, D7). The
/// pick brands the login screen and is remembered; after sign-in the account
/// decides the brand. The login screen links back here to change it.
class ChooseScreen extends ConsumerWidget {
  const ChooseScreen({super.key});

  // Mockup 01-choice colours (docs/plans/school-app-mockups/build_mockups.py).
  static const _gold = Color(0xFFC9973F);
  static const _goldInk = Color(0xFF8A5A12);
  static const _goldSoft = Color(0xFFE9C77E);
  static const _centerHi = Color(0xFF103A57);
  static const _centerDeep = Color(0xFF07233A);
  static const _centerLime = Color(0xFFCDF163);

  void _pick(BuildContext context, WidgetRef ref, IceBrand brand) {
    HapticFeedback.selectionClick();
    ref.read(lastBrandProvider.notifier).remember(brand);
    context.go('/login');
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(stringsProvider);
    final dark = Theme.of(context).brightness == Brightness.dark;
    final bg = dark ? SchoolColors.darkBg : SchoolColors.bg;
    final text = dark ? SchoolColors.darkText : SchoolColors.primary;
    final muted = dark ? SchoolColors.darkMuted : SchoolColors.muted;

    return Scaffold(
      backgroundColor: bg,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.fromLTRB(20, 10, 20, 24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 440),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Container(
                        width: 40,
                        height: 40,
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(
                          color: SchoolColors.primary,
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: Image.asset(
                          IceBrandLogo.schoolCrestAsset,
                          errorBuilder: (_, __, ___) => const SizedBox(),
                        ),
                      ),
                      const Spacer(),
                      const _LanguageSwitch(),
                    ],
                  ),
                  const SizedBox(height: 34),
                  Text(
                    s('Welcome').toUpperCase(),
                    style: TextStyle(
                      fontSize: 11.5,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.4,
                      color: dark ? _goldSoft : _goldInk,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    s('Which Iceberg are you signing in to?'),
                    style: TextStyle(
                      fontSize: 32,
                      height: 1.12,
                      fontWeight: FontWeight.w800,
                      letterSpacing: -0.3,
                      color: text,
                    ),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    s('Choose one. Next time the app opens there.'),
                    style: TextStyle(fontSize: 15.5, height: 1.5, color: muted),
                  ),
                  const SizedBox(height: 28),
                  _BrandCard(
                    key: const ValueKey('choose-school'),
                    title: IceBrand.school.appTitle,
                    subtitle: s('Private school · Grades 1–11'),
                    subtitleColor: SchoolColors.onPrimarySoft,
                    gradient: const [
                      SchoolColors.primaryHover,
                      SchoolColors.primary,
                      SchoolColors.primaryDeep,
                    ],
                    shadow: SchoolColors.primary,
                    underline: _gold,
                    chevron: Colors.white,
                    logo: Image.asset(
                      IceBrandLogo.schoolCrestAsset,
                      height: 58,
                      errorBuilder: (_, __, ___) => const SizedBox(height: 58),
                    ),
                    onTap: () => _pick(context, ref, IceBrand.school),
                  ),
                  const SizedBox(height: 14),
                  _BrandCard(
                    key: const ValueKey('choose-center'),
                    title: IceBrand.center.appTitle,
                    subtitle: s('IELTS, CEFR, SAT and subject courses'),
                    subtitleColor: const Color(0xFFAFD9F2),
                    gradient: const [_centerHi, _centerDeep],
                    shadow: _centerDeep,
                    underline: _centerLime,
                    chevron: _centerLime,
                    logo: ClipRRect(
                      borderRadius: BorderRadius.circular(16),
                      child: Image.asset(
                        IceBrandLogo.centerAsset,
                        width: 58,
                        height: 58,
                        errorBuilder: (_, __, ___) =>
                            const SizedBox(width: 58, height: 58),
                      ),
                    ),
                    onTap: () => _pick(context, ref, IceBrand.center),
                  ),
                  const SizedBox(height: 22),
                  Center(
                    child: Text(
                      s('You can change this on the sign-in screen'),
                      textAlign: TextAlign.center,
                      style: TextStyle(fontSize: 13, color: muted),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _BrandCard extends StatelessWidget {
  const _BrandCard({
    super.key,
    required this.title,
    required this.subtitle,
    required this.subtitleColor,
    required this.gradient,
    required this.shadow,
    required this.underline,
    required this.chevron,
    required this.logo,
    required this.onTap,
  });

  final String title;
  final String subtitle;
  final Color subtitleColor;
  final List<Color> gradient;
  final Color shadow;
  final Color underline;
  final Color chevron;
  final Widget logo;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final radius = BorderRadius.circular(28);
    return Semantics(
      button: true,
      label: '$title. $subtitle',
      excludeSemantics: true,
      child: Container(
        decoration: BoxDecoration(
          borderRadius: radius,
          gradient: LinearGradient(
            begin: Alignment.topRight,
            end: Alignment.bottomLeft,
            colors: gradient,
          ),
          boxShadow: [
            BoxShadow(
              color: shadow.withValues(alpha: 0.28),
              blurRadius: 40,
              offset: const Offset(0, 18),
            ),
          ],
        ),
        child: Material(
          color: Colors.transparent,
          child: InkWell(
            borderRadius: radius,
            onTap: onTap,
            child: ConstrainedBox(
              constraints: const BoxConstraints(minHeight: 178),
              child: Padding(
                padding: const EdgeInsets.all(22),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        logo,
                        const Spacer(),
                        Container(
                          width: 40,
                          height: 40,
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.14),
                            shape: BoxShape.circle,
                          ),
                          child: Icon(
                            Icons.chevron_right_rounded,
                            color: chevron,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 18),
                    Text(
                      title,
                      style: const TextStyle(
                        fontSize: 24,
                        fontWeight: FontWeight.w800,
                        letterSpacing: -0.2,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      subtitle,
                      style: TextStyle(fontSize: 14, color: subtitleColor),
                    ),
                    const SizedBox(height: 12),
                    Container(
                      width: 46,
                      height: 2,
                      decoration: BoxDecoration(
                        color: underline,
                        borderRadius: BorderRadius.circular(2),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    ).animate().fadeIn(duration: 300.ms).slideY(begin: 0.06, duration: 400.ms);
  }
}

/// UZ / RU / EN pills; the pick is the app language from now on.
class _LanguageSwitch extends ConsumerWidget {
  const _LanguageSwitch();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final lang = ref.watch(appSettingsProvider.select((s) => s.language));
    final dark = Theme.of(context).brightness == Brightness.dark;
    return Container(
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: dark ? SchoolColors.darkSurface : Colors.white,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
          color: dark ? SchoolColors.darkBorder : SchoolColors.border,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          for (final code in const ['uz', 'ru', 'en'])
            Semantics(
              button: true,
              selected: lang == code,
              child: InkWell(
                key: ValueKey('lang-$code'),
                borderRadius: BorderRadius.circular(999),
                onTap: () =>
                    ref.read(appSettingsProvider.notifier).setLanguage(code),
                child: Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 14,
                    vertical: 8,
                  ),
                  decoration: BoxDecoration(
                    color: lang == code
                        ? (dark ? SchoolColors.darkFill : SchoolColors.primary)
                        : Colors.transparent,
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: Text(
                    code.toUpperCase(),
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                      color: lang == code
                          ? Colors.white
                          : (dark
                                ? SchoolColors.darkMuted
                                : SchoolColors.muted),
                    ),
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}
