import 'package:flutter/material.dart';

import 'brand.dart';

/// ICEBERG dark design language — tokens sampled from the design reference
/// screenshots (dark navy/teal surfaces, lime neon accent, mint secondary).
///
/// All student screens read these via `context.ice` so the appearance
/// settings (theme + accent colour) can swap the whole palette at runtime.
class IceTokens extends ThemeExtension<IceTokens> {
  // Surfaces
  final Color bg; // page background
  final Color card; // standard card
  final Color cardHi; // gradient top of hero cards
  final Color cardLo; // gradient bottom of hero cards
  final Color inset; // inset fields / chips on cards
  final Color stroke; // hairline card border

  // Text
  final Color textHi;
  final Color textMid;
  final Color textLow;

  // Brand
  final Color accent; // lime by default — used for FILLS (buttons, active pills)
  final Color accentInk; // legible accent for TEXT/ICONS on the page background
  final Color onAccent; // dark text on the accent
  final Color mint; // soft cyan/mint secondary (ICEBERG wordmark)

  // Semantics
  final Color coral; // absent / overdue / danger
  final Color sky; // late / info
  final Color amber; // pending / warning

  final bool isDark;

  /// Learning Center (default) or School — set from the signed-in user's
  /// branch. Widgets read it via `context.brand` (brand.dart).
  final IceBrand brand;

  const IceTokens({
    required this.bg,
    required this.card,
    required this.cardHi,
    required this.cardLo,
    required this.inset,
    required this.stroke,
    required this.textHi,
    required this.textMid,
    required this.textLow,
    required this.accent,
    required this.accentInk,
    required this.onAccent,
    required this.mint,
    required this.coral,
    required this.sky,
    required this.amber,
    required this.isDark,
    this.brand = IceBrand.center,
  });

  /// Deepens a bright accent so it stays legible as text/icons on a light
  /// surface (bright lime is nearly invisible on white). Bright accents are
  /// kept for fills where dark [onAccent] text sits on top.
  static Color _inkFor(Color c) {
    final h = HSLColor.fromColor(c);
    return h
        .withLightness((h.lightness * 0.42).clamp(0.0, 1.0))
        .withSaturation((h.saturation * 1.12).clamp(0.0, 1.0))
        .toColor();
  }

  factory IceTokens.dark({
    Color accent = IceAccents.ice,
    IceBrand brand = IceBrand.center,
  }) => brand.isSchool
      ? _schoolDark(accent)
      : IceTokens(
    bg: const Color(0xFF071520), // deep glacier navy
    card: const Color(0xFF0E2233),
    cardHi: const Color(0xFF143A57), // hero cards — rich iceberg blue
    cardLo: const Color(0xFF0A1F31),
    inset: const Color(0xFF122B40),
    stroke: const Color(0xFF1E3C57),
    textHi: const Color(0xFFF0F6FC),
    textMid: const Color(0xFF9FB7D0),
    textLow: const Color(0xFF607890),
    accent: accent,
    accentInk: accent, // bright accent reads well on the dark surface
    onAccent: const Color(0xFF052033),
    mint: const Color(0xFFAFD9F2), // icy light blue (wordmark / labels)
    coral: const Color(0xFFF2917F),
    sky: const Color(0xFF93D2EC),
    amber: const Color(0xFFF4C95D),
    isDark: true,
  );

  factory IceTokens.light({
    Color accent = IceAccents.ice,
    IceBrand brand = IceBrand.center,
  }) => brand.isSchool
      ? _schoolLight(accent)
      : IceTokens(
    bg: const Color(0xFFEDF3F9), // soft cool off-white with a blue cast
    card: Colors.white,
    cardHi: const Color(0xFF103A57), // hero cards stay deep iceberg blue
    cardLo: const Color(0xFF07233A),
    inset: const Color(0xFFE6EEF7),
    stroke: const Color(0xFFD2DFEC),
    textHi: const Color(0xFF06223A), // deeper for stronger contrast
    textMid: const Color(0xFF4C6480),
    textLow: const Color(0xFF8195AB),
    accent: accent,
    accentInk: _inkFor(accent), // legible deep variant for text/icons
    onAccent: const Color(0xFF052033),
    mint: const Color(0xFF0E6486),
    coral: const Color(0xFFD64C3D),
    sky: const Color(0xFF2487B5),
    amber: const Color(0xFFC98A12),
    isDark: false,
  );

  // ── Iceberg School palette ───────────────────────────────────────────────
  // Users who kept the default accent get the School maroon; anyone who picked
  // another accent in Settings keeps it.

  static IceTokens _schoolLight(Color accent) {
    final branded = accent == IceAccents.ice;
    return IceTokens(
      bg: SchoolColors.bg,
      card: Colors.white,
      cardHi: SchoolColors.primary, // hero cards — crest maroon
      cardLo: SchoolColors.primaryDeep,
      inset: const Color(0xFFF4ECEB),
      stroke: SchoolColors.border,
      textHi: SchoolColors.text,
      textMid: SchoolColors.muted,
      textLow: const Color(0xFF8C7270),
      accent: branded ? SchoolColors.primary : accent,
      accentInk: branded ? SchoolColors.primary : _inkFor(accent),
      onAccent: branded ? Colors.white : const Color(0xFF052033),
      mint: SchoolColors.primaryHover,
      coral: const Color(0xFFD64C3D),
      sky: const Color(0xFF2487B5),
      amber: const Color(0xFFC98A12),
      isDark: false,
      brand: IceBrand.school,
    );
  }

  static IceTokens _schoolDark(Color accent) {
    final branded = accent == IceAccents.ice;
    return IceTokens(
      bg: SchoolColors.darkBg,
      card: SchoolColors.darkSurface,
      cardHi: SchoolColors.primary,
      cardLo: const Color(0xFF240707),
      inset: SchoolColors.darkSurface2,
      stroke: SchoolColors.darkBorder,
      textHi: SchoolColors.darkText,
      textMid: SchoolColors.darkMuted,
      textLow: const Color(0xFF8C7270),
      accent: branded ? SchoolColors.ink : accent,
      accentInk: branded ? SchoolColors.ink : accent,
      onAccent: branded ? SchoolColors.primaryDeep : const Color(0xFF052033),
      mint: SchoolColors.onPrimarySoft,
      coral: const Color(0xFFF2917F),
      sky: const Color(0xFF93D2EC),
      amber: const Color(0xFFF4C95D),
      isDark: true,
      brand: IceBrand.school,
    );
  }

  /// Slightly translucent accent for soft fills behind icons.
  Color get accentSoft => accent.withValues(alpha: 0.14);
  Color get coralSoft => coral.withValues(alpha: 0.14);
  Color get skySoft => sky.withValues(alpha: 0.16);
  Color get amberSoft => amber.withValues(alpha: 0.16);

  LinearGradient get heroGradient => LinearGradient(
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
    colors: [cardHi, cardLo],
  );

  @override
  IceTokens copyWith({Color? accent}) => accent == null
      ? this
      : (isDark
            ? IceTokens.dark(accent: accent, brand: brand)
            : IceTokens.light(accent: accent, brand: brand));

  @override
  IceTokens lerp(ThemeExtension<IceTokens>? other, double t) {
    if (other is! IceTokens) return this;
    Color l(Color a, Color b) => Color.lerp(a, b, t)!;
    return IceTokens(
      bg: l(bg, other.bg),
      card: l(card, other.card),
      cardHi: l(cardHi, other.cardHi),
      cardLo: l(cardLo, other.cardLo),
      inset: l(inset, other.inset),
      stroke: l(stroke, other.stroke),
      textHi: l(textHi, other.textHi),
      textMid: l(textMid, other.textMid),
      textLow: l(textLow, other.textLow),
      accent: l(accent, other.accent),
      accentInk: l(accentInk, other.accentInk),
      onAccent: l(onAccent, other.onAccent),
      mint: l(mint, other.mint),
      coral: l(coral, other.coral),
      sky: l(sky, other.sky),
      amber: l(amber, other.amber),
      isDark: t < 0.5 ? isDark : other.isDark,
      brand: t < 0.5 ? brand : other.brand,
    );
  }
}

/// Accent palette selectable in Settings → Appearance.
class IceAccents {
  static const ice = Color(0xFF38BDF0); // brand iceberg blue (default)
  static const cyan = Color(0xFF6FE3D4);
  static const blue = Color(0xFF7FB7F7);
  static const lime = Color(0xFFCDF163);
  static const purple = Color(0xFFC49BF4);
  static const pink = Color(0xFFF49AC1);
  static const orange = Color(0xFFF5B36B);

  static const byName = <String, Color>{
    'ice': ice,
    'cyan': cyan,
    'blue': blue,
    'lime': lime,
    'purple': purple,
    'pink': pink,
    'orange': orange,
  };
}

extension IceContext on BuildContext {
  IceTokens get ice =>
      Theme.of(this).extension<IceTokens>() ?? IceTokens.dark();
}

/// Smooth fade-up transition used for every pushed route. Lighter than the
/// default platform slide, which makes navigation feel faster on Flutter web.
class IceFadeTransitionsBuilder extends PageTransitionsBuilder {
  const IceFadeTransitionsBuilder();

  @override
  Widget buildTransitions<T>(
    PageRoute<T> route,
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) {
    // Incoming page: fade in + rise 4% from below
    final enter = CurvedAnimation(
      parent: animation,
      curve: Curves.easeOutCubic,
      reverseCurve: Curves.easeInCubic,
    );
    // Current page dims slightly when a new one is pushed on top
    final dim = CurvedAnimation(
      parent: secondaryAnimation,
      curve: Curves.easeOut,
    );
    return FadeTransition(
      opacity: Tween<double>(begin: 1.0, end: 0.92).animate(dim),
      child: FadeTransition(
        opacity: enter,
        child: SlideTransition(
          position: Tween<Offset>(
            begin: const Offset(0, 0.04),
            end: Offset.zero,
          ).animate(enter),
          child: child,
        ),
      ),
    );
  }
}

const icePageTransitionsTheme = PageTransitionsTheme(
  builders: {
    TargetPlatform.android: IceFadeTransitionsBuilder(),
    TargetPlatform.iOS: IceFadeTransitionsBuilder(),
    TargetPlatform.macOS: IceFadeTransitionsBuilder(),
    TargetPlatform.windows: IceFadeTransitionsBuilder(),
    TargetPlatform.linux: IceFadeTransitionsBuilder(),
    TargetPlatform.fuchsia: IceFadeTransitionsBuilder(),
  },
);

const _noDecor = TextStyle(
  decoration: TextDecoration.none,
  decorationColor: Colors.transparent,
  decorationThickness: 0,
);

/// Strips all text-decoration from every slot in [theme] so that Material 3's
/// colorScheme.primary cannot bleed through as lime underlines.
TextTheme _noUnderlineTheme(TextTheme theme) => TextTheme(
  displayLarge: (theme.displayLarge ?? const TextStyle()).merge(_noDecor),
  displayMedium: (theme.displayMedium ?? const TextStyle()).merge(_noDecor),
  displaySmall: (theme.displaySmall ?? const TextStyle()).merge(_noDecor),
  headlineLarge: (theme.headlineLarge ?? const TextStyle()).merge(_noDecor),
  headlineMedium: (theme.headlineMedium ?? const TextStyle()).merge(_noDecor),
  headlineSmall: (theme.headlineSmall ?? const TextStyle()).merge(_noDecor),
  titleLarge: (theme.titleLarge ?? const TextStyle()).merge(_noDecor),
  titleMedium: (theme.titleMedium ?? const TextStyle()).merge(_noDecor),
  titleSmall: (theme.titleSmall ?? const TextStyle()).merge(_noDecor),
  bodyLarge: (theme.bodyLarge ?? const TextStyle()).merge(_noDecor),
  bodyMedium: (theme.bodyMedium ?? const TextStyle()).merge(_noDecor),
  bodySmall: (theme.bodySmall ?? const TextStyle()).merge(_noDecor),
  labelLarge: (theme.labelLarge ?? const TextStyle()).merge(_noDecor),
  labelMedium: (theme.labelMedium ?? const TextStyle()).merge(_noDecor),
  labelSmall: (theme.labelSmall ?? const TextStyle()).merge(_noDecor),
);

/// Builds the student-app ThemeData carrying [IceTokens].
ThemeData buildIceTheme({
  required bool dark,
  required Color accent,
  IceBrand brand = IceBrand.center,
}) {
  final t = dark
      ? IceTokens.dark(accent: accent, brand: brand)
      : IceTokens.light(accent: accent, brand: brand);
  final base = dark
      ? ThemeData.dark(useMaterial3: true)
      : ThemeData.light(useMaterial3: true);
  return base.copyWith(
    extensions: [t],
    scaffoldBackgroundColor: t.bg,
    colorScheme: base.colorScheme.copyWith(
      primary: t.accent,
      onPrimary: t.onAccent,
      secondary: t.mint,
      surface: t.card,
      onSurface: t.textHi,
      error: t.coral,
    ),
    textTheme: _noUnderlineTheme(
      base.textTheme.apply(
        fontFamily: 'Inter',
        bodyColor: t.textHi,
        displayColor: t.textHi,
        decoration: TextDecoration.none,
        decorationColor: Colors.transparent,
      ),
    ),
    splashFactory: InkSparkle.splashFactory,
    pageTransitionsTheme: icePageTransitionsTheme,
    dividerColor: t.stroke,
    appBarTheme: AppBarTheme(
      backgroundColor: t.bg,
      foregroundColor: t.textHi,
      elevation: 0,
      surfaceTintColor: Colors.transparent,
      centerTitle: true,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: t.inset,
      hintStyle: TextStyle(color: t.textLow, fontSize: 14),
      labelStyle: TextStyle(color: t.textMid, fontSize: 14),
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: t.stroke),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: t.stroke),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: t.accent, width: 1.6),
      ),
      errorBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(14),
        borderSide: BorderSide(color: t.coral),
      ),
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: t.cardHi,
      contentTextStyle: TextStyle(color: t.textHi, fontFamily: 'Inter'),
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
    ),
    progressIndicatorTheme: ProgressIndicatorThemeData(color: t.accent),
  );
}
