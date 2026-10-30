import 'package:flutter/material.dart';

import 'brand.dart';

/// Type scale (plan section 6.2). Sizes in logical pixels (scaled by the
/// phone's text size setting like every other `fontSize`).
///
/// School display text (choice-screen title, greetings, screen titles and
/// big numbers such as the time, a quarter grade or an amount due) uses
/// Fraunces 600; everything else, and every Study Center screen, uses Inter.
abstract final class IceType {
  static const double display = 28;
  static const double title = 22;
  static const double heading = 18;
  static const double body = 16;
  static const double label = 14;
  static const double caption = 12;

  /// Line heights: tight for display text, roomy for reading text.
  static const double heightTight = 1.3;
  static const double heightBody = 1.5;

  static const String bodyFamily = 'Inter';
  static const String displayFamily = 'Fraunces';

  /// Fraunces has no Cyrillic and no ʻ (Uzbek oʻ, gʻ): those glyphs fall
  /// back to Inter, so Russian headings render in Inter.
  static const List<String> displayFallback = ['Inter'];

  /// Numbers in tables and lists line up (Inter has tabular figures).
  static const List<FontFeature> tabular = [FontFeature.tabularFigures()];

  /// Display/heading style for [brand]: Fraunces 600 for the School,
  /// Inter 800 (the current look) for the Study Center.
  static TextStyle headline(
    IceBrand brand, {
    double size = display,
    Color? color,
  }) => brand.isSchool
      ? TextStyle(
          fontFamily: displayFamily,
          fontFamilyFallback: displayFallback,
          fontWeight: FontWeight.w600,
          fontSize: size,
          height: heightTight,
          letterSpacing: -0.01 * size,
          color: color,
        )
      : TextStyle(
          fontFamily: bodyFamily,
          fontWeight: FontWeight.w800,
          fontSize: size,
          height: heightTight,
          letterSpacing: -0.01 * size,
          color: color,
        );

  /// Inter text at one of the scale sizes.
  static TextStyle text({
    double size = body,
    FontWeight weight = FontWeight.w500,
    Color? color,
    bool numbers = false,
  }) => TextStyle(
    fontFamily: bodyFamily,
    fontSize: size,
    fontWeight: weight,
    height: size >= heading ? heightTight : heightBody,
    color: color,
    fontFeatures: numbers ? tabular : null,
  );
}

/// Spacing steps on a 4-point grid (plan 6.2: generous spacing).
abstract final class IceSpace {
  static const double xxs = 4;
  static const double xs = 8;
  static const double sm = 12;
  static const double md = 16;
  static const double lg = 20;
  static const double xl = 24;
  static const double xxl = 32;

  /// Left and right page padding on a phone.
  static const double gutter = md;

  /// Smallest tappable target (48 × 48 dp).
  static const double minTap = 48;
}
