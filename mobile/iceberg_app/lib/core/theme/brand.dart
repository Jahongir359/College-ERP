import 'package:flutter/material.dart';

import 'app_theme.dart';
import 'ice_tokens.dart';

/// Which Iceberg brand the app renders: the Learning Center (default) or the
/// School. The server decides it per user (`brand` in /auth/login/ and /me/);
/// users cannot pick it. See docs/plans/ICEBERG_SCHOOL_BRAND_PLAN.md (Phase 5).
enum IceBrand {
  center,
  school;

  /// Unknown or missing values fall back to the Learning Center.
  static IceBrand fromApi(String? value) =>
      value == 'school' ? IceBrand.school : IceBrand.center;

  bool get isSchool => this == IceBrand.school;

  String get appTitle => isSchool ? 'Iceberg School' : 'Iceberg Study Center';
  String get shortName => isSchool ? 'School' : 'Learning Center';

  /// Translation keys for the group noun: the School says "Class".
  /// Use with the strings provider: `s(brand.groupKey)`.
  String get groupKey => isSchool ? 'Class' : 'Group';
  String get myGroupKey => isSchool ? 'My Class' : 'My Group';
}

/// Iceberg School palette (docs/brand/iceberg-school/tokens.json).
class SchoolColors {
  static const primary = Color(0xFF4C0909); // maroon
  static const primaryHover = Color(0xFF7A1F1F); // brick
  static const primaryDeep = Color(0xFF2E0505);
  static const onPrimarySoft = Color(0xFFF2D9D6); // blush
  static const ink = Color(0xFFF2B8B0); // light rose — accents on dark surfaces
  static const tint = Color(0xFFF8F1F0);
  static const bg = Color(0xFFFBF7F6);
  static const border = Color(0xFFE8DCDA);
  static const text = Color(0xFF1F1515);
  static const muted = Color(0xFF5A4747);

  // Dark mode
  static const darkBg = Color(0xFF140808);
  static const darkSurface = Color(0xFF1D0E0E);
  static const darkSurface2 = Color(0xFF251212);
  static const darkBorder = Color(0xFF3A1E1E);
  static const darkText = Color(0xFFF4E9E7);
  static const darkMuted = Color(0xFFBFA5A2);
  static const darkFill = Color(0xFF8E2A2A);
}

/// Brand-aware replacements for the fixed Learning Center [IceColors]
/// brand colours. For the Learning Center they return exactly the old
/// constant, so existing screens look the same.
extension IceBrandColors on BuildContext {
  IceBrand get brand => ice.brand;

  /// Was `IceColors.navyDeep` — primary icons, text and highlights.
  Color get brandPrimary =>
      brand.isSchool ? SchoolColors.primary : IceColors.navyDeep;

  /// Was `IceColors.cyan` — secondary accents.
  Color get brandSecondary =>
      brand.isSchool ? SchoolColors.primaryHover : IceColors.cyan;

  /// Was `IceColors.navy` — darkest surfaces (rail, badges).
  Color get brandDeep => brand.isSchool ? SchoolColors.primaryDeep : IceColors.navy;

  /// Was `IceColors.lime` — bright highlight that sits on dark surfaces.
  Color get brandHighlight => brand.isSchool ? SchoolColors.ink : IceColors.lime;
}

/// The brand's app logo as a square tile. The Learning Center shows
/// `assets/images/logo.png` exactly as before; the School shows the white
/// crest on a maroon tile.
class IceBrandLogo extends StatelessWidget {
  const IceBrandLogo({
    super.key,
    required this.size,
    this.radius = 0,
    this.fit = BoxFit.contain,
    this.errorBuilder,
  });

  final double size;
  final double radius;
  final BoxFit fit;
  final ImageErrorWidgetBuilder? errorBuilder;

  static const centerAsset = 'assets/images/logo.png';
  static const schoolCrestAsset = 'assets/images/brand/school/crest-white.png';

  @override
  Widget build(BuildContext context) {
    if (!context.brand.isSchool) {
      return Image.asset(
        centerAsset,
        width: size,
        height: size,
        fit: fit,
        errorBuilder: errorBuilder,
      );
    }
    return Container(
      width: size,
      height: size,
      padding: EdgeInsets.all(size * 0.16),
      decoration: BoxDecoration(
        color: SchoolColors.primary,
        borderRadius: BorderRadius.circular(radius),
      ),
      child: Image.asset(
        schoolCrestAsset,
        fit: BoxFit.contain,
        errorBuilder: errorBuilder,
      ),
    );
  }
}
