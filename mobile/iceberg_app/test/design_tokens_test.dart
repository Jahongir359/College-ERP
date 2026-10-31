import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:iceberg_app/core/auth/auth_state.dart';
import 'package:iceberg_app/core/router/app_router.dart';
import 'package:iceberg_app/core/theme/brand.dart';
import 'package:iceberg_app/core/theme/ice_tokens.dart';
import 'package:iceberg_app/core/theme/ice_type.dart';
import 'package:iceberg_app/features/debug/component_sheet_screen.dart';

/// WCAG contrast ratio between two opaque colours.
double _contrast(Color a, Color b) {
  final la = a.computeLuminance();
  final lb = b.computeLuminance();
  return (math.max(la, lb) + 0.05) / (math.min(la, lb) + 0.05);
}

void main() {
  group('PD.1 School tokens', () {
    test('gold highlight matches the mockups', () {
      expect(SchoolColors.gold, const Color(0xFFC9973F));
      expect(SchoolColors.goldInk, const Color(0xFF8A5A12));
      expect(SchoolColors.goldSoft, const Color(0xFFE9C77E));
    });

    test('gold matches docs/brand/iceberg-school/tokens.json', () {
      final json =
          jsonDecode(
                File(
                  '../../docs/brand/iceberg-school/tokens.json',
                ).readAsStringSync(),
              )
              as Map<String, dynamic>;
      final school = json['brands']['school'] as Map<String, dynamic>;
      Color hex(String v) => Color(int.parse('FF${v.substring(1)}', radix: 16));
      expect(hex(school['light']['gold']), SchoolColors.gold);
      expect(hex(school['light']['goldInk']), SchoolColors.goldInk);
      expect(hex(school['light']['goldSoft']), SchoolColors.goldSoft);
      expect(
        hex(school['dark']['goldInk']),
        IceTokens.dark(brand: IceBrand.school).highlightInk,
      );
    });

    test('School themes expose gold as the highlight', () {
      final light = IceTokens.light(brand: IceBrand.school);
      final dark = IceTokens.dark(brand: IceBrand.school);
      expect(light.highlight, SchoolColors.gold);
      expect(dark.highlight, SchoolColors.gold);
      expect(light.highlightInk, SchoolColors.goldInk);
      expect(dark.highlightInk, SchoolColors.goldSoft);
      expect(light.highlightSoft, SchoolColors.goldSoft);
    });

    test('gold text is readable; raw gold is not used as text on white', () {
      final light = IceTokens.light(brand: IceBrand.school);
      final dark = IceTokens.dark(brand: IceBrand.school);
      expect(_contrast(light.highlightInk, Colors.white), greaterThan(4.5));
      expect(_contrast(light.highlightInk, light.bg), greaterThan(4.5));
      expect(_contrast(dark.highlightInk, dark.card), greaterThan(4.5));
      expect(_contrast(dark.highlightInk, dark.bg), greaterThan(4.5));
      expect(_contrast(SchoolColors.gold, Colors.white), lessThan(4.5));
    });

    test('status pills are 4.5:1 or more in light and dark', () {
      const pairs = [
        (SchoolColors.present, SchoolColors.presentBg),
        (SchoolColors.late, SchoolColors.lateBg),
        (SchoolColors.absent, SchoolColors.absentBg),
        (SchoolColors.darkPresent, SchoolColors.darkPresentBg),
        (SchoolColors.darkLate, SchoolColors.darkLateBg),
        (SchoolColors.darkAbsent, SchoolColors.darkAbsentBg),
      ];
      for (final (fg, bg) in pairs) {
        expect(_contrast(fg, bg), greaterThanOrEqualTo(4.5), reason: '$fg');
      }
    });

    test('type scale, spacing and shapes follow plan 6.2', () {
      expect(
        [
          IceType.display,
          IceType.title,
          IceType.heading,
          IceType.body,
          IceType.label,
          IceType.caption,
        ],
        [28, 22, 18, 16, 14, 12],
      );
      expect(IceType.heightTight, inInclusiveRange(1.3, 1.5));
      expect(IceType.heightBody, inInclusiveRange(1.3, 1.5));
      expect(
        [
          IceSpace.xxs,
          IceSpace.xs,
          IceSpace.sm,
          IceSpace.md,
          IceSpace.lg,
          IceSpace.xl,
          IceSpace.xxl,
        ],
        [4, 8, 12, 16, 20, 24, 32],
      );
      expect(IceSpace.minTap, 48);
      expect([IceTokens.r, IceTokens.rSm, IceTokens.rLg], [24, 14, 32]);
    });

    test('display text: Fraunces 600 for School, Inter for Study Center', () {
      final school = IceType.headline(IceBrand.school);
      expect(school.fontFamily, 'Fraunces');
      expect(school.fontWeight, FontWeight.w600);
      expect(school.fontFamilyFallback, ['Inter']);
      expect(school.fontSize, IceType.display);
      final center = IceType.headline(IceBrand.center, size: IceType.title);
      expect(center.fontFamily, 'Inter');
      expect(center.fontSize, IceType.title);
    });

    test('Fraunces is bundled with its OFL licence and declared', () {
      expect(File('assets/fonts/Fraunces-SemiBold.ttf').existsSync(), isTrue);
      final licence = File('assets/fonts/Fraunces-OFL.txt').readAsStringSync();
      expect(licence, contains('SIL Open Font License'));
      final pubspec = File('pubspec.yaml').readAsStringSync();
      expect(pubspec, contains('family: Fraunces'));
      expect(pubspec, contains('assets/fonts/Fraunces-SemiBold.ttf'));
    });
  });

  group('PD.1 Study Center tokens unchanged', () {
    // Values from before PD.1; the Study Center must look exactly the same.
    test('light', () {
      final t = IceTokens.light();
      expect(t.brand, IceBrand.center);
      expect(t.bg, const Color(0xFFEDF3F9));
      expect(t.card, Colors.white);
      expect(t.cardHi, const Color(0xFF103A57));
      expect(t.cardLo, const Color(0xFF07233A));
      expect(t.inset, const Color(0xFFE6EEF7));
      expect(t.stroke, const Color(0xFFD2DFEC));
      expect(t.textHi, const Color(0xFF06223A));
      expect(t.textMid, const Color(0xFF4C6480));
      expect(t.textLow, const Color(0xFF8195AB));
      expect(t.accent, IceAccents.ice);
      expect(t.onAccent, const Color(0xFF052033));
      expect(t.mint, const Color(0xFF0E6486));
      expect(t.coral, const Color(0xFFD64C3D));
      expect(t.sky, const Color(0xFF2487B5));
      expect(t.amber, const Color(0xFFC98A12));
      // No separate highlight: it stays the accent.
      expect(t.highlight, t.accent);
      expect(t.highlightInk, t.accentInk);
      expect(t.highlightSoft, t.accentSoft);
    });

    test('dark', () {
      final t = IceTokens.dark();
      expect(t.bg, const Color(0xFF071520));
      expect(t.card, const Color(0xFF0E2233));
      expect(t.cardHi, const Color(0xFF143A57));
      expect(t.cardLo, const Color(0xFF0A1F31));
      expect(t.inset, const Color(0xFF122B40));
      expect(t.stroke, const Color(0xFF1E3C57));
      expect(t.textHi, const Color(0xFFF0F6FC));
      expect(t.textMid, const Color(0xFF9FB7D0));
      expect(t.textLow, const Color(0xFF607890));
      expect(t.accent, IceAccents.ice);
      expect(t.accentInk, IceAccents.ice);
      expect(t.onAccent, const Color(0xFF052033));
      expect(t.mint, const Color(0xFFAFD9F2));
      expect(t.coral, const Color(0xFFF2917F));
      expect(t.sky, const Color(0xFF93D2EC));
      expect(t.amber, const Color(0xFFF4C95D));
      expect(t.highlight, t.accent);
    });

    test('body font stays Inter for both brands', () {
      for (final brand in IceBrand.values) {
        final theme = buildIceTheme(
          dark: false,
          accent: IceAccents.ice,
          brand: brand,
        );
        expect(theme.textTheme.bodyMedium!.fontFamily, 'Inter');
      }
    });
  });

  group('component sheet', () {
    for (final school in [true, false]) {
      for (final dark in [false, true]) {
        testWidgets('renders (school: $school, dark: $dark)', (tester) async {
          tester.view.physicalSize = const Size(390, 6000);
          tester.view.devicePixelRatio = 1;
          addTearDown(tester.view.reset);
          await tester.pumpWidget(
            MaterialApp(
              home: ComponentSheetScreen(school: school, dark: dark),
            ),
          );
          await tester.pump();
          expect(tester.takeException(), isNull);
          expect(find.text('Xayrli tong, Dilnoza'), findsOneWidget);
          expect(find.text('Keldi 08:12'), findsOneWidget);
          expect(find.text('No internet connection'), findsOneWidget);
          final title = tester.widget<Text>(find.text('Xayrli tong, Dilnoza'));
          expect(title.style!.fontFamily, school ? 'Fraunces' : 'Inter');
        });
      }
    }
  });

  group('component sheet route is debug-only', () {
    IceUser user(String type) => IceUser(
      id: 1,
      email: 'u@example.com',
      loginId: 'U1',
      firstName: 'Test',
      lastName: 'User',
      userType: type,
      brand: 'school',
    );
    final auths = {
      'signed out': AuthState.unauth(),
      'teacher': AuthState.auth(user('2')),
      'parent': AuthState.auth(user('4')),
      'admin': AuthState.auth(user('1')),
    };

    test('the guard is the compile-time kDebugMode', () {
      // Release and profile builds compile with kDebugMode == false, which is
      // the `debug: false` case below.
      expect(kDebugMode, isTrue, reason: 'tests run in debug mode');
    });

    test('release: no route, and the path gets the normal role redirect', () {
      expect(debugRoutes(debug: false), isEmpty);
      auths.forEach((name, auth) {
        expect(
          appRedirect(auth, componentSheetPath, debug: false),
          roleRedirect(auth, componentSheetPath),
          reason: name,
        );
        expect(
          appRedirect(auth, componentSheetPath, debug: false),
          isNotNull,
          reason: name,
        );
      });
    });

    test('debug: the route exists and opens for anyone', () {
      final routes = debugRoutes(debug: true);
      expect(routes, hasLength(1));
      expect((routes.single as GoRoute).path, componentSheetPath);
      auths.forEach((name, auth) {
        expect(appRedirect(auth, componentSheetPath, debug: true), isNull);
      });
    });

    test('every other path behaves exactly like roleRedirect', () {
      for (final debug in [true, false]) {
        auths.forEach((name, auth) {
          for (final path in ['/login', '/student/home', '/staff/home']) {
            expect(
              appRedirect(auth, path, debug: debug),
              roleRedirect(auth, path),
              reason: '$name $path',
            );
          }
        });
      }
    });
  });
}
