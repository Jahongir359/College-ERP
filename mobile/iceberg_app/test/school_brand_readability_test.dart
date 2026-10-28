import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/core/theme/brand.dart';
import 'package:iceberg_app/core/theme/ice_tokens.dart';
import 'package:iceberg_app/core/utils/formatters.dart';

/// WCAG contrast ratio between two opaque colours.
double _contrast(Color a, Color b) {
  final la = a.computeLuminance();
  final lb = b.computeLuminance();
  return (math.max(la, lb) + 0.05) / (math.min(la, lb) + 0.05);
}

void main() {
  group('hero card tokens (P4.13)', () {
    final themes = {
      'School light': IceTokens.light(brand: IceBrand.school),
      'School dark': IceTokens.dark(brand: IceBrand.school),
    };

    themes.forEach((name, t) {
      test('$name: accent text on the hero is 4.5:1 or more', () {
        final hero = t.onHero;
        for (final surface in [t.cardHi, t.cardLo]) {
          expect(_contrast(hero.accent, surface), greaterThanOrEqualTo(4.5));
          expect(_contrast(hero.mint, surface), greaterThanOrEqualTo(4.5));
        }
      });
    });

    test('School light swaps the maroon accent on the hero only', () {
      final t = IceTokens.light(brand: IceBrand.school);
      expect(t.accent, SchoolColors.primary);
      expect(t.onHero.accent, SchoolColors.ink);
      expect(t.onHero.onAccent, SchoolColors.primaryDeep);
    });

    test('Learning Center and a picked accent keep the same tokens', () {
      for (final t in [
        IceTokens.light(),
        IceTokens.dark(),
        IceTokens.light(brand: IceBrand.school, accent: IceAccents.lime),
        IceTokens.dark(brand: IceBrand.school),
      ]) {
        expect(identical(t.onHero, t), isTrue);
      }
    });
  });

  group('teacher class list wording', () {
    test('School says classes, the Learning Center keeps groups', () {
      expect(IceBrand.school.teacherGroupsKey, 'Classes');
      expect(IceBrand.center.teacherGroupsKey, 'My Classes');
      expect(const S('uz')(IceBrand.school.teacherGroupsKey), 'Sinflar');
      expect(const S('ru')(IceBrand.school.teacherGroupsKey), 'Классы');
    });
  });

  group('strings added for the School brand pass', () {
    const keys = [
      'Overall rate',
      'No attendance recorded yet.',
      'Days streak',
      'Missed total',
      'Tuition Balance',
      'All paid',
      'Classes you teach',
      'The parent app is still under construction.',
      'Due {date}',
      'Due in {n} days',
    ];

    for (final lang in ['uz', 'ru']) {
      test('$lang has every key', () {
        for (final key in keys) {
          expect(S(lang)(key), isNot(key), reason: '$lang: $key');
        }
      });
    }

    test('templates keep their placeholder', () {
      for (final lang in ['uz', 'ru', 'ko']) {
        expect(S(lang)('Due {date}'), contains('{date}'));
        expect(S(lang)('Due in {n} days'), contains('{n}'));
      }
    });
  });

  group('roomLabel', () {
    test('adds the word only when the room name lacks it', () {
      expect(roomLabel(const S('en'), '12'), 'Room 12');
      expect(roomLabel(const S('uz'), '12'), 'Xona 12');
      expect(roomLabel(const S('uz'), 'Xona 1A'), 'Xona 1A');
      expect(roomLabel(const S('ru'), 'Room 5'), 'Room 5');
    });
  });
}
