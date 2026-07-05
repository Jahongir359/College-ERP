import 'package:flutter_test/flutter_test.dart';

import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/core/utils/formatters.dart';

void main() {
  group('formatters', () {
    test('fmtDate formats ISO dates and survives bad input', () {
      expect(fmtDate('2026-07-05'), '5 Jul 2026');
      expect(fmtDate(null), '—');
      expect(fmtDate(''), '—');
      expect(fmtDate('not-a-date'), 'not-a-date'); // must not throw
    });

    test('fmtPercent handles num, string and garbage', () {
      expect(fmtPercent(87.25), '87.3%');
      expect(fmtPercent('42'), '42.0%');
      expect(fmtPercent(null), '—');
      expect(fmtPercent('n/a'), '—');
    });

    test('fmtCurrency groups thousands and survives bad input', () {
      expect(fmtCurrency(1500000), '1,500,000');
      expect(fmtCurrency('2500'), '2,500');
      expect(fmtCurrency(null), '—');
      expect(fmtCurrency('oops'), '—');
    });
  });

  group('i18n', () {
    test('translates known keys per language', () {
      expect(const S('uz')('Dashboard'), 'Asosiy');
      expect(const S('ru')('All'), 'Все');
      expect(const S('ko')('All'), '전체');
      expect(const S('en')('Dashboard'), 'Dashboard');
    });

    test('falls back to the English key when a translation is missing', () {
      expect(const S('uz')('A key that does not exist'),
          'A key that does not exist');
      expect(const S('ru')('A key that does not exist'),
          'A key that does not exist');
    });
  });
}
