import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/core/settings/app_settings.dart';
import 'package:iceberg_app/core/update/app_update.dart';

/// Minimum app version gate (plan P4.12, app half).

Map<String, dynamic> _answer(
  String androidMin, {
  String url = 'https://play.google.com/x',
}) => {
  'min_app_version': '0.0.0',
  'android': {'min_app_version': androidMin, 'store_url': url},
  'ios': {'min_app_version': '0.0.0', 'store_url': ''},
};

Future<void> _pump(
  WidgetTester tester, {
  required Future<Map<String, dynamic>> Function() fetch,
  String current = '1.0.2',
  String? platform = 'android',
  String lang = 'en',
}) async {
  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        currentAppVersionProvider.overrideWith((ref) async => current),
        updatePlatformProvider.overrideWithValue(platform),
        appVersionFetcherProvider.overrideWithValue(fetch),
        stringsProvider.overrideWithValue(S(lang)),
      ],
      child: const MaterialApp(
        home: UpdateGate(child: Scaffold(body: Text('APP'))),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  group('version compare', () {
    test('parses dotted versions and ignores the build number', () {
      expect(parseVersion('1.0.2+3'), [1, 0, 2]);
      expect(parseVersion('2'), [2, 0, 0]);
      expect(parseVersion('1.x'), isNull);
      expect(parseVersion(''), isNull);
      expect(parseVersion('1.2.3.4'), isNull);
    });

    test('older only when both parse and current < minimum', () {
      expect(isOlderThan('1.0.2', '1.0.3'), isTrue);
      expect(isOlderThan('1.9.9', '2.0.0'), isTrue);
      expect(isOlderThan('1.0.2', '1.0.2'), isFalse);
      expect(isOlderThan('1.10.0', '1.9.0'), isFalse);
      expect(isOlderThan('1.0.2', 'garbage'), isFalse);
      expect(isOlderThan('1.0.2', '0.0.0'), isFalse);
    });
  });

  group('UpdateGate', () {
    testWidgets('older app shows the update screen with the store button', (
      tester,
    ) async {
      await _pump(tester, fetch: () async => _answer('1.1.0'));
      expect(find.text('APP'), findsNothing);
      expect(find.text('Update required'), findsOneWidget);
      expect(find.text('Update'), findsOneWidget);
    });

    testWidgets('update screen is in the user\'s language', (tester) async {
      await _pump(tester, lang: 'ru', fetch: () async => _answer('1.1.0'));
      expect(find.text('Требуется обновление'), findsOneWidget);
      expect(find.text('Обновить'), findsOneWidget);
    });

    testWidgets('no store link: update screen without a button', (
      tester,
    ) async {
      await _pump(tester, fetch: () async => _answer('1.1.0', url: ''));
      expect(find.text('Update required'), findsOneWidget);
      expect(find.byType(FilledButton), findsNothing);
    });

    testWidgets('equal or newer app opens normally', (tester) async {
      for (final min in ['1.0.2', '1.0.1', '0.0.0']) {
        await _pump(tester, fetch: () async => _answer(min));
        expect(find.text('APP'), findsOneWidget, reason: 'min $min');
        expect(find.text('Update required'), findsNothing);
      }
    });

    testWidgets('network error opens normally', (tester) async {
      await _pump(tester, fetch: () async => throw Exception('offline'));
      expect(find.text('APP'), findsOneWidget);
    });

    testWidgets('malformed answer opens normally', (tester) async {
      for (final data in <Map<String, dynamic>>[
        {},
        {'android': 'nope'},
        {
          'android': {'min_app_version': 5},
        },
        _answer('not-a-version'),
      ]) {
        await _pump(tester, fetch: () async => data);
        expect(find.text('APP'), findsOneWidget, reason: '$data');
      }
    });

    testWidgets('web and desktop never block', (tester) async {
      await _pump(tester, platform: null, fetch: () async => _answer('99.0.0'));
      expect(find.text('APP'), findsOneWidget);
    });

    testWidgets('app shows while the check is still running', (tester) async {
      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            currentAppVersionProvider.overrideWith((ref) async => '1.0.2'),
            updatePlatformProvider.overrideWithValue('android'),
            appVersionFetcherProvider.overrideWithValue(
              () => Future.delayed(
                const Duration(seconds: 5),
                () => _answer('0.0.0'),
              ),
            ),
          ],
          child: const MaterialApp(
            home: UpdateGate(child: Scaffold(body: Text('APP'))),
          ),
        ),
      );
      expect(find.text('APP'), findsOneWidget);
      await tester.pump(const Duration(seconds: 6));
    });
  });
}
