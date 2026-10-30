import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/core/settings/app_settings.dart';
import 'package:iceberg_app/core/theme/brand.dart';
import 'package:iceberg_app/core/theme/ice_tokens.dart';
import 'package:iceberg_app/features/staff/screens/register/register_screen.dart';

final _day = DateTime(2026, 10, 29); // a Thursday

Map<String, dynamic> _register({bool canEdit = true}) => {
      'class': {'id': 7, 'name': '3-A'},
      'date': '2026-10-29',
      'taken': false,
      'taken_at': null,
      'can_edit': canEdit,
      'students': [
        {
          'student_id': 1,
          'name': 'Aliyev Bekzod',
          'initials': 'AB',
          'status': 'present',
          'arrival_time': null,
          'note': '',
          'saved': false,
        },
        {
          'student_id': 2,
          'name': 'Karimov Aziz',
          'initials': 'KA',
          'status': 'present',
          'arrival_time': null,
          'note': '',
          'saved': false,
        },
      ],
    };

Widget _app(Map<String, dynamic> data, {String lang = 'en'}) => ProviderScope(
      overrides: [
        registerProvider('7|2026-10-29').overrideWith((_) async => data),
        stringsProvider.overrideWithValue(S(lang)),
      ],
      child: MaterialApp(
        theme: buildIceTheme(
          dark: false,
          accent: IceAccents.ice,
          brand: IceBrand.school,
        ),
        home: StaffRegisterScreen(classId: 7, day: _day),
      ),
    );

/// Lets pending animation timers finish before the test ends.
Future<void> _finish(WidgetTester tester) async {
  await tester.pump(const Duration(seconds: 10));
  await tester.pumpWidget(const SizedBox());
  await tester.pump(const Duration(seconds: 10));
}

void main() {
  group('registerDayTitle', () {
    test('weekday and month in the app language', () {
      expect(registerDayTitle(const S('en'), _day), 'Thursday, 29 October');
      expect(registerDayTitle(const S('uz'), _day), 'Payshanba, 29-oktabr');
      expect(registerDayTitle(const S('ru'), _day), 'Четверг, 29 октября');
    });
  });

  group('register screen', () {
    testWidgets('everyone starts present; tapping absent updates the counts',
        (tester) async {
      await tester.pumpWidget(_app(_register()));
      await tester.pumpAndSettle();

      expect(find.text('2 present'), findsOneWidget);
      expect(find.text('0 absent'), findsOneWidget);
      expect(find.text('Save · 2 pupils'), findsOneWidget);

      await tester.tap(find.byIcon(Icons.close_rounded).first);
      await tester.pumpAndSettle();
      expect(find.text('1 present'), findsOneWidget);
      expect(find.text('1 absent'), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('late opens the arrival sheet and shows the time',
        (tester) async {
      await tester.pumpWidget(_app(_register()));
      await tester.pumpAndSettle();

      await tester.tap(find.byIcon(Icons.schedule_rounded).first);
      await tester.pumpAndSettle();
      expect(find.text('Late — when did they arrive?'), findsOneWidget);

      await tester.tap(find.text('Done'));
      await tester.pumpAndSettle();
      expect(find.text('1 late'), findsOneWidget);
      expect(find.textContaining('Arrived '), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('read-only for other teachers: no save button, no changes',
        (tester) async {
      await tester.pumpWidget(_app(_register(canEdit: false)));
      await tester.pumpAndSettle();

      expect(find.textContaining('Save ·'), findsNothing);
      expect(
        find.text('Only the homeroom teacher can change this register.'),
        findsOneWidget,
      );
      await tester.tap(find.byIcon(Icons.close_rounded).first);
      await tester.pumpAndSettle();
      expect(find.text('0 absent'), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('Uzbek labels', (tester) async {
      await tester.pumpWidget(_app(_register(), lang: 'uz'));
      await tester.pumpAndSettle();
      expect(find.text('Davomat · 3-A'), findsOneWidget);
      expect(find.text('2 keldi'), findsOneWidget);
      expect(find.text('Saqlash · 2 oʻquvchi'), findsOneWidget);
      await _finish(tester);
    });
  });
}
