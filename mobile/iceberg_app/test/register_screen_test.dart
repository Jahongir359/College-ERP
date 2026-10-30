import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/core/settings/app_settings.dart';
import 'package:iceberg_app/core/theme/brand.dart';
import 'package:iceberg_app/core/theme/ice_tokens.dart';
import 'package:iceberg_app/features/staff/screens/register/register_screen.dart';
import 'package:iceberg_app/shared/widgets/ice_kit.dart';

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

Widget _app(
  Map<String, dynamic>? data, {
  String lang = 'en',
  RegisterSaver? saver,
  Object? loadError,
}) =>
    ProviderScope(
      overrides: [
        registerProvider('7|2026-10-29').overrideWith((_) async {
          if (loadError != null) throw loadError;
          return data!;
        }),
        stringsProvider.overrideWithValue(S(lang)),
        if (saver != null) registerSaverProvider.overrideWithValue(saver),
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

Widget _home(List<Map<String, dynamic>> classes, IceBrand brand) =>
    ProviderScope(
      overrides: [
        myRegistersProvider.overrideWith((_) async => classes),
        stringsProvider.overrideWithValue(const S('en')),
      ],
      child: MaterialApp(
        theme: buildIceTheme(dark: false, accent: IceAccents.ice, brand: brand),
        home: const Scaffold(body: RegisterReminder()),
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
    testWidgets('save sends only the changed pupils', (tester) async {
      List<Map<String, dynamic>>? sent;
      String? sentDay;
      await tester.pumpWidget(_app(
        _register(),
        saver: (id, day, records) async {
          sentDay = day;
          sent = records;
        },
      ));
      await tester.pumpAndSettle();

      await tester.tap(find.byIcon(Icons.close_rounded).last);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Save · 2 pupils'));
      await tester.pumpAndSettle();

      expect(sentDay, '2026-10-29');
      expect(sent, [
        {'student_id': 2, 'status': 'absent', 'note': ''},
      ]);
      expect(find.text('Register saved'), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('a failed save says it was not saved and keeps the marks',
        (tester) async {
      await tester.pumpWidget(_app(
        _register(),
        saver: (_, __, ___) async => throw Exception('no network'),
      ));
      await tester.pumpAndSettle();

      await tester.tap(find.byIcon(Icons.close_rounded).first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Save · 2 pupils'));
      await tester.pumpAndSettle();

      expect(
        find.text('Could not save the register. Try again.'),
        findsOneWidget,
      );
      expect(find.text('1 absent'), findsOneWidget);
      expect(find.text('Save · 2 pupils'), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('load error shows a translated retry', (tester) async {
      await tester.pumpWidget(
        _app(null, lang: 'ru', loadError: Exception('offline')),
      );
      await tester.pumpAndSettle();
      expect(find.text('Не удалось загрузить журнал'), findsOneWidget);
      expect(find.text('Повторить'), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('a class with no pupils shows the empty state, no save',
        (tester) async {
      await tester.pumpWidget(_app({..._register(), 'students': []}));
      await tester.pumpAndSettle();
      expect(find.text('No students enrolled yet'), findsOneWidget);
      expect(find.textContaining('Save ·'), findsNothing);
      await _finish(tester);
    });
  });

  group('home reminder', () {
    final todo = {
      'id': 7,
      'name': '3-A',
      'pupils': 2,
      'can_edit': true,
      'taken': false,
      'present': 0,
      'late': 0,
      'absent': 0,
    };

    testWidgets('School homeroom teacher sees "not taken yet"',
        (tester) async {
      await tester.pumpWidget(_home([todo], IceBrand.school));
      await tester.pumpAndSettle();
      expect(find.text('3-A register not taken yet'), findsOneWidget);
      expect(find.text('Take the register'), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('taken register shows the counts', (tester) async {
      await tester.pumpWidget(_home([
        {...todo, 'taken': true, 'present': 1, 'absent': 1},
      ], IceBrand.school));
      await tester.pumpAndSettle();
      expect(find.text('3-A register taken'), findsOneWidget);
      expect(find.text('1 present · 0 late · 1 absent'), findsOneWidget);
      await _finish(tester);
    });

    testWidgets('Study Center teachers see nothing', (tester) async {
      await tester.pumpWidget(_home([todo], IceBrand.center));
      await tester.pumpAndSettle();
      expect(find.textContaining('register'), findsNothing);
      expect(find.byType(IceButton), findsNothing);
      await _finish(tester);
    });

    testWidgets('teachers without a homeroom class see nothing',
        (tester) async {
      await tester.pumpWidget(_home([], IceBrand.school));
      await tester.pumpAndSettle();
      expect(find.byType(IceButton), findsNothing);
      await _finish(tester);
    });
  });
}
