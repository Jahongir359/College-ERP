import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:iceberg_app/core/auth/auth_state.dart';
import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/features/parent/parent_data.dart';
import 'package:iceberg_app/features/parent/parent_format.dart';
import 'package:iceberg_app/features/parent/parent_home_screen.dart';
import 'package:iceberg_app/features/parent/parent_shell.dart';
import 'package:iceberg_app/features/student/screens/student_shell.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Thursday 29 October 2026, 09:00 — during lesson 2.
final _now = DateTime(2026, 10, 29, 9, 0);

typedef _Handler = (int, Object) Function(RequestOptions);

class _FakeServer implements HttpClientAdapter {
  _FakeServer(this.handler);

  final _Handler handler;
  final calls = <String>[];

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    calls.add('${options.path}?${options.queryParameters['student'] ?? ''}');
    final (status, body) = handler(options);
    return ResponseBody.fromString(
      jsonEncode(body),
      status,
      headers: {
        Headers.contentTypeHeader: [Headers.jsonContentType],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

Map<String, Object?> _lesson(int n, String subject, String start, String end) =>
    {
      'subject_name': subject,
      'room': '12',
      'period': {'number': n, 'start_time': '$start:00', 'end_time': '$end:00'},
    };

final _week = {
  'days': [
    {
      'date': '2026-10-29',
      'lessons': [
        _lesson(2, 'Mathematics', '08:55', '09:40'),
        _lesson(1, 'English', '08:00', '08:45'),
        _lesson(3, 'Mother tongue', '09:50', '10:35'),
      ],
    },
  ],
};

/// A school day for child 1 (Aziza); child 2 (Bobur) has nothing marked.
(int, Object) _school(RequestOptions o) {
  final child = o.queryParameters['student'];
  return switch (o.path) {
    '/attendance/' when child == 1 => (
      200,
      {
        'results': [
          {'date': '2026-10-29', 'status': 1, 'arrival_time': '07:52'},
          {'date': '2026-10-28', 'status': 0},
        ],
      },
    ),
    '/attendance/' => (200, {'results': []}),
    '/school/timetable/' => (200, child == 1 ? _week : {'days': []}),
    '/assignments/' => (
      200,
      {
        'results': [
          {'title': 'Read pages 10-12', 'due_date': '2026-10-30'},
          {'title': 'Exercise 4', 'due_date': '2026-11-02'},
          {'title': 'Old essay', 'due_date': '2026-10-20'},
        ],
      },
    ),
    '/invoices/' => (
      200,
      {
        'results': [
          {
            'period': '2026-11-01',
            'amount_due': '450000.00',
            'due_date': '2026-11-05',
            'status': 'due',
            'is_overdue': false,
          },
          {'period': '2026-10-01', 'amount_due': '0.00', 'status': 'paid'},
        ],
      },
    ),
    '/messages/parent/' => (
      200,
      {
        'threads': [
          {
            'teacher': {'name': 'Dilnoza Rahimova'},
            'last_message': 'Bring sports clothes tomorrow',
            'unread_count': 1,
          },
        ],
      },
    ),
    '/notifications/' when o.queryParameters['unread'] == '1' => (
      200,
      {'count': 2, 'results': []},
    ),
    '/notifications/' => (
      200,
      {
        'results': [
          {
            'message': 'Parents meeting\nSaturday, 31 Oct · 10:00 · room 12',
            'created_at': '2026-10-27T08:00:00Z',
          },
        ],
      },
    ),
    _ => (404, {'detail': 'Not found.'}),
  };
}

IceUser _parent({List<Map<String, Object?>>? children}) => IceUser.fromJson({
  'id': 9,
  'first_name': 'Malika',
  'last_name': 'Karimova',
  'user_type': '4',
  'brand': 'school',
  'login_id': 'PR500',
  'children':
      children ??
      [
        {
          'id': 1,
          'name': 'Aziza Karimova',
          'class': {'id': 3, 'name': '3-A'},
          'brand': 'school',
        },
        {
          'id': 2,
          'name': 'Bobur Karimov',
          'class': {'id': 7, 'name': '7-B'},
          'brand': 'school',
        },
      ],
});

ProviderContainer _container(_FakeServer server, IceUser user) {
  final dio = Dio(BaseOptions(baseUrl: 'http://test/api/v1'))
    ..httpClientAdapter = server;
  final c = ProviderContainer(
    overrides: [
      authProvider.overrideWith(
        (_) => AuthNotifier.withState(AuthState.auth(user), dio: dio),
      ),
      parentDioProvider.overrideWithValue(dio),
      parentClockProvider.overrideWithValue(() => _now),
    ],
  );
  addTearDown(c.dispose);
  return c;
}

Future<void> _pumpHome(
  WidgetTester tester,
  ProviderContainer c, {
  Size size = const Size(390, 844),
}) async {
  tester.view.physicalSize = size * 3;
  tester.view.devicePixelRatio = 3;
  addTearDown(tester.view.reset);
  await tester.pumpWidget(
    UncontrolledProviderScope(
      container: c,
      child: const MaterialApp(
        home: StudentThemeScope(child: Scaffold(body: ParentHomeScreen())),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({'ice_lang': 'en'});
    FlutterSecureStorage.setMockInitialValues({});
  });

  group('today, worked out from the API', () {
    test('arrival', () {
      final a = todayAttendance(
        _school(
          RequestOptions(path: '/attendance/', queryParameters: {'student': 1}),
        ).$2,
        _now,
      );
      expect((a.status, a.arrivalTime), (ArrivalStatus.present, '07:52'));
      final late = todayAttendance({
        'results': [
          {'date': '2026-10-29', 'status': 2, 'arrival_time': '08:20'},
        ],
      }, _now);
      expect(late.status, ArrivalStatus.late);
      final absent = todayAttendance({
        'results': [
          {'date': '2026-10-29', 'status': 0},
        ],
      }, _now);
      expect(absent.status, ArrivalStatus.absent);
      // Yesterday's mark is not today's.
      final none = todayAttendance({
        'results': [
          {'date': '2026-10-28', 'status': 1},
        ],
      }, _now);
      expect(none.status, ArrivalStatus.notMarked);
    });

    test('the lesson on now, next, between and after school', () {
      TodayLessons at(int h, int m) =>
          todayLessons(_week, DateTime(2026, 10, 29, h, m));
      final now = at(9, 0);
      expect(now.phase, LessonPhase.now);
      expect(now.main!.subject, 'Mathematics');
      expect(now.after!.subject, 'Mother tongue');
      expect(at(7, 30).phase, LessonPhase.before);
      expect(at(7, 30).main!.subject, 'English');
      expect(at(9, 45).phase, LessonPhase.between);
      expect(at(9, 45).main!.subject, 'Mother tongue');
      expect(at(11, 0).phase, LessonPhase.done);
      expect(
        todayLessons(_week, DateTime(2026, 10, 30, 9)).phase,
        LessonPhase.none,
      );
    });

    test('homework due skips past work; the oldest unpaid month wins', () {
      final hw = homeworkDue(
        _school(RequestOptions(path: '/assignments/')).$2,
        _now,
      );
      expect(hw.count, 2);
      expect(hw.nextDue, DateTime(2026, 10, 30));
      final inv = unpaidInvoice(
        _school(RequestOptions(path: '/invoices/')).$2,
      )!;
      expect(inv.period, DateTime(2026, 11, 1));
      expect(inv.amountDue, '450000.00');
      expect(unpaidInvoice({'results': []}), isNull);
      expect(
        unpaidInvoice({
          'results': [
            {
              'period': '2026-09-01',
              'amount_due': '10.00',
              'status': 'cancelled',
            },
          ],
        }),
        isNull,
      );
    });

    test('unread teacher message and recent announcement', () {
      final m = unreadMessage(
        _school(RequestOptions(path: '/messages/parent/')).$2,
      )!;
      expect((m.teacher, m.unread), ('Dilnoza Rahimova', 1));
      expect(
        unreadMessage({
          'threads': [
            {
              'teacher': {'name': 'X'},
              'unread_count': 0,
            },
          ],
        }),
        isNull,
      );
      final old = latestAnnouncement({
        'results': [
          {'message': 'Old', 'created_at': '2026-09-01T08:00:00Z'},
        ],
      }, _now);
      expect(old, isNull);
    });

    test('children come from me/ with their class', () {
      final kids = _parent().children;
      expect(kids.map((k) => (k.id, k.className, k.initials)), [
        (1, '3-A', 'AK'),
        (2, '7-B', 'BK'),
      ]);
      final again = IceUser.fromJson(_parent().toJson()).children;
      expect(again.first.className, '3-A');
      expect(
        ParentChildInfo.fromJson({
          'id': 4,
          'name': 'Ali',
          'class': null,
        }).className,
        '',
      );
    });

    test('dates and sums read naturally', () {
      expect(weekdayDate('uz', _now), 'Payshanba, 29-okt');
      expect(weekdayDate('ru', _now), 'четверг, 29 окт');
      expect(monthName('uz', DateTime(2026, 11)), 'Noyabr');
      expect(groupedAmount('450000.00'), '450 000');
      expect(groupedAmount('1250.50'), '1 250,50');
    });
  });

  group('ParentHomeScreen', () {
    testWidgets('shows today for the first child', (tester) async {
      final server = _FakeServer(_school);
      final c = _container(server, _parent());
      await _pumpHome(tester, c);

      expect(find.text('Good Morning!'), findsOneWidget);
      expect(find.text('Aziza · 3-A'), findsOneWidget);
      expect(find.text('Bobur · 7-B'), findsOneWidget);
      expect(find.text('TODAY · THURSDAY, 29 OCT'), findsOneWidget);
      expect(find.text('Arrived 07:52'), findsOneWidget);
      expect(find.text('Marked by the homeroom teacher'), findsOneWidget);
      expect(find.text('Now · Lesson 2, 08:55–09:40'), findsOneWidget);
      expect(find.text('Mathematics'), findsOneWidget);
      expect(find.text('Then: Mother tongue · 09:50'), findsOneWidget);
      expect(find.text('2'), findsOneWidget);
      expect(find.text('homework due · tomorrow'), findsOneWidget);
      expect(find.text('November'), findsOneWidget);
      expect(find.text('450 000 soum'), findsOneWidget);
      expect(find.text('Due 5 Nov'), findsOneWidget);
      expect(find.text('Dilnoza Rahimova'), findsOneWidget);
      await tester.ensureVisible(
        find.byKey(const ValueKey('announcement-card')),
      );
      await tester.pumpAndSettle();
      expect(find.text('ANNOUNCEMENT · 3-A'), findsOneWidget);
      expect(find.text('Parents meeting'), findsOneWidget);
      expect(server.calls, contains('/assignments/?1'));
    });

    testWidgets('the child switcher loads the other child and is remembered', (
      tester,
    ) async {
      final server = _FakeServer(_school);
      final c = _container(server, _parent());
      await _pumpHome(tester, c);

      final chip = find.byKey(const ValueKey('child-chip-2'));
      // The chip row scrolls sideways; tap the part that is on screen.
      await tester.tapAt(tester.getTopLeft(chip) + const Offset(24, 20));
      await tester.pumpAndSettle();
      expect(c.read(selectedChildProvider)!.id, 2);
      expect(server.calls, contains('/attendance/?2'));
      expect(find.text('Not marked yet'), findsOneWidget);
      expect(find.text('No lessons today'), findsOneWidget);
      expect(find.text('Arrived 07:52'), findsNothing);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getInt('cache_parent_child'), 2);
    });

    testWidgets('one failing request leaves the rest of Home working', (
      tester,
    ) async {
      final server = _FakeServer(
        (o) => o.path == '/school/timetable/'
            ? (500, {'detail': 'boom'})
            : _school(o),
      );
      final c = _container(server, _parent());
      await _pumpHome(tester, c);
      expect(find.text('Arrived 07:52'), findsOneWidget);
      expect(find.text('Could not load'), findsOneWidget);
      expect(find.byKey(const ValueKey('payment-tile')), findsOneWidget);
    });

    testWidgets('offline: one error card with a retry', (tester) async {
      var down = true;
      final server = _FakeServer(
        (o) => down ? (503, {'detail': 'down'}) : _school(o),
      );
      final c = _container(server, _parent());
      await _pumpHome(tester, c);
      expect(find.byKey(const ValueKey('load-error')), findsOneWidget);
      expect(find.byKey(const ValueKey('today-card')), findsNothing);

      down = false;
      await tester.tap(find.text('Try again'));
      await tester.pumpAndSettle();
      expect(find.text('Arrived 07:52'), findsOneWidget);
    });

    testWidgets('a parent with no linked children is told what to do', (
      tester,
    ) async {
      final server = _FakeServer(_school);
      final c = _container(server, _parent(children: []));
      await _pumpHome(tester, c);
      expect(find.byKey(const ValueKey('no-children')), findsOneWidget);
      expect(server.calls.where((x) => x.startsWith('/attendance/')), isEmpty);
    });

    testWidgets('in Uzbek', (tester) async {
      SharedPreferences.setMockInitialValues({'ice_lang': 'uz'});
      final c = _container(_FakeServer(_school), _parent());
      await _pumpHome(tester, c);
      expect(find.text('Xayrli tong!'), findsOneWidget);
      expect(find.text('BUGUN · PAYSHANBA, 29-OKT'), findsOneWidget);
      expect(find.text('Keldi 07:52'), findsOneWidget);
      expect(find.text('Hozir · 2-dars, 08:55–09:40'), findsOneWidget);
      expect(find.text('ta vazifa · ertaga'), findsOneWidget);
      expect(find.text('450 000 soʻm'), findsOneWidget);
    });

    testWidgets('on a laptop the column stays phone-width', (tester) async {
      final c = _container(_FakeServer(_school), _parent());
      await _pumpHome(tester, c, size: const Size(1366, 900));
      final card = tester.getSize(find.byKey(const ValueKey('today-card')));
      expect(card.width, lessThanOrEqualTo(ParentHomeScreen.maxWidth));
      expect(tester.takeException(), isNull);
    });
  });

  testWidgets('parent tabs: Home, coming-soon tabs and Profile with log out', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1170, 2532);
    tester.view.devicePixelRatio = 3;
    addTearDown(tester.view.reset);
    final server = _FakeServer(
      (o) => o.path == '/auth/logout/' ? (200, <String, Object>{}) : _school(o),
    );
    final c = _container(server, _parent());
    final router = GoRouter(
      initialLocation: '/parent/home',
      routes: [
        GoRoute(path: '/login', builder: (_, __) => const Text('login')),
        StatefulShellRoute.indexedStack(
          builder: (_, __, shell) => ParentShell(navigationShell: shell),
          branches: [
            for (final (path, page) in [
              ('/parent/home', const ParentHomeScreen()),
              (
                '/parent/timetable',
                const ParentSoonTab(
                  title: 'Timetable',
                  icon: Icons.calendar_today,
                ),
              ),
              (
                '/parent/homework',
                const ParentSoonTab(title: 'Homework', icon: Icons.menu_book),
              ),
              (
                '/parent/messages',
                const ParentSoonTab(title: 'Messages', icon: Icons.chat),
              ),
              ('/parent/profile', const ParentProfileTab()),
            ])
              StatefulShellBranch(
                routes: [GoRoute(path: path, builder: (_, __) => page)],
              ),
          ],
        ),
      ],
    );
    await tester.pumpWidget(
      UncontrolledProviderScope(
        container: c,
        child: MaterialApp.router(routerConfig: router),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('today-card')), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('parent-tab-1')));
    await tester.pumpAndSettle();
    expect(find.text('This section comes in the next update.'), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('soon-home')));
    await tester.pumpAndSettle();
    expect(find.byKey(const ValueKey('today-card')), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('parent-tab-4')));
    await tester.pumpAndSettle();
    expect(find.text('Malika Karimova'), findsOneWidget);
    expect(find.text('Bobur Karimov'), findsOneWidget);
    await tester.ensureVisible(find.byKey(const ValueKey('parent-logout')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('parent-logout')));
    await tester.pumpAndSettle();
    expect(c.read(authProvider).status, AuthStatus.unauthenticated);
  });

  test('every new parent string exists in uz, ru and ko', () {
    const keys = [
      'Arrived',
      'Not marked yet',
      'Marked by the homeroom teacher',
      'Lesson {n}',
      'Lessons are over for today',
      'No lessons today',
      'homework due',
      'Nothing to pay',
      'soum',
      'This section comes in the next update.',
      'No children are linked to your account yet.',
    ];
    for (final lang in ['uz', 'ru', 'ko']) {
      for (final k in keys) {
        expect(S(lang)(k), isNot(k), reason: '$lang: $k');
      }
    }
    expect(S('uz')('soum'), contains('ʻ'));
  });
}
