import 'dart:convert';
import 'dart:typed_data';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:iceberg_app/core/api/api_client.dart';
import 'package:iceberg_app/core/auth/auth_state.dart';
import 'package:iceberg_app/core/router/app_router.dart';
import 'package:iceberg_app/features/auth/screens/change_password_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Answers requests from a table of `'METHOD /path'` → (status, body).
class _FakeServer implements HttpClientAdapter {
  _FakeServer(this.routes);

  final Map<String, (int, Object)> routes;
  final calls = <String>[];
  final bodies = <String, Object?>{};

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    final key = '${options.method} ${options.path}';
    calls.add(key);
    bodies[key] = options.data;
    final (status, body) = routes[key] ?? (404, {'detail': 'Not found.'});
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

Map<String, Object?> _userJson({bool mustChange = true, String type = '4'}) => {
  'id': 5,
  'first_name': 'Dilnoza',
  'user_type': type,
  'brand': 'school',
  'must_change_password': mustChange,
};

IceUser _user({bool mustChange = true, String type = '4'}) =>
    IceUser.fromJson(_userJson(mustChange: mustChange, type: type));

Dio _dio(_FakeServer server) =>
    Dio(BaseOptions(baseUrl: 'http://test/api/v1'))..httpClientAdapter = server;

/// The real redirect rules with a home stub and the password screen.
Widget _app(ProviderContainer c) {
  final refresh = ValueNotifier(0);
  c.listen(authProvider, (_, __) => refresh.value++);
  final router = GoRouter(
    initialLocation: '/student/home',
    refreshListenable: refresh,
    redirect: (_, state) =>
        roleRedirect(c.read(authProvider), state.matchedLocation),
    routes: [
      GoRoute(path: '/student/home', builder: (_, __) => const Text('home')),
      GoRoute(path: '/parent/home', builder: (_, __) => const Text('home')),
      GoRoute(path: '/login', builder: (_, __) => const Text('login')),
      GoRoute(
        path: '/change-password',
        builder: (_, __) => const ChangePasswordScreen(),
      ),
    ],
  );
  return UncontrolledProviderScope(
    container: c,
    child: MaterialApp.router(routerConfig: router),
  );
}

Future<ProviderContainer> _container(
  WidgetTester tester,
  _FakeServer server,
  IceUser user,
) async {
  tester.view.physicalSize = const Size(1170, 2532);
  tester.view.devicePixelRatio = 3;
  addTearDown(tester.view.reset);
  final c = ProviderContainer(
    overrides: [
      authProvider.overrideWith(
        (_) => AuthNotifier.withState(AuthState.auth(user), dio: _dio(server)),
      ),
    ],
  );
  addTearDown(c.dispose);
  return c;
}

Future<void> _fill(WidgetTester tester, String old, String pw) async {
  await tester.enterText(find.byKey(const ValueKey('pw-old')), old);
  await tester.enterText(find.byKey(const ValueKey('pw-new')), pw);
  await tester.enterText(find.byKey(const ValueKey('pw-confirm')), pw);
  await tester.tap(find.byKey(const ValueKey('pw-submit')));
  await tester.pumpAndSettle();
}

void main() {
  setUp(() {
    // English, so the tests read the key strings.
    SharedPreferences.setMockInitialValues({'ice_lang': 'en'});
    FlutterSecureStorage.setMockInitialValues({});
  });

  group('roleRedirect with a temporary password', () {
    test('every role is held on /change-password', () {
      for (final type in ['1', '2', '3', '4']) {
        final auth = AuthState.auth(_user(type: type));
        expect(roleRedirect(auth, '/student/home'), '/change-password');
        expect(roleRedirect(auth, '/staff/home'), '/change-password');
        expect(roleRedirect(auth, '/coming-soon'), '/change-password');
        expect(roleRedirect(auth, '/change-password'), isNull);
      }
    });

    test('once changed, the screen sends users home', () {
      expect(
        roleRedirect(
          AuthState.auth(_user(mustChange: false, type: '3')),
          '/change-password',
        ),
        '/student/home',
      );
      expect(
        roleRedirect(
          AuthState.auth(_user(mustChange: false, type: '2')),
          '/change-password',
        ),
        '/staff/home',
      );
      expect(
        roleRedirect(
          AuthState.auth(_user(mustChange: false)),
          '/change-password',
        ),
        '/parent/home',
      );
    });

    test('the flag is read from login and me/ and survives the cache', () {
      final u = IceUser.fromJson(_userJson());
      expect(u.mustChangePassword, isTrue);
      expect(IceUser.fromJson(u.toJson()).mustChangePassword, isTrue);
      expect(
        IceUser.fromJson({'id': 1, 'user_type': 3}).mustChangePassword,
        isFalse,
      );
    });
  });

  group('the 403 "password_change_required"', () {
    Response<dynamic> res(int code, Object data) => Response(
      requestOptions: RequestOptions(),
      statusCode: code,
      data: data,
    );

    test('is recognised by its code only', () {
      expect(
        isPasswordChangeRequired(
          res(403, {'code': 'password_change_required'}),
        ),
        isTrue,
      );
      expect(isPasswordChangeRequired(res(403, {'detail': 'No.'})), isFalse);
      expect(
        isPasswordChangeRequired(
          res(401, {'code': 'password_change_required'}),
        ),
        isFalse,
      );
      expect(isPasswordChangeRequired(null), isFalse);
    });

    test('any API call refused with it reaches the app', () async {
      final api = ApiClient.instance;
      await api.loadTokens();
      api.dio.httpClientAdapter = _FakeServer({
        'GET /student/home/': (
          403,
          {
            'detail': 'Change your password before continuing.',
            'code': 'password_change_required',
          },
        ),
      });
      var called = 0;
      api.onPasswordChangeRequired = () => called++;
      await expectLater(
        api.dio.get('/student/home/'),
        throwsA(isA<DioException>()),
      );
      expect(called, 1);
    });

    testWidgets('a signed-in user is sent to the screen and checked with me/', (
      tester,
    ) async {
      final server = _FakeServer({'GET /me/': (200, _userJson())});
      final c = await _container(tester, server, _user(mustChange: false));
      await tester.pumpWidget(_app(c));
      await tester.pumpAndSettle();
      expect(find.text('home'), findsOneWidget);

      c.read(authProvider.notifier).passwordChangeRequired();
      await tester.pumpAndSettle();
      expect(find.byType(ChangePasswordScreen), findsOneWidget);
      expect(server.calls, contains('GET /me/'));
    });
  });

  group('ChangePasswordScreen', () {
    testWidgets('success saves, refreshes me/ and continues home', (
      tester,
    ) async {
      final server = _FakeServer({
        'POST /me/change-password/': (
          200,
          {'detail': 'Password changed successfully.'},
        ),
        'GET /me/': (200, _userJson(mustChange: false)),
      });
      final c = await _container(tester, server, _user());
      await tester.pumpWidget(_app(c));
      await tester.pumpAndSettle();
      expect(find.byType(ChangePasswordScreen), findsOneWidget);
      expect(find.text('Choose your password'), findsOneWidget);

      await _fill(tester, 'Temp-1234', 'my-own-pass');
      expect(server.bodies['POST /me/change-password/'], {
        'old_password': 'Temp-1234',
        'new_password': 'my-own-pass',
        'confirm_password': 'my-own-pass',
      });
      expect(server.calls.last, 'GET /me/');
      expect(c.read(authProvider).user!.mustChangePassword, isFalse);
      expect(find.text('home'), findsOneWidget);
    });

    testWidgets('continues even if me/ fails after the change', (tester) async {
      final server = _FakeServer({
        'POST /me/change-password/': (
          200,
          {'detail': 'Password changed successfully.'},
        ),
        'GET /me/': (500, {'detail': 'Server error'}),
      });
      final c = await _container(tester, server, _user());
      await tester.pumpWidget(_app(c));
      await tester.pumpAndSettle();
      await _fill(tester, 'Temp-1234', 'my-own-pass');
      expect(find.text('home'), findsOneWidget);
    });

    testWidgets('a wrong temporary password (plain string) is shown', (
      tester,
    ) async {
      final server = _FakeServer({
        'POST /me/change-password/': (
          400,
          {'old_password': 'Incorrect password.'},
        ),
      });
      final c = await _container(tester, server, _user());
      await tester.pumpWidget(_app(c));
      await tester.pumpAndSettle();
      await _fill(tester, 'wrong', 'my-own-pass');
      expect(
        find.text('The temporary password is not correct.'),
        findsOneWidget,
      );
      expect(find.byType(ChangePasswordScreen), findsOneWidget);
      expect(c.read(authProvider).user!.mustChangePassword, isTrue);
    });

    testWidgets('validator errors (a list) show the server text', (
      tester,
    ) async {
      final server = _FakeServer({
        'POST /me/change-password/': (
          400,
          {
            'new_password': ['This password is too common.', 'Another one.'],
          },
        ),
      });
      final c = await _container(tester, server, _user());
      await tester.pumpWidget(_app(c));
      await tester.pumpAndSettle();
      await _fill(tester, 'Temp-1234', 'password1');
      expect(find.text('This password is too common.'), findsOneWidget);
      expect(find.byType(ChangePasswordScreen), findsOneWidget);
    });

    testWidgets('short or mismatched passwords never reach the server', (
      tester,
    ) async {
      final server = _FakeServer({});
      final c = await _container(tester, server, _user());
      await tester.pumpWidget(_app(c));
      await tester.pumpAndSettle();

      await _fill(tester, 'Temp-1234', 'short');
      expect(find.text('At least 8 characters'), findsWidgets);
      await tester.enterText(
        find.byKey(const ValueKey('pw-new')),
        'long-enough-1',
      );
      await tester.enterText(
        find.byKey(const ValueKey('pw-confirm')),
        'long-enough-2',
      );
      await tester.tap(find.byKey(const ValueKey('pw-submit')));
      await tester.pumpAndSettle();
      expect(find.text('Passwords do not match'), findsOneWidget);
      expect(server.calls, isEmpty);
    });

    testWidgets('back is blocked; log out is the only other way', (
      tester,
    ) async {
      final server = _FakeServer({'POST /auth/logout/': (200, {})});
      final c = await _container(tester, server, _user());
      await tester.pumpWidget(_app(c));
      await tester.pumpAndSettle();

      final pop = tester.widget<PopScope>(find.byType(PopScope));
      expect(pop.canPop, isFalse);
      // Going home directly is redirected back.
      GoRouter.of(
        tester.element(find.byType(ChangePasswordScreen)),
      ).go('/student/home');
      await tester.pumpAndSettle();
      expect(find.byType(ChangePasswordScreen), findsOneWidget);

      await tester.tap(find.byKey(const ValueKey('pw-logout')));
      await tester.pumpAndSettle();
      expect(c.read(authProvider).status, AuthStatus.unauthenticated);
      expect(find.text('login'), findsOneWidget);
    });
  });

  group('ChangePasswordError.from', () {
    ChangePasswordError parse(Object? data) => ChangePasswordError.from(
      DioException(
        requestOptions: RequestOptions(),
        response: data == null
            ? null
            : Response(
                requestOptions: RequestOptions(),
                statusCode: 400,
                data: data,
              ),
      ),
    );

    test('reads strings, lists, detail and no response', () {
      final a = parse({'old_password': 'Incorrect password.'});
      expect((a.field, a.message), ('old_password', 'Incorrect password.'));
      final b = parse({
        'confirm_password': ['Passwords do not match.'],
      });
      expect(
        (b.field, b.message),
        ('confirm_password', 'Passwords do not match.'),
      );
      final c = parse({'detail': 'Throttled.'});
      expect((c.field, c.message), (null, 'Throttled.'));
      final d = parse(null);
      expect((d.field, d.message), (null, null));
    });
  });
}
