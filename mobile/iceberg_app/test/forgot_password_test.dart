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
import 'package:iceberg_app/core/router/app_router.dart';
import 'package:iceberg_app/core/theme/brand_provider.dart';
import 'package:iceberg_app/features/auth/password_reset_api.dart';
import 'package:iceberg_app/features/auth/screens/forgot_password_screen.dart';
import 'package:iceberg_app/features/auth/screens/login_screen.dart';
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

const _request = 'POST /auth/password-reset/';
const _confirm = 'POST /auth/password-reset/confirm/';

Future<void> _open(WidgetTester tester, _FakeServer server) async {
  tester.view.physicalSize = const Size(1170, 2532);
  tester.view.devicePixelRatio = 3;
  addTearDown(tester.view.reset);
  final dio = Dio(BaseOptions(baseUrl: 'http://test/api/v1'))
    ..httpClientAdapter = server;
  final router = GoRouter(
    initialLocation: '/forgot-password',
    routes: [
      GoRoute(
        path: '/login',
        builder: (_, __) => const Scaffold(body: Text('login page')),
      ),
      GoRoute(
        path: '/forgot-password',
        builder: (_, __) => const ForgotPasswordScreen(),
      ),
    ],
  );
  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        passwordResetApiProvider.overrideWithValue(PasswordResetApi(dio)),
      ],
      child: MaterialApp.router(routerConfig: router),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _askForCode(
  WidgetTester tester, {
  String login = ' PR-0007 ',
  String phone = '+998 90 111-22-33',
}) async {
  await tester.enterText(find.byKey(const ValueKey('reset-login')), login);
  await tester.enterText(find.byKey(const ValueKey('reset-phone')), phone);
  await tester.tap(find.byKey(const ValueKey('reset-send')));
  await tester.pumpAndSettle();
}

Future<void> _saveWithCode(
  WidgetTester tester, {
  String code = '123456',
  String pw = 'Yangi-parol-77',
}) async {
  await tester.enterText(find.byKey(const ValueKey('reset-code')), code);
  await tester.enterText(find.byKey(const ValueKey('reset-new')), pw);
  await tester.enterText(find.byKey(const ValueKey('reset-confirm')), pw);
  await tester.tap(find.byKey(const ValueKey('reset-save')));
  await tester.pumpAndSettle();
}

void main() {
  setUp(() {
    // English, so the tests read the key strings.
    SharedPreferences.setMockInitialValues({'ice_lang': 'en'});
    FlutterSecureStorage.setMockInitialValues({});
  });

  group('roleRedirect and /forgot-password', () {
    test('signed out: open after the brand is chosen, not before', () {
      final out = AuthState.unauth();
      expect(roleRedirect(out, '/forgot-password'), isNull);
      expect(
        roleRedirect(out, '/forgot-password', brandChosen: false),
        '/choose',
      );
    });

    test('signed in: every role is sent to its home', () {
      IceUser user(String type) => IceUser.fromJson({
        'id': 1,
        'first_name': 'A',
        'user_type': type,
        'brand': 'school',
      });
      expect(
        roleRedirect(AuthState.auth(user('3')), '/forgot-password'),
        '/student/home',
      );
      expect(
        roleRedirect(AuthState.auth(user('2')), '/forgot-password'),
        '/staff/home',
      );
      for (final type in ['1', '4']) {
        expect(
          roleRedirect(AuthState.auth(user(type)), '/forgot-password'),
          isNot(anyOf(isNull, '/forgot-password')),
        );
      }
    });
  });

  group('ForgotPasswordScreen', () {
    testWidgets('asks for a code, then saves the new password', (tester) async {
      final server = _FakeServer({
        _request: (200, {'detail': 'ok'}),
        _confirm: (200, {'detail': 'ok'}),
      });
      await _open(tester, server);
      expect(find.text('Forgot your password?'), findsOneWidget);
      expect(
        find.text(
          'Teachers and students: ask the school office for a new password.',
        ),
        findsOneWidget,
      );

      await _askForCode(tester);
      expect(server.bodies[_request], {
        'login_id': 'PR-0007',
        'phone': '+998 90 111-22-33',
      });
      expect(find.text('Enter the code'), findsOneWidget);

      await _saveWithCode(tester);
      expect(server.bodies[_confirm], {
        'login_id': 'PR-0007',
        'code': '123456',
        'new_password': 'Yangi-parol-77',
      });
      expect(find.text('login page'), findsOneWidget);
      expect(
        find.text('Password changed. Sign in with the new password.'),
        findsOneWidget,
      );
      // Let the message time out.
      await tester.pump(const Duration(seconds: 5));
      await tester.pumpAndSettle();
    });

    testWidgets('nothing is sent until the form is filled in', (tester) async {
      final server = _FakeServer({});
      await _open(tester, server);
      await _askForCode(tester, login: '', phone: '90 111');
      expect(find.text('Required'), findsOneWidget);
      expect(find.text('Enter the full phone number.'), findsOneWidget);
      expect(server.calls, isEmpty);
    });

    testWidgets('a wrong code keeps the user on the code step', (tester) async {
      final server = _FakeServer({
        _request: (200, {'detail': 'ok'}),
        _confirm: (400, {'detail': 'x', 'code': 'invalid_code'}),
      });
      await _open(tester, server);
      await _askForCode(tester);
      await _saveWithCode(tester);
      expect(
        find.text('The code is wrong or no longer works. Ask for a new one.'),
        findsOneWidget,
      );
      expect(find.text('Enter the code'), findsOneWidget);

      // "Send the code again" goes back with the login ID and phone kept.
      await tester.tap(find.byKey(const ValueKey('reset-again')));
      await tester.pumpAndSettle();
      expect(find.text('Forgot your password?'), findsOneWidget);
      expect(find.text('PR-0007'), findsNothing); // typed with spaces
      expect(find.text(' PR-0007 '), findsOneWidget);
      expect(find.byKey(const ValueKey('reset-error')), findsNothing);
    });

    testWidgets('the code step checks the code and both passwords', (
      tester,
    ) async {
      final server = _FakeServer({
        _request: (200, {'detail': 'ok'}),
      });
      await _open(tester, server);
      await _askForCode(tester);
      await tester.enterText(find.byKey(const ValueKey('reset-code')), '123');
      await tester.enterText(find.byKey(const ValueKey('reset-new')), 'short');
      await tester.enterText(
        find.byKey(const ValueKey('reset-confirm')),
        'other',
      );
      await tester.tap(find.byKey(const ValueKey('reset-save')));
      await tester.pumpAndSettle();
      expect(find.text('Enter the 6 digits.'), findsOneWidget);
      expect(find.text('At least 8 characters'), findsWidgets);
      expect(find.text('Passwords do not match'), findsOneWidget);
      expect(server.calls, [_request]);
    });

    testWidgets("shows the server's password rule", (tester) async {
      final server = _FakeServer({
        _request: (200, {'detail': 'ok'}),
        _confirm: (
          400,
          {
            'new_password': ['This password is too common.'],
          },
        ),
      });
      await _open(tester, server);
      await _askForCode(tester);
      await _saveWithCode(tester, pw: 'password1');
      expect(find.text('This password is too common.'), findsOneWidget);
    });

    testWidgets('too many requests and no internet have their own text', (
      tester,
    ) async {
      final server = _FakeServer({
        _request: (429, {'detail': 'throttled'}),
      });
      await _open(tester, server);
      await _askForCode(tester);
      expect(
        find.text('Too many tries. Please try again later.'),
        findsOneWidget,
      );
      expect(find.text('Forgot your password?'), findsOneWidget);

      server.routes[_request] = (500, {'detail': 'boom'});
      await tester.tap(find.byKey(const ValueKey('reset-send')));
      await tester.pumpAndSettle();
      expect(
        find.text('Something went wrong. Check your internet and try again.'),
        findsOneWidget,
      );
    });

    testWidgets('"Back to sign in" returns to the login', (tester) async {
      await _open(tester, _FakeServer({}));
      await tester.tap(find.byKey(const ValueKey('reset-back')));
      await tester.pumpAndSettle();
      expect(find.text('login page'), findsOneWidget);
    });
  });

  group('login screen', () {
    for (final brand in ['school', 'center']) {
      testWidgets('"Forgot password?" opens the reset screen ($brand)', (
        tester,
      ) async {
        SharedPreferences.setMockInitialValues({
          'ice_lang': 'en',
          'ice_brand': brand,
        });
        tester.view.physicalSize = const Size(1170, 2532);
        tester.view.devicePixelRatio = 3;
        addTearDown(tester.view.reset);
        final c = ProviderContainer(
          overrides: [
            authProvider.overrideWith(
              (_) => AuthNotifier.withState(AuthState.unauth(), dio: Dio()),
            ),
          ],
        );
        addTearDown(c.dispose);
        c.read(lastBrandProvider);
        await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)),
        );
        final router = GoRouter(
          initialLocation: '/login',
          routes: [
            GoRoute(path: '/login', builder: (_, __) => const LoginScreen()),
            GoRoute(
              path: '/forgot-password',
              builder: (_, __) => const Text('reset page'),
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
        // The Study Center keeps its line; the School follows mockup 02.
        expect(
          find.text('Contact your administrator to reset your password.'),
          brand == 'school' ? findsNothing : findsOneWidget,
        );
        await tester.tap(find.byKey(const ValueKey('login-forgot')));
        await tester.pumpAndSettle();
        expect(find.text('reset page'), findsOneWidget);
      });
    }
  });

  test('every reset string exists in uz, ru and ko', () {
    const keys = [
      'Forgot password?',
      'Forgot your password?',
      'Parents: enter your login ID and the phone number the school has for you. We will send a code by SMS.',
      'Login ID',
      'Phone number',
      'Enter the full phone number.',
      'Send code',
      'Teachers and students: ask the school office for a new password.',
      'Enter the code',
      'If the login ID and phone number match, a 6-digit code was sent by SMS. It works for 10 minutes.',
      'Code from the SMS',
      'Enter the 6 digits.',
      'Save new password',
      'Send the code again',
      'No SMS after a few minutes? Ask the school office.',
      'Back to sign in',
      'Password changed. Sign in with the new password.',
      'Too many tries. Please try again later.',
      'The code is wrong or no longer works. Ask for a new one.',
      'Choose a stronger password.',
      'Something went wrong. Check your internet and try again.',
    ];
    for (final lang in ['uz', 'ru', 'ko']) {
      final s = S(lang);
      for (final key in keys) {
        // 'Login ID' is the same word in Uzbek.
        if (lang == 'uz' && key == 'Login ID') continue;
        expect(s(key), isNot(key), reason: '$lang: $key');
      }
    }
  });
}
