import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
import 'package:iceberg_app/core/auth/auth_state.dart';
import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/core/router/app_router.dart';
import 'package:iceberg_app/core/settings/app_settings.dart';
import 'package:iceberg_app/core/theme/brand.dart';
import 'package:iceberg_app/core/theme/brand_provider.dart';
import 'package:iceberg_app/features/auth/screens/choose_screen.dart';
import 'package:iceberg_app/features/auth/screens/login_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Settings without the server call (signed out, it would only time out).
class _LocalSettings extends AppSettingsNotifier {
  @override
  void setLanguage(String lang) => state = state.copyWith(language: lang);
}

/// A signed-out app: the real redirect rules, choice screen and login screen,
/// with the brand from [lastBrandProvider] (no auth or network).
Widget _app(ProviderContainer container) {
  final router = GoRouter(
    initialLocation: '/splash',
    redirect: (_, state) {
      final choice = container.read(lastBrandProvider);
      return roleRedirect(
        AuthState.unauth(),
        state.matchedLocation,
        brandChosen: choice.loaded ? choice.chosen : null,
      );
    },
    routes: [
      GoRoute(path: '/splash', builder: (_, __) => const Text('splash')),
      GoRoute(path: '/choose', builder: (_, __) => const ChooseScreen()),
      GoRoute(path: '/login', builder: (_, __) => const LoginScreen()),
    ],
  );
  return UncontrolledProviderScope(
    container: container,
    child: MaterialApp.router(routerConfig: router),
  );
}

Future<ProviderContainer> _container(WidgetTester tester) async {
  // A tall phone so both cards and the login link fit without scrolling.
  tester.view.physicalSize = const Size(1170, 2532);
  tester.view.devicePixelRatio = 3;
  addTearDown(tester.view.reset);
  final c = ProviderContainer(
    overrides: [
      appSettingsProvider.overrideWith((_) => _LocalSettings()),
      // Signed out: the brand comes from the device's choice.
      brandProvider.overrideWith(
        (ref) => ref.watch(lastBrandProvider.select((b) => b.brand)),
      ),
    ],
  );
  addTearDown(c.dispose);
  // Let the saved choice load before the first route is resolved.
  c.read(lastBrandProvider);
  await tester.runAsync(() => Future<void>.delayed(Duration.zero));
  expect(c.read(lastBrandProvider).loaded, isTrue);
  return c;
}

void main() {
  testWidgets('first launch shows the choice, School opens a School login', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final c = await _container(tester);
    await tester.pumpWidget(_app(c));
    await tester.pumpAndSettle();

    expect(find.byType(ChooseScreen), findsOneWidget);
    expect(find.text('Iceberg School'), findsOneWidget);
    expect(find.text('Iceberg Study Center'), findsOneWidget);
    // Default language is Uzbek.
    expect(find.text('Xususiy maktab · 1–11-sinflar'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('choose-school')));
    await tester.pumpAndSettle();

    expect(find.byType(LoginScreen), findsOneWidget);
    expect(c.read(lastBrandProvider).brand, IceBrand.school);
    expect(c.read(lastBrandProvider).chosen, isTrue);
    expect(find.text('Iceberg School · '), findsOneWidget);
    final prefs = await SharedPreferences.getInstance();
    expect(prefs.getString('ice_brand'), 'school');
  });

  testWidgets('the login link goes back to the choice to switch brand', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({'ice_brand': 'school'});
    final c = await _container(tester);
    await tester.pumpWidget(_app(c));
    await tester.pumpAndSettle();

    // A remembered choice skips straight to login.
    expect(find.byType(LoginScreen), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('login-change-brand')));
    await tester.pumpAndSettle();
    expect(find.byType(ChooseScreen), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('choose-center')));
    await tester.pumpAndSettle();
    expect(find.byType(LoginScreen), findsOneWidget);
    expect(c.read(lastBrandProvider).brand, IceBrand.center);
    expect(find.text('Iceberg Study Center · '), findsOneWidget);
  });

  testWidgets('the language pills translate the choice screen', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final c = await _container(tester);
    await tester.pumpWidget(_app(c));
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const ValueKey('lang-ru')));
    await tester.pumpAndSettle();
    expect(find.text('Частная школа · 1–11 классы'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('lang-en')));
    await tester.pumpAndSettle();
    expect(find.text('Private school · Grades 1–11'), findsOneWidget);
    // D7: the brand names stay the same in every language.
    expect(find.text('Iceberg Study Center'), findsOneWidget);
  });

  test('choice strings exist in uz, ru and ko', () {
    const keys = [
      'Which Iceberg are you signing in to?',
      'Choose one. Next time the app opens there.',
      'Private school · Grades 1–11',
      'IELTS, CEFR, SAT and subject courses',
      'You can change this on the sign-in screen',
      'Choose another',
    ];
    for (final lang in ['uz', 'ru', 'ko']) {
      for (final k in keys) {
        expect(S(lang)(k), isNot(k), reason: '$lang: $k');
      }
    }
  });
}
