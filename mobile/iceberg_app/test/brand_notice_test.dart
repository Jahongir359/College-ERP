import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/auth/auth_state.dart';
import 'package:iceberg_app/core/i18n/strings.dart';
import 'package:iceberg_app/core/theme/brand.dart';
import 'package:iceberg_app/core/theme/brand_notice.dart';
import 'package:iceberg_app/core/theme/brand_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

IceUser _user(String brand) =>
    IceUser.fromJson({'id': 3, 'user_type': '3', 'brand': brand});

Future<ProviderContainer> _container(WidgetTester tester) async {
  final c = ProviderContainer(
    overrides: [
      authProvider.overrideWith(
        (_) => AuthNotifier.withState(AuthState.unauth(), dio: Dio()),
      ),
    ],
  );
  addTearDown(c.dispose);
  c.read(lastBrandProvider);
  await tester.runAsync(() => Future<void>.delayed(Duration.zero));
  return c;
}

Widget _app(ProviderContainer c) => UncontrolledProviderScope(
  container: c,
  child: MaterialApp(
    builder: (_, child) => BrandWatcher(child: child!),
    home: const Scaffold(body: Text('screen')),
  ),
);

void main() {
  setUp(() => FlutterSecureStorage.setMockInitialValues({}));

  group('brandSwitchNotice', () {
    const center = BrandChoice(
      brand: IceBrand.center,
      chosen: true,
      loaded: true,
    );

    test('only when a signed-in account differs from the pick', () {
      expect(
        brandSwitchNotice(
          device: center,
          account: IceBrand.school,
          signedIn: true,
        ),
        IceBrand.school,
      );
      expect(
        brandSwitchNotice(
          device: center,
          account: IceBrand.center,
          signedIn: true,
        ),
        isNull,
      );
      expect(
        brandSwitchNotice(
          device: center,
          account: IceBrand.school,
          signedIn: false,
        ),
        isNull,
      );
    });

    test('not for a device that never picked (installed before /choose)', () {
      expect(
        brandSwitchNotice(
          device: const BrandChoice(loaded: true),
          account: IceBrand.school,
          signedIn: true,
        ),
        isNull,
      );
    });
  });

  testWidgets(
    'Study Center picked, School account: one notice, then remembered',
    (tester) async {
      SharedPreferences.setMockInitialValues({'ice_brand': 'center'});
      final c = await _container(tester);
      await tester.pumpWidget(_app(c));

      c.read(authProvider.notifier).updateUser(_user('school'));
      await tester.pump();
      expect(find.byType(SnackBar), findsOneWidget);
      expect(find.textContaining('Iceberg School'), findsOneWidget);
      expect(c.read(lastBrandProvider).brand, IceBrand.school);
      final prefs = await SharedPreferences.getInstance();
      expect(prefs.getString('ice_brand'), 'school');

      // Sign out and in again: the device now agrees, so no second notice.
      ScaffoldMessenger.of(tester.element(find.text('screen'))).removeCurrentSnackBar();
    await tester.pump();
    expect(find.byType(SnackBar), findsNothing);
      await c.read(authProvider.notifier).logout();
      await tester.pump();
      c.read(authProvider.notifier).updateUser(_user('school'));
      await tester.pump();
      expect(find.byType(SnackBar), findsNothing);
    },
  );

  testWidgets('matching brands show nothing', (tester) async {
    SharedPreferences.setMockInitialValues({'ice_brand': 'school'});
    final c = await _container(tester);
    await tester.pumpWidget(_app(c));

    c.read(authProvider.notifier).updateUser(_user('school'));
    await tester.pump();
    expect(find.byType(SnackBar), findsNothing);
  });

  test('the notice exists in uz and ru with the brand placeholder', () {
    const key = 'Your account is in {brand}, so the app has switched to it.';
    for (final lang in ['uz', 'ru', 'ko']) {
      expect(S(lang)(key), isNot(key));
      expect(S(lang)(key), contains('{brand}'));
    }
  });
}
