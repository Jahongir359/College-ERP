import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/theme/brand_provider.dart';
import 'package:iceberg_app/features/auth/screens/login_screen.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// The white wordmark must sit on the maroon header (330 px) at any height.
void main() {
  for (final size in const [Size(390, 844), Size(390, 1000), Size(1366, 900)]) {
    testWidgets('School wordmark stays on the header at $size', (tester) async {
      SharedPreferences.setMockInitialValues({'ice_brand': 'school'});
      FlutterSecureStorage.setMockInitialValues({});
      tester.view.physicalSize = size * 2;
      tester.view.devicePixelRatio = 2;
      addTearDown(tester.view.reset);
      final c = ProviderContainer();
      addTearDown(c.dispose);
      c.read(lastBrandProvider);
      await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 50)),
      );

      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: c,
          child: const MaterialApp(home: LoginScreen()),
        ),
      );
      await tester.pumpAndSettle();
      final wordmark = find.byWidgetPredicate(
        (w) =>
            w is Image &&
            w.image is AssetImage &&
            (w.image as AssetImage).assetName.endsWith('logo-h-white.png'),
      );
      expect(wordmark, findsOneWidget);
      expect(tester.getRect(wordmark).bottom, lessThan(330));
      // Let the card's entrance animation finish.
      await tester.pumpWidget(const SizedBox());
      await tester.pump(const Duration(seconds: 3));
    });
  }
}
