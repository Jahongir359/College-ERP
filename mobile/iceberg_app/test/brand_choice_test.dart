import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/theme/brand.dart';
import 'package:iceberg_app/core/theme/brand_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('a first launch loads as not chosen', () async {
    SharedPreferences.setMockInitialValues({});
    final n = LastBrandNotifier();
    await Future<void>.delayed(Duration.zero);
    expect(n.state.loaded, isTrue);
    expect(n.state.chosen, isFalse);
    expect(n.state.brand, IceBrand.center);
  });

  test('a saved brand loads as chosen', () async {
    SharedPreferences.setMockInitialValues({'ice_brand': 'school'});
    final n = LastBrandNotifier();
    await Future<void>.delayed(Duration.zero);
    expect(n.state.chosen, isTrue);
    expect(n.state.brand, IceBrand.school);
  });

  test('a choice made while storage loads is not overwritten', () async {
    SharedPreferences.setMockInitialValues({'ice_brand': 'center'});
    final n = LastBrandNotifier();
    await n.remember(IceBrand.school);
    await Future<void>.delayed(Duration.zero);
    expect(n.state.brand, IceBrand.school);
    final p = await SharedPreferences.getInstance();
    expect(p.getString('ice_brand'), 'school');
  });
}
