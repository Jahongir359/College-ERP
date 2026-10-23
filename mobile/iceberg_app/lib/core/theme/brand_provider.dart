import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../auth/auth_state.dart';
import 'brand.dart';

const _brandPrefKey = 'ice_brand';

/// The last brand this device showed, so the splash and login screens keep a
/// School user's look after they sign out.
class LastBrandNotifier extends StateNotifier<IceBrand> {
  LastBrandNotifier() : super(IceBrand.center) {
    _load();
  }

  Future<void> _load() async {
    final p = await SharedPreferences.getInstance();
    if (!mounted) return;
    state = IceBrand.fromApi(p.getString(_brandPrefKey));
  }

  Future<void> remember(IceBrand brand) async {
    if (state == brand) return;
    state = brand;
    final p = await SharedPreferences.getInstance();
    await p.setString(_brandPrefKey, brand.name);
  }
}

final lastBrandProvider = StateNotifierProvider<LastBrandNotifier, IceBrand>(
  (_) => LastBrandNotifier(),
);

/// The brand to render: the signed-in user's (from the server), otherwise the
/// last one this device showed. Users cannot choose it.
final brandProvider = Provider<IceBrand>((ref) {
  final user = ref.watch(authProvider.select((s) => s.user));
  if (user != null) return IceBrand.fromApi(user.brand);
  return ref.watch(lastBrandProvider);
});
