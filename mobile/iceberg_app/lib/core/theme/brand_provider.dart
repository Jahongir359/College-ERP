import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../auth/auth_state.dart';
import 'brand.dart';

const _brandPrefKey = 'ice_brand';

/// What this device remembers about the brand before anyone signs in.
class BrandChoice {
  const BrandChoice({
    this.brand = IceBrand.center,
    this.chosen = false,
    this.loaded = false,
  });

  final IceBrand brand;

  /// A brand was picked on `/choose` (or remembered from an earlier sign-in),
  /// so signed-out users go straight to the login screen.
  final bool chosen;

  /// Read from storage. Until then the router keeps the splash screen.
  final bool loaded;
}

/// The last brand this device showed: picked on the choice screen, then
/// replaced by the account's brand after sign-in, so the splash and login
/// screens keep a School user's look after they sign out.
class LastBrandNotifier extends StateNotifier<BrandChoice> {
  LastBrandNotifier() : super(const BrandChoice()) {
    _load();
  }

  Future<void> _load() async {
    final p = await SharedPreferences.getInstance();
    // A choice made while storage was still loading wins.
    if (!mounted || state.chosen) return;
    final saved = p.getString(_brandPrefKey);
    state = BrandChoice(
      brand: IceBrand.fromApi(saved),
      chosen: saved != null,
      loaded: true,
    );
  }

  Future<void> remember(IceBrand brand) async {
    if (state.chosen && state.brand == brand) return;
    state = BrandChoice(brand: brand, chosen: true, loaded: true);
    final p = await SharedPreferences.getInstance();
    await p.setString(_brandPrefKey, brand.name);
  }
}

final lastBrandProvider = StateNotifierProvider<LastBrandNotifier, BrandChoice>(
  (_) => LastBrandNotifier(),
);

/// The brand to render: the signed-in user's (from the server), otherwise the
/// one this device last showed or the person picked on `/choose`.
final brandProvider = Provider<IceBrand>((ref) {
  final user = ref.watch(authProvider.select((s) => s.user));
  if (user != null) return IceBrand.fromApi(user.brand);
  return ref.watch(lastBrandProvider.select((c) => c.brand));
});
