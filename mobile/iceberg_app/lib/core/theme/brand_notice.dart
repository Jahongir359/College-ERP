import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../auth/auth_state.dart';
import '../settings/app_settings.dart';
import 'brand.dart';
import 'brand_provider.dart';

/// The brand to announce when the app switches to [account] (plan 5.1): only
/// for a signed-in user whose account is not the brand this device picked on
/// `/choose`. Null means no notice.
IceBrand? brandSwitchNotice({
  required BrandChoice device,
  required IceBrand account,
  required bool signedIn,
}) {
  if (!signedIn || !device.chosen) return null;
  return device.brand == account ? null : account;
}

/// Remembers the brand on screen (so the splash and login keep it after
/// sign-out) and, when the account's brand differs from the device's pick,
/// says so once. Once remembered, the device and the account agree, so the
/// notice is not shown again.
class BrandWatcher extends ConsumerWidget {
  const BrandWatcher({super.key, required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    ref.listen(brandProvider, (_, next) {
      final notice = brandSwitchNotice(
        device: ref.read(lastBrandProvider),
        account: next,
        signedIn: ref.read(authProvider).user != null,
      );
      ref.read(lastBrandProvider.notifier).remember(next);
      if (notice == null) return;
      final s = ref.read(stringsProvider);
      ScaffoldMessenger.maybeOf(context)?.showSnackBar(
        SnackBar(
          content: Text(
            s(
              'Your account is in {brand}, so the app has switched to it.',
            ).replaceAll('{brand}', notice.appTitle),
          ),
          behavior: SnackBarBehavior.floating,
          duration: const Duration(seconds: 5),
        ),
      );
    });
    return child;
  }
}
