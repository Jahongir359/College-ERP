import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:url_launcher/url_launcher.dart';

import '../api/api_client.dart';
import '../settings/app_settings.dart';

/// Minimum app version check (plan P4.12, app half).
///
/// At start-up the app asks `GET /api/v1/app/version/` for the oldest version
/// still supported on its platform. When the installed app is older it shows
/// [UpdateScreen] with the store link instead of the app. Anything unexpected
/// (no answer, an error, a malformed version, web) lets the app through.

/// Parses "1.2.3" (a "+build" suffix is ignored) into [major, minor, patch].
/// Returns null when [v] is not a plain dotted version.
List<int>? parseVersion(String? v) {
  if (v == null) return null;
  final core = v.trim().split('+').first;
  final parts = core.split('.');
  if (parts.isEmpty || parts.length > 3) return null;
  final nums = <int>[];
  for (final p in parts) {
    final n = int.tryParse(p);
    if (n == null || n < 0) return null;
    nums.add(n);
  }
  while (nums.length < 3) {
    nums.add(0);
  }
  return nums;
}

/// True only when both versions parse and [current] is older than [minimum].
bool isOlderThan(String current, String minimum) {
  final c = parseVersion(current);
  final m = parseVersion(minimum);
  if (c == null || m == null) return false;
  for (var i = 0; i < 3; i++) {
    if (c[i] != m[i]) return c[i] < m[i];
  }
  return false;
}

class UpdateCheck {
  final bool required;
  final String storeUrl;
  const UpdateCheck({this.required = false, this.storeUrl = ''});

  static const none = UpdateCheck();
}

/// The installed app's version ("1.0.2"). Tests override this.
final currentAppVersionProvider = FutureProvider<String>((ref) async {
  final info = await PackageInfo.fromPlatform();
  return info.version;
});

/// Platform key in the API answer ("android" / "ios"), or null where the
/// check never blocks (web, desktop). Tests override this.
final updatePlatformProvider = Provider<String?>((ref) {
  if (kIsWeb) return null;
  switch (defaultTargetPlatform) {
    case TargetPlatform.android:
      return 'android';
    case TargetPlatform.iOS:
      return 'ios';
    default:
      return null;
  }
});

/// Fetches the version answer. One quick try, no retries: the app must not
/// wait on a slow network. Tests override this.
final appVersionFetcherProvider =
    Provider<Future<Map<String, dynamic>> Function()>(
      (ref) => () async {
        final res = await ApiClient.instance.dio.get(
          '/app/version/',
          options: Options(
            sendTimeout: const Duration(seconds: 8),
            receiveTimeout: const Duration(seconds: 8),
          ),
        );
        return Map<String, dynamic>.from(res.data as Map);
      },
    );

final updateCheckProvider = FutureProvider<UpdateCheck>((ref) async {
  final platform = ref.watch(updatePlatformProvider);
  if (platform == null) return UpdateCheck.none;
  try {
    final data = await ref.watch(appVersionFetcherProvider)();
    final entry = data[platform];
    if (entry is! Map) return UpdateCheck.none;
    final minimum = entry['min_app_version'];
    if (minimum is! String) return UpdateCheck.none;
    final current = await ref.watch(currentAppVersionProvider.future);
    if (!isOlderThan(current, minimum)) return UpdateCheck.none;
    final url = entry['store_url'];
    return UpdateCheck(
      required: true,
      storeUrl: url is String ? url.trim() : '',
    );
  } catch (_) {
    // Fail open: an unreachable or broken check never locks anyone out.
    return UpdateCheck.none;
  }
});

/// Shows [UpdateScreen] instead of [child] when the app is too old. While the
/// check runs, or if it fails, [child] is shown as usual.
class UpdateGate extends ConsumerWidget {
  final Widget child;
  const UpdateGate({super.key, required this.child});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final check = ref.watch(updateCheckProvider).valueOrNull;
    if (check != null && check.required) {
      return UpdateScreen(storeUrl: check.storeUrl);
    }
    return child;
  }
}

class UpdateScreen extends ConsumerWidget {
  final String storeUrl;
  const UpdateScreen({super.key, required this.storeUrl});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(stringsProvider);
    final theme = Theme.of(context);
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  Icons.system_update_rounded,
                  size: 64,
                  color: theme.colorScheme.primary,
                ),
                const SizedBox(height: 24),
                Text(
                  s('Update required'),
                  style: theme.textTheme.headlineSmall,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                Text(
                  s(
                    'This version of the app is no longer supported. Please install the latest version to continue.',
                  ),
                  style: theme.textTheme.bodyLarge,
                  textAlign: TextAlign.center,
                ),
                if (storeUrl.isNotEmpty) ...[
                  const SizedBox(height: 32),
                  FilledButton.icon(
                    onPressed: () => launchUrl(
                      Uri.parse(storeUrl),
                      mode: LaunchMode.externalApplication,
                    ),
                    icon: const Icon(Icons.open_in_new_rounded),
                    label: Text(s('Update')),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
