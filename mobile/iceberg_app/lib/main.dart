import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'core/router/app_router.dart';
import 'core/settings/app_settings.dart';
import 'core/theme/ice_tokens.dart';

final sharedPrefsProvider = Provider<SharedPreferences>(
  (ref) => throw UnimplementedError(),
);

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  SystemChrome.setPreferredOrientations([
    DeviceOrientation.portraitUp,
    DeviceOrientation.portraitDown,
    DeviceOrientation.landscapeLeft,
    DeviceOrientation.landscapeRight,
  ]);

  final prefs = await SharedPreferences.getInstance();

  runApp(
    ProviderScope(
      overrides: [sharedPrefsProvider.overrideWithValue(prefs)],
      child: const IcebergApp(),
    ),
  );
}

class IcebergApp extends ConsumerWidget {
  const IcebergApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(appSettingsProvider);
    final router = ref.watch(appRouterProvider);

    // Apply the ICEBERG design system (underline-free textTheme + the user's
    // chosen accent) as the GLOBAL theme so every screen is themed — including
    // the top-level routes (leave, feedback, notifications, settings, …) that
    // live outside the role shells and therefore never reach the shell-local
    // Theme wrappers.
    return MaterialApp.router(
      title: 'Iceberg Study Center',
      theme: buildIceTheme(dark: false, accent: settings.accentColor),
      darkTheme: buildIceTheme(dark: true, accent: settings.accentColor),
      themeMode: settings.themeMode,
      routerConfig: router,
      debugShowCheckedModeBanner: false,
      builder: (context, child) {
        // Apply the user's font-size preference to EVERY route — including the
        // standalone screens outside the role shells (staff more/vocabulary/
        // leave, notifications, settings, …). The shells rely on this too.
        return MediaQuery(
          data: MediaQuery.of(context).copyWith(
            textScaler: TextScaler.linear(settings.textScale),
          ),
          // Final safety net: force "no underline" on the default text style
          // for the entire navigator (covers dialogs/overlays too).
          child: DefaultTextStyle.merge(
            style: const TextStyle(
              decoration: TextDecoration.none,
              decorationColor: Colors.transparent,
              decorationThickness: 0,
            ),
            child: child ?? const SizedBox.shrink(),
          ),
        );
      },
    );
  }
}
