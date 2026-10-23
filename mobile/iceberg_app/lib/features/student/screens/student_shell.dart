import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/settings/app_settings.dart';
import '../../../core/theme/brand_provider.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Applies the ICEBERG dark design system (theme mode, accent colour and
/// font size from Settings) to the whole student experience without
/// affecting the staff/admin sections of the app.
class StudentThemeScope extends ConsumerWidget {
  final Widget child;
  const StudentThemeScope({super.key, required this.child});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final settings = ref.watch(appSettingsProvider);
    final platformDark =
        MediaQuery.platformBrightnessOf(context) == Brightness.dark;
    final dark = switch (settings.themeMode) {
      ThemeMode.dark => true,
      ThemeMode.light => false,
      ThemeMode.system => platformDark,
    };
    final theme = buildIceTheme(
      dark: dark,
      accent: settings.accentColor,
      brand: ref.watch(brandProvider),
    );

    return AnnotatedRegion<SystemUiOverlayStyle>(
      value: dark ? SystemUiOverlayStyle.light : SystemUiOverlayStyle.dark,
      child: Theme(
        data: theme,
        child: DefaultTextStyle.merge(
          style: const TextStyle(
            decoration: TextDecoration.none,
            decorationColor: Colors.transparent,
          ),
          child: MediaQuery(
            data: MediaQuery.of(
              context,
            ).copyWith(textScaler: TextScaler.linear(settings.textScale)),
            child: child,
          ),
        ),
      ),
    );
  }
}

class StudentShell extends ConsumerStatefulWidget {
  final StatefulNavigationShell navigationShell;
  const StudentShell({super.key, required this.navigationShell});

  @override
  ConsumerState<StudentShell> createState() => _StudentShellState();
}

class _StudentShellState extends ConsumerState<StudentShell>
    with SingleTickerProviderStateMixin {
  late final AnimationController _fadeCtrl;
  late final Animation<double> _fadeAnim;

  @override
  void initState() {
    super.initState();
    _fadeCtrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 140),
      value: 1.0,
    );
    _fadeAnim = CurvedAnimation(parent: _fadeCtrl, curve: Curves.easeOut);
    // Pull server-side appearance/notification preferences once per session.
    Future.microtask(
      () => ref.read(appSettingsProvider.notifier).syncFromServer(),
    );
  }

  @override
  void dispose() {
    _fadeCtrl.dispose();
    super.dispose();
  }

  void _onTabTap(int i) {
    final isSameTab = i == widget.navigationShell.currentIndex;
    if (isSameTab) {
      widget.navigationShell.goBranch(i, initialLocation: true);
      return;
    }
    // Quick fade-out → switch → fade-in so the content change feels smooth
    _fadeCtrl
        .animateTo(
          0.0,
          duration: const Duration(milliseconds: 60),
          curve: Curves.easeIn,
        )
        .then((_) {
      if (!mounted) return;
      widget.navigationShell.goBranch(i);
      _fadeCtrl.animateTo(
        1.0,
        duration: const Duration(milliseconds: 130),
        curve: Curves.easeOut,
      );
    });
  }

  @override
  Widget build(BuildContext context) {
    return StudentThemeScope(
      child: Builder(
        builder: (themed) => Scaffold(
          backgroundColor: themed.ice.bg,
          drawer: const IceDrawer(),
          appBar: const IceHeader(),
          body: DefaultTextStyle.merge(
            style: const TextStyle(
              decoration: TextDecoration.none,
              decorationColor: Colors.transparent,
              decorationThickness: 0,
            ),
            child: FadeTransition(
              opacity: _fadeAnim,
              child: Center(
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 720),
                  child: widget.navigationShell,
                ),
              ),
            ),
          ),
          bottomNavigationBar: IceBottomNav(
            index: widget.navigationShell.currentIndex,
            onTap: _onTabTap,
          ),
        ),
      ),
    );
  }
}
