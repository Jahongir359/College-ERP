import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_shell.dart';

class StaffShell extends ConsumerStatefulWidget {
  final StatefulNavigationShell navigationShell;
  const StaffShell({super.key, required this.navigationShell});

  @override
  ConsumerState<StaffShell> createState() => _StaffShellState();
}

class _StaffShellState extends ConsumerState<StaffShell>
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
    final settings = ref.watch(appSettingsProvider);
    final platformDark =
        MediaQuery.platformBrightnessOf(context) == Brightness.dark;
    final dark = switch (settings.themeMode) {
      ThemeMode.dark => true,
      ThemeMode.light => false,
      ThemeMode.system => platformDark,
    };
    final theme = buildIceTheme(dark: dark, accent: settings.accentColor);

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
            data: MediaQuery.of(context)
                .copyWith(textScaler: TextScaler.linear(settings.textScale)),
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
                bottomNavigationBar: _StaffBottomNav(
                  index: widget.navigationShell.currentIndex,
                  onTap: _onTabTap,
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _StaffBottomNav extends ConsumerWidget {
  final int index;
  final ValueChanged<int> onTap;
  const _StaffBottomNav({required this.index, required this.onTap});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    const items = [
      (Icons.grid_view_rounded, 'Dashboard'),
      (Icons.event_available_rounded, 'Attendance'),
      (Icons.bar_chart_rounded, 'Results'),
      (Icons.assignment_outlined, 'Assignments'),
      (Icons.person_rounded, 'Profile'),
    ];

    return RepaintBoundary(
      child: Container(
      decoration: BoxDecoration(
        color: t.card,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(26)),
        border: Border(top: BorderSide(color: t.stroke)),
        boxShadow: [
          BoxShadow(
            color:
                Colors.black.withValues(alpha: t.isDark ? 0.35 : 0.08),
            blurRadius: 10,
            offset: const Offset(0, -3),
          ),
        ],
      ),
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: SizedBox(
            height: 64,
            child: Row(
              children: List.generate(items.length, (i) {
              final active = i == index;
              final (icon, label) = items[i];
              return Expanded(
                child: GestureDetector(
                  behavior: HitTestBehavior.opaque,
                  onTap: () {
                    HapticFeedback.selectionClick();
                    onTap(i);
                  },
                  child: active
                      ? Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            AnimatedContainer(
                              duration: const Duration(milliseconds: 220),
                              curve: Curves.easeOutBack,
                              width: 42,
                              height: 42,
                              decoration: BoxDecoration(
                                color: t.accent,
                                shape: BoxShape.circle,
                                boxShadow: [
                                  BoxShadow(
                                    color:
                                        t.accent.withValues(alpha: 0.45),
                                    blurRadius: 14,
                                    offset: const Offset(0, 4),
                                  ),
                                ],
                              ),
                              child: Icon(icon,
                                  color: t.onAccent, size: 21),
                            ),
                          ],
                        )
                      : Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(icon, color: t.textMid, size: 22),
                            const SizedBox(height: 3),
                            Text(
                              s(label),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                fontSize: 10,
                                fontWeight: FontWeight.w600,
                                color: t.textLow,
                              ),
                            ),
                          ],
                        ),
                ),
              );
            }),
            ),
          ),
        ),
      ),
    ));
  }
}
