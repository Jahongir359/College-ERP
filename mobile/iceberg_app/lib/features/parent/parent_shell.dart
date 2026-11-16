import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/auth_state.dart';
import '../../core/settings/app_settings.dart';
import '../../core/theme/brand.dart';
import '../../core/theme/ice_tokens.dart';
import '../student/screens/student_shell.dart' show StudentThemeScope;
import 'parent_data.dart';
import 'parent_home_screen.dart';

/// Parent app (plan P4.4): five tabs under one bottom bar. Home is built
/// here; Timetable (P4.5), Homework and Messages (P4.8) say what is coming
/// and point back to Home, which already shows today for each.
class ParentShell extends ConsumerWidget {
  const ParentShell({super.key, required this.navigationShell});

  final StatefulNavigationShell navigationShell;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return StudentThemeScope(
      child: Builder(
        builder: (themed) => Scaffold(
          backgroundColor: themed.ice.bg,
          body: navigationShell,
          bottomNavigationBar: ParentNavBar(
            index: navigationShell.currentIndex,
            onTap: (i) => navigationShell.goBranch(
              i,
              initialLocation: i == navigationShell.currentIndex,
            ),
          ),
        ),
      ),
    );
  }
}

class ParentNavBar extends ConsumerWidget {
  const ParentNavBar({super.key, required this.index, required this.onTap});

  final int index;
  final ValueChanged<int> onTap;

  static const items = [
    (Icons.home_outlined, Icons.home_outlined, 'Home'),
    (Icons.calendar_month_outlined, Icons.calendar_month_outlined, 'Timetable'),
    (
      Icons.import_contacts_outlined,
      Icons.import_contacts_outlined,
      'Homework',
    ),
    (
      Icons.chat_bubble_outline_rounded,
      Icons.chat_bubble_outline_rounded,
      'Messages',
    ),
    (Icons.person_outline_rounded, Icons.person_outline_rounded, 'Profile'),
  ];

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final active = t.isDark ? SchoolColors.ink : SchoolColors.primary;
    return DecoratedBox(
      decoration: BoxDecoration(
        color: t.card,
        border: Border(top: BorderSide(color: t.stroke)),
      ),
      child: SafeArea(
        top: false,
        child: Center(
          heightFactor: 1,
          child: ConstrainedBox(
            constraints: const BoxConstraints(
              maxWidth: ParentHomeScreen.maxWidth,
            ),
            child: SizedBox(
              height: 72,
              child: Row(
                children: [
                  for (var i = 0; i < items.length; i++)
                    Expanded(
                      child: InkResponse(
                        key: ValueKey('parent-tab-$i'),
                        onTap: () {
                          HapticFeedback.selectionClick();
                          onTap(i);
                        },
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            AnimatedContainer(
                              duration: const Duration(milliseconds: 180),
                              width: 56,
                              height: 32,
                              decoration: BoxDecoration(
                                color: i == index
                                    ? t.inset
                                    : Colors.transparent,
                                borderRadius: BorderRadius.circular(99),
                              ),
                              child: Icon(
                                i == index ? items[i].$2 : items[i].$1,
                                size: 23,
                                color: i == index ? active : t.textMid,
                              ),
                            ),
                            const SizedBox(height: 4),
                            Text(
                              s(items[i].$3),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: i == index
                                    ? FontWeight.w800
                                    : FontWeight.w600,
                                color: i == index ? active : t.textMid,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// A tab whose screen comes in a later update.
class ParentSoonTab extends ConsumerWidget {
  const ParentSoonTab({super.key, required this.title, required this.icon});

  final String title;
  final IconData icon;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    return _ParentPage(
      title: s(title),
      child: Container(
        padding: const EdgeInsets.all(24),
        decoration: BoxDecoration(
          color: t.card,
          borderRadius: BorderRadius.circular(24),
          border: Border.all(color: t.stroke),
        ),
        child: Column(
          children: [
            Icon(icon, size: 40, color: parentGold(t)),
            const SizedBox(height: 12),
            Text(
              s('This section comes in the next update.'),
              textAlign: TextAlign.center,
              style: TextStyle(
                color: t.textHi,
                fontSize: 16,
                fontWeight: FontWeight.w700,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              s('Today’s summary for your child is on Home.'),
              textAlign: TextAlign.center,
              style: TextStyle(color: t.textMid, fontSize: 14),
            ),
            const SizedBox(height: 16),
            FilledButton(
              key: const ValueKey('soon-home'),
              onPressed: () => context.go('/parent/home'),
              style: FilledButton.styleFrom(
                backgroundColor: t.accent,
                foregroundColor: t.onAccent,
              ),
              child: Text(s('Home')),
            ),
          ],
        ),
      ),
    );
  }
}

/// Profile: who is signed in, the children, language, theme and log out.
class ParentProfileTab extends ConsumerWidget {
  const ParentProfileTab({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider).user;
    final children = ref.watch(parentChildrenProvider);
    final settings = ref.watch(appSettingsProvider);
    final notifier = ref.read(appSettingsProvider.notifier);

    Widget section(String label, Widget child) => Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(18),
        decoration: BoxDecoration(
          color: t.card,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: t.stroke),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label.toUpperCase(),
              style: TextStyle(
                color: parentGold(t),
                fontSize: 12,
                fontWeight: FontWeight.w800,
                letterSpacing: 1.4,
              ),
            ),
            const SizedBox(height: 10),
            child,
          ],
        ),
      ),
    );

    return _ParentPage(
      title: s('Profile'),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          section(
            s('Parent'),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  user?.fullName ?? '',
                  style: TextStyle(
                    color: t.textHi,
                    fontSize: 18,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                if (user?.loginId.isNotEmpty == true)
                  Text(
                    'ID: ${user!.loginId}',
                    style: TextStyle(color: t.textMid),
                  ),
              ],
            ),
          ),
          section(
            s('Children'),
            Column(
              children: [
                for (final c in children)
                  ListTile(
                    contentPadding: EdgeInsets.zero,
                    leading: CircleAvatar(
                      backgroundColor: t.inset,
                      child: Text(
                        c.initials,
                        style: TextStyle(
                          color: t.isDark
                              ? SchoolColors.ink
                              : SchoolColors.primary,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ),
                    title: Text(
                      c.name,
                      style: TextStyle(
                        color: t.textHi,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    subtitle: c.className.isEmpty
                        ? null
                        : Text(c.className, style: TextStyle(color: t.textMid)),
                  ),
                if (children.isEmpty)
                  Text(
                    s('No children are linked to your account yet.'),
                    style: TextStyle(color: t.textMid),
                  ),
              ],
            ),
          ),
          section(
            s('Language'),
            Wrap(
              spacing: 8,
              children: [
                for (final (code, label) in const [
                  ('uz', 'Oʻzbekcha'),
                  ('ru', 'Русский'),
                  ('en', 'English'),
                ])
                  ChoiceChip(
                    key: ValueKey('lang-$code'),
                    label: Text(label),
                    selected: settings.language == code,
                    onSelected: (_) => notifier.setLanguage(code),
                  ),
              ],
            ),
          ),
          section(
            s('Theme'),
            Wrap(
              spacing: 8,
              children: [
                for (final (mode, label) in [
                  (ThemeMode.light, s('Light')),
                  (ThemeMode.dark, s('Dark')),
                  (ThemeMode.system, s('System')),
                ])
                  ChoiceChip(
                    label: Text(label),
                    selected: settings.themeMode == mode,
                    onSelected: (_) => notifier.setTheme(mode),
                  ),
              ],
            ),
          ),
          OutlinedButton.icon(
            key: const ValueKey('parent-logout'),
            onPressed: () => ref.read(authProvider.notifier).logout(),
            icon: const Icon(Icons.logout_rounded),
            label: Text(s('Log out')),
            style: OutlinedButton.styleFrom(
              foregroundColor: t.isDark
                  ? SchoolColors.ink
                  : SchoolColors.primary,
              side: BorderSide(color: t.stroke),
              minimumSize: const Size.fromHeight(50),
            ),
          ),
        ],
      ),
    );
  }
}

/// A plain parent page: title and one centred column.
class _ParentPage extends StatelessWidget {
  const _ParentPage({required this.title, required this.child});

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return ColoredBox(
      color: t.bg,
      child: SafeArea(
        bottom: false,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(16, 20, 16, 24),
          children: [
            Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(
                  maxWidth: ParentHomeScreen.maxWidth,
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        color: t.textHi,
                        fontSize: 28,
                        fontWeight: FontWeight.w800,
                      ),
                    ),
                    const SizedBox(height: 18),
                    child,
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
