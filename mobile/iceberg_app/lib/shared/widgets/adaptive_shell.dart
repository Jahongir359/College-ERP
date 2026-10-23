import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import 'ice_nav_bar.dart';
import '../../core/theme/brand.dart';

/// Renders a bottom nav bar on phones (< 600px) and a side rail on tablets/desktop.
class AdaptiveShell extends StatelessWidget {
  final StatefulNavigationShell navigationShell;
  final List<IceNavItem> items;
  final String title;

  const AdaptiveShell({
    super.key,
    required this.navigationShell,
    required this.items,
    required this.title,
  });

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    if (width >= 600) {
      return _SidebarLayout(
        navigationShell: navigationShell,
        items: items,
        title: title,
      );
    }
    return Scaffold(
      body: navigationShell,
      bottomNavigationBar: IceNavBar(
        selectedIndex: navigationShell.currentIndex,
        items: items,
        onTap: (i) => navigationShell.goBranch(
          i,
          initialLocation: i == navigationShell.currentIndex,
        ),
      ),
    );
  }
}

class _SidebarLayout extends StatelessWidget {
  final StatefulNavigationShell navigationShell;
  final List<IceNavItem> items;
  final String title;

  const _SidebarLayout({
    required this.navigationShell,
    required this.items,
    required this.title,
  });

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            selectedIndex: navigationShell.currentIndex,
            onDestinationSelected: (i) => navigationShell.goBranch(
              i,
              initialLocation: i == navigationShell.currentIndex,
            ),
            backgroundColor: context.brandDeep,
            selectedIconTheme: IconThemeData(
              color: context.brandHighlight,
              size: 24,
            ),
            unselectedIconTheme: IconThemeData(
              color: Colors.white.withAlpha(120),
              size: 22,
            ),
            selectedLabelTextStyle: TextStyle(
              color: context.brandHighlight,
              fontSize: 11,
              fontWeight: FontWeight.w700,
            ),
            unselectedLabelTextStyle: TextStyle(
              color: Colors.white.withAlpha(100),
              fontSize: 10,
            ),
            labelType: NavigationRailLabelType.all,
            indicatorColor: Colors.white.withAlpha(15),
            leading: Padding(
              padding: const EdgeInsets.symmetric(vertical: 16),
              child: IceBrandLogo(
                size: 36,
                radius: 10,
                errorBuilder: (_, __, ___) => const Icon(
                  Icons.school_rounded,
                  color: Colors.white,
                  size: 32,
                ),
              ),
            ),
            destinations: items
                .map(
                  (item) => NavigationRailDestination(
                    icon: Icon(item.icon),
                    selectedIcon: Icon(item.activeIcon),
                    label: Text(item.label),
                  ),
                )
                .toList(),
          ),
          const VerticalDivider(
            width: 1,
            thickness: 1,
            color: Color(0xFF073B42),
          ),
          Expanded(child: navigationShell),
        ],
      ),
    );
  }
}
