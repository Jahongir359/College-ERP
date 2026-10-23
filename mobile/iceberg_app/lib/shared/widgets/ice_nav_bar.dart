import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../core/theme/app_theme.dart';
import '../../core/theme/brand.dart';

class IceNavBar extends StatelessWidget {
  final int selectedIndex;
  final List<IceNavItem> items;
  final ValueChanged<int> onTap;

  const IceNavBar({
    super.key,
    required this.selectedIndex,
    required this.items,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.sizeOf(context).width;
    final useScroll = items.length > 5;
    final itemWidth = useScroll ? 72.0 : screenWidth / items.length;

    Widget buildItem(int i) {
      final selected = i == selectedIndex;
      return GestureDetector(
        onTap: () {
          HapticFeedback.selectionClick();
          onTap(i);
        },
        behavior: HitTestBehavior.opaque,
        child: SizedBox(
          width: useScroll ? itemWidth : null,
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 4),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Icon
                AnimatedSwitcher(
                  duration: const Duration(milliseconds: 200),
                  child: Icon(
                    selected ? items[i].activeIcon : items[i].icon,
                    key: ValueKey(selected),
                    size: 22,
                    color: selected ? context.brandPrimary : IceColors.muted,
                  ),
                ),
                const SizedBox(height: 3),
                // Label
                AnimatedDefaultTextStyle(
                  duration: const Duration(milliseconds: 200),
                  style: TextStyle(
                    fontSize: 9,
                    fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
                    color: selected ? context.brandPrimary : IceColors.muted,
                  ),
                  child: Text(
                    items[i].label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                const SizedBox(height: 4),
                // Active indicator: small lime dot below label
                AnimatedContainer(
                  duration: const Duration(milliseconds: 250),
                  width: selected ? 6 : 0,
                  height: selected ? 6 : 0,
                  decoration: BoxDecoration(
                    color: context.brandHighlight,
                    shape: BoxShape.circle,
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    }

    return RepaintBoundary(
      child: Container(
      decoration: const BoxDecoration(
        color: Colors.white,
        boxShadow: [
          BoxShadow(
            color: Color(0x18000000),
            blurRadius: 8,
            offset: Offset(0, -2),
          ),
        ],
      ),
      child: SafeArea(
        top: false,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 4),
          child: useScroll
              ? SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(children: List.generate(items.length, buildItem)),
                )
              : Row(
                  children: List.generate(
                    items.length,
                    (i) => Expanded(child: buildItem(i)),
                  ),
                ),
        ),
      ),
    ));
  }
}

class IceNavItem {
  final IconData icon;
  final IconData activeIcon;
  final String label;
  const IceNavItem({
    required this.icon,
    required this.activeIcon,
    required this.label,
  });
}
