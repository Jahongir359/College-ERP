import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../core/theme/brand.dart';
import '../../core/theme/ice_tokens.dart';
import '../../core/theme/ice_type.dart';
import '../../shared/widgets/ice_kit.dart';

/// Route of the component sheet. Registered only when [kDebugMode] is true.
const componentSheetPath = '/debug/components';

/// Debug-only "component sheet" (plan PD.1): the design rules of section 6.2
/// rendered with the real widgets, for both brands in light and dark.
///
/// Open `/debug/components?brand=school&dark=1` in a debug build. Not in
/// release builds, so its text is English only and not translated.
class ComponentSheetScreen extends StatefulWidget {
  const ComponentSheetScreen({
    super.key,
    this.school = true,
    this.dark = false,
  });

  final bool school;
  final bool dark;

  factory ComponentSheetScreen.fromState(GoRouterState state) {
    final q = state.uri.queryParameters;
    return ComponentSheetScreen(
      school: q['brand'] != 'center',
      dark: q['dark'] == '1',
    );
  }

  @override
  State<ComponentSheetScreen> createState() => _ComponentSheetScreenState();
}

class _ComponentSheetScreenState extends State<ComponentSheetScreen> {
  late bool _school = widget.school;
  late bool _dark = widget.dark;

  @override
  Widget build(BuildContext context) {
    assert(kDebugMode, 'The component sheet is for debug builds only.');
    final brand = _school ? IceBrand.school : IceBrand.center;
    return Theme(
      data: buildIceTheme(dark: _dark, accent: IceAccents.ice, brand: brand),
      child: Builder(
        builder: (context) {
          final t = context.ice;
          return Scaffold(
            backgroundColor: t.bg,
            body: SafeArea(
              child: ListView(
                padding: const EdgeInsets.fromLTRB(
                  IceSpace.gutter,
                  IceSpace.md,
                  IceSpace.gutter,
                  IceSpace.xxl,
                ),
                children: [
                  _Switches(
                    school: _school,
                    dark: _dark,
                    onSchool: (v) => setState(() => _school = v),
                    onDark: (v) => setState(() => _dark = v),
                  ),
                  const SizedBox(height: IceSpace.md),
                  const _Header(),
                  const _Section('Type scale', _TypeScale()),
                  const _Section('Colours', _Swatches()),
                  const _Section('Buttons', _Buttons()),
                  const _Section('Chips', _Chips()),
                  const _Section('Cards', _Cards()),
                  const _Section('Status pills', _Pills()),
                  const _Section('Empty and error states', _States()),
                  const _Section('Spacing', _Spacing()),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

class _Switches extends StatelessWidget {
  const _Switches({
    required this.school,
    required this.dark,
    required this.onSchool,
    required this.onDark,
  });

  final bool school;
  final bool dark;
  final ValueChanged<bool> onSchool;
  final ValueChanged<bool> onDark;

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: IceSpace.xs,
      runSpacing: IceSpace.xs,
      children: [
        IceChipTabs(
          tabs: const ['School', 'Study Center'],
          index: school ? 0 : 1,
          onChanged: (i) => onSchool(i == 0),
        ),
        IceChipTabs(
          tabs: const ['Light', 'Dark'],
          index: dark ? 1 : 0,
          onChanged: (i) => onDark(i == 1),
        ),
      ],
    );
  }
}

class _Section extends StatelessWidget {
  const _Section(this.title, this.child);

  final String title;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Padding(
      padding: const EdgeInsets.only(top: IceSpace.xl),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title.toUpperCase(),
            style: IceType.text(
              size: IceType.caption,
              weight: FontWeight.w800,
              color: t.textMid,
            ).copyWith(letterSpacing: 1.2),
          ),
          const SizedBox(height: IceSpace.sm),
          child,
        ],
      ),
    );
  }
}

/// Maroon (or navy) gradient header with the active child chip in gold.
class _Header extends StatelessWidget {
  const _Header();

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final hero = t.onHero;
    return Container(
      padding: const EdgeInsets.all(IceSpace.lg),
      decoration: BoxDecoration(
        gradient: t.heroGradient,
        borderRadius: BorderRadius.circular(IceTokens.r),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Xayrli tong, Dilnoza',
            style: IceType.headline(t.brand, color: Colors.white),
          ),
          const SizedBox(height: IceSpace.xxs),
          Text(
            'Seshanba, 3-sentabr',
            style: IceType.text(size: IceType.label, color: hero.mint),
          ),
          const SizedBox(height: IceSpace.md),
          const Wrap(
            spacing: IceSpace.xs,
            runSpacing: IceSpace.xs,
            children: [
              _ChildChip('Malika · 3-A', active: true),
              _ChildChip('Sardor · 1-B'),
            ],
          ),
        ],
      ),
    );
  }
}

class _ChildChip extends StatelessWidget {
  const _ChildChip(this.label, {this.active = false});

  final String label;
  final bool active;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Container(
      constraints: const BoxConstraints(minHeight: IceSpace.minTap),
      padding: const EdgeInsets.symmetric(horizontal: IceSpace.sm),
      decoration: BoxDecoration(
        color: active ? Colors.white : Colors.white.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(999),
        border: Border.all(
          color: active ? t.highlight : Colors.white.withValues(alpha: 0.18),
          width: active ? 2 : 1,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircleAvatar(
            radius: 14,
            backgroundColor: t.highlightSoft,
            child: Text(
              label.substring(0, 1),
              style: IceType.text(
                size: IceType.caption,
                weight: FontWeight.w800,
                color: t.brand.isSchool ? SchoolColors.primaryDeep : t.onAccent,
              ),
            ),
          ),
          const SizedBox(width: IceSpace.xs),
          Text(
            label,
            style: IceType.text(
              size: IceType.label,
              weight: FontWeight.w600,
              color: active ? t.cardHi : Colors.white,
            ),
          ),
        ],
      ),
    );
  }
}

class _TypeScale extends StatelessWidget {
  const _TypeScale();

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    Widget row(String name, double size, TextStyle style) => Padding(
      padding: const EdgeInsets.only(bottom: IceSpace.xs),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.baseline,
        textBaseline: TextBaseline.alphabetic,
        children: [
          SizedBox(
            width: 92,
            child: Text(
              '$name ${size.toInt()}',
              style: IceType.text(size: IceType.caption, color: t.textLow),
            ),
          ),
          Expanded(child: Text('Sinf jadvali', style: style)),
        ],
      ),
    );
    return IceCard(
      radius: IceTokens.r,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          row(
            'Display',
            IceType.display,
            IceType.headline(t.brand, color: t.textHi),
          ),
          row(
            'Title',
            IceType.title,
            IceType.headline(t.brand, size: IceType.title, color: t.textHi),
          ),
          row(
            'Heading',
            IceType.heading,
            IceType.headline(t.brand, size: IceType.heading, color: t.textHi),
          ),
          row('Body', IceType.body, IceType.text(color: t.textHi)),
          row(
            'Label',
            IceType.label,
            IceType.text(size: IceType.label, color: t.textMid),
          ),
          row(
            'Caption',
            IceType.caption,
            IceType.text(size: IceType.caption, color: t.textMid),
          ),
          const SizedBox(height: IceSpace.xs),
          Text(
            'Расписание класса',
            style: IceType.headline(
              t.brand,
              size: IceType.title,
              color: t.textHi,
            ),
          ),
          const SizedBox(height: IceSpace.xs),
          Row(
            children: [
              Text('08:12', style: IceType.headline(t.brand, color: t.textHi)),
              const Spacer(),
              Text(
                '1 110 000\n  987 500',
                textAlign: TextAlign.right,
                style: IceType.text(
                  size: IceType.label,
                  color: t.textMid,
                  numbers: true,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _Swatches extends StatelessWidget {
  const _Swatches();

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final swatches = <(String, Color)>[
      ('accent', t.accent),
      ('highlight', t.highlight),
      ('highlightInk', t.highlightInk),
      ('highlightSoft', t.highlightSoft),
      ('coral', t.coral),
      ('sky', t.sky),
      ('amber', t.amber),
      ('stroke', t.stroke),
    ];
    return Wrap(
      spacing: IceSpace.xs,
      runSpacing: IceSpace.xs,
      children: [
        for (final (name, c) in swatches)
          SizedBox(
            width: 80,
            child: Column(
              children: [
                Container(
                  height: 40,
                  decoration: BoxDecoration(
                    color: c,
                    borderRadius: BorderRadius.circular(IceTokens.rSm),
                    border: Border.all(color: t.stroke),
                  ),
                ),
                const SizedBox(height: IceSpace.xxs),
                Text(name, style: IceType.text(size: 11, color: t.textMid)),
              ],
            ),
          ),
      ],
    );
  }
}

class _Buttons extends StatelessWidget {
  const _Buttons();

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Column(
      children: [
        IceButton('Saqlash', icon: Icons.check_rounded, onPressed: () {}),
        const SizedBox(height: IceSpace.sm),
        IceButton('Bekor qilish', secondary: true, onPressed: () {}),
        const SizedBox(height: IceSpace.sm),
        const IceButton('Saqlash', busy: true),
        const SizedBox(height: IceSpace.sm),
        const IceButton('Disabled'),
        const SizedBox(height: IceSpace.sm),
        Row(
          children: [
            OutlinedButton(
              onPressed: () {},
              style: OutlinedButton.styleFrom(
                minimumSize: const Size(IceSpace.minTap, IceSpace.minTap),
                foregroundColor: t.accentInk,
                side: BorderSide(color: t.stroke),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(IceTokens.rSm),
                ),
              ),
              child: const Text('Outlined'),
            ),
            const SizedBox(width: IceSpace.xs),
            TextButton(
              onPressed: () {},
              style: TextButton.styleFrom(
                minimumSize: const Size(IceSpace.minTap, IceSpace.minTap),
                foregroundColor: t.accentInk,
              ),
              child: const Text('Text button'),
            ),
          ],
        ),
      ],
    );
  }
}

class _Chips extends StatefulWidget {
  const _Chips();

  @override
  State<_Chips> createState() => _ChipsState();
}

class _ChipsState extends State<_Chips> {
  int _i = 0;

  @override
  Widget build(BuildContext context) {
    return IceChipTabs(
      tabs: const ['Bu hafta', 'Keyingi hafta', 'Hammasi'],
      index: _i,
      onChanged: (i) => setState(() => _i = i),
    );
  }
}

class _Cards extends StatelessWidget {
  const _Cards();

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Column(
      children: [
        IceCard(
          radius: IceTokens.r,
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Matematika',
                      style: IceType.text(
                        size: IceType.body,
                        weight: FontWeight.w700,
                        color: t.textHi,
                      ),
                    ),
                    Text(
                      '2-chorak bahosi',
                      style: IceType.text(
                        size: IceType.label,
                        color: t.textMid,
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                width: 48,
                height: 48,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: t.highlightSoft,
                  shape: BoxShape.circle,
                  border: Border.all(color: t.highlight, width: 2),
                ),
                child: Text(
                  '5',
                  style: IceType.headline(
                    t.brand,
                    size: IceType.title,
                    color: t.brand.isSchool
                        ? SchoolColors.primaryDeep
                        : t.onAccent,
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: IceSpace.sm),
        IceCard(
          hero: true,
          radius: IceTokens.r,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                "To'lanadigan summa",
                style: IceType.text(size: IceType.label, color: t.onHero.mint),
              ),
              const SizedBox(height: IceSpace.xxs),
              Text(
                '[summa]',
                style: IceType.headline(t.brand, color: Colors.white),
              ),
            ],
          ),
        ),
        const SizedBox(height: IceSpace.sm),
        ActionTile(
          icon: Icons.menu_book_outlined,
          title: 'Uy vazifalari',
          subtitle: '3 ta vazifa ertaga',
          onTap: () {},
        ),
      ],
    );
  }
}

class _Pills extends StatelessWidget {
  const _Pills();

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final d = t.isDark;
    return Wrap(
      spacing: IceSpace.xs,
      runSpacing: IceSpace.xs,
      children: [
        _Pill(
          Icons.check_rounded,
          'Keldi 08:12',
          d ? SchoolColors.darkPresent : SchoolColors.present,
          d ? SchoolColors.darkPresentBg : SchoolColors.presentBg,
        ),
        _Pill(
          Icons.schedule_rounded,
          'Kechikdi 08:41',
          d ? SchoolColors.darkLate : SchoolColors.late,
          d ? SchoolColors.darkLateBg : SchoolColors.lateBg,
        ),
        _Pill(
          Icons.close_rounded,
          'Kelmadi',
          d ? SchoolColors.darkAbsent : SchoolColors.absent,
          d ? SchoolColors.darkAbsentBg : SchoolColors.absentBg,
        ),
        _Pill(
          Icons.emoji_events_outlined,
          'Eng yaxshi',
          t.isDark ? t.highlightInk : SchoolColors.primaryDeep,
          t.isDark ? t.highlightInk.withValues(alpha: 0.16) : t.highlightSoft,
        ),
        const StatusBadge('accent', tone: BadgeTone.accent),
        const StatusBadge('coral', tone: BadgeTone.coral),
        const StatusBadge('sky', tone: BadgeTone.sky),
        const StatusBadge('amber', tone: BadgeTone.amber),
        const StatusBadge('neutral'),
      ],
    );
  }
}

class _Pill extends StatelessWidget {
  const _Pill(this.icon, this.label, this.fg, this.bg);

  final IconData icon;
  final String label;
  final Color fg;
  final Color bg;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 15, color: fg),
          const SizedBox(width: 5),
          Text(
            label,
            style: IceType.text(
              size: 12.5,
              weight: FontWeight.w700,
              color: fg,
              numbers: true,
            ),
          ),
        ],
      ),
    );
  }
}

class _States extends StatelessWidget {
  const _States();

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const IceCard(
          radius: IceTokens.r,
          padding: EdgeInsets.zero,
          child: EmptyState(
            icon: Icons.event_available_outlined,
            title: "Bugun dars yo'q",
            message: 'Dam olish kuni. Jadval dushanba kuni yangilanadi.',
          ),
        ),
        const SizedBox(height: IceSpace.sm),
        IceCard(
          radius: IceTokens.r,
          padding: EdgeInsets.zero,
          child: ErrorState(error: 'SocketException', onRetry: () {}),
        ),
        const SizedBox(height: IceSpace.sm),
        IceCard(
          radius: IceTokens.r,
          padding: EdgeInsets.zero,
          child: ErrorState(error: 'HTTP 500', onRetry: () {}),
        ),
        const SizedBox(height: IceSpace.sm),
        const IceCard(
          radius: IceTokens.r,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SkeletonBox(height: 18, width: 160),
              SizedBox(height: IceSpace.xs),
              SkeletonBox(height: 14),
            ],
          ),
        ),
      ],
    );
  }
}

class _Spacing extends StatelessWidget {
  const _Spacing();

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    const steps = <(String, double)>[
      ('xxs', IceSpace.xxs),
      ('xs', IceSpace.xs),
      ('sm', IceSpace.sm),
      ('md', IceSpace.md),
      ('lg', IceSpace.lg),
      ('xl', IceSpace.xl),
      ('xxl', IceSpace.xxl),
      ('minTap', IceSpace.minTap),
    ];
    return Column(
      children: [
        for (final (name, v) in steps)
          Padding(
            padding: const EdgeInsets.only(bottom: IceSpace.xxs),
            child: Row(
              children: [
                SizedBox(
                  width: 92,
                  child: Text(
                    '$name ${v.toInt()}',
                    style: IceType.text(
                      size: IceType.caption,
                      color: t.textMid,
                      numbers: true,
                    ),
                  ),
                ),
                Container(
                  width: v * 2,
                  height: 10,
                  decoration: BoxDecoration(
                    color: t.accent,
                    borderRadius: BorderRadius.circular(3),
                  ),
                ),
              ],
            ),
          ),
      ],
    );
  }
}
