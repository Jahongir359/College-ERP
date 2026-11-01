import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/auth/auth_state.dart';
import '../../core/i18n/strings.dart';
import '../../core/settings/app_settings.dart';
import '../../core/theme/brand.dart';
import '../../core/theme/ice_tokens.dart';
import 'parent_data.dart';
import 'parent_format.dart';

/// Gold accents of the School brand (eyebrows, the chosen child).
Color parentGold(IceTokens t) =>
    t.isDark ? const Color(0xFFE2C36F) : const Color(0xFF8A5A10);
const _goldRing = Color(0xFFD4A84B);

/// Parent Home (plan P4.4, mockups 04/05): a maroon header with the child
/// switcher, then today for the chosen child — arrival, the lesson on now,
/// homework due, money owed, an unread teacher message and the latest
/// announcement.
class ParentHomeScreen extends ConsumerWidget {
  const ParentHomeScreen({super.key});

  /// The page is a phone column; on a laptop it stays this wide, centred.
  static const maxWidth = 560.0;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final children = ref.watch(parentChildrenProvider);
    final child = ref.watch(selectedChildProvider);
    final today = child == null
        ? null
        : ref.watch(parentTodayProvider(child.id));

    return ColoredBox(
      color: t.bg,
      child: RefreshIndicator(
        color: t.accent,
        onRefresh: () async {
          if (child != null) {
            ref.invalidate(parentTodayProvider(child.id));
            await ref.read(parentTodayProvider(child.id).future);
          }
          await ref.read(authProvider.notifier).refreshMe();
        },
        child: ListView(
          key: const ValueKey('parent-home'),
          padding: EdgeInsets.zero,
          physics: const AlwaysScrollableScrollPhysics(),
          children: [
            Stack(
              children: [
                const Positioned(
                  left: 0,
                  right: 0,
                  top: 0,
                  height: _ParentHeader.height,
                  child: _HeaderBackground(),
                ),
                Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: maxWidth),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 16),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          _ParentHeader(children: children, selected: child),
                          if (child == null)
                            _NoChildren(s: s)
                          else
                            ...switch (today) {
                              AsyncData(:final value) => _cards(
                                context,
                                s,
                                child,
                                value,
                              ),
                              AsyncError() => [
                                _LoadError(
                                  s: s,
                                  onRetry: () => ref.invalidate(
                                    parentTodayProvider(child.id),
                                  ),
                                ),
                              ],
                              _ => const [_Loading()],
                            },
                          const SizedBox(height: 24),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  List<Widget> _cards(
    BuildContext context,
    S s,
    ParentChildInfo child,
    ParentToday today,
  ) {
    if (today.allFailed) {
      return [
        _LoadError(
          s: s,
          onRetry: () =>
              ProviderScope.containerOf(context)
                  .invalidate(parentTodayProvider(child.id)),
        ),
      ];
    }
    return [
      _TodayCard(today: today),
      const SizedBox(height: 14),
      IntrinsicHeight(
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Expanded(child: _HomeworkTile(homework: today.homework)),
            const SizedBox(width: 14),
            Expanded(
              child: _PaymentTile(
                invoice: today.invoice,
                loaded: today.invoiceLoaded,
              ),
            ),
          ],
        ),
      ),
      if (today.message != null) ...[
        const SizedBox(height: 14),
        _MessageCard(message: today.message!),
      ],
      if (today.announcement != null) ...[
        const SizedBox(height: 14),
        _AnnouncementCard(
          announcement: today.announcement!,
          className: child.className,
        ),
      ],
    ];
  }
}

// ── Header ───────────────────────────────────────────────────────────────────

class _HeaderBackground extends StatelessWidget {
  const _HeaderBackground();

  @override
  Widget build(BuildContext context) {
    return DecoratedBox(
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topRight,
          end: Alignment.bottomLeft,
          colors: [
            SchoolColors.primaryHover,
            SchoolColors.primary,
            SchoolColors.primaryDeep,
          ],
        ),
      ),
      child: Align(
        alignment: Alignment.topRight,
        child: Padding(
          padding: const EdgeInsets.only(top: 40),
          child: Opacity(
            opacity: 0.07,
            child: Image.asset(
              IceBrandLogo.schoolCrestAsset,
              height: 300,
              errorBuilder: (_, __, ___) => const SizedBox(),
            ),
          ),
        ),
      ),
    );
  }
}

class _ParentHeader extends ConsumerWidget {
  const _ParentHeader({required this.children, required this.selected});

  /// How far the maroon reaches; the Today card overlaps its bottom.
  static const height = 300.0;

  final List<ParentChildInfo> children;
  final ParentChildInfo? selected;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(stringsProvider);
    final hour = ref.watch(parentClockProvider)().hour;
    final greeting = hour < 12
        ? s('Good Morning')
        : (hour < 18 ? s('Good Afternoon') : s('Good Evening'));
    final unread = ref.watch(
      parentUnreadNotificationsProvider.select((v) => v.valueOrNull ?? 0),
    );

    return SafeArea(
      bottom: false,
      child: Padding(
        padding: const EdgeInsets.only(top: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Image.asset(
                  'assets/images/brand/school/logo-h-white.png',
                  height: 34,
                  semanticLabel: IceBrand.school.appTitle,
                  errorBuilder: (_, __, ___) => Text(
                    IceBrand.school.appTitle,
                    style: const TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.w800,
                    ),
                  ),
                ),
                const Spacer(),
                IconButton(
                  key: const ValueKey('parent-bell'),
                  tooltip: s('Notifications'),
                  onPressed: () => context.go('/parent/messages'),
                  icon: Stack(
                    clipBehavior: Clip.none,
                    children: [
                      const Icon(
                        Icons.notifications_none_rounded,
                        color: Colors.white,
                        size: 27,
                      ),
                      if (unread > 0)
                        Positioned(
                          right: 1,
                          top: 1,
                          child: Container(
                            width: 9,
                            height: 9,
                            decoration: BoxDecoration(
                              color: _goldRing,
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: SchoolColors.primary,
                                width: 1.5,
                              ),
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 18),
            Text(
              '$greeting!',
              style: const TextStyle(
                color: Colors.white,
                fontSize: 30,
                fontWeight: FontWeight.w800,
                letterSpacing: -0.5,
              ),
            ),
            const SizedBox(height: 16),
            if (children.isNotEmpty)
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                clipBehavior: Clip.none,
                child: Row(
                  children: [
                    for (final c in children) ...[
                      _ChildChip(child: c, selected: c.id == selected?.id),
                      const SizedBox(width: 10),
                    ],
                  ],
                ),
              ),
            const SizedBox(height: 22),
          ],
        ),
      ),
    );
  }
}

class _ChildChip extends ConsumerWidget {
  const _ChildChip({required this.child, required this.selected});

  final ParentChildInfo child;
  final bool selected;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final label = child.className.isEmpty
        ? child.firstName
        : '${child.firstName} · ${child.className}';
    return Semantics(
      button: true,
      selected: selected,
      child: Material(
        color: selected ? Colors.white : Colors.white.withValues(alpha: 0.12),
        shape: StadiumBorder(
          side: BorderSide(
            color: selected ? _goldRing : Colors.white.withValues(alpha: 0.28),
            width: selected ? 3 : 1,
          ),
        ),
        child: InkWell(
          key: ValueKey('child-chip-${child.id}'),
          customBorder: const StadiumBorder(),
          onTap: () => selectChild(ref, child.id),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(6, 6, 16, 6),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                CircleAvatar(
                  radius: 17,
                  backgroundColor: selected
                      ? const Color(0xFFE9C77D)
                      : const Color(0xFFF4ECEB),
                  child: Text(
                    child.initials,
                    style: const TextStyle(
                      color: SchoolColors.primary,
                      fontWeight: FontWeight.w800,
                      fontSize: 13,
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  label,
                  style: TextStyle(
                    color: selected ? SchoolColors.text : Colors.white,
                    fontWeight: FontWeight.w700,
                    fontSize: 15,
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ── Cards ───────────────────────────────────────────────────────────────────

class _Card extends StatelessWidget {
  const _Card({super.key, required this.child, this.padding, this.leftAccent});

  final Widget child;
  final EdgeInsets? padding;
  final Color? leftAccent;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final radius = BorderRadius.circular(24);
    return Container(
      decoration: BoxDecoration(
        color: t.card,
        borderRadius: radius,
        border: Border.all(color: t.stroke),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: t.isDark ? 0.25 : 0.06),
            blurRadius: 18,
            offset: const Offset(0, 6),
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: radius,
        child: Container(
          decoration: leftAccent == null
              ? null
              : BoxDecoration(
                  border: Border(
                    left: BorderSide(color: leftAccent!, width: 5),
                  ),
                ),
          padding: padding ?? const EdgeInsets.all(20),
          child: child,
        ),
      ),
    );
  }
}

class _IconBox extends StatelessWidget {
  const _IconBox(this.icon, {this.filled = false});

  final IconData icon;
  final bool filled;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Container(
      width: 52,
      height: 52,
      decoration: BoxDecoration(
        gradient: filled
            ? const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [SchoolColors.primaryHover, SchoolColors.primary],
              )
            : null,
        color: filled ? null : t.inset,
        borderRadius: BorderRadius.circular(16),
      ),
      child: Icon(
        icon,
        size: 24,
        color: filled
            ? const Color(0xFFE9C77D)
            : (t.isDark ? SchoolColors.ink : SchoolColors.primary),
      ),
    );
  }
}

class _Eyebrow extends StatelessWidget {
  const _Eyebrow(this.text);

  final String text;

  @override
  Widget build(BuildContext context) {
    return Text(
      text.toUpperCase(),
      style: TextStyle(
        color: parentGold(context.ice),
        fontSize: 12.5,
        fontWeight: FontWeight.w800,
        letterSpacing: 1.6,
      ),
    );
  }
}

class _TodayCard extends ConsumerWidget {
  const _TodayCard({required this.today});

  final ParentToday today;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final lang = ref.watch(appSettingsProvider.select((a) => a.language));
    final now = ref.watch(parentClockProvider)();

    return _Card(
      key: const ValueKey('today-card'),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Eyebrow('${s('Today')} · ${weekdayDate(lang, now)}'),
          const SizedBox(height: 14),
          _ArrivalRow(attendance: today.attendance),
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 16),
            child: Divider(height: 1, color: t.stroke),
          ),
          _LessonRow(lessons: today.lessons),
        ],
      ),
    );
  }
}

class _ArrivalRow extends ConsumerWidget {
  const _ArrivalRow({required this.attendance});

  final TodayAttendance? attendance;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final a = attendance;
    final time = a?.arrivalTime;
    final (label, icon, fg, bg) = switch (a?.status) {
      ArrivalStatus.present => (
        time == null ? s('Arrived') : '${s('Arrived')} $time',
        Icons.check_rounded,
        t.isDark ? const Color(0xFF86D9A0) : const Color(0xFF1D7A3E),
        t.isDark ? const Color(0xFF12301C) : const Color(0xFFE2F4E7),
      ),
      ArrivalStatus.late => (
        time == null ? s('Late') : '${s('Late')} $time',
        Icons.schedule_rounded,
        t.isDark ? const Color(0xFFF2C46B) : const Color(0xFF8A5A10),
        t.isDark ? const Color(0xFF33260F) : const Color(0xFFFBF0DA),
      ),
      ArrivalStatus.absent => (
        s('Absent'),
        Icons.close_rounded,
        t.isDark ? const Color(0xFFF2A39A) : const Color(0xFFB3261E),
        t.isDark ? const Color(0xFF3A1513) : const Color(0xFFFBE6E4),
      ),
      ArrivalStatus.notMarked => (
        s('Not marked yet'),
        Icons.more_horiz_rounded,
        t.textMid,
        t.inset,
      ),
      null => (
        s('Could not load'),
        Icons.cloud_off_rounded,
        t.textMid,
        t.inset,
      ),
    };
    final marked = a != null && a.status != ArrivalStatus.notMarked;
    return Row(
      children: [
        Container(
          key: const ValueKey('arrival-pill'),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
          decoration: BoxDecoration(
            color: bg,
            borderRadius: BorderRadius.circular(99),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, size: 17, color: fg),
              const SizedBox(width: 6),
              Text(
                label,
                style: TextStyle(
                  color: fg,
                  fontWeight: FontWeight.w800,
                  fontSize: 14.5,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(width: 10),
        if (marked)
          Expanded(
            child: Text(
              s('Marked by the homeroom teacher'),
              textAlign: TextAlign.end,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(color: t.textMid, fontSize: 13),
            ),
          ),
      ],
    );
  }
}

class _LessonRow extends ConsumerWidget {
  const _LessonRow({required this.lessons});

  final TodayLessons? lessons;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final l = lessons;
    final main = l?.main;

    String lessonNo(LessonSlot x) =>
        s('Lesson {n}').replaceAll('{n}', '${x.number}');

    final (String caption, String title) = switch (l?.phase) {
      LessonPhase.now => (
        '${s('Now')} · ${lessonNo(main!)}, ${main.start}–${main.end}',
        main.subject,
      ),
      LessonPhase.before || LessonPhase.between => (
        '${s('Next')} · ${lessonNo(main!)}, ${main.start}–${main.end}',
        main.subject,
      ),
      LessonPhase.done => (s('Today'), s('Lessons are over for today')),
      LessonPhase.none => (s('Today'), s('No lessons today')),
      null => (s('Timetable'), s('Could not load')),
    };
    final after = l?.phase == LessonPhase.now ? l?.after : null;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _IconBox(Icons.access_time_rounded, filled: true),
        const SizedBox(width: 16),
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(caption, style: TextStyle(color: t.textMid, fontSize: 13.5)),
              const SizedBox(height: 2),
              Text(
                title,
                key: const ValueKey('lesson-title'),
                style: TextStyle(
                  color: t.textHi,
                  fontSize: 21,
                  fontWeight: FontWeight.w800,
                ),
              ),
              if (after != null) ...[
                const SizedBox(height: 12),
                Text(
                  '${s('Then')}: ${after.subject} · ${after.start}',
                  style: TextStyle(color: t.textMid, fontSize: 14.5),
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }
}

class _HomeworkTile extends ConsumerWidget {
  const _HomeworkTile({required this.homework});

  final HomeworkDue? homework;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final lang = ref.watch(appSettingsProvider.select((a) => a.language));
    final now = ref.watch(parentClockProvider)();
    final h = homework;

    String when(DateTime d) {
      final today = DateTime(now.year, now.month, now.day);
      final days = d.difference(today).inDays;
      if (days == 0) return s('today');
      if (days == 1) return s('tomorrow');
      return shortDate(lang, d);
    }

    return _Card(
      key: const ValueKey('homework-tile'),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _IconBox(Icons.menu_book_outlined),
          const SizedBox(height: 18),
          Text(
            h == null ? '–' : '${h.count}',
            style: TextStyle(
              color: t.textHi,
              fontSize: 26,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 2),
          Text(switch (h) {
            null => s('Could not load'),
            HomeworkDue(count: 0) => s('No homework due'),
            final h => '${s('homework due')} · ${when(h.nextDue!)}',
          }, style: TextStyle(color: t.textMid, fontSize: 14.5)),
        ],
      ),
    );
  }
}

class _PaymentTile extends ConsumerWidget {
  const _PaymentTile({required this.invoice, required this.loaded});

  final UnpaidInvoice? invoice;
  final bool loaded;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final lang = ref.watch(appSettingsProvider.select((a) => a.language));
    final inv = invoice;

    return _Card(
      key: const ValueKey('payment-tile'),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _IconBox(Icons.account_balance_wallet_outlined),
          const SizedBox(height: 18),
          Text(
            !loaded
                ? '–'
                : inv == null
                ? s('Paid')
                : monthName(lang, inv.period),
            style: TextStyle(
              color: t.textHi,
              fontSize: 21,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            !loaded
                ? s('Could not load')
                : inv == null
                ? s('Nothing to pay')
                : '${groupedAmount(inv.amountDue)} ${s('soum')}',
            style: TextStyle(color: t.textMid, fontSize: 14.5),
          ),
          if (inv?.dueDate case final due?) ...[
            const SizedBox(height: 6),
            Text(
              inv!.overdue
                  ? s('Overdue since {date}')
                        .replaceAll('{date}', shortDate(lang, due))
                  : s('Due {date}').replaceAll('{date}', shortDate(lang, due)),
              style: TextStyle(
                color: inv.overdue
                    ? (t.isDark
                          ? const Color(0xFFF2A39A)
                          : const Color(0xFFB3261E))
                    : parentGold(t),
                fontSize: 14,
                fontWeight: FontWeight.w800,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _MessageCard extends ConsumerWidget {
  const _MessageCard({required this.message});

  final TeacherMessage message;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    return _Card(
      key: const ValueKey('message-card'),
      padding: const EdgeInsets.fromLTRB(20, 18, 20, 18),
      child: Row(
        children: [
          const _IconBox(Icons.chat_bubble_outline_rounded),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  message.teacher,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    color: t.textHi,
                    fontSize: 17,
                    fontWeight: FontWeight.w800,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  message.preview,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(color: t.textMid, fontSize: 14.5),
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          Container(
            constraints: const BoxConstraints(minWidth: 28),
            height: 28,
            padding: const EdgeInsets.symmetric(horizontal: 8),
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: t.isDark ? SchoolColors.darkFill : SchoolColors.primary,
              borderRadius: BorderRadius.circular(99),
            ),
            child: Text(
              '${message.unread}',
              style: const TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _AnnouncementCard extends ConsumerWidget {
  const _AnnouncementCard({
    required this.announcement,
    required this.className,
  });

  final Announcement announcement;
  final String className;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final lines = announcement.message.trim().split('\n');
    final rest = lines.skip(1).join(' ').trim();
    return _Card(
      key: const ValueKey('announcement-card'),
      leftAccent: _goldRing,
      padding: const EdgeInsets.fromLTRB(22, 18, 20, 18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _Eyebrow(
            className.isEmpty
                ? s('Announcement')
                : '${s('Announcement')} · $className',
          ),
          const SizedBox(height: 6),
          Text(
            lines.first,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              color: t.textHi,
              fontSize: 18,
              fontWeight: FontWeight.w800,
            ),
          ),
          if (rest.isNotEmpty) ...[
            const SizedBox(height: 2),
            Text(
              rest,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(color: t.textMid, fontSize: 14.5),
            ),
          ],
        ],
      ),
    );
  }
}

// ── Empty, loading, error ───────────────────────────────────────────────────

class _NoChildren extends StatelessWidget {
  const _NoChildren({required this.s});

  final S s;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return _Card(
      key: const ValueKey('no-children'),
      child: Column(
        children: [
          Icon(Icons.family_restroom_rounded, size: 40, color: parentGold(t)),
          const SizedBox(height: 12),
          Text(
            s('No children are linked to your account yet.'),
            textAlign: TextAlign.center,
            style: TextStyle(
              color: t.textHi,
              fontSize: 16,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            s('Please contact the school office.'),
            textAlign: TextAlign.center,
            style: TextStyle(color: t.textMid, fontSize: 14),
          ),
        ],
      ),
    );
  }
}

class _Loading extends StatelessWidget {
  const _Loading();

  @override
  Widget build(BuildContext context) {
    return _Card(
      child: SizedBox(
        height: 160,
        child: Center(
          child: CircularProgressIndicator(color: context.ice.accent),
        ),
      ),
    );
  }
}

class _LoadError extends StatelessWidget {
  const _LoadError({required this.s, required this.onRetry});

  final S s;
  final VoidCallback onRetry;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return _Card(
      key: const ValueKey('load-error'),
      child: Column(
        children: [
          Icon(Icons.cloud_off_rounded, size: 36, color: t.textMid),
          const SizedBox(height: 10),
          Text(
            s('Could not load. Check your internet and try again.'),
            textAlign: TextAlign.center,
            style: TextStyle(color: t.textHi, fontSize: 15),
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: onRetry,
            style: FilledButton.styleFrom(
              backgroundColor: t.accent,
              foregroundColor: t.onAccent,
            ),
            child: Text(s('Try again')),
          ),
        ],
      ),
    );
  }
}
