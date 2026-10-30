import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/i18n/strings.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Attendance Hub — overall rate, encouragement, streak/missed, monthly
/// calendar with Present/Late/Absent legend, 12-week trend and quick actions.
class StudentAttendanceScreen extends ConsumerStatefulWidget {
  const StudentAttendanceScreen({super.key});

  @override
  ConsumerState<StudentAttendanceScreen> createState() =>
      _StudentAttendanceScreenState();
}

class _StudentAttendanceScreenState
    extends ConsumerState<StudentAttendanceScreen> {
  DateTime _month = DateTime(DateTime.now().year, DateTime.now().month);
  int? _groupId;

  String get _key =>
      '${DateFormat('yyyy-MM').format(_month)}|${_groupId ?? ''}';

  @override
  Widget build(BuildContext context) {
    final summary = ref.watch(attendanceSummaryProvider(_key));

    return summary.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.invalidate(attendanceSummaryProvider(_key)),
      ),
      data: (d) => _buildHub(context, d),
    );
  }

  Widget _buildHub(BuildContext context, Map<String, dynamic> d) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final overall = (d['overall_rate'] as num?)?.toDouble();
    final streak = (d['streak_days'] as num?)?.toInt() ?? 0;
    final missed = (d['absent_count'] as num?)?.toInt() ?? 0;
    final days = (d['days'] as List?) ?? [];
    final weekly = (d['weekly_trend'] as List?) ?? [];
    final groups = (d['groups'] as List?) ?? [];
    final teachers = (d['teachers'] as List?) ?? [];

    final groupName = _groupId == null
        ? s('All courses')
        : (groups.firstWhere(
                (g) => g['id'] == _groupId,
                orElse: () => {'name': ''},
              )['name'] ??
              '');

    return IcePage(
      title: s('Attendance'),
      subtitle: groupName,
      backButton: true,
      onRefresh: () async =>
          ref.refresh(attendanceSummaryProvider(_key).future),
      action: groups.isEmpty
          ? null
          : _FilterButton(
              groups: groups,
              selected: _groupId,
              onChanged: (id) => setState(() => _groupId = id),
            ),
      children: [
        // ── Overall rate hero ────────────────────────────────────────────
        IceCard(
          hero: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              MicroLabel(s('Overall rate'), color: t.onHero.mint),
              const SizedBox(height: 8),
              Row(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(
                    overall != null
                        ? '${overall.toStringAsFixed(overall % 1 == 0 ? 0 : 1)}%'
                        : '—',
                    style: TextStyle(
                      fontSize: 40,
                      height: 1.0,
                      fontWeight: FontWeight.w800,
                      color: t.onHero.accent,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Padding(
                    padding: const EdgeInsets.only(bottom: 6),
                    child: Text(
                      s('Present'),
                      style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w600,
                        color: Colors.white.withValues(alpha: 0.8),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.symmetric(
                  horizontal: 14,
                  vertical: 12,
                ),
                decoration: BoxDecoration(
                  color: t.onHero.accent.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: t.onHero.accent.withValues(alpha: 0.25)),
                ),
                child: Row(
                  children: [
                    Icon(Icons.verified_outlined, size: 18, color: t.onHero.accent),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        _encouragement(s, overall),
                        style: TextStyle(
                          fontSize: 13.5,
                          fontWeight: FontWeight.w700,
                          color: t.onHero.accent,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // ── Streak / missed ──────────────────────────────────────────────
        Row(
          children: [
            Expanded(
              child: StatCard(
                icon: Icons.local_fire_department_outlined,
                value: '$streak',
                label: streak == 1 ? s('Day streak') : s('Days streak'),
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: StatCard(
                icon: Icons.warning_amber_rounded,
                iconColor: t.coral,
                value: '$missed',
                label: s('Missed total'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),

        // ── Calendar ─────────────────────────────────────────────────────
        IceCard(
          child: Column(
            children: [
              Row(
                children: [
                  Icon(
                    Icons.calendar_month_rounded,
                    size: 19,
                    color: t.textMid,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      DateFormat('MMMM yyyy').format(_month),
                      style: TextStyle(
                        fontSize: 17,
                        fontWeight: FontWeight.w800,
                        color: t.textHi,
                      ),
                    ),
                  ),
                  _RoundIconButton(
                    icon: Icons.chevron_left_rounded,
                    onTap: () => setState(
                      () => _month = DateTime(_month.year, _month.month - 1),
                    ),
                  ),
                  const SizedBox(width: 8),
                  _RoundIconButton(
                    icon: Icons.chevron_right_rounded,
                    onTap: () => setState(
                      () => _month = DateTime(_month.year, _month.month + 1),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 14),
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  _LegendDot(color: t.accent, label: s('Present')),
                  const SizedBox(width: 14),
                  _LegendDot(color: t.sky, label: s('Late')),
                  const SizedBox(width: 14),
                  _LegendDot(color: t.coral, label: s('Absent')),
                ],
              ),
              const SizedBox(height: 14),
              _MonthCalendar(month: _month, records: days),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // ── 12-week trend ────────────────────────────────────────────────
        IceCard(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.trending_up_rounded, size: 19, color: t.accent),
                  const SizedBox(width: 8),
                  Text(
                    s('12-Week Trend'),
                    style: TextStyle(
                      fontSize: 17,
                      fontWeight: FontWeight.w800,
                      color: t.textHi,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 18),
              SizedBox(height: 140, child: _WeeklyBars(weekly: weekly)),
              const SizedBox(height: 6),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text(
                    'WK 1',
                    style: TextStyle(fontSize: 10, color: t.textLow),
                  ),
                  Text(
                    'WK 12',
                    style: TextStyle(fontSize: 10, color: t.textLow),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 22),

        // ── Quick actions ────────────────────────────────────────────────
        SectionHeader(s('Quick Actions')),
        Row(
          children: [
            Expanded(
              child: _QuickAction(
                icon: Icons.description_outlined,
                label: s('Export Report'),
                onTap: () => _exportReport(context, d),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _QuickAction(
                icon: Icons.mail_outline_rounded,
                label: s('Email Teacher'),
                onTap: () => _emailTeacher(context, teachers),
              ),
            ),
          ],
        ),
      ],
    );
  }

  String _encouragement(S s, double? rate) {
    if (rate == null) return s('No attendance recorded yet.');
    if (rate >= 95) return s('Excellent consistency! Keep it up.');
    if (rate >= 85) return s('Great attendance — almost perfect!');
    if (rate >= 70) return s('Good effort. A few more days on time!');
    return s('Attendance needs attention — you can do this!');
  }

  void _exportReport(BuildContext context, Map<String, dynamic> d) {
    final t = context.ice;
    final buffer = StringBuffer()
      ..writeln('ICEBERG — Attendance report (${d['month']})')
      ..writeln('Overall rate: ${d['overall_rate'] ?? '—'}%')
      ..writeln(
        'Present: ${d['present_count']}  Late: ${d['late_count']}  Absent: ${d['absent_count']}',
      )
      ..writeln('Streak: ${d['streak_days']} days');
    for (final r in (d['days'] as List? ?? [])) {
      buffer.writeln(
        '${r['date']}  ${switch (r['status']) {
          1 => 'Present',
          2 => 'Late',
          _ => 'Absent',
        }}  ${r['group_name'] ?? ''}',
      );
    }
    showModalBottomSheet(
      context: context,
      backgroundColor: t.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Attendance Report',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w800,
                color: t.textHi,
              ),
            ),
            const SizedBox(height: 12),
            Container(
              constraints: const BoxConstraints(maxHeight: 280),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: t.inset,
                borderRadius: BorderRadius.circular(14),
              ),
              child: SingleChildScrollView(
                child: SelectableText(
                  buffer.toString(),
                  style: TextStyle(
                    fontSize: 12,
                    height: 1.5,
                    color: t.textMid,
                    fontFamily: 'Roboto',
                  ),
                ),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Long-press to copy. PDF export is coming with the reports module.',
              style: TextStyle(fontSize: 11.5, color: t.textLow),
            ),
          ],
        ),
      ),
    );
  }

  void _emailTeacher(BuildContext context, List teachers) {
    final t = context.ice;
    if (teachers.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No teacher contact available.')),
      );
      return;
    }
    showModalBottomSheet(
      context: context,
      backgroundColor: t.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const SizedBox(height: 18),
            ...teachers.map(
              (tc) => ListTile(
                leading: Icon(Icons.mail_outline_rounded, color: t.accent),
                title: Text(
                  tc['name'] ?? '',
                  style: TextStyle(
                    color: t.textHi,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                subtitle: Text(
                  tc['group_name'] ?? '',
                  style: TextStyle(color: t.textMid, fontSize: 12.5),
                ),
                onTap: () => launchUrl(
                  Uri(
                    scheme: 'mailto',
                    path: tc['email'],
                    query: 'subject=Attendance question',
                  ),
                ),
              ),
            ),
            const SizedBox(height: 12),
          ],
        ),
      ),
    );
  }
}

// ─── Pieces ──────────────────────────────────────────────────────────────────
class _FilterButton extends ConsumerWidget {
  final List groups;
  final int? selected;
  final ValueChanged<int?> onChanged;

  const _FilterButton({
    required this.groups,
    required this.selected,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    return PopupMenuButton<int?>(
      color: t.card,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      onSelected: (v) => onChanged(v == -1 ? null : v),
      itemBuilder: (_) => [
        PopupMenuItem(
          value: -1,
          child: Text(s('All courses'), style: TextStyle(color: t.textHi)),
        ),
        ...groups.map(
          (g) => PopupMenuItem(
            value: g['id'] as int,
            child: Text(g['name'] ?? '', style: TextStyle(color: t.textHi)),
          ),
        ),
      ],
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
        decoration: BoxDecoration(
          color: t.inset,
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: t.stroke),
        ),
        child: Row(
          children: [
            Icon(Icons.tune_rounded, size: 15, color: t.textMid),
            const SizedBox(width: 6),
            Text(
              s('Filter'),
              style: TextStyle(
                fontSize: 12.5,
                fontWeight: FontWeight.w700,
                color: t.textMid,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _RoundIconButton extends StatelessWidget {
  final IconData icon;
  final VoidCallback onTap;
  const _RoundIconButton({required this.icon, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(6),
        decoration: BoxDecoration(color: t.inset, shape: BoxShape.circle),
        child: Icon(icon, size: 20, color: t.textHi),
      ),
    );
  }
}

class _LegendDot extends StatelessWidget {
  final Color color;
  final String label;
  const _LegendDot({required this.color, required this.label});

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Container(
        width: 8,
        height: 8,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
      ),
      const SizedBox(width: 5),
      Text(
        label.toUpperCase(),
        style: TextStyle(
          fontSize: 9.5,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.8,
          color: context.ice.textMid,
        ),
      ),
    ],
  );
}

class _MonthCalendar extends StatelessWidget {
  final DateTime month;
  final List records;
  const _MonthCalendar({required this.month, required this.records});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final byDay = <int, List<Map<String, dynamic>>>{};
    for (final r in records) {
      final date = DateTime.tryParse(r['date'] ?? '');
      if (date != null) {
        byDay.putIfAbsent(date.day, () => []).add(r as Map<String, dynamic>);
      }
    }

    final firstWeekday =
        DateTime(month.year, month.month, 1).weekday % 7; // Sun=0
    final daysInMonth = DateTime(month.year, month.month + 1, 0).day;
    final today = DateTime.now();

    final cells = <Widget>[];
    for (final wd in const ['S', 'M', 'T', 'W', 'T', 'F', 'S']) {
      cells.add(
        Center(
          child: Text(
            wd,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w700,
              color: t.textLow,
            ),
          ),
        ),
      );
    }
    for (var i = 0; i < firstWeekday; i++) {
      cells.add(const SizedBox.shrink());
    }
    for (var day = 1; day <= daysInMonth; day++) {
      final recs = byDay[day];
      final isToday =
          today.year == month.year &&
          today.month == month.month &&
          today.day == day;
      // Worst status of the day decides the dot colour.
      Color? dot;
      if (recs != null) {
        final statuses = recs.map((r) => r['status'] as num?).toList();
        if (statuses.contains(0)) {
          dot = t.coral;
        } else if (statuses.contains(2)) {
          dot = t.sky;
        } else {
          dot = t.accent;
        }
      }
      cells.add(
        GestureDetector(
          onTap: recs == null ? null : () => _showDay(context, day, recs),
          child: Container(
            decoration: isToday
                ? BoxDecoration(
                    color: t.inset,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: t.stroke),
                  )
                : null,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Text(
                  '$day',
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: isToday ? FontWeight.w800 : FontWeight.w600,
                    color: dot == t.coral ? t.coral : t.textHi,
                  ),
                ),
                const SizedBox(height: 3),
                Container(
                  width: 5,
                  height: 5,
                  decoration: BoxDecoration(
                    color: dot ?? Colors.transparent,
                    shape: BoxShape.circle,
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    }

    return GridView.count(
      crossAxisCount: 7,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      childAspectRatio: 0.95,
      children: cells,
    );
  }

  void _showDay(
    BuildContext context,
    int day,
    List<Map<String, dynamic>> recs,
  ) {
    final t = context.ice;
    final s = ProviderScope.containerOf(context).read(stringsProvider);
    showModalBottomSheet(
      context: context,
      backgroundColor: t.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => SafeArea(
        child: Padding(
          padding: const EdgeInsets.fromLTRB(24, 20, 24, 24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                DateFormat(
                  'EEEE, MMM d',
                ).format(DateTime(month.year, month.month, day)),
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w800,
                  color: t.textHi,
                ),
              ),
              const SizedBox(height: 14),
              ...recs.map(
                (r) => Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          r['group_name'] ?? s('Class'),
                          style: TextStyle(
                            fontSize: 14.5,
                            fontWeight: FontWeight.w600,
                            color: t.textHi,
                          ),
                        ),
                      ),
                      StatusBadge(
                        switch (r['status']) {
                          1 => s('Present'),
                          2 => s('Late'),
                          _ => s('Absent'),
                        },
                        tone: switch (r['status']) {
                          1 => BadgeTone.accent,
                          2 => BadgeTone.sky,
                          _ => BadgeTone.coral,
                        },
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _WeeklyBars extends StatelessWidget {
  final List weekly;
  const _WeeklyBars({required this.weekly});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    if (weekly.every((w) => w['pct'] == null)) {
      return Center(
        child: Text(
          'No attendance data yet.',
          style: TextStyle(color: t.textLow, fontSize: 13),
        ),
      );
    }
    return BarChart(
      BarChartData(
        minY: 0,
        maxY: 100,
        gridData: const FlGridData(show: false),
        titlesData: const FlTitlesData(show: false),
        borderData: FlBorderData(show: false),
        barTouchData: BarTouchData(enabled: false),
        barGroups: [
          for (var i = 0; i < weekly.length; i++)
            BarChartGroupData(
              x: i,
              barRods: [
                BarChartRodData(
                  toY: (weekly[i]['pct'] as num?)?.toDouble() ?? 0,
                  width: 13,
                  borderRadius: BorderRadius.circular(4),
                  color: switch ((weekly[i]['pct'] as num?)?.toDouble()) {
                    null => t.inset,
                    < 60 => t.coral,
                    < 85 => t.sky,
                    _ => t.accent,
                  },
                  backDrawRodData: BackgroundBarChartRodData(
                    show: true,
                    toY: 100,
                    color: t.inset.withValues(alpha: 0.45),
                  ),
                ),
              ],
            ),
        ],
      ),
      duration: const Duration(milliseconds: 350),
    );
  }
}

class _QuickAction extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  const _QuickAction({
    required this.icon,
    required this.label,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      onTap: onTap,
      padding: const EdgeInsets.symmetric(vertical: 20),
      child: Column(
        children: [
          Icon(icon, size: 23, color: t.textHi),
          const SizedBox(height: 10),
          Text(
            label,
            style: TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w700,
              color: t.textHi,
            ),
          ),
        ],
      ),
    );
  }
}
