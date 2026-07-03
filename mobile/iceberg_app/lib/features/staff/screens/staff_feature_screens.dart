import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../core/utils/formatters.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

// ════════════════════════════════════════════════════════════════════════════
//  Shared helpers
// ════════════════════════════════════════════════════════════════════════════

void _toast(BuildContext context, String msg) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
}

/// Extracts the server's `detail` message from an error response. Gateways
/// (Cloudflare/nginx) return HTML or plain-text bodies on 5xx, so the body is
/// not always a Map — indexing a String with `['detail']` throws.
String _errDetail(DioException e, String fallback) {
  final data = e.response?.data;
  if (data is Map) {
    final d = data['detail']?.toString();
    if (d != null && d.isNotEmpty) return d;
  }
  return fallback;
}

String _studentName(Map s) {
  final f = (s['first_name'] ?? '').toString().trim();
  final l = (s['last_name'] ?? '').toString().trim();
  final full = '$f $l'.trim();
  return full.isEmpty ? (s['email']?.toString() ?? 'Student') : full;
}

// ── Themed group dropdown ─────────────────────────────────────────────────────
class _GroupDropdown extends ConsumerWidget {
  final int? value;
  final ValueChanged<int?> onChanged;
  const _GroupDropdown({required this.value, required this.onChanged});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final groups = ref.watch(staffGroupsProvider);
    return groups.when(
      loading: () => LinearProgressIndicator(color: t.accent),
      error: (e, _) => Text(
        'Could not load groups: $e',
        style: TextStyle(color: t.coral),
      ),
      data: (list) {
        if (list.isEmpty) {
          return Text(
            'No groups are assigned to you yet.',
            style: TextStyle(color: t.textMid),
          );
        }
        return DropdownButtonFormField<int>(
          value: value,
          isExpanded: true,
          dropdownColor: t.card,
          style: TextStyle(color: t.textHi, fontSize: 14),
          decoration: InputDecoration(
            labelText: 'Group',
            labelStyle: TextStyle(color: t.textMid),
          ),
          items: [
            for (final g in list)
              DropdownMenuItem(
                value: g['id'] as int,
                child: Text(
                  '${g['name']}${g['course_name'] != null ? ' · ${g['course_name']}' : ''}',
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
          onChanged: onChanged,
        );
      },
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  1 · Classes  — list groups, tap to see the enrolled roster
// ════════════════════════════════════════════════════════════════════════════

class StaffClassesScreen extends ConsumerWidget {
  const StaffClassesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final groups = ref.watch(staffGroupsProvider);

    return Scaffold(
      backgroundColor: t.bg,
      body: SafeArea(
        bottom: false,
        child: groups.when(
          loading: () => const PageSkeleton(),
          error: (e, _) => ErrorState(
            error: e,
            onRetry: () => ref.invalidate(staffGroupsProvider),
          ),
          data: (list) => IcePage(
            title: 'My Classes',
            subtitle: 'Groups you teach',
            backButton: true,
            onRefresh: () => ref.refresh(staffGroupsProvider.future),
        children: [
          if (list.isEmpty)
            IceCard(
              child: EmptyState(
                icon: Icons.class_outlined,
                title: 'No groups assigned',
                message: 'Your groups will appear here once assigned.',
              ),
            )
          else
            ...list.map(
              (g) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _ClassCard(group: g as Map<String, dynamic>),
              ),
            ),
          ],
        ),
      ),
    ),
  );
  }
}

class _ClassCard extends StatelessWidget {
  final Map<String, dynamic> group;
  const _ClassCard({required this.group});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      padding: const EdgeInsets.all(16),
      onTap: () => showModalBottomSheet(
        context: context,
        isScrollControlled: true,
        backgroundColor: t.card,
        shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
        ),
        builder: (_) => _RosterSheet(
          groupId: group['id'] as int,
          groupName: (group['name'] ?? 'Group').toString(),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 46,
            height: 46,
            decoration: BoxDecoration(
              color: t.accentSoft,
              borderRadius: BorderRadius.circular(13),
            ),
            child: Icon(Icons.group_rounded, color: t.accentInk),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  group['name']?.toString() ?? 'Group',
                  style: TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 15,
                    color: t.textHi,
                  ),
                ),
                const SizedBox(height: 2),
                if ((group['course_name']?.toString() ?? '').isNotEmpty)
                  Text(
                    group['course_name'].toString(),
                    style: TextStyle(fontSize: 12.5, color: t.textMid),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                if ((group['schedule']?.toString() ?? '').isNotEmpty ||
                    group['room'] != null)
                  Text(
                    [
                      group['schedule']?.toString(),
                      group['room'] != null ? 'Room ${group['room']}' : null,
                    ].where((e) => e != null && e.isNotEmpty).join(' · '),
                    style: TextStyle(fontSize: 12, color: t.textLow),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
              ],
            ),
          ),
          Icon(Icons.chevron_right_rounded, color: t.textLow),
        ],
      ),
    );
  }
}

class _RosterSheet extends ConsumerWidget {
  final int groupId;
  final String groupName;
  const _RosterSheet({required this.groupId, required this.groupName});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final detail = ref.watch(groupDetailProvider(groupId));
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.6,
      maxChildSize: 0.9,
      builder: (_, controller) => Column(
        children: [
          const SizedBox(height: 10),
          Container(
            width: 42,
            height: 4,
            decoration: BoxDecoration(
              color: t.stroke,
              borderRadius: BorderRadius.circular(99),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 14, 20, 8),
            child: Row(
              children: [
                Icon(Icons.people_alt_rounded, color: t.accentInk),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '$groupName · Students',
                    style: TextStyle(
                      fontSize: 17,
                      fontWeight: FontWeight.w800,
                      color: t.textHi,
                    ),
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: detail.when(
              loading: () => const PageSkeleton(),
              error: (e, _) => ErrorState(
                error: e,
                onRetry: () => ref.invalidate(groupDetailProvider(groupId)),
              ),
              data: (d) {
                final students = (d['enrolled_students'] as List?) ?? [];
                if (students.isEmpty) {
                  return EmptyState(
                    icon: Icons.person_off_outlined,
                    title: 'No students enrolled yet',
                  );
                }
                return ListView.separated(
                  controller: controller,
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
                  cacheExtent: 600,
                  itemCount: students.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (_, i) {
                    final s = students[i] as Map<String, dynamic>;
                    final name = _studentName(s);
                    return IceCard(
                      padding: const EdgeInsets.all(12),
                      child: Row(
                        children: [
                          CircleAvatar(
                            radius: 18,
                            backgroundColor: t.accentSoft,
                            child: Text(
                              name.characters.first.toUpperCase(),
                              style: TextStyle(
                                color: t.accentInk,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              name,
                              style: TextStyle(
                                fontWeight: FontWeight.w600,
                                color: t.textHi,
                              ),
                            ),
                          ),
                          if ((s['status']?.toString() ?? '') != 'active')
                            StatusBadge(
                              s['status']?.toString() ?? '',
                              tone: BadgeTone.amber,
                            ),
                        ],
                      ),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  2 · Attendance  — pick group + date, mark each student
// ════════════════════════════════════════════════════════════════════════════

class StaffAttendanceScreen extends ConsumerStatefulWidget {
  const StaffAttendanceScreen({super.key});

  @override
  ConsumerState<StaffAttendanceScreen> createState() =>
      _StaffAttendanceScreenState();
}

class _StaffAttendanceScreenState
    extends ConsumerState<StaffAttendanceScreen> {
  int? _groupId;
  DateTime _date = DateTime.now();
  final Map<int, String> _status = {}; // studentId -> 'P'/'L'/'A'
  bool _saving = false;

  Future<void> _save(List students) async {
    if (_groupId == null) return;
    setState(() => _saving = true);
    final records = [
      for (final s in students)
        {
          'student_id': s['id'],
          'status': () {
            final st = _status[s['id'] as int] ?? 'P';
            return st == 'P' ? 1 : st == 'L' ? 2 : 0;
          }(),
        },
    ];
    try {
      await ApiClient.instance.dio.post('/attendance/', data: {
        'group_id': _groupId,
        'date': DateFormat('yyyy-MM-dd').format(_date),
        'records': records,
      });
      if (mounted) _toast(context, 'Attendance saved.');
    } on DioException catch (e) {
      if (mounted) {
        _toast(context, _errDetail(e, 'Could not save.'));
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  int get _presentCount => _status.values.where((v) => v == 'P').length;
  int get _lateCount => _status.values.where((v) => v == 'L').length;
  int get _absentCount => _status.values.where((v) => v == 'A').length;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);

    return IcePage(
      title: s('Take Attendance'),
      subtitle: s('Record student presence for today\'s session.'),
      children: [
        // ── Group + Date selectors ─────────────────────────────────────
        _GroupDropdown(
          value: _groupId,
          onChanged: (v) => setState(() {
            _groupId = v;
            _status.clear();
          }),
        ),
        const SizedBox(height: 12),
        _IceDatePicker(
          date: _date,
          onPick: (d) => setState(() => _date = d),
        ),
        const SizedBox(height: 20),

        // ── Student list ───────────────────────────────────────────────
        if (_groupId == null)
          IceCard(
            child: EmptyState(
              icon: Icons.groups_outlined,
              title: s('Select a group to begin'),
              message: s('Choose a group above to load students.'),
            ),
          )
        else
          Consumer(
            builder: (ctx, innerRef, _) {
              final detail = innerRef.watch(groupDetailProvider(_groupId!));
              return detail.when(
                loading: () => const PageSkeleton(),
                error: (e, _) => ErrorState(
                  error: e,
                  onRetry: () =>
                      innerRef.invalidate(groupDetailProvider(_groupId!)),
                ),
                data: (d) {
                  final students = (d['enrolled_students'] as List?) ?? [];
                  if (students.isEmpty) {
                    return IceCard(
                      child: EmptyState(
                        icon: Icons.person_off_outlined,
                        title: s('No students enrolled'),
                      ),
                    );
                  }
                  return Column(
                    children: [
                      // Summary bar
                      IceCard(
                        padding: const EdgeInsets.symmetric(
                          vertical: 12,
                          horizontal: 16,
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.spaceAround,
                          children: [
                            _SummaryCount(
                              label: s('Present'),
                              count: _presentCount,
                              color: t.accentInk,
                            ),
                            Container(
                              width: 1,
                              height: 28,
                              color: t.stroke,
                            ),
                            _SummaryCount(
                              label: s('Late'),
                              count: _lateCount,
                              color: t.amber,
                            ),
                            Container(
                              width: 1,
                              height: 28,
                              color: t.stroke,
                            ),
                            _SummaryCount(
                              label: s('Absent'),
                              count: _absentCount,
                              color: t.coral,
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(height: 12),

                      // Student rows
                      ...students.map((st) {
                        final student = st as Map<String, dynamic>;
                        final id = student['id'] as int;
                        final name = _studentName(student);
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 8),
                          child: IceCard(
                            padding: const EdgeInsets.fromLTRB(14, 10, 10, 10),
                            child: Row(
                              children: [
                                CircleAvatar(
                                  radius: 18,
                                  backgroundColor: t.accentSoft,
                                  child: Text(
                                    name.characters.first.toUpperCase(),
                                    style: TextStyle(
                                      color: t.accentInk,
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                                ),
                                const SizedBox(width: 12),
                                Expanded(
                                  child: Column(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.start,
                                    children: [
                                      Text(
                                        name,
                                        style: TextStyle(
                                          color: t.textHi,
                                          fontWeight: FontWeight.w600,
                                          fontSize: 14,
                                        ),
                                      ),
                                      if (student['student_id'] != null)
                                        Text(
                                          '${student['student_id']}',
                                          style: TextStyle(
                                            color: t.textLow,
                                            fontSize: 11,
                                          ),
                                        ),
                                    ],
                                  ),
                                ),
                                _StatusToggle(
                                  value: _status[id] ?? 'P',
                                  onChanged: (v) =>
                                      setState(() => _status[id] = v),
                                ),
                              ],
                            ),
                          ),
                        );
                      }),
                      const SizedBox(height: 12),

                      // Submit button
                      IceButton(
                        s('Submit Attendance'),
                        busy: _saving,
                        icon: Icons.check_rounded,
                        onPressed: () => _save(students),
                      ),
                    ],
                  );
                },
              );
            },
          ),
      ],
    );
  }
}

class _IceDatePicker extends StatelessWidget {
  final DateTime date;
  final ValueChanged<DateTime> onPick;
  const _IceDatePicker({required this.date, required this.onPick});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return GestureDetector(
      onTap: () async {
        final now = DateTime.now();
        final picked = await showDatePicker(
          context: context,
          initialDate: date,
          firstDate: now.subtract(const Duration(days: 60)),
          lastDate: now.add(const Duration(days: 30)),
        );
        if (picked != null) onPick(picked);
      },
      child: IceCard(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
        child: Row(
          children: [
            Icon(Icons.calendar_today_rounded, color: t.textMid, size: 18),
            const SizedBox(width: 12),
            Text(
              DateFormat('MMM d, yyyy').format(date),
              style: TextStyle(
                color: t.textHi,
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
            const Spacer(),
            Icon(Icons.edit_calendar_rounded, color: t.textLow, size: 16),
          ],
        ),
      ),
    );
  }
}

class _StatusToggle extends StatelessWidget {
  final String value;
  final ValueChanged<String> onChanged;
  const _StatusToggle({required this.value, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    Color colorFor(String opt) => switch (opt) {
          'P' => t.accentInk,
          'L' => t.amber,
          _ => t.coral,
        };

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        for (final opt in ['P', 'L', 'A'])
          Padding(
            padding: const EdgeInsets.only(left: 6),
            child: GestureDetector(
              onTap: () => onChanged(opt),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 150),
                width: 34,
                height: 34,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: value == opt
                      ? colorFor(opt).withValues(alpha: 0.18)
                      : Colors.transparent,
                  shape: BoxShape.circle,
                  border: Border.all(
                    color: value == opt ? colorFor(opt) : t.stroke,
                    width: 1.5,
                  ),
                ),
                child: Text(
                  opt,
                  style: TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 12,
                    color: value == opt ? colorFor(opt) : t.textLow,
                  ),
                ),
              ),
            ),
          ),
      ],
    );
  }
}

class _SummaryCount extends StatelessWidget {
  final String label;
  final int count;
  final Color color;
  const _SummaryCount({
    required this.label,
    required this.count,
    required this.color,
  });

  @override
  Widget build(BuildContext context) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            '$count',
            style: TextStyle(
              color: color,
              fontSize: 22,
              fontWeight: FontWeight.w900,
            ),
          ),
          Text(
            label,
            style: TextStyle(color: context.ice.textMid, fontSize: 11),
          ),
        ],
      );
}

/// Update-attendance entry point reuses the same screen.
class StaffUpdateAttendanceScreen extends StatelessWidget {
  const StaffUpdateAttendanceScreen({super.key});
  @override
  Widget build(BuildContext context) => const StaffAttendanceScreen();
}

// ════════════════════════════════════════════════════════════════════════════
//  3 · Results  — pick group, enter test/exam/comment per student
// ════════════════════════════════════════════════════════════════════════════

class StaffResultsScreen extends ConsumerStatefulWidget {
  const StaffResultsScreen({super.key});

  @override
  ConsumerState<StaffResultsScreen> createState() => _StaffResultsScreenState();
}

class _StaffResultsScreenState extends ConsumerState<StaffResultsScreen> {
  int? _groupId;

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);

    return IcePage(
      title: s('Results'),
      subtitle: s('Record test & exam scores'),
      backButton: true,
      children: [
        _GroupDropdown(
          value: _groupId,
          onChanged: (v) => setState(() => _groupId = v),
        ),
        const SizedBox(height: 16),
        if (_groupId == null)
          IceCard(
            child: EmptyState(
              icon: Icons.grade_outlined,
              title: s('Pick a group to begin'),
              message: s('Select a group above to view and enter results.'),
            ),
          )
        else
          _ResultsRoster(
            groupId: _groupId!,
            onEditResult: (student, existing) =>
                _editResult(t, student, existing),
          ),
      ],
    );
  }

  Future<void> _editResult(
    IceTokens t,
    Map<String, dynamic> student,
    Map<String, dynamic>? existing,
  ) async {
    final testC = TextEditingController(
      text: existing?['test']?.toString() ?? '',
    );
    final examC = TextEditingController(
      text: existing?['exam']?.toString() ?? '',
    );
    final commentC = TextEditingController(
      text: existing?['comment']?.toString() ?? '',
    );
    var saving = false;

    await showDialog<void>(
      context: context,
      builder: (dctx) => StatefulBuilder(
        builder: (dctx, setLocal) => AlertDialog(
          backgroundColor: t.card,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
            side: BorderSide(color: t.stroke),
          ),
          title: Text(
            _studentName(student),
            style: TextStyle(
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: testC,
                      keyboardType: TextInputType.number,
                      style: TextStyle(color: t.textHi),
                      decoration: const InputDecoration(labelText: 'Test'),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: TextField(
                      controller: examC,
                      keyboardType: TextInputType.number,
                      style: TextStyle(color: t.textHi),
                      decoration: const InputDecoration(labelText: 'Exam'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              TextField(
                controller: commentC,
                maxLines: 2,
                style: TextStyle(color: t.textHi),
                decoration: const InputDecoration(
                  labelText: 'Comment',
                  hintText: 'Optional',
                ),
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: saving ? null : () => Navigator.pop(dctx),
              child: Text('Cancel', style: TextStyle(color: t.textMid)),
            ),
            FilledButton(
              style: FilledButton.styleFrom(
                backgroundColor: t.accent,
                foregroundColor: t.onAccent,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              onPressed: saving
                  ? null
                  : () async {
                      setLocal(() => saving = true);
                      try {
                        await ApiClient.instance.dio.post(
                          '/results/',
                          data: {
                            'student_id': student['id'],
                            'group_id': _groupId,
                            'test': int.tryParse(testC.text.trim()) ?? 0,
                            'exam': int.tryParse(examC.text.trim()) ?? 0,
                            'comment': commentC.text.trim(),
                          },
                        );
                        ref.invalidate(groupResultsProvider(_groupId!));
                        if (dctx.mounted) Navigator.pop(dctx);
                        if (mounted) _toast(context, 'Result saved.');
                      } on DioException catch (e) {
                        setLocal(() => saving = false);
                        if (dctx.mounted) {
                          _toast(dctx, _errDetail(e, 'Could not save.'));
                        }
                      }
                    },
              child: const Text('Save'),
            ),
          ],
        ),
      ),
    );
  }
}

class _ResultsRoster extends ConsumerWidget {
  final int groupId;
  final void Function(Map<String, dynamic>, Map<String, dynamic>?) onEditResult;
  const _ResultsRoster({
    required this.groupId,
    required this.onEditResult,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final detail = ref.watch(groupDetailProvider(groupId));
    final results = ref.watch(groupResultsProvider(groupId));

    return detail.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.invalidate(groupDetailProvider(groupId)),
      ),
      data: (d) {
        final students = (d['enrolled_students'] as List?) ?? [];
        if (students.isEmpty) {
          return IceCard(
            child: EmptyState(
              icon: Icons.person_off_outlined,
              title: 'No students enrolled',
            ),
          );
        }
        final byStudent = <int, Map<String, dynamic>>{};
        results.maybeWhen(
          data: (list) {
            for (final r in list) {
              byStudent[(r as Map)['student'] as int] =
                  r as Map<String, dynamic>;
            }
          },
          orElse: () {},
        );
        return Column(
          children: [
            for (var i = 0; i < students.length; i++) ...[
              _ResultRow(
                name: _studentName(students[i] as Map<String, dynamic>),
                existing: byStudent[students[i]['id'] as int],
                onTap: () => onEditResult(
                  students[i] as Map<String, dynamic>,
                  byStudent[students[i]['id'] as int],
                ),
              ),
              if (i < students.length - 1) const SizedBox(height: 8),
            ],
          ],
        );
      },
    );
  }
}

class _ResultRow extends StatelessWidget {
  final String name;
  final Map<String, dynamic>? existing;
  final VoidCallback onTap;
  const _ResultRow({
    required this.name,
    required this.existing,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final has = existing != null;
    return IceCard(
      padding: const EdgeInsets.all(14),
      onTap: onTap,
      child: Row(
        children: [
          Expanded(
            child: Text(
              name,
              style: TextStyle(
                fontWeight: FontWeight.w600,
                color: t.textHi,
              ),
            ),
          ),
          if (has) ...[
            _ScorePill('T', existing!['test']),
            const SizedBox(width: 6),
            _ScorePill('E', existing!['exam']),
          ] else
            Text(
              'Tap to add',
              style: TextStyle(fontSize: 12, color: t.textMid),
            ),
          const SizedBox(width: 6),
          Icon(Icons.edit_rounded, size: 18, color: t.accentInk),
        ],
      ),
    );
  }
}

class _ScorePill extends StatelessWidget {
  final String k;
  final dynamic v;
  const _ScorePill(this.k, this.v);

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
      decoration: BoxDecoration(
        color: t.accentSoft,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Text(
        '$k ${v ?? 0}',
        style: TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w800,
          color: t.accentInk,
        ),
      ),
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  4 · Assignments  — list own assignments, create new
// ════════════════════════════════════════════════════════════════════════════

class StaffAssignmentsScreen extends ConsumerStatefulWidget {
  const StaffAssignmentsScreen({super.key});

  @override
  ConsumerState<StaffAssignmentsScreen> createState() =>
      _StaffAssignmentsScreenState();
}

class _StaffAssignmentsScreenState
    extends ConsumerState<StaffAssignmentsScreen> {
  int _filter = 0; // 0 All · 1 Active · 2 Past due

  bool _isPastDue(Map<String, dynamic> a) {
    final due = DateTime.tryParse(a['due_date']?.toString() ?? '');
    if (due == null) return false;
    final today = DateTime.now();
    return due.isBefore(DateTime(today.year, today.month, today.day));
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final items = ref.watch(staffAssignmentsProvider);

    return Scaffold(
      backgroundColor: t.bg,
      floatingActionButton: FloatingActionButton(
        backgroundColor: t.accent,
        foregroundColor: t.onAccent,
        onPressed: () => _createDialog(context, ref),
        child: const Icon(Icons.add_rounded),
      ),
      body: items.when(
        loading: () => const PageSkeleton(),
        error: (e, _) => ErrorState(
          error: e,
          onRetry: () => ref.invalidate(staffAssignmentsProvider),
        ),
        data: (list) {
          final all = list.cast<Map<String, dynamic>>();
          final visible = switch (_filter) {
            1 => all.where((a) => !_isPastDue(a)).toList(),
            2 => all.where(_isPastDue).toList(),
            _ => all,
          };
          return IcePage(
            title: s('Assignments'),
            subtitle: s('Manage and track student assignments'),
            onRefresh: () => ref.refresh(staffAssignmentsProvider.future),
            children: [
              // Filter chips
              IceChipTabs(
                tabs: [s('All'), s('Active'), s('Past due')],
                index: _filter,
                onChanged: (i) => setState(() => _filter = i),
              ),
              const SizedBox(height: 16),

              if (all.isEmpty)
                IceCard(
                  child: EmptyState(
                    icon: Icons.assignment_outlined,
                    title: s('No assignments yet'),
                    message: s(
                      'Create your first assignment using the + button.',
                    ),
                  ),
                )
              else if (visible.isEmpty)
                IceCard(
                  child: EmptyState(
                    icon: Icons.filter_alt_off_outlined,
                    title: s('Nothing here'),
                  ),
                )
              else
                ...visible.map(
                  (a) => Padding(
                    padding: const EdgeInsets.only(bottom: 12),
                    child: _AssignmentCard(a: a),
                  ),
                ),
              // Extra bottom padding for FAB
              const SizedBox(height: 60),
            ],
          );
        },
      ),
    );
  }

  Future<void> _createDialog(BuildContext context, WidgetRef ref) async {
    final t = context.ice;
    int? groupId;
    final titleC = TextEditingController();
    final descC = TextEditingController();
    DateTime? due;
    var saving = false;

    await showDialog<void>(
      context: context,
      builder: (dctx) => StatefulBuilder(
        builder: (dctx, setLocal) => AlertDialog(
          backgroundColor: t.card,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
            side: BorderSide(color: t.stroke),
          ),
          title: Text(
            'New Assignment',
            style: TextStyle(
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                _GroupDropdown(
                  value: groupId,
                  onChanged: (v) => setLocal(() => groupId = v),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: titleC,
                  style: TextStyle(color: t.textHi),
                  decoration: const InputDecoration(labelText: 'Title'),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: descC,
                  maxLines: 3,
                  style: TextStyle(color: t.textHi),
                  decoration: const InputDecoration(
                    labelText: 'Description',
                    hintText: 'Optional',
                  ),
                ),
                const SizedBox(height: 10),
                _IceDatePicker(
                  date: due ?? DateTime.now(),
                  onPick: (d) => setLocal(() => due = d),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: saving ? null : () => Navigator.pop(dctx),
              child: Text('Cancel', style: TextStyle(color: t.textMid)),
            ),
            FilledButton(
              style: FilledButton.styleFrom(
                backgroundColor: t.accent,
                foregroundColor: t.onAccent,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              onPressed: saving
                  ? null
                  : () async {
                      if (groupId == null || titleC.text.trim().isEmpty) {
                        _toast(dctx, 'Pick a group and enter a title.');
                        return;
                      }
                      setLocal(() => saving = true);
                      try {
                        await ApiClient.instance.dio.post(
                          '/assignments/',
                          data: {
                            'group': groupId,
                            'title': titleC.text.trim(),
                            'description': descC.text.trim(),
                            if (due != null)
                              'due_date': DateFormat('yyyy-MM-dd').format(due!),
                          },
                        );
                        ref.invalidate(staffAssignmentsProvider);
                        if (dctx.mounted) Navigator.pop(dctx);
                      } on DioException catch (e) {
                        setLocal(() => saving = false);
                        if (dctx.mounted) {
                          _toast(dctx, _errDetail(e, 'Could not create.'));
                        }
                      }
                    },
              child: saving
                  ? SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(
                        strokeWidth: 2,
                        color: t.onAccent,
                      ),
                    )
                  : const Text('Create'),
            ),
          ],
        ),
      ),
    );
  }
}

class _AssignmentCard extends StatelessWidget {
  final Map<String, dynamic> a;
  const _AssignmentCard({required this.a});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final due = a['due_date']?.toString();
    final groupName = a['group_name']?.toString();
    final submitted = a['submitted_count'] as int? ?? 0;
    final total = a['total_students'] as int? ?? 0;
    final progress = total > 0 ? submitted / total : 0.0;

    return IceCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(
                  color: t.accentSoft,
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(
                  Icons.assignment_rounded,
                  color: t.accentInk,
                  size: 20,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      a['title']?.toString() ?? 'Assignment',
                      style: TextStyle(
                        color: t.textHi,
                        fontWeight: FontWeight.w800,
                        fontSize: 15,
                      ),
                    ),
                    if (due != null && due.isNotEmpty)
                      Text(
                        'Due $due',
                        style: TextStyle(color: t.textMid, fontSize: 12),
                      ),
                  ],
                ),
              ),
              RichText(
                text: TextSpan(
                  children: [
                    TextSpan(
                      text: '$submitted',
                      style: TextStyle(
                        color: t.accentInk,
                        fontWeight: FontWeight.w900,
                        fontSize: 16,
                      ),
                    ),
                    TextSpan(
                      text: ' /${total > 0 ? total : '—'}',
                      style: TextStyle(color: t.textMid, fontSize: 13),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          // Tags
          Wrap(
            spacing: 6,
            runSpacing: 4,
            children: [
              if (groupName != null)
                StatusBadge(groupName.toUpperCase(), tone: BadgeTone.neutral),
              if (a['subject'] != null)
                StatusBadge(
                  a['subject'].toString().toUpperCase(),
                  tone: BadgeTone.neutral,
                ),
            ],
          ),
          if (total > 0) ...[
            const SizedBox(height: 10),
            ClipRRect(
              borderRadius: BorderRadius.circular(4),
              child: LinearProgressIndicator(
                value: progress.clamp(0.0, 1.0),
                backgroundColor: t.inset,
                valueColor: AlwaysStoppedAnimation(t.accentInk),
                minHeight: 4,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              'Submitted',
              style: TextStyle(color: t.textLow, fontSize: 10),
            ),
          ],
        ],
      ),
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  5 · Vocabulary  — list days, create day, manage words
// ════════════════════════════════════════════════════════════════════════════

class StaffVocabularyScreen extends ConsumerWidget {
  const StaffVocabularyScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final days = ref.watch(staffVocabularyProvider);

    return Scaffold(
      backgroundColor: t.bg,
      floatingActionButton: FloatingActionButton.extended(
        backgroundColor: t.accent,
        foregroundColor: t.onAccent,
        onPressed: () => _createDayDialog(context, ref),
        icon: const Icon(Icons.add_rounded),
        label: const Text('New day'),
      ),
      body: days.when(
        loading: () => const PageSkeleton(),
        error: (e, _) => ErrorState(
          error: e,
          onRetry: () => ref.invalidate(staffVocabularyProvider),
        ),
        data: (list) => IcePage(
          title: s('Vocabulary'),
          subtitle: s('Word sets for your groups'),
          backButton: true,
          onRefresh: () => ref.refresh(staffVocabularyProvider.future),
          children: [
            if (list.isEmpty)
              IceCard(
                child: EmptyState(
                  icon: Icons.menu_book_outlined,
                  title: s('No vocabulary days yet'),
                  message: s('Create your first vocabulary set with the + button.'),
                ),
              )
            else
              ...list.map(
                (day) => Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: _VocabDayCard(day: day as Map<String, dynamic>),
                ),
              ),
            const SizedBox(height: 60),
          ],
        ),
      ),
    );
  }

  Future<void> _createDayDialog(BuildContext context, WidgetRef ref) async {
    final t = context.ice;
    int? groupId;
    final dayC = TextEditingController();
    final titleC = TextEditingController();
    var saving = false;

    await showDialog<void>(
      context: context,
      builder: (dctx) => StatefulBuilder(
        builder: (dctx, setLocal) => AlertDialog(
          backgroundColor: t.card,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
            side: BorderSide(color: t.stroke),
          ),
          title: Text(
            'New vocabulary day',
            style: TextStyle(
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                _GroupDropdown(
                  value: groupId,
                  onChanged: (v) => setLocal(() => groupId = v),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: dayC,
                  keyboardType: TextInputType.number,
                  style: TextStyle(color: t.textHi),
                  decoration: const InputDecoration(
                    labelText: 'Day number',
                    hintText: 'e.g. 1',
                  ),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: titleC,
                  style: TextStyle(color: t.textHi),
                  decoration: const InputDecoration(
                    labelText: 'Title',
                    hintText: 'Optional',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: saving ? null : () => Navigator.pop(dctx),
              child: Text('Cancel', style: TextStyle(color: t.textMid)),
            ),
            FilledButton(
              style: FilledButton.styleFrom(
                backgroundColor: t.accent,
                foregroundColor: t.onAccent,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              onPressed: saving
                  ? null
                  : () async {
                      final dayNum = int.tryParse(dayC.text.trim());
                      if (groupId == null || dayNum == null) {
                        _toast(dctx, 'Pick a group and a day number.');
                        return;
                      }
                      setLocal(() => saving = true);
                      try {
                        await ApiClient.instance.dio
                            .post('/staff/vocabulary/create/', data: {
                          'group': groupId,
                          'day_number': dayNum,
                          'title': titleC.text.trim(),
                          'release_at':
                              DateTime.now().toUtc().toIso8601String(),
                        });
                        ref.invalidate(staffVocabularyProvider);
                        if (dctx.mounted) Navigator.pop(dctx);
                      } on DioException catch (e) {
                        setLocal(() => saving = false);
                        if (dctx.mounted) {
                          _toast(dctx, _errDetail(e, 'Could not create.'));
                        }
                      }
                    },
              child: const Text('Create'),
            ),
          ],
        ),
      ),
    );
  }
}

class _VocabDayCard extends StatelessWidget {
  final Map<String, dynamic> day;
  const _VocabDayCard({required this.day});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final released = day['is_released'] == true;
    return IceCard(
      padding: const EdgeInsets.all(16),
      onTap: () => Navigator.of(context).push(
        MaterialPageRoute(
          builder: (_) => StaffVocabularyDetailScreen(
            vocabId: (day['id'] as int).toString(),
          ),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 46,
            height: 46,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: t.accentSoft,
              borderRadius: BorderRadius.circular(13),
            ),
            child: Text(
              '${day['day_number'] ?? '?'}',
              style: TextStyle(
                fontWeight: FontWeight.w900,
                color: t.accentInk,
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  (day['title']?.toString().isNotEmpty ?? false)
                      ? day['title'].toString()
                      : 'Day ${day['day_number']}',
                  style: TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 15,
                    color: t.textHi,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  '${day['group_name'] ?? ''} · ${day['word_count'] ?? 0} words',
                  style: TextStyle(fontSize: 12.5, color: t.textMid),
                ),
              ],
            ),
          ),
          StatusBadge(
            released ? 'Released' : 'Scheduled',
            tone: released ? BadgeTone.accent : BadgeTone.amber,
          ),
        ],
      ),
    );
  }
}

class StaffVocabularyDetailScreen extends ConsumerWidget {
  final String vocabId;
  const StaffVocabularyDetailScreen({super.key, required this.vocabId});

  int get _id => int.tryParse(vocabId) ?? 0;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final detail = ref.watch(staffVocabDetailProvider(_id));

    return Scaffold(
      backgroundColor: t.bg,
      appBar: AppBar(
        backgroundColor: t.card,
        foregroundColor: t.textHi,
        title: Text(
          'Vocabulary Day',
          style: TextStyle(
            color: t.textHi,
            fontWeight: FontWeight.w800,
            fontSize: 17,
          ),
        ),
        elevation: 0,
        surfaceTintColor: Colors.transparent,
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(1),
          child: Container(height: 1, color: t.stroke),
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        backgroundColor: t.accent,
        foregroundColor: t.onAccent,
        onPressed: () => _addWordDialog(context, ref, t),
        icon: const Icon(Icons.add_rounded),
        label: const Text('Add word'),
      ),
      body: detail.when(
        loading: () => const PageSkeleton(),
        error: (e, _) => ErrorState(
          error: e,
          onRetry: () => ref.invalidate(staffVocabDetailProvider(_id)),
        ),
        data: (d) {
          final words = (d['words'] as List?) ?? [];
          return IceRefresh(
            onRefresh: () => ref.refresh(staffVocabDetailProvider(_id).future),
            child: ListView(
              physics: const AlwaysScrollableScrollPhysics(),
              cacheExtent: 600,
              padding: const EdgeInsets.fromLTRB(20, 16, 20, 100),
              children: [
                Text(
                  (d['title']?.toString().isNotEmpty ?? false)
                      ? d['title'].toString()
                      : 'Day ${d['day_number']}',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.w900,
                    color: t.textHi,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '${d['group_name'] ?? ''} · ${words.length} words',
                  style: TextStyle(color: t.textMid),
                ),
                const SizedBox(height: 16),
                if (words.isEmpty)
                  IceCard(
                    child: EmptyState(
                      icon: Icons.translate_rounded,
                      title: 'No words yet',
                      message: 'Tap "Add word" to get started.',
                    ),
                  )
                else
                  ...words.map(
                    (w) => Padding(
                      padding: const EdgeInsets.only(bottom: 8),
                      child: _WordTile(
                        id: _id,
                        word: w as Map<String, dynamic>,
                      ),
                    ),
                  ),
              ],
            ),
          );
        },
      ),
    );
  }

  Future<void> _addWordDialog(
    BuildContext context,
    WidgetRef ref,
    IceTokens t,
  ) async {
    final wordC = TextEditingController();
    final meaningC = TextEditingController();
    final exampleC = TextEditingController();
    var saving = false;

    await showDialog<void>(
      context: context,
      builder: (dctx) => StatefulBuilder(
        builder: (dctx, setLocal) => AlertDialog(
          backgroundColor: t.card,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
            side: BorderSide(color: t.stroke),
          ),
          title: Text(
            'Add word',
            style: TextStyle(
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          content: SingleChildScrollView(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                TextField(
                  controller: wordC,
                  style: TextStyle(color: t.textHi),
                  decoration: const InputDecoration(labelText: 'Word'),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: meaningC,
                  style: TextStyle(color: t.textHi),
                  decoration: const InputDecoration(labelText: 'Meaning'),
                ),
                const SizedBox(height: 10),
                TextField(
                  controller: exampleC,
                  maxLines: 2,
                  style: TextStyle(color: t.textHi),
                  decoration: const InputDecoration(
                    labelText: 'Example',
                    hintText: 'Optional',
                  ),
                ),
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: saving ? null : () => Navigator.pop(dctx),
              child: Text('Cancel', style: TextStyle(color: t.textMid)),
            ),
            FilledButton(
              style: FilledButton.styleFrom(
                backgroundColor: t.accent,
                foregroundColor: t.onAccent,
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
              ),
              onPressed: saving
                  ? null
                  : () async {
                      if (wordC.text.trim().isEmpty ||
                          meaningC.text.trim().isEmpty) {
                        _toast(dctx, 'Word and meaning are required.');
                        return;
                      }
                      setLocal(() => saving = true);
                      try {
                        await ApiClient.instance.dio
                            .post('/staff/vocabulary/$_id/words/', data: {
                          'word': wordC.text.trim(),
                          'meaning': meaningC.text.trim(),
                          'example_sentence': exampleC.text.trim(),
                        });
                        ref.invalidate(staffVocabDetailProvider(_id));
                        ref.invalidate(staffVocabularyProvider);
                        if (dctx.mounted) Navigator.pop(dctx);
                      } on DioException catch (e) {
                        setLocal(() => saving = false);
                        if (dctx.mounted) {
                          _toast(dctx, _errDetail(e, 'Could not add.'));
                        }
                      }
                    },
              child: const Text('Add'),
            ),
          ],
        ),
      ),
    );
  }
}

class _WordTile extends ConsumerWidget {
  final int id;
  final Map<String, dynamic> word;
  const _WordTile({required this.id, required this.word});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    return IceCard(
      padding: const EdgeInsets.fromLTRB(14, 12, 6, 12),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  word['word']?.toString() ?? '',
                  style: TextStyle(
                    fontWeight: FontWeight.w800,
                    color: t.textHi,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  word['meaning']?.toString() ?? '',
                  style: TextStyle(fontSize: 13, color: t.textMid),
                ),
                if ((word['example_sentence']?.toString() ?? '').isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Text(
                    '"${word['example_sentence']}"',
                    style: TextStyle(
                      fontSize: 12,
                      fontStyle: FontStyle.italic,
                      color: t.textLow,
                    ),
                  ),
                ],
              ],
            ),
          ),
          IconButton(
            icon: Icon(Icons.delete_outline_rounded, color: t.coral, size: 20),
            onPressed: () async {
              try {
                await ApiClient.instance.dio
                    .delete('/staff/vocabulary/$id/words/${word['id']}/');
                if (context.mounted) {
                  ref.invalidate(staffVocabDetailProvider(id));
                  ref.invalidate(staffVocabularyProvider);
                }
              } on DioException {
                if (context.mounted) _toast(context, 'Could not delete.');
              }
            },
          ),
        ],
      ),
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  6 · Leave  — apply + history (own staff leave)
// ════════════════════════════════════════════════════════════════════════════

class StaffLeaveScreen extends ConsumerStatefulWidget {
  const StaffLeaveScreen({super.key});

  @override
  ConsumerState<StaffLeaveScreen> createState() => _StaffLeaveScreenState();
}

class _StaffLeaveScreenState extends ConsumerState<StaffLeaveScreen> {
  DateTime? _date;
  final _reason = TextEditingController();
  bool _busy = false;

  @override
  void dispose() {
    _reason.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_date == null || _reason.text.trim().isEmpty) {
      _toast(context, 'Pick a date and add a reason.');
      return;
    }
    setState(() => _busy = true);
    try {
      await ApiClient.instance.dio.post('/leave/', data: {
        'date': DateFormat('yyyy-MM-dd').format(_date!),
        'message': _reason.text.trim(),
      });
      ref.invalidate(leaveProvider);
      if (mounted) {
        setState(() {
          _reason.clear();
          _date = null;
        });
        _toast(context, 'Leave request submitted.');
      }
    } on DioException {
      if (mounted) _toast(context, 'Could not submit. Try again.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final leaves = ref.watch(leaveProvider);

    return IcePage(
      title: s('Leave'),
      subtitle: s('Request time off'),
      backButton: true,
      onRefresh: () => ref.refresh(leaveProvider.future),
      children: [
            // ── Request form ─────────────────────────────────────────────
            IceCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  MicroLabel(s('Date')),
                  const SizedBox(height: 10),
                  GestureDetector(
                    behavior: HitTestBehavior.opaque,
                    onTap: _pickDate,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 14,
                        vertical: 14,
                      ),
                      decoration: BoxDecoration(
                        color: t.inset,
                        borderRadius: BorderRadius.circular(14),
                        border: Border.all(color: t.stroke),
                      ),
                      child: Row(
                        children: [
                          Icon(Icons.calendar_today_rounded,
                              size: 17, color: t.accentInk),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              _date != null
                                  ? DateFormat('EEE, MMM d, yyyy')
                                      .format(_date!)
                                  : s('Select date'),
                              style: TextStyle(
                                fontSize: 15,
                                fontWeight: FontWeight.w600,
                                color: _date != null ? t.textHi : t.textLow,
                              ),
                            ),
                          ),
                          Icon(Icons.expand_more_rounded,
                              size: 20, color: t.textMid),
                        ],
                      ),
                    ),
                  ),
                  const SizedBox(height: 16),
                  MicroLabel(s('Reason')),
                  const SizedBox(height: 10),
                  TextField(
                    controller: _reason,
                    maxLines: 3,
                    style: TextStyle(color: t.textHi, fontSize: 14.5),
                    decoration: InputDecoration(
                      hintText: s('Briefly explain…'),
                    ),
                  ),
                  const SizedBox(height: 16),
                  IceButton(
                    s('Submit request'),
                    busy: _busy,
                    onPressed: _submit,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            SectionHeader(s('History')),

            leaves.when(
              loading: () => Column(
                children: const [
                  SkeletonBox(height: 74),
                  SizedBox(height: 8),
                  SkeletonBox(height: 74),
                ],
              ),
              error: (e, _) => ErrorState(
                error: e,
                onRetry: () => ref.invalidate(leaveProvider),
              ),
              data: (list) {
                if (list.isEmpty) {
                  return IceCard(
                    child: EmptyState(
                      icon: Icons.event_busy_outlined,
                      title: s('No leave requests'),
                      message: s('Your submitted requests will appear here.'),
                    ),
                  );
                }
                return Column(
                  children: [
                    for (var i = 0; i < list.length; i++) ...[
                      _LeaveCard(leave: list[i] as Map<String, dynamic>),
                      if (i < list.length - 1) const SizedBox(height: 8),
                    ],
                  ],
                );
              },
            ),
          ],
    );
  }

  Future<void> _pickDate() async {
    final now = DateTime.now();
    final picked = await showDatePicker(
      context: context,
      initialDate: _date ?? now,
      firstDate: now.subtract(const Duration(days: 60)),
      lastDate: now.add(const Duration(days: 365)),
    );
    if (picked != null) setState(() => _date = picked);
  }
}

class _LeaveCard extends ConsumerWidget {
  final Map<String, dynamic> leave;
  const _LeaveCard({required this.leave});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final st = leave['status'];
    final (tone, label) = switch (st) {
      1 => (BadgeTone.accent, s('Approved')),
      -1 => (BadgeTone.coral, s('Rejected')),
      _ => (BadgeTone.amber, s('Pending')),
    };
    final message = leave['message']?.toString() ?? '';
    return IceCard(
      padding: const EdgeInsets.all(16),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: t.inset,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(Icons.event_rounded, size: 18, color: t.accentInk),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  fmtDate(leave['date']?.toString()),
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w800,
                    color: t.textHi,
                  ),
                ),
                if (message.isNotEmpty) ...[
                  const SizedBox(height: 3),
                  Text(
                    message,
                    style: TextStyle(
                      fontSize: 13,
                      color: t.textMid,
                      height: 1.3,
                    ),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(width: 10),
          StatusBadge(label, tone: tone),
        ],
      ),
    );
  }
}

// ════════════════════════════════════════════════════════════════════════════
//  7 · Feedback  — send to admin + view replies (own staff feedback)
// ════════════════════════════════════════════════════════════════════════════

class StaffFeedbackScreen extends ConsumerStatefulWidget {
  const StaffFeedbackScreen({super.key});

  @override
  ConsumerState<StaffFeedbackScreen> createState() =>
      _StaffFeedbackScreenState();
}

class _StaffFeedbackScreenState extends ConsumerState<StaffFeedbackScreen> {
  final _text = TextEditingController();
  bool _busy = false;

  @override
  void dispose() {
    _text.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_text.text.trim().isEmpty) {
      _toast(context, 'Write your feedback first.');
      return;
    }
    setState(() => _busy = true);
    try {
      await ApiClient.instance.dio
          .post('/feedback/', data: {'feedback': _text.text.trim()});
      ref.invalidate(feedbackProvider);
      if (mounted) {
        setState(() => _text.clear());
        _toast(context, 'Feedback sent.');
      }
    } on DioException {
      if (mounted) _toast(context, 'Could not send. Try again.');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final items = ref.watch(feedbackProvider);

    return IcePage(
      title: s('Feedback'),
      subtitle: s('Send a note to administration'),
      backButton: true,
      onRefresh: () => ref.refresh(feedbackProvider.future),
      children: [
            // ── Compose ──────────────────────────────────────────────────
            IceCard(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  MicroLabel(s('Your feedback')),
                  const SizedBox(height: 10),
                  TextField(
                    controller: _text,
                    maxLines: 4,
                    style: TextStyle(color: t.textHi, fontSize: 14.5),
                    decoration: InputDecoration(
                      hintText: s('Share a suggestion or concern…'),
                    ),
                  ),
                  const SizedBox(height: 16),
                  IceButton(
                    s('Send feedback'),
                    busy: _busy,
                    onPressed: _submit,
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),

            SectionHeader(s('Previous feedback')),

            items.when(
              loading: () => Column(
                children: const [
                  SkeletonBox(height: 88),
                  SizedBox(height: 8),
                  SkeletonBox(height: 88),
                ],
              ),
              error: (e, _) => ErrorState(
                error: e,
                onRetry: () => ref.invalidate(feedbackProvider),
              ),
              data: (list) {
                if (list.isEmpty) {
                  return IceCard(
                    child: EmptyState(
                      icon: Icons.rate_review_outlined,
                      title: s('No feedback yet'),
                      message: s('Your feedback history will appear here.'),
                    ),
                  );
                }
                return Column(
                  children: [
                    for (var i = 0; i < list.length; i++) ...[
                      _FeedbackCard(fb: list[i] as Map<String, dynamic>),
                      if (i < list.length - 1) const SizedBox(height: 8),
                    ],
                  ],
                );
              },
            ),
          ],
    );
  }
}

class _FeedbackCard extends ConsumerWidget {
  final Map<String, dynamic> fb;
  const _FeedbackCard({required this.fb});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final reply = fb['reply']?.toString() ?? '';
    final feedback = fb['feedback']?.toString() ?? '';
    return IceCard(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            feedback,
            style: TextStyle(
              fontSize: 14.5,
              fontWeight: FontWeight.w600,
              color: t.textHi,
              height: 1.35,
            ),
          ),
          const SizedBox(height: 12),
          if (reply.isNotEmpty)
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: t.inset,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: t.stroke),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Icon(Icons.reply_rounded, size: 15, color: t.accentInk),
                      const SizedBox(width: 6),
                      Text(
                        s('Reply'),
                        style: TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          letterSpacing: 0.5,
                          color: t.accentInk,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    reply,
                    style: TextStyle(
                      fontSize: 13.5,
                      color: t.textHi,
                      height: 1.35,
                    ),
                  ),
                ],
              ),
            )
          else
            StatusBadge(s('Awaiting reply'), tone: BadgeTone.amber),
        ],
      ),
    );
  }
}
