part of '../staff_feature_screens.dart';

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
        _toast(
          context,
          e.response?.data?['detail']?.toString() ?? 'Could not save.',
        );
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
