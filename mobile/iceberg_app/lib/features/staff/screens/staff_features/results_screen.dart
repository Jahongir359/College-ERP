part of '../staff_feature_screens.dart';

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
                          _toast(
                            dctx,
                            e.response?.data?['detail']?.toString() ??
                                'Could not save.',
                          );
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
