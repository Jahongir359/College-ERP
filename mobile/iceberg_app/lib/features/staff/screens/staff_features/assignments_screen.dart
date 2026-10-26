part of '../staff_feature_screens.dart';

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
  String _filter = 'Active';

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
        data: (list) => IcePage(
          title: s('Assignments'),
          subtitle: s('Manage and track student assignments'),
          onRefresh: () => ref.refresh(staffAssignmentsProvider.future),
          children: [
            // Filter chips
            IceChipTabs(
              tabs: const ['Active', 'Scheduled', 'Drafts'],
              index: ['Active', 'Scheduled', 'Drafts'].indexOf(_filter),
              onChanged: (i) => setState(
                () => _filter = ['Active', 'Scheduled', 'Drafts'][i],
              ),
            ),
            const SizedBox(height: 16),

            if (list.isEmpty)
              IceCard(
                child: EmptyState(
                  icon: Icons.assignment_outlined,
                  title: s('No assignments yet'),
                  message: s(
                    'Create your first assignment using the + button.',
                  ),
                ),
              )
            else
              ...list.map(
                (a) => Padding(
                  padding: const EdgeInsets.only(bottom: 12),
                  child: _AssignmentCard(a: a as Map<String, dynamic>),
                ),
              ),
            // Extra bottom padding for FAB
            const SizedBox(height: 60),
          ],
        ),
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
                          _toast(
                            dctx,
                            e.response?.data?['detail']?.toString() ??
                                'Could not create.',
                          );
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
