part of '../staff_feature_screens.dart';

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
