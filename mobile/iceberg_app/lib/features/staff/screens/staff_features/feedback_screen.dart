part of '../staff_feature_screens.dart';

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
