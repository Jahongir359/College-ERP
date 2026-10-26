part of '../staff_feature_screens.dart';

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
                          _toast(
                            dctx,
                            e.response?.data?['detail']?.toString() ??
                                'Could not create.',
                          );
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
                          _toast(
                            dctx,
                            e.response?.data?['detail']?.toString() ??
                                'Could not add.',
                          );
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
                ref.invalidate(staffVocabDetailProvider(id));
                ref.invalidate(staffVocabularyProvider);
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
