import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_tts/flutter_tts.dart';
import 'package:go_router/go_router.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/storage/vocab_progress.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Vocabulary Day Detail — flashcard preview, direction progress, mode
/// launcher (Kartochkalar · Oʻrganish · Test) and the word list.
class StudentVocabularyDetailScreen extends ConsumerStatefulWidget {
  final String vocabId;
  const StudentVocabularyDetailScreen({super.key, required this.vocabId});

  @override
  ConsumerState<StudentVocabularyDetailScreen> createState() =>
      _StudentVocabularyDetailScreenState();
}

class _StudentVocabularyDetailScreenState
    extends ConsumerState<StudentVocabularyDetailScreen> {
  final _preview = PageController();
  final _tts = FlutterTts();
  int _previewIndex = 0;
  bool _shuffled = false;

  int get _dayId => int.tryParse(widget.vocabId) ?? 0;

  @override
  void dispose() {
    _preview.dispose();
    _tts.stop();
    super.dispose();
  }

  Future<void> _speak(String word) async {
    await _tts.setLanguage('en-US');
    await _tts.speak(word);
  }

  @override
  Widget build(BuildContext context) {
    final day = ref.watch(vocabDayProvider(_dayId));

    return day.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.invalidate(vocabDayProvider(_dayId)),
      ),
      data: (d) => _buildBody(context, d),
    );
  }

  Widget _buildBody(BuildContext context, Map<String, dynamic> d) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final words = ((d['words'] as List?) ?? []).cast<Map<String, dynamic>>();
    final sorted = [...words];
    if (_shuffled) sorted.shuffle();
    final previewWords = words.take(5).toList();

    final knownFwd = ref.watch(vocabKnownProvider((_dayId, 'fwd')));
    final knownRev = ref.watch(vocabKnownProvider((_dayId, 'rev')));
    final wordIds = words.map((w) => w['id'] as int).toSet();
    int countIn(AsyncValue<Set<int>> v) => v.maybeWhen(
      data: (ids) => ids.intersection(wordIds).length,
      orElse: () => 0,
    );

    return IcePage(
      title: '${s('Day')} ${d['day_number']}',
      subtitle:
          '${words.length} ${s('Words')}'
          '${(d['title'] as String?)?.isNotEmpty == true ? ' · ${d['title']}' : ''}',
      backButton: true,
      onRefresh: () async => ref.refresh(vocabDayProvider(_dayId).future),
      children: [
        // ── Big flashcard preview ────────────────────────────────────────
        if (previewWords.isNotEmpty) ...[
          IceCard(
            hero: true,
            padding: EdgeInsets.zero,
            radius: 26,
            child: SizedBox(
              height: 190,
              child: Column(
                children: [
                  Expanded(
                    child: PageView.builder(
                      controller: _preview,
                      itemCount: previewWords.length,
                      onPageChanged: (i) => setState(() => _previewIndex = i),
                      itemBuilder: (_, i) => Center(
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Text(
                              previewWords[i]['word'] ?? '',
                              textAlign: TextAlign.center,
                              style: const TextStyle(
                                fontSize: 34,
                                fontWeight: FontWeight.w800,
                                color: Colors.white,
                              ),
                            ),
                            if ((previewWords[i]['pronunciation_note']
                                        as String?)
                                    ?.isNotEmpty ==
                                true) ...[
                              const SizedBox(height: 6),
                              Text(
                                previewWords[i]['pronunciation_note'],
                                style: TextStyle(
                                  fontSize: 15,
                                  fontStyle: FontStyle.italic,
                                  color: Colors.white.withValues(alpha: 0.55),
                                ),
                              ),
                            ],
                          ],
                        ),
                      ),
                    ),
                  ),
                  Padding(
                    padding: const EdgeInsets.only(bottom: 16),
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: List.generate(
                        previewWords.length,
                        (i) => AnimatedContainer(
                          duration: const Duration(milliseconds: 200),
                          margin: const EdgeInsets.symmetric(horizontal: 3),
                          width: i == _previewIndex ? 8 : 6,
                          height: i == _previewIndex ? 8 : 6,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            color: i == _previewIndex
                                ? t.accent
                                : Colors.white.withValues(alpha: 0.3),
                          ),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
        ],

        // ── Direction progress ───────────────────────────────────────────
        _DirectionRow(
          label: s('Word → Translation'),
          done: countIn(knownFwd),
          total: words.length,
        ),
        const SizedBox(height: 8),
        _DirectionRow(
          label: s('Translation → Word'),
          done: countIn(knownRev),
          total: words.length,
        ),
        const SizedBox(height: 18),

        // ── Mode launcher ────────────────────────────────────────────────
        ActionTile(
          icon: Icons.style_rounded,
          title: s('Flashcards'),
          subtitle: s('Flip through flashcards'),
          onTap: () =>
              context.go('/student/vocabulary/${widget.vocabId}/flashcards'),
        ),
        const SizedBox(height: 10),
        ActionTile(
          icon: Icons.school_rounded,
          iconColor: t.mint,
          title: s('Learn'),
          subtitle: s('Learn with known / practice piles'),
          onTap: () =>
              context.go('/student/vocabulary/${widget.vocabId}/learn'),
        ),
        const SizedBox(height: 10),
        ActionTile(
          icon: Icons.quiz_rounded,
          iconColor: t.sky,
          title: s('Test'),
          subtitle: s('Multiple-choice quiz · 60% to complete the day'),
          onTap: () => context.go(
            '/student/vocabulary/${widget.vocabId}/quiz?title=Day ${d['day_number']}',
          ),
        ),
        const SizedBox(height: 22),

        // ── Word list ────────────────────────────────────────────────────
        SectionHeader(
          s('Flashcards'),
          actionLabel: _shuffled ? '${s('Shuffled')} ✓' : s('Original order'),
          onAction: () => setState(() => _shuffled = !_shuffled),
        ),
        ...sorted.map(
          (w) => Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: IceCard(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Expanded(
                        child: Text(
                          w['word'] ?? '',
                          style: TextStyle(
                            fontSize: 17,
                            fontWeight: FontWeight.w800,
                            color: t.textHi,
                          ),
                        ),
                      ),
                      GestureDetector(
                        onTap: () => _speak(w['word'] ?? ''),
                        child: Icon(
                          Icons.volume_up_rounded,
                          size: 20,
                          color: t.mint,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  Text(
                    w['meaning'] ?? '',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: t.textMid,
                    ),
                  ),
                  if ((w['example_sentence'] as String?)?.isNotEmpty ==
                      true) ...[
                    const SizedBox(height: 6),
                    Text(
                      w['example_sentence'],
                      style: TextStyle(
                        fontSize: 12.5,
                        fontStyle: FontStyle.italic,
                        color: t.textLow,
                        height: 1.4,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }
}

class _DirectionRow extends StatelessWidget {
  final String label;
  final int done;
  final int total;
  const _DirectionRow({
    required this.label,
    required this.done,
    required this.total,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final complete = total > 0 && done >= total;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
      decoration: BoxDecoration(
        color: t.card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: t.stroke),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w700,
                color: complete ? t.accent : t.textHi,
              ),
            ),
          ),
          StatusBadge(
            '$done/$total',
            tone: complete ? BadgeTone.accent : BadgeTone.neutral,
          ),
        ],
      ),
    );
  }
}
