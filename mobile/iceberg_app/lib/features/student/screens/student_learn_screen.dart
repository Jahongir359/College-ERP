import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_tts/flutter_tts.dart';
import 'package:go_router/go_router.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/storage/vocab_progress.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Oʻrganish (Learn) mode — word + translation + example shown together,
/// sorted into "known" and "need practice" piles. The day is marked complete
/// on the server when every word is known.
class StudentLearnScreen extends ConsumerStatefulWidget {
  final String vocabId;
  const StudentLearnScreen({super.key, required this.vocabId});

  @override
  ConsumerState<StudentLearnScreen> createState() => _StudentLearnScreenState();
}

class _StudentLearnScreenState extends ConsumerState<StudentLearnScreen> {
  final _tts = FlutterTts();
  List<Map<String, dynamic>> _queue = [];
  int _knownCount = 0;
  int _practiceCount = 0;
  int _total = 0;
  bool _seeded = false;
  bool _finished = false;

  int get _dayId => int.tryParse(widget.vocabId) ?? 0;

  @override
  void dispose() {
    _tts.stop();
    super.dispose();
  }

  Future<void> _speak(String text) async {
    await _tts.setLanguage('en-US');
    await _tts.speak(text);
  }

  Future<void> _answer(bool known) async {
    final word = _queue.removeAt(0);
    await VocabProgress.mark(_dayId, 'fwd', word['id'] as int, isKnown: known);
    ref.invalidate(vocabKnownProvider((_dayId, 'fwd')));
    setState(() {
      if (known) {
        _knownCount++;
      } else {
        _practiceCount++;
        _queue.add(word); // practice words come back around
      }
      if (_queue.isEmpty) _finished = true;
    });
    if (_queue.isEmpty) {
      // Every word marked known → complete the day on the server.
      try {
        await ApiClient.instance.dio.post('/vocabulary/$_dayId/complete/');
        ref.invalidate(vocabularyProvider);
        ref.invalidate(vocabDayProvider(_dayId));
      } catch (_) {
        /* completion is best-effort; quiz can also complete it */
      }
    }
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
      data: (d) {
        if (!_seeded) {
          final words = ((d['words'] as List?) ?? [])
              .cast<Map<String, dynamic>>();
          _queue = [...words];
          _total = words.length;
          _seeded = true;
        }
        return _buildBody(context, d);
      },
    );
  }

  Widget _buildBody(BuildContext context, Map<String, dynamic> d) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);

    if (_total == 0) {
      return EmptyState(
        icon: Icons.school_rounded,
        title: s('No words to learn'),
      );
    }

    if (_finished) {
      return IcePage(
        title: s('Learn'),
        backButton: true,
        children: [
          const SizedBox(height: 30),
          Center(
            child: ProgressRing(
              value: 1,
              size: 130,
              strokeWidth: 11,
              center: Icon(Icons.check_rounded, size: 44, color: t.accent),
            ),
          ),
          const SizedBox(height: 22),
          Center(
            child: Text(
              '${s('Day')} ${d['day_number']} ${s('learned!')} 🎉',
              style: TextStyle(
                fontSize: 21,
                fontWeight: FontWeight.w800,
                color: t.textHi,
              ),
            ),
          ),
          const SizedBox(height: 8),
          Center(
            child: Text(
              '${s('Known first try:')} $_knownCount · ${s('Needed practice:')} $_practiceCount',
              style: TextStyle(fontSize: 13.5, color: t.textMid),
            ),
          ),
          const SizedBox(height: 28),
          IceButton(
            s('Take the Test'),
            icon: Icons.quiz_rounded,
            onPressed: () => context.go(
              '/student/vocabulary/${widget.vocabId}/quiz?title=Day ${d['day_number']}',
            ),
          ),
          const SizedBox(height: 10),
          IceButton(
            s('Back to Day'),
            secondary: true,
            onPressed: () =>
                context.go('/student/vocabulary/${widget.vocabId}'),
          ),
        ],
      );
    }

    final word = _queue.first;
    final progress =
        (_total - _queue.length + _practiceCount) / (_total + _practiceCount);

    return IcePage(
      title: s('Learn'),
      subtitle: '${s('Day')} ${d['day_number']} · ${_queue.length} ${s('left')}',
      backButton: true,
      children: [
        ClipRRect(
          borderRadius: BorderRadius.circular(99),
          child: LinearProgressIndicator(
            value: progress.clamp(0.0, 1.0),
            minHeight: 6,
            backgroundColor: t.inset,
            valueColor: AlwaysStoppedAnimation(t.accent),
          ),
        ),
        const SizedBox(height: 18),
        IceCard(
          hero: true,
          radius: 26,
          padding: const EdgeInsets.all(24),
          child: Column(
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Flexible(
                    child: Text(
                      word['word'] ?? '',
                      textAlign: TextAlign.center,
                      style: const TextStyle(
                        fontSize: 30,
                        fontWeight: FontWeight.w800,
                        color: Colors.white,
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  GestureDetector(
                    onTap: () => _speak(word['word'] ?? ''),
                    child: Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: Colors.white.withValues(alpha: 0.08),
                        shape: BoxShape.circle,
                      ),
                      child: Icon(
                        Icons.volume_up_rounded,
                        size: 19,
                        color: t.mint,
                      ),
                    ),
                  ),
                ],
              ),
              if ((word['pronunciation_note'] as String?)?.isNotEmpty ==
                  true) ...[
                const SizedBox(height: 5),
                Text(
                  word['pronunciation_note'],
                  style: TextStyle(
                    fontSize: 14,
                    fontStyle: FontStyle.italic,
                    color: Colors.white.withValues(alpha: 0.5),
                  ),
                ),
              ],
              const SizedBox(height: 16),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: Colors.white.withValues(alpha: 0.06),
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Column(
                  children: [
                    Text(
                      word['meaning'] ?? '',
                      textAlign: TextAlign.center,
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.w700,
                        color: t.accent,
                      ),
                    ),
                    if ((word['example_sentence'] as String?)?.isNotEmpty ==
                        true) ...[
                      const SizedBox(height: 8),
                      Text(
                        word['example_sentence'],
                        textAlign: TextAlign.center,
                        style: TextStyle(
                          fontSize: 13,
                          fontStyle: FontStyle.italic,
                          color: Colors.white.withValues(alpha: 0.65),
                          height: 1.45,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 20),
        Row(
          children: [
            Expanded(
              child: SizedBox(
                height: 52,
                child: OutlinedButton.icon(
                  onPressed: () => _answer(false),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: t.coral,
                    side: BorderSide(color: t.coral.withValues(alpha: 0.5)),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16),
                    ),
                  ),
                  icon: const Icon(Icons.refresh_rounded, size: 19),
                  label: Text(
                    s('Need practice'),
                    style: const TextStyle(
                      fontWeight: FontWeight.w700,
                      fontSize: 13.5,
                    ),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: SizedBox(
                height: 52,
                child: FilledButton.icon(
                  onPressed: () => _answer(true),
                  style: FilledButton.styleFrom(
                    backgroundColor: t.accent,
                    foregroundColor: t.onAccent,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16),
                    ),
                  ),
                  icon: const Icon(Icons.check_rounded, size: 19),
                  label: Text(
                    s('I know it'),
                    style: const TextStyle(
                      fontWeight: FontWeight.w800,
                      fontSize: 13.5,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),
        Center(
          child: Text(
            '✓ $_knownCount known   ↻ $_practiceCount practising',
            style: TextStyle(fontSize: 12.5, color: t.textMid),
          ),
        ),
      ],
    );
  }
}
