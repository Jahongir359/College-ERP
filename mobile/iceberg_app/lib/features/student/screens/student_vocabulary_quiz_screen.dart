import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Quiz mode + result page. Questions come pre-shuffled from the server;
/// the attempt is saved on finish and the day auto-completes at ≥60%.
class StudentVocabularyQuizScreen extends ConsumerStatefulWidget {
  final int dayId;
  final String dayTitle;
  const StudentVocabularyQuizScreen({
    super.key,
    required this.dayId,
    required this.dayTitle,
  });

  @override
  ConsumerState<StudentVocabularyQuizScreen> createState() =>
      _StudentVocabularyQuizScreenState();
}

class _StudentVocabularyQuizScreenState
    extends ConsumerState<StudentVocabularyQuizScreen> {
  List<Map<String, dynamic>> _questions = [];
  int _index = 0;
  int _correct = 0;
  int? _selectedId;
  bool _revealed = false;
  bool _loading = true;
  Object? _loadError;
  bool _finished = false;
  bool _saving = false;
  double? _bestScore;
  DateTime? _completedAt;
  final List<Map<String, dynamic>> _wrong = [];

  @override
  void initState() {
    super.initState();
    _fetch();
  }

  Future<void> _fetch() async {
    setState(() {
      _loading = true;
      _loadError = null;
    });
    try {
      final res = await ApiClient.instance.dio.get(
        '/vocabulary/${widget.dayId}/quiz/',
      );
      final data = res.data as Map<String, dynamic>;
      setState(() {
        _questions = ((data['questions'] as List?) ?? [])
            .cast<Map<String, dynamic>>();
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _loadError = e;
        _loading = false;
      });
    }
  }

  void _choose(int id) {
    if (_revealed) return;
    setState(() {
      _selectedId = id;
      _revealed = true;
      final q = _questions[_index];
      if (id == q['correct_id']) {
        _correct++;
      } else {
        _wrong.add(q);
      }
    });
  }

  Future<void> _next() async {
    if (_index < _questions.length - 1) {
      setState(() {
        _index++;
        _selectedId = null;
        _revealed = false;
      });
    } else {
      setState(() {
        _finished = true;
        _saving = true;
        _completedAt = DateTime.now();
      });
      try {
        final res = await ApiClient.instance.dio.post(
          '/vocabulary/${widget.dayId}/quiz-result/',
          data: {'correct': _correct, 'total': _questions.length},
        );
        final d = res.data as Map<String, dynamic>;
        setState(() => _bestScore = (d['best_score'] as num?)?.toDouble());
        ref.invalidate(vocabularyProvider);
        ref.invalidate(vocabDayProvider(widget.dayId));
        ref.invalidate(studentProgressProvider);
      } on DioException {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text(
                'Score could not be saved — check your connection.',
              ),
            ),
          );
        }
      } finally {
        if (mounted) setState(() => _saving = false);
      }
    }
  }

  void _retry() => setState(() {
    _index = 0;
    _correct = 0;
    _selectedId = null;
    _revealed = false;
    _finished = false;
    _bestScore = null;
    _wrong.clear();
    _fetch();
  });

  @override
  Widget build(BuildContext context) {
    final s = ref.watch(stringsProvider);
    if (_loading) return const PageSkeleton();
    if (_loadError != null) {
      return ErrorState(error: _loadError, onRetry: _fetch);
    }
    if (_questions.isEmpty) {
      return EmptyState(
        icon: Icons.quiz_outlined,
        title: s('Quiz unavailable'),
        message: s('This day needs at least 2 words for a quiz.'),
      );
    }
    return _finished ? _buildResult(context) : _buildQuiz(context);
  }

  // ── Quiz ───────────────────────────────────────────────────────────────
  Widget _buildQuiz(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final q = _questions[_index];
    final choices = ((q['choices'] as List?) ?? [])
        .cast<Map<String, dynamic>>();
    final letters = ['A', 'B', 'C', 'D', 'E'];

    return IcePage(
      title: widget.dayTitle,
      subtitle: '${s('Quiz')} · ${s('Question')} ${_index + 1} / ${_questions.length}',
      backButton: true,
      children: [
        ClipRRect(
          borderRadius: BorderRadius.circular(99),
          child: LinearProgressIndicator(
            value: (_index + (_revealed ? 1 : 0)) / _questions.length,
            minHeight: 6,
            backgroundColor: t.inset,
            valueColor: AlwaysStoppedAnimation(t.accent),
          ),
        ),
        const SizedBox(height: 20),
        Text(
          'Choose the correct word for the meaning below:',
          style: TextStyle(fontSize: 13, color: t.textMid),
        ),
        const SizedBox(height: 10),
        IceCard(
          hero: true,
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                q['meaning'] ?? '',
                style: const TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.w800,
                  color: Colors.white,
                  height: 1.35,
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        ...List.generate(choices.length, (i) {
          final c = choices[i];
          final id = c['id'] as int;
          final isCorrect = id == q['correct_id'];
          final isSelected = id == _selectedId;

          Color border = t.stroke;
          Color bg = t.card;
          Widget? trailing;
          if (_revealed) {
            if (isCorrect) {
              border = t.accent;
              bg = t.accent.withValues(alpha: 0.1);
              trailing = Icon(
                Icons.check_circle_rounded,
                size: 20,
                color: t.accent,
              );
            } else if (isSelected) {
              border = t.coral;
              bg = t.coral.withValues(alpha: 0.1);
              trailing = Icon(Icons.cancel_rounded, size: 20, color: t.coral);
            }
          } else if (isSelected) {
            border = t.accent;
          }

          return Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: GestureDetector(
              onTap: () => _choose(id),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 180),
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 14,
                ),
                decoration: BoxDecoration(
                  color: bg,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: border, width: 1.4),
                ),
                child: Row(
                  children: [
                    Text(
                      '${letters[i % letters.length]}.',
                      style: TextStyle(
                        fontSize: 14,
                        fontWeight: FontWeight.w800,
                        color: t.textMid,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Text(
                        c['word'] ?? '',
                        style: TextStyle(
                          fontSize: 15.5,
                          fontWeight: FontWeight.w700,
                          color: t.textHi,
                        ),
                      ),
                    ),
                    if (trailing != null) trailing,
                  ],
                ),
              ),
            ),
          );
        }),
        const SizedBox(height: 10),
        IceButton(
          _index == _questions.length - 1 ? 'Finish Quiz' : 'Next Question',
          onPressed: _revealed ? _next : null,
        ),
      ],
    );
  }

  // ── Result ─────────────────────────────────────────────────────────────
  Widget _buildResult(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final total = _questions.length;
    final score = total == 0 ? 0.0 : _correct / total * 100;
    final passed = score >= 60;

    return IcePage(
      title: s('Quiz Result'),
      subtitle: widget.dayTitle,
      backButton: true,
      children: [
        const SizedBox(height: 8),
        Center(
          child: ProgressRing(
            value: score / 100,
            size: 160,
            strokeWidth: 13,
            color: passed ? t.accent : t.coral,
            center: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  '${score.toStringAsFixed(0)}%',
                  style: TextStyle(
                    fontSize: 34,
                    fontWeight: FontWeight.w800,
                    color: t.textHi,
                  ),
                ),
                Text(
                  passed ? s('Great Job! 🎉') : s('Keep Going!'),
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: t.textMid,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 22),
        Row(
          children: [
            Expanded(
              child: _ResultStat(
                label: s('Correct'),
                value: '$_correct',
                color: t.accent,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _ResultStat(
                label: s('Incorrect'),
                value: '${total - _correct}',
                color: t.coral,
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: _ResultStat(
                label: s('Total'),
                value: '$total',
                color: t.textHi,
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),
        IceCard(
          padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    MicroLabel(s('Best score')),
                    const SizedBox(height: 4),
                    Text(
                      _saving
                          ? s('Saving…')
                          : _bestScore != null
                          ? '${_bestScore!.toStringAsFixed(0)}%'
                          : '${score.toStringAsFixed(0)}%',
                      style: TextStyle(
                        fontSize: 17,
                        fontWeight: FontWeight.w800,
                        color: t.accent,
                      ),
                    ),
                  ],
                ),
              ),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  MicroLabel(s('Completed')),
                  const SizedBox(height: 4),
                  Text(
                    _completedAt != null
                        ? DateFormat('MMM d, yyyy').format(_completedAt!)
                        : '—',
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                      color: t.textHi,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 8),
        Center(
          child: Text(
            passed
                ? 'Day marked as completed — score saved automatically.'
                : 'Score saved. Reach 60% or higher to complete the day.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: t.textLow),
          ),
        ),
        const SizedBox(height: 18),

        if (_wrong.isNotEmpty) ...[
          const SectionHeader('Review wrong answers'),
          ..._wrong.map(
            (q) => Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: IceCard(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      q['meaning'] ?? '',
                      style: TextStyle(
                        fontSize: 13.5,
                        color: t.textMid,
                        height: 1.4,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '✓ ${(((q['choices'] as List?) ?? []).cast<Map<String, dynamic>>().firstWhere((c) => c['id'] == q['correct_id'], orElse: () => {'word': ''}))['word']}',
                      style: TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w800,
                        color: t.accent,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(height: 8),
        ],

        IceButton(s('Retry Quiz'), icon: Icons.replay_rounded, onPressed: _retry),
        const SizedBox(height: 10),
        IceButton(
          'Back to Vocabulary',
          secondary: true,
          onPressed: () => context.go('/student/vocabulary'),
        ),
      ],
    );
  }
}

class _ResultStat extends StatelessWidget {
  final String label;
  final String value;
  final Color color;
  const _ResultStat({
    required this.label,
    required this.value,
    required this.color,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      radius: 16,
      padding: const EdgeInsets.symmetric(vertical: 14),
      child: Column(
        children: [
          Text(
            value,
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.w800,
              color: color,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            label,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: t.textMid,
            ),
          ),
        ],
      ),
    );
  }
}
