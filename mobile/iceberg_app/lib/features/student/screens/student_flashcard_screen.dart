import 'dart:math' as math;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_tts/flutter_tts.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/storage/vocab_progress.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Flashcard mode — tap to flip, swipe / arrows to move, shuffle, audio and
/// per-direction known marking.
class StudentFlashcardScreen extends ConsumerStatefulWidget {
  final String vocabId;
  const StudentFlashcardScreen({super.key, required this.vocabId});

  @override
  ConsumerState<StudentFlashcardScreen> createState() =>
      _StudentFlashcardScreenState();
}

class _StudentFlashcardScreenState
    extends ConsumerState<StudentFlashcardScreen> {
  final _tts = FlutterTts();
  List<Map<String, dynamic>> _cards = [];
  int _index = 0;
  bool _flipped = false;
  bool _reverse = false; // false: word→meaning · true: meaning→word
  bool _seeded = false;

  int get _dayId => int.tryParse(widget.vocabId) ?? 0;
  String get _direction => _reverse ? 'rev' : 'fwd';

  @override
  void dispose() {
    _tts.stop();
    super.dispose();
  }

  Future<void> _speak(String text) async {
    await _tts.setLanguage('en-US');
    await _tts.speak(text);
  }

  void _move(int delta) {
    if (_cards.isEmpty) return;
    setState(() {
      _index = (_index + delta).clamp(0, _cards.length - 1);
      _flipped = false;
    });
  }

  void _shuffle() {
    setState(() {
      _cards.shuffle();
      _index = 0;
      _flipped = false;
    });
  }

  Future<void> _mark(bool known) async {
    final id = _cards[_index]['id'] as int;
    await VocabProgress.mark(_dayId, _direction, id, isKnown: known);
    ref.invalidate(vocabKnownProvider((_dayId, _direction)));
    if (_index < _cards.length - 1) {
      _move(1);
    } else {
      setState(() => _flipped = false);
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
          _cards = ((d['words'] as List?) ?? []).cast<Map<String, dynamic>>();
          _seeded = true;
        }
        return _buildBody(context, d);
      },
    );
  }

  Widget _buildBody(BuildContext context, Map<String, dynamic> d) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    if (_cards.isEmpty) {
      return EmptyState(
        icon: Icons.style_rounded,
        title: s('No words in this day'),
      );
    }
    final card = _cards[_index];
    final front = _reverse ? (card['meaning'] ?? '') : (card['word'] ?? '');
    final known = ref
        .watch(vocabKnownProvider((_dayId, _direction)))
        .maybeWhen(
          data: (ids) => ids.contains(card['id']),
          orElse: () => false,
        );

    return IcePage(
      title: s('Flashcards'),
      subtitle:
          '${s('Day')} ${d['day_number']} · ${_reverse ? s('Translation → Word') : s('Word → Translation')}',
      backButton: true,
      action: GestureDetector(
        onTap: () => setState(() {
          _reverse = !_reverse;
          _flipped = false;
        }),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(
            color: t.inset,
            borderRadius: BorderRadius.circular(999),
            border: Border.all(color: t.stroke),
          ),
          child: Icon(Icons.swap_horiz_rounded, size: 18, color: t.textHi),
        ),
      ),
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            StatusBadge(
              '${_index + 1} / ${_cards.length}',
              tone: BadgeTone.accent,
            ),
            const SizedBox(width: 8),
            if (known) StatusBadge('${s('Known')} ✓', tone: BadgeTone.sky),
          ],
        ),
        const SizedBox(height: 14),

        // ── Flip card ────────────────────────────────────────────────────
        GestureDetector(
          onTap: () => setState(() => _flipped = !_flipped),
          onHorizontalDragEnd: (details) {
            final v = details.primaryVelocity ?? 0;
            if (v < -200) _move(1);
            if (v > 200) _move(-1);
          },
          child: TweenAnimationBuilder<double>(
            tween: Tween(begin: 0, end: _flipped ? math.pi : 0),
            duration: const Duration(milliseconds: 380),
            curve: Curves.easeOutCubic,
            builder: (_, angle, __) {
              final showBack = angle > math.pi / 2;
              return Transform(
                alignment: Alignment.center,
                transform: Matrix4.identity()
                  ..setEntry(3, 2, 0.0012)
                  ..rotateY(angle),
                child: showBack
                    ? Transform(
                        alignment: Alignment.center,
                        transform: Matrix4.identity()..rotateY(math.pi),
                        child: _BackFace(
                          card: card,
                          reverse: _reverse,
                          onSpeak: _speak,
                        ),
                      )
                    : _FrontFace(
                        text: front,
                        hint: _reverse ? null : card['pronunciation_note'],
                        onSpeak: () => _speak(card['word'] ?? ''),
                      ),
              );
            },
          ),
        ),
        const SizedBox(height: 10),
        Center(
          child: Text(
            s('Tap card to flip · swipe to move'),
            style: TextStyle(fontSize: 12, color: t.textLow),
          ),
        ),
        const SizedBox(height: 18),

        // ── Controls ─────────────────────────────────────────────────────
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            _ControlButton(
              icon: Icons.arrow_back_rounded,
              enabled: _index > 0,
              onTap: () => _move(-1),
            ),
            const SizedBox(width: 14),
            _ControlButton(
              icon: Icons.shuffle_rounded,
              label: s('Shuffle'),
              onTap: _shuffle,
            ),
            const SizedBox(width: 14),
            _ControlButton(
              icon: Icons.arrow_forward_rounded,
              enabled: _index < _cards.length - 1,
              accent: true,
              onTap: () => _move(1),
            ),
          ],
        ),
        const SizedBox(height: 18),

        // ── Known / unknown ──────────────────────────────────────────────
        Row(
          children: [
            Expanded(
              child: SizedBox(
                height: 48,
                child: OutlinedButton.icon(
                  onPressed: () => _mark(false),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: t.coral,
                    side: BorderSide(color: t.coral.withValues(alpha: 0.5)),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                  ),
                  icon: const Icon(Icons.refresh_rounded, size: 18),
                  label: Text(
                    s('Need practice'),
                    style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13),
                  ),
                ),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: SizedBox(
                height: 48,
                child: FilledButton.icon(
                  onPressed: () => _mark(true),
                  style: FilledButton.styleFrom(
                    backgroundColor: t.accent,
                    foregroundColor: t.onAccent,
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                  ),
                  icon: const Icon(Icons.check_rounded, size: 18),
                  label: Text(
                    s('I know it'),
                    style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 13),
                  ),
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

class _FrontFace extends StatelessWidget {
  final String text;
  final String? hint;
  final VoidCallback onSpeak;
  const _FrontFace({required this.text, this.hint, required this.onSpeak});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      hero: true,
      radius: 26,
      padding: const EdgeInsets.all(24),
      child: SizedBox(
        height: 240,
        child: Stack(
          children: [
            Align(
              alignment: Alignment.topRight,
              child: GestureDetector(
                onTap: onSpeak,
                child: Container(
                  padding: const EdgeInsets.all(9),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: 0.08),
                    shape: BoxShape.circle,
                  ),
                  child: Icon(Icons.volume_up_rounded, size: 20, color: t.mint),
                ),
              ),
            ),
            Center(
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    text,
                    textAlign: TextAlign.center,
                    style: const TextStyle(
                      fontSize: 36,
                      fontWeight: FontWeight.w800,
                      color: Colors.white,
                      height: 1.2,
                    ),
                  ),
                  if (hint?.isNotEmpty == true) ...[
                    const SizedBox(height: 8),
                    Text(
                      hint!,
                      style: TextStyle(
                        fontSize: 16,
                        fontStyle: FontStyle.italic,
                        color: Colors.white.withValues(alpha: 0.5),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _BackFace extends StatelessWidget {
  final Map<String, dynamic> card;
  final bool reverse;
  final Future<void> Function(String) onSpeak;
  const _BackFace({
    required this.card,
    required this.reverse,
    required this.onSpeak,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      radius: 26,
      padding: const EdgeInsets.all(24),
      child: SizedBox(
        height: 240,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Flexible(
                  child: Text(
                    card['word'] ?? '',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 24,
                      fontWeight: FontWeight.w800,
                      color: t.accent,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                GestureDetector(
                  onTap: () => onSpeak(card['word'] ?? ''),
                  child: Icon(Icons.volume_up_rounded, size: 20, color: t.mint),
                ),
              ],
            ),
            if ((card['pronunciation_note'] as String?)?.isNotEmpty ==
                true) ...[
              const SizedBox(height: 4),
              Text(
                card['pronunciation_note'],
                style: TextStyle(
                  fontSize: 14,
                  fontStyle: FontStyle.italic,
                  color: t.textLow,
                ),
              ),
            ],
            const SizedBox(height: 12),
            Container(width: 60, height: 1.5, color: t.stroke),
            const SizedBox(height: 12),
            Text(
              card['meaning'] ?? '',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 19,
                fontWeight: FontWeight.w700,
                color: t.textHi,
                height: 1.35,
              ),
            ),
            if ((card['example_sentence'] as String?)?.isNotEmpty == true) ...[
              const SizedBox(height: 10),
              Text(
                card['example_sentence'],
                textAlign: TextAlign.center,
                maxLines: 3,
                overflow: TextOverflow.ellipsis,
                style: TextStyle(
                  fontSize: 13,
                  fontStyle: FontStyle.italic,
                  color: t.textMid,
                  height: 1.45,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _ControlButton extends StatelessWidget {
  final IconData icon;
  final String? label;
  final bool enabled;
  final bool accent;
  final VoidCallback onTap;

  const _ControlButton({
    required this.icon,
    this.label,
    this.enabled = true,
    this.accent = false,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return GestureDetector(
      onTap: enabled ? onTap : null,
      child: Container(
        padding: EdgeInsets.symmetric(
          horizontal: label != null ? 20 : 16,
          vertical: 14,
        ),
        decoration: BoxDecoration(
          color: accent && enabled ? t.accent : t.inset,
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: t.stroke),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 20,
              color: accent && enabled
                  ? t.onAccent
                  : enabled
                  ? t.textHi
                  : t.textLow,
            ),
            if (label != null) ...[
              const SizedBox(width: 7),
              Text(
                label!,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w700,
                  color: t.textHi,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
