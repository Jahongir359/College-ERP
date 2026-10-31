import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../../core/api/api_client.dart';
import '../../../../core/api/api_providers.dart';
import '../../../../core/i18n/strings.dart';
import '../../../../core/settings/app_settings.dart';
import '../../../../core/theme/brand.dart';
import '../../../../core/theme/ice_tokens.dart';
import '../../../../shared/widgets/ice_kit.dart';
import '../../../../shared/widgets/ice_shell.dart';

// ════════════════════════════════════════════════════════════════════════════
//  Daily register (plan P4.6, design screens 11–13)
//
//  The homeroom teacher marks a School class once a day. Every pupil starts as
//  present, so the teacher only taps the few who are late or absent, then
//  saves. API: `school/register/` (my classes today) and
//  `school/register/<class>/<YYYY-MM-DD>/` (one day, GET and POST), P2.2.
// ════════════════════════════════════════════════════════════════════════════

String _isoDay(DateTime d) => DateFormat('yyyy-MM-dd').format(d);

/// The classes whose register this teacher takes, with today's state.
final myRegistersProvider = FutureProvider.autoDispose<List<dynamic>>((_) async {
  final data = await apiGet('/school/register/');
  return (data['classes'] as List?) ?? [];
});

/// One class's register for a day. Key: `"<class id>|<YYYY-MM-DD>"`.
final registerProvider =
    FutureProvider.autoDispose.family<Map<String, dynamic>, String>((_, key) {
  final [id, day] = key.split('|');
  return apiGet('/school/register/$id/$day/');
});

/// Saves one class's register for a day (POST). A provider so tests can fake
/// the network.
typedef RegisterSaver = Future<void> Function(
    int classId, String day, List<Map<String, dynamic>> records);

final registerSaverProvider = Provider<RegisterSaver>(
  (_) => (classId, day, records) => ApiClient.instance.dio.post(
        '/school/register/$classId/$day/',
        data: {'records': records},
      ),
);

/// "Thursday, 24 October" in the app language, via strings.dart templates.
String registerDayTitle(S s, DateTime d) {
  const weekdays = [
    'Monday',
    'Tuesday',
    'Wednesday',
    'Thursday',
    'Friday',
    'Saturday',
    'Sunday',
  ];
  const months = [
    '{d} January',
    '{d} February',
    '{d} March',
    '{d} April',
    '{d} May',
    '{d} June',
    '{d} July',
    '{d} August',
    '{d} September',
    '{d} October',
    '{d} November',
    '{d} December',
  ];
  final day = s(months[d.month - 1]).replaceAll('{d}', '${d.day}');
  return '${s(weekdays[d.weekday - 1])}, $day';
}

// Status colours from the approved mockup 12 (green / amber / red pills).
class _Tone {
  final Color fg;
  final Color bg;
  const _Tone(this.fg, this.bg);

  static _Tone of(String status, bool dark) => switch (status) {
        'late' => dark
            ? const _Tone(Color(0xFFE9C77E), Color(0xFF33260F))
            : const _Tone(Color(0xFF8A5A12), Color(0xFFFBF0D9)),
        'absent' => dark
            ? const _Tone(Color(0xFFF2A39A), Color(0xFF3A1513))
            : const _Tone(Color(0xFFA8322A), Color(0xFFFBE6E3)),
        _ => dark
            ? const _Tone(Color(0xFF7FD3A0), Color(0xFF12301F))
            : const _Tone(Color(0xFF17633A), Color(0xFFE3F4EA)),
      };
}

class _Mark {
  String status;
  String? arrival; // "HH:MM", late only
  String note;
  _Mark(this.status, this.arrival, this.note);
}

/// Always starts with "not saved, try again"; adds the server's reason, if any.
String _apiError(Object e, S s) {
  final notSaved = s('Could not save the register. Try again.');
  if (e is DioException) {
    final data = e.response?.data;
    if (data is Map) {
      final detail = data['detail'] ?? data['date'] ?? data['records'];
      String? reason;
      if (detail is String) reason = detail;
      if (detail is List && detail.isNotEmpty) reason = '${detail.first}';
      if (detail is Map && detail.isNotEmpty) reason = '${detail.values.first}';
      if (reason != null && reason.isNotEmpty) return '$notSaved\n$reason';
    }
  }
  return notSaved;
}

// ─── Register screen ─────────────────────────────────────────────────────────
class StaffRegisterScreen extends ConsumerStatefulWidget {
  final int classId;
  final DateTime day;
  const StaffRegisterScreen({
    super.key,
    required this.classId,
    required this.day,
  });

  @override
  ConsumerState<StaffRegisterScreen> createState() =>
      _StaffRegisterScreenState();
}

class _StaffRegisterScreenState extends ConsumerState<StaffRegisterScreen> {
  // Marks the teacher changed on this screen, by student id.
  final Map<int, _Mark> _edits = {};
  bool _saving = false;

  String get _key => '${widget.classId}|${_isoDay(widget.day)}';

  _Mark _markOf(Map<String, dynamic> pupil) {
    final id = pupil['student_id'] as int;
    return _edits[id] ??
        _Mark(
          pupil['status'] as String? ?? 'present',
          pupil['arrival_time'] as String?,
          pupil['note'] as String? ?? '',
        );
  }

  void _set(Map<String, dynamic> pupil, _Mark mark) =>
      setState(() => _edits[pupil['student_id'] as int] = mark);

  Future<void> _save(List pupils) async {
    final s = ref.read(stringsProvider);
    setState(() => _saving = true);
    final records = <Map<String, dynamic>>[
      for (final p in pupils.cast<Map<String, dynamic>>())
        if (_markOf(p).status != 'present' || _markOf(p).note.isNotEmpty)
          {
            'student_id': p['student_id'],
            'status': _markOf(p).status,
            if (_markOf(p).arrival != null) 'arrival_time': _markOf(p).arrival,
            'note': _markOf(p).note,
          },
    ];
    try {
      await ref
          .read(registerSaverProvider)(widget.classId, _isoDay(widget.day), records);
      ref.invalidate(myRegistersProvider);
      ref.invalidate(registerProvider(_key));
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(s('Register saved'))));
      if (context.canPop()) context.pop();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text(_apiError(e, s))));
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _openLate(Map<String, dynamic> pupil) async {
    final mark = await showModalBottomSheet<_Mark>(
      context: context,
      isScrollControlled: true,
      backgroundColor: context.ice.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => _LateSheet(pupil: pupil, current: _markOf(pupil)),
    );
    if (mark != null) _set(pupil, mark);
  }

  Future<void> _openNote(Map<String, dynamic> pupil) async {
    final current = _markOf(pupil);
    final note = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      backgroundColor: context.ice.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => _NoteSheet(pupil: pupil, note: current.note),
    );
    if (note != null) _set(pupil, _Mark(current.status, current.arrival, note));
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final register = ref.watch(registerProvider(_key));

    return Scaffold(
      backgroundColor: t.bg,
      body: SafeArea(
        bottom: false,
        child: register.when(
          loading: () => const PageSkeleton(),
          error: (e, _) => IcePage(
            title: s('Register'),
            subtitle: registerDayTitle(s, widget.day),
            backButton: true,
            children: [
              EmptyState(
                icon: Icons.wifi_off_rounded,
                title: s('Could not load the register'),
                message: s('Check your connection and try again.'),
                action: IceButton(
                  s('Retry'),
                  onPressed: () => ref.invalidate(registerProvider(_key)),
                ),
              ),
            ],
          ),
          data: (d) => _body(context, s, d),
        ),
      ),
      bottomNavigationBar: register.maybeWhen(
        data: (d) {
          final pupils = (d['students'] as List?) ?? [];
          if (d['can_edit'] != true || pupils.isEmpty) return null;
          return SafeArea(
            child: Container(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 12),
              decoration: BoxDecoration(
                color: t.card,
                border: Border(top: BorderSide(color: t.stroke)),
              ),
              child: IceButton(
                s('Save · {n} pupils').replaceAll('{n}', '${pupils.length}'),
                busy: _saving,
                onPressed: _saving ? null : () => _save(pupils),
              ),
            ),
          );
        },
        orElse: () => null,
      ),
    );
  }

  Widget _body(BuildContext context, S s, Map<String, dynamic> d) {
    final t = context.ice;
    final pupils = ((d['students'] as List?) ?? []).cast<Map<String, dynamic>>();
    final canEdit = d['can_edit'] == true;
    final counts = {'present': 0, 'late': 0, 'absent': 0};
    for (final p in pupils) {
      counts[_markOf(p).status] = (counts[_markOf(p).status] ?? 0) + 1;
    }
    final className = (d['class'] as Map?)?['name']?.toString() ?? '';

    String hint;
    if (!canEdit) {
      hint = s('Only the homeroom teacher can change this register.');
    } else if (d['taken'] == true) {
      final at = DateTime.tryParse(d['taken_at']?.toString() ?? '')?.toLocal();
      hint = s('Saved at {time}. Change a mark and save again.')
          .replaceAll('{time}', at != null ? DateFormat('HH:mm').format(at) : '');
    } else {
      hint = s('Everyone is marked present. Tap only the pupils who are not.');
    }

    return IcePage(
      title: '${s('Register')} · $className',
      subtitle: registerDayTitle(s, widget.day),
      backButton: true,
      onRefresh: () async {
        setState(_edits.clear);
        ref.invalidate(registerProvider(_key));
        await ref.read(registerProvider(_key).future);
      },
      children: [
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            _CountChip(
              text: s('{n} present').replaceAll('{n}', '${counts['present']}'),
              status: 'present',
            ),
            _CountChip(
              text: s('{n} late').replaceAll('{n}', '${counts['late']}'),
              status: 'late',
            ),
            _CountChip(
              text: s('{n} absent').replaceAll('{n}', '${counts['absent']}'),
              status: 'absent',
            ),
          ],
        ),
        const SizedBox(height: 10),
        Text(hint, style: TextStyle(fontSize: 13, color: t.textMid)),
        const SizedBox(height: 8),
        if (pupils.isEmpty)
          IceCard(
            child: EmptyState(
              icon: Icons.person_off_outlined,
              title: s('No students enrolled yet'),
            ),
          )
        else
          for (final p in pupils)
            _PupilRow(
              pupil: p,
              mark: _markOf(p),
              enabled: canEdit,
              onPresent: () => _set(p, _Mark('present', null, '')),
              onLate: () => _openLate(p),
              onAbsent: () => _set(p, _Mark('absent', null, _markOf(p).note)),
              onNote: () => _openNote(p),
            ),
      ],
    );
  }
}

// ─── Pieces ──────────────────────────────────────────────────────────────────
class _CountChip extends StatelessWidget {
  final String text;
  final String status;
  const _CountChip({required this.text, required this.status});

  @override
  Widget build(BuildContext context) {
    final tone = _Tone.of(status, context.ice.isDark);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: tone.bg,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        text,
        style: TextStyle(
          fontSize: 13,
          fontWeight: FontWeight.w700,
          color: tone.fg,
        ),
      ),
    );
  }
}

class _Initials extends StatelessWidget {
  final String text;
  const _Initials(this.text);

  @override
  Widget build(BuildContext context) => Container(
        width: 42,
        height: 42,
        alignment: Alignment.center,
        decoration: const BoxDecoration(
          color: Color(0xFFE9C77E), // School gold, as in the mockups
          shape: BoxShape.circle,
        ),
        child: Text(
          text,
          style: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w800,
            color: SchoolColors.primaryDeep,
          ),
        ),
      );
}

class _PupilRow extends ConsumerWidget {
  final Map<String, dynamic> pupil;
  final _Mark mark;
  final bool enabled;
  final VoidCallback onPresent;
  final VoidCallback onLate;
  final VoidCallback onAbsent;
  final VoidCallback onNote;

  const _PupilRow({
    required this.pupil,
    required this.mark,
    required this.enabled,
    required this.onPresent,
    required this.onLate,
    required this.onAbsent,
    required this.onNote,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final tone = _Tone.of(mark.status, t.isDark);
    final detail = [
      if (mark.status == 'late' && mark.arrival != null)
        s('Arrived {time}').replaceAll('{time}', mark.arrival!),
      if (mark.note.isNotEmpty) mark.note,
    ].join(' · ');

    return Container(
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(
        border: Border(bottom: BorderSide(color: t.stroke)),
      ),
      child: Row(
        children: [
          Expanded(
            child: InkWell(
              onTap: enabled ? onNote : null,
              borderRadius: BorderRadius.circular(12),
              child: Row(
                children: [
                  _Initials(pupil['initials']?.toString() ?? ''),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          pupil['name']?.toString() ?? '',
                          style: TextStyle(
                            fontSize: 15.5,
                            fontWeight: FontWeight.w700,
                            color: t.textHi,
                          ),
                        ),
                        if (detail.isNotEmpty)
                          Text(
                            detail,
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                            style: TextStyle(
                              fontSize: 12.5,
                              fontWeight: FontWeight.w600,
                              color: mark.status == 'present'
                                  ? t.textMid
                                  : tone.fg,
                            ),
                          ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 8),
          _StatusToggle(
            status: mark.status,
            enabled: enabled,
            onPresent: onPresent,
            onLate: onLate,
            onAbsent: onAbsent,
          ),
        ],
      ),
    );
  }
}

/// Three-way switch: ✓ present · clock late · ✕ absent. The chosen one shows
/// its word on a coloured pill; the others are plain icons.
class _StatusToggle extends ConsumerWidget {
  final String status;
  final bool enabled;
  final VoidCallback onPresent;
  final VoidCallback onLate;
  final VoidCallback onAbsent;

  const _StatusToggle({
    required this.status,
    required this.enabled,
    required this.onPresent,
    required this.onLate,
    required this.onAbsent,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);

    Widget option(String value, IconData icon, String label, VoidCallback tap) {
      final on = status == value;
      final tone = _Tone.of(value, t.isDark);
      return Semantics(
        button: true,
        selected: on,
        label: label,
        child: InkWell(
          onTap: enabled ? tap : null,
          borderRadius: BorderRadius.circular(999),
          child: Container(
            constraints: const BoxConstraints(minWidth: 40, minHeight: 40),
            padding: EdgeInsets.symmetric(horizontal: on ? 12 : 8),
            decoration: BoxDecoration(
              color: on ? tone.bg : Colors.transparent,
              borderRadius: BorderRadius.circular(999),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(icon, size: 18, color: on ? tone.fg : t.textMid),
                if (on) ...[
                  const SizedBox(width: 6),
                  Text(
                    label,
                    style: TextStyle(
                      fontSize: 13.5,
                      fontWeight: FontWeight.w700,
                      color: tone.fg,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      );
    }

    return Container(
      padding: const EdgeInsets.all(3),
      decoration: BoxDecoration(
        color: t.inset,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          option('present', Icons.check_rounded, s('Present'), onPresent),
          option('late', Icons.schedule_rounded, s('Late'), onLate),
          option('absent', Icons.close_rounded, s('Absent'), onAbsent),
        ],
      ),
    );
  }
}

// ─── Late arrival sheet (design screen 13) ───────────────────────────────────
class _LateSheet extends ConsumerStatefulWidget {
  final Map<String, dynamic> pupil;
  final _Mark current;
  const _LateSheet({required this.pupil, required this.current});

  @override
  ConsumerState<_LateSheet> createState() => _LateSheetState();
}

class _LateSheetState extends ConsumerState<_LateSheet> {
  late TimeOfDay _time;
  late final TextEditingController _note;

  @override
  void initState() {
    super.initState();
    final saved = widget.current.arrival?.split(':');
    _time = saved != null && saved.length == 2
        ? TimeOfDay(hour: int.parse(saved[0]), minute: int.parse(saved[1]))
        : TimeOfDay.now();
    _note = TextEditingController(text: widget.current.note);
  }

  @override
  void dispose() {
    _note.dispose();
    super.dispose();
  }

  void _minus(int minutes) {
    final now = DateTime.now().subtract(Duration(minutes: minutes));
    setState(() => _time = TimeOfDay(hour: now.hour, minute: now.minute));
  }

  String get _hhmm =>
      '${_time.hour.toString().padLeft(2, '0')}:${_time.minute.toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final bottom = MediaQuery.viewInsetsOf(context).bottom;

    Widget quick(String label, VoidCallback onTap, bool primary) => Padding(
          padding: const EdgeInsets.symmetric(horizontal: 4),
          child: ChoiceChip(
            label: Text(label),
            selected: primary,
            onSelected: (_) => onTap(),
            showCheckmark: false,
            selectedColor: t.accent,
            labelStyle: TextStyle(
              fontWeight: FontWeight.w700,
              color: primary ? t.onAccent : t.textHi,
            ),
            backgroundColor: t.inset,
            side: BorderSide.none,
            shape: const StadiumBorder(),
          ),
        );

    return Padding(
      padding: EdgeInsets.fromLTRB(24, 12, 24, 24 + bottom),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: t.stroke,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 18),
            Row(
              children: [
                _Initials(widget.pupil['initials']?.toString() ?? ''),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        widget.pupil['name']?.toString() ?? '',
                        style: TextStyle(
                          fontSize: 17,
                          fontWeight: FontWeight.w800,
                          color: t.textHi,
                        ),
                      ),
                      Text(
                        s('Late — when did they arrive?'),
                        style: TextStyle(fontSize: 13.5, color: t.textMid),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 14),
            Center(
              child: InkWell(
                borderRadius: BorderRadius.circular(16),
                onTap: () async {
                  final picked =
                      await showTimePicker(context: context, initialTime: _time);
                  if (picked != null) setState(() => _time = picked);
                },
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                  child: Text(
                    _hhmm,
                    style: TextStyle(
                      fontSize: 56,
                      fontWeight: FontWeight.w800,
                      color: t.accentInk,
                      fontFeatures: const [FontFeature.tabularFigures()],
                    ),
                  ),
                ),
              ),
            ),
            const SizedBox(height: 6),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                quick(s('Now'), () => _minus(0), false),
                quick(s('−5 min'), () => _minus(5), false),
                quick(s('−10 min'), () => _minus(10), false),
              ],
            ),
            const SizedBox(height: 18),
            Text(
              s('Note (optional)'),
              style: TextStyle(
                fontSize: 13.5,
                fontWeight: FontWeight.w700,
                color: t.textHi,
              ),
            ),
            const SizedBox(height: 6),
            TextField(
              controller: _note,
              maxLength: 200,
              decoration: InputDecoration(
                hintText: s('For example: the bus was late'),
                counterText: '',
              ),
            ),
            const SizedBox(height: 16),
            IceButton(
              s('Done'),
              onPressed: () => Navigator.of(context)
                  .pop(_Mark('late', _hhmm, _note.text.trim())),
            ),
          ],
        ),
      ),
    );
  }
}

// ─── Note sheet (tap a pupil's name) ─────────────────────────────────────────
class _NoteSheet extends ConsumerStatefulWidget {
  final Map<String, dynamic> pupil;
  final String note;
  const _NoteSheet({required this.pupil, required this.note});

  @override
  ConsumerState<_NoteSheet> createState() => _NoteSheetState();
}

class _NoteSheetState extends ConsumerState<_NoteSheet> {
  late final TextEditingController _note =
      TextEditingController(text: widget.note);

  @override
  void dispose() {
    _note.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final bottom = MediaQuery.viewInsetsOf(context).bottom;
    return Padding(
      padding: EdgeInsets.fromLTRB(24, 20, 24, 24 + bottom),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              widget.pupil['name']?.toString() ?? '',
              style: TextStyle(
                fontSize: 17,
                fontWeight: FontWeight.w800,
                color: t.textHi,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _note,
              autofocus: true,
              maxLength: 200,
              decoration: InputDecoration(
                labelText: s('Note (optional)'),
                hintText: s('For example: ill, the parent called'),
              ),
            ),
            const SizedBox(height: 12),
            IceButton(
              s('Done'),
              onPressed: () => Navigator.of(context).pop(_note.text.trim()),
            ),
          ],
        ),
      ),
    );
  }
}

// ─── Teacher home reminder (design screen 11) ────────────────────────────────
/// One card per homeroom class: "3-A register not taken yet" with a button,
/// or today's counts once it is saved. Shows nothing for teachers without a
/// homeroom class (and for the Learning Center, which has no classes).
class RegisterReminder extends ConsumerWidget {
  const RegisterReminder({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    if (!context.brand.isSchool) return const SizedBox.shrink();
    final classes = ref.watch(myRegistersProvider).valueOrNull ?? const [];
    if (classes.isEmpty) return const SizedBox.shrink();
    return Column(
      children: [
        for (final c in classes.cast<Map<String, dynamic>>())
          Padding(
            padding: const EdgeInsets.only(bottom: 14),
            child: _ReminderCard(row: c),
          ),
      ],
    );
  }
}

class _ReminderCard extends ConsumerWidget {
  final Map<String, dynamic> row;
  const _ReminderCard({required this.row});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final name = row['name']?.toString() ?? '';
    final taken = row['taken'] == true;
    final tone = _Tone.of(taken ? 'present' : 'late', t.isDark);
    void open() => context.push('/staff/register/${row['id']}');

    final title = taken
        ? s('{class} register taken').replaceAll('{class}', name)
        : s('{class} register not taken yet').replaceAll('{class}', name);
    final subtitle = taken
        ? [
            s('{n} present').replaceAll('{n}', '${row['present']}'),
            s('{n} late').replaceAll('{n}', '${row['late']}'),
            s('{n} absent').replaceAll('{n}', '${row['absent']}'),
          ].join(' · ')
        : s('Parents are told when you mark a pupil late or absent.');

    return IceCard(
      color: tone.bg,
      onTap: taken ? open : null,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Container(
                width: 44,
                height: 44,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: t.card,
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Icon(
                  taken ? Icons.check_rounded : Icons.warning_amber_rounded,
                  color: tone.fg,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      title,
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w800,
                        color: t.textHi,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      subtitle,
                      style: TextStyle(fontSize: 13, color: t.textMid),
                    ),
                  ],
                ),
              ),
              if (taken) Icon(Icons.chevron_right_rounded, color: t.textMid),
            ],
          ),
          if (!taken) ...[
            const SizedBox(height: 14),
            IceButton(s('Take the register'), onPressed: open),
          ],
        ],
      ),
    );
  }
}
