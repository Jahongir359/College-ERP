import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../../core/api/api_client.dart';
import '../../core/auth/auth_state.dart';

/// Requests for the parent screens; tests swap in a fake server.
final parentDioProvider = Provider<Dio>((_) => ApiClient.instance.dio);

/// "Now" for the Today card; tests pin it.
final parentClockProvider = Provider<DateTime Function()>((_) => DateTime.now);

// ── Which child is shown ────────────────────────────────────────────────────

/// The child the parent is looking at. Remembered per device (`cache_` keys
/// are cleared on sign-out); falls back to the first child.
class SelectedChildNotifier extends StateNotifier<int?> {
  SelectedChildNotifier() : super(null) {
    _load();
  }

  static const _key = 'cache_parent_child';

  Future<void> _load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final id = prefs.getInt(_key);
      if (id != null && state == null) state = id;
    } catch (_) {}
  }

  Future<void> select(int id) async {
    state = id;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt(_key, id);
    } catch (_) {}
  }
}

final _selectedChildIdProvider =
    StateNotifierProvider<SelectedChildNotifier, int?>(
      (_) => SelectedChildNotifier(),
    );

/// The signed-in parent's children (from `me/`).
final parentChildrenProvider = Provider<List<ParentChildInfo>>(
  (ref) => ref.watch(authProvider.select((a) => a.user?.children ?? const [])),
);

/// The child on screen: the remembered one if still linked, else the first.
final selectedChildProvider = Provider<ParentChildInfo?>((ref) {
  final children = ref.watch(parentChildrenProvider);
  if (children.isEmpty) return null;
  final id = ref.watch(_selectedChildIdProvider);
  return children.firstWhere((c) => c.id == id, orElse: () => children.first);
});

void selectChild(WidgetRef ref, int id) =>
    ref.read(_selectedChildIdProvider.notifier).select(id);

// ── Today for one child ─────────────────────────────────────────────────────

enum ArrivalStatus { notMarked, present, late, absent }

class TodayAttendance {
  final ArrivalStatus status;
  final String? arrivalTime; // "07:52"
  const TodayAttendance(this.status, [this.arrivalTime]);
}

class LessonSlot {
  final int number;
  final String subject;
  final String start; // "08:55"
  final String end;
  final String room;
  const LessonSlot({
    required this.number,
    required this.subject,
    required this.start,
    required this.end,
    this.room = '',
  });
}

/// What the Today card says about lessons.
enum LessonPhase { none, before, now, between, done }

class TodayLessons {
  final LessonPhase phase;
  final LessonSlot? main; // the lesson on now, or the next one
  final LessonSlot? after; // the one after [main]
  const TodayLessons(this.phase, {this.main, this.after});
}

class HomeworkDue {
  final int count; // due today or later
  final DateTime? nextDue;
  final String? nextTitle;
  const HomeworkDue(this.count, {this.nextDue, this.nextTitle});
}

class UnpaidInvoice {
  final DateTime period; // first day of the month
  final String amountDue; // "450000.00"
  final DateTime? dueDate;
  final bool overdue;
  const UnpaidInvoice({
    required this.period,
    required this.amountDue,
    this.dueDate,
    this.overdue = false,
  });
}

class TeacherMessage {
  final String teacher;
  final String preview;
  final int unread;
  const TeacherMessage(this.teacher, this.preview, this.unread);
}

class Announcement {
  final String message;
  final DateTime createdAt;
  const Announcement(this.message, this.createdAt);
}

/// Everything Home shows for one child. A part is null when its request
/// failed, so one broken endpoint never blanks the whole screen.
class ParentToday {
  final TodayAttendance? attendance;
  final TodayLessons? lessons;
  final HomeworkDue? homework;
  final UnpaidInvoice? invoice; // null also when nothing is owed
  final bool invoiceLoaded;
  final TeacherMessage? message;
  final Announcement? announcement;

  const ParentToday({
    this.attendance,
    this.lessons,
    this.homework,
    this.invoice,
    this.invoiceLoaded = false,
    this.message,
    this.announcement,
  });

  /// True when every request failed (likely offline).
  bool get allFailed =>
      attendance == null &&
      lessons == null &&
      homework == null &&
      !invoiceLoaded;
}

String _ymd(DateTime d) =>
    '${d.year.toString().padLeft(4, '0')}-${d.month.toString().padLeft(2, '0')}-'
    '${d.day.toString().padLeft(2, '0')}';

DateTime? _date(Object? v) => v is String ? DateTime.tryParse(v) : null;

List<Map<String, dynamic>> _rows(Object? data, [String key = 'results']) {
  final list = data is List ? data : (data is Map ? data[key] : null);
  return [
    for (final r in (list as List? ?? const []))
      if (r is Map) Map<String, dynamic>.from(r),
  ];
}

/// Today's register mark from `attendance/` rows (newest first).
TodayAttendance todayAttendance(Object? data, DateTime now) {
  final today = _ymd(now);
  for (final r in _rows(data)) {
    if (r['date'] != today) continue;
    final time = r['arrival_time'] as String?;
    return switch (r['status']) {
      1 => TodayAttendance(ArrivalStatus.present, time),
      2 => TodayAttendance(ArrivalStatus.late, time),
      0 => const TodayAttendance(ArrivalStatus.absent),
      _ => const TodayAttendance(ArrivalStatus.notMarked),
    };
  }
  return const TodayAttendance(ArrivalStatus.notMarked);
}

int _minutes(String hhmm) {
  final p = hhmm.split(':');
  if (p.length < 2) return 0;
  return (int.tryParse(p[0]) ?? 0) * 60 + (int.tryParse(p[1]) ?? 0);
}

String _hhmm(Object? v) {
  final s = (v ?? '').toString();
  return s.length >= 5 ? s.substring(0, 5) : s;
}

/// The lesson on now (or next) from a `school/timetable/` week.
TodayLessons todayLessons(Object? data, DateTime now) {
  final today = _ymd(now);
  final days = data is Map ? (data['days'] as List? ?? const []) : const [];
  final day = days.whereType<Map>().where((d) => d['date'] == today);
  final lessons = <LessonSlot>[
    if (day.isNotEmpty)
      for (final l
          in (day.first['lessons'] as List? ?? const []).whereType<Map>())
        LessonSlot(
          number: ((l['period'] as Map?)?['number'] as num?)?.toInt() ?? 0,
          subject: (l['subject_name'] ?? '').toString(),
          start: _hhmm((l['period'] as Map?)?['start_time']),
          end: _hhmm((l['period'] as Map?)?['end_time']),
          room: (l['room'] ?? '').toString(),
        ),
  ]..sort((a, b) => _minutes(a.start).compareTo(_minutes(b.start)));
  if (lessons.isEmpty) return const TodayLessons(LessonPhase.none);

  final t = now.hour * 60 + now.minute;
  for (var i = 0; i < lessons.length; i++) {
    final l = lessons[i];
    final after = i + 1 < lessons.length ? lessons[i + 1] : null;
    if (t < _minutes(l.start)) {
      return TodayLessons(
        i == 0 ? LessonPhase.before : LessonPhase.between,
        main: l,
        after: after,
      );
    }
    if (t < _minutes(l.end)) {
      return TodayLessons(LessonPhase.now, main: l, after: after);
    }
  }
  return const TodayLessons(LessonPhase.done);
}

/// Homework not yet due (today or later) from `assignments/` rows.
HomeworkDue homeworkDue(Object? data, DateTime now) {
  final today = DateTime(now.year, now.month, now.day);
  final open = [
    for (final r in _rows(data))
      if (_date(r['due_date']) case final due? when !due.isBefore(today))
        (due: due, title: (r['title'] ?? '').toString()),
  ]..sort((a, b) => a.due.compareTo(b.due));
  if (open.isEmpty) return const HomeworkDue(0);
  return HomeworkDue(
    open.length,
    nextDue: open.first.due,
    nextTitle: open.first.title,
  );
}

/// The oldest invoice with money still owed, from `invoices/` rows.
UnpaidInvoice? unpaidInvoice(Object? data) {
  final owed = [
    for (final r in _rows(data))
      if (r['status'] != 'cancelled' &&
          (double.tryParse('${r['amount_due']}') ?? 0) > 0 &&
          _date(r['period']) != null)
        r,
  ]..sort((a, b) => '${a['period']}'.compareTo('${b['period']}'));
  if (owed.isEmpty) return null;
  final r = owed.first;
  return UnpaidInvoice(
    period: _date(r['period'])!,
    amountDue: '${r['amount_due']}',
    dueDate: _date(r['due_date']),
    overdue: r['is_overdue'] == true,
  );
}

/// The teacher thread with the newest unread message, from `messages/parent/`.
TeacherMessage? unreadMessage(Object? data) {
  for (final t in _rows(data, 'threads')) {
    final unread = (t['unread_count'] as num?)?.toInt() ?? 0;
    if (unread == 0) continue;
    final teacher = t['teacher'] as Map?;
    final name = teacher?['name'];
    final display = name is Map
        ? (name['name'] ?? name['full_name'] ?? '').toString()
        : (name ?? '').toString();
    return TeacherMessage(
      display,
      (t['last_message'] ?? '').toString(),
      unread,
    );
  }
  return null;
}

/// The newest announcement from the last two weeks, from `notifications/`.
Announcement? latestAnnouncement(Object? data, DateTime now) {
  for (final n in _rows(data)) {
    final at = _date(n['created_at']);
    if (at == null || now.difference(at).inDays > 14) continue;
    return Announcement((n['message'] ?? '').toString(), at.toLocal());
  }
  return null;
}

final parentTodayProvider = FutureProvider.autoDispose.family<ParentToday, int>(
  (ref, childId) async {
    final dio = ref.watch(parentDioProvider);
    final now = ref.watch(parentClockProvider)();
    final child = {'student': childId};

    Future<Object?> get(String path, [Map<String, Object?>? query]) async {
      try {
        return (await dio.get(path, queryParameters: query)).data;
      } catch (_) {
        return null;
      }
    }

    final results = await Future.wait([
      get('/attendance/', child),
      get('/school/timetable/', {...child, 'date': _ymd(now)}),
      get('/assignments/', child),
      get('/invoices/', child),
      get('/messages/parent/', child),
      get('/notifications/', {'category': 'announcement'}),
    ]);
    final [att, week, hw, inv, msg, ann] = results;
    return ParentToday(
      attendance: att == null ? null : todayAttendance(att, now),
      lessons: week == null ? null : todayLessons(week, now),
      homework: hw == null ? null : homeworkDue(hw, now),
      invoice: inv == null ? null : unpaidInvoice(inv),
      invoiceLoaded: inv != null,
      message: msg == null ? null : unreadMessage(msg),
      announcement: ann == null ? null : latestAnnouncement(ann, now),
    );
  },
);

/// Unread notifications, for the dot on the bell.
final parentUnreadNotificationsProvider = FutureProvider.autoDispose<int>((
  ref,
) async {
  final res = await ref
      .watch(parentDioProvider)
      .get('/notifications/', queryParameters: {'unread': '1'});
  final data = res.data;
  if (data is Map && data['count'] is num) {
    return (data['count'] as num).toInt();
  }
  return _rows(data).length;
});
