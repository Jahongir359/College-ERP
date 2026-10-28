import 'package:intl/intl.dart';

import '../i18n/strings.dart';

String fmtDate(String? iso) {
  if (iso == null || iso.isEmpty) return '—';
  try {
    return DateFormat('d MMM yyyy').format(DateTime.parse(iso));
  } catch (_) {
    return iso;
  }
}

String fmtPercent(dynamic value) {
  if (value == null) return '—';
  final d = (value is num)
      ? value.toDouble()
      : double.tryParse(value.toString());
  if (d == null) return '—';
  return '${d.toStringAsFixed(1)}%';
}

String fmtNum(dynamic value) {
  if (value == null) return '—';
  return value.toString();
}

String fmtCurrency(dynamic value) {
  if (value == null) return '—';
  final d = (value is num) ? value.toDouble() : double.tryParse(value.toString());
  if (d == null) return '—';
  return NumberFormat('#,##0', 'en_US').format(d);
}

/// "Room 12", or the room name alone when it already says so ("Xona 1A").
String roomLabel(S s, String room) {
  final word = s('Room');
  final lower = room.toLowerCase();
  if (lower.startsWith(word.toLowerCase()) || lower.startsWith('room')) {
    return room;
  }
  return '$word $room';
}
