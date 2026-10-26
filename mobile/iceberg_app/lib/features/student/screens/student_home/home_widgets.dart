part of '../student_home_screen.dart';

// ─── Trend chart ─────────────────────────────────────────────────────────────
// Custom-painted sparkline. We previously used fl_chart here, but its CustomPaint
// backend intermittently rendered a flat grey rectangle on iOS Safari / web,
// which no amount of backgroundColor tweaking fixed. Painting it ourselves is
// lighter (better scrolling) and renders identically on every platform.
class _TrendChart extends StatelessWidget {
  final List trend;
  const _TrendChart({required this.trend});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final points = <double>[];
    final labels = <String>[];
    for (var i = 0; i < trend.length; i++) {
      final item = trend[i];
      // Handle both dict format {attendance_pct, label} and legacy plain number.
      final double? pct;
      final String label;
      if (item is Map) {
        pct = (item['attendance_pct'] as num?)?.toDouble();
        label = (item['label'] as String?) ?? '${i + 1}';
      } else {
        pct = (item as num?)?.toDouble();
        label = '${i + 1}';
      }
      if (pct != null) {
        points.add(pct.clamp(0, 100).toDouble());
        labels.add(label);
      }
    }
    if (points.length < 2) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.show_chart_rounded, size: 30, color: t.textLow),
            const SizedBox(height: 8),
            Text(
              'No performance data yet',
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: t.textMid,
              ),
            ),
            const SizedBox(height: 3),
            Text(
              'Progress will appear here after results are added.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 11.5, color: t.textLow),
            ),
          ],
        ),
      );
    }
    return CustomPaint(
      size: Size.infinite,
      painter: _SparklinePainter(
        points: points,
        labels: labels,
        line: t.accent,
        grid: t.stroke,
        labelColor: t.textLow,
        dotFill: t.card,
      ),
    );
  }
}

class _SparklinePainter extends CustomPainter {
  final List<double> points; // each 0..100
  final List<String> labels;
  final Color line;
  final Color grid;
  final Color labelColor;
  final Color dotFill;

  _SparklinePainter({
    required this.points,
    required this.labels,
    required this.line,
    required this.grid,
    required this.labelColor,
    required this.dotFill,
  });

  @override
  void paint(Canvas canvas, Size size) {
    const labelBand = 22.0;
    final chartH = size.height - labelBand;
    if (chartH <= 0) return;
    final n = points.length;
    final dx = n > 1 ? size.width / (n - 1) : size.width;

    Offset pos(int i) =>
        Offset(i * dx, chartH - (points[i] / 100) * chartH);

    // Horizontal grid lines at 0/25/50/75/100.
    final gridPaint = Paint()
      ..color = grid
      ..strokeWidth = 1;
    for (var g = 0; g <= 100; g += 25) {
      final y = chartH - (g / 100) * chartH;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }

    // Smooth curve through the points.
    final path = Path()..moveTo(pos(0).dx, pos(0).dy);
    for (var i = 0; i < n - 1; i++) {
      final p0 = pos(i);
      final p1 = pos(i + 1);
      final midX = (p0.dx + p1.dx) / 2;
      path.cubicTo(midX, p0.dy, midX, p1.dy, p1.dx, p1.dy);
    }

    // Gradient fill below the curve.
    final fillPath = Path.from(path)
      ..lineTo(pos(n - 1).dx, chartH)
      ..lineTo(pos(0).dx, chartH)
      ..close();
    canvas.drawPath(
      fillPath,
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [
            line.withValues(alpha: 0.28),
            line.withValues(alpha: 0.0),
          ],
        ).createShader(Rect.fromLTWH(0, 0, size.width, chartH)),
    );

    // The line itself.
    canvas.drawPath(
      path,
      Paint()
        ..color = line
        ..strokeWidth = 3
        ..style = PaintingStyle.stroke
        ..strokeJoin = StrokeJoin.round
        ..strokeCap = StrokeCap.round,
    );

    // Dots.
    final dotInner = Paint()..color = dotFill;
    final dotRing = Paint()
      ..color = line
      ..style = PaintingStyle.stroke
      ..strokeWidth = 2;
    for (var i = 0; i < n; i++) {
      final p = pos(i);
      canvas.drawCircle(p, 3.5, dotInner);
      canvas.drawCircle(p, 3.5, dotRing);
    }

    // Bottom labels.
    for (var i = 0; i < n; i++) {
      final tp = TextPainter(
        text: TextSpan(
          text: labels[i],
          style: TextStyle(
            fontSize: 10,
            fontWeight: FontWeight.w600,
            color: labelColor,
          ),
        ),
        textDirection: ui.TextDirection.ltr,
      )..layout();
      final px = (pos(i).dx - tp.width / 2).clamp(0.0, size.width - tp.width);
      tp.paint(canvas, Offset(px, chartH + 6));
    }
  }

  @override
  bool shouldRepaint(_SparklinePainter old) =>
      !listEquals(old.points, points) ||
      !listEquals(old.labels, labels) ||
      old.line != line ||
      old.grid != grid ||
      old.labelColor != labelColor ||
      old.dotFill != dotFill;
}

// ─── Campus Pulse card ───────────────────────────────────────────────────────
class _PulseCard extends StatelessWidget {
  final Map<String, dynamic> story;
  const _PulseCard({required this.story});

  IconData get _icon => switch (story['story_type']) {
    'event' => Icons.event_rounded,
    'challenge' => Icons.emoji_events_rounded,
    'vocab' => Icons.translate_rounded,
    'tip' => Icons.lightbulb_outline_rounded,
    'update' => Icons.campaign_rounded,
    _ => Icons.campaign_rounded,
  };

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final created = DateTime.tryParse(story['created_at'] ?? '');
    final when = created == null ? '' : _relative(created);

    return SizedBox(
      width: 240,
      child: IceCard(
        padding: const EdgeInsets.all(16),
        onTap: () => _showDetail(context),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(7),
                  decoration: BoxDecoration(
                    color: t.skySoft,
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Icon(_icon, size: 16, color: t.sky),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '${_typeLabel(story['story_type'])}\n$when',
                    maxLines: 2,
                    style: TextStyle(
                      fontSize: 10.5,
                      height: 1.25,
                      fontWeight: FontWeight.w600,
                      color: t.textLow,
                    ),
                  ),
                ),
              ],
            ),
            const Spacer(),
            Text(
              story['title'] ?? '',
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 15.5,
                fontWeight: FontWeight.w800,
                height: 1.25,
                color: t.textHi,
              ),
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Text(
                  'Read More',
                  style: TextStyle(
                    fontSize: 12.5,
                    fontWeight: FontWeight.w700,
                    color: t.accent,
                  ),
                ),
                const SizedBox(width: 4),
                Icon(Icons.arrow_forward_rounded, size: 14, color: t.accent),
              ],
            ),
          ],
        ),
      ),
    );
  }

  String _typeLabel(dynamic type) => switch (type) {
    'event' => 'Event',
    'challenge' => 'Competition',
    'vocab' => 'Vocabulary',
    'tip' => 'Study Tip',
    'update' => 'Teacher Update',
    _ => 'Announcement',
  };

  String _relative(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
    if (diff.inHours < 24) return '${diff.inHours}h ago';
    if (diff.inDays < 7) return '${diff.inDays}d ago';
    return DateFormat('MMM d').format(dt);
  }

  void _showDetail(BuildContext context) {
    final t = context.ice;
    showModalBottomSheet(
      context: context,
      backgroundColor: t.card,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 18, 24, 36),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Container(
                width: 44,
                height: 4,
                decoration: BoxDecoration(
                  color: t.stroke,
                  borderRadius: BorderRadius.circular(99),
                ),
              ),
            ),
            const SizedBox(height: 18),
            StatusBadge(_typeLabel(story['story_type']), tone: BadgeTone.sky),
            const SizedBox(height: 12),
            Text(
              story['title'] ?? '',
              style: TextStyle(
                fontSize: 21,
                fontWeight: FontWeight.w800,
                color: t.textHi,
              ),
            ),
            const SizedBox(height: 10),
            if ((story['image_url'] as String?)?.isNotEmpty == true) ...[
              ClipRRect(
                borderRadius: BorderRadius.circular(16),
                child: Image.network(
                  story['image_url'],
                  height: 170,
                  width: double.infinity,
                  fit: BoxFit.cover,
                  cacheWidth: (MediaQuery.sizeOf(context).width *
                          MediaQuery.devicePixelRatioOf(context))
                      .ceil(),
                  errorBuilder: (_, __, ___) => const SizedBox.shrink(),
                ),
              ),
              const SizedBox(height: 12),
            ],
            Flexible(
              child: SingleChildScrollView(
                child: Text(
                  (story['content'] as String?)?.isNotEmpty == true
                      ? story['content']
                      : 'No further details.',
                  style: TextStyle(
                    fontSize: 14.5,
                    height: 1.5,
                    color: t.textMid,
                  ),
                ),
              ),
            ),
            const SizedBox(height: 12),
            if ((story['author_name'] as String?)?.isNotEmpty == true)
              Text(
                '— ${story['author_name']}',
                style: TextStyle(
                  fontSize: 12.5,
                  fontWeight: FontWeight.w600,
                  color: t.textLow,
                ),
              ),
          ],
        ),
      ),
    );
  }
}

// ─── Assignment preview row ──────────────────────────────────────────────────
class _AssignmentPreview extends StatelessWidget {
  final Map<String, dynamic> a;
  const _AssignmentPreview({required this.a});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final due = DateTime.tryParse(a['due_date'] ?? '');
    final overdue = a['is_overdue'] == true;
    final dueLabel = due == null
        ? ''
        : overdue
        ? 'Overdue'
        : _dueIn(due);

    return IceCard(
      padding: const EdgeInsets.all(16),
      onTap: () => context.go('/student/assignments/${a['id']}'),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          MicroLabel(dueLabel, color: overdue ? t.coral : t.amber),
          const SizedBox(height: 6),
          Text(
            a['title'] ?? '',
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Icon(Icons.schedule_rounded, size: 14, color: t.textLow),
              const SizedBox(width: 5),
              Text(
                due != null ? DateFormat('MMM d').format(due) : '',
                style: TextStyle(
                  fontSize: 12.5,
                  fontWeight: FontWeight.w600,
                  color: t.textMid,
                ),
              ),
              const Spacer(),
              StatusBadge(
                overdue ? 'Overdue' : 'Submit',
                tone: overdue ? BadgeTone.coral : BadgeTone.accent,
              ),
            ],
          ),
        ],
      ),
    );
  }

  String _dueIn(DateTime due) {
    final today = DateTime.now();
    final diff = due
        .difference(DateTime(today.year, today.month, today.day))
        .inDays;
    if (diff <= 0) return 'Due Today';
    if (diff == 1) return 'Due Tomorrow';
    return 'In $diff Days';
  }
}

// ── Lesson card (Upcoming Lessons on the dashboard) ──────────────────────────
class _LessonCard extends StatelessWidget {
  final Map<String, dynamic> group;
  final bool highlight;
  const _LessonCard({required this.group, this.highlight = false});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final name = group['name']?.toString() ?? 'Class';
    final course = group['course_name']?.toString() ?? '';
    final room = group['room']?.toString() ?? '';
    final schedule = group['schedule']?.toString() ?? '';
    final meta = [
      if (course.isNotEmpty) course,
      if (room.isNotEmpty) 'Room $room',
    ].join(' · ');

    return IceCard(
      padding: const EdgeInsets.all(14),
      color: highlight ? t.accentSoft : null,
      child: Row(
        children: [
          Container(
            width: 46,
            height: 46,
            decoration: BoxDecoration(
              color: highlight ? t.accent : t.inset,
              borderRadius: BorderRadius.circular(13),
            ),
            child: Icon(
              Icons.menu_book_rounded,
              size: 22,
              color: highlight ? t.onAccent : t.accentInk,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          fontSize: 15,
                          fontWeight: FontWeight.w800,
                          color: t.textHi,
                        ),
                      ),
                    ),
                    if (highlight)
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: t.accent,
                          borderRadius: BorderRadius.circular(999),
                        ),
                        child: Text(
                          'NEXT',
                          style: TextStyle(
                            color: t.onAccent,
                            fontSize: 9,
                            fontWeight: FontWeight.w900,
                            letterSpacing: 0.8,
                          ),
                        ),
                      ),
                  ],
                ),
                if (meta.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(
                    meta,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(fontSize: 12.5, color: t.textMid),
                  ),
                ],
                if (schedule.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      Icon(Icons.schedule_rounded,
                          size: 13, color: t.textLow),
                      const SizedBox(width: 5),
                      Expanded(
                        child: Text(
                          schedule,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: TextStyle(fontSize: 12, color: t.textLow),
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
