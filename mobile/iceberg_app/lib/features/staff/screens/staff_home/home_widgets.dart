part of '../staff_home_screen.dart';

// ── Hero stat item (inside the gradient card) ─────────────────────────────────
class _HeroStat extends StatelessWidget {
  final String value;
  final String label;
  const _HeroStat({required this.value, required this.label});

  @override
  Widget build(BuildContext context) => Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            value,
            style: const TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.w900,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            label,
            textAlign: TextAlign.center,
            style: TextStyle(
              fontSize: 10.5,
              fontWeight: FontWeight.w500,
              color: Colors.white.withValues(alpha: 0.65),
            ),
          ),
        ],
      );
}

// ── Quick action button ───────────────────────────────────────────────────────
class _QuickAction extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;
  const _QuickAction({
    required this.icon,
    required this.label,
    required this.color,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: SizedBox(
        width: 72,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 50,
              height: 50,
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.14),
                shape: BoxShape.circle,
              ),
              child: Icon(icon, color: color, size: 22),
            ),
            const SizedBox(height: 6),
            Text(
              label,
              textAlign: TextAlign.center,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 11,
                fontWeight: FontWeight.w600,
                color: context.ice.textMid,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Schedule card ─────────────────────────────────────────────────────────────
class _ScheduleCard extends ConsumerWidget {
  final Map<String, dynamic> group;
  final String time;
  final bool isNow;
  final VoidCallback onAttendance;
  const _ScheduleCard({
    required this.group,
    required this.time,
    required this.isNow,
    required this.onAttendance,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final name = group['name']?.toString() ?? 'Group';
    final subtitle = [
      group['course_name']?.toString(),
      group['room'] != null ? roomLabel(s, '${group['room']}') : null,
    ].where((e) => e != null && e.isNotEmpty).join(' · ');

    return IceCard(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
      color: isNow ? t.accentSoft : null,
      child: Row(
        children: [
          // Time column
          SizedBox(
            width: 76,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  time,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: isNow ? t.accentInk : t.textMid,
                  ),
                ),
                if (isNow) ...[
                  const SizedBox(height: 3),
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: t.accent,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Text(
                      'NOW',
                      style: TextStyle(
                        color: t.onAccent,
                        fontSize: 8.5,
                        fontWeight: FontWeight.w900,
                        letterSpacing: 0.8,
                      ),
                    ),
                  ),
                ],
              ],
            ),
          ),
          // Group info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name,
                  style: TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 15,
                    color: t.textHi,
                  ),
                ),
                if (subtitle.isNotEmpty) ...[
                  const SizedBox(height: 2),
                  Text(
                    subtitle,
                    style: TextStyle(fontSize: 12, color: t.textMid),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ],
            ),
          ),
          // Attendance CTA for current class
          if (isNow)
            GestureDetector(
              onTap: onAttendance,
              child: Container(
                padding: const EdgeInsets.symmetric(
                    horizontal: 10, vertical: 6),
                decoration: BoxDecoration(
                  color: t.accent,
                  borderRadius: BorderRadius.circular(20),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.how_to_reg_rounded,
                        color: t.onAccent, size: 14),
                    const SizedBox(width: 4),
                    Text(
                      'Attend',
                      style: TextStyle(
                        color: t.onAccent,
                        fontSize: 11,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
              ),
            )
          else
            Icon(Icons.chevron_right_rounded, color: t.textLow, size: 20),
        ],
      ),
    );
  }
}

// ── Campus Pulse card ─────────────────────────────────────────────────────────
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
                  story['image_url'] as String,
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
                      ? story['content'] as String
                      : 'No further details.',
                  style: TextStyle(
                    fontSize: 14.5,
                    height: 1.5,
                    color: t.textMid,
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
