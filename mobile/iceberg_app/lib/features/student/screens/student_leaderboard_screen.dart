import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';
import '../../../core/theme/brand.dart';

/// Leaderboard — scope tabs (Overall / Group / Branch), top-3 podium and the
/// full ranking list with the current student highlighted.
class StudentLeaderboardScreen extends ConsumerStatefulWidget {
  const StudentLeaderboardScreen({super.key});

  @override
  ConsumerState<StudentLeaderboardScreen> createState() =>
      _StudentLeaderboardScreenState();
}

class _StudentLeaderboardScreenState
    extends ConsumerState<StudentLeaderboardScreen> {
  int _tab = 0;
  static const _scopes = ['overall', 'group', 'branch'];

  @override
  Widget build(BuildContext context) {
    final scope = _scopes[_tab];
    final board = ref.watch(leaderboardScopedProvider(scope));

    return board.when(
      loading: () => _scaffold(context, const PageSkeleton()),
      error: (e, _) {
        // 404 = no active season; show a friendly empty state instead of error.
        final notFound = e.toString().contains('404');
        return _scaffold(
          context,
          notFound
              ? const EmptyState(
                  icon: Icons.emoji_events_outlined,
                  title: 'No active season',
                  message: 'The leaderboard opens when a new season starts.',
                )
              : ErrorState(
                  error: e,
                  onRetry: () =>
                      ref.invalidate(leaderboardScopedProvider(scope)),
                ),
        );
      },
      data: (d) => _buildBody(context, d),
    );
  }

  Widget _scaffold(BuildContext context, Widget body) {
    final s = ref.watch(stringsProvider);
    return IcePage(
      title: s('Leaderboard'),
      subtitle: 'Season standings',
      children: [
        IceChipTabs(
          tabs: [s('Overall'), s(context.brand.groupKey), s('Branch')],
          index: _tab,
          onChanged: (i) => setState(() => _tab = i),
        ),
        const SizedBox(height: 16),
        SizedBox(height: 360, child: body),
      ],
    );
  }

  Widget _buildBody(BuildContext context, Map<String, dynamic> d) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final scope = _scopes[_tab];
    final entries = ((d['entries'] as List?) ?? [])
        .cast<Map<String, dynamic>>();
    final myRank = (d['my_rank'] as num?)?.toInt();
    final top3 = entries.take(3).toList();
    final rest = entries.length > 3
        ? entries.sublist(3)
        : <Map<String, dynamic>>[];

    return IcePage(
      title: s('Leaderboard'),
      subtitle: (d['name'] as String?) ?? 'Season standings',
      onRefresh: () async =>
          ref.refresh(leaderboardScopedProvider(scope).future),
      children: [
        IceChipTabs(
          tabs: [s('Overall'), s(context.brand.myGroupKey), s('Branch')],
          index: _tab,
          onChanged: (i) => setState(() => _tab = i),
        ),
        const SizedBox(height: 18),

        if (entries.isEmpty)
          const IceCard(
            child: EmptyState(
              icon: Icons.emoji_events_outlined,
              title: 'No ranking yet',
              message: 'Rankings appear once scores are captured this season.',
            ),
          )
        else ...[
          if (top3.isNotEmpty) _Podium(top3: top3),
          const SizedBox(height: 18),
          ...rest.map(
            (e) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _RankRow(entry: e),
            ),
          ),
          if (myRank != null && myRank > 3) ...[
            const SizedBox(height: 10),
            Center(
              child: Text(
                'Your rank: #$myRank',
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w700,
                  color: t.accent,
                ),
              ),
            ),
          ],
        ],
      ],
    );
  }
}

class _Podium extends StatelessWidget {
  final List<Map<String, dynamic>> top3;
  const _Podium({required this.top3});

  @override
  Widget build(BuildContext context) {
    // Order: 2nd · 1st · 3rd
    final ordered = <Map<String, dynamic>?>[
      top3.length > 1 ? top3[1] : null,
      top3.isNotEmpty ? top3[0] : null,
      top3.length > 2 ? top3[2] : null,
    ];
    return Row(
      crossAxisAlignment: CrossAxisAlignment.end,
      children: ordered
          .map((e) => Expanded(child: _PodiumColumn(entry: e)))
          .toList(),
    );
  }
}

class _PodiumColumn extends StatelessWidget {
  final Map<String, dynamic>? entry;
  const _PodiumColumn({required this.entry});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    if (entry == null) return const SizedBox.shrink();
    final rank = (entry!['rank'] as num?)?.toInt() ?? 0;
    final isFirst = rank == 1;
    final me = entry!['is_me'] == true;
    final medal = switch (rank) {
      1 => t.accent,
      2 => const Color(0xFFB8C4C9),
      _ => const Color(0xFFCC8B5C),
    };

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        Stack(
          clipBehavior: Clip.none,
          alignment: Alignment.center,
          children: [
            Container(
              padding: const EdgeInsets.all(3),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: medal, width: 2.5),
              ),
              child: CircleAvatar(
                radius: isFirst ? 32 : 26,
                backgroundColor: t.inset,
                backgroundImage:
                    (entry!['avatar_url'] as String?)?.isNotEmpty == true
                    ? NetworkImage(entry!['avatar_url'])
                    : null,
                child: (entry!['avatar_url'] as String?)?.isNotEmpty == true
                    ? null
                    : Text(
                        _initial(entry!['student_name']),
                        style: TextStyle(
                          fontSize: isFirst ? 24 : 20,
                          fontWeight: FontWeight.w800,
                          color: t.textMid,
                        ),
                      ),
              ),
            ),
            Positioned(
              bottom: -10,
              child: Container(
                width: 24,
                height: 24,
                decoration: BoxDecoration(color: medal, shape: BoxShape.circle),
                child: Center(
                  child: Text(
                    '$rank',
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w800,
                      color: Colors.black87,
                    ),
                  ),
                ),
              ),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Text(
          _firstName(entry!['student_name']),
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w800,
            color: me ? t.accent : t.textHi,
          ),
        ),
        Text(
          ((entry!['score'] as num?) ?? 0).toStringAsFixed(0),
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: t.textMid,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          height: isFirst ? 70 : 48,
          margin: const EdgeInsets.symmetric(horizontal: 6),
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topCenter,
              end: Alignment.bottomCenter,
              colors: [
                medal.withValues(alpha: 0.4),
                medal.withValues(alpha: 0.08),
              ],
            ),
            borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
          ),
        ),
      ],
    );
  }

  String _initial(dynamic name) {
    final s = (name ?? '').toString().trim();
    return s.isEmpty ? '?' : s[0].toUpperCase();
  }

  String _firstName(dynamic name) {
    final s = (name ?? '').toString().trim();
    return s.isEmpty ? 'Student' : s.split(' ').first;
  }
}

class _RankRow extends StatelessWidget {
  final Map<String, dynamic> entry;
  const _RankRow({required this.entry});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final me = entry['is_me'] == true;
    final rank = (entry['rank'] as num?)?.toInt() ?? 0;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: me ? t.accent : t.card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: me ? t.accent : t.stroke),
      ),
      child: Row(
        children: [
          SizedBox(
            width: 26,
            child: Text(
              '$rank',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 14,
                fontWeight: FontWeight.w800,
                color: me ? t.onAccent : t.textMid,
              ),
            ),
          ),
          const SizedBox(width: 8),
          CircleAvatar(
            radius: 18,
            backgroundColor: me ? t.onAccent.withValues(alpha: 0.15) : t.inset,
            backgroundImage:
                (entry['avatar_url'] as String?)?.isNotEmpty == true
                ? NetworkImage(entry['avatar_url'])
                : null,
            child: (entry['avatar_url'] as String?)?.isNotEmpty == true
                ? null
                : Text(
                    _initial(entry['student_name']),
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w800,
                      color: me ? t.onAccent : t.textMid,
                    ),
                  ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              me ? 'You' : (entry['student_name'] ?? 'Student'),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: TextStyle(
                fontSize: 14.5,
                fontWeight: FontWeight.w700,
                color: me ? t.onAccent : t.textHi,
              ),
            ),
          ),
          Text(
            ((entry['score'] as num?) ?? 0).toStringAsFixed(0),
            style: TextStyle(
              fontSize: 15,
              fontWeight: FontWeight.w800,
              color: me ? t.onAccent : t.accent,
            ),
          ),
        ],
      ),
    );
  }

  String _initial(dynamic name) {
    final s = (name ?? '').toString().trim();
    return s.isEmpty ? '?' : s[0].toUpperCase();
  }
}
