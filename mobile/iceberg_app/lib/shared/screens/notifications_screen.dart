import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../core/api/api_client.dart';
import '../../core/api/api_providers.dart';
import '../../core/settings/app_settings.dart';
import '../../core/theme/app_theme.dart';
import '../widgets/ice_page_header.dart';
import '../../core/theme/brand.dart';

class NotificationsScreen extends ConsumerStatefulWidget {
  const NotificationsScreen({super.key});
  @override
  ConsumerState<NotificationsScreen> createState() => _State();
}

class _State extends ConsumerState<NotificationsScreen> {
  Future<void> _markAllRead() async {
    try {
      await ApiClient.instance.dio.post('/notifications/mark-all-read/');
      ref.invalidate(notificationsProvider);
    } on DioException catch (_) {}
  }

  Future<void> _markRead(int id) async {
    try {
      await ApiClient.instance.dio.post('/notifications/$id/read/');
      ref.invalidate(notificationsProvider);
    } on DioException catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    final async = ref.watch(notificationsProvider);
    final s = ref.watch(stringsProvider);
    return Scaffold(
      backgroundColor: IceColors.bg,
      body: RefreshIndicator(
        onRefresh: () => ref.refresh(notificationsProvider.future),
        color: context.brandPrimary,
        child: CustomScrollView(
          physics: const BouncingScrollPhysics(),
          slivers: [
            SliverToBoxAdapter(
              child: IcePageHeader(
                title: s('Notifications'),
                subtitle: s('Updates from your teachers and admins'),
                chips: [
                  IceHeaderChip(
                    icon: Icons.done_all_rounded,
                    label: s('Mark all read'),
                    onTap: _markAllRead,
                  ),
                ],
              ),
            ),
            async.when(
              loading: () => const SliverToBoxAdapter(child: _Skeleton()),
              error: (e, _) => SliverToBoxAdapter(child: _ErrorCard('$e')),
              data: (list) => list.isEmpty
                  ? SliverToBoxAdapter(child: _Empty())
                  : SliverList(
                      delegate: SliverChildBuilderDelegate((_, i) {
                        final n = list[i] as Map<String, dynamic>;
                        return _NotifCard(
                          item: n,
                          index: i,
                          onTap: () {
                            if (n['is_read'] != true) {
                              _markRead(n['id'] as int);
                            }
                          },
                        );
                      }, childCount: list.length),
                    ),
            ),
            const SliverToBoxAdapter(child: SizedBox(height: 100)),
          ],
        ),
      ),
    );
  }
}

class _NotifCard extends StatelessWidget {
  final Map<String, dynamic> item;
  final int index;
  final VoidCallback onTap;
  const _NotifCard({
    required this.item,
    required this.index,
    required this.onTap,
  });

  Color _categoryColor(BuildContext context, String? cat) {
    switch (cat) {
      case 'RESULT':
        return IceColors.success;
      case 'LEAVE':
        return IceColors.warning;
      case 'ASSIGNMENT':
        return IceColors.info;
      case 'ATTENDANCE':
        return IceColors.danger;
      default:
        return context.brandPrimary;
    }
  }

  IconData _categoryIcon(String? cat) {
    switch (cat) {
      case 'RESULT':
        return Icons.grade_outlined;
      case 'LEAVE':
        return Icons.event_note_outlined;
      case 'ASSIGNMENT':
        return Icons.assignment_outlined;
      case 'ATTENDANCE':
        return Icons.bar_chart_outlined;
      default:
        return Icons.notifications_outlined;
    }
  }

  @override
  Widget build(BuildContext context) {
    final isRead = item['is_read'] == true;
    final cat = item['category']?.toString();
    final color = _categoryColor(context, cat);

    return GestureDetector(
          onTap: onTap,
          child: Container(
            margin: const EdgeInsets.fromLTRB(16, 0, 16, 10),
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: isRead ? Colors.white : color.withAlpha(10),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(
                color: isRead ? IceColors.border : color.withAlpha(60),
                width: isRead ? 1 : 1.5,
              ),
              boxShadow: [
                BoxShadow(
                  color: color.withAlpha(isRead ? 0 : 12),
                  blurRadius: 10,
                  offset: const Offset(0, 3),
                ),
              ],
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  width: 42,
                  height: 42,
                  decoration: BoxDecoration(
                    color: color.withAlpha(20),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Icon(_categoryIcon(cat), color: color, size: 20),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      if (cat != null)
                        Text(
                          cat,
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                            color: color,
                            letterSpacing: 0.8,
                          ),
                        ),
                      const SizedBox(height: 2),
                      Text(
                        item['message']?.toString() ?? '',
                        style: TextStyle(
                          fontSize: 13,
                          color: IceColors.text,
                          fontWeight: isRead
                              ? FontWeight.w500
                              : FontWeight.w600,
                          height: 1.4,
                        ),
                      ),
                      if (item['created_at'] != null)
                        Padding(
                          padding: const EdgeInsets.only(top: 6),
                          child: Text(
                            _fmt(item['created_at'].toString()),
                            style: const TextStyle(
                              fontSize: 11,
                              color: IceColors.muted,
                            ),
                          ),
                        ),
                    ],
                  ),
                ),
                if (!isRead)
                  Container(
                    width: 8,
                    height: 8,
                    margin: const EdgeInsets.only(top: 4),
                    decoration: BoxDecoration(
                      color: color,
                      shape: BoxShape.circle,
                    ),
                  ),
              ],
            ),
          ),
        )
        .animate(delay: Duration(milliseconds: 60 + index * 50))
        .slideX(begin: 0.1, duration: 320.ms, curve: Curves.easeOut)
        .fadeIn(duration: 280.ms);
  }

  String _fmt(String iso) {
    try {
      final dt = DateTime.parse(iso).toLocal();
      final now = DateTime.now();
      final diff = now.difference(dt);
      if (diff.inMinutes < 1) return 'Just now';
      if (diff.inHours < 1) return '${diff.inMinutes}m ago';
      if (diff.inDays < 1) return '${diff.inHours}h ago';
      if (diff.inDays < 7) return '${diff.inDays}d ago';
      return '${dt.day}/${dt.month}/${dt.year}';
    } catch (_) {
      return iso;
    }
  }
}

class _Skeleton extends StatelessWidget {
  const _Skeleton();
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(16),
    child: Column(
      children: [
        for (int i = 0; i < 6; i++) ...[
          Container(
            height: 76,
            decoration: BoxDecoration(
              color: Colors.grey[200],
              borderRadius: BorderRadius.circular(18),
            ),
          ),
          const SizedBox(height: 10),
        ],
      ],
    ),
  );
}

class _Empty extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final s = ref.watch(stringsProvider);
    return Padding(
      padding: const EdgeInsets.all(40),
      child: Column(
        children: [
          Icon(
            Icons.notifications_none_rounded,
            size: 56,
            color: IceColors.muted.withAlpha(100),
          ),
          const SizedBox(height: 16),
          Text(
            s('All clear'),
            style: const TextStyle(
              fontSize: 16,
              fontWeight: FontWeight.w600,
              color: IceColors.muted,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            s('No notifications yet.'),
            style: const TextStyle(fontSize: 13, color: IceColors.muted),
          ),
        ],
      ),
    );
  }
}

class _ErrorCard extends StatelessWidget {
  final String message;
  const _ErrorCard(this.message);
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.all(24),
    child: Text(
      'Error: $message',
      style: const TextStyle(color: IceColors.danger),
    ),
  );
}
