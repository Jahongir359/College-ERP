part of '../staff_feature_screens.dart';

// ════════════════════════════════════════════════════════════════════════════
//  1 · Classes  — list groups, tap to see the enrolled roster
// ════════════════════════════════════════════════════════════════════════════

class StaffClassesScreen extends ConsumerWidget {
  const StaffClassesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final brand = context.brand;
    final groups = ref.watch(staffGroupsProvider);

    return Scaffold(
      backgroundColor: t.bg,
      body: SafeArea(
        bottom: false,
        child: groups.when(
          loading: () => const PageSkeleton(),
          error: (e, _) => ErrorState(
            error: e,
            onRetry: () => ref.invalidate(staffGroupsProvider),
          ),
          data: (list) => IcePage(
            title: s(brand.teacherGroupsKey),
            subtitle: s(brand.teacherGroupsHintKey),
            backButton: true,
            onRefresh: () => ref.refresh(staffGroupsProvider.future),
        children: [
          if (list.isEmpty)
            IceCard(
              child: EmptyState(
                icon: Icons.class_outlined,
                title: s(brand.isSchool ? 'No classes assigned' : 'No groups assigned'),
                message: s(
                  brand.isSchool
                      ? 'Your classes will appear here once assigned.'
                      : 'Your groups will appear here once assigned.',
                ),
              ),
            )
          else
            ...list.map(
              (g) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _ClassCard(group: g as Map<String, dynamic>),
              ),
            ),
          ],
        ),
      ),
    ),
  );
  }
}

class _ClassCard extends ConsumerWidget {
  final Map<String, dynamic> group;
  const _ClassCard({required this.group});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    return IceCard(
      padding: const EdgeInsets.all(16),
      onTap: () => showModalBottomSheet(
        context: context,
        isScrollControlled: true,
        backgroundColor: t.card,
        shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
        ),
        builder: (_) => _RosterSheet(
          groupId: group['id'] as int,
          groupName: (group['name'] ?? 'Group').toString(),
        ),
      ),
      child: Row(
        children: [
          Container(
            width: 46,
            height: 46,
            decoration: BoxDecoration(
              color: t.accentSoft,
              borderRadius: BorderRadius.circular(13),
            ),
            child: Icon(Icons.group_rounded, color: t.accentInk),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  group['name']?.toString() ?? 'Group',
                  style: TextStyle(
                    fontWeight: FontWeight.w800,
                    fontSize: 15,
                    color: t.textHi,
                  ),
                ),
                const SizedBox(height: 2),
                if ((group['course_name']?.toString() ?? '').isNotEmpty)
                  Text(
                    group['course_name'].toString(),
                    style: TextStyle(fontSize: 12.5, color: t.textMid),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                if ((group['schedule']?.toString() ?? '').isNotEmpty ||
                    group['room'] != null)
                  Text(
                    [
                      group['schedule']?.toString(),
                      group['room'] != null ? roomLabel(s, '${group['room']}') : null,
                    ].where((e) => e != null && e.isNotEmpty).join(' · '),
                    style: TextStyle(fontSize: 12, color: t.textLow),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
              ],
            ),
          ),
          Icon(Icons.chevron_right_rounded, color: t.textLow),
        ],
      ),
    );
  }
}

class _RosterSheet extends ConsumerWidget {
  final int groupId;
  final String groupName;
  const _RosterSheet({required this.groupId, required this.groupName});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final detail = ref.watch(groupDetailProvider(groupId));
    return DraggableScrollableSheet(
      expand: false,
      initialChildSize: 0.6,
      maxChildSize: 0.9,
      builder: (_, controller) => Column(
        children: [
          const SizedBox(height: 10),
          Container(
            width: 42,
            height: 4,
            decoration: BoxDecoration(
              color: t.stroke,
              borderRadius: BorderRadius.circular(99),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 14, 20, 8),
            child: Row(
              children: [
                Icon(Icons.people_alt_rounded, color: t.accentInk),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    '$groupName · Students',
                    style: TextStyle(
                      fontSize: 17,
                      fontWeight: FontWeight.w800,
                      color: t.textHi,
                    ),
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: detail.when(
              loading: () => const PageSkeleton(),
              error: (e, _) => ErrorState(
                error: e,
                onRetry: () => ref.invalidate(groupDetailProvider(groupId)),
              ),
              data: (d) {
                final students = (d['enrolled_students'] as List?) ?? [];
                if (students.isEmpty) {
                  return EmptyState(
                    icon: Icons.person_off_outlined,
                    title: s('No students enrolled yet'),
                  );
                }
                return ListView.separated(
                  controller: controller,
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
                  cacheExtent: 600,
                  itemCount: students.length,
                  separatorBuilder: (_, __) => const SizedBox(height: 8),
                  itemBuilder: (_, i) {
                    final s = students[i] as Map<String, dynamic>;
                    final name = _studentName(s);
                    return IceCard(
                      padding: const EdgeInsets.all(12),
                      child: Row(
                        children: [
                          CircleAvatar(
                            radius: 18,
                            backgroundColor: t.accentSoft,
                            child: Text(
                              name.characters.first.toUpperCase(),
                              style: TextStyle(
                                color: t.accentInk,
                                fontWeight: FontWeight.w800,
                              ),
                            ),
                          ),
                          const SizedBox(width: 12),
                          Expanded(
                            child: Text(
                              name,
                              style: TextStyle(
                                fontWeight: FontWeight.w600,
                                color: t.textHi,
                              ),
                            ),
                          ),
                          if ((s['status']?.toString() ?? '') != 'active')
                            StatusBadge(
                              s['status']?.toString() ?? '',
                              tone: BadgeTone.amber,
                            ),
                        ],
                      ),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}
