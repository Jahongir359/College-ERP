import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:image_picker/image_picker.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/auth/auth_state.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';
import '../../../core/theme/brand.dart';

String _uzs(num v) =>
    '${NumberFormat('#,###').format(v).replaceAll(',', ' ')} soʻm';

// ─────────────────────────────────────────────────────────────────────────────
// Profile tab
// ─────────────────────────────────────────────────────────────────────────────
class StudentProfileScreen extends ConsumerWidget {
  const StudentProfileScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider).user;
    final dash = ref.watch(studentDashProvider);
    final notifications = ref.watch(notificationsProvider);
    final settings = ref.watch(appSettingsProvider);

    final tier = dash.maybeWhen(
      data: (d) => (d['tier'] as String?) ?? '',
      orElse: () => '',
    );
    final balance = dash.maybeWhen(
      data: (d) => (d['balance_due'] as num?) ?? 0,
      orElse: () => 0,
    );
    final dueDate = dash.maybeWhen(
      data: (d) => DateTime.tryParse(d['balance_due_date'] ?? ''),
      orElse: () => null,
    );

    return IcePage(
      title: s('Profile'),
      onRefresh: () async {
        ref.invalidate(studentDashProvider);
        ref.invalidate(notificationsProvider);
      },
      children: [
        // ── Avatar + identity ────────────────────────────────────────────
        Center(
          child: GestureDetector(
            onTap: () => context.push('/student/profile/avatar'),
            child: Container(
              padding: const EdgeInsets.all(4),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: t.accent, width: 2),
              ),
              child: IceUserAvatar(
                radius: 44,
                photoUrl: user?.profilePicUrl,
                emoji: user?.avatar.isNotEmpty == true ? user!.avatar : null,
                fallbackText: user?.firstName.isNotEmpty == true
                    ? user!.firstName[0].toUpperCase()
                    : '?',
                bgColor: t.inset,
              ),
            ),
          ),
        ),
        const SizedBox(height: 14),
        Center(
          child: Text(
            user?.fullName ?? '',
            style: TextStyle(
              fontSize: 23,
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
        ),
        const SizedBox(height: 6),
        Center(
          child: Wrap(
            spacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Text(
                'ID ${user?.loginId ?? ''}',
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                  color: t.textMid,
                ),
              ),
              if (tier.isNotEmpty)
                StatusBadge('★ $tier', tone: BadgeTone.accent),
            ],
          ),
        ),
        const SizedBox(height: 10),
        Center(
          child: TextButton.icon(
            onPressed: () => context.go('/student/profile/edit'),
            icon: Icon(Icons.edit_outlined, size: 16, color: t.accent),
            label: Text(
              s('Edit Profile'),
              style: TextStyle(
                color: t.accent,
                fontWeight: FontWeight.w700,
                fontSize: 13.5,
              ),
            ),
          ),
        ),
        const SizedBox(height: 8),

        // ── Balance card ─────────────────────────────────────────────────
        IceCard(
          hero: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.account_balance_rounded, size: 16, color: t.mint),
                  const SizedBox(width: 8),
                  MicroLabel('Tuition Balance', color: t.mint),
                ],
              ),
              const SizedBox(height: 10),
              Text(
                balance > 0 ? _uzs(balance) : 'All paid 🎉',
                style: const TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.w800,
                  color: Colors.white,
                  letterSpacing: -0.5,
                ),
              ),
              if (balance > 0) ...[
                const SizedBox(height: 10),
                Row(
                  children: [
                    if (dueDate != null)
                      StatusBadge(
                        _dueLabel(dueDate),
                        tone: dueDate.isBefore(DateTime.now())
                            ? BadgeTone.coral
                            : BadgeTone.amber,
                      ),
                  ],
                ),
                const SizedBox(height: 14),
                SizedBox(
                  width: 140,
                  height: 44,
                  child: FilledButton(
                    onPressed: () => context.go('/student/payments'),
                    style: FilledButton.styleFrom(
                      backgroundColor: t.accent,
                      foregroundColor: t.onAccent,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14),
                      ),
                    ),
                    child: Text(
                      s('Pay Now'),
                      style: const TextStyle(
                        fontWeight: FontWeight.w800,
                        fontSize: 14,
                      ),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 14),

        // ── Quick cards 2×2 ──────────────────────────────────────────────
        Row(
          children: [
            Expanded(
              child: _QuickCard(
                icon: Icons.payments_outlined,
                title: s('Payments'),
                subtitle: 'History & invoices',
                onTap: () => context.go('/student/payments'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _QuickCard(
                icon: Icons.event_busy_outlined,
                title: s('Leave Requests'),
                subtitle: 'Manage absences',
                onTap: () => context.go('/student/leave'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: _QuickCard(
                icon: Icons.forum_outlined,
                title: s('Feedback'),
                subtitle: 'Reviews & reports',
                onTap: () => context.go('/student/feedback'),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _QuickCard(
                icon: Icons.settings_outlined,
                title: s('Settings'),
                subtitle: 'App preferences',
                onTap: () => context.push('/student/settings'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 22),

        // ── Recent activity ──────────────────────────────────────────────
        SectionHeader(
          'Recent Activity',
          actionLabel: s('View All'),
          onAction: () => context.go('/student/notifications'),
        ),
        notifications.maybeWhen(
          data: (list) => list.isEmpty
              ? const IceCard(
                  child: EmptyState(
                    icon: Icons.history_rounded,
                    title: 'No activity yet',
                  ),
                )
              : Column(
                  children: list
                      .take(3)
                      .map(
                        (n) => Padding(
                          padding: const EdgeInsets.only(bottom: 10),
                          child: ActionTile(
                            icon: _categoryIcon(n['category']),
                            iconColor: t.mint,
                            title: _categoryTitle(n['category']),
                            subtitle: n['message'] ?? '',
                            trailing: n['is_read'] == false
                                ? StatusBadge('New', tone: BadgeTone.accent)
                                : null,
                            onTap: () => context.go('/student/notifications'),
                          ),
                        ),
                      )
                      .toList(),
                ),
          orElse: () => const SkeletonBox(height: 64),
        ),
        const SizedBox(height: 16),

        // ── Appearance selector ──────────────────────────────────────────
        const SectionHeader('Appearance'),
        IceCard(
          padding: const EdgeInsets.all(8),
          child: Column(
            children: [
              _ThemeRow(
                icon: Icons.contrast_rounded,
                label: 'System Default',
                selected: settings.themeMode == ThemeMode.system,
                onTap: () => ref
                    .read(appSettingsProvider.notifier)
                    .setTheme(ThemeMode.system),
              ),
              _ThemeRow(
                icon: Icons.light_mode_outlined,
                label: 'Light Mode',
                selected: settings.themeMode == ThemeMode.light,
                onTap: () => ref
                    .read(appSettingsProvider.notifier)
                    .setTheme(ThemeMode.light),
              ),
              _ThemeRow(
                icon: Icons.dark_mode_outlined,
                label: 'Dark Mode',
                selected: settings.themeMode == ThemeMode.dark,
                onTap: () => ref
                    .read(appSettingsProvider.notifier)
                    .setTheme(ThemeMode.dark),
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        IceButton(
          s('Log out'),
          secondary: true,
          icon: Icons.logout_rounded,
          onPressed: () => ref.read(authProvider.notifier).logout(),
        ),
      ],
    );
  }

  String _dueLabel(DateTime due) {
    final today = DateTime.now();
    final diff = due
        .difference(DateTime(today.year, today.month, today.day))
        .inDays;
    if (diff < 0) return 'Overdue';
    if (diff == 0) return 'Due today';
    return 'Due in $diff days';
  }

  IconData _categoryIcon(dynamic c) => switch (c) {
    'attendance' => Icons.event_available_rounded,
    'result' => Icons.workspace_premium_outlined,
    'announcement' => Icons.campaign_rounded,
    'homework' => Icons.assignment_outlined,
    'vocabulary' => Icons.translate_rounded,
    'payment' => Icons.payments_outlined,
    _ => Icons.notifications_none_rounded,
  };

  String _categoryTitle(dynamic c) => switch (c) {
    'attendance' => 'Attendance',
    'result' => 'Result',
    'announcement' => 'Announcement',
    'homework' => 'Assignment',
    'vocabulary' => 'Vocabulary',
    'payment' => 'Payment',
    _ => 'Notification',
  };
}

class _QuickCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;

  const _QuickCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      onTap: onTap,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(9),
            decoration: BoxDecoration(
              color: t.accentSoft,
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, size: 19, color: t.accent),
          ),
          const SizedBox(height: 12),
          Text(
            title,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 14.5,
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            subtitle,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 11.5,
              fontWeight: FontWeight.w500,
              color: t.textMid,
            ),
          ),
        ],
      ),
    );
  }
}

class _ThemeRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  const _ThemeRow({
    required this.icon,
    required this.label,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: selected ? t.accent : Colors.transparent,
          borderRadius: BorderRadius.circular(15),
        ),
        child: Row(
          children: [
            Icon(icon, size: 19, color: selected ? t.onAccent : t.textMid),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                label,
                style: TextStyle(
                  fontSize: 14.5,
                  fontWeight: FontWeight.w700,
                  color: selected ? t.onAccent : t.textHi,
                ),
              ),
            ),
            if (selected)
              Icon(
                Icons.check_circle_outline_rounded,
                size: 19,
                color: t.onAccent,
              ),
          ],
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Edit profile
// ─────────────────────────────────────────────────────────────────────────────
class StudentEditProfileScreen extends ConsumerStatefulWidget {
  const StudentEditProfileScreen({super.key});

  @override
  ConsumerState<StudentEditProfileScreen> createState() =>
      _StudentEditProfileScreenState();
}

class _StudentEditProfileScreenState
    extends ConsumerState<StudentEditProfileScreen> {
  final _phone = TextEditingController();
  final _address = TextEditingController();
  bool _busy = false;
  bool _seeded = false;

  @override
  void dispose() {
    _phone.dispose();
    _address.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    setState(() => _busy = true);
    try {
      final res = await ApiClient.instance.dio.patch(
        '/me/',
        data: {'phone': _phone.text.trim(), 'address': _address.text.trim()},
      );
      ref
          .read(authProvider.notifier)
          .updateUser(IceUser.fromJson(res.data as Map<String, dynamic>));
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('Profile updated.')));
        context.pop();
      }
    } on DioException {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Could not save changes. Try again.')),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final user = ref.watch(authProvider).user;
    final role = user?.roleProfile ?? {};

    if (!_seeded && user != null) {
      _phone.text = (role['phone'] as String?) ?? '';
      _address.text = ''; // address not cached locally; user enters new value
      _seeded = true;
    }

    Widget label(String text) => Padding(
      padding: const EdgeInsets.only(bottom: 8, top: 16),
      child: MicroLabel(text),
    );

    Widget readOnly(String value) => Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: t.inset.withValues(alpha: 0.5),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: t.stroke),
      ),
      child: Row(
        children: [
          Expanded(
            child: Text(
              value.isEmpty ? '—' : value,
              style: TextStyle(
                color: t.textMid,
                fontSize: 14.5,
                fontWeight: FontWeight.w600,
              ),
            ),
          ),
          Icon(Icons.lock_outline_rounded, size: 15, color: t.textLow),
        ],
      ),
    );

    return IcePage(
      title: 'Edit Profile',
      backButton: true,
      children: [
        Center(
          child: GestureDetector(
            onTap: () => context.push('/student/profile/avatar'),
            child: Stack(
              children: [
                Container(
                  padding: const EdgeInsets.all(4),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    border: Border.all(color: t.accent, width: 2),
                  ),
                  child: IceUserAvatar(
                    radius: 40,
                    photoUrl: user?.profilePicUrl,
                    emoji: user?.avatar.isNotEmpty == true ? user!.avatar : null,
                    fallbackText: user?.firstName.isNotEmpty == true
                        ? user!.firstName[0].toUpperCase()
                        : '?',
                    bgColor: t.inset,
                  ),
                ),
                Positioned(
                  bottom: 2,
                  right: 2,
                  child: Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: t.accent,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      Icons.photo_camera_outlined,
                      size: 14,
                      color: t.onAccent,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
        label('Full name'),
        readOnly(user?.fullName ?? ''),
        label('Student ID'),
        readOnly(user?.loginId ?? ''),
        label('Email'),
        readOnly(user?.email ?? ''),
        label(context.brand.groupKey),
        readOnly(((role['group_names'] as List?) ?? []).join(', ')),
        label('Branch'),
        readOnly((role['branch_name'] as String?) ?? ''),
        label('Phone'),
        TextField(
          controller: _phone,
          keyboardType: TextInputType.phone,
          style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
          decoration: const InputDecoration(hintText: '+998 90 123 45 67'),
        ),
        label('Address'),
        TextField(
          controller: _address,
          maxLines: 2,
          style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
          decoration: const InputDecoration(hintText: 'City, street…'),
        ),
        const SizedBox(height: 24),
        IceButton('Save Changes', busy: _busy, onPressed: _save),
        const SizedBox(height: 10),
        Center(
          child: Text(
            'Name, ID, group and branch changes require the admin office.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: t.textLow),
          ),
        ),
      ],
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Change avatar
// ─────────────────────────────────────────────────────────────────────────────
class StudentAvatarScreen extends ConsumerStatefulWidget {
  const StudentAvatarScreen({super.key});

  @override
  ConsumerState<StudentAvatarScreen> createState() =>
      _StudentAvatarScreenState();
}

class _StudentAvatarScreenState extends ConsumerState<StudentAvatarScreen> {
  static const _emojis = [
    '🧑‍🎓',
    '👩‍🎓',
    '👨‍🎓',
    '🦊',
    '🐼',
    '🐯',
    '🦁',
    '🐸',
    '🐙',
    '🦄',
    '🐳',
    '🦉',
    '🚀',
    '🌟',
    '🔥',
    '🍀',
    '🎧',
    '🎮',
    '📚',
    '🧠',
    '⚽',
    '🏀',
    '🎸',
    '🎨',
  ];

  String? _selected;
  bool _busy = false;
  int _tab = 0;

  Future<void> _saveEmoji() async {
    if (_selected == null) return;
    setState(() => _busy = true);
    try {
      final res = await ApiClient.instance.dio.patch(
        '/me/',
        data: {'avatar': _selected},
      );
      ref
          .read(authProvider.notifier)
          .updateUser(IceUser.fromJson(res.data as Map<String, dynamic>));
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Avatar saved ✓'),
            duration: Duration(seconds: 2),
            behavior: SnackBarBehavior.floating,
          ),
        );
        await Future.delayed(const Duration(milliseconds: 420));
        if (mounted) context.pop();
      }
    } on DioException {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Could not save avatar.')),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _uploadPhoto() async {
    final picked = await ImagePicker().pickImage(
      source: ImageSource.gallery,
      maxWidth: 800,
      imageQuality: 85,
    );
    if (picked == null) return;
    setState(() => _busy = true);
    try {
      final form = FormData.fromMap({
        'profile_pic': MultipartFile.fromBytes(
          await picked.readAsBytes(),
          filename: picked.name,
        ),
      });
      final res = await ApiClient.instance.dio.patch('/me/', data: form);
      PaintingBinding.instance.imageCache.clear();
      PaintingBinding.instance.imageCache.clearLiveImages();
      ref
          .read(authProvider.notifier)
          .updateUser(IceUser.fromJson(res.data as Map<String, dynamic>));
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Avatar saved ✓'),
            duration: Duration(seconds: 2),
            behavior: SnackBarBehavior.floating,
          ),
        );
        await Future.delayed(const Duration(milliseconds: 420));
        if (mounted) context.pop();
      }
    } on DioException {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Upload failed. Try a smaller image.')),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider).user;

    final activeEmoji = _selected ??
        (user?.avatar.isNotEmpty == true ? user!.avatar : null);

    return Scaffold(
      backgroundColor: t.bg,
      appBar: AppBar(
        backgroundColor: t.bg,
        elevation: 0,
        scrolledUnderElevation: 0,
        leading: IconButton(
          onPressed: () => context.pop(),
          icon: Icon(Icons.arrow_back_rounded, color: t.textHi),
        ),
        centerTitle: true,
        title: Text(
          s('Choose Avatar'),
          style: TextStyle(
            color: t.textHi,
            fontWeight: FontWeight.w800,
            fontSize: 17,
            fontFamily: 'Inter',
          ),
        ),
      ),
      body: ListView(
        cacheExtent: 600,
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
        children: [
          // ── Live avatar preview ──────────────────────────────────────────
          Center(
            child: Container(
              padding: const EdgeInsets.all(4),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: t.accent, width: 2.5),
              ),
              child: CircleAvatar(
                radius: 46,
                backgroundColor: t.inset,
                child: activeEmoji != null && user?.profilePicUrl == null
                    ? Text(activeEmoji,
                        style: const TextStyle(fontSize: 40))
                    : IceUserAvatar(
                        radius: 46,
                        photoUrl: user?.profilePicUrl,
                        emoji: activeEmoji,
                        fallbackText: user?.firstName.isNotEmpty == true
                            ? user!.firstName[0].toUpperCase()
                            : 'S',
                      ),
              ),
            ),
          ),
          const SizedBox(height: 22),

          // ── Tabs ──────────────────────────────────────────────────────────
          IceChipTabs(
            tabs: [s('Emoji'), s('Upload')],
            index: _tab,
            onChanged: (i) => setState(() => _tab = i),
          ),
          const SizedBox(height: 18),

          if (_tab == 0) ...[
            GridView.count(
              crossAxisCount: 4,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              mainAxisSpacing: 12,
              crossAxisSpacing: 12,
              children: _emojis.map((e) {
                final isSelected =
                    _selected == e || (_selected == null && user?.avatar == e);
                return GestureDetector(
                  onTap: () => setState(() => _selected = e),
                  child: AnimatedContainer(
                    duration: const Duration(milliseconds: 160),
                    decoration: BoxDecoration(
                      color: isSelected ? t.accentSoft : t.card,
                      borderRadius: BorderRadius.circular(16),
                      border: Border.all(
                        color: isSelected ? t.accent : t.stroke,
                        width: isSelected ? 2.5 : 1,
                      ),
                    ),
                    alignment: Alignment.center,
                    child: Text(e, style: const TextStyle(fontSize: 30)),
                  ),
                );
              }).toList(),
            ),
            const SizedBox(height: 100), // Space for sticky bottom button
          ] else ...[
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: t.card,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: t.stroke),
              ),
              child: Column(
                children: [
                  Icon(Icons.photo_library_outlined, size: 48, color: t.textLow),
                  const SizedBox(height: 14),
                  Text(
                    s('Upload Photo'),
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w700,
                      color: t.textHi,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Select a photo from your gallery to use as your profile picture.',
                    textAlign: TextAlign.center,
                    style:
                        TextStyle(fontSize: 13, color: t.textMid, height: 1.5),
                  ),
                  const SizedBox(height: 22),
                  SizedBox(
                    width: double.infinity,
                    height: 52,
                    child: FilledButton.icon(
                      onPressed: _busy ? null : _uploadPhoto,
                      icon: _busy
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(
                                  color: Colors.white, strokeWidth: 2),
                            )
                          : const Icon(Icons.photo_library_outlined),
                      label: Text(_busy ? 'Uploading…' : s('Choose Photo')),
                      style: FilledButton.styleFrom(
                        backgroundColor: t.accent,
                        foregroundColor: t.onAccent,
                        shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(16),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
      // ── Sticky save button (emoji tab only) ─────────────────────────────────
      bottomNavigationBar: _tab == 0
          ? SafeArea(
              top: false,
              child: Padding(
                padding: const EdgeInsets.fromLTRB(20, 8, 20, 16),
                child: SizedBox(
                  height: 52,
                  child: FilledButton(
                    onPressed: (_selected == null || _busy) ? null : _saveEmoji,
                    style: FilledButton.styleFrom(
                      backgroundColor: t.accent,
                      foregroundColor: t.onAccent,
                      disabledBackgroundColor:
                          t.accent.withValues(alpha: 0.4),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(16),
                      ),
                    ),
                    child: _busy
                        ? const SizedBox(
                            width: 22,
                            height: 22,
                            child: CircularProgressIndicator(
                                color: Colors.white, strokeWidth: 2),
                          )
                        : Text(
                            s('Save Avatar'),
                            style: const TextStyle(
                              fontWeight: FontWeight.w700,
                              fontSize: 16,
                              fontFamily: 'Inter',
                            ),
                          ),
                  ),
                ),
              ),
            )
          : null,
    );
  }
}
