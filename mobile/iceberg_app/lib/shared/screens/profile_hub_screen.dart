import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../core/api/api_client.dart';
import '../../core/api/api_providers.dart';
import '../../core/auth/auth_state.dart';
import '../../core/settings/app_settings.dart';
import '../../core/theme/brand.dart';
import '../../core/theme/ice_tokens.dart';
import '../../shared/widgets/ice_kit.dart';
import '../../shared/widgets/ice_shell.dart';

class ProfileHubScreen extends ConsumerWidget {
  const ProfileHubScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final user = ref.watch(authProvider).user;
    final settings = ref.watch(appSettingsProvider);
    final notifications = ref.watch(notificationsProvider);

    final roleLabel = user?.isStaff == true
        ? s('Teacher')
        : user?.isAdmin == true
            ? s('Administrator')
            : s('Staff');

    final initials = () {
      final full = '${user?.firstName ?? ''} ${user?.lastName ?? ''}'.trim();
      if (full.isEmpty) return '?';
      final parts = full.split(' ').where((p) => p.isNotEmpty).toList();
      if (parts.length == 1) return parts[0][0].toUpperCase();
      return '${parts[0][0]}${parts[1][0]}'.toUpperCase();
    }();

    return IcePage(
      title: s('Profile'),
      onRefresh: () async => ref.invalidate(notificationsProvider),
      children: [
        // ── Avatar + identity ──────────────────────────────────────────────
        Center(
          child: GestureDetector(
            onTap: () => context.push('/staff/profile/avatar'),
            child: Stack(
              children: [
                Container(
                  padding: const EdgeInsets.all(4),
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    border: Border.all(color: t.accent, width: 2.5),
                  ),
                  child: IceUserAvatar(
                    radius: 44,
                    photoUrl: user?.profilePicUrl,
                    emoji: user?.avatar.isNotEmpty == true ? user!.avatar : null,
                    fallbackText: initials,
                    bgColor: t.inset,
                  ),
                ),
                Positioned(
                  bottom: 4,
                  right: 4,
                  child: Container(
                    padding: const EdgeInsets.all(6),
                    decoration: BoxDecoration(
                      color: t.accent,
                      shape: BoxShape.circle,
                      border: Border.all(color: t.bg, width: 2),
                    ),
                    child: Icon(Icons.edit_rounded,
                        size: 13, color: t.onAccent),
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        Center(
          child: Text(
            user?.fullName.isNotEmpty == true
                ? user!.fullName
                : (user?.loginId ?? ''),
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
                    color: t.textMid),
              ),
              StatusBadge(roleLabel, tone: BadgeTone.accent),
            ],
          ),
        ),
        const SizedBox(height: 10),
        Center(
          child: TextButton.icon(
            onPressed: () => _showEditSheet(context, ref, user),
            icon: Icon(Icons.edit_outlined, size: 16, color: t.accent),
            label: Text(
              s('Edit Profile'),
              style: TextStyle(
                  color: t.accent,
                  fontWeight: FontWeight.w700,
                  fontSize: 13.5),
            ),
          ),
        ),
        const SizedBox(height: 8),

        // ── Quick cards 2×2 ────────────────────────────────────────────────
        Row(children: [
          Expanded(
            child: _QuickCard(
              icon: Icons.event_busy_outlined,
              title: s('Leave'),
              subtitle: s('Request time off'),
              onTap: () => context.push('/staff/leave'),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: _QuickCard(
              icon: Icons.forum_outlined,
              title: s('Feedback'),
              subtitle: s('Send a report'),
              onTap: () => context.push('/staff/feedback'),
            ),
          ),
        ]),
        const SizedBox(height: 12),
        Row(children: [
          Expanded(
            child: _QuickCard(
              icon: Icons.class_outlined,
              title: s(context.brand.teacherGroupsKey),
              subtitle: s(context.brand.teacherGroupsHintKey),
              onTap: () => context.push('/staff/classes'),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: _QuickCard(
              icon: Icons.chat_rounded,
              title: s('Messages'),
              subtitle: s('Group conversations'),
              onTap: () => context.push('/staff/messages'),
            ),
          ),
        ]),
        const SizedBox(height: 12),
        Row(children: [
          Expanded(
            child: _QuickCard(
              icon: Icons.settings_outlined,
              title: s('Settings'),
              subtitle: s('Theme, language & more'),
              onTap: () => context.push('/staff/settings'),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: _QuickCard(
              icon: Icons.payments_outlined,
              title: s('Payments'),
              subtitle: s('Student invoices'),
              onTap: () => context.push('/staff/payments'),
            ),
          ),
        ]),
        const SizedBox(height: 22),

        // ── Recent notifications ────────────────────────────────────────────
        SectionHeader(
          s('Recent Activity'),
          actionLabel: s('View All'),
          onAction: () => context.push('/staff/notifications'),
        ),
        notifications.maybeWhen(
          data: (list) => list.isEmpty
              ? IceCard(
                  child: EmptyState(
                    icon: Icons.history_rounded,
                    title: s('No activity yet'),
                  ),
                )
              : Column(
                  children: list
                      .take(3)
                      .map((n) => Padding(
                            padding: const EdgeInsets.only(bottom: 10),
                            child: ActionTile(
                              icon: _categoryIcon(n['category']),
                              iconColor: t.mint,
                              title: s(_categoryTitle(n['category'])),
                              subtitle: n['message'] ?? '',
                              trailing: n['is_read'] == false
                                  ? StatusBadge(s('New'), tone: BadgeTone.accent)
                                  : null,
                              onTap: () =>
                                  context.push('/staff/notifications'),
                            ),
                          ))
                      .toList(),
                ),
          orElse: () => const SkeletonBox(height: 64),
        ),
        const SizedBox(height: 16),

        // ── Appearance shortcut ─────────────────────────────────────────────
        SectionHeader(s('Appearance')),
        IceCard(
          padding: const EdgeInsets.all(8),
          child: Column(children: [
            _ThemeRow(
              icon: Icons.contrast_rounded,
              label: s('System Default'),
              selected: settings.themeMode == ThemeMode.system,
              onTap: () => ref
                  .read(appSettingsProvider.notifier)
                  .setTheme(ThemeMode.system),
            ),
            _ThemeRow(
              icon: Icons.light_mode_outlined,
              label: s('Light Mode'),
              selected: settings.themeMode == ThemeMode.light,
              onTap: () => ref
                  .read(appSettingsProvider.notifier)
                  .setTheme(ThemeMode.light),
            ),
            _ThemeRow(
              icon: Icons.dark_mode_outlined,
              label: s('Dark Mode'),
              selected: settings.themeMode == ThemeMode.dark,
              onTap: () => ref
                  .read(appSettingsProvider.notifier)
                  .setTheme(ThemeMode.dark),
            ),
          ]),
        ),
        const SizedBox(height: 8),
        ActionTile(
          icon: Icons.tune_rounded,
          iconColor: t.accent,
          title: s('Language, Accent & More'),
          subtitle: s('Full appearance settings'),
          onTap: () => context.push('/staff/settings'),
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

  void _showEditSheet(BuildContext context, WidgetRef ref, IceUser? user) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => _EditProfileSheet(user: user),
    );
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

// ─── Quick Card ───────────────────────────────────────────────────────────────

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
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
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
              fontSize: 14.5, fontWeight: FontWeight.w800, color: t.textHi),
        ),
        const SizedBox(height: 2),
        Text(
          subtitle,
          maxLines: 1,
          overflow: TextOverflow.ellipsis,
          style: TextStyle(
              fontSize: 11.5, fontWeight: FontWeight.w500, color: t.textMid),
        ),
      ]),
    );
  }
}

// ─── Theme Row ────────────────────────────────────────────────────────────────

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
        child: Row(children: [
          Icon(icon, size: 19, color: selected ? t.onAccent : t.textMid),
          const SizedBox(width: 12),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                  fontSize: 14.5,
                  fontWeight: FontWeight.w700,
                  color: selected ? t.onAccent : t.textHi),
            ),
          ),
          if (selected)
            Icon(Icons.check_circle_outline_rounded,
                size: 19, color: t.onAccent),
        ]),
      ),
    );
  }
}

// ─── Edit Profile Sheet ───────────────────────────────────────────────────────

class _EditProfileSheet extends ConsumerStatefulWidget {
  final IceUser? user;
  const _EditProfileSheet({this.user});

  @override
  ConsumerState<_EditProfileSheet> createState() => _EditProfileSheetState();
}

class _EditProfileSheetState extends ConsumerState<_EditProfileSheet> {
  late final TextEditingController _first;
  late final TextEditingController _last;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    _first = TextEditingController(text: widget.user?.firstName ?? '');
    _last = TextEditingController(text: widget.user?.lastName ?? '');
  }

  @override
  void dispose() {
    _first.dispose();
    _last.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    setState(() => _saving = true);
    try {
      final res = await ApiClient.instance.dio.patch('/me/', data: {
        'first_name': _first.text.trim(),
        'last_name': _last.text.trim(),
      });
      ref.read(authProvider.notifier).updateUser(
            IceUser.fromJson(Map<String, dynamic>.from(res.data as Map)),
          );
      if (mounted) Navigator.of(context).pop();
    } catch (_) {
      if (mounted) {
        final s = ref.read(stringsProvider);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(s('Could not save changes.'))),
        );
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final bottom =
        MediaQuery.viewInsetsOf(context).bottom + MediaQuery.paddingOf(context).bottom;
    return Container(
      padding: EdgeInsets.fromLTRB(20, 20, 20, 20 + bottom),
      decoration: BoxDecoration(
        color: t.card,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        Center(
          child: Container(
            width: 40, height: 4,
            margin: const EdgeInsets.only(bottom: 16),
            decoration: BoxDecoration(
              color: t.stroke, borderRadius: BorderRadius.circular(2)),
          ),
        ),
        Text(s('Edit Profile'),
            style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w800,
                color: t.textHi)),
        const SizedBox(height: 20),
        TextField(
          controller: _first,
          style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
          decoration: InputDecoration(labelText: s('First Name')),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _last,
          style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
          decoration: InputDecoration(labelText: s('Last Name')),
        ),
        const SizedBox(height: 20),
        IceButton(s('Save Changes'), busy: _saving, onPressed: _save),
      ]),
    );
  }
}

// ─── Change Password Sheet ────────────────────────────────────────────────────

class _ChangePasswordSheet extends ConsumerStatefulWidget {
  const _ChangePasswordSheet();

  @override
  ConsumerState<_ChangePasswordSheet> createState() =>
      _ChangePasswordSheetState();
}

class _ChangePasswordSheetState extends ConsumerState<_ChangePasswordSheet> {
  final _old = TextEditingController();
  final _new = TextEditingController();
  final _confirm = TextEditingController();
  final _formKey = GlobalKey<FormState>();
  bool _saving = false;
  bool _showOld = false;
  bool _showNew = false;
  bool _showConfirm = false;

  @override
  void dispose() {
    _old.dispose();
    _new.dispose();
    _confirm.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() => _saving = true);
    try {
      await ApiClient.instance.dio.post('/me/change-password/', data: {
        'old_password': _old.text,
        'new_password': _new.text,
        'confirm_password': _confirm.text,
      });
      if (mounted) Navigator.of(context).pop();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context)
            .showSnackBar(SnackBar(content: Text('${ref.read(stringsProvider)('Error')}: $e')));
      }
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final bottom =
        MediaQuery.viewInsetsOf(context).bottom + MediaQuery.paddingOf(context).bottom;
    return Container(
      padding: EdgeInsets.fromLTRB(20, 20, 20, 20 + bottom),
      decoration: BoxDecoration(
        color: t.card,
        borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
      ),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        Center(
          child: Container(
            width: 40, height: 4,
            margin: const EdgeInsets.only(bottom: 16),
            decoration: BoxDecoration(
              color: t.stroke, borderRadius: BorderRadius.circular(2)),
          ),
        ),
        Text(s('Change Password'),
            style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w800,
                color: t.textHi)),
        const SizedBox(height: 20),
        Form(
          key: _formKey,
          child: Column(children: [
            _PwdField(
              ctrl: _old, label: s('Current Password'),
              show: _showOld, onToggle: () => setState(() => _showOld = !_showOld),
              validator: (v) => (v?.isEmpty ?? true) ? s('Required') : null,
            ),
            const SizedBox(height: 12),
            _PwdField(
              ctrl: _new, label: s('New Password'),
              show: _showNew, onToggle: () => setState(() => _showNew = !_showNew),
              validator: (v) {
                if (v?.isEmpty ?? true) return s('Required');
                if (v!.length < 6) return s('At least 6 characters');
                return null;
              },
            ),
            const SizedBox(height: 12),
            _PwdField(
              ctrl: _confirm, label: s('Confirm Password'),
              show: _showConfirm, onToggle: () => setState(() => _showConfirm = !_showConfirm),
              validator: (v) {
                if (v?.isEmpty ?? true) return s('Required');
                if (v != _new.text) return s('Passwords do not match');
                return null;
              },
            ),
            const SizedBox(height: 20),
            IceButton(s('Update Password'), busy: _saving, onPressed: _submit),
          ]),
        ),
      ]),
    );
  }
}

class _PwdField extends StatelessWidget {
  final TextEditingController ctrl;
  final String label;
  final bool show;
  final VoidCallback onToggle;
  final FormFieldValidator<String>? validator;
  const _PwdField({
    required this.ctrl, required this.label,
    required this.show, required this.onToggle, this.validator,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return TextFormField(
      controller: ctrl,
      obscureText: !show,
      validator: validator,
      style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
      decoration: InputDecoration(
        labelText: label,
        suffixIcon: IconButton(
          onPressed: onToggle,
          icon: Icon(
            show ? Icons.visibility_off_rounded : Icons.visibility_rounded,
            size: 18, color: t.textLow,
          ),
        ),
      ),
    );
  }
}
