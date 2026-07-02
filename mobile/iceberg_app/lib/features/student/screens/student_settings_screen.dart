import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/api/api_client.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

class StudentSettingsScreen extends ConsumerWidget {
  const StudentSettingsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final settings = ref.watch(appSettingsProvider);
    final notifier = ref.read(appSettingsProvider.notifier);

    Widget section(String title) => Padding(
      padding: const EdgeInsets.only(top: 22, bottom: 10),
      child: MicroLabel(title),
    );

    return IcePage(
      title: s('Settings'),
      subtitle: s('Appearance'),
      backButton: true,
      children: [
        // ── Theme ────────────────────────────────────────────────────────
        section(s('Theme')),
        IceCard(
          padding: const EdgeInsets.all(8),
          child: Column(
            children: [
              for (final (mode, icon, label) in [
                (ThemeMode.system, Icons.contrast_rounded, s('System')),
                (ThemeMode.light, Icons.light_mode_outlined, s('Light')),
                (ThemeMode.dark, Icons.dark_mode_outlined, s('Dark')),
              ])
                _OptionRow(
                  icon: icon,
                  label: label,
                  selected: settings.themeMode == mode,
                  onTap: () => notifier.setTheme(mode),
                ),
            ],
          ),
        ),

        // ── Accent colour ────────────────────────────────────────────────
        section(s('Accent Color')),
        IceCard(
          child: Wrap(
            spacing: 14,
            runSpacing: 14,
            alignment: WrapAlignment.spaceBetween,
            children: IceAccents.byName.entries.map((e) {
              final selected = settings.accent == e.key;
              return GestureDetector(
                onTap: () => notifier.setAccent(e.key),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 160),
                  width: 38,
                  height: 38,
                  decoration: BoxDecoration(
                    color: e.value,
                    shape: BoxShape.circle,
                    border: Border.all(
                      color: selected ? t.textHi : Colors.transparent,
                      width: 3,
                    ),
                    boxShadow: selected
                        ? [
                            BoxShadow(
                              color: e.value.withValues(alpha: 0.5),
                              blurRadius: 12,
                            ),
                          ]
                        : null,
                  ),
                  child: selected
                      ? Icon(
                          Icons.check_rounded,
                          size: 19,
                          color: context.ice.onAccent,
                        )
                      : null,
                ),
              );
            }).toList(),
          ),
        ),

        // ── Font size ────────────────────────────────────────────────────
        section(s('Font Size')),
        IceChipTabs(
          tabs: [s('Small'), s('Medium'), s('Large')],
          index: switch (settings.fontSize) {
            'small' => 0,
            'large' => 2,
            _ => 1,
          },
          onChanged: (i) =>
              notifier.setFontSize(const ['small', 'medium', 'large'][i]),
        ),

        // ── Language ─────────────────────────────────────────────────────
        section(s('Language')),
        IceCard(
          padding: const EdgeInsets.all(8),
          child: Column(
            children: [
              for (final (code, label) in [
                ('en', 'English'),
                ('uz', 'Oʻzbekcha'),
                ('ru', 'Русский'),
                ('ko', '한국어'),
              ])
                _OptionRow(
                  icon: Icons.language_rounded,
                  label: label,
                  selected: settings.language == code,
                  onTap: () => notifier.setLanguage(code),
                ),
            ],
          ),
        ),

        // ── Notifications ────────────────────────────────────────────────
        section(s('Notifications')),
        IceCard(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
          child: Column(
            children: [
              for (final (i, (key, label, icon)) in [
                (
                  'assignments',
                  'Assignment reminders',
                  Icons.assignment_outlined,
                ),
                ('vocabulary', 'Vocabulary reminders', Icons.translate_rounded),
                ('payments', 'Payment reminders', Icons.payments_outlined),
                (
                  'announcements',
                  'Announcement alerts',
                  Icons.campaign_outlined,
                ),
              ].indexed) ...[
                if (i > 0) Divider(color: t.stroke, height: 1),
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 11),
                  child: Row(
                    children: [
                      Icon(icon, size: 19, color: t.textMid),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Text(
                          s(label),
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                            color: t.textHi,
                          ),
                        ),
                      ),
                      IceSwitch(
                        value: settings.notifications[key] ?? true,
                        onChanged: (v) => notifier.setNotification(key, v),
                      ),
                    ],
                  ),
                ),
              ],
            ],
          ),
        ),

        // ── Security ─────────────────────────────────────────────────────
        section(s('Security')),
        ActionTile(
          icon: Icons.lock_outline_rounded,
          title: s('Change Password'),
          subtitle: 'Update your account password',
          onTap: () => _changePassword(context),
        ),
        const SizedBox(height: 24),
      ],
    );
  }

  void _changePassword(BuildContext context) {
    final t = context.ice;
    final old = TextEditingController();
    final newPw = TextEditingController();
    final confirm = TextEditingController();
    bool busy = false;
    String? error;

    showModalBottomSheet(
      context: context,
      backgroundColor: t.card,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (sheetCtx) => StatefulBuilder(
        builder: (ctx, setSheet) => Padding(
          padding: EdgeInsets.fromLTRB(
            24,
            20,
            24,
            24 + MediaQuery.of(ctx).viewInsets.bottom,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Change Password',
                style: TextStyle(
                  fontSize: 19,
                  fontWeight: FontWeight.w800,
                  color: t.textHi,
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: old,
                obscureText: true,
                style: TextStyle(color: t.textHi),
                decoration: const InputDecoration(hintText: 'Current password'),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: newPw,
                obscureText: true,
                style: TextStyle(color: t.textHi),
                decoration: const InputDecoration(
                  hintText: 'New password (min 8 chars)',
                ),
              ),
              const SizedBox(height: 10),
              TextField(
                controller: confirm,
                obscureText: true,
                style: TextStyle(color: t.textHi),
                decoration: const InputDecoration(
                  hintText: 'Confirm new password',
                ),
              ),
              if (error != null) ...[
                const SizedBox(height: 10),
                Text(error!, style: TextStyle(color: t.coral, fontSize: 13)),
              ],
              const SizedBox(height: 18),
              IceButton(
                'Update Password',
                busy: busy,
                onPressed: () async {
                  setSheet(() {
                    busy = true;
                    error = null;
                  });
                  try {
                    await ApiClient.instance.dio.post(
                      '/me/change-password/',
                      data: {
                        'old_password': old.text,
                        'new_password': newPw.text,
                        'confirm_password': confirm.text,
                      },
                    );
                    if (sheetCtx.mounted) Navigator.pop(sheetCtx);
                  } on DioException catch (e) {
                    final data = e.response?.data;
                    setSheet(() {
                      busy = false;
                      error = data is Map && data.isNotEmpty
                          ? data.values.first.toString()
                          : 'Could not change password.';
                    });
                  }
                },
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _OptionRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  const _OptionRow({
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
        duration: const Duration(milliseconds: 180),
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
        decoration: BoxDecoration(
          color: selected ? t.accent : Colors.transparent,
          borderRadius: BorderRadius.circular(14),
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
                size: 18,
                color: t.onAccent,
              ),
          ],
        ),
      ),
    );
  }
}
