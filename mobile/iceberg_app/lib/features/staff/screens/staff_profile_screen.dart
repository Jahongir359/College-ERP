import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:image_picker/image_picker.dart';

import '../../../core/api/api_client.dart';
import '../../../core/auth/auth_state.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';

// ─── Teacher avatar selection ─────────────────────────────────────────────────
class StaffAvatarScreen extends ConsumerStatefulWidget {
  const StaffAvatarScreen({super.key});

  @override
  ConsumerState<StaffAvatarScreen> createState() => _StaffAvatarScreenState();
}

class _StaffAvatarScreenState extends ConsumerState<StaffAvatarScreen> {
  static const _emojis = [
    '👨‍🏫', '👩‍🏫', '🧑‍💼', '👔', '🎓', '📋', '🏆', '⭐',
    '🦁', '🦊', '🐼', '🦉', '🐯', '🐸', '🐙', '🦄',
    '🚀', '🌟', '🔥', '💡', '🎯', '📚', '✏️', '🎨',
  ];

  String? _selected;
  bool _busy = false;
  int _tab = 0; // 0 = Emoji, 1 = Upload

  Future<void> _saveEmoji() async {
    final emoji = _selected;
    if (emoji == null) return;
    setState(() => _busy = true);
    try {
      final res = await ApiClient.instance.dio.patch(
        '/me/',
        data: {'avatar': emoji},
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
    final user = ref.watch(authProvider).user;
    final s = ref.watch(stringsProvider);

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
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
        children: [
          // ── Avatar preview ────────────────────────────────────────────
          Center(
            child: Container(
              padding: const EdgeInsets.all(4),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(color: t.accent, width: 2.5),
              ),
              child: _IceUserAvatarInline(
                radius: 48,
                photoUrl: user?.profilePicUrl,
                emoji: (_tab == 0 && _selected != null)
                    ? _selected
                    : (user?.avatar.isNotEmpty == true ? user!.avatar : null),
                fallbackText: user?.firstName.isNotEmpty == true
                    ? user!.firstName[0].toUpperCase()
                    : 'T',
                bgColor: t.inset,
              ),
            ),
          ),
          const SizedBox(height: 24),

          // ── Tabs ──────────────────────────────────────────────────────
          _ChipTabs(
            tabs: [s('Emoji'), s('Upload')],
            index: _tab,
            onChanged: (i) => setState(() => _tab = i),
          ),
          const SizedBox(height: 20),

          if (_tab == 0) ...[
            // ── Emoji grid ────────────────────────────────────────────
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
                        width: isSelected ? 2 : 1,
                      ),
                    ),
                    alignment: Alignment.center,
                    child: Text(e, style: const TextStyle(fontSize: 28)),
                  ),
                );
              }).toList(),
            ),
            const SizedBox(height: 120), // Space for sticky button
          ] else ...[
            // ── Photo upload ──────────────────────────────────────────
            Container(
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                color: t.card,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: t.stroke),
              ),
              child: Column(
                children: [
                  Icon(Icons.photo_library_outlined, size: 52, color: t.textLow),
                  const SizedBox(height: 16),
                  Text(
                    s('Choose Photo'),
                    style: TextStyle(
                      fontSize: 17,
                      fontWeight: FontWeight.w700,
                      color: t.textHi,
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Select a photo from your gallery to use as your profile picture.',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 13, color: t.textMid, height: 1.5),
                  ),
                  const SizedBox(height: 24),
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
      // ── Sticky save button (emoji tab only) ───────────────────────────────
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
                      disabledBackgroundColor: t.accent.withValues(alpha: 0.4),
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
                            s('Save'),
                            style: const TextStyle(
                                fontWeight: FontWeight.w700,
                                fontSize: 16,
                                fontFamily: 'Inter'),
                          ),
                  ),
                ),
              ),
            )
          : null,
    );
  }
}

// Inline versions of shared widgets to avoid import cycles in staff_profile
class _IceUserAvatarInline extends StatelessWidget {
  final String? photoUrl;
  final String? emoji;
  final String fallbackText;
  final double radius;
  final Color? bgColor;

  const _IceUserAvatarInline({
    this.photoUrl,
    this.emoji,
    required this.fallbackText,
    this.radius = 22,
    this.bgColor,
  });

  static String? _resolveUrl(String? raw, BuildContext context) {
    if (raw == null || raw.isEmpty) return raw;
    if (raw.startsWith('http')) return raw;
    final base = Uri.tryParse(kBaseUrl);
    if (base == null) return raw;
    return '${base.scheme}://${base.host}$raw';
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final bg = bgColor ?? t.accentSoft;
    final resolvedUrl = _resolveUrl(photoUrl, context);
    final hasPhoto = resolvedUrl != null && resolvedUrl.isNotEmpty;

    Widget fallback() {
      if (emoji != null && emoji!.isNotEmpty) {
        return Text(emoji!, style: TextStyle(fontSize: radius * 0.9));
      }
      return Text(
        fallbackText,
        style: TextStyle(
          fontSize: radius * 0.65,
          fontWeight: FontWeight.w800,
          color: t.accent,
        ),
      );
    }

    if (hasPhoto) {
      final dpr = MediaQuery.devicePixelRatioOf(context).ceil();
      final px = (radius * 2 * dpr).ceil();
      return CircleAvatar(
        radius: radius,
        backgroundColor: bg,
        child: ClipOval(
          child: Image.network(
            resolvedUrl,
            width: radius * 2,
            height: radius * 2,
            fit: BoxFit.cover,
            cacheWidth: px,
            cacheHeight: px,
            errorBuilder: (_, __, ___) => fallback(),
          ),
        ),
      );
    }
    return CircleAvatar(
      radius: radius,
      backgroundColor: bg,
      child: fallback(),
    );
  }
}

class _ChipTabs extends StatelessWidget {
  final List<String> tabs;
  final int index;
  final void Function(int) onChanged;

  const _ChipTabs(
      {required this.tabs, required this.index, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Row(
      children: List.generate(tabs.length, (i) {
        final active = i == index;
        return Padding(
          padding: EdgeInsets.only(right: i < tabs.length - 1 ? 8 : 0),
          child: GestureDetector(
            onTap: () => onChanged(i),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 180),
              padding:
                  const EdgeInsets.symmetric(horizontal: 20, vertical: 10),
              decoration: BoxDecoration(
                color: active ? t.accent : t.card,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: active ? t.accent : t.stroke),
              ),
              child: Text(
                tabs[i],
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w700,
                  color: active ? t.onAccent : t.textMid,
                ),
              ),
            ),
          ),
        );
      }),
    );
  }
}
