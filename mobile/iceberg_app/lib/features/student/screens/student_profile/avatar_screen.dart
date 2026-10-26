part of '../student_profile_screen.dart';

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
