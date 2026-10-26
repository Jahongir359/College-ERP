part of '../student_profile_screen.dart';

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
