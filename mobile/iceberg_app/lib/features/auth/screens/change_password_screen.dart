import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/auth/auth_state.dart';
import '../../../core/i18n/strings.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/brand.dart';
import '../../../core/theme/ice_tokens.dart';

/// "Choose your password" (PL.1): the only screen a user with a temporary
/// password sees. It cannot be skipped — the router sends every other path
/// here and back is blocked — but the user can log out.
class ChangePasswordScreen extends ConsumerStatefulWidget {
  const ChangePasswordScreen({super.key});

  /// The server's minimum (Django validators may ask for more).
  static const minLength = 8;

  @override
  ConsumerState<ChangePasswordScreen> createState() =>
      _ChangePasswordScreenState();
}

class _ChangePasswordScreenState extends ConsumerState<ChangePasswordScreen> {
  final _formKey = GlobalKey<FormState>();
  final _old = TextEditingController();
  final _new = TextEditingController();
  final _confirm = TextEditingController();
  bool _saving = false;
  bool _obscure = true;
  ChangePasswordError? _error;

  @override
  void dispose() {
    _old.dispose();
    _new.dispose();
    _confirm.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    // On success the router leaves this screen by itself.
    final err = await ref
        .read(authProvider.notifier)
        .changePassword(oldPassword: _old.text, newPassword: _new.text);
    if (mounted) {
      setState(() {
        _saving = false;
        _error = err;
      });
    }
  }

  String _errorText(S s, ChangePasswordError e) {
    if (e.field == 'old_password') {
      return s('The temporary password is not correct.');
    }
    if (e.message != null) return e.message!;
    return s('Could not save. Check your internet and try again.');
  }

  @override
  Widget build(BuildContext context) {
    final s = ref.watch(stringsProvider);
    final t = context.ice;

    return PopScope(
      canPop: false,
      child: Scaffold(
        backgroundColor: t.bg,
        body: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Form(
                  key: _formKey,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      IceBrandLogo(size: 52, radius: 14),
                      const SizedBox(height: 24),
                      Text(
                        s('Choose your password'),
                        style: TextStyle(
                          fontSize: 26,
                          fontWeight: FontWeight.w800,
                          color: t.textHi,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        s(
                          'You signed in with a temporary password. Choose your own to continue.',
                        ),
                        style: TextStyle(
                          fontSize: 15,
                          height: 1.45,
                          color: t.textMid,
                        ),
                      ),
                      const SizedBox(height: 24),
                      _field(
                        key: const ValueKey('pw-old'),
                        ctrl: _old,
                        label: s('Temporary password'),
                        validator: (v) =>
                            (v == null || v.isEmpty) ? s('Required') : null,
                      ),
                      const SizedBox(height: 14),
                      _field(
                        key: const ValueKey('pw-new'),
                        ctrl: _new,
                        label: s('New Password'),
                        helper: s('At least 8 characters'),
                        validator: (v) {
                          if (v == null || v.isEmpty) return s('Required');
                          if (v.length < ChangePasswordScreen.minLength) {
                            return s('At least 8 characters');
                          }
                          if (v == _old.text) {
                            return s(
                              'Use a different password from the temporary one.',
                            );
                          }
                          return null;
                        },
                      ),
                      const SizedBox(height: 14),
                      _field(
                        key: const ValueKey('pw-confirm'),
                        ctrl: _confirm,
                        label: s('Confirm Password'),
                        validator: (v) =>
                            v != _new.text ? s('Passwords do not match') : null,
                        onSubmitted: (_) => _submit(),
                      ),
                      if (_error != null) ...[
                        const SizedBox(height: 14),
                        Container(
                          key: const ValueKey('pw-error'),
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: t.coralSoft,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: Text(
                            _errorText(s, _error!),
                            style: TextStyle(color: t.coral, fontSize: 13.5),
                          ),
                        ),
                      ],
                      const SizedBox(height: 22),
                      SizedBox(
                        width: double.infinity,
                        height: 54,
                        child: FilledButton(
                          key: const ValueKey('pw-submit'),
                          onPressed: _saving ? null : _submit,
                          style: FilledButton.styleFrom(
                            backgroundColor: t.accent,
                            foregroundColor: t.onAccent,
                            shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(14),
                            ),
                          ),
                          child: _saving
                              ? SizedBox(
                                  width: 22,
                                  height: 22,
                                  child: CircularProgressIndicator(
                                    strokeWidth: 2.5,
                                    color: t.onAccent,
                                  ),
                                )
                              : Text(
                                  s('Save and continue'),
                                  style: const TextStyle(
                                    fontSize: 15,
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                        ),
                      ),
                      const SizedBox(height: 10),
                      Center(
                        child: TextButton(
                          key: const ValueKey('pw-logout'),
                          onPressed: _saving
                              ? null
                              : () => ref.read(authProvider.notifier).logout(),
                          child: Text(
                            s('Log out'),
                            style: TextStyle(color: t.textMid),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _field({
    required Key key,
    required TextEditingController ctrl,
    required String label,
    String? helper,
    FormFieldValidator<String>? validator,
    ValueChanged<String>? onSubmitted,
  }) {
    final t = context.ice;
    return TextFormField(
      key: key,
      controller: ctrl,
      obscureText: _obscure,
      validator: validator,
      onFieldSubmitted: onSubmitted,
      textInputAction: onSubmitted == null
          ? TextInputAction.next
          : TextInputAction.done,
      style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
      decoration: InputDecoration(
        labelText: label,
        helperText: helper,
        suffixIcon: IconButton(
          onPressed: () => setState(() => _obscure = !_obscure),
          icon: Icon(
            _obscure
                ? Icons.visibility_outlined
                : Icons.visibility_off_outlined,
            size: 20,
            color: t.textLow,
          ),
        ),
      ),
    );
  }
}
