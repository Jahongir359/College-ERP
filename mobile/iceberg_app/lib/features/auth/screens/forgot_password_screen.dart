import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/i18n/strings.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/brand.dart';
import '../../../core/theme/ice_tokens.dart';
import '../password_reset_api.dart';
import 'change_password_screen.dart';

/// "Forgot password?" (PL.2, D13): a parent enters their login ID and phone,
/// gets a code by SMS and chooses a new password. Teachers and students are
/// told to ask the school office.
///
/// Step one always moves on to step two, whatever was typed: the server does
/// not say whether the login ID and phone matched, and neither does the app.
class ForgotPasswordScreen extends ConsumerStatefulWidget {
  const ForgotPasswordScreen({super.key});

  @override
  ConsumerState<ForgotPasswordScreen> createState() =>
      _ForgotPasswordScreenState();
}

class _ForgotPasswordScreenState extends ConsumerState<ForgotPasswordScreen> {
  final _requestKey = GlobalKey<FormState>();
  final _confirmKey = GlobalKey<FormState>();
  final _login = TextEditingController();
  final _phone = TextEditingController();
  final _code = TextEditingController();
  final _new = TextEditingController();
  final _confirm = TextEditingController();

  bool _codeStep = false;
  bool _busy = false;
  bool _obscure = true;
  PasswordResetError? _error;

  @override
  void dispose() {
    _login.dispose();
    _phone.dispose();
    _code.dispose();
    _new.dispose();
    _confirm.dispose();
    super.dispose();
  }

  Future<void> _sendCode() async {
    if (!_requestKey.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    final err = await ref
        .read(passwordResetApiProvider)
        .requestCode(loginId: _login.text.trim(), phone: _phone.text.trim());
    if (!mounted) return;
    setState(() {
      _busy = false;
      _error = err;
      if (err == null) {
        _codeStep = true;
        _code.clear();
      }
    });
  }

  Future<void> _savePassword() async {
    if (!_confirmKey.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    final err = await ref
        .read(passwordResetApiProvider)
        .confirm(
          loginId: _login.text.trim(),
          code: _code.text.trim(),
          newPassword: _new.text,
        );
    if (!mounted) return;
    if (err != null) {
      setState(() {
        _busy = false;
        _error = err;
      });
      return;
    }
    final s = ref.read(stringsProvider);
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(s('Password changed. Sign in with the new password.')),
      ),
    );
    context.go('/login');
  }

  void _backToRequest() {
    setState(() {
      _codeStep = false;
      _error = null;
    });
  }

  String _errorText(S s, PasswordResetError e) {
    switch (e.kind) {
      case PasswordResetFailure.tooMany:
        return s('Too many tries. Please try again later.');
      case PasswordResetFailure.invalidCode:
        return s('The code is wrong or no longer works. Ask for a new one.');
      case PasswordResetFailure.password:
        return e.message ?? s('Choose a stronger password.');
      case PasswordResetFailure.other:
        return s('Something went wrong. Check your internet and try again.');
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = ref.watch(stringsProvider);
    final t = context.ice;

    return PopScope(
      // Back on the code step returns to the first step, not to the login.
      canPop: !_codeStep,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop && !_busy) _backToRequest();
      },
      child: Scaffold(
        backgroundColor: t.bg,
        body: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    IceBrandLogo(size: 52, radius: 14),
                    const SizedBox(height: 24),
                    if (_codeStep) _codeForm(s, t) else _requestForm(s, t),
                    const SizedBox(height: 10),
                    Center(
                      child: TextButton(
                        key: const ValueKey('reset-back'),
                        onPressed: _busy ? null : () => context.go('/login'),
                        child: Text(
                          s('Back to sign in'),
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
    );
  }

  Widget _requestForm(S s, IceTokens t) {
    return Form(
      key: _requestKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _title(s('Forgot your password?'), t),
          const SizedBox(height: 8),
          _body(
            s(
              'Parents: enter your login ID and the phone number the school has for you. We will send a code by SMS.',
            ),
            t,
          ),
          const SizedBox(height: 24),
          TextFormField(
            key: const ValueKey('reset-login'),
            controller: _login,
            textInputAction: TextInputAction.next,
            autocorrect: false,
            style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
            decoration: InputDecoration(labelText: s('Login ID')),
            validator: (v) =>
                (v == null || v.trim().isEmpty) ? s('Required') : null,
          ),
          const SizedBox(height: 14),
          TextFormField(
            key: const ValueKey('reset-phone'),
            controller: _phone,
            keyboardType: TextInputType.phone,
            textInputAction: TextInputAction.done,
            onFieldSubmitted: (_) => _sendCode(),
            inputFormatters: [
              FilteringTextInputFormatter.allow(RegExp(r'[0-9+\-() ]')),
            ],
            style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
            decoration: InputDecoration(
              labelText: s('Phone number'),
              hintText: '+998 90 123 45 67',
            ),
            validator: (v) {
              final digits = (v ?? '').replaceAll(RegExp(r'\D'), '');
              if (digits.isEmpty) return s('Required');
              if (digits.length < 9) return s('Enter the full phone number.');
              return null;
            },
          ),
          _errorBox(s, t),
          const SizedBox(height: 22),
          _button(
            key: const ValueKey('reset-send'),
            label: s('Send code'),
            onPressed: _sendCode,
            t: t,
          ),
          const SizedBox(height: 18),
          _note(
            s(
              'Teachers and students: ask the school office for a new password.',
            ),
            t,
          ),
        ],
      ),
    );
  }

  Widget _codeForm(S s, IceTokens t) {
    return Form(
      key: _confirmKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _title(s('Enter the code'), t),
          const SizedBox(height: 8),
          _body(
            s(
              'If the login ID and phone number match, a 6-digit code was sent by SMS. It works for 10 minutes.',
            ),
            t,
          ),
          const SizedBox(height: 24),
          TextFormField(
            key: const ValueKey('reset-code'),
            controller: _code,
            keyboardType: TextInputType.number,
            textInputAction: TextInputAction.next,
            autofillHints: const [AutofillHints.oneTimeCode],
            inputFormatters: [
              FilteringTextInputFormatter.digitsOnly,
              LengthLimitingTextInputFormatter(6),
            ],
            style: TextStyle(
              color: t.textHi,
              fontWeight: FontWeight.w700,
              fontSize: 20,
              letterSpacing: 6,
            ),
            decoration: InputDecoration(labelText: s('Code from the SMS')),
            validator: (v) =>
                (v ?? '').trim().length == 6 ? null : s('Enter the 6 digits.'),
          ),
          const SizedBox(height: 14),
          _passwordField(
            key: const ValueKey('reset-new'),
            ctrl: _new,
            label: s('New Password'),
            helper: s('At least 8 characters'),
            t: t,
            validator: (v) {
              if (v == null || v.isEmpty) return s('Required');
              if (v.length < ChangePasswordScreen.minLength) {
                return s('At least 8 characters');
              }
              return null;
            },
          ),
          const SizedBox(height: 14),
          _passwordField(
            key: const ValueKey('reset-confirm'),
            ctrl: _confirm,
            label: s('Confirm Password'),
            t: t,
            validator: (v) =>
                v != _new.text ? s('Passwords do not match') : null,
            onSubmitted: (_) => _savePassword(),
          ),
          _errorBox(s, t),
          const SizedBox(height: 22),
          _button(
            key: const ValueKey('reset-save'),
            label: s('Save new password'),
            onPressed: _savePassword,
            t: t,
          ),
          const SizedBox(height: 6),
          Center(
            child: TextButton(
              key: const ValueKey('reset-again'),
              onPressed: _busy ? null : _backToRequest,
              child: Text(
                s('Send the code again'),
                style: TextStyle(
                  color: t.isDark ? t.textHi : t.accentInk,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
          ),
          const SizedBox(height: 8),
          _note(s('No SMS after a few minutes? Ask the school office.'), t),
        ],
      ),
    );
  }

  Widget _title(String text, IceTokens t) => Text(
    text,
    style: TextStyle(
      fontSize: 26,
      fontWeight: FontWeight.w800,
      color: t.textHi,
    ),
  );

  Widget _body(String text, IceTokens t) => Text(
    text,
    style: TextStyle(fontSize: 15, height: 1.45, color: t.textMid),
  );

  Widget _note(String text, IceTokens t) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      color: t.inset,
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: t.stroke),
    ),
    child: Text(
      text,
      style: TextStyle(fontSize: 13.5, height: 1.4, color: t.textMid),
    ),
  );

  Widget _errorBox(S s, IceTokens t) {
    final error = _error;
    if (error == null) return const SizedBox.shrink();
    return Container(
      key: const ValueKey('reset-error'),
      width: double.infinity,
      margin: const EdgeInsets.only(top: 14),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: t.coralSoft,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Text(
        _errorText(s, error),
        style: TextStyle(color: t.coral, fontSize: 13.5),
      ),
    );
  }

  Widget _button({
    required Key key,
    required String label,
    required VoidCallback onPressed,
    required IceTokens t,
  }) {
    return SizedBox(
      width: double.infinity,
      height: 54,
      child: FilledButton(
        key: key,
        onPressed: _busy ? null : onPressed,
        style: FilledButton.styleFrom(
          backgroundColor: t.accent,
          foregroundColor: t.onAccent,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(14),
          ),
        ),
        child: _busy
            ? SizedBox(
                width: 22,
                height: 22,
                child: CircularProgressIndicator(
                  strokeWidth: 2.5,
                  color: t.onAccent,
                ),
              )
            : Text(
                label,
                style: const TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.w800,
                ),
              ),
      ),
    );
  }

  Widget _passwordField({
    required Key key,
    required TextEditingController ctrl,
    required String label,
    required IceTokens t,
    String? helper,
    FormFieldValidator<String>? validator,
    ValueChanged<String>? onSubmitted,
  }) {
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
