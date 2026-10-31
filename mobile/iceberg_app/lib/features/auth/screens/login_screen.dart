import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/auth/auth_state.dart';
import '../../../core/i18n/strings.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../core/theme/brand.dart';
import '../../../core/theme/brand_provider.dart';

/// ICEBERG login — dark hero in the brand picked on `/choose` (navy for the
/// Study Center, maroon for the School), shared by all roles (the API routes
/// each role to its own shell after sign-in).
class LoginScreen extends ConsumerStatefulWidget {
  const LoginScreen({super.key});
  @override
  ConsumerState<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends ConsumerState<LoginScreen> {
  final _formKey = GlobalKey<FormState>();
  final _idCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  bool _loading = false;
  bool _obscure = true;
  String? _error;

  // Login renders before any role/theme is known — use the dark palette of
  // the brand picked on /choose.
  late IceTokens t;

  @override
  void dispose() {
    _idCtrl.dispose();
    _passCtrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    HapticFeedback.lightImpact();
    setState(() {
      _loading = true;
      _error = null;
    });
    final err = await ref
        .read(authProvider.notifier)
        .login(_idCtrl.text.trim(), _passCtrl.text);
    if (mounted) {
      setState(() {
        _loading = false;
        _error = err;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = ref.watch(stringsProvider);
    final brand = ref.watch(brandProvider);
    t = IceTokens.dark(brand: brand);
    return Scaffold(
      backgroundColor: t.bg,
      body: Container(
        decoration: BoxDecoration(gradient: t.heroGradient),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    // ── Logo + wordmark ─────────────────────────────────────
                    Container(
                          width: 96,
                          height: 96,
                          decoration: BoxDecoration(
                            color: Colors.white.withValues(alpha: 0.06),
                            borderRadius: BorderRadius.circular(28),
                            border: Border.all(
                              color: t.accent.withValues(alpha: 0.4),
                              width: 1.5,
                            ),
                          ),
                          alignment: Alignment.center,
                          child: IceBrandLogo(
                            size: 60,
                            radius: 16,
                            errorBuilder: (_, __, ___) => Text(
                              'ICE',
                              style: TextStyle(
                                color: t.accent,
                                fontSize: 26,
                                fontWeight: FontWeight.w900,
                                letterSpacing: 2,
                              ),
                            ),
                          ),
                        )
                        .animate()
                        .scale(duration: 500.ms, curve: Curves.easeOutBack)
                        .fadeIn(duration: 300.ms),
                    const SizedBox(height: 18),
                    if (brand.isSchool)
                      Image.asset(
                        'assets/images/brand/school/logo-h-white.png',
                        height: 44,
                        semanticLabel: brand.appTitle,
                        errorBuilder: (_, __, ___) => _wordmark(),
                      )
                    else
                      _wordmark(),
                    const SizedBox(height: 30),

                    // ── Card ────────────────────────────────────────────────
                    Container(
                          padding: const EdgeInsets.fromLTRB(24, 28, 24, 26),
                          decoration: BoxDecoration(
                            color: t.card.withValues(alpha: 0.85),
                            borderRadius: BorderRadius.circular(24),
                            border: Border.all(color: t.stroke),
                            boxShadow: [
                              BoxShadow(
                                color: Colors.black.withValues(alpha: 0.3),
                                blurRadius: 30,
                                offset: const Offset(0, 14),
                              ),
                            ],
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                s('Welcome'),
                                style: TextStyle(
                                  fontSize: 23,
                                  fontWeight: FontWeight.w800,
                                  color: t.textHi,
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(
                                s('Please sign in to your account'),
                                style: TextStyle(
                                  fontSize: 14,
                                  fontWeight: FontWeight.w500,
                                  color: t.textMid,
                                ),
                              ),
                              const SizedBox(height: 24),
                              _form(s),
                            ],
                          ),
                        )
                        .animate(delay: 150.ms)
                        .slideY(
                          begin: 0.08,
                          duration: 450.ms,
                          curve: Curves.easeOutCubic,
                        )
                        .fadeIn(duration: 350.ms),
                    const SizedBox(height: 18),
                    _changeBrand(s, brand),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _wordmark() => Text(
    'ICEBERG',
    style: TextStyle(
      fontSize: 22,
      fontWeight: FontWeight.w800,
      letterSpacing: 6,
      color: t.mint,
    ),
  );

  /// "Iceberg School · Choose another" — back to /choose.
  Widget _changeBrand(S s, IceBrand brand) {
    return Wrap(
      alignment: WrapAlignment.center,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        Text(
          '${brand.appTitle} · ',
          style: TextStyle(fontSize: 13.5, color: t.textMid),
        ),
        TextButton(
          key: const ValueKey('login-change-brand'),
          onPressed: _loading ? null : () => context.go('/choose'),
          style: TextButton.styleFrom(
            foregroundColor: t.textHi,
            padding: const EdgeInsets.symmetric(horizontal: 4),
            minimumSize: const Size(0, 40),
            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
          ),
          child: Text(
            s('Choose another'),
            style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w800),
          ),
        ),
      ],
    );
  }

  InputDecoration _dec({
    required String label,
    required IconData icon,
    Widget? suffixIcon,
  }) {
    OutlineInputBorder b(Color color, [double w = 1.4]) => OutlineInputBorder(
      borderRadius: BorderRadius.circular(14),
      borderSide: BorderSide(color: color, width: w),
    );
    return InputDecoration(
      labelText: label,
      labelStyle: TextStyle(color: t.textMid, fontSize: 14),
      filled: true,
      fillColor: t.inset,
      border: b(t.stroke),
      enabledBorder: b(t.stroke),
      focusedBorder: b(t.accent, 1.8),
      errorBorder: b(t.coral),
      focusedErrorBorder: b(t.coral, 1.8),
      prefixIcon: Padding(
        padding: const EdgeInsets.only(left: 12, right: 8),
        child: Icon(icon, size: 20, color: t.textMid),
      ),
      prefixIconConstraints: const BoxConstraints(minWidth: 0, minHeight: 0),
      suffixIcon: suffixIcon,
      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 16),
    );
  }

  Widget _form(S s) {
    return Form(
      key: _formKey,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          TextFormField(
            controller: _idCtrl,
            keyboardType: TextInputType.emailAddress,
            textInputAction: TextInputAction.next,
            style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
            decoration: _dec(
              label: s('ID number or email'),
              icon: Icons.person_outline_rounded,
            ),
            validator: (v) =>
                (v == null || v.trim().isEmpty) ? s('Required') : null,
          ),
          const SizedBox(height: 14),
          TextFormField(
            controller: _passCtrl,
            obscureText: _obscure,
            textInputAction: TextInputAction.done,
            onFieldSubmitted: (_) => _submit(),
            style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
            decoration: _dec(
              label: s('Password'),
              icon: Icons.lock_outline_rounded,
              suffixIcon: IconButton(
                icon: Icon(
                  _obscure
                      ? Icons.visibility_off_outlined
                      : Icons.visibility_outlined,
                  color: t.textMid,
                  size: 20,
                ),
                onPressed: () => setState(() => _obscure = !_obscure),
              ),
            ),
            validator: (v) => (v == null || v.isEmpty) ? s('Required') : null,
          ),
          AnimatedSize(
            duration: 300.ms,
            child: _error == null
                ? const SizedBox(height: 20)
                : Container(
                        margin: const EdgeInsets.only(top: 14),
                        padding: const EdgeInsets.symmetric(
                          horizontal: 14,
                          vertical: 12,
                        ),
                        decoration: BoxDecoration(
                          color: t.coral.withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: t.coral.withValues(alpha: 0.4),
                          ),
                        ),
                        child: Row(
                          children: [
                            Icon(
                              Icons.error_outline_rounded,
                              color: t.coral,
                              size: 16,
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                _error!,
                                style: TextStyle(color: t.coral, fontSize: 13),
                              ),
                            ),
                          ],
                        ),
                      )
                      .animate()
                      .shake(duration: 400.ms, hz: 3)
                      .fadeIn(duration: 200.ms),
          ),
          SizedBox(
            width: double.infinity,
            height: 54,
            child: FilledButton(
              onPressed: _loading ? null : _submit,
              style: FilledButton.styleFrom(
                backgroundColor: t.accent,
                foregroundColor: t.onAccent,
                disabledBackgroundColor: t.accent.withValues(alpha: 0.5),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                ),
              ),
              child: _loading
                  ? SizedBox(
                      width: 22,
                      height: 22,
                      child: CircularProgressIndicator(
                        strokeWidth: 2.5,
                        color: t.onAccent,
                      ),
                    )
                  : Text(
                      s('LOGIN'),
                      style: const TextStyle(
                        fontSize: 15,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.5,
                      ),
                    ),
            ),
          ),
          const SizedBox(height: 16),
          Center(
            child: Text(
              s('Contact your administrator to reset your password.'),
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 12, color: t.textLow),
            ),
          ),
        ],
      ),
    );
  }
}
