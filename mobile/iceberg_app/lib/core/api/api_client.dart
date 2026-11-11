import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

const String kBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'https://app.iceberglc.com/api/v1',
);

/// A 403 the server sends while the user's password is still temporary.
bool isPasswordChangeRequired(Response<dynamic>? res) {
  final data = res?.data;
  return res?.statusCode == 403 &&
      data is Map &&
      data['code'] == 'password_change_required';
}

class ApiClient {
  ApiClient._();
  static ApiClient? _instance;
  static ApiClient get instance => _instance ??= ApiClient._();

  // EncryptedSharedPreferences avoids the Android Keystore lock-up that occurs
  // on MIUI/EMUI/OneUI when the Keystore provider is busy or uninitialized —
  // matches the backend used in AuthNotifier so token reads stay consistent.
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  // In-memory copies so requests stay authenticated even if a per-request
  // secure-storage read is slow/flaky (notably on web, where the storage
  // backend is best-effort). Storage remains the source of truth across
  // app launches.
  String? _access;
  String? _refresh;

  // Completer that resolves once loadTokens() has run.  Any request fired
  // before tokens finish loading will wait here instead of going out
  // unauthenticated and getting an unnecessary 401.
  final _tokensLoaded = Completer<void>();

  // Invoked when a 401 cannot be refreshed (refresh token expired/blacklisted)
  // so the app can drop to the login screen instead of looping on errors.
  void Function()? onSessionExpired;

  // Invoked when the server refuses a call because the user still has a
  // temporary password (PL.1), so the app can show the password screen.
  void Function()? onPasswordChangeRequired;

  late final Dio dio = _buildDio();

  Dio _buildDio() {
    final d = Dio(
      BaseOptions(
        baseUrl: kBaseUrl,
        // Generous timeouts for slow first-connect on weak mobile networks
        // (our user base is on high-latency mobile data) through Cloudflare.
        connectTimeout: const Duration(seconds: 30),
        receiveTimeout: const Duration(seconds: 30),
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      ),
    );

    d.interceptors.add(
      InterceptorsWrapper(
        onRequest: (options, handler) async {
          // Wait for token loading to complete before attaching auth header.
          // Timeout prevents hanging forever if loadTokens() was never called.
          if (!_tokensLoaded.isCompleted) {
            await _tokensLoaded.future.timeout(
              const Duration(seconds: 6),
              onTimeout: () {},
            );
          }
          final token = _access;
          if (token != null && token.isNotEmpty) {
            options.headers['Authorization'] = 'Bearer $token';
          }
          handler.next(options);
        },
        onError: (error, handler) async {
          final path = error.requestOptions.path;
          final isAuthCall =
              path.contains('/auth/login') ||
              path.contains('/auth/token/refresh');

          if (error.response?.statusCode == 401 && !isAuthCall) {
            final refreshed = await _tryRefresh();
            if (refreshed) {
              // Retry the original request with the new access token.
              final opts = error.requestOptions;
              opts.headers['Authorization'] = 'Bearer $_access';
              try {
                final res = await dio.fetch(opts);
                return handler.resolve(res);
              } catch (_) {
                // fall through to error
              }
            } else {
              // Session is dead — clear it and let the app return to login.
              await clearTokens();
              onSessionExpired?.call();
            }
          }
          if (isPasswordChangeRequired(error.response)) {
            onPasswordChangeRequired?.call();
          }
          handler.next(error);
        },
      ),
    );

    return d;
  }

  // Single-flight refresh: concurrent 401s share one refresh attempt.
  Future<bool>? _refreshing;
  Future<bool> _tryRefresh() =>
      _refreshing ??= _doRefresh().whenComplete(() => _refreshing = null);

  Future<bool> _doRefresh() async {
    final refresh = _refresh ??= await _storage.read(key: 'refresh_token');
    if (refresh == null || refresh.isEmpty) return false;
    try {
      // A bare Dio avoids the auth interceptor (no Authorization header here).
      final res = await Dio(
        BaseOptions(baseUrl: kBaseUrl),
      ).post('/auth/token/refresh/', data: {'refresh': refresh});
      final data = res.data as Map<String, dynamic>;
      final newAccess = data['access'] as String?;
      // ROTATE_REFRESH_TOKENS is on server-side: a new refresh token is issued
      // and the old one is blacklisted. Persist it or the *next* refresh fails.
      final newRefresh = data['refresh'] as String?;
      if (newAccess != null) {
        await saveTokens(newAccess, newRefresh ?? refresh);
        return true;
      }
    } catch (_) {}
    return false;
  }

  /// Populate the in-memory cache from storage at app startup.
  /// Always completes _tokensLoaded so waiting requests are unblocked.
  Future<void> loadTokens() async {
    try {
      // Per-read timeouts ensure _tokensLoaded completes promptly even when the
      // storage backend is slow on first access. Without these, a slow read can
      // consume the auth interceptor's 6s budget, leaving too little time for
      // the TCP+TLS handshake on a slow network — surfacing as connectionError.
      _access = await _storage
          .read(key: 'access_token')
          .timeout(const Duration(seconds: 5));
      _refresh = await _storage
          .read(key: 'refresh_token')
          .timeout(const Duration(seconds: 5));
    } catch (_) {
      // Storage timed out or errored — continue with null tokens; the user
      // will simply be asked to log in again.
    } finally {
      if (!_tokensLoaded.isCompleted) _tokensLoaded.complete();
    }
  }

  Future<void> saveTokens(String access, String refresh) async {
    _access = access;
    _refresh = refresh;
    await _storage.write(key: 'access_token', value: access);
    await _storage.write(key: 'refresh_token', value: refresh);
  }

  Future<void> clearTokens() async {
    _access = null;
    _refresh = null;
    await _storage.deleteAll();
    await _clearUserCaches();
  }

  /// Drop data that belongs to the signed-out user (cached dashboard JSON,
  /// per-word vocab progress) so the next person on this device never sees
  /// it. Runs on explicit logout and when a dead session is cleared.
  /// Device-level UI preferences (`ice_*`: theme, language…) are kept.
  Future<void> _clearUserCaches() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      for (final key in prefs.getKeys().toList()) {
        if (key.startsWith('cache_') || key.startsWith('vocab_known_')) {
          await prefs.remove(key);
        }
      }
    } catch (_) {}
  }

  Future<String?> get accessToken async =>
      _access ??= await _storage.read(key: 'access_token');
}
