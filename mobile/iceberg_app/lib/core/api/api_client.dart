import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const String kBaseUrl = String.fromEnvironment(
  'API_BASE_URL',
  defaultValue: 'https://app.iceberglc.com/api/v1',
);

class ApiClient {
  ApiClient._();
  static ApiClient? _instance;
  static ApiClient get instance => _instance ??= ApiClient._();

  // EncryptedSharedPreferences avoids the Android Keystore lock-up that occurs
  // on MIUI/EMUI/OneUI when the Keystore provider is busy or uninitialized —
  // which caused _tokensLoaded to never complete and login requests to time out.
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

  late final Dio dio = _buildDio();

  Dio _buildDio() {
    final d = Dio(
      BaseOptions(
        baseUrl: kBaseUrl,
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
              path.contains('/auth/login') || path.contains('/auth/token/refresh');

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
      final res = await Dio(BaseOptions(baseUrl: kBaseUrl)).post(
        '/auth/token/refresh/',
        data: {'refresh': refresh},
      );
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
      // Individual timeouts ensure _tokensLoaded is completed promptly even
      // when the underlying storage (Keystore or EncryptedSharedPrefs) is slow
      // on first access. Without these, the auth interceptor could block login
      // requests for the full 6s fallback timeout.
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
  }

  Future<String?> get accessToken async => _access ??= await _storage.read(key: 'access_token');
}
