import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import '../api/api_client.dart';

// ─── User model ──────────────────────────────────────────────────────────────
class IceUser {
  final int id;
  final String email;
  final String loginId;
  final String firstName;
  final String lastName;
  final String userType; // "1" admin, "2" staff, "3" student
  final String? profilePicUrl;
  final String avatar; // emoji avatar ('' when unset)
  final Map<String, dynamic>? roleProfile;
  final String brand; // "center" or "school" — server-decided, see IceBrand
  // Signed in with a temporary password (PL.1): the app shows only
  // /change-password until the user picks their own.
  final bool mustChangePassword;

  const IceUser({
    required this.id,
    required this.email,
    required this.loginId,
    required this.firstName,
    required this.lastName,
    required this.userType,
    this.profilePicUrl,
    this.avatar = '',
    this.roleProfile,
    this.brand = 'center',
    this.mustChangePassword = false,
  });

  String get fullName => '$firstName $lastName'.trim();
  bool get isAdmin => userType == '1';
  bool get isStaff => userType == '2';
  bool get isStudent => userType == '3';
  bool get isParent => userType == '4';
  bool get isSuperAdmin => isAdmin && (roleProfile?['is_super_admin'] == true);
  List<int> get branchIds =>
      isAdmin ? ((roleProfile?['branch_ids'] as List?)?.cast<int>() ?? []) : [];

  factory IceUser.fromJson(Map<String, dynamic> j) => IceUser(
    id: j['id'],
    email: j['email'] ?? '',
    loginId: j['login_id'] ?? '',
    firstName: j['first_name'] ?? '',
    lastName: j['last_name'] ?? '',
    userType: j['user_type'].toString(),
    profilePicUrl: j['profile_pic_url'],
    avatar: j['avatar'] ?? '',
    roleProfile: j['role_profile'],
    // Older servers and cached users have no brand → Learning Center.
    brand: j['brand'] ?? 'center',
    mustChangePassword: j['must_change_password'] == true,
  );

  Map<String, dynamic> toJson() => {
    'id': id,
    'email': email,
    'login_id': loginId,
    'first_name': firstName,
    'last_name': lastName,
    'user_type': userType,
    'profile_pic_url': profilePicUrl,
    'avatar': avatar,
    'role_profile': roleProfile,
    'brand': brand,
    'must_change_password': mustChangePassword,
  };
}

// ─── Auth state ───────────────────────────────────────────────────────────────
enum AuthStatus { loading, authenticated, unauthenticated }

class AuthState {
  final AuthStatus status;
  final IceUser? user;
  final String? error;

  const AuthState({required this.status, this.user, this.error});

  factory AuthState.loading() => const AuthState(status: AuthStatus.loading);
  factory AuthState.unauth([String? e]) =>
      AuthState(status: AuthStatus.unauthenticated, error: e);
  factory AuthState.auth(IceUser u) =>
      AuthState(status: AuthStatus.authenticated, user: u);
}

// ─── Provider ────────────────────────────────────────────────────────────────
class AuthNotifier extends StateNotifier<AuthState> {
  AuthNotifier() : _dio = ApiClient.instance.dio, super(AuthState.loading()) {
    // When a token refresh fails (expired/blacklisted), drop to login cleanly
    // instead of leaving the user stuck on an error screen.
    _api.onSessionExpired = _handleSessionExpired;
    // Any call refused because the password is still temporary (PL.1).
    _api.onPasswordChangeRequired = passwordChangeRequired;
    _init();
  }

  /// Starts in the given state without reading the saved session; requests
  /// go through [dio].
  @visibleForTesting
  AuthNotifier.withState(super.state, {required Dio dio}) : _dio = dio;

  final Dio _dio;

  // encryptedSharedPreferences avoids the raw Android Keystore path, which is
  // known to hang or fail on some Xiaomi/MIUI and Huawei/EMUI devices and could
  // otherwise strand the app on the splash screen at startup.
  final _storage = const FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  final _api = ApiClient.instance;

  Future<void> _init() async {
    // Run a minimum display timer in parallel with auth loading so the splash
    // animation always completes (~1.8 s) regardless of how fast storage reads
    // resolve. Both paths await minDisplay before transitioning.
    final minDisplay = Future<void>.delayed(const Duration(milliseconds: 1800));

    IceUser? user;
    try {
      // One hard cap around ALL secure-storage work. On some Android devices
      // (notably Xiaomi/MIUI and Huawei/EMUI, common in our user base) the
      // Keystore-backed storage can hang on first access — without an overall
      // timeout the app would sit on the splash forever and never reach login.
      user = await _loadCachedUser().timeout(const Duration(seconds: 5));
    } catch (_) {
      // Any failure (timeout, corrupt cache, storage error) → treat as logged
      // out. The user can simply sign in again.
      user = null;
    }

    await minDisplay;
    state = user != null ? AuthState.auth(user) : AuthState.unauth();
  }

  /// Read the persisted session, returning the cached user when a valid token
  /// is present. Never used without an enclosing timeout (see [_init]).
  Future<IceUser?> _loadCachedUser() async {
    await _api.loadTokens();
    final cached = await _storage.read(key: 'user_json');
    final token = await _api.accessToken;
    if (cached != null && token != null) {
      return IceUser.fromJson(jsonDecode(cached));
    }
    return null;
  }

  void _handleSessionExpired() {
    _storage.delete(key: 'user_json');
    state = AuthState.unauth('Your session expired. Please sign in again.');
  }

  /// Login with email OR login_id + password.
  Future<String?> login(String identifier, String password) async {
    // One automatic retry on network errors — covers a flaky first-connect on
    // mobile where the initial TCP/TLS handshake drops.
    for (var attempt = 0; attempt < 2; attempt++) {
      try {
        final res = await _dio.post(
          '/auth/login/',
          data: {'identifier': identifier, 'password': password},
        );
        final data = res.data as Map<String, dynamic>;
        await _api.saveTokens(data['access'], data['refresh']);
        final user = IceUser.fromJson(data['user']);
        await _storage.write(
          key: 'user_json',
          value: jsonEncode(user.toJson()),
        );
        state = AuthState.auth(user);
        return null; // success
      } on DioException catch (e) {
        final isNetworkError =
            e.type == DioExceptionType.connectionError ||
            e.type == DioExceptionType.connectionTimeout ||
            e.type == DioExceptionType.sendTimeout ||
            e.type == DioExceptionType.receiveTimeout;

        // On the first attempt, retry network errors after a short delay.
        if (isNetworkError && attempt == 0) {
          await Future.delayed(const Duration(seconds: 2));
          continue;
        }

        final data = e.response?.data;
        // Surface the server's own detail message when available.
        if (data is Map) {
          final detail = data['detail']?.toString();
          if (detail != null && detail.isNotEmpty) return detail;
        }
        final code = e.response?.statusCode;
        if (code == 401) return 'Invalid ID or password.';
        if (code == 403) return 'Account locked or disabled.';
        if (e.type == DioExceptionType.connectionTimeout ||
            e.type == DioExceptionType.sendTimeout ||
            e.type == DioExceptionType.receiveTimeout) {
          return 'Connection timed out. Check your internet.';
        }
        if (e.type == DioExceptionType.connectionError) {
          return 'Cannot reach server. Check your internet connection.';
        }
        return 'Login failed (${e.type.name}). Check your credentials.';
      } on Exception catch (e) {
        return 'Unexpected error: $e';
      }
    }
    return 'Cannot reach server. Check your internet connection.';
  }

  Future<void> logout() async {
    try {
      final refresh = await _storage.read(key: 'refresh_token');
      if (refresh != null) {
        await _dio.post('/auth/logout/', data: {'refresh': refresh});
      }
    } catch (_) {}
    await _api.clearTokens();
    await _storage.delete(key: 'user_json');
    state = AuthState.unauth();
  }

  void updateUser(IceUser user) {
    _storage.write(key: 'user_json', value: jsonEncode(user.toJson()));
    state = AuthState.auth(user);
  }

  /// Reload the signed-in user from `me/`. Returns false when it failed.
  Future<bool> refreshMe() async {
    try {
      final res = await _dio.get('/me/');
      if (state.status != AuthStatus.authenticated) return false;
      updateUser(IceUser.fromJson(res.data as Map<String, dynamic>));
      return true;
    } catch (_) {
      return false;
    }
  }

  /// The server refused a call with code "password_change_required": show
  /// the password screen now, then confirm the flag with `me/`.
  void passwordChangeRequired() {
    final user = state.user;
    if (user == null) return;
    if (!user.mustChangePassword) {
      updateUser(
        IceUser.fromJson({...user.toJson(), 'must_change_password': true}),
      );
    }
    refreshMe();
  }

  /// Replace a temporary password (PL.1). Returns null on success, else the
  /// server's message; [ChangePasswordError] says which field it is about.
  Future<ChangePasswordError?> changePassword({
    required String oldPassword,
    required String newPassword,
  }) async {
    try {
      await _dio.post(
        '/me/change-password/',
        data: {
          'old_password': oldPassword,
          'new_password': newPassword,
          'confirm_password': newPassword,
        },
      );
    } on DioException catch (e) {
      return ChangePasswordError.from(e);
    } on Exception {
      return const ChangePasswordError(null, null);
    }
    // The same token keeps working. If me/ fails, the server has still
    // cleared the flag, so let the user continue.
    if (!await refreshMe()) {
      final user = state.user;
      if (user != null) {
        updateUser(
          IceUser.fromJson({...user.toJson(), 'must_change_password': false}),
        );
      }
    }
    return null;
  }
}

/// Why `me/change-password/` refused: [field] is `old_password`,
/// `new_password`, `confirm_password` or null (network or other), [message]
/// is the server's text when it sent one.
class ChangePasswordError {
  const ChangePasswordError(this.field, this.message);

  final String? field;
  final String? message;

  /// The server sends `{"old_password": "Incorrect password."}` (a string)
  /// or serializer errors (`{"new_password": ["…", …]}`); accept both.
  factory ChangePasswordError.from(DioException e) {
    final data = e.response?.data;
    if (data is Map) {
      for (final key in const [
        'old_password',
        'new_password',
        'confirm_password',
        'non_field_errors',
        'detail',
      ]) {
        final msg = _firstMessage(data[key]);
        if (msg != null) {
          return ChangePasswordError(
            key.endsWith('password') ? key : null,
            msg,
          );
        }
      }
    }
    return const ChangePasswordError(null, null);
  }

  static String? _firstMessage(Object? v) {
    if (v is String && v.isNotEmpty) return v;
    if (v is List && v.isNotEmpty) return v.first.toString();
    return null;
  }
}

final authProvider = StateNotifierProvider<AuthNotifier, AuthState>(
  (_) => AuthNotifier(),
);
