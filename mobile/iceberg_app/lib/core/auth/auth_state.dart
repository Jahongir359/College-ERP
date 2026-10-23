import 'dart:convert';
import 'package:dio/dio.dart';
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
  });

  String get fullName => '$firstName $lastName'.trim();
  bool get isAdmin => userType == '1';
  bool get isStaff => userType == '2';
  bool get isStudent => userType == '3';
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
  AuthNotifier() : super(AuthState.loading()) {
    // When a token refresh fails (expired/blacklisted), drop to login cleanly
    // instead of leaving the user stuck on an error screen.
    _api.onSessionExpired = _handleSessionExpired;
    _init();
  }

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
    final minDisplay = Future<void>.delayed(
      const Duration(milliseconds: 1800),
    );

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
        final res = await _api.dio.post(
          '/auth/login/',
          data: {'identifier': identifier, 'password': password},
        );
        final data = res.data as Map<String, dynamic>;
        await _api.saveTokens(data['access'], data['refresh']);
        final user = IceUser.fromJson(data['user']);
        await _storage.write(key: 'user_json', value: jsonEncode(user.toJson()));
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
        await _api.dio.post('/auth/logout/', data: {'refresh': refresh});
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
}

final authProvider = StateNotifierProvider<AuthNotifier, AuthState>(
  (_) => AuthNotifier(),
);
