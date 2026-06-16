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

  // Must match the backend used in ApiClient so token reads are consistent.
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
    try {
      await _api.loadTokens().timeout(const Duration(seconds: 4));
      final cached = await _storage
          .read(key: 'user_json')
          .timeout(const Duration(seconds: 4));
      final token = await _api.accessToken;
      await minDisplay;
      if (cached != null && token != null) {
        state = AuthState.auth(IceUser.fromJson(jsonDecode(cached)));
        return;
      }
    } catch (_) {
      // Fall through to unauthenticated — the user can simply log in again.
    }
    await minDisplay;
    state = AuthState.unauth();
  }

  void _handleSessionExpired() {
    _storage.delete(key: 'user_json');
    state = AuthState.unauth('Your session expired. Please sign in again.');
  }

  /// Login with email OR login_id + password.
  Future<String?> login(String identifier, String password) async {
    // One automatic retry on network errors — covers a flaky first-connect on
    // mobile where the TCP/TLS handshake drops on the initial attempt.
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
