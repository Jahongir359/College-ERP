import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../core/api/api_client.dart';

/// Why a password reset call failed.
enum PasswordResetFailure {
  /// 429: too many requests from this phone or address.
  tooMany,

  /// The code is wrong, used up or too old (`code: "invalid_code"`).
  invalidCode,

  /// The server's password rules refused the new password.
  password,

  /// No internet, a timeout or anything else.
  other,
}

class PasswordResetError {
  const PasswordResetError(this.kind, [this.message]);

  final PasswordResetFailure kind;

  /// The server's own text, only for [PasswordResetFailure.password].
  final String? message;

  factory PasswordResetError.from(DioException e) {
    final res = e.response;
    if (res?.statusCode == 429) {
      return const PasswordResetError(PasswordResetFailure.tooMany);
    }
    final data = res?.data;
    if (data is Map) {
      if (data['code'] == 'invalid_code') {
        return const PasswordResetError(PasswordResetFailure.invalidCode);
      }
      final pw = data['new_password'];
      if (pw is List && pw.isNotEmpty) {
        return PasswordResetError(
          PasswordResetFailure.password,
          pw.map((m) => '$m').join(' '),
        );
      }
      if (pw is String && pw.isNotEmpty) {
        return PasswordResetError(PasswordResetFailure.password, pw);
      }
    }
    return const PasswordResetError(PasswordResetFailure.other);
  }
}

/// Parents' forgotten password by SMS code (PL.2, D13). Both calls are
/// public; the first one answers the same whether or not the login ID and
/// phone match, so the app never learns (or shows) which accounts exist.
class PasswordResetApi {
  PasswordResetApi(this._dio);

  final Dio _dio;

  /// Ask for a code. Null means the server accepted the request.
  Future<PasswordResetError?> requestCode({
    required String loginId,
    required String phone,
  }) => _post('/auth/password-reset/', {'login_id': loginId, 'phone': phone});

  /// Set [newPassword] with the SMS [code]. Null means it was changed.
  Future<PasswordResetError?> confirm({
    required String loginId,
    required String code,
    required String newPassword,
  }) => _post('/auth/password-reset/confirm/', {
    'login_id': loginId,
    'code': code,
    'new_password': newPassword,
  });

  Future<PasswordResetError?> _post(
    String path,
    Map<String, String> data,
  ) async {
    try {
      await _dio.post(path, data: data);
      return null;
    } on DioException catch (e) {
      return PasswordResetError.from(e);
    } on Exception {
      return const PasswordResetError(PasswordResetFailure.other);
    }
  }
}

final passwordResetApiProvider = Provider<PasswordResetApi>(
  (ref) => PasswordResetApi(ApiClient.instance.dio),
);
