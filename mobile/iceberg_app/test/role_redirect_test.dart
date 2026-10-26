import 'package:flutter_test/flutter_test.dart';
import 'package:iceberg_app/core/auth/auth_state.dart';
import 'package:iceberg_app/core/router/app_router.dart';

IceUser _user(String userType, {String brand = 'center'}) => IceUser(
      id: 1,
      email: 'u@example.com',
      loginId: 'U1',
      firstName: 'Test',
      lastName: 'User',
      userType: userType,
      brand: brand,
    );

void main() {
  group('roleRedirect', () {
    test('loading always shows the splash screen', () {
      expect(roleRedirect(AuthState.loading(), '/student/home'), '/splash');
    });

    test('signed-out users go to login and stay there', () {
      final auth = AuthState.unauth();
      expect(roleRedirect(auth, '/student/home'), '/login');
      expect(roleRedirect(auth, '/staff/home'), '/login');
      expect(roleRedirect(auth, '/login'), isNull);
    });

    test('admins only see the coming-soon wall', () {
      final auth = AuthState.auth(_user('1'));
      expect(roleRedirect(auth, '/login'), '/coming-soon');
      expect(roleRedirect(auth, '/student/home'), '/coming-soon');
      expect(roleRedirect(auth, '/staff/home'), '/coming-soon');
      expect(roleRedirect(auth, '/coming-soon'), isNull);
    });

    test('teachers stay in the teacher portal', () {
      final auth = AuthState.auth(_user('2'));
      expect(roleRedirect(auth, '/login'), '/staff/home');
      expect(roleRedirect(auth, '/student/home'), '/staff/home');
      expect(roleRedirect(auth, '/staff/attendance'), isNull);
    });

    test('students land on the student app and cannot open teacher pages', () {
      final auth = AuthState.auth(_user('3'));
      expect(roleRedirect(auth, '/login'), '/student/home');
      expect(roleRedirect(auth, '/splash'), '/student/home');
      expect(roleRedirect(auth, '/coming-soon'), '/student/home');
      expect(roleRedirect(auth, '/staff/home'), '/student/home');
      expect(roleRedirect(auth, '/student/payments'), isNull);
    });
  });

  group('IceUser.fromJson', () {
    test('reads the role and defaults the brand to the Study Center', () {
      final u = IceUser.fromJson({'id': 7, 'user_type': 2, 'first_name': 'Ali'});
      expect(u.isStaff, isTrue);
      expect(u.isAdmin || u.isStudent, isFalse);
      expect(u.brand, 'center');
      expect(u.fullName, 'Ali');
    });

    test('keeps a School brand and survives a toJson round trip', () {
      final u = IceUser.fromJson({'id': 8, 'user_type': '3', 'brand': 'school'});
      final again = IceUser.fromJson(u.toJson());
      expect(again.isStudent, isTrue);
      expect(again.brand, 'school');
    });

    test('a super admin is read from the role profile', () {
      final u = IceUser.fromJson({
        'id': 9,
        'user_type': '1',
        'role_profile': {'is_super_admin': true, 'branch_ids': [1, 2]},
      });
      expect(u.isSuperAdmin, isTrue);
      expect(u.branchIds, [1, 2]);
    });
  });
}
