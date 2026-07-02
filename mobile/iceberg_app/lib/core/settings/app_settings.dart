import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../api/api_client.dart';
import '../i18n/strings.dart';
import '../theme/ice_tokens.dart';

/// Appearance + notification preferences. Persisted locally for instant
/// startup, then synced with `GET/PATCH /student/settings/` so they follow
/// the student across devices.
class AppSettings {
  final ThemeMode themeMode;
  final String accent; // key into IceAccents.byName
  final String fontSize; // small | medium | large
  final String language; // uz | en | ru | ko (Uzbek is the default)
  final Map<String, bool> notifications;

  const AppSettings({
    this.themeMode = ThemeMode.light,
    this.accent = 'ice',
    this.fontSize = 'medium',
    this.language = 'uz',
    this.notifications = const {
      'assignments': true,
      'vocabulary': true,
      'payments': true,
      'announcements': true,
    },
  });

  Color get accentColor => IceAccents.byName[accent] ?? IceAccents.ice;

  double get textScale => switch (fontSize) {
    'small' => 0.92,
    'large' => 1.12,
    _ => 1.0,
  };

  AppSettings copyWith({
    ThemeMode? themeMode,
    String? accent,
    String? fontSize,
    String? language,
    Map<String, bool>? notifications,
  }) => AppSettings(
    themeMode: themeMode ?? this.themeMode,
    accent: accent ?? this.accent,
    fontSize: fontSize ?? this.fontSize,
    language: language ?? this.language,
    notifications: notifications ?? this.notifications,
  );

  static ThemeMode themeModeFrom(String v) => switch (v) {
    'light' => ThemeMode.light,
    'dark' => ThemeMode.dark,
    _ => ThemeMode.system,
  };

  String get themeName => switch (themeMode) {
    ThemeMode.light => 'light',
    ThemeMode.dark => 'dark',
    ThemeMode.system => 'system',
  };
}

class AppSettingsNotifier extends StateNotifier<AppSettings> {
  AppSettingsNotifier() : super(const AppSettings()) {
    _load();
  }

  Future<void> _load() async {
    final p = await SharedPreferences.getInstance();
    // One-time rebrand: the old default accent was lime. Move anyone still on
    // it (i.e. who never explicitly picked it) onto the new iceberg-blue brand.
    var accent = p.getString('ice_accent') ?? 'ice';
    if (!(p.getBool('ice_rebrand_blue') ?? false)) {
      if (accent == 'lime') accent = 'ice';
      await p.setBool('ice_rebrand_blue', true);
      await p.setString('ice_accent', accent);
    }
    // Uzbek is the default language for new installs (our user base is in
    // Uzbekistan). Users who explicitly picked another language keep it.
    var lang = p.getString('ice_lang') ?? 'uz';
    // Migrate: Japanese removed in this version — reset to the default.
    if (lang == 'ja') {
      lang = 'uz';
      await p.setString('ice_lang', 'uz');
    }
    state = AppSettings(
      themeMode: AppSettings.themeModeFrom(p.getString('ice_theme') ?? 'light'),
      accent: accent,
      fontSize: p.getString('ice_font') ?? 'medium',
      language: lang,
      notifications: {
        for (final k in const [
          'assignments',
          'vocabulary',
          'payments',
          'announcements',
        ])
          k: p.getBool('ice_notif_$k') ?? true,
      },
    );
  }

  Future<void> _persist() async {
    final p = await SharedPreferences.getInstance();
    await p.setString('ice_theme', state.themeName);
    await p.setString('ice_accent', state.accent);
    await p.setString('ice_font', state.fontSize);
    await p.setString('ice_lang', state.language);
    for (final e in state.notifications.entries) {
      await p.setBool('ice_notif_${e.key}', e.value);
    }
  }

  /// Pull server-side settings after login (server wins over local cache).
  Future<void> syncFromServer() async {
    try {
      final res = await ApiClient.instance.dio.get('/student/settings/');
      final d = res.data as Map<String, dynamic>;
      state = AppSettings(
        themeMode: AppSettings.themeModeFrom(d['theme'] ?? 'system'),
        accent: d['accent'] ?? 'ice',
        fontSize: d['font_size'] ?? 'medium',
        language: d['language'] ?? 'uz',
        notifications: {
          ...state.notifications,
          ...((d['notifications'] as Map?)?.map(
                (k, v) => MapEntry(k.toString(), v == true),
              ) ??
              {}),
        },
      );
      await _persist();
    } catch (_) {
      // Offline or non-student account — local settings stay in effect.
    }
  }

  Future<void> _patch(Map<String, dynamic> body) async {
    try {
      await ApiClient.instance.dio.patch('/student/settings/', data: body);
    } catch (_) {
      // Saved locally; will re-sync next launch.
    }
  }

  void setTheme(ThemeMode mode) {
    state = state.copyWith(themeMode: mode);
    _persist();
    _patch({'theme': state.themeName});
  }

  void setAccent(String accent) {
    state = state.copyWith(accent: accent);
    _persist();
    _patch({'accent': accent});
  }

  void setFontSize(String size) {
    state = state.copyWith(fontSize: size);
    _persist();
    _patch({'font_size': size});
  }

  void setLanguage(String lang) {
    state = state.copyWith(language: lang);
    _persist();
    _patch({'language': lang});
  }

  void setNotification(String key, bool value) {
    state = state.copyWith(notifications: {...state.notifications, key: value});
    _persist();
    _patch({
      'notifications': {key: value},
    });
  }
}

final appSettingsProvider =
    StateNotifierProvider<AppSettingsNotifier, AppSettings>(
      (_) => AppSettingsNotifier(),
    );

/// Chrome strings in the selected language: `final s = ref.watch(stringsProvider);`
final stringsProvider = Provider<S>(
  (ref) => S(ref.watch(appSettingsProvider.select((s) => s.language))),
);
