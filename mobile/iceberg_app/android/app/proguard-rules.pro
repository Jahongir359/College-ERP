# Flutter / R8 keep rules for the release build.
#
# The Flutter engine and most first-party plugins ship their own consumer
# ProGuard rules, so this file only needs project-specific keeps. Add entries
# here if a release build crashes with ClassNotFoundException / missing-method
# errors that do not appear in debug.

# Flutter embedding (defensive — usually covered by the engine's own rules).
-keep class io.flutter.embedding.** { *; }
-keep class io.flutter.plugin.** { *; }

# Keep annotations and generic signatures so reflection-based plugins behave.
-keepattributes *Annotation*, Signature, InnerClasses, EnclosingMethod
