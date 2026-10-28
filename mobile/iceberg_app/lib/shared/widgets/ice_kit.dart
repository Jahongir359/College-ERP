import 'package:flutter/material.dart';

import '../../core/api/api_client.dart';
import '../../core/theme/ice_tokens.dart';

/// Resolves a potentially relative media URL to an absolute one using the
/// configured API base host. Relative paths starting with '/' are common
/// when Django REST Framework returns media URLs without a domain.
String? _resolveMediaUrl(String? raw) {
  if (raw == null || raw.isEmpty) return raw;
  if (raw.startsWith('http://') || raw.startsWith('https://')) return raw;
  final base = Uri.tryParse(kBaseUrl);
  if (base == null) return raw;
  return '${base.scheme}://${base.host}$raw';
}

// ─── IceCard ─────────────────────────────────────────────────────────────────
/// Rounded dark card with hairline stroke. `hero: true` adds the teal
/// gradient used by headline cards in the design references.
class IceCard extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry padding;
  final EdgeInsetsGeometry? margin;
  final VoidCallback? onTap;
  final bool hero;
  final double radius;
  final Color? color;

  const IceCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(18),
    this.margin,
    this.onTap,
    this.hero = false,
    this.radius = 22,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final body = Container(
      width: double.infinity,
      margin: margin,
      padding: padding,
      decoration: BoxDecoration(
        color: hero ? null : (color ?? t.card),
        gradient: hero ? t.heroGradient : null,
        borderRadius: BorderRadius.circular(radius),
        border: Border.all(color: t.stroke),
        boxShadow: t.isDark
            ? const [
                BoxShadow(
                  color: Color(0x40000000), // black @ 25%
                  blurRadius: 8,
                  offset: Offset(0, 3),
                ),
              ]
            : const [
                BoxShadow(
                  color: Color(0x14104049),
                  blurRadius: 6,
                  offset: Offset(0, 3),
                ),
              ],
      ),
      child: hero ? IceOnHero(child: child) : child,
    );

    // RepaintBoundary caches each card as a GPU texture so the compositor
    // can scroll them without repainting shadows/gradients/borders every frame.
    if (onTap == null) return RepaintBoundary(child: body);
    return RepaintBoundary(
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(radius),
          child: body,
        ),
      ),
    );
  }
}

// ─── IceOnHero ───────────────────────────────────────────────────────────────
/// Gives [child] the [IceTokens.onHero] tokens, so widgets below that read
/// `context.ice` keep accent text readable on a hero gradient. [IceCard] with
/// `hero: true` already does this. Colours a screen picked from its own `t`
/// before the hero must use `t.onHero` directly.
class IceOnHero extends StatelessWidget {
  final Widget child;
  const IceOnHero({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final hero = t.onHero;
    if (identical(hero, t)) return child;
    final theme = Theme.of(context);
    return Theme(
      data: theme.copyWith(
        extensions: [
          ...theme.extensions.values.where((e) => e is! IceTokens),
          hero,
        ],
      ),
      child: child,
    );
  }
}

// ─── MicroLabel ──────────────────────────────────────────────────────────────
/// Uppercase, letter-spaced micro heading ("ATTENDANCE", "OVERALL RATE"…).
class MicroLabel extends StatelessWidget {
  final String text;
  final Color? color;
  const MicroLabel(this.text, {super.key, this.color});

  @override
  Widget build(BuildContext context) => Text(
    text.toUpperCase(),
    style: TextStyle(
      fontSize: 11,
      fontWeight: FontWeight.w700,
      letterSpacing: 1.6,
      color: color ?? context.ice.textMid,
    ),
  );
}

// ─── SectionHeader ───────────────────────────────────────────────────────────
class SectionHeader extends StatelessWidget {
  final String title;
  final String? actionLabel;
  final VoidCallback? onAction;
  const SectionHeader(this.title, {super.key, this.actionLabel, this.onAction});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Padding(
      padding: const EdgeInsets.fromLTRB(2, 6, 2, 12),
      child: Row(
        children: [
          Expanded(
            child: Text(
              title,
              style: TextStyle(
                fontSize: 20,
                fontWeight: FontWeight.w800,
                color: t.textHi,
                letterSpacing: -0.3,
              ),
            ),
          ),
          if (actionLabel != null)
            GestureDetector(
              onTap: onAction,
              child: Text(
                actionLabel!,
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w700,
                  color: t.accentInk,
                ),
              ),
            ),
        ],
      ),
    );
  }
}

// ─── StatCard ────────────────────────────────────────────────────────────────
/// Small dashboard tile: soft icon chip, big number, muted label.
class StatCard extends StatelessWidget {
  final IconData icon;
  final String value;
  final String label;
  final Color? iconColor;
  final VoidCallback? onTap;
  final Widget? trailing;

  const StatCard({
    super.key,
    required this.icon,
    required this.value,
    required this.label,
    this.iconColor,
    this.onTap,
    this.trailing,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final c = iconColor ?? t.accentInk;
    return IceCard(
      onTap: onTap,
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: c.withValues(alpha: 0.14),
                  borderRadius: BorderRadius.circular(11),
                ),
                child: Icon(icon, size: 18, color: c),
              ),
              const Spacer(),
              if (trailing != null) trailing!,
            ],
          ),
          const SizedBox(height: 14),
          Text(
            value,
            style: TextStyle(
              fontSize: 24,
              fontWeight: FontWeight.w800,
              color: t.textHi,
              height: 1.0,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            label,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: TextStyle(
              fontSize: 12.5,
              fontWeight: FontWeight.w600,
              color: t.textMid,
            ),
          ),
        ],
      ),
    );
  }
}

// ─── ProgressRing ────────────────────────────────────────────────────────────
class ProgressRing extends StatelessWidget {
  final double value; // 0..1
  final double size;
  final double strokeWidth;
  final Widget? center;
  final Color? color;

  const ProgressRing({
    super.key,
    required this.value,
    this.size = 130,
    this.strokeWidth = 10,
    this.center,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        fit: StackFit.expand,
        children: [
          TweenAnimationBuilder<double>(
            tween: Tween(begin: 0, end: value.clamp(0.0, 1.0)),
            duration: const Duration(milliseconds: 900),
            curve: Curves.easeOutCubic,
            builder: (_, v, __) => CircularProgressIndicator(
              value: v,
              strokeWidth: strokeWidth,
              strokeCap: StrokeCap.round,
              backgroundColor: t.inset,
              valueColor: AlwaysStoppedAnimation(color ?? t.accentInk),
            ),
          ),
          if (center != null) Center(child: center),
        ],
      ),
    );
  }
}

// ─── StatusBadge ─────────────────────────────────────────────────────────────
enum BadgeTone { accent, coral, sky, amber, neutral }

class StatusBadge extends StatelessWidget {
  final String label;
  final BadgeTone tone;
  const StatusBadge(this.label, {super.key, this.tone = BadgeTone.neutral});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final (bg, fg) = switch (tone) {
      BadgeTone.accent => (t.accentSoft, t.accentInk),
      BadgeTone.coral => (t.coralSoft, t.coral),
      BadgeTone.sky => (t.skySoft, t.sky),
      BadgeTone.amber => (t.amberSoft, t.amber),
      BadgeTone.neutral => (t.inset, t.textMid),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 11.5,
          fontWeight: FontWeight.w700,
          color: fg,
        ),
      ),
    );
  }
}

// ─── IceChipTabs ─────────────────────────────────────────────────────────────
/// Horizontal pill tabs (All / Completed / Pending…). Active pill = accent.
class IceChipTabs extends StatelessWidget {
  final List<String> tabs;
  final int index;
  final ValueChanged<int> onChanged;

  const IceChipTabs({
    super.key,
    required this.tabs,
    required this.index,
    required this.onChanged,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      clipBehavior: Clip.none,
      child: Row(
        children: [
          for (var i = 0; i < tabs.length; i++) ...[
            GestureDetector(
              onTap: () => onChanged(i),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 180),
                padding: const EdgeInsets.symmetric(
                  horizontal: 16,
                  vertical: 9,
                ),
                decoration: BoxDecoration(
                  color: i == index ? t.accent : t.inset,
                  borderRadius: BorderRadius.circular(999),
                ),
                child: Text(
                  tabs[i],
                  style: TextStyle(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    color: i == index ? t.onAccent : t.textMid,
                  ),
                ),
              ),
            ),
            if (i < tabs.length - 1) const SizedBox(width: 8),
          ],
        ],
      ),
    );
  }
}

// ─── ActionTile ──────────────────────────────────────────────────────────────
/// Row card with leading icon chip, title/subtitle and chevron — used for
/// quick actions and list rows throughout the app.
class ActionTile extends StatelessWidget {
  final IconData icon;
  final String title;
  final String? subtitle;
  final VoidCallback? onTap;
  final Color? iconColor;
  final Widget? trailing;

  const ActionTile({
    super.key,
    required this.icon,
    required this.title,
    this.subtitle,
    this.onTap,
    this.iconColor,
    this.trailing,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final c = iconColor ?? t.accentInk;
    return IceCard(
      onTap: onTap,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: c.withValues(alpha: 0.13),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(icon, size: 20, color: c),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  title,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 15,
                    fontWeight: FontWeight.w700,
                    color: t.textHi,
                  ),
                ),
                if (subtitle != null) ...[
                  const SizedBox(height: 2),
                  Text(
                    subtitle!,
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 12.5,
                      fontWeight: FontWeight.w500,
                      color: t.textMid,
                    ),
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(width: 8),
          trailing ?? Icon(Icons.chevron_right_rounded, color: t.textLow),
        ],
      ),
    );
  }
}

// ─── Primary button ──────────────────────────────────────────────────────────
class IceButton extends StatelessWidget {
  final String label;
  final VoidCallback? onPressed;
  final bool busy;
  final bool secondary;
  final IconData? icon;

  const IceButton(
    this.label, {
    super.key,
    this.onPressed,
    this.busy = false,
    this.secondary = false,
    this.icon,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: FilledButton(
        onPressed: busy ? null : onPressed,
        style: FilledButton.styleFrom(
          backgroundColor: secondary ? t.inset : t.accent,
          foregroundColor: secondary ? t.textHi : t.onAccent,
          disabledBackgroundColor: (secondary ? t.inset : t.accent).withValues(
            alpha: 0.45,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
          ),
          textStyle: const TextStyle(
            fontFamily: 'Inter',
            fontSize: 15,
            fontWeight: FontWeight.w800,
          ),
        ),
        child: busy
            ? SizedBox(
                width: 22,
                height: 22,
                child: CircularProgressIndicator(
                  strokeWidth: 2.5,
                  color: secondary ? t.textHi : t.onAccent,
                ),
              )
            : Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (icon != null) ...[
                    Icon(icon, size: 19),
                    const SizedBox(width: 8),
                  ],
                  Text(label),
                ],
              ),
      ),
    );
  }
}

// ─── IceSwitch ───────────────────────────────────────────────────────────────
/// Custom on/off toggle built from plain containers. Deliberately avoids the
/// Material [Switch], whose unstyled track renders as a large opaque grey
/// block on iOS Safari / CanvasKit.
class IceSwitch extends StatelessWidget {
  final bool value;
  final ValueChanged<bool> onChanged;
  const IceSwitch({super.key, required this.value, required this.onChanged});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: () => onChanged(!value),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 170),
        curve: Curves.easeOut,
        width: 46,
        height: 28,
        padding: const EdgeInsets.all(3),
        decoration: BoxDecoration(
          color: value ? t.accent : t.inset,
          borderRadius: BorderRadius.circular(999),
          border: Border.all(color: value ? t.accent : t.stroke),
        ),
        child: AnimatedAlign(
          duration: const Duration(milliseconds: 170),
          curve: Curves.easeOut,
          alignment: value ? Alignment.centerRight : Alignment.centerLeft,
          child: Container(
            width: 22,
            height: 22,
            decoration: BoxDecoration(
              color: value ? t.onAccent : t.textMid,
              shape: BoxShape.circle,
            ),
          ),
        ),
      ),
    );
  }
}

// ─── Skeleton loaders ────────────────────────────────────────────────────────
/// Pulsing placeholder box. Deliberately avoids the `shimmer` package's
/// `ShaderMask`, which renders as a solid opaque grey block on iOS Safari /
/// CanvasKit. A plain colour-tween pulse composites reliably everywhere.
class SkeletonBox extends StatefulWidget {
  final double height;
  final double? width;
  final double radius;
  const SkeletonBox({
    super.key,
    required this.height,
    this.width,
    this.radius = 22,
  });

  @override
  State<SkeletonBox> createState() => _SkeletonBoxState();
}

class _SkeletonBoxState extends State<SkeletonBox>
    with SingleTickerProviderStateMixin {
  late final AnimationController _c = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 950),
  )..repeat(reverse: true);

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return AnimatedBuilder(
      animation: _c,
      builder: (context, _) => Container(
        height: widget.height,
        width: widget.width ?? double.infinity,
        decoration: BoxDecoration(
          color: Color.lerp(t.card, t.inset, _c.value),
          borderRadius: BorderRadius.circular(widget.radius),
        ),
      ),
    );
  }
}

/// Standard page skeleton: hero card + stat row + list rows.
class PageSkeleton extends StatelessWidget {
  const PageSkeleton({super.key});

  @override
  Widget build(BuildContext context) => ListView(
    physics: const NeverScrollableScrollPhysics(),
    padding: const EdgeInsets.all(20),
    children: const [
      SkeletonBox(height: 150),
      SizedBox(height: 14),
      Row(
        children: [
          Expanded(child: SkeletonBox(height: 110)),
          SizedBox(width: 14),
          Expanded(child: SkeletonBox(height: 110)),
        ],
      ),
      SizedBox(height: 14),
      SkeletonBox(height: 72),
      SizedBox(height: 14),
      SkeletonBox(height: 72),
      SizedBox(height: 14),
      SkeletonBox(height: 72),
    ],
  );
}

// ─── Empty & error states ────────────────────────────────────────────────────
class EmptyState extends StatelessWidget {
  final IconData icon;
  final String title;
  final String? message;
  final Widget? action;

  const EmptyState({
    super.key,
    this.icon = Icons.inbox_rounded,
    required this.title,
    this.message,
    this.action,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(color: t.inset, shape: BoxShape.circle),
              child: Icon(icon, size: 34, color: t.textLow),
            ),
            const SizedBox(height: 18),
            Text(
              title,
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.w800,
                color: t.textHi,
              ),
            ),
            if (message != null) ...[
              const SizedBox(height: 6),
              Text(
                message!,
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 13.5,
                  fontWeight: FontWeight.w500,
                  color: t.textMid,
                  height: 1.45,
                ),
              ),
            ],
            if (action != null) ...[const SizedBox(height: 20), action!],
          ],
        ),
      ),
    );
  }
}

class ErrorState extends StatelessWidget {
  final Object? error;
  final VoidCallback onRetry;
  const ErrorState({super.key, this.error, required this.onRetry});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final offline =
        error.toString().contains('SocketException') ||
        error.toString().contains('connection');
    return EmptyState(
      icon: offline ? Icons.wifi_off_rounded : Icons.error_outline_rounded,
      title: offline ? 'No internet connection' : 'Something went wrong',
      message: offline
          ? 'Check your connection and try again.'
          : 'The server could not be reached. Pull down or tap retry.',
      action: SizedBox(
        width: 160,
        child: FilledButton(
          onPressed: onRetry,
          style: FilledButton.styleFrom(
            backgroundColor: t.accent,
            foregroundColor: t.onAccent,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(14),
            ),
          ),
          child: const Text(
            'Retry',
            style: TextStyle(fontWeight: FontWeight.w800),
          ),
        ),
      ),
    );
  }
}

// ─── User avatar with photo / emoji / initials fallback ─────────────────────
class IceUserAvatar extends StatelessWidget {
  final String? photoUrl;
  final String? emoji;
  final String fallbackText;
  final double radius;
  final Color? bgColor;

  const IceUserAvatar({
    super.key,
    this.photoUrl,
    this.emoji,
    required this.fallbackText,
    this.radius = 22,
    this.bgColor,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final bg = bgColor ?? t.accentSoft;
    final resolvedUrl = _resolveMediaUrl(photoUrl);
    final hasPhoto = resolvedUrl != null && resolvedUrl.isNotEmpty;

    Widget fallback() {
      if (emoji != null && emoji!.isNotEmpty) {
        return Text(emoji!, style: TextStyle(fontSize: radius * 0.9));
      }
      return Text(
        fallbackText,
        style: TextStyle(
          fontSize: radius * 0.65,
          fontWeight: FontWeight.w800,
          color: t.accent,
        ),
      );
    }

    if (hasPhoto) {
      // Decode at physical pixel size so the image cache stores a small
      // texture rather than the full server resolution.
      final dpr = MediaQuery.devicePixelRatioOf(context).ceil();
      final px = (radius * 2 * dpr).ceil();
      return CircleAvatar(
        radius: radius,
        backgroundColor: bg,
        child: ClipOval(
          child: Image.network(
            resolvedUrl,
            width: radius * 2,
            height: radius * 2,
            fit: BoxFit.cover,
            cacheWidth: px,
            cacheHeight: px,
            errorBuilder: (_, __, ___) => fallback(),
          ),
        ),
      );
    }
    return CircleAvatar(
      radius: radius,
      backgroundColor: bg,
      child: fallback(),
    );
  }
}

// ─── Pull-to-refresh wrapper ─────────────────────────────────────────────────
class IceRefresh extends StatelessWidget {
  final Future<void> Function() onRefresh;
  final Widget child;
  const IceRefresh({super.key, required this.onRefresh, required this.child});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return RefreshIndicator(
      onRefresh: onRefresh,
      color: t.onAccent,
      backgroundColor: t.accent,
      child: child,
    );
  }
}
