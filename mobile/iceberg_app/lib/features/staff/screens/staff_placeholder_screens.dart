import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../core/utils/formatters.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

// ─── Staff Payments Screen ────────────────────────────────────────────────────
class StaffPaymentsScreen extends ConsumerWidget {
  const StaffPaymentsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final invoices = ref.watch(staffPaymentsProvider);
    final s = ref.watch(stringsProvider);

    return invoices.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.invalidate(staffPaymentsProvider),
      ),
      data: (list) => IcePage(
        title: s('Payments'),
        subtitle: s('Student invoices for your groups'),
        backButton: true,
        onRefresh: () => ref.refresh(staffPaymentsProvider.future),
        children: [
          if (list.isEmpty)
            IceCard(
              child: EmptyState(
                icon: Icons.payment_outlined,
                title: s('No payment records'),
                message: s('Student invoices will appear here.'),
              ),
            )
          else ...[
            // Summary row
            _SummaryRow(
              total: list.length,
              paid: list.where((i) => i['status'] == 'paid').length,
              pending: list.where((i) => i['status'] != 'paid').length,
            ),
            const SizedBox(height: 16),
            // Invoice cards
            ...list.asMap().entries.map(
              (e) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _InvoiceCard(inv: e.value, idx: e.key),
              ),
            ),
          ],
        ],
      ),
    );
  }
}

class _SummaryRow extends ConsumerWidget {
  final int total, paid, pending;
  const _SummaryRow({
    required this.total,
    required this.paid,
    required this.pending,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    return Row(
      children: [
        Expanded(child: _StatChip(s('Total'), '$total', t.accentInk)),
        const SizedBox(width: 8),
        Expanded(child: _StatChip(s('Paid'), '$paid', t.accentInk)),
        const SizedBox(width: 8),
        Expanded(child: _StatChip(s('Pending'), '$pending', t.amber)),
      ],
    );
  }
}

class _StatChip extends StatelessWidget {
  final String label, value;
  final Color color;
  const _StatChip(this.label, this.value, this.color);

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      padding: const EdgeInsets.symmetric(vertical: 12),
      child: Column(
        children: [
          Text(
            value,
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.w900,
              color: color,
            ),
          ),
          const SizedBox(height: 2),
          Text(
            label,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: t.textMid,
            ),
          ),
        ],
      ),
    );
  }
}

class _InvoiceCard extends ConsumerWidget {
  final dynamic inv;
  final int idx;
  const _InvoiceCard({required this.inv, required this.idx});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final isPaid = inv['status']?.toString() == 'paid';
    final statusTone = isPaid ? BadgeTone.accent : BadgeTone.amber;
    final iconColor = isPaid ? t.accentInk : t.amber;
    final student = inv['student_name'] ?? inv['student'] ?? '—';
    final group = inv['group_name'] ?? inv['group'] ?? '—';
    final due = inv['due_date']?.toString() ?? '';
    final amount = inv['amount'];

    return IceCard(
      padding: const EdgeInsets.all(16),
      child: Row(
        children: [
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: iconColor.withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              isPaid
                  ? Icons.check_circle_rounded
                  : Icons.schedule_rounded,
              color: iconColor,
              size: 22,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  student.toString(),
                  style: TextStyle(
                    fontWeight: FontWeight.w700,
                    fontSize: 14,
                    color: t.textHi,
                  ),
                ),
                Text(
                  group.toString(),
                  style: TextStyle(fontSize: 12, color: t.textMid),
                ),
                if (due.isNotEmpty)
                  Text(
                    '${s('Due')} $due',
                    style: TextStyle(fontSize: 11, color: t.textLow),
                  ),
              ],
            ),
          ),
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                amount != null ? fmtCurrency(amount) : '—',
                style: TextStyle(
                  fontWeight: FontWeight.w900,
                  fontSize: 16,
                  color: t.textHi,
                ),
              ),
              const SizedBox(height: 4),
              StatusBadge(isPaid ? s('Paid') : s('Pending'), tone: statusTone),
            ],
          ),
        ],
      ),
    )
        .animate(delay: Duration(milliseconds: 300 + idx * 60))
        .slideY(begin: 0.1, duration: 350.ms, curve: Curves.easeOut)
        .fadeIn(duration: 300.ms);
  }
}

// ─── Staff Notifications Screen ───────────────────────────────────────────────
class StaffNotificationsScreen extends ConsumerWidget {
  const StaffNotificationsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final notifs = ref.watch(notificationsProvider);
    final s = ref.watch(stringsProvider);

    return notifs.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.invalidate(notificationsProvider),
      ),
      data: (list) => IcePage(
        title: s('Notifications'),
        subtitle: s('Admin broadcasts and system alerts'),
        backButton: true,
        onRefresh: () => ref.refresh(notificationsProvider.future),
        children: [
          if (list.isEmpty)
            IceCard(
              child: EmptyState(
                icon: Icons.notifications_none_rounded,
                title: s('No notifications'),
                message: s('New notifications from the admin will appear here.'),
              ),
            )
          else
            ...list.asMap().entries.map(
              (e) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _NotifCard(n: e.value, idx: e.key),
              ),
            ),
        ],
      ),
    );
  }
}

class _NotifCard extends StatelessWidget {
  final dynamic n;
  final int idx;
  const _NotifCard({required this.n, required this.idx});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final isRead = n['is_read'] == true;
    final title = n['title']?.toString() ?? n['message']?.toString() ?? '—';
    final message = n['message']?.toString() ?? '';
    final date = n['created_at']?.toString() ?? '';

    return IceCard(
      padding: const EdgeInsets.all(16),
      color: isRead ? null : t.accentSoft,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 44,
            height: 44,
            decoration: BoxDecoration(
              color: (isRead ? t.textMid : t.accentInk).withValues(alpha: 0.14),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              isRead
                  ? Icons.notifications_none_rounded
                  : Icons.notifications_active_rounded,
              color: isRead ? t.textMid : t.accentInk,
              size: 22,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        title,
                        style: TextStyle(
                          fontWeight:
                              isRead ? FontWeight.w600 : FontWeight.w800,
                          fontSize: 14,
                          color: t.textHi,
                        ),
                      ),
                    ),
                    if (!isRead)
                      Container(
                        width: 8,
                        height: 8,
                        decoration: BoxDecoration(
                          color: t.accentInk,
                          shape: BoxShape.circle,
                        ),
                      ),
                  ],
                ),
                if (message.isNotEmpty && message != title) ...[
                  const SizedBox(height: 4),
                  Text(
                    message,
                    style: TextStyle(fontSize: 13, color: t.textMid),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
                if (date.length >= 10) ...[
                  const SizedBox(height: 6),
                  Text(
                    date.substring(0, 10),
                    style: TextStyle(fontSize: 11, color: t.textLow),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    )
        .animate(delay: Duration(milliseconds: 200 + idx * 60))
        .slideX(begin: 0.06, duration: 350.ms, curve: Curves.easeOut)
        .fadeIn(duration: 300.ms);
  }
}
