import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/i18n/strings.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Money fields arrive as either a JSON number (amount_paid / amount_due) or a
/// DRF decimal **string** ("150000.00") for model DecimalFields (amount /
/// discount / payment amount). Parse defensively — a raw `as num` cast on a
/// String throws in release and paints the card as a grey ErrorWidget box.
num _money(dynamic v) {
  if (v is num) return v;
  if (v is String) return num.tryParse(v) ?? 0;
  return 0;
}

String _uzs(num v) =>
    '${NumberFormat('#,###').format(v).replaceAll(',', ' ')} soʻm';

/// Payments — balance summary + invoice history (amounts in UZS soʻm).
class StudentPaymentsScreen extends ConsumerStatefulWidget {
  const StudentPaymentsScreen({super.key});

  @override
  ConsumerState<StudentPaymentsScreen> createState() =>
      _StudentPaymentsScreenState();
}

class _StudentPaymentsScreenState extends ConsumerState<StudentPaymentsScreen> {
  int _tab = 0; // 0 invoices · 1 payment history

  @override
  Widget build(BuildContext context) {
    final invoices = ref.watch(invoicesProvider);

    return invoices.when(
      loading: () => const PageSkeleton(),
      error: (e, _) =>
          ErrorState(error: e, onRetry: () => ref.invalidate(invoicesProvider)),
      data: (list) => _buildBody(context, list.cast<Map<String, dynamic>>()),
    );
  }

  Widget _buildBody(BuildContext context, List<Map<String, dynamic>> invoices) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);

    num totalPaid = 0;
    num outstanding = 0;
    DateTime? nextDue;
    final payments = <Map<String, dynamic>>[];
    for (final inv in invoices) {
      totalPaid += _money(inv['amount_paid']);
      final due = _money(inv['amount_due']);
      outstanding += due;
      if (due > 0) {
        final d = DateTime.tryParse(inv['due_date']?.toString() ?? '');
        if (d != null && (nextDue == null || d.isBefore(nextDue))) nextDue = d;
      }
      for (final p in (inv['payments'] as List? ?? [])) {
        payments.add({
          ...(p as Map).map((k, v) => MapEntry(k.toString(), v)),
          'invoice_id': inv['id'],
        });
      }
    }
    payments.sort(
      (a, b) => (b['paid_on'] ?? '').toString().compareTo(
        (a['paid_on'] ?? '').toString(),
      ),
    );

    return IcePage(
      title: s('Payments'),
      onRefresh: () async => ref.refresh(invoicesProvider.future),
      children: [
        // ── Balance hero ─────────────────────────────────────────────────
        IceCard(
          hero: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              MicroLabel(s('Outstanding Balance'), color: t.onHero.mint),
              const SizedBox(height: 8),
              Text(
                outstanding > 0 ? _uzs(outstanding) : s('All paid 🎉'),
                style: const TextStyle(
                  fontSize: 28,
                  fontWeight: FontWeight.w800,
                  color: Colors.white,
                  letterSpacing: -0.5,
                ),
              ),
              if (outstanding > 0 && nextDue != null) ...[
                const SizedBox(height: 10),
                StatusBadge(
                  s('Due {date}').replaceAll('{date}', DateFormat('MMM d, yyyy').format(nextDue)),
                  tone: nextDue.isBefore(DateTime.now())
                      ? BadgeTone.coral
                      : BadgeTone.amber,
                ),
                const SizedBox(height: 16),
                SizedBox(
                  width: 140,
                  height: 44,
                  child: FilledButton(
                    onPressed: () => _payInfo(context),
                    style: FilledButton.styleFrom(
                      backgroundColor: t.onHero.accent,
                      foregroundColor: t.onHero.onAccent,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14),
                      ),
                    ),
                    child: Text(
                      s('Pay Now'),
                      style: const TextStyle(
                        fontWeight: FontWeight.w800,
                        fontSize: 14,
                      ),
                    ),
                  ),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 14),

        Row(
          children: [
            Expanded(
              child: StatCard(
                icon: Icons.check_circle_outline_rounded,
                value: _uzs(totalPaid).replaceAll(' soʻm', ''),
                label: s('Total Paid (soʻm)'),
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: StatCard(
                icon: Icons.receipt_long_outlined,
                iconColor: t.sky,
                value: '${invoices.length}',
                label: s('Total Invoices'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 18),

        IceChipTabs(
          tabs: [s('Invoices'), s('History')],
          index: _tab,
          onChanged: (i) => setState(() => _tab = i),
        ),
        const SizedBox(height: 16),

        if (_tab == 0)
          if (invoices.isEmpty)
            IceCard(
              child: EmptyState(
                icon: Icons.receipt_long_outlined,
                title: s('No invoices yet'),
                message: s('Your tuition invoices will appear here.'),
              ),
            )
          else
            ...invoices.map(
              (inv) => Padding(
                padding: const EdgeInsets.only(bottom: 10),
                child: _InvoiceCard(inv: inv),
              ),
            )
        else if (payments.isEmpty)
          IceCard(
            child: EmptyState(
              icon: Icons.payments_outlined,
              title: s('No payments recorded'),
              message: s('Recorded payments will show up here.'),
            ),
          )
        else
          ...payments.map(
            (p) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _PaymentRow(payment: p),
            ),
          ),
      ],
    );
  }

  void _payInfo(BuildContext context) {
    final t = context.ice;
    showModalBottomSheet(
      context: context,
      backgroundColor: t.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 34),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(
              Icons.account_balance_wallet_outlined,
              size: 34,
              color: t.accent,
            ),
            const SizedBox(height: 14),
            Text(
              'Pay at the front desk',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w800,
                color: t.textHi,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Online payment (Payme · Click · Uzum) is coming soon. For now, '
              'please pay at the ICEBERG front desk and the office will mark your '
              'invoice as paid.',
              style: TextStyle(fontSize: 14, color: t.textMid, height: 1.5),
            ),
          ],
        ),
      ),
    );
  }
}

class _InvoiceCard extends ConsumerWidget {
  final Map<String, dynamic> inv;
  const _InvoiceCard({required this.inv});

  (String, BadgeTone) _badge(S s) => switch (inv['status']) {
    'paid' => (s('Paid'), BadgeTone.accent),
    'partial' => (s('Partial'), BadgeTone.amber),
    'cancelled' => (s('Cancelled'), BadgeTone.neutral),
    _ => (s('Due'), BadgeTone.coral),
  };

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final period = DateTime.tryParse(inv['period']?.toString() ?? '');
    final due = DateTime.tryParse(inv['due_date']?.toString() ?? '');
    final (badge, tone) = _badge(s);
    final amount = _money(inv['amount']);
    final amountDue = _money(inv['amount_due']);

    return IceCard(
      padding: const EdgeInsets.all(16),
      onTap: () => _showDetail(context, s),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  period != null
                      ? DateFormat('MMMM yyyy').format(period)
                      : '${s('Invoice')} #${inv['id']}',
                  style: TextStyle(
                    fontSize: 15.5,
                    fontWeight: FontWeight.w800,
                    color: t.textHi,
                  ),
                ),
              ),
              StatusBadge(badge, tone: tone),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Text(
                _uzs(amount),
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w700,
                  color: t.textMid,
                ),
              ),
              const Spacer(),
              if (amountDue > 0)
                Text(
                  '${_uzs(amountDue)} ${s('due')}',
                  style: TextStyle(
                    fontSize: 12.5,
                    fontWeight: FontWeight.w700,
                    color: t.coral,
                  ),
                )
              else
                Text(
                  due != null ? s('Due {date}').replaceAll('{date}', DateFormat('MMM d').format(due)) : '',
                  style: TextStyle(fontSize: 12, color: t.textLow),
                ),
            ],
          ),
        ],
      ),
    );
  }

  void _showDetail(BuildContext context, S s) {
    final t = context.ice;
    final payments = (inv['payments'] as List? ?? [])
        .cast<Map<String, dynamic>>();
    showModalBottomSheet(
      context: context,
      backgroundColor: t.card,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(26)),
      ),
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 20, 24, 32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Invoice #${inv['id']}',
              style: TextStyle(
                fontSize: 19,
                fontWeight: FontWeight.w800,
                color: t.textHi,
              ),
            ),
            const SizedBox(height: 16),
            _row(context, 'Amount', _uzs(_money(inv['amount']))),
            if (_money(inv['discount']) > 0)
              _row(context, 'Discount', '- ${_uzs(_money(inv['discount']))}'),
            _row(context, 'Paid', _uzs(_money(inv['amount_paid']))),
            _row(
              context,
              'Outstanding',
              _uzs(_money(inv['amount_due'])),
              accent: true,
            ),
            if ((inv['note'] as String?)?.isNotEmpty == true) ...[
              const SizedBox(height: 10),
              Text(
                inv['note'],
                style: TextStyle(color: t.textMid, fontSize: 13),
              ),
            ],
            if (payments.isNotEmpty) ...[
              const SizedBox(height: 16),
              MicroLabel(s('Payments')),
              const SizedBox(height: 8),
              ...payments.map((p) => _PaymentRow(payment: p)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _row(
    BuildContext context,
    String label,
    String value, {
    bool accent = false,
  }) {
    final t = context.ice;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: TextStyle(fontSize: 14, color: t.textMid)),
          Text(
            value,
            style: TextStyle(
              fontSize: 14.5,
              fontWeight: FontWeight.w800,
              color: accent ? t.accent : t.textHi,
            ),
          ),
        ],
      ),
    );
  }
}

class _PaymentRow extends StatelessWidget {
  final Map<String, dynamic> payment;
  const _PaymentRow({required this.payment});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final paidOn = DateTime.tryParse(payment['paid_on']?.toString() ?? '');
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      decoration: BoxDecoration(
        color: t.card,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: t.stroke),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: t.accentSoft,
              shape: BoxShape.circle,
            ),
            child: Icon(Icons.check_rounded, size: 16, color: t.accent),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _uzs(_money(payment['amount'])),
                  style: TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w800,
                    color: t.textHi,
                  ),
                ),
                Text(
                  [
                    if (paidOn != null)
                      DateFormat('MMM d, yyyy').format(paidOn),
                    (payment['method'] ?? '').toString(),
                  ].where((s) => s.isNotEmpty).join(' · '),
                  style: TextStyle(fontSize: 11.5, color: t.textMid),
                ),
              ],
            ),
          ),
          StatusBadge('Paid', tone: BadgeTone.accent),
        ],
      ),
    );
  }
}
