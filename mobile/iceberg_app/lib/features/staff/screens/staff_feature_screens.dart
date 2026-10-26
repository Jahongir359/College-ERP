import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../core/utils/formatters.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

part 'staff_features/classes_screen.dart';
part 'staff_features/attendance_screen.dart';
part 'staff_features/results_screen.dart';
part 'staff_features/assignments_screen.dart';
part 'staff_features/vocabulary_screen.dart';
part 'staff_features/leave_screen.dart';
part 'staff_features/feedback_screen.dart';

// ════════════════════════════════════════════════════════════════════════════
//  Shared helpers
// ════════════════════════════════════════════════════════════════════════════

void _toast(BuildContext context, String msg) {
  ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
}

String _studentName(Map s) {
  final f = (s['first_name'] ?? '').toString().trim();
  final l = (s['last_name'] ?? '').toString().trim();
  final full = '$f $l'.trim();
  return full.isEmpty ? (s['email']?.toString() ?? 'Student') : full;
}

// ── Themed group dropdown ─────────────────────────────────────────────────────
class _GroupDropdown extends ConsumerWidget {
  final int? value;
  final ValueChanged<int?> onChanged;
  const _GroupDropdown({required this.value, required this.onChanged});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final groups = ref.watch(staffGroupsProvider);
    return groups.when(
      loading: () => LinearProgressIndicator(color: t.accent),
      error: (e, _) => Text(
        'Could not load groups: $e',
        style: TextStyle(color: t.coral),
      ),
      data: (list) {
        if (list.isEmpty) {
          return Text(
            'No groups are assigned to you yet.',
            style: TextStyle(color: t.textMid),
          );
        }
        return DropdownButtonFormField<int>(
          value: value,
          isExpanded: true,
          dropdownColor: t.card,
          style: TextStyle(color: t.textHi, fontSize: 14),
          decoration: InputDecoration(
            labelText: 'Group',
            labelStyle: TextStyle(color: t.textMid),
          ),
          items: [
            for (final g in list)
              DropdownMenuItem(
                value: g['id'] as int,
                child: Text(
                  '${g['name']}${g['course_name'] != null ? ' · ${g['course_name']}' : ''}',
                  overflow: TextOverflow.ellipsis,
                ),
              ),
          ],
          onChanged: onChanged,
        );
      },
    );
  }
}
