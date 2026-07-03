import 'dart:io';

import 'package:dio/dio.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:intl/intl.dart';
import 'package:open_filex/open_filex.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Submit Assignment — details, current submission, file picker + comment.
class StudentAssignmentDetailScreen extends ConsumerStatefulWidget {
  final int assignmentId;
  const StudentAssignmentDetailScreen({super.key, required this.assignmentId});

  @override
  ConsumerState<StudentAssignmentDetailScreen> createState() =>
      _StudentAssignmentDetailScreenState();
}

class _StudentAssignmentDetailScreenState
    extends ConsumerState<StudentAssignmentDetailScreen> {
  final _comment = TextEditingController();
  PlatformFile? _picked;
  bool _busy = false;
  bool _seeded = false;

  @override
  void dispose() {
    _comment.dispose();
    super.dispose();
  }

  Future<void> _pickFile() async {
    final result = await FilePicker.pickFiles(withData: true);
    if (result != null && result.files.isNotEmpty) {
      setState(() => _picked = result.files.first);
    }
  }

  Future<void> _submit() async {
    final s = ref.read(stringsProvider);
    setState(() => _busy = true);
    try {
      final form = FormData.fromMap({
        'note': _comment.text.trim(),
        if (_picked?.bytes != null)
          'file': MultipartFile.fromBytes(
            _picked!.bytes!,
            filename: _picked!.name,
          ),
      });
      await ApiClient.instance.dio.post(
        '/assignments/${widget.assignmentId}/submit/',
        data: form,
      );
      ref.invalidate(assignmentDetailProvider(widget.assignmentId));
      ref.invalidate(assignmentsProvider);
      ref.invalidate(studentDashProvider);
      if (mounted) {
        setState(() => _picked = null);
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text(s('Assignment submitted.'))));
      }
    } on DioException catch (e) {
      if (mounted) {
        final data = e.response?.data;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              data is Map && data.isNotEmpty
                  ? data.values.first.toString()
                  : s('Submission failed. Try again.'),
            ),
          ),
        );
      }
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final detail = ref.watch(assignmentDetailProvider(widget.assignmentId));

    return detail.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () =>
            ref.invalidate(assignmentDetailProvider(widget.assignmentId)),
      ),
      data: (a) => _buildBody(context, a),
    );
  }

  Widget _buildBody(BuildContext context, Map<String, dynamic> a) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    final sub = a['my_submission'] as Map<String, dynamic>?;
    final due = DateTime.tryParse(a['due_date'] ?? '');
    final overdue = due != null && due.isBefore(DateTime.now());
    final graded = sub?['grade'] != null;

    if (!_seeded && sub != null) {
      _comment.text = (sub['note'] as String?) ?? '';
      _seeded = true;
    }

    return IcePage(
      title: s('Submit Assignment'),
      backButton: true,
      onRefresh: () async =>
          ref.refresh(assignmentDetailProvider(widget.assignmentId).future),
      children: [
        // ── Header ───────────────────────────────────────────────────────
        IceCard(
          hero: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Expanded(
                    child: Text(
                      a['title'] ?? '',
                      style: const TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.w800,
                        color: Colors.white,
                      ),
                    ),
                  ),
                  StatusBadge(
                    sub != null
                        ? (graded ? s('Graded') : s('Submitted'))
                        : (overdue ? s('Overdue') : s('To Do')),
                    tone: sub != null
                        ? (graded ? BadgeTone.sky : BadgeTone.accent)
                        : (overdue ? BadgeTone.coral : BadgeTone.amber),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Wrap(
                spacing: 14,
                runSpacing: 6,
                children: [
                  if ((a['subject_name'] as String?)?.isNotEmpty == true)
                    _MetaItem(
                      icon: Icons.book_outlined,
                      text: a['subject_name'],
                    ),
                  if ((a['group_name'] as String?)?.isNotEmpty == true)
                    _MetaItem(
                      icon: Icons.groups_outlined,
                      text: a['group_name'],
                    ),
                  if (due != null)
                    _MetaItem(
                      icon: Icons.schedule_rounded,
                      text: 'Due ${DateFormat('MMM d, h:mm a').format(due)}',
                    ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),

        if ((a['description'] as String?)?.isNotEmpty == true) ...[
          IceCard(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                MicroLabel(s('Instructions')),
                const SizedBox(height: 8),
                Text(
                  a['description'],
                  style: TextStyle(fontSize: 14, height: 1.5, color: t.textMid),
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
        ],

        if (graded) ...[
          IceCard(
            child: Row(
              children: [
                Icon(Icons.workspace_premium_rounded, color: t.sky),
                const SizedBox(width: 12),
                Text(
                  s('Grade: '),
                  style: TextStyle(fontSize: 15, color: t.textMid),
                ),
                Text(
                  '${sub!['grade']}',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.w800,
                    color: t.sky,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
        ],

        // ── Current submission ───────────────────────────────────────────
        if (sub != null &&
            (sub['file_url'] as String?)?.isNotEmpty == true) ...[
          MicroLabel(s('Your Submission')),
          const SizedBox(height: 8),
          _FileChip(
            name: _fileName(sub['file_url']),
            subtitle: sub['submitted_at'] != null
                ? 'Submitted ${DateFormat('MMM d, h:mm a').format(DateTime.parse(sub['submitted_at']))}'
                : null,
            onOpen: () => _openUrl(sub['file_url']),
          ),
          const SizedBox(height: 14),
        ],

        // ── Upload ───────────────────────────────────────────────────────
        MicroLabel(sub != null ? 'Replace File' : 'Add File'),
        const SizedBox(height: 8),
        if (_picked != null)
          _FileChip(
            name: _picked!.name,
            subtitle:
                '${(_picked!.size / 1024).toStringAsFixed(0)} KB · ready to upload',
            onRemove: () => setState(() => _picked = null),
          )
        else
          GestureDetector(
            onTap: _pickFile,
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 22),
              decoration: BoxDecoration(
                color: t.inset,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(
                  color: t.stroke,
                  width: 1.5,
                  style: BorderStyle.solid,
                ),
              ),
              child: Column(
                children: [
                  Icon(Icons.upload_file_rounded, size: 28, color: t.textMid),
                  const SizedBox(height: 8),
                  Text(
                    s('Choose File'),
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                      color: t.textHi,
                    ),
                  ),
                ],
              ),
            ),
          ),
        const SizedBox(height: 16),

        MicroLabel(s('Comments (Optional)')),
        const SizedBox(height: 8),
        TextField(
          controller: _comment,
          maxLines: 3,
          maxLength: 200,
          style: TextStyle(color: t.textHi, fontWeight: FontWeight.w500),
          decoration: InputDecoration(
            hintText: s('Add a note for your teacher…'),
          ),
        ),
        const SizedBox(height: 8),
        IceButton(
          sub != null ? s('Update Submission') : s('Submit Assignment'),
          busy: _busy,
          onPressed: (_picked == null && sub == null) ? null : _submit,
        ),
        if (_picked == null && sub == null) ...[
          const SizedBox(height: 8),
          Center(
            child: Text(
              'Attach a file to submit.',
              style: TextStyle(fontSize: 12, color: t.textLow),
            ),
          ),
        ],
      ],
    );
  }

  String _fileName(String url) {
    final clean = url.split('?').first;
    return Uri.decodeComponent(clean.split('/').last);
  }

  Future<void> _openUrl(String url) async {
    // Download to a temp file with auth, then open it.
    try {
      final dir = Directory.systemTemp.path;
      final name = _fileName(url);
      final path = '$dir/$name';
      await ApiClient.instance.dio.download(url, path);
      await OpenFilex.open(path);
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(const SnackBar(content: Text('Could not open file.')));
      }
    }
  }
}

class _MetaItem extends StatelessWidget {
  final IconData icon;
  final String text;
  const _MetaItem({required this.icon, required this.text});

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Icon(icon, size: 14, color: Colors.white.withValues(alpha: 0.6)),
      const SizedBox(width: 5),
      Text(
        text,
        style: TextStyle(
          fontSize: 12.5,
          fontWeight: FontWeight.w600,
          color: Colors.white.withValues(alpha: 0.8),
        ),
      ),
    ],
  );
}

class _FileChip extends StatelessWidget {
  final String name;
  final String? subtitle;
  final VoidCallback? onOpen;
  final VoidCallback? onRemove;

  const _FileChip({
    required this.name,
    this.subtitle,
    this.onOpen,
    this.onRemove,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      padding: const EdgeInsets.all(14),
      onTap: onOpen,
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: t.coralSoft,
              borderRadius: BorderRadius.circular(11),
            ),
            child: Icon(
              Icons.insert_drive_file_rounded,
              size: 18,
              color: t.coral,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                    color: t.textHi,
                  ),
                ),
                if (subtitle != null) ...[
                  const SizedBox(height: 2),
                  Text(
                    subtitle!,
                    style: TextStyle(fontSize: 11.5, color: t.textMid),
                  ),
                ],
              ],
            ),
          ),
          if (onRemove != null)
            GestureDetector(
              onTap: onRemove,
              child: Icon(Icons.close_rounded, size: 20, color: t.textMid),
            )
          else if (onOpen != null)
            Icon(Icons.download_rounded, size: 20, color: t.mint),
        ],
      ),
    );
  }
}
