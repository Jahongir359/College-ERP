import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:intl/intl.dart';

import '../../../core/api/api_client.dart';
import '../../../core/api/api_providers.dart';
import '../../../core/auth/auth_state.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// Messages — list of the student's class group chats with last message and
/// unread counts. Students can only see groups they're enrolled in.
class StudentMessagesScreen extends ConsumerStatefulWidget {
  const StudentMessagesScreen({super.key});

  @override
  ConsumerState<StudentMessagesScreen> createState() =>
      _StudentMessagesScreenState();
}

class _StudentMessagesScreenState extends ConsumerState<StudentMessagesScreen> {
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final threads = ref.watch(messageThreadsProvider);

    return threads.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.invalidate(messageThreadsProvider),
      ),
      data: (data) => _buildBody(context, data),
    );
  }

  Widget _buildBody(BuildContext context, Map<String, dynamic> data) {
    final t = context.ice;
    final all = ((data['threads'] as List?) ?? []).cast<Map<String, dynamic>>();
    final visible = _query.isEmpty
        ? all
        : all
              .where(
                (th) => (th['group_name'] ?? '')
                    .toString()
                    .toLowerCase()
                    .contains(_query),
              )
              .toList();

    return IcePage(
      title: 'Messages',
      backButton: true,
      onRefresh: () async => ref.refresh(messageThreadsProvider.future),
      children: [
        TextField(
          onChanged: (v) => setState(() => _query = v.trim().toLowerCase()),
          style: TextStyle(color: t.textHi, fontWeight: FontWeight.w600),
          decoration: InputDecoration(
            hintText: 'Search groups…',
            prefixIcon: Icon(Icons.search_rounded, color: t.textMid, size: 20),
          ),
        ),
        const SizedBox(height: 16),
        if (all.isEmpty)
          const IceCard(
            child: EmptyState(
              icon: Icons.chat_bubble_outline_rounded,
              title: 'No group chats',
              message: 'Your class group conversations will appear here.',
            ),
          )
        else if (visible.isEmpty)
          const IceCard(
            child: EmptyState(
              icon: Icons.search_off_rounded,
              title: 'No matches',
            ),
          )
        else
          ...visible.map(
            (th) => Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: _ThreadCard(thread: th),
            ),
          ),
      ],
    );
  }
}

class _ThreadCard extends StatelessWidget {
  final Map<String, dynamic> thread;
  const _ThreadCard({required this.thread});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final name = (thread['group_name'] ?? 'Group').toString();
    final unread = (thread['unread_count'] as num?)?.toInt() ?? 0;
    final lastTime = DateTime.tryParse(thread['last_message_time'] ?? '');

    return IceCard(
      padding: const EdgeInsets.all(14),
      onTap: () => context.go(
        '/student/messages/${thread['group_id']}?name=${Uri.encodeComponent(name)}',
      ),
      child: Row(
        children: [
          CircleAvatar(
            radius: 24,
            backgroundColor: t.accentSoft,
            child: Text(
              name.isNotEmpty ? name[0].toUpperCase() : '#',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.w800,
                color: t.accent,
              ),
            ),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        name,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          fontSize: 15,
                          fontWeight: FontWeight.w800,
                          color: t.textHi,
                        ),
                      ),
                    ),
                    if (lastTime != null)
                      Text(
                        _relative(lastTime),
                        style: TextStyle(fontSize: 11, color: t.textLow),
                      ),
                  ],
                ),
                const SizedBox(height: 3),
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        (thread['last_message'] as String?)?.isNotEmpty == true
                            ? thread['last_message']
                            : 'No messages yet',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: TextStyle(
                          fontSize: 13,
                          color: unread > 0 ? t.textHi : t.textMid,
                          fontWeight: unread > 0
                              ? FontWeight.w600
                              : FontWeight.w400,
                        ),
                      ),
                    ),
                    if (unread > 0) ...[
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 7,
                          vertical: 2,
                        ),
                        decoration: BoxDecoration(
                          color: t.accent,
                          borderRadius: BorderRadius.circular(999),
                        ),
                        child: Text(
                          '$unread',
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.w800,
                            color: t.onAccent,
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _relative(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inMinutes < 1) return 'now';
    if (diff.inMinutes < 60) return '${diff.inMinutes}m';
    if (diff.inHours < 24) return '${diff.inHours}h';
    if (diff.inDays < 7) return '${diff.inDays}d';
    return DateFormat('MMM d').format(dt);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Chat detail
// ─────────────────────────────────────────────────────────────────────────────
class StudentChatScreen extends ConsumerStatefulWidget {
  final int groupId;
  final String groupName;
  const StudentChatScreen({
    super.key,
    required this.groupId,
    required this.groupName,
  });

  @override
  ConsumerState<StudentChatScreen> createState() => _StudentChatScreenState();
}

class _StudentChatScreenState extends ConsumerState<StudentChatScreen> {
  final _scroll = ScrollController();
  final _input = TextEditingController();
  List<Map<String, dynamic>> _messages = [];
  bool _loading = true;
  bool _sending = false;
  Object? _error;
  Timer? _poll;

  @override
  void initState() {
    super.initState();
    _fetch();
    // Light polling keeps the conversation fresh while open.
    _poll = Timer.periodic(
      const Duration(seconds: 10),
      (_) => _fetch(silent: true),
    );
  }

  @override
  void dispose() {
    _poll?.cancel();
    _scroll.dispose();
    _input.dispose();
    super.dispose();
  }

  Future<void> _fetch({bool silent = false}) async {
    if (!silent) setState(() => _loading = true);
    try {
      final res = await ApiClient.instance.dio.get(
        '/messages/${widget.groupId}/',
      );
      final msgs = ((res.data['messages'] as List?) ?? [])
          .cast<Map<String, dynamic>>();
      if (mounted) {
        setState(() {
          _messages = msgs;
          _loading = false;
          _error = null;
        });
        _jumpToBottom();
        ref.invalidate(messageThreadsProvider);
      }
    } catch (e) {
      if (mounted && !silent) {
        setState(() {
          _error = e;
          _loading = false;
        });
      }
    }
  }

  void _jumpToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.jumpTo(_scroll.position.maxScrollExtent);
      }
    });
  }

  Future<void> _send() async {
    final text = _input.text.trim();
    if (text.isEmpty) return;
    setState(() => _sending = true);
    _input.clear();
    try {
      final res = await ApiClient.instance.dio.post(
        '/messages/${widget.groupId}/',
        data: {'message': text},
      );
      if (mounted) {
        setState(() => _messages.add(res.data as Map<String, dynamic>));
        _jumpToBottom();
      }
    } on DioException {
      if (mounted) {
        _input.text = text;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Message not sent. Try again.')),
        );
      }
    } finally {
      if (mounted) setState(() => _sending = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final myName = ref.watch(authProvider).user?.fullName;

    return Scaffold(
      backgroundColor: t.bg,
      appBar: AppBar(
        backgroundColor: t.bg,
        elevation: 0,
        leading: IconButton(
          icon: Icon(Icons.arrow_back_rounded, color: t.textHi),
          onPressed: () => context.canPop()
              ? context.pop()
              : context.go('/student/messages'),
        ),
        title: Text(
          widget.groupName,
          style: TextStyle(
            fontSize: 17,
            fontWeight: FontWeight.w800,
            color: t.textHi,
          ),
        ),
      ),
      body: Column(
        children: [
          Expanded(child: _body(context, myName)),
          _composer(context),
        ],
      ),
    );
  }

  Widget _body(BuildContext context, String? myName) {
    if (_loading) {
      return const Padding(
        padding: EdgeInsets.all(20),
        child: Column(
          children: [
            SkeletonBox(height: 50),
            SizedBox(height: 12),
            SkeletonBox(height: 50),
          ],
        ),
      );
    }
    if (_error != null) {
      return ErrorState(error: _error, onRetry: _fetch);
    }
    if (_messages.isEmpty) {
      return const EmptyState(
        icon: Icons.chat_bubble_outline_rounded,
        title: 'No messages yet',
        message: 'Be the first to say hello 👋',
      );
    }
    return ListView.builder(
      controller: _scroll,
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 12),
      cacheExtent: 600,
      itemCount: _messages.length,
      itemBuilder: (_, i) => _Bubble(message: _messages[i]),
    );
  }

  Widget _composer(BuildContext context) {
    final t = context.ice;
    return SafeArea(
      top: false,
      child: Container(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
        decoration: BoxDecoration(
          color: t.card,
          border: Border(top: BorderSide(color: t.stroke)),
        ),
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: _input,
                textCapitalization: TextCapitalization.sentences,
                minLines: 1,
                maxLines: 4,
                style: TextStyle(color: t.textHi),
                decoration: InputDecoration(
                  hintText: 'Message…',
                  fillColor: t.inset,
                  contentPadding: const EdgeInsets.symmetric(
                    horizontal: 16,
                    vertical: 10,
                  ),
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(24),
                    borderSide: BorderSide.none,
                  ),
                ),
                onSubmitted: (_) => _send(),
              ),
            ),
            const SizedBox(width: 8),
            GestureDetector(
              onTap: _sending ? null : _send,
              child: Container(
                width: 46,
                height: 46,
                decoration: BoxDecoration(
                  color: t.accent,
                  shape: BoxShape.circle,
                ),
                child: _sending
                    ? Padding(
                        padding: const EdgeInsets.all(13),
                        child: CircularProgressIndicator(
                          strokeWidth: 2.4,
                          color: t.onAccent,
                        ),
                      )
                    : Icon(Icons.send_rounded, color: t.onAccent, size: 20),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _Bubble extends StatelessWidget {
  final Map<String, dynamic> message;
  const _Bubble({required this.message});

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final mine = message['is_mine'] == true;
    final created = DateTime.tryParse(message['created_at'] ?? '');

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Column(
        crossAxisAlignment: mine
            ? CrossAxisAlignment.end
            : CrossAxisAlignment.start,
        children: [
          if (!mine)
            Padding(
              padding: const EdgeInsets.only(left: 8, bottom: 2),
              child: Text(
                message['sender_name'] ?? '',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: t.mint,
                ),
              ),
            ),
          Container(
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.74,
            ),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: mine ? t.accent : t.card,
              borderRadius: BorderRadius.only(
                topLeft: const Radius.circular(16),
                topRight: const Radius.circular(16),
                bottomLeft: Radius.circular(mine ? 16 : 4),
                bottomRight: Radius.circular(mine ? 4 : 16),
              ),
              border: mine ? null : Border.all(color: t.stroke),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                if ((message['attachment_url'] as String?)?.isNotEmpty ==
                    true) ...[
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.attach_file_rounded,
                        size: 14,
                        color: mine ? t.onAccent : t.textMid,
                      ),
                      const SizedBox(width: 4),
                      Flexible(
                        child: Text(
                          message['attachment_name'] ?? 'Attachment',
                          style: TextStyle(
                            fontSize: 12,
                            fontStyle: FontStyle.italic,
                            color: mine ? t.onAccent : t.textMid,
                          ),
                        ),
                      ),
                    ],
                  ),
                  if ((message['message'] as String?)?.isNotEmpty == true)
                    const SizedBox(height: 4),
                ],
                if ((message['message'] as String?)?.isNotEmpty == true)
                  Text(
                    message['message'],
                    style: TextStyle(
                      fontSize: 14.5,
                      color: mine ? t.onAccent : t.textHi,
                      height: 1.35,
                    ),
                  ),
              ],
            ),
          ),
          if (created != null)
            Padding(
              padding: const EdgeInsets.only(top: 3, left: 6, right: 6),
              child: Text(
                DateFormat('h:mm a').format(created),
                style: TextStyle(fontSize: 10, color: t.textLow),
              ),
            ),
        ],
      ),
    );
  }
}
