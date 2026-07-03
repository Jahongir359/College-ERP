import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../core/api/api_client.dart';
import '../../core/settings/app_settings.dart';
import '../../core/theme/ice_tokens.dart';
import '../widgets/ice_kit.dart';
import '../widgets/ice_shell.dart';

class MessagesScreen extends ConsumerStatefulWidget {
  const MessagesScreen({super.key});

  @override
  ConsumerState<MessagesScreen> createState() => _State();
}

class _State extends ConsumerState<MessagesScreen> {
  bool _loading = true;
  bool _notAvailable = false;
  List<dynamic> _threads = [];

  @override
  void initState() {
    super.initState();
    _fetch();
  }

  Future<void> _fetch() async {
    setState(() {
      _loading = true;
      _notAvailable = false;
    });
    try {
      final res = await ApiClient.instance.dio.get('/messages/');
      final data = res.data;
      List<dynamic> list = [];
      if (data is List) {
        list = data;
      } else if (data is Map) {
        list = (data['results'] as List?) ?? (data['threads'] as List?) ?? [];
      }
      setState(() {
        _threads = list;
        _loading = false;
      });
    } catch (_) {
      setState(() {
        _notAvailable = true;
        _loading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const PageSkeleton();
    final s = ref.watch(stringsProvider);

    return IcePage(
      title: s('Messages'),
      subtitle: s('Group conversations'),
      backButton: true,
      onRefresh: _fetch,
      children: [
        if (_notAvailable)
          IceCard(
            child: EmptyState(
              icon: Icons.chat_bubble_outline_rounded,
              title: s('Messaging unavailable'),
              message: s('Group chat could not be loaded. Pull to retry.'),
            ),
          )
        else if (_threads.isEmpty)
          IceCard(
            child: EmptyState(
              icon: Icons.mark_chat_unread_outlined,
              title: s('No conversations yet'),
              message: s('Messages from your groups will appear here.'),
            ),
          )
        else
          ..._threads.asMap().entries.map(
            (e) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: _ThreadTile(
                thread: _threads[e.key] as Map,
                index: e.key,
                onTap: () => _openThread(_threads[e.key] as Map),
              ),
            ),
          ),
      ],
    );
  }

  void _openThread(Map thread) {
    Navigator.of(
      context,
    ).push(MaterialPageRoute(builder: (_) => _ChatScreen(thread: thread)));
  }
}

// ─── Thread Tile ──────────────────────────────────────────────────────────────

class _ThreadTile extends ConsumerWidget {
  final Map thread;
  final int index;
  final VoidCallback onTap;
  const _ThreadTile({
    required this.thread,
    required this.index,
    required this.onTap,
  });

  String get _groupName =>
      thread['group_name']?.toString() ??
      thread['name']?.toString() ??
      'Group Chat';

  String get _lastMessage =>
      thread['last_message']?.toString() ?? thread['preview']?.toString() ?? '';

  String get _time {
    final raw =
        thread['last_message_time']?.toString() ??
        thread['updated_at']?.toString() ??
        '';
    if (raw.isEmpty) return '';
    try {
      final dt = DateTime.parse(raw).toLocal();
      final now = DateTime.now();
      final diff = now.difference(dt);
      if (diff.inMinutes < 1) return 'now';
      if (diff.inHours < 1) return '${diff.inMinutes}m';
      if (diff.inDays < 1) return '${diff.inHours}h';
      if (diff.inDays < 7) return '${diff.inDays}d';
      return '${dt.day}/${dt.month}';
    } catch (_) {
      return '';
    }
  }

  int get _unread =>
      thread['unread_count'] is int ? thread['unread_count'] as int : 0;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    return GestureDetector(
          onTap: onTap,
          child: IceCard(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
            child: Row(
              children: [
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: t.accent,
                    shape: BoxShape.circle,
                  ),
                  alignment: Alignment.center,
                  child: Text(
                    _groupName.isNotEmpty ? _groupName[0].toUpperCase() : 'G',
                    style: TextStyle(
                      fontSize: 18,
                      fontWeight: FontWeight.w900,
                      color: t.onAccent,
                    ),
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
                              _groupName,
                              style: TextStyle(
                                fontSize: 14,
                                fontWeight: _unread > 0
                                    ? FontWeight.w800
                                    : FontWeight.w600,
                                color: t.textHi,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          if (_time.isNotEmpty)
                            Text(
                              _time,
                              style: TextStyle(
                                fontSize: 11,
                                color: _unread > 0 ? t.accent : t.textLow,
                                fontWeight: _unread > 0
                                    ? FontWeight.w700
                                    : FontWeight.w400,
                              ),
                            ),
                        ],
                      ),
                      const SizedBox(height: 3),
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              _lastMessage.isEmpty
                                  ? s('No messages yet')
                                  : _lastMessage,
                              style: TextStyle(
                                fontSize: 12,
                                color: _lastMessage.isEmpty
                                    ? t.textLow
                                    : t.textMid,
                                fontWeight: _unread > 0
                                    ? FontWeight.w600
                                    : FontWeight.w400,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          if (_unread > 0) ...[
                            const SizedBox(width: 8),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 6,
                                vertical: 2,
                              ),
                              decoration: BoxDecoration(
                                color: t.accent,
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: Text(
                                '$_unread',
                                style: TextStyle(
                                  fontSize: 10,
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
          ),
        )
        .animate(delay: Duration(milliseconds: 40 * index))
        .fadeIn(duration: 250.ms)
        .slideX(begin: 0.05, duration: 250.ms);
  }
}

// ─── Chat Screen ──────────────────────────────────────────────────────────────

class _ChatScreen extends ConsumerStatefulWidget {
  final Map thread;
  const _ChatScreen({required this.thread});

  @override
  ConsumerState<_ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends ConsumerState<_ChatScreen> {
  bool _loading = true;
  List<dynamic> _messages = [];
  final _scrollCtrl = ScrollController();
  final _msgCtrl = TextEditingController();
  bool _sending = false;

  String get _groupName =>
      widget.thread['group_name']?.toString() ??
      widget.thread['name']?.toString() ??
      'Chat';

  dynamic get _threadId => widget.thread['id'] ?? widget.thread['group_id'];

  @override
  void initState() {
    super.initState();
    _fetch();
  }

  @override
  void dispose() {
    _scrollCtrl.dispose();
    _msgCtrl.dispose();
    super.dispose();
  }

  Future<void> _fetch() async {
    setState(() => _loading = true);
    try {
      final res = await ApiClient.instance.dio.get('/messages/$_threadId/');
      final data = res.data;
      List<dynamic> msgs = [];
      if (data is List) {
        msgs = data;
      } else if (data is Map) {
        msgs = (data['messages'] as List?) ?? [];
      }
      setState(() {
        _messages = msgs;
        _loading = false;
      });
      _scrollToBottom();
    } catch (_) {
      setState(() => _loading = false);
    }
  }

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollCtrl.hasClients) {
        _scrollCtrl.animateTo(
          _scrollCtrl.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _send() async {
    final text = _msgCtrl.text.trim();
    if (text.isEmpty || _sending) return;
    setState(() => _sending = true);
    _msgCtrl.clear();
    try {
      await ApiClient.instance.dio.post(
        '/messages/$_threadId/',
        data: {'message': text},
      );
      await _fetch();
    } catch (_) {}
    if (mounted) setState(() => _sending = false);
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);
    return Scaffold(
      backgroundColor: t.bg,
      appBar: AppBar(
        backgroundColor: t.bg,
        elevation: 0,
        leading: BackButton(color: t.textHi),
        title: Row(
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                color: t.accent,
                shape: BoxShape.circle,
              ),
              alignment: Alignment.center,
              child: Text(
                _groupName.isNotEmpty ? _groupName[0].toUpperCase() : 'G',
                style: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w900,
                  color: t.onAccent,
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                _groupName,
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w800,
                  color: t.textHi,
                ),
              ),
            ),
          ],
        ),
      ),
      body: Column(
        children: [
          Expanded(
            child: _loading
                ? Center(
                    child: CircularProgressIndicator(color: t.accent),
                  )
                : _messages.isEmpty
                ? Center(
                    child: Text(
                      s('No messages yet.'),
                      style: TextStyle(color: t.textLow),
                    ),
                  )
                : ListView.builder(
                    controller: _scrollCtrl,
                    padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
                    cacheExtent: 600,
                    itemCount: _messages.length,
                    itemBuilder: (_, i) =>
                        _MessageBubble(message: _messages[i] as Map),
                  ),
          ),

          // Message input
          SafeArea(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: t.card,
                border: Border(top: BorderSide(color: t.stroke)),
              ),
              child: Row(
                children: [
                  Expanded(
                    child: TextField(
                      controller: _msgCtrl,
                      style: TextStyle(color: t.textHi),
                      decoration: InputDecoration(
                        hintText: s('Type a message...'),
                        hintStyle: TextStyle(color: t.textLow),
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: BorderSide(color: t.stroke),
                        ),
                        enabledBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: BorderSide(color: t.stroke),
                        ),
                        focusedBorder: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(24),
                          borderSide: BorderSide(color: t.accent),
                        ),
                        contentPadding: const EdgeInsets.symmetric(
                          horizontal: 16,
                          vertical: 10,
                        ),
                        isDense: true,
                      ),
                      onSubmitted: (_) => _send(),
                      textInputAction: TextInputAction.send,
                    ),
                  ),
                  const SizedBox(width: 8),
                  GestureDetector(
                    onTap: _send,
                    child: AnimatedContainer(
                      duration: const Duration(milliseconds: 200),
                      width: 44,
                      height: 44,
                      decoration: BoxDecoration(
                        color: _sending ? t.stroke : t.accent,
                        shape: BoxShape.circle,
                      ),
                      child: _sending
                          ? Padding(
                              padding: const EdgeInsets.all(12),
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                color: t.onAccent,
                              ),
                            )
                          : Icon(
                              Icons.send_rounded,
                              color: t.onAccent,
                              size: 20,
                            ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Message Bubble ───────────────────────────────────────────────────────────

class _MessageBubble extends StatelessWidget {
  final Map message;
  const _MessageBubble({required this.message});

  bool get _isSent =>
      message['is_mine'] == true || message['sender_type'] == 'me';

  String get _text =>
      message['message']?.toString() ?? message['text']?.toString() ?? '';

  String get _senderName => message['sender_name']?.toString() ?? '';

  String get _time {
    final raw =
        message['created_at']?.toString() ??
        message['timestamp']?.toString() ??
        '';
    if (raw.isEmpty) return '';
    try {
      final dt = DateTime.parse(raw).toLocal();
      final h = dt.hour.toString().padLeft(2, '0');
      final m = dt.minute.toString().padLeft(2, '0');
      return '$h:$m';
    } catch (_) {
      return '';
    }
  }

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        mainAxisAlignment:
            _isSent ? MainAxisAlignment.end : MainAxisAlignment.start,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          if (!_isSent) ...[
            CircleAvatar(
              radius: 14,
              backgroundColor: t.accentSoft,
              child: Text(
                _senderName.isNotEmpty ? _senderName[0].toUpperCase() : '?',
                style: TextStyle(
                  fontSize: 10,
                  fontWeight: FontWeight.w800,
                  color: t.accent,
                ),
              ),
            ),
            const SizedBox(width: 6),
          ],
          ConstrainedBox(
            constraints: BoxConstraints(
              maxWidth: MediaQuery.of(context).size.width * 0.72,
            ),
            child: Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: _isSent ? t.accent : t.inset,
                borderRadius: BorderRadius.only(
                  topLeft: const Radius.circular(16),
                  topRight: const Radius.circular(16),
                  bottomLeft: Radius.circular(_isSent ? 16 : 4),
                  bottomRight: Radius.circular(_isSent ? 4 : 16),
                ),
                border: _isSent ? null : Border.all(color: t.stroke),
              ),
              child: Column(
                crossAxisAlignment: _isSent
                    ? CrossAxisAlignment.end
                    : CrossAxisAlignment.start,
                children: [
                  if (!_isSent && _senderName.isNotEmpty) ...[
                    Text(
                      _senderName,
                      style: TextStyle(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        color: t.accent,
                      ),
                    ),
                    const SizedBox(height: 2),
                  ],
                  Text(
                    _text,
                    style: TextStyle(
                      fontSize: 14,
                      color: _isSent ? t.onAccent : t.textHi,
                    ),
                  ),
                  if (_time.isNotEmpty) ...[
                    const SizedBox(height: 2),
                    Text(
                      _time,
                      style: TextStyle(
                        fontSize: 10,
                        color: _isSent
                            ? t.onAccent.withValues(alpha: 0.6)
                            : t.textLow,
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
