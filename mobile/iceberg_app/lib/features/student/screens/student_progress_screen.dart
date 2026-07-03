import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../core/api/api_providers.dart';
import '../../../core/settings/app_settings.dart';
import '../../../core/theme/ice_tokens.dart';
import '../../../shared/widgets/ice_kit.dart';
import '../../../shared/widgets/ice_shell.dart';

/// My Progress — vocabulary completion, quiz score trend, exam scores and
/// attendance, with a time filter.
class StudentProgressScreen extends ConsumerStatefulWidget {
  const StudentProgressScreen({super.key});

  @override
  ConsumerState<StudentProgressScreen> createState() =>
      _StudentProgressScreenState();
}

class _StudentProgressScreenState extends ConsumerState<StudentProgressScreen> {
  int _range = 1; // 0 = 7d, 1 = 30d, 2 = all time

  @override
  Widget build(BuildContext context) {
    final progress = ref.watch(studentProgressProvider);

    return progress.when(
      loading: () => const PageSkeleton(),
      error: (e, _) => ErrorState(
        error: e,
        onRetry: () => ref.invalidate(studentProgressProvider),
      ),
      data: (d) => _buildBody(context, d),
    );
  }

  Widget _buildBody(BuildContext context, Map<String, dynamic> d) {
    final t = context.ice;
    final s = ref.watch(stringsProvider);

    final activity = ((d['activity_30d'] as List?) ?? []).cast<num>();
    final labels = ((d['date_labels_30d'] as List?) ?? []).cast<String>();
    final quizScores = (d['quiz_scores'] as List?) ?? [];
    final examResults = (d['exam_results'] as List?) ?? [];
    final attendancePct = (d['attendance_pct'] as num?)?.toDouble() ?? 0;
    final completedDays = (d['completed_days'] as num?)?.toInt() ?? 0;
    final avgQuiz = (d['avg_quiz_score'] as num?)?.toDouble() ?? 0;

    // Time filter slices the 30-day series client-side.
    final window = switch (_range) {
      0 => 7,
      1 => 30,
      _ => activity.length,
    };
    final actSlice = activity.length > window
        ? activity.sublist(activity.length - window)
        : activity;
    final labSlice = labels.length > window
        ? labels.sublist(labels.length - window)
        : labels;
    final quizSlice = _range == 2
        ? quizScores
        : quizScores.length > (window ~/ 2)
        ? quizScores.sublist(quizScores.length - (window ~/ 2))
        : quizScores;

    return IcePage(
      title: s('My Progress'),
      subtitle: s('Overview of your learning'),
      onRefresh: () async => ref.refresh(studentProgressProvider.future),
      action: IceChipTabs(
        tabs: ['7d', '30d', s('All')],
        index: _range,
        onChanged: (i) => setState(() => _range = i),
      ),
      children: [
        // ── Summary tiles ────────────────────────────────────────────────
        Row(
          children: [
            Expanded(
              child: StatCard(
                icon: Icons.menu_book_rounded,
                value: '$completedDays',
                label: s('Vocab days done'),
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: StatCard(
                icon: Icons.quiz_outlined,
                iconColor: t.sky,
                value: '${avgQuiz.toStringAsFixed(avgQuiz % 1 == 0 ? 0 : 1)}%',
                label: s('Avg quiz score'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),

        // ── Vocabulary days completed ────────────────────────────────────
        _ChartCard(
          title: s('Vocabulary Days Completed'),
          subtitle: '${actSlice.fold<num>(0, (a, b) => a + b)} ${s('in this period')}',
          child: actSlice.every((v) => v == 0)
              ? _NoData(text: s('Complete vocabulary days to see your activity.'))
              : LineChart(
                  LineChartData(
                    minY: 0,
                    gridData: FlGridData(
                      show: true,
                      drawVerticalLine: false,
                      getDrawingHorizontalLine: (_) =>
                          FlLine(color: t.stroke, strokeWidth: 1),
                    ),
                    titlesData: FlTitlesData(
                      leftTitles: const AxisTitles(),
                      topTitles: const AxisTitles(),
                      rightTitles: const AxisTitles(),
                      bottomTitles: AxisTitles(
                        sideTitles: SideTitles(
                          showTitles: true,
                          reservedSize: 24,
                          interval: (actSlice.length / 4)
                              .clamp(1, 30)
                              .toDouble(),
                          getTitlesWidget: (v, _) {
                            final i = v.toInt();
                            if (i < 0 || i >= labSlice.length) {
                              return const SizedBox.shrink();
                            }
                            return Padding(
                              padding: const EdgeInsets.only(top: 6),
                              child: Text(
                                labSlice[i],
                                style: TextStyle(
                                  fontSize: 9.5,
                                  color: t.textLow,
                                ),
                              ),
                            );
                          },
                        ),
                      ),
                    ),
                    borderData: FlBorderData(show: false),
                    lineTouchData: const LineTouchData(enabled: false),
                    lineBarsData: [
                      LineChartBarData(
                        spots: [
                          for (var i = 0; i < actSlice.length; i++)
                            FlSpot(i.toDouble(), actSlice[i].toDouble()),
                        ],
                        isCurved: true,
                        preventCurveOverShooting: true,
                        barWidth: 2.5,
                        color: t.accent,
                        dotData: const FlDotData(show: false),
                        belowBarData: BarAreaData(
                          show: true,
                          gradient: LinearGradient(
                            begin: Alignment.topCenter,
                            end: Alignment.bottomCenter,
                            colors: [
                              t.accent.withValues(alpha: 0.25),
                              t.accent.withValues(alpha: 0),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
        ),
        const SizedBox(height: 14),

        // ── Quiz scores ──────────────────────────────────────────────────
        _ChartCard(
          title: s('Average Quiz Score'),
          subtitle: quizSlice.isEmpty
              ? s('No quizzes yet')
              : '${s('Last')} ${quizSlice.length} ${s('quizzes')}',
          child: quizSlice.isEmpty
              ? _NoData(
                  text: s('Take a vocabulary quiz to start tracking scores.'),
                )
              : LineChart(
                  LineChartData(
                    minY: 0,
                    maxY: 100,
                    gridData: FlGridData(
                      show: true,
                      drawVerticalLine: false,
                      horizontalInterval: 25,
                      getDrawingHorizontalLine: (_) =>
                          FlLine(color: t.stroke, strokeWidth: 1),
                    ),
                    titlesData: const FlTitlesData(show: false),
                    borderData: FlBorderData(show: false),
                    lineTouchData: LineTouchData(
                      touchTooltipData: LineTouchTooltipData(
                        getTooltipColor: (_) => t.cardHi,
                        getTooltipItems: (spots) => spots
                            .map(
                              (s) => LineTooltipItem(
                                '${quizSlice[s.x.toInt()]['day_title'] ?? ''}\n${s.y.toStringAsFixed(0)}%',
                                TextStyle(
                                  color: t.textHi,
                                  fontSize: 11,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                            )
                            .toList(),
                      ),
                    ),
                    lineBarsData: [
                      LineChartBarData(
                        spots: [
                          for (var i = 0; i < quizSlice.length; i++)
                            FlSpot(
                              i.toDouble(),
                              (quizSlice[i]['score'] as num?)?.toDouble() ?? 0,
                            ),
                        ],
                        isCurved: true,
                        preventCurveOverShooting: true,
                        barWidth: 2.5,
                        color: t.sky,
                        dotData: FlDotData(
                          show: true,
                          getDotPainter: (_, __, ___, ____) =>
                              FlDotCirclePainter(
                                radius: 3,
                                color: t.card,
                                strokeWidth: 2,
                                strokeColor: t.sky,
                              ),
                        ),
                        belowBarData: BarAreaData(
                          show: true,
                          gradient: LinearGradient(
                            begin: Alignment.topCenter,
                            end: Alignment.bottomCenter,
                            colors: [
                              t.sky.withValues(alpha: 0.2),
                              t.sky.withValues(alpha: 0),
                            ],
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
        ),
        const SizedBox(height: 14),

        // ── Exam scores ──────────────────────────────────────────────────
        _ChartCard(
          title: s('Exam Scores (Average)'),
          subtitle: examResults.isEmpty
              ? s('No results yet')
              : '${examResults.length} ${examResults.length == 1 ? s('subject') : s('subjects')}',
          child: examResults.isEmpty
              ? _NoData(text: s('Exam results will appear here once published.'))
              : BarChart(
                  BarChartData(
                    minY: 0,
                    maxY: 100,
                    gridData: const FlGridData(show: false),
                    borderData: FlBorderData(show: false),
                    barTouchData: BarTouchData(enabled: false),
                    titlesData: FlTitlesData(
                      leftTitles: const AxisTitles(),
                      topTitles: const AxisTitles(),
                      rightTitles: const AxisTitles(),
                      bottomTitles: AxisTitles(
                        sideTitles: SideTitles(
                          showTitles: true,
                          reservedSize: 30,
                          getTitlesWidget: (v, _) {
                            final i = v.toInt();
                            if (i < 0 || i >= examResults.length) {
                              return const SizedBox.shrink();
                            }
                            return Padding(
                              padding: const EdgeInsets.only(top: 6),
                              child: Text(
                                (examResults[i]['group_name'] ?? '').toString(),
                                style: TextStyle(
                                  fontSize: 9.5,
                                  color: t.textLow,
                                ),
                                maxLines: 2,
                                textAlign: TextAlign.center,
                              ),
                            );
                          },
                        ),
                      ),
                    ),
                    barGroups: [
                      for (var i = 0; i < examResults.length; i++)
                        BarChartGroupData(
                          x: i,
                          barRods: [
                            BarChartRodData(
                              toY:
                                  (examResults[i]['total'] as num?)
                                      ?.toDouble() ??
                                  0,
                              width: 26,
                              borderRadius: BorderRadius.circular(6),
                              gradient: LinearGradient(
                                begin: Alignment.bottomCenter,
                                end: Alignment.topCenter,
                                colors: [
                                  t.accent.withValues(alpha: 0.6),
                                  t.accent,
                                ],
                              ),
                              backDrawRodData: BackgroundBarChartRodData(
                                show: true,
                                toY: 100,
                                color: t.inset.withValues(alpha: 0.4),
                              ),
                            ),
                          ],
                        ),
                    ],
                  ),
                ),
        ),
        const SizedBox(height: 14),

        // ── Attendance progress ──────────────────────────────────────────
        IceCard(
          onTap: () => context.go('/student/attendance'),
          child: Row(
            children: [
              ProgressRing(
                value: attendancePct / 100,
                size: 74,
                strokeWidth: 7,
                center: Text(
                  '${attendancePct.toStringAsFixed(0)}%',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w800,
                    color: t.textHi,
                  ),
                ),
              ),
              const SizedBox(width: 18),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      s('Attendance Progress'),
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w800,
                        color: t.textHi,
                      ),
                    ),
                    const SizedBox(height: 3),
                    Text(
                      s('Open the Attendance Hub for the full calendar.'),
                      style: TextStyle(fontSize: 12.5, color: t.textMid),
                    ),
                  ],
                ),
              ),
              Icon(Icons.chevron_right_rounded, color: t.textLow),
            ],
          ),
        ),
      ],
    );
  }
}

class _ChartCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final Widget child;
  const _ChartCard({
    required this.title,
    required this.subtitle,
    required this.child,
  });

  @override
  Widget build(BuildContext context) {
    final t = context.ice;
    return IceCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: TextStyle(
              fontSize: 16.5,
              fontWeight: FontWeight.w800,
              color: t.textHi,
            ),
          ),
          const SizedBox(height: 2),
          Text(subtitle, style: TextStyle(fontSize: 12.5, color: t.textMid)),
          const SizedBox(height: 18),
          SizedBox(height: 150, child: child),
        ],
      ),
    );
  }
}

class _NoData extends StatelessWidget {
  final String text;
  const _NoData({required this.text});

  @override
  Widget build(BuildContext context) => Center(
    child: Text(
      text,
      textAlign: TextAlign.center,
      style: TextStyle(color: context.ice.textLow, fontSize: 13),
    ),
  );
}
