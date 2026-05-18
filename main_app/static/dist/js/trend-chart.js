/* ════════════════════════════════════════════════════════════════════
   Iceberg Trend Chart — premium line graph helper
   Usage:
     IcebergTrend.line({
       canvas: 'myChart',
       labels: ['Sep 5', 'Sep 12', ...],
       series: [
         { name: 'Score', data: [85, 90, ...], color: '#06B6D4' },
       ],
       suffix: '%',
       yMax: 100,
     });
══════════════════════════════════════════════════════════════════════ */
(function (global) {
  'use strict';

  function isDark() {
    return document.body.classList.contains('dark-mode');
  }

  function makeGradient(ctx, color, height) {
    var rgb = hexToRgb(color);
    var g = ctx.createLinearGradient(0, 0, 0, height);
    g.addColorStop(0,   'rgba(' + rgb + ', 0.32)');
    g.addColorStop(0.5, 'rgba(' + rgb + ', 0.08)');
    g.addColorStop(1,   'rgba(' + rgb + ', 0.0)');
    return g;
  }

  function hexToRgb(hex) {
    var h = hex.replace('#', '');
    if (h.length === 3) h = h.split('').map(function (c) { return c + c; }).join('');
    var n = parseInt(h, 16);
    return ((n >> 16) & 255) + ', ' + ((n >> 8) & 255) + ', ' + (n & 255);
  }

  function line(cfg) {
    var canvas = typeof cfg.canvas === 'string'
      ? document.getElementById(cfg.canvas)
      : cfg.canvas;
    if (!canvas || typeof Chart === 'undefined') return null;

    var ctx = canvas.getContext('2d');
    var height = canvas.height || 200;
    var dark = isDark();

    var datasets = cfg.series.map(function (s) {
      var c = s.color || '#06B6D4';
      return {
        label: s.name || '',
        data: s.data,
        borderColor: c,
        backgroundColor: cfg.fill === false ? 'transparent' : makeGradient(ctx, c, height),
        borderWidth: 2.5,
        fill: cfg.fill !== false,
        tension: 0.4,
        cubicInterpolationMode: 'monotone',
        pointRadius: s.data.map(function (v) { return v !== null ? 3.5 : 0; }),
        pointBackgroundColor: c,
        pointHoverRadius: 6,
        pointHoverBackgroundColor: '#fff',
        pointHoverBorderColor: c,
        pointHoverBorderWidth: 3,
        spanGaps: true,
      };
    });

    var suffix = cfg.suffix || '';
    var prefix = cfg.prefix || '';
    var yMax   = cfg.yMax   || (cfg.suffix === '%' ? 100 : undefined);
    var yMin   = cfg.yMin   || 0;

    return new Chart(ctx, {
      type: 'line',
      data: {
        labels: cfg.labels,
        datasets: datasets,
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: {
          duration: 1100,
          easing: 'easeOutQuart',
        },
        interaction: {
          mode: 'index',
          intersect: false,
        },
        plugins: {
          legend: {
            display: cfg.series.length > 1,
            position: 'bottom',
            labels: {
              boxWidth: 8,
              boxHeight: 8,
              usePointStyle: true,
              pointStyle: 'circle',
              color: dark ? '#94AFC8' : '#64748B',
              font: { size: 11, weight: '600', family: 'Inter, sans-serif' },
              padding: 14,
            },
          },
          tooltip: {
            backgroundColor: dark ? 'rgba(7,15,28,0.96)' : 'rgba(12,31,69,0.95)',
            titleColor: '#fff',
            titleFont: { size: 11, weight: '600', family: 'Inter, sans-serif' },
            titleMarginBottom: 6,
            bodyColor: '#67E8F9',
            bodyFont: { size: 14, weight: '700', family: 'Inter, sans-serif' },
            bodySpacing: 4,
            padding: 12,
            cornerRadius: 12,
            displayColors: false,
            caretSize: 6,
            caretPadding: 8,
            borderColor: 'rgba(6,182,212,0.3)',
            borderWidth: 1,
            callbacks: {
              label: function (item) {
                var name = item.dataset.label ? item.dataset.label + ': ' : '';
                return name + prefix + item.parsed.y + suffix;
              },
            },
          },
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: dark ? '#4A6080' : '#94A3B8',
              font: { size: 10, weight: '500', family: 'Inter, sans-serif' },
              maxRotation: 0,
              autoSkip: true,
              autoSkipPadding: 14,
            },
            border: { display: false },
          },
          y: {
            beginAtZero: true,
            min: yMin,
            max: yMax,
            grid: {
              color: dark ? 'rgba(255,255,255,0.04)' : 'rgba(12,31,69,0.06)',
              drawBorder: false,
              tickBorderDash: [4, 4],
            },
            ticks: {
              color: dark ? '#4A6080' : '#94A3B8',
              font: { size: 10, weight: '500', family: 'Inter, sans-serif' },
              padding: 8,
              callback: function (v) { return prefix + v + suffix; },
              maxTicksLimit: 5,
            },
            border: { display: false },
          },
        },
      },
    });
  }

  global.IcebergTrend = { line: line };
})(window);
