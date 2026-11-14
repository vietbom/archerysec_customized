(function () {
    'use strict';
    if (!window.Chart) return;
    Chart.defaults.global.defaultFontFamily = "'Inter', 'Segoe UI', sans-serif";
    Chart.defaults.global.defaultFontColor = '#64748b';
    Chart.defaults.global.responsive = true;
    Chart.defaults.global.maintainAspectRatio = false;
    Chart.defaults.global.legend.position = 'bottom';
    Chart.defaults.global.legend.labels.usePointStyle = true;
    Chart.defaults.global.legend.labels.boxWidth = 8;
    Chart.defaults.global.legend.labels.padding = 18;
    Chart.defaults.horizontalBar.legend = {display: false};
    Chart.defaults.horizontalBar.scales.xAxes[0].ticks = {beginAtZero: true, precision: 0};
    Chart.defaults.horizontalBar.scales.xAxes[0].gridLines = {color: '#edf2f7'};
    Chart.defaults.global.animation.duration = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 450;
    Chart.plugins.register({
        afterDraw: function (chart) {
            var hasData = chart.data.datasets.some(function (set) {
                return set.data.some(function (value) { return Number(value) > 0; });
            });
            if (hasData) return;
            var ctx = chart.chart.ctx;
            var area = chart.chartArea;
            ctx.save();
            ctx.fillStyle = '#64748b';
            ctx.font = '13px Segoe UI, sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText('No open findings', (area.left + area.right) / 2, (area.top + area.bottom) / 2);
            ctx.restore();
        }
    });
}());
