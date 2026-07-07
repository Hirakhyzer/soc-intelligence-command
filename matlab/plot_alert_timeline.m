function plot_alert_timeline(results_dir)
%PLOT_ALERT_TIMELINE Plot a local synthetic or authorized SOC alert timeline.
% Usage: plot_alert_timeline('outputs')

if nargin < 1
    results_dir = fullfile('..', 'outputs');
end
input_path = fullfile(results_dir, 'results', 'synthetic_alerts.csv');
if ~isfile(input_path)
    error('Missing %s. Run the synthetic SOC laboratory first.', input_path);
end
T = readtable(input_path);
T.timestamp = datetime(T.timestamp, 'InputFormat', "yyyy-MM-dd'T'HH:mm:ssXXX", 'TimeZone', 'UTC');
figure('Color', 'w', 'Position', [100 100 1000 430]);
gscatter(T.timestamp, T.risk_score, T.rule_id);
grid on;
xlabel('Time (UTC)'); ylabel('Risk score');
title('Synthetic SOC prioritized alert timeline');
legend('Location', 'best');
exportgraphics(gcf, fullfile(results_dir, 'figures', 'synthetic_alert_timeline_matlab.png'), 'Resolution', 250);
end
