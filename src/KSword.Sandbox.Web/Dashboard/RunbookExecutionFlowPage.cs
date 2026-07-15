using System.Net;
using System.Text;
using KSword.Sandbox.Abstractions;

namespace KSword.Sandbox.Web.Dashboard;

/// <summary>
/// Inputs: one planned job plus an optional persisted runbook execution result.
/// Processing: renders a separate operator page for the provider execution flow
/// without exposing PowerShell command text or stdout/stderr on the main
/// dashboard. Return behavior: returns a complete HTML document.
/// </summary>
internal static class RunbookExecutionFlowPage
{
    /// <summary>
    /// Renders the human-facing execution flow page.
    /// Inputs are job metadata and optional execution results; processing
    /// merges planned runbook steps with per-step status; return is HTML text.
    /// </summary>
    internal static string Render(AnalysisJob job, SandboxRunbookExecutionResult? execution)
    {
        var jobId = job.JobId.ToString("D");
        var title = "进度页（执行流程） / Progress page (execution flow)";
        var rows = RenderStepCards(job, execution);
        var summary = RenderSummary(job, execution);
        var liveEventsLink = $"<a class=\"button secondary\" href=\"/jobs/{Attr(jobId)}/live-events\" target=\"_blank\" rel=\"noopener\" data-zh=\"实时原始事件监控\" data-en=\"Live raw event monitor\">实时原始事件监控</a>";
        var hasAnyReport = !string.IsNullOrWhiteSpace(job.HtmlReportPath)
            || !string.IsNullOrWhiteSpace(job.HtmlReportZhPath)
            || !string.IsNullOrWhiteSpace(job.HtmlReportEnPath);
        var reportLink = !hasAnyReport
            ? "<span class=\"muted\" data-zh=\"暂无报告\" data-en=\"No report yet\">暂无报告</span>"
            : $"<a class=\"button\" href=\"/api/jobs/{Attr(jobId)}/report/html?lang=zh\" target=\"_blank\" rel=\"noopener\" data-zh=\"打开中文报告\" data-en=\"Open Chinese report\">打开中文报告</a><a class=\"button secondary\" href=\"/api/jobs/{Attr(jobId)}/report/html?lang=en\" target=\"_blank\" rel=\"noopener\" data-zh=\"打开英文报告\" data-en=\"Open English report\">打开英文报告</a>";

        return $$"""
        <!doctype html>
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <title>{{Html(title)}} - KSword Sandbox</title>
          <style>
            :root { --blue:#43A0FF; --blue-dark:#0B6FCC; --line:#dbeafe; color-scheme: light; }
            body { background: radial-gradient(circle at 8% 4%,rgba(67,160,255,.18),transparent 27%),linear-gradient(180deg,#f4f9ff,#f8fafc); color: #111827; font-family: Segoe UI, Microsoft YaHei UI, Arial, sans-serif; margin: 0; }
            header { background: radial-gradient(circle at 84% 12%,rgba(67,160,255,.55),transparent 30%),linear-gradient(135deg, #08111f, #0B6FCC); color: white; padding: 24px 34px; }
            main { max-width: 1080px; margin: 22px auto 54px; padding: 0 22px; }
            .topbar { align-items: center; display: flex; gap: 12px; justify-content: space-between; }
            .actions { align-items: center; display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }
            a.button, button { background: var(--blue); border: 0; border-radius:2px; color: white; cursor: pointer; display: inline-block; font-weight: 700; padding: 9px 14px; text-decoration: none; }
            a.secondary, button.secondary { background: #334155; }
            section, article.step { background: white; border: 1px solid var(--line); border-radius:2px; box-shadow:none; margin-bottom: 14px; padding: 18px; }
            .grid { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(0, 1fr)); }
            .metric { background: #f8fafc; border: 1px solid #e2e8f0; border-radius:2px; padding: 12px; }
            .metric strong { display: block; font-size: 12px; color: #64748b; margin-bottom: 6px; }
            .step { align-items: flex-start; display: grid; gap: 14px; grid-template-columns: 64px minmax(0, 1fr) 150px; }
            .num { align-items: center; background: #e7f3ff; border: 1px solid rgba(67,160,255,.35); border-radius:2px; color: #075985; display: inline-flex; font-weight: 800; height: 42px; justify-content: center; width: 42px; }
            .pill { background: #e7f3ff; border: 1px solid rgba(67,160,255,.35); border-radius:2px; color: #075985; display: inline-block; font-size: 12px; font-weight: 800; padding: 4px 9px; }
            .ok { background: #dcfce7; color: #166534; }
            .failed { background: #fee2e2; color: #991b1b; }
            .skipped { background: #fef3c7; color: #92400e; }
            .pending { background: #e2e8f0; color: #475569; }
            .muted { color: #64748b; }
            code { background: #f1f5f9; border-radius:2px; padding: 2px 5px; word-break: break-all; }
            [data-copy], code { cursor: copy; }
            [data-copy]:hover, code:hover { outline: 1px dashed var(--blue); outline-offset: 2px; }
            .toast { background: #0f172a; border-radius:2px; bottom: 22px; color: white; left: 50%; opacity: 0; padding: 10px 16px; pointer-events: none; position: fixed; transform: translate(-50%, 12px); transition: opacity .15s ease, transform .15s ease; }
            .toast.visible { opacity: .96; transform: translate(-50%, 0); }

            /* Square, flat operator theme: keep visual nesting shallow. */
            section, article, .metric, .pill, button, a.button, a.buttonlink, input, code, pre, .pathbox, .callout, .report-notice, .report-entry, .workspace-tab, .tab-button, .tab-panel, details, .progress-box, .progress-bar, .progress-fill, .stage, .recent-job-card, .runbook-step, .empty, .table-wrap, .step-card, .report-ready, .toast, .num { border-radius: 0 !important; }
            section, article, .metric, .pathbox, .callout, .report-notice, .report-entry, .tab-panel, .progress-box, .stage, .recent-job-card, .runbook-step, .step-card, .report-ready { box-shadow: none !important; }
            .pill, button, a.button, a.buttonlink { box-shadow: none !important; }
            @media (max-width: 820px) { .grid { grid-template-columns: 1fr; } .step { grid-template-columns: 48px minmax(0, 1fr); } .step-status { grid-column: 2; } }
          </style>
        </head>
        <body>
          <header>
            <div class="topbar">
              <div>
                <h1 data-zh="进度页（执行流程）" data-en="Progress page (execution flow)">进度页（执行流程）</h1>
                <p data-zh="这里只展示人能理解的执行进度，不展示命令行细节、PowerShell 命令、stdout 或 stderr。" data-en="This page shows human-readable execution progress only; command-line details, PowerShell commands, stdout, and stderr stay hidden.">这里只展示人能理解的执行进度，不展示命令行细节、PowerShell 命令、stdout 或 stderr。</p>
                <p data-zh="报告按钮会在报告生成后可用；实时原始事件请进入独立监控页，最终结论以报告页为准。" data-en="Report buttons are useful after report generation. Use the standalone monitor for live raw events, and treat the report page as the final source of truth.">报告按钮会在报告生成后可用；实时原始事件请进入独立监控页，最终结论以报告页为准。</p>
              </div>
              <button class="secondary" id="langToggle" type="button">EN</button>
            </div>
            <div class="actions">
              <a class="button secondary" href="/" data-zh="返回主界面" data-en="Back to dashboard">返回主界面</a>
              {{reportLink}}
              {{liveEventsLink}}
            </div>
          </header>
          <main>
            <section>
              <h2 data-zh="任务概览" data-en="Job summary">任务概览</h2>
              {{summary}}
            </section>
            <section>
              <h2 data-zh="步骤状态" data-en="Step status">步骤状态</h2>
              <p class="muted" data-zh="如需排障，请复制 runbook-execution.json 路径查看本机文件；主界面不再铺开 1~16 步。" data-en="For troubleshooting, copy the runbook-execution.json path and inspect the local file; the dashboard no longer expands all steps inline.">如需排障，请复制 runbook-execution.json 路径查看本机文件；主界面不再铺开 1~16 步。</p>
              {{rows}}
            </section>
          </main>
          <div id="copyToast" class="toast" role="status" aria-live="polite"></div>
          <script>
            let lang = localStorage.getItem('ksword-lang') || 'zh';
            const button = document.getElementById('langToggle');
            function applyLang() {
              document.documentElement.lang = lang === 'en' ? 'en' : 'zh-CN';
              document.querySelectorAll('[data-zh][data-en]').forEach(el => {
                el.textContent = lang === 'en' ? el.getAttribute('data-en') : el.getAttribute('data-zh');
              });
              button.textContent = lang === 'en' ? '中文' : 'EN';
            }
            button.addEventListener('click', () => {
              lang = lang === 'en' ? 'zh' : 'en';
              localStorage.setItem('ksword-lang', lang);
              applyLang();
            });
            document.addEventListener('contextmenu', event => {
              const target = event.target.closest ? event.target.closest('[data-copy], code, h1, h2, h3, p, span, a') : null;
              if (!target) { return; }
              const value = target.getAttribute('data-copy') || target.innerText || target.textContent || '';
              if (!value.trim()) { return; }
              event.preventDefault();
              copyText(value);
            });
            function fallbackCopyText(text) {
              const area = document.createElement('textarea');
              area.value = text;
              area.setAttribute('readonly', 'readonly');
              area.style.position = 'fixed';
              area.style.left = '-9999px';
              document.body.appendChild(area);
              area.select();
              document.execCommand('copy');
              document.body.removeChild(area);
            }
            function copyText(text) {
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(() => showToast(localStorage.getItem('ksword-lang') === 'en' ? 'Copied.' : '已复制。')).catch(() => {
                  fallbackCopyText(text);
                  showToast(localStorage.getItem('ksword-lang') === 'en' ? 'Copied.' : '已复制。');
                });
                return;
              }

              fallbackCopyText(text);
              showToast(localStorage.getItem('ksword-lang') === 'en' ? 'Copied.' : '已复制。');
            }
            function showToast(text) {
              const toast = document.getElementById('copyToast');
              toast.textContent = text;
              toast.classList.add('visible');
              setTimeout(() => toast.classList.remove('visible'), 1200);
            }
            applyLang();
          </script>
        </body>
        </html>
        """;
    }

    private static string RenderSummary(AnalysisJob job, SandboxRunbookExecutionResult? execution)
    {
        var jobId = job.JobId.ToString("D");
        var runbookSteps = job.Runbook?.Steps.Count ?? 0;
        var executionPath = job.RunbookExecutionResultPath ?? string.Empty;
        var provider = execution?.Provider ?? job.Runbook?.Provider ?? job.Submission.Provider ?? VirtualizationProvider.HyperV;
        var targetVmName = job.Runbook?.TargetVmName ?? job.Submission.GoldenVmName ?? string.Empty;
        var baselineName = job.Runbook?.BaselineName ?? job.Submission.GoldenSnapshotName ?? string.Empty;
        var machineDefinitionPath = job.Runbook?.MachineDefinitionPath ?? job.Submission.MachineDefinitionPath ?? string.Empty;
        var providerResourceMetric = provider is VirtualizationProvider.HyperV
            ? string.Empty
            : $"<div class=\"metric\"><strong data-zh=\"{(provider is VirtualizationProvider.VMware ? "VMX 路径" : "基础磁盘路径")}\" data-en=\"{(provider is VirtualizationProvider.VMware ? "VMX path" : "Base disk path")}\">{(provider is VirtualizationProvider.VMware ? "VMX 路径" : "基础磁盘路径")}</strong><code data-copy=\"{Attr(machineDefinitionPath)}\">{Html(string.IsNullOrWhiteSpace(machineDefinitionPath) ? "-" : machineDefinitionPath)}</code></div>";
        var qemuFormatMetric = provider is VirtualizationProvider.Qemu
            ? $"<div class=\"metric\"><strong data-zh=\"QEMU 磁盘格式\" data-en=\"QEMU disk format\">QEMU 磁盘格式</strong><span class=\"pill\" data-copy=\"{Attr(job.Runbook?.QemuDiskFormat ?? job.Submission.QemuDiskFormat ?? string.Empty)}\">{Html(job.Runbook?.QemuDiskFormat ?? job.Submission.QemuDiskFormat ?? "-")}</span></div>"
            : string.Empty;
        var jobStatus = FormatAnalysisStatus(job.Status);
        var executionState = execution is null
            ? "未执行 / not executed"
            : execution.Success
                ? "成功 / success"
                : execution.WasCanceled
                    ? "已取消 / canceled"
                    : "失败 / failed";
        var samplePath = job.Sample?.FullPath ?? job.Submission.SamplePath;

        return $$"""
          <div class="grid">
            <div class="metric"><strong data-zh="任务 / Job" data-en="Job">任务 / Job</strong><code data-copy="{{Attr(jobId)}}">{{Html(jobId)}}</code></div>
            <div class="metric"><strong data-zh="虚拟化后端" data-en="Virtualization provider">虚拟化后端</strong><span class="pill" data-copy="{{Attr(provider.ToString())}}">{{Html(provider.ToString())}}</span></div>
            <div class="metric"><strong data-zh="运行目标 VM" data-en="Runtime VM target">运行目标 VM</strong><code data-copy="{{Attr(targetVmName)}}">{{Html(string.IsNullOrWhiteSpace(targetVmName) ? "-" : targetVmName)}}</code></div>
            <div class="metric"><strong data-zh="干净基线" data-en="Clean baseline">干净基线</strong><code data-copy="{{Attr(baselineName)}}">{{Html(string.IsNullOrWhiteSpace(baselineName) ? "-" : baselineName)}}</code></div>
            {{providerResourceMetric}}
            {{qemuFormatMetric}}
            <div class="metric"><strong data-zh="样本" data-en="Sample">样本</strong><code data-copy="{{Attr(samplePath)}}">{{Html(samplePath)}}</code></div>
            <div class="metric"><strong data-zh="任务状态" data-en="Job status">任务状态</strong><span class="pill" data-copy="{{Attr(jobStatus)}}">{{Html(jobStatus)}}</span></div>
            <div class="metric"><strong data-zh="执行状态" data-en="Execution status">执行状态</strong><span class="pill {{StatusClass(execution)}}">{{Html(executionState)}}</span></div>
            <div class="metric"><strong data-zh="计划步骤" data-en="Planned steps">计划步骤</strong><span>{{runbookSteps}}</span></div>
            <div class="metric"><strong data-zh="已执行" data-en="Executed">已执行</strong><span>{{(execution?.ExecutedSteps.ToString() ?? "-")}}</span></div>
            <div class="metric"><strong data-zh="耗时" data-en="Duration">耗时</strong><span>{{Html(FormatDuration(execution?.Duration))}}</span></div>
            <div class="metric"><strong>runbook-execution.json</strong>{{(string.IsNullOrWhiteSpace(executionPath) ? "<span class=\"muted\">-</span>" : $"<code data-copy=\"{Attr(executionPath)}\">{Html(executionPath)}</code>")}}</div>
          </div>
          {{(string.IsNullOrWhiteSpace(execution?.Message) ? string.Empty : $"<p class=\"muted\" data-copy=\"{Attr(execution.Message)}\">{Html(execution.Message)}</p>")}}
        """;
    }

    private static string RenderStepCards(AnalysisJob job, SandboxRunbookExecutionResult? execution)
    {
        if (job.Runbook is null || job.Runbook.Steps.Count == 0)
        {
            return "<p class=\"muted\" data-zh=\"当前任务没有执行计划。\" data-en=\"This job has no execution plan.\">当前任务没有执行计划。</p>";
        }

        var resultsByIndex = (execution?.StepResults ?? Array.Empty<SandboxRunbookStepExecutionResult>())
            .ToDictionary(step => step.StepIndex, step => step);
        var builder = new StringBuilder();

        for (var index = 0; index < job.Runbook.Steps.Count; index++)
        {
            var step = job.Runbook.Steps[index];
            resultsByIndex.TryGetValue(index, out var result);
            var canceled = result is not null && IsCanceledStepResult(result);
            var statusText = result is null
                ? "未执行 / pending"
                : result.Skipped ? "已记录 / recorded" : result.Success ? "成功 / success" : canceled ? "已取消 / canceled" : "失败 / failed";
            var css = result is null ? "pending" : result.Skipped ? "skipped" : result.Success ? "ok" : "failed";
            var message = string.IsNullOrWhiteSpace(result?.Message)
                ? string.Empty
                : $"<p class=\"muted\" data-copy=\"{Attr(result.Message)}\">{Html(result.Message)}</p>";

            builder.Append($$"""
              <article class="step">
                <div><span class="num">{{index + 1}}</span></div>
                <div>
                  <h3 data-copy="{{Attr(step.Title)}}">{{Html(step.Title)}}</h3>
                  <p class="muted"><code data-copy="{{Attr(step.Id)}}">{{Html(step.Id)}}</code></p>
                  {{message}}
                </div>
                <div class="step-status">
                  <span class="pill {{css}}" data-copy="{{Attr(statusText)}}">{{Html(statusText)}}</span>
                  <p class="muted">{{Html(FormatDuration(result?.Duration))}}</p>
                  {{(result?.ExitCode is null ? string.Empty : $"<p class=\"muted\">退出码 / Exit: {result.ExitCode}</p>")}}
                </div>
              </article>
            """);
        }

        return builder.ToString();
    }

    private static string StatusClass(SandboxRunbookExecutionResult? execution)
    {
        return execution is null ? "pending" : execution.Success ? "ok" : "failed";
    }

    private static bool IsCanceledStepResult(SandboxRunbookStepExecutionResult result)
    {
        return !result.Success &&
            ((result.Message?.Contains("canceled", StringComparison.OrdinalIgnoreCase) ?? false) ||
             (result.Message?.Contains("cancelled", StringComparison.OrdinalIgnoreCase) ?? false));
    }

    private static string FormatDuration(TimeSpan? duration)
    {
        if (duration is null)
        {
            return "-";
        }

        return duration.Value.TotalSeconds < 1
            ? $"{duration.Value.TotalMilliseconds:N0} ms"
            : $"{duration.Value.TotalSeconds:N1} s";
    }

    private static string FormatAnalysisStatus(AnalysisStatus status)
    {
        return status switch
        {
            AnalysisStatus.Queued => "排队中 / queued",
            AnalysisStatus.Planning => "规划中 / planning",
            AnalysisStatus.Planned => "已规划 / planned",
            AnalysisStatus.Running => "运行中 / running",
            AnalysisStatus.Completed => "已完成 / completed",
            AnalysisStatus.Failed => "失败 / failed",
            _ => $"{status}"
        };
    }

    private static string Html(string? value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty);
    }

    private static string Attr(string? value)
    {
        return WebUtility.HtmlEncode(value ?? string.Empty).Replace("\"", "&quot;", StringComparison.Ordinal);
    }
}
