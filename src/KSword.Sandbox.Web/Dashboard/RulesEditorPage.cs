using System.Net;
using System.Text.Encodings.Web;
using System.Text.Json;
using KSword.Sandbox.Core.Rules;

namespace KSword.Sandbox.Web.Dashboard;

/// <summary>Renders the bilingual, flat-style behavior-rule editor used by the local dashboard.</summary>
internal static class RulesEditorPage
{
    internal static string Render(BehaviorRuleSet rules, string? rulesPath)
    {
        var json = JsonSerializer.Serialize(rules, new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Encoder = JavaScriptEncoder.Default
        });
        var path = WebUtility.HtmlEncode(rulesPath ?? string.Empty);
        return $$"""
        <!doctype html>
        <html lang="zh-CN">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width,initial-scale=1">
          <title>规则编辑器 / Rule editor - KSword Sandbox</title>
          <style>
            :root { --page:#f7f8fa; --surface:#fff; --subtle:#f5f5f5; --subtle-strong:#ededed; --ink:#151515; --muted:#757575; --muted-soft:#a5a5a5; --line:#ededed; --accent:#1f78ff; --accent-soft:#e5f0ff; --success:#16704a; --warn:#946200; --danger:#a32020; color-scheme:light; }
            * { box-sizing:border-box; }
            body { background:var(--page); color:var(--ink); font-family:Inter,"Microsoft YaHei UI","Segoe UI",Arial,sans-serif; font-size:14px; line-height:1.55; margin:0; }
            header { background:var(--surface); border-bottom:1px solid var(--line); padding:30px max(20px,calc((100% - 1240px)/2)); }
            header .head { align-items:flex-start; display:flex; gap:24px; justify-content:space-between; }
            header .eyebrow { color:var(--accent); font-family:Consolas,"JetBrains Mono",monospace; font-size:11px; font-weight:600; letter-spacing:.04em; margin:0 0 8px; text-transform:uppercase; }
            header .intro { max-width:760px; }
            main { margin:0 auto; max-width:1240px; padding:28px 20px 72px; }
            h1,h2,h3 { color:var(--ink); line-height:1.25; margin:0 0 8px; }
            h1 { font-size:clamp(26px,3vw,38px); font-weight:500; letter-spacing:-.02em; }
            h2 { font-size:21px; font-weight:500; }
            h3 { font-size:17px; font-weight:500; }
            p { margin:8px 0; }
            .muted { color:var(--muted); }
            .small { font-size:12px; }
            section { background:var(--surface); border:1px solid var(--line); border-radius:10px; box-shadow:0 1px 2px rgba(15,23,42,.03); margin:0 0 20px; padding:22px; }
            .toolbar,.actions { align-items:center; display:flex; flex-wrap:wrap; gap:8px; }
            .toolbar { justify-content:space-between; }
            .toolbar-group { align-items:center; display:flex; flex-wrap:wrap; gap:8px; }
            .toolbar-group.primary-actions { flex:1 1 420px; }
            .toolbar-group.secondary-actions { justify-content:flex-end; }
            button,a.button { align-items:center; background:var(--accent); border:1px solid var(--accent); border-radius:7px; color:#fff; cursor:pointer; display:inline-flex; font:inherit; font-weight:600; justify-content:center; line-height:1.25; min-height:36px; padding:8px 13px; text-decoration:none; }
            button:hover,a.button:hover { background:#155fc9; border-color:#155fc9; }
            button.secondary,a.secondary,button.ghost { background:var(--surface); border-color:#d6dbe1; color:var(--ink); }
            button.secondary:hover,a.secondary:hover,button.ghost:hover { background:var(--subtle); border-color:#b8bec7; }
            button.danger { background:#fff; border-color:#efb5b5; color:var(--danger); }
            button.danger:hover { background:#fff1f1; border-color:#d98a8a; }
            button:disabled { cursor:wait; opacity:.6; }
            button:focus-visible,a:focus-visible,input:focus,textarea:focus,select:focus { border-color:var(--accent); outline:2px solid #b8d6ff; outline-offset:1px; }
            .path { background:var(--subtle); border:1px solid var(--line); border-radius:7px; color:var(--muted); font-family:Consolas,"JetBrains Mono",monospace; margin:16px 0 0; overflow-wrap:anywhere; padding:10px 12px; }
            .status { border-left:3px solid var(--line); margin-top:12px; min-height:24px; padding:9px 10px; }
            .status.ok { background:#eefbf4; border-color:var(--success); color:var(--success); }
            .status.error { background:#fff1f1; border-color:var(--danger); color:var(--danger); }
            .status.warn { background:#fff8e8; border-color:var(--warn); color:var(--warn); }
            .rules { display:grid; gap:14px; }
            .rule-card { background:var(--surface); border:1px solid var(--line); border-radius:10px; box-shadow:0 1px 2px rgba(15,23,42,.03); padding:20px; }
            .rule-head { align-items:flex-start; border-bottom:1px solid var(--line); display:flex; gap:16px; justify-content:space-between; margin-bottom:18px; padding-bottom:14px; }
            .rule-index { color:var(--muted-soft); font-family:Consolas,"JetBrains Mono",monospace; font-size:11px; font-weight:600; margin-bottom:4px; text-transform:uppercase; }
            .rule-head h3 { overflow-wrap:anywhere; }
            .grid { display:grid; gap:16px; grid-template-columns:repeat(12,minmax(0,1fr)); }
            .grid > div { grid-column:span 3; min-width:0; }
            .wide { grid-column:span 6 !important; }
            .full { grid-column:1/-1; }
            label { display:block; font-size:13px; font-weight:600; margin-bottom:6px; }
            input,textarea,select { background:var(--surface); border:1px solid #d6dbe1; border-radius:6px; color:var(--ink); font:inherit; padding:9px 10px; width:100%; }
            textarea { min-height:84px; resize:vertical; }
            textarea.long { min-height:118px; }
            .field-help { color:var(--muted-soft); font-size:11px; margin-top:5px; }
            .check { align-items:center; display:flex; gap:8px; min-height:38px; }
            .check input { width:auto; }
            .empty { border:1px dashed #cfd4dc; border-radius:8px; color:var(--muted); padding:32px 22px; text-align:center; }
            .import-label { cursor:pointer; }
            #importFile { display:none; }
            @media(max-width:900px) { .grid { grid-template-columns:repeat(6,minmax(0,1fr)); } .grid > div { grid-column:span 3; } .wide { grid-column:span 6 !important; } }
            @media(max-width:560px) { header { padding-left:16px; padding-right:16px; } header .head { flex-direction:column; } header .head .secondary { align-self:flex-start; } main { padding:20px 14px 56px; } section,.rule-card { padding:16px; } .toolbar,.toolbar-group { align-items:stretch; flex-direction:column; } .toolbar-group,.toolbar-group.primary-actions { width:100%; } .toolbar-group button,.toolbar-group .button,.import-label { width:100%; } .grid,.grid > div,.wide { display:grid; grid-column:1/-1 !important; } .rule-head { display:block; } .rule-head .actions { margin-top:12px; } .rule-head .actions button { width:100%; } }
          </style>
        </head>
        <body>
          <header>
            <div class="head">
              <div class="intro">
                <p class="eyebrow">KSword Sandbox · local workspace</p>
                <h1 data-zh="行为规则编辑器" data-en="Behavior rule editor">行为规则编辑器</h1>
                <p class="muted" data-zh="以卡片方式编辑检测规则；保存后立即供本机 Web Host 使用。" data-en="Edit detection rules as cards; saved changes are immediately available to this local Web Host.">以卡片方式编辑检测规则；保存后立即供本机 Web Host 使用。</p>
              </div>
              <button class="secondary" id="languageButton" type="button" onclick="toggleLanguage()" data-zh="English" data-en="中文">English</button>
            </div>
          </header>
          <main>
            <section>
              <div class="toolbar">
                <div class="toolbar-group primary-actions">
                  <button type="button" onclick="addRule()" data-zh="新增规则" data-en="Add rule">新增规则</button>
                  <button type="button" onclick="saveRules()" data-zh="保存规则" data-en="Save rules">保存规则</button>
                  <button class="secondary" type="button" onclick="loadRules()" data-zh="从服务端重新载入" data-en="Reload from server">从服务端重新载入</button>
                </div>
                <div class="toolbar-group secondary-actions">
                  <button class="ghost" type="button" onclick="validateRules()" data-zh="校验" data-en="Validate">校验</button>
                  <button class="ghost" type="button" onclick="exportRules()" data-zh="导出 JSON" data-en="Export JSON">导出 JSON</button>
                  <label class="button secondary import-label" for="importFile" data-zh="导入 JSON" data-en="Import JSON">导入 JSON</label>
                  <input id="importFile" type="file" accept="application/json,.json" onchange="importRules(event)">
                </div>
              </div>
              <div class="path" data-zh="规则文件：{{path}}" data-en="Rule file: {{path}}">规则文件：{{path}}</div>
              <div id="status" class="status muted" role="status" aria-live="polite"></div>
            </section>
            <section>
              <h2 data-zh="规则列表" data-en="Rules">规则列表</h2>
              <p class="muted small" data-zh="数组字段使用换行或逗号分隔。id 和标题必须填写且不能重复。" data-en="Use a newline or comma between array values. Each id and title is required and ids must be unique.">数组字段使用换行或逗号分隔。id 和标题必须填写且不能重复。</p>
              <div id="rules" class="rules"></div>
            </section>
          </main>
          <script>
            const fallbackRules = {{json}};
            let state = normalizeSet(fallbackRules);
            let language = 'zh';
            const fieldSpecs = [
              ['id','规则 ID / Rule ID','input',''],
              ['title','标题 / Title','input','wide'],
              ['titleZh','中文标题 / Chinese title','input','wide'],
              ['severity','严重级别 / Severity','select',''],
              ['confidence','置信度 / Confidence','select',''],
              ['summary','摘要 / Summary','textarea','wide'],
              ['summaryZh','中文摘要 / Chinese summary','textarea','wide'],
              ['mitreTechniqueId','MITRE 技术 ID / MITRE technique ID','input',''],
              ['mitreTechniqueName','MITRE 技术名称 / MITRE technique name','input',''],
              ['eventTypes','事件类型 / Event types','textarea',''],
              ['containsCommandLine','命令行包含 / Command line contains','textarea',''],
              ['containsPath','路径包含 / Path contains','textarea',''],
              ['tags','标签 / Tags','textarea',''],
              ['includeNonBehaviorEvidence','包含非行为证据 / Include non-behavior evidence','checkbox','']
            ];
            const htmlEscape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
            const attrEscape = value => htmlEscape(value).replace(/`/g, '&#96;');
            function t(zh, en) { return language === 'zh' ? zh : en; }
            function splitValues(value) { return Array.isArray(value) ? value.join('\n') : String(value ?? ''); }
            function normalizeSet(value) {
              if (value && Array.isArray(value.rules)) return { version: value.version || '1', rules: value.rules.map(normalizeRule) };
              if (value && value.data && Array.isArray(value.data.rules)) return normalizeSet(value.data);
              if (Array.isArray(value)) return { version:'1', rules:value.map(normalizeRule) };
              return { version:'1', rules:[] };
            }
            function normalizeRule(rule) {
              return Object.assign({ id:'', title:'', titleZh:'', severity:'info', confidence:'medium', summary:'', summaryZh:'', mitreTechniqueId:'', mitreTechniqueName:'', eventTypes:[], containsCommandLine:[], containsPath:[], tags:[], includeNonBehaviorEvidence:false }, rule || {});
            }
            function fieldLabel(label) { const parts = String(label || '').split(' / '); return language === 'zh' ? parts[0] : (parts[1] || parts[0]); }
            function render() {
              const host = document.getElementById('rules');
              if (!state.rules.length) { host.innerHTML = `<div class="empty">${htmlEscape(t('还没有规则。点击“新增规则”开始。','No rules yet. Select “Add rule” to begin.'))}</div>`; return; }
              host.innerHTML = state.rules.map((rule, index) => renderRule(rule, index)).join('');
            }
            function renderRule(rule, index) {
              const controls = fieldSpecs.map(([key, label, type, classes]) => {
                const id = `rule-${index}-${key}`;
                if (type === 'checkbox') return `<div class="${classes}"><label class="check"><input id="${id}" type="checkbox" ${rule[key] ? 'checked' : ''} onchange="updateRule(${index})"><span>${htmlEscape(fieldLabel(label))}</span></label></div>`;
                const value = type === 'textarea' ? splitValues(rule[key]) : String(rule[key] ?? '');
                const control = type === 'select'
                  ? `<select id="${id}" onchange="updateRule(${index})"><option value="info" ${value === 'info' ? 'selected' : ''}>info</option><option value="low" ${value === 'low' ? 'selected' : ''}>low</option><option value="medium" ${value === 'medium' ? 'selected' : ''}>medium</option><option value="high" ${value === 'high' ? 'selected' : ''}>high</option><option value="critical" ${value === 'critical' ? 'selected' : ''}>critical</option></select>`
                  : type === 'textarea' ? `<textarea class="${key === 'summary' || key === 'summaryZh' ? 'long' : ''}" id="${id}" oninput="updateRule(${index})">${htmlEscape(value)}</textarea>`
                  : `<input id="${id}" value="${attrEscape(value)}" oninput="updateRule(${index})">`;
                return `<div class="${classes}"><label for="${id}">${htmlEscape(fieldLabel(label))}</label>${control}${['eventTypes','containsCommandLine','containsPath','tags'].includes(key) ? `<div class="field-help">${htmlEscape(t('可用换行或逗号分隔','Separate with newlines or commas'))}</div>` : ''}</div>`;
              }).join('');
              return `<article class="rule-card"><div class="rule-head"><div><div class="rule-index">${htmlEscape(t('规则','Rule'))} #${index + 1}</div><h3>${htmlEscape(rule.title || rule.id || t('未命名规则','Untitled rule'))}</h3></div><div class="actions"><button class="danger" type="button" onclick="removeRule(${index})" data-zh="删除" data-en="Delete">${htmlEscape(t('删除','Delete'))}</button></div></div><div class="grid">${controls}</div></article>`;
            }
            function updateRule(index) {
              const rule = state.rules[index]; if (!rule) return;
              fieldSpecs.forEach(([key,,type]) => { const element = document.getElementById(`rule-${index}-${key}`); if (!element) return; rule[key] = type === 'checkbox' ? element.checked : type === 'textarea' ? parseList(element.value) : element.value; });
              const title = document.querySelectorAll('.rule-card h3')[index]; if (title) title.textContent = rule.title || rule.id || t('未命名规则','Untitled rule');
            }
            function parseList(value) { return String(value || '').split(/[\n,]/).map(item => item.trim()).filter(Boolean); }
            function addRule() { state.rules.push(normalizeRule({ id:`rule-${state.rules.length + 1}`, title:t('新规则','New rule'), summary:t('请填写规则摘要','Describe what this rule detects') })); render(); document.querySelector('.rule-card:last-child')?.scrollIntoView({ behavior:'smooth', block:'start' }); }
            function removeRule(index) { if (!confirm(t('确认删除这条规则？','Delete this rule?'))) return; state.rules.splice(index,1); render(); setStatus(t('规则已从编辑器移除，点击保存后才会写入文件。','Rule removed from the editor; save to write the file.'), 'warn'); }
            function collect() { state.rules.forEach((_, index) => updateRule(index)); return { version:state.version || '1', rules:state.rules }; }
            function validateRules() {
              const value = collect(), errors = [], ids = new Set();
              value.rules.forEach((rule, index) => { if (!String(rule.id || '').trim()) errors.push(t(`第 ${index + 1} 条缺少 id。`,`Rule ${index + 1} has no id.`)); else if (ids.has(rule.id.toLowerCase())) errors.push(t(`id 重复：${rule.id}`,`Duplicate id: ${rule.id}`)); else ids.add(rule.id.toLowerCase()); if (!String(rule.title || '').trim()) errors.push(t(`第 ${index + 1} 条缺少标题。`,`Rule ${index + 1} has no title.`)); });
              setStatus(errors.length ? errors.join(' ') : t(`校验通过：${value.rules.length} 条规则。`,`Validation passed: ${value.rules.length} rule(s).`), errors.length ? 'error' : 'ok');
              return !errors.length;
            }
            async function loadRules() {
              setStatus(t('正在载入…','Loading…'), 'warn');
              try { const response = await fetch('/api/rules', { headers:{ Accept:'application/json' } }); if (!response.ok) throw new Error(`${response.status} ${response.statusText}`); state = normalizeSet(await response.json()); render(); setStatus(t('已从服务端载入。','Loaded from server.'), 'ok'); }
              catch (error) { setStatus(t(`载入失败：${error.message}`,`Load failed: ${error.message}`), 'error'); }
            }
            async function saveRules() {
              if (!validateRules()) return;
              const button = document.querySelector('button[onclick="saveRules()"]'); if (button) button.disabled = true;
              try { const response = await fetch('/api/rules', { method:'PUT', headers:{ 'Content-Type':'application/json', Accept:'application/json' }, body:JSON.stringify(collect()) }); if (!response.ok) throw new Error(`${response.status} ${response.statusText}`); const body = await response.json().catch(() => null); if (body) state = normalizeSet(body); render(); setStatus(t('规则已保存。','Rules saved.'), 'ok'); }
              catch (error) { setStatus(t(`保存失败：${error.message}`,`Save failed: ${error.message}`), 'error'); }
              finally { if (button) button.disabled = false; }
            }
            function exportRules() { const blob = new Blob([JSON.stringify(collect(), null, 2)], { type:'application/json' }); const link = document.createElement('a'); link.href = URL.createObjectURL(blob); link.download = 'behavior-rules.json'; link.click(); URL.revokeObjectURL(link.href); setStatus(t('已导出 JSON。','JSON exported.'), 'ok'); }
            function importRules(event) { const file = event.target.files?.[0]; if (!file) return; const reader = new FileReader(); reader.onload = () => { try { const parsed = normalizeSet(JSON.parse(String(reader.result))); state = parsed; render(); setStatus(t(`已导入 ${parsed.rules.length} 条规则；点击保存写入服务端。`,`Imported ${parsed.rules.length} rule(s); click Save to write to the server.`), 'warn'); } catch (error) { setStatus(t(`JSON 无效：${error.message}`,`Invalid JSON: ${error.message}`), 'error'); } }; reader.readAsText(file); event.target.value = ''; }
            function setStatus(message, kind) { const element = document.getElementById('status'); element.className = `status ${kind || 'muted'}`; element.textContent = message; }
            function applyLanguage() { document.documentElement.lang = language === 'zh' ? 'zh-CN' : 'en'; document.querySelectorAll('[data-zh][data-en]').forEach(element => { if (element.id === 'languageButton') { element.textContent = language === 'zh' ? 'English' : '中文'; return; } if (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') return; element.textContent = language === 'zh' ? element.dataset.zh : element.dataset.en; }); render(); }
            function toggleLanguage() { collect(); language = language === 'zh' ? 'en' : 'zh'; applyLanguage(); }
            render();
            loadRules();
          </script>
        </body>
        </html>
        """;
    }
}
