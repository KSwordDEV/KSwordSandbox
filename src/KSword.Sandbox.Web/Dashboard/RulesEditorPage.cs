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
            :root { --ink:#111827; --muted:#5b6472; --line:#c8d1dc; --soft:#f5f7fa; --blue:#1f5f8b; --danger:#a32626; --ok:#176b45; }
            * { box-sizing:border-box; }
            body { background:#eef1f4; color:var(--ink); font-family:"Microsoft YaHei UI",Segoe UI,Arial,sans-serif; margin:0; }
            header { background:#1b2938; border-bottom:4px solid #2b709d; color:#fff; padding:22px clamp(18px,4vw,48px); }
            header .head { align-items:flex-start; display:flex; gap:18px; justify-content:space-between; }
            main { margin:24px auto 56px; max-width:1280px; padding:0 18px; }
            section, .rule-card { background:#fff; border:1px solid var(--line); border-radius:0; box-shadow:none; }
            section { margin-bottom:18px; padding:18px; }
            h1,h2,h3 { margin:0 0 8px; }
            h1 { font-size:clamp(22px,3vw,32px); }
            h2 { font-size:19px; }
            h3 { color:#173a55; font-size:17px; }
            p { line-height:1.5; }
            .muted { color:var(--muted); }
            .small { font-size:12px; }
            .toolbar, .actions { align-items:center; display:flex; flex-wrap:wrap; gap:8px; }
            button, a.button { background:var(--blue); border:1px solid var(--blue); border-radius:0; color:white; cursor:pointer; display:inline-block; font:inherit; font-weight:700; padding:9px 13px; text-decoration:none; }
            button:hover, a.button:hover { filter:brightness(1.1); }
            button.secondary, a.secondary { background:#5c6773; border-color:#5c6773; }
            button.danger { background:var(--danger); border-color:var(--danger); }
            button.ghost { background:#fff; border-color:var(--line); color:var(--ink); }
            button:disabled { cursor:wait; opacity:.6; }
            .path { background:var(--soft); border:1px solid var(--line); font-family:Consolas,monospace; margin:10px 0 0; overflow-wrap:anywhere; padding:8px; }
            .status { border-left:4px solid var(--line); margin:12px 0 0; min-height:24px; padding:8px 10px; }
            .status.ok { border-color:var(--ok); color:var(--ok); }
            .status.error { border-color:var(--danger); color:var(--danger); }
            .status.warn { border-color:#9a6500; color:#7c4d00; }
            .rules { display:grid; gap:16px; }
            .rule-card { padding:16px; }
            .rule-head { align-items:flex-start; border-bottom:1px solid var(--line); display:flex; gap:10px; justify-content:space-between; margin-bottom:10px; padding-bottom:9px; }
            .rule-index { color:var(--muted); font-size:12px; font-weight:700; }
            .grid { display:grid; gap:11px 14px; grid-template-columns:repeat(4,minmax(0,1fr)); }
            .wide { grid-column:span 2; }
            .full { grid-column:1/-1; }
            label { display:block; font-size:13px; font-weight:700; margin-bottom:5px; }
            input, textarea, select { background:#fff; border:1px solid #aebbc8; border-radius:0; color:var(--ink); font:inherit; padding:8px 9px; width:100%; }
            textarea { min-height:72px; resize:vertical; }
            textarea.long { min-height:98px; }
            input:focus, textarea:focus, select:focus { border-color:#2b709d; outline:2px solid #c6e2f5; }
            .field-help { color:var(--muted); font-size:11px; margin-top:3px; }
            .check { align-items:center; display:flex; gap:8px; min-height:38px; }
            .check input { width:auto; }
            .empty { border:1px dashed var(--line); color:var(--muted); padding:22px; text-align:center; }
            .import-label { cursor:pointer; }
            #importFile { display:none; }
            @media (max-width:900px) { .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .wide { grid-column:span 2; } }
            @media (max-width:560px) { .grid { grid-template-columns:1fr; } .wide { grid-column:auto; } .rule-head { display:block; } .rule-head .actions { margin-top:8px; } }
          </style>
        </head>
        <body>
          <header>
            <div class="head">
              <div>
                <h1 data-zh="行为规则编辑器" data-en="Behavior rule editor">行为规则编辑器</h1>
                <p class="muted" style="color:#d4e0ea" data-zh="以卡片方式编辑检测规则；保存后立即供本机 Web Host 使用。" data-en="Edit detection rules as cards; saved changes are immediately available to this local Web Host.">以卡片方式编辑检测规则；保存后立即供本机 Web Host 使用。</p>
              </div>
              <button class="secondary" id="languageButton" type="button" onclick="toggleLanguage()" data-zh="English" data-en="中文">English</button>
            </div>
          </header>
          <main>
            <section>
              <div class="toolbar">
                <button type="button" onclick="addRule()" data-zh="新增规则" data-en="Add rule">新增规则</button>
                <button type="button" onclick="saveRules()" data-zh="保存规则" data-en="Save rules">保存规则</button>
                <button class="secondary" type="button" onclick="loadRules()" data-zh="从服务端重新载入" data-en="Reload from server">从服务端重新载入</button>
                <button class="ghost" type="button" onclick="validateRules()" data-zh="校验" data-en="Validate">校验</button>
                <button class="ghost" type="button" onclick="exportRules()" data-zh="导出 JSON" data-en="Export JSON">导出 JSON</button>
                <label class="button secondary import-label" for="importFile" data-zh="导入 JSON" data-en="Import JSON">导入 JSON</label>
                <input id="importFile" type="file" accept="application/json,.json" onchange="importRules(event)">
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
            function render() {
              const host = document.getElementById('rules');
              if (!state.rules.length) { host.innerHTML = `<div class="empty">${htmlEscape(t('还没有规则。点击“新增规则”开始。','No rules yet. Select “Add rule” to begin.'))}</div>`; return; }
              host.innerHTML = state.rules.map((rule, index) => renderRule(rule, index)).join('');
            }
            function renderRule(rule, index) {
              const controls = fieldSpecs.map(([key, label, type, classes]) => {
                const id = `rule-${index}-${key}`;
                if (type === 'checkbox') return `<div class="${classes}"><label class="check"><input id="${id}" type="checkbox" ${rule[key] ? 'checked' : ''} onchange="updateRule(${index})"><span>${htmlEscape(label)}</span></label></div>`;
                const value = type === 'textarea' ? splitValues(rule[key]) : String(rule[key] ?? '');
                const control = type === 'select'
                  ? `<select id="${id}" onchange="updateRule(${index})"><option value="info" ${value === 'info' ? 'selected' : ''}>info</option><option value="low" ${value === 'low' ? 'selected' : ''}>low</option><option value="medium" ${value === 'medium' ? 'selected' : ''}>medium</option><option value="high" ${value === 'high' ? 'selected' : ''}>high</option><option value="critical" ${value === 'critical' ? 'selected' : ''}>critical</option></select>`
                  : type === 'textarea' ? `<textarea class="${key === 'summary' || key === 'summaryZh' ? 'long' : ''}" id="${id}" oninput="updateRule(${index})">${htmlEscape(value)}</textarea>`
                  : `<input id="${id}" value="${attrEscape(value)}" oninput="updateRule(${index})">`;
                return `<div class="${classes}"><label for="${id}">${htmlEscape(label)}</label>${control}${['eventTypes','containsCommandLine','containsPath','tags'].includes(key) ? `<div class="field-help">${htmlEscape(t('可用换行或逗号分隔','Separate with newlines or commas'))}</div>` : ''}</div>`;
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

