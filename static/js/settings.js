/* 系统设置页：左侧分类切换 + 关于与更新（在线检测/更新）+ Linux.do 回调地址辅助 */
(function () {
    /* ---------- 设置分类：左侧标签切换 ---------- */
    var panes = Array.prototype.slice.call(document.querySelectorAll('.settings-pane'));
    var navItems = Array.prototype.slice.call(document.querySelectorAll('.settings-nav-item'));
    var valid = {};
    panes.forEach(function (p) { valid[p.getAttribute('data-pane')] = p; });

    // 当前分类写入隐藏字段：保存后重定向回同一分类，避免跳回"基本信息"
    var paneInput = document.getElementById('settingsPane');

    function showPane(name) {
        if (!valid[name]) name = 'basic';
        panes.forEach(function (p) {
            p.classList.toggle('active', p.getAttribute('data-pane') === name);
        });
        navItems.forEach(function (a) {
            a.classList.toggle('active', a.getAttribute('data-pane') === name);
        });
        if (paneInput) paneInput.value = name;
        return name;
    }
    var initial = (location.hash || '').replace('#', '');
    showPane(initial);
    navItems.forEach(function (a) {
        a.addEventListener('click', function (e) {
            e.preventDefault();
            var name = showPane(a.getAttribute('data-pane'));
            try { history.replaceState(null, '', '#' + name); } catch (err) {}
        });
    });
    window.addEventListener('hashchange', function () {
        showPane((location.hash || '').replace('#', ''));
    });

    /* ---------- 关于与更新：在线检测 / 在线更新 ---------- */
    var checkBtn = document.getElementById('checkUpdateBtn');
    var applyBtn = document.getElementById('applyUpdateBtn');
    var badge = document.getElementById('updVersionBadge');
    var resultBox = document.getElementById('updResult');
    var csrfEl = document.querySelector('input[name="_csrf"]');
    var lastInContainer = false;
    if (checkBtn && resultBox) {
        var csrf = csrfEl ? csrfEl.value : '';
        function escapeHtml(s) {
            return String(s == null ? '' : s)
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        }
        function showResult(html, extraClass) {
            resultBox.hidden = false;
            resultBox.className = 'mt-3 pt-3 border-top' + (extraClass ? ' ' + extraClass : '');
            resultBox.innerHTML = html;
        }
        function failResult(msg) {
            if (badge) badge.textContent = '检测失败';
            if (applyBtn) applyBtn.hidden = true;
            showResult('<div class="text-danger small">' + escapeHtml(msg) + '</div>');
        }
        checkBtn.addEventListener('click', function () {
            checkBtn.disabled = true;
            checkBtn.textContent = '检测中…';
            showResult('<span class="text-muted small">正在连接 GitHub 查询最新版本…</span>');
            fetch('/admin/check-update', { headers: { 'Accept': 'application/json' }, credentials: 'same-origin' })
                .then(function (resp) { return resp.json(); })
                .then(function (d) {
                    checkBtn.disabled = false;
                    checkBtn.textContent = '在线检测新版本';
                    if (!d.ok || d.error) { failResult(d.error || '检测失败'); return; }
                    lastInContainer = !!d.in_container;
                    if (badge) {
                        badge.textContent = d.upToDate ? '已是最新' : '发现新版本 ' + d.latest;
                        badge.className = 'badge ' + (d.upToDate ? 'text-bg-light' : 'text-bg-primary text-bg-tint');
                    }
                    var html = '<div class="d-flex align-items-center gap-2 flex-wrap mb-2 small">' +
                        '当前版本 <strong>' + escapeHtml(d.current) + '</strong> → 最新版本 <strong>' + escapeHtml(d.latest) + '</strong>' +
                        '（<a href="' + escapeHtml(d.html_url) + '" target="_blank" rel="noopener">查看发布详情</a>）</div>';
                    if (lastInContainer) {
                        html += '<div class="alert alert-warning py-2 px-3 small mb-2">当前为<strong>容器部署</strong>：在线更新对运行中的容器立即生效、容器不退出；但容器重建后会恢复镜像版本，持久升级请执行 <code>docker compose pull</code>（或配置 Watchtower 全自动升级）。</div>';
                    }
                    if (d.upToDate) {
                        html += '<div class="alert alert-success py-2 px-3 small mb-0">当前已是最新版本，无需更新。</div>';
                        if (applyBtn) applyBtn.hidden = true;
                    } else {
                        if (d.name) html += '<div class="fw-semibold small mb-1">' + escapeHtml(d.name) + '</div>';
                        if (d.notes) html += '<div class="small text-muted mb-2" style="max-height:180px;overflow:auto;white-space:pre-wrap;">' + escapeHtml(d.notes) + '</div>';
                        if (d.hasAsset) {
                            html += '<div class="text-muted small mb-2">将更新到安装包：<code>' + escapeHtml(d.assetName) + '</code></div>';
                            if (applyBtn) { applyBtn.hidden = false; applyBtn.disabled = false; applyBtn.textContent = '在线更新到新版本'; }
                        } else {
                            html += '<div class="alert alert-warning py-2 px-3 small mb-0">当前平台暂无对应的安装包（' + escapeHtml(d.assetName) + '），请到 GitHub Releases 手动下载。</div>';
                            if (applyBtn) applyBtn.hidden = true;
                        }
                    }
                    showResult(html);
                })
                .catch(function () {
                    checkBtn.disabled = false;
                    checkBtn.textContent = '在线检测新版本';
                    failResult('网络异常（无法访问 GitHub），请稍后重试。');
                });
        });
        if (applyBtn) applyBtn.addEventListener('click', function () {
            var tip = lastInContainer
                ? '确定在线更新到最新版本吗？\n应用将下载安装包并在当前容器内原地重启（容器不退出）。\n注意：容器重建后会恢复镜像版本，持久升级请用 docker compose pull。'
                : '确定在线更新到最新版本吗？\n应用将自动下载安装包并重启，期间服务会中断约 10~30 秒，请谨慎操作。';
            if (!confirm(tip)) return;
            applyBtn.disabled = true;
            applyBtn.textContent = '更新中…';
            var body = new URLSearchParams();
            body.set('_csrf', csrf);
            fetch('/admin/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: body.toString(),
                credentials: 'same-origin'
            })
                .then(function (resp) { return resp.json(); })
                .then(function (d) {
                    if (!d.ok) {
                        applyBtn.disabled = false;
                        applyBtn.textContent = '重试更新';
                        failResult(d.error || '更新失败');
                        return;
                    }
                    applyBtn.textContent = '更新中…';
                    showResult('<div class="alert alert-success py-2 px-3 small mb-0">' + escapeHtml(d.message) + '</div>');
                    setTimeout(function () { location.reload(); }, 8000);
                })
                .catch(function () {
                    applyBtn.disabled = false;
                    applyBtn.textContent = '重试更新';
                    failResult('网络异常，无法发起更新，请稍后重试。');
                });
        });
    }

    /* ---------- Linux.do 回调地址：填入 / 复制 ---------- */
    var el = document.getElementById('ldoCallbackData');
    if (el) {
        var cb = el.dataset.cb || '';
        var input = document.querySelector('input[name="linuxdo_redirect_uri"]');
        var fillBtn = document.getElementById('ldoFillCallback');
        var copyBtn = document.getElementById('ldoCopyCallback');
        if (fillBtn && input && cb) {
            fillBtn.addEventListener('click', function () {
                input.value = cb;
                input.focus();
            });
        }
        if (copyBtn && cb) {
            copyBtn.addEventListener('click', function () {
                var done = function (ok) {
                    copyBtn.textContent = ok ? '已复制' : '复制失败';
                    setTimeout(function () { copyBtn.textContent = '复制'; }, 1600);
                };
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(cb).then(function () { done(true); }, function () { done(false); });
                    return;
                }
                var ta = document.createElement('textarea');
                ta.value = cb;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                var ok = false;
                try { ok = document.execCommand('copy'); } catch (e) {}
                document.body.removeChild(ta);
                done(ok);
            });
        }
    }
})();