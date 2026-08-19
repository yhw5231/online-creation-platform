/* ============================================================
   在线创作平台 · 前台交互脚本
   ============================================================ */
(function () {
  'use strict';

  /* ---------- Toast 通知 ---------- */
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function showToast(message, type) {
    var container = document.getElementById('toastContainer');
    if (!container) return;
    var typeClass = type === 'success' ? 'text-success' : (type === 'error' ? 'text-danger' : 'text-primary');
    var el = document.createElement('div');
    el.className = 'toast align-items-center';
    el.setAttribute('role', 'alert');
    el.innerHTML = '<div class="d-flex"><div class="toast-body"><strong class="' + typeClass + '">' + escapeHtml(message) + '</strong></div>' +
      '<button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast" aria-label="关闭"></button></div>';
    container.appendChild(el);
    var t = new bootstrap.Toast(el, { delay: 3000 });
    t.show();
    el.addEventListener('hidden.bs.toast', function () { el.remove(); });
  }
  window.appToast = showToast;

  /* ---------- Toast（操作反馈，session flash 优先，兼容旧 URL 参数） ---------- */
  var toastMsg = document.body ? document.body.getAttribute('data-toast') : null;
  if (!toastMsg) {
    toastMsg = new URLSearchParams(location.search).get('toast');
  }
  if (toastMsg) {
    setTimeout(function () {
      showToast(toastMsg, 'success');
    }, 250);
  }

  /* ---------- 自动关闭可关闭的提示条 ---------- */
  document.querySelectorAll('.dismissible-auto').forEach(function (alertEl) {
    setTimeout(function () {
      if (alertEl && alertEl.parentNode) {
        alertEl.style.transition = 'opacity .4s ease';
        alertEl.style.opacity = '0';
        setTimeout(function () { alertEl.remove(); }, 400);
      }
    }, 6000);
  });

  /* ---------- Bootstrap Tooltip 初始化 ---------- */
  if (window.bootstrap && bootstrap.Tooltip) {
    document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(function (el) {
      new bootstrap.Tooltip(el, { trigger: 'hover', placement: 'top' });
    });
  }

  /* ---------- 表单提交加载态 ---------- */
  document.querySelectorAll('form[data-submit]').forEach(function (form) {
    // data-async 表单由下方异步处理器统一管理按钮加载态与出错恢复，
    // 此处跳过，避免先把按钮替换成加载态、导致异步出错后无法复原
    if (form.hasAttribute('data-async')) return;
    form.addEventListener('submit', function () {
      form.querySelectorAll('.btn-loading').forEach(function (btn) {
        var text = btn.getAttribute('data-loading-text') || '处理中...';
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>' + text;
        btn.disabled = true;
      });
    });
  });

  /* ---------- 异步表单：注册 / 兑换 / Linux.do 完善账号 ----------
     出错时原地显示错误信息（不刷新页面、不丢失已输入内容），
     成功后按后端返回的 redirect 跳转（兑换成功原地更新积分与记录）。 */
  (function () {
    function esc(s) {
      return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
      });
    }
    function commaJs(n) {
      var v = Number(n || 0);
      if (!isFinite(v)) v = 0;
      return v.toLocaleString('en-US');
    }
    // 在输入框下方显示/更新字段级错误（id 与后端渲染的错误节点一致）
    function setFieldError(input, id, msg) {
      var wrap = input ? (input.closest('.mb-3, .mb-4') || input.parentElement) : null;
      var prev = wrap ? wrap.querySelector('#' + id) : null;
      if (prev) prev.remove();
      if (!msg) {
        if (input) input.classList.remove('is-invalid');
        return;
      }
      if (input) {
        input.classList.add('is-invalid');
        input.setAttribute('aria-describedby', id);
      }
      if (!wrap) return;
      var div = document.createElement('div');
      div.className = 'text-danger small mt-1';
      div.id = id;
      div.setAttribute('role', 'alert');
      div.textContent = msg;
      wrap.appendChild(div);
    }
    // 表单顶部提示条（用户名/密码等整体错误）
    function setFormAlert(msg) {
      var box = document.getElementById('asyncFormAlert');
      if (!box) return;
      box.innerHTML = msg
        ? '<div class="alert alert-danger" role="alert">' + esc(msg) + '</div>'
        : '';
    }
    // 兑换页成功：原地刷新积分、成功提示与最近记录，不刷新页面
    function redeemSuccess(form, d) {
      var msgBox = document.getElementById('redeemMsg');
      if (msgBox) {
        msgBox.innerHTML = '<div class="alert alert-success" role="alert">' + esc(d.msg || '兑换成功') + '</div>';
      }
      var pts = document.getElementById('redeemPoints');
      if (pts) pts.textContent = commaJs(d.points);
      var navPts = document.querySelector('.nav-points-val');
      if (navPts) navPts.textContent = commaJs(d.points);
      if (d.history && d.history.length && d.history[0].Code) {
        var list = document.getElementById('redeemHistory');
        var row = d.history[0];
        if (list) {
          var li = document.createElement('li');
          li.className = 'd-flex justify-content-between align-items-center gap-2 py-2 border-bottom';
          li.innerHTML = '<span class="font-monospace fw-semibold me-2">' + esc(row.Code) + '</span>' +
            '<span class="text-muted text-nowrap">' + esc(row.UsedAt || '') + '</span>' +
            '<span class="points-text text-nowrap">+' + commaJs(row.Points) + '</span>';
          list.insertBefore(li, list.firstChild);
          while (list.children.length > 5) list.removeChild(list.lastChild);
        } else {
          // 无历史区块（首次兑换）：在积分行下方创建"最近兑换记录"
          var ptsRow = document.getElementById('redeemPoints');
          var host = ptsRow ? ptsRow.closest('.d-flex') : null;
          if (host && host.parentNode) {
            var hr = document.createElement('hr');
            var h6 = document.createElement('h6');
            h6.className = 'fw-bold mb-3';
            h6.textContent = '最近兑换记录';
            list = document.createElement('ul');
            list.id = 'redeemHistory';
            list.className = 'list-unstyled mb-0 small';
            list.appendChild(li);
            host.parentNode.insertBefore(hr, host.nextSibling);
            host.parentNode.insertBefore(h6, host.nextSibling);
            host.parentNode.insertBefore(list, host.nextSibling);
          }
        }
      }
      var codeInput = form.querySelector('input[name="code"]');
      if (codeInput) {
        codeInput.value = '';
        codeInput.classList.remove('is-invalid');
      }
      // 清除上一次的错误提示
      var prevErr = document.getElementById('codeError');
      if (prevErr) prevErr.remove();
    }
    // 通用错误展示：兑换页显示在兑换码输入框下，注册类显示顶部（+注册码字段）
    function showAsyncError(form, d, status) {
      var isRedeem = (form.getAttribute('action') || '').indexOf('/redeem') !== -1;
      if (isRedeem) {
        var input = form.querySelector('input[name="code"]');
        setFieldError(input, 'codeError', d && d.error ? d.error : (status === 429 ? '操作过于频繁，请稍后再试' : '操作失败，请重试'));
        return;
      }
      setFormAlert((d && d.form) || (status === 429 ? '操作过于频繁，请稍后再试' : null));
      setFieldError(form.querySelector('input[name="reg_code"]'), 'regCodeError', (d && d.reg_code) || null);
      if (!(d && (d.form || d.reg_code)) && status !== 429) {
        setFormAlert('网络异常，请稍后重试');
      }
    }

    document.querySelectorAll('form[data-async]').forEach(function (form) {
      var btn = form.querySelector('.btn-loading');
      // 在绑定阶段就记录按钮原始内容：提交出错时用它复原按钮。
      // 不能在 submit 时才读取 innerHTML，否则可能拿到的是加载态内容，
      // 导致“注册中/兑换中”等提示无法恢复。
      var origHTML = btn ? btn.innerHTML : '';
      form.addEventListener('submit', function (e) {
        e.preventDefault();
        if (form.getAttribute('data-ajax-busy') === '1') return;
        form.setAttribute('data-ajax-busy', '1');
        if (btn) {
          var text = btn.getAttribute('data-loading-text') || '处理中...';
          btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>' + esc(text);
          btn.disabled = true;
        }
        var action = form.getAttribute('action') || location.pathname;
        function done() {
          form.setAttribute('data-ajax-busy', '0');
          if (btn) { btn.innerHTML = origHTML; btn.disabled = false; }
        }
        fetch(action, {
          method: 'POST',
          headers: { 'X-Requested-With': 'XMLHttpRequest' },
          body: new FormData(form),
          credentials: 'same-origin'
        }).then(function (resp) {
          // 中间件重定向（如未登录跳登录页）：跟随跳转
          if (resp.redirected) { location.href = resp.url; return null; }
          return resp.json().then(function (data) {
            return { data: data, status: resp.status };
          }).catch(function () {
            return { _broken: true, status: resp.status };
          });
        }).then(function (r) {
          if (r === null) return;
          done();
          if (r._broken) {
            showAsyncError(form, null, r.status);
            return;
          }
          var d = r.data;
          if (d.ok) {
            if ((form.getAttribute('action') || '').indexOf('/redeem') !== -1) {
              redeemSuccess(form, d);
            } else if (d.redirect) {
              location.href = d.redirect;
            } else {
              location.reload();
            }
            return;
          }
          showAsyncError(form, d, r.status);
        }).catch(function () {
          done();
          showAsyncError(form, null, 0);
        });
      });
    });
  })();

  /* ---------- 导航高亮 ---------- */
  (function highlightNav() {
    var path = location.pathname;
    // 隐藏与当前页面重复的导航按钮（登录页不显示登录按钮，注册页不显示注册按钮）
    if (path === '/login') {
      document.querySelectorAll('nav .btn-login').forEach(function (b) { b.style.visibility = 'hidden'; });
    } else if (path === '/register') {
      document.querySelectorAll('nav .btn-register').forEach(function (b) { b.style.visibility = 'hidden'; });
    }
    document.querySelectorAll('[data-nav]').forEach(function (a) {
      var target = a.getAttribute('data-nav');
      if (!target) return;
      var match =
        path === target ||
        (target.length > 1 && path.indexOf(target + '/') === 0) ||
        (target === '/create' && path === '/generate');
      if (match) {
        a.classList.add('active');
        a.setAttribute('aria-current', 'page');
      }
    });
    // 移动端点击后收起菜单
    document.querySelectorAll('#navMenu .nav-link, #navMenu .dropdown-item').forEach(function (a) {
      a.addEventListener('click', function () {
        var collapseEl = document.getElementById('navMenu');
        if (collapseEl && collapseEl.classList.contains('show') && window.bootstrap) {
          bootstrap.Collapse.getOrCreateInstance(collapseEl).hide();
        }
      });
    });
  })();

  /* ---------- 提示词字数统计 ---------- */
  var promptInput = document.querySelector('.prompt-input');
  var charCount = document.getElementById('charCount');
  if (promptInput && charCount) {
    var maxLen = promptInput.getAttribute('maxlength') || '∞';
    function updateCount() {
      charCount.textContent = promptInput.value.length + ' / ' + maxLen;
    }
    promptInput.addEventListener('input', updateCount);
    updateCount();
    var clearBtn = document.getElementById('clearPrompt');
    if (clearBtn) {
      clearBtn.addEventListener('click', function () {
        promptInput.value = '';
        updateCount();
        promptInput.focus();
      });
    }
  }

  /* ---------- 密码强度指示 ---------- */
  (function pwStrength() {
    var levels = [
      { max: 1, label: '太短，还需 6 位以上', color: '#ef4444' },
      { max: 2, label: '较弱，建议混合字母/数字/符号', color: '#f59e0b' },
      { max: 4, label: '一般', color: '#eab308' },
      { max: 8, label: '良好', color: '#22c55e' },
      { max: 99, label: '强', color: '#10b981' }
    ];
    document.querySelectorAll('input[data-meter]').forEach(function (inp) {
      var cell = inp.closest('.mb-3, .mb-4');
      if (!cell) return;
      var box = cell.querySelector('.pw-meter');
      var fill = cell.querySelector('.pw-meter-fill');
      var text = cell.querySelector('.pw-meter-text');
      if (!box || !fill || !text) return;
      inp.addEventListener('input', function () {
        var v = inp.value;
        var score = 0;
        if (v.length >= 6) score++;
        if (v.length >= 10) score++;
        if (/[a-z]/.test(v) && /[A-Z]/.test(v)) score++;
        if (/\d/.test(v)) score++;
        if (/[^A-Za-z0-9]/.test(v)) score++;
        if (v.length === 0) {
          box.hidden = true;
          return;
        }
        box.hidden = false;
        var lv = levels[levels.length - 1];
        for (var i = 0; i < levels.length; i++) {
          if (score <= levels[i].max) { lv = levels[i]; break; }
        }
        fill.style.width = (score / 5 * 100) + '%';
        fill.style.background = lv.color;
        text.textContent = lv.label;
        text.style.color = lv.color;
      });
    });
  })();

  /* ---------- Ctrl/⌘ + Enter 快速提交 ---------- */
  (function ctrlEnterSubmit() {
    var ta = document.querySelector('textarea[name="prompt"]');
    var form = ta && ta.closest('form[action="/generate"]');
    if (!ta || !form) return;
    ta.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        if (form.requestSubmit) form.requestSubmit(); else form.submit();
      }
    });
  })();

  /* ---------- 站点公告关闭 ---------- */
  document.querySelectorAll('[data-dismiss-notice]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var bar = document.getElementById('siteNotice');
      if (bar && bar.parentNode) {
        bar.style.transition = 'height .2s ease, opacity .2s ease';
        bar.style.opacity = '0';
        setTimeout(function () { bar.remove(); }, 200);
      }
    });
  });

  /* ---------- 图片加载失败占位（防止破图图标） ---------- */
  document.querySelectorAll('.record-cover, .showcase-thumb img, .record-subs img').forEach(function (img) {
    img.addEventListener('error', function () {
      // 子图条：直接隐藏该失效图，避免一排在破图标中间
      if (img.closest('.record-subs')) {
        img.classList.add('d-none');
        return;
      }
      if (img.classList.contains('record-cover')) {
        var ph = document.createElement('div');
        ph.className = 'record-cover record-cover-empty';
        ph.innerHTML = '<span class="text-muted small">暂无图片</span>';
        if (img.parentNode) img.replaceWith(ph);
        return;
      }
      var anchor = img.closest('.showcase-thumb');
      if (anchor && anchor.parentNode) {
        var d = document.createElement('div');
        d.className = 'showcase-thumb';
        d.setAttribute('aria-hidden', 'true');
        d.style.cssText = 'background:#eef0f6;height:96px;border-radius:8px;display:flex;align-items:center;justify-content:center;color:#9ca3af;font-size:.8rem;';
        d.textContent = '图已失效';
        anchor.replaceWith(d);
      }
    });
  });

  /* ---------- 回到顶部 ---------- */
  (function backTop() {
    var btn = document.getElementById('backTop');
    if (!btn) return;
    window.addEventListener('scroll', function () {
      btn.classList.toggle('back-top-show', window.scrollY > 400);
    }, { passive: true });
    btn.addEventListener('click', function () {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  })();

  /* ---------- 生成数量实时计价 + 积分不足拦截 ---------- */
  (function costPreview() {
    var nSel = document.querySelector('form[action="/generate"] select[name="n"]');
    var baseEl = document.querySelector('[data-base-cost]');
    var totalEl = document.getElementById('totalCost');
    var countEl = document.getElementById('genCount');
    var hintEl = document.getElementById('insufficientHint');
    var submitBtn = document.getElementById('genSubmit');
    if (!nSel || !baseEl || !totalEl || !countEl) return;
    var base = parseInt(baseEl.getAttribute('data-base-cost'), 10) || 0;
    var points = parseInt(baseEl.getAttribute('data-points'), 10) || 0;
    function update() {
      var n = parseInt(nSel.value, 10) || 1;
      var total = base * n;
      countEl.textContent = n;
      totalEl.textContent = total;
      var short = total > points;
      if (hintEl && submitBtn) {
        if (short) {
          hintEl.textContent = '当前积分 ' + points + '，本次需 ' + total + ' 积分，不足以生成。' +
            '请先签到或兑换积分。';
          hintEl.classList.remove('d-none');
          submitBtn.setAttribute('disabled', 'disabled');
        } else {
          hintEl.classList.add('d-none');
          submitBtn.removeAttribute('disabled');
        }
      }
    }
    nSel.addEventListener('change', update);
    update();
  })();

  /* ---------- 渠道切换：分辨率档位 + 模型联动 ---------- */
  (function channelResolutions() {
    var chSel = document.getElementById('channelSelect');
    var resSel = document.getElementById('resolutionSelect');
    var modelSel = document.getElementById('modelSelect');
    if (!chSel) return;
    function rebuildResolutions() {
      if (!resSel) return;
      var opt = chSel.options[chSel.selectedIndex];
      if (!opt) return;
      var csv = opt.getAttribute('data-resolutions') || '';
      var list = csv.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      if (!list.length) list = ['1k', '2k'];
      var prev = resSel.value;
      resSel.innerHTML = '';
      list.forEach(function (r) {
        var o = document.createElement('option');
        o.value = r;
        o.textContent = r;
        resSel.appendChild(o);
      });
      // 保留旧选择，若新渠道不支持则回退到第一个档位
      if (list.indexOf(prev) !== -1) {
        resSel.value = prev;
      }
    }
    function rebuildModels() {
      if (!modelSel) return;
      var opt = chSel.options[chSel.selectedIndex];
      if (!opt) return;
      var csv = opt.getAttribute('data-models') || '';
      var list = csv.split(',').map(function (s) { return s.trim(); }).filter(Boolean);
      if (!list.length) {
        list = ['grok-imagine-image-lite', 'grok-imagine-image', 'grok-imagine-image-edit', 'grok-imagine-image-2.0', 'grok-imagine-video', 'gpt-image-2'];
      }
      var prev = modelSel.value;
      modelSel.innerHTML = '';
      list.forEach(function (m) {
        var o = document.createElement('option');
        o.value = m;
        o.textContent = m;
        modelSel.appendChild(o);
      });
      // 保留旧选择，若新渠道不支持则回退到第一个模型
      if (list.indexOf(prev) !== -1) {
        modelSel.value = prev;
      }
    }
    chSel.addEventListener('change', function () {
      rebuildResolutions();
      rebuildModels();
    });
    rebuildResolutions();
    rebuildModels();
  })();

  /* ---------- 灵感示例 chips ---------- */
  var toggleSamples = document.getElementById('toggleSamples');
  var samplePrompts = document.querySelector('.sample-prompts');
  if (toggleSamples && samplePrompts) {
    toggleSamples.addEventListener('click', function () {
      samplePrompts.classList.toggle('d-none');
      toggleSamples.textContent = samplePrompts.classList.contains('d-none') ? '灵感示例' : '收起示例';
    });
    samplePrompts.querySelectorAll('.sample-chip').forEach(function (chip) {
      chip.addEventListener('click', function () {
        if (promptInput) {
          promptInput.value = chip.getAttribute('data-prompt');
          if (charCount) updateCountSafe(promptInput, charCount);
          promptInput.focus();
        }
      });
    });
  }

  function updateCountSafe(txt, counter) {
    counter.textContent = txt.value.length + ' / ' + (txt.getAttribute('maxlength') || '');
  }

  /* ---------- 图片灯箱预览 ---------- */
  var modalEl = document.getElementById('imageModal');
  var modalImg = document.getElementById('imageModalImg');
  var modalDl = document.getElementById('imageModalDownload');
  var lightboxModal = null;
  if (modalEl && modalImg && window.bootstrap) {
    lightboxModal = new bootstrap.Modal(modalEl);
  }
  function bindLightbox(img) {
    if (!img || img.__lbBound) return;
    img.__lbBound = true;
    img.addEventListener('click', function () {
      var src = img.getAttribute('src');
      if (lightboxModal) {
        modalImg.src = src;
        if (modalDl) {
          modalDl.href = src;
          // 提取文件名作为默认下载名，便于本地保存
          var last = src.split('/').pop().split('?')[0];
          if (last) modalDl.setAttribute('download', last);
        }
        lightboxModal.show();
      } else {
        window.open(src, '_blank');
      }
    });
  }
  document.querySelectorAll('[data-lightbox]').forEach(bindLightbox);

  /* ---------- 危险操作二次确认 ---------- */
  document.querySelectorAll('[data-confirm]').forEach(function (el) {
    el.addEventListener('click', function (e) {
      if (!window.confirm(el.getAttribute('data-confirm'))) {
        e.preventDefault();
        e.stopPropagation();
      }
    });
  });

  /* ---------- 密码可见性切换 ---------- */
  document.querySelectorAll('.pwd-toggle').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.getElementById(btn.getAttribute('data-target'));
      if (!input) return;
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.textContent = show ? '隐藏' : '显示';
    });
  });

  /* ---------- 下载文件名沿用服务端真实文件名 ---------- */
  document.querySelectorAll('a[download]').forEach(function (a) {
    var href = a.getAttribute('href') || '';
    if (href.indexOf('data:') === 0) {
      a.setAttribute('download', 'creation.png');
      return;
    }
    var m = href.match(/\/([^/?#]+)$/);
    a.setAttribute('download', m ? m[1] : 'creation.png');
  });

  /* ---------- 兑换码自动大写 + 去空格 ---------- */
  var redeemInput = document.querySelector('input[name="code"]');
  if (redeemInput) {
    redeemInput.addEventListener('input', function () {
      this.value = this.value.toUpperCase().replace(/\s+/g, '');
    });
  }

  /* ---------- 注册两次密码一致性即时校验 ---------- */
  var regForm = document.querySelector('form[action="/register"]');
  if (regForm) {
    var pw = regForm.querySelector('input[name="password"]');
    var cw = regForm.querySelector('input[name="confirm_password"]');
    var hint = document.getElementById('confirmHint');
    function checkConfirm() {
      var ok = !cw.value || pw.value === cw.value;
      if (hint) hint.classList.toggle('d-none', ok);
      cw.classList.toggle('is-invalid', !ok && cw.value !== '');
    }
    if (cw && pw && hint) {
      cw.addEventListener('input', checkConfirm);
      cw.addEventListener('blur', checkConfirm);
    }
  }

  /* ---------- 复制到剪贴板 ---------- */
  function copyText(text, okMessage) {
    function done() {
      showToast(okMessage || '已复制到剪贴板', 'success');
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }
  function fallbackCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (e) {}
    document.body.removeChild(ta);
  }
  document.querySelectorAll('.copy-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var code = btn.getAttribute('data-copy') || '';
      var msg = btn.getAttribute('data-copy-msg') || '已复制到剪贴板';
      copyText(code, msg);
    });
  });

  /* ---------- 创作页：生成任务异步轮询 ---------- */
  var taskDetailBox = document.getElementById('taskDetail');
  var recentTasksBox = document.getElementById('recentTasks');
  if (taskDetailBox || recentTasksBox) {
    var TASK_ACTIVE = 'processing';

    function esc(s) {
      return escapeHtml(s == null ? '' : String(s));
    }

    function taskBadge(status) {
      if (status === 'processing') return '<span class="badge text-bg-primary">生成中</span>';
      if (status === 'success') return '<span class="badge text-bg-success">已完成</span>';
      return '<span class="badge text-bg-danger">失败</span>';
    }

    function taskThumb(t) {
      var imgs = t.Images || [];
      var src = t.ImageURL || imgs[0] || '';
      if (src) return '<img src="' + esc(src) + '" alt="任务缩略图" loading="lazy">';
      var ph = t.Status === 'success' ? '无图' : (t.Status === 'failed' ? '失败' : '…');
      return '<span class="recent-task-ph">' + ph + '</span>';
    }

    // 生成任务详情卡（进度 / 结果 / 失败原因）
    function renderTaskDetail(t) {
      if (!taskDetailBox) return;
      var html = '';
      if (t.Status === TASK_ACTIVE) {
        html += '<div class="d-flex align-items-center gap-2 text-muted mb-2">' +
          '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>' +
          '<span class="small">正在生成中，请稍候…（' + (t.N || 1) + ' 张可能需要一两分钟，页面会自动更新）</span></div>';
        html += '<p class="record-prompt mb-0">' + esc(t.Prompt) + '</p>';
      } else if (t.Status === 'failed') {
        html += '<div class="alert alert-danger mb-2 py-2 small">' + esc(t.Error || '生成失败') + '</div>';
        html += '<p class="record-prompt mb-0">' + esc(t.Prompt) + '</p>';
      } else {
        var imgs = (t.Images && t.Images.length) ? t.Images : (t.ImageURL ? [t.ImageURL] : []);
        html += '<div class="d-flex justify-content-between align-items-start gap-2 flex-wrap mb-2">';
        html += '<div>' + taskBadge(t.Status) + ' <span class="text-muted small">#' + (t.TaskKey || t.ID) + ' · ' + (t.N || 1) + ' 张</span></div>';
        html += '<a href="/records" class="btn btn-sm btn-outline-secondary">查看创作记录</a>';
        html += '</div>';
        if (!imgs.length) {
          html += '<p class="text-muted small mb-0">作品图片已生成但可能已被服务器清理，请尽快下载保存。</p>';
        } else {
          html += '<div class="row g-3 mt-1">';
          imgs.forEach(function (src, i) {
            var fname = src.split('/').pop();
            html += '<div class="col-md-6"><div class="result-img-wrap">' +
              '<img src="' + esc(src) + '" class="result-img" loading="lazy" alt="生成图片" data-lightbox>' +
              '<div class="result-actions"><a href="' + esc(src) + '" download="' + esc(fname) + '" class="btn btn-sm btn-light">下载图片</a></div>' +
              '</div></div>';
          });
          html += '</div>';
        }
      }
      taskDetailBox.innerHTML = html;
      taskDetailBox.setAttribute('data-task-status', t.Status || '');
      // 结果大图支持灯箱放大
      taskDetailBox.querySelectorAll('[data-lightbox]').forEach(bindLightbox);
    }

    // 最近任务列表（3 条）
    function renderRecentTasks(list) {
      if (!recentTasksBox) return;
      if (!list || !list.length) {
        recentTasksBox.innerHTML = '<p class="text-muted small text-center py-3 mb-0">还没有任务，开始你的第一次创作吧</p>';
        return;
      }
      var html = '';
      list.forEach(function (t) {
        html += '<div class="recent-task d-flex align-items-start gap-3 py-2 px-2 rounded" data-task-id="' + esc(t.TaskKey || t.ID) + '" data-task-status="' + esc(t.Status) + '">';
        html += '<div class="recent-task-thumb flex-shrink-0">' + taskThumb(t) + '</div>';
        html += '<div class="flex-grow-1 min-w-0">';
        html += '<p class="record-prompt mb-1" title="' + esc(t.Prompt) + '">' + esc(t.Prompt) + '</p>';
        html += '<div class="d-flex align-items-center gap-2 flex-wrap">';
        html += '<span class="text-muted small">#' + (t.TaskKey || t.ID) + ' · ' + esc(t.CreatedAt) + ' · ×' + (t.N || 1) + '</span>';
        html += taskBadge(t.Status);
        html += '</div>';
        if (t.Status === 'failed') {
          var e = t.Error || '';
          html += '<div class="text-danger small mt-1" title="' + esc(e) + '">' + esc(e.substring(0, 80)) +
            (e.length > 80 ? '…' : '') + '</div>';
        }
        html += '</div></div>';
      });
      recentTasksBox.innerHTML = html;
    }

    var activeTaskId = taskDetailBox ? taskDetailBox.getAttribute('data-task-id') : '';

    function collectTaskIds() {
      var ids = [];
      if (activeTaskId) ids.push(activeTaskId);
      if (recentTasksBox) {
        recentTasksBox.querySelectorAll('[data-task-id]').forEach(function (el) {
          var id = el.getAttribute('data-task-id');
          if (id && ids.indexOf(id) < 0) ids.push(id);
        });
      }
      return ids;
    }

    function anyTaskProcessing() {
      if (taskDetailBox && taskDetailBox.getAttribute('data-task-status') === TASK_ACTIVE) return true;
      if (recentTasksBox && recentTasksBox.querySelector('[data-task-status="' + TASK_ACTIVE + '"]')) return true;
      return false;
    }

    function pollTasks(ids) {
      if (!ids.length) return;
      fetch('/generate/status?ids=' + ids.join(','), {
        headers: { 'Accept': 'application/json' },
        credentials: 'same-origin'
      }).then(function (resp) {
        if (!resp.ok) throw new Error('bad status');
        return resp.json();
      }).then(function (data) {
        if (taskDetailBox && activeTaskId && data.tasks) {
          data.tasks.forEach(function (t) {
            if ((t.TaskKey || String(t.ID)) === activeTaskId) renderTaskDetail(t);
          });
        }
        if (data.recent) renderRecentTasks(data.recent);
        if (anyTaskProcessing()) {
          setTimeout(function () { pollTasks(collectTaskIds()); }, 2500);
        }
      }).catch(function () {
        // 网络抖动等：稍后重试
        setTimeout(function () { pollTasks(collectTaskIds()); }, 4000);
      });
    }

    // 有进行中任务，或已有任务列表时启动一次轮询（会自行持续/停止）
    if (anyTaskProcessing() || recentTasksBox && recentTasksBox.querySelector('[data-task-id]')) {
      pollTasks(collectTaskIds());
    }
  }

  /* ---------- 系统设置：图片生成接口行管理 ---------- */
  (function endpointRows() {
    var rows = document.getElementById('endpointRows');
    if (!rows) return;

    function makeRow() {
      var div = document.createElement('div');
      div.className = 'endpoint-row border rounded-3 p-3 mb-3 bg-white';
      div.innerHTML =
        '<input type="hidden" name="ep_id[]" value="">' +
        '<div class="row g-3">' +
        '<div class="col-md-2"><label class="form-label fw-semibold">渠道名称 <span class="badge text-bg-light" title="新增渠道保存后自动分配稳定编号；编号即 API 调用 channel 参数取值">编号 自动</span></label><input name="ep_name[]" class="form-control" autocomplete="off" placeholder="渠道名称"></div>' +
        '<div class="col-md-3"><label class="form-label fw-semibold">API 地址</label><input name="ep_url[]" class="form-control" autocomplete="off" placeholder="https://grok.example.com/v1"></div>' +
        '<div class="col-md-3"><label class="form-label fw-semibold">API Key</label><input name="ep_key[]" type="text" class="form-control" autocomplete="off" placeholder="尚未配置，粘贴密钥"></div>' +
        '<div class="col-md-2"><label class="form-label fw-semibold">默认模型</label><input name="ep_model[]" class="form-control" list="ep-model-list" placeholder="grok-imagine-image-lite"></div>' +
        '<div class="col-md-2"><label class="form-label fw-semibold">NSFW 渠道</label><select name="ep_nsfw[]" class="form-select"><option value="0" selected>否</option><option value="1">是</option></select></div>' +
        '</div>' +
        '<div class="row g-3 mt-1">' +
        '<div class="col-md-6"><label class="form-label fw-semibold">支持分辨率档位</label>' +
        '<div class="d-flex flex-wrap gap-3 pt-1">' +
        '<span class="ep-res-check"><input class="form-check-input" type="checkbox" data-res="1k" checked><label class="form-check-label small">1k</label></span>' +
        '<span class="ep-res-check"><input class="form-check-input" type="checkbox" data-res="2k" checked><label class="form-check-label small">2k</label></span>' +
        '<span class="ep-res-check"><input class="form-check-input" type="checkbox" data-res="4k"><label class="form-check-label small">4k</label></span>' +
        '</div>' +
        '<input type="hidden" name="ep_res[]" class="ep-res-input" value="1k,2k">' +
        '<div class="form-text">用户创作时只能选择勾选的档位（可多选）；全不勾选则默认提供 1k,2k。</div>' +
        '</div>' +
        '<div class="col-md-6"><label class="form-label fw-semibold">可用模型（多选）</label>' +
        '<div class="d-flex flex-wrap gap-3 pt-1">' +
        '<span class="ep-model-check"><input class="form-check-input" type="checkbox" data-model="grok-imagine-image-lite" checked><label class="form-check-label small">grok-imagine-image-lite</label></span>' +
        '<span class="ep-model-check"><input class="form-check-input" type="checkbox" data-model="grok-imagine-image" checked><label class="form-check-label small">grok-imagine-image</label></span>' +
        '<span class="ep-model-check"><input class="form-check-input" type="checkbox" data-model="grok-imagine-image-edit" checked><label class="form-check-label small">grok-imagine-image-edit</label></span>' +
        '<span class="ep-model-check"><input class="form-check-input" type="checkbox" data-model="grok-imagine-image-2.0" checked><label class="form-check-label small">grok-imagine-image-2.0</label></span>' +
        '<span class="ep-model-check"><input class="form-check-input" type="checkbox" data-model="grok-imagine-video" checked><label class="form-check-label small">grok-imagine-video</label></span>' +
        '<span class="ep-model-check"><input class="form-check-input" type="checkbox" data-model="gpt-image-2" checked><label class="form-check-label small">gpt-image-2</label></span>' +
        '</div>' +
        '<input type="hidden" name="ep_models[]" class="ep-models-input" value="grok-imagine-image-lite,grok-imagine-image,grok-imagine-image-edit,grok-imagine-image-2.0,grok-imagine-video,gpt-image-2">' +
        '<input name="ep_extra_models[]" class="ep-extra-models form-control form-control-sm mt-2" autocomplete="off" placeholder="自定义模型（逗号分隔），如 my-model-1, my-model-2">' +
        '<div class="form-text">用户创作时可在所选渠道勾选的模型中切换；默认模型见上方输入框（可手动输入自定义模型）。</div>' +
        '</div>' +
        '</div>' +
        '<div class="mt-2 text-end"><button type="button" class="btn btn-sm btn-outline-danger endpoint-del">删除此渠道</button></div>';
      return div;
    }
    // 分辨率档位 checkbox 与隐藏字段联动：勾选即写入隐藏提交字段，仅取勾选值
    function syncEpRes(container) {
      var input = container.querySelector('.ep-res-input');
      if (!input) return;
      var checked = [];
      Array.prototype.slice.call(container.querySelectorAll('.ep-res-check input:checked')).forEach(function (cb) {
        checked.push(cb.getAttribute('data-res'));
      });
      input.value = checked.join(',');
    }
    // 可用模型：预设勾选 + 自定义补充（逗号分隔）合并写入隐藏提交字段
    var PRESET_MODELS = ['grok-imagine-image-lite', 'grok-imagine-image', 'grok-imagine-image-edit', 'grok-imagine-image-2.0', 'grok-imagine-video', 'gpt-image-2'];
    function syncEpModels(container) {
      var input = container.querySelector('.ep-models-input');
      if (!input) return;
      var list = [];
      Array.prototype.slice.call(container.querySelectorAll('.ep-model-check input:checked')).forEach(function (cb) {
        var m = cb.getAttribute('data-model');
        if (list.indexOf(m) === -1) list.push(m);
      });
      var extra = container.querySelector('.ep-extra-models');
      if (extra && extra.value.trim()) {
        extra.value.split(/[,，]/).forEach(function (s) {
          s = s.trim();
          if (s && list.indexOf(s) === -1) list.push(s);
        });
      }
      input.value = list.join(',');
    }
    function initEpModels(row) {
      var hidden = row.querySelector('.ep-models-input');
      var extra = row.querySelector('.ep-extra-models');
      if (!hidden || !extra) return;
      // 已保存但不在预设内的模型回填到自定义输入框，避免保存后丢失
      var custom = hidden.value.split(/[,，]/).map(function (s) { return s.trim(); })
        .filter(function (s) { return s && PRESET_MODELS.indexOf(s) === -1; });
      extra.value = custom.join(', ');
      syncEpModels(row);
    }
    document.addEventListener('change', function (e) {
      var ck = e.target.closest('.ep-res-check input');
      if (ck) {
        var row = ck.closest('.endpoint-row');
        if (row) syncEpRes(row);
        return;
      }
      var mc = e.target.closest('.ep-model-check input');
      if (mc) {
        var row2 = mc.closest('.endpoint-row');
        if (row2) syncEpModels(row2);
      }
    });
    document.addEventListener('input', function (e) {
      var extra = e.target.classList && e.target.classList.contains('ep-extra-models');
      if (!extra) return;
      var row = e.target.closest('.endpoint-row');
      if (row) syncEpModels(row);
    });
    // 初始化既有行：回填自定义模型并同步隐藏字段
    Array.prototype.slice.call(rows.querySelectorAll('.endpoint-row')).forEach(initEpModels);

    var addBtn = document.getElementById('addEndpoint');
    if (addBtn) {
      addBtn.addEventListener('click', function () {
        rows.appendChild(makeRow());
      });
    }
    // 删除行（事件委托，至少保留一行）
    rows.addEventListener('click', function (e) {
      var del = e.target.closest('.endpoint-del');
      if (!del) return;
      var row = del.closest('.endpoint-row');
      if (rows.querySelectorAll('.endpoint-row').length <= 1) {
        row.replaceWith(makeRow());
        return;
      }
      row.remove();
    });
  })();

  /* ---------- 创作记录页：图片本地缓存 + 备用下载 ---------- */
  // 记录页的图片默认"换存到浏览器本地"（IndexedDB）：首次访问时把图片
  // 缓存到浏览器，服务器本地文件被自动清理后，用户仍可从缓存查看/下载。
  // 配置了外部存储的记录会显示"备用下载"按钮，使用备用地址下载。
  (function () {
    // 缓存键 = 任务随机编号-图片序号（如 d5ey63d7-0），
    // 任务编号使用随机值，图片序号为记录内的位置
    var cacheKeyRE = /[a-z0-9]+-\d+/;
    var imgs = document.querySelectorAll('img[data-cache-key]');
    if (!imgs.length) return;

    var DB_NAME = 'creation-records';
    var DB_VERSION = 1;
    var STORE = 'images';
    var dbPromise = null;
    function openDB() {
      if (dbPromise) return dbPromise;
      if (!window.indexedDB) return Promise.resolve(null);
      dbPromise = new Promise(function (resolve) {
        var req = indexedDB.open(DB_NAME, DB_VERSION);
        req.onupgradeneeded = function () {
          if (!req.result.objectStoreNames.contains(STORE)) {
            req.result.createObjectStore(STORE);
          }
        };
        req.onsuccess = function () { resolve(req.result); };
        req.onerror = function () { resolve(null); };
      });
      return dbPromise;
    }
    function cidb(mode, fn) {
      return openDB().then(function (db) {
        if (!db) return Promise.resolve(null);
        return new Promise(function (resolve) {
          try {
            var tx = db.transaction(STORE, mode);
            var store = tx.objectStore(STORE);
            var result = fn(store);
            if (result && result.onsuccess) {
              result.onsuccess = function () { resolve(result.result); };
              result.onerror = function () { resolve(null); };
            } else {
              tx.oncomplete = function () { resolve(null); };
            }
          } catch (e) {
            resolve(null);
          }
        });
      });
    }
    function cacheGet(key) {
      return cidb('readonly', function (s) { return s.get(key); });
    }
    function cacheSet(key, blob) {
      return cidb('readwrite', function (s) { s.put(blob, key); });
    }
    function cacheDelete(key) {
      return cidb('readwrite', function (s) { s.delete(key); });
    }

    // 图片加载前：先尝试本地缓存；随后跟随 alt 回退。
    function prepareImage(img) {
      var key = img.getAttribute('data-cache-key');
      var alt = img.getAttribute('data-alt') || '';
      if (!cacheKeyRE.test(key)) return;
      cacheGet(key).then(function (blob) {
        if (blob && blob.size > 0) {
          var url = URL.createObjectURL(blob);
          img.addEventListener('load', function () { URL.revokeObjectURL(url); }, { once: true });
          img.src = url;
          return;
        }
        // 缓存未命中：从服务器加载并写入缓存
        img.addEventListener('load', function () {
          img.__fromServer = true;
          try {
            fetch(img.currentSrc || img.src, { cache: 'force-cache' })
              .then(function (r) { return r.ok ? r.blob() : null; })
              .then(function (b) { if (b) cacheSet(key, b); })
              .catch(function () {});
          } catch (e) {}
        });
        // 服务器文件被清理（404）时回退到备用地址
        img.addEventListener('error', function () {
          if (alt && img.src.indexOf(alt) === -1) {
            img.src = alt;
          }
        });
      });
    }
    imgs.forEach(prepareImage);

    // "下载"按钮：优先使用本地缓存（服务器文件可能已被清理）；
    // 否则回退到 src（服务器本地或备用地址）。
    document.addEventListener('click', function (e) {
      var a = e.target.closest('a[download][data-dl]');
      if (!a) return;
      e.preventDefault();
      var key = null;
      // 找到同卡片内带缓存键的图片（封面）
      var card = a.closest('.record-card');
      if (card) {
        var cover = card.querySelector('img[data-cache-key]');
        if (cover) key = cover.getAttribute('data-cache-key');
      } else {
        var m = (a.getAttribute('href') || '').match(/images\/([^/]+)$/);
        var target = document.querySelector('img[data-cache-key]');
        if (m && target && target.src.indexOf(m[1]) !== -1) key = target.getAttribute('data-cache-key');
      }
      if (!key) { window.open(a.href, '_blank'); return; }
      cacheGet(key).then(function (blob) {
        if (blob && blob.size > 0) {
          var url = URL.createObjectURL(blob);
          var tmp = document.createElement('a');
          tmp.href = url;
          tmp.download = a.getAttribute('download') || 'creation.png';
          document.body.appendChild(tmp);
          tmp.click();
          setTimeout(function () { URL.revokeObjectURL(url); tmp.remove(); }, 4000);
        } else {
          window.open(a.href, '_blank');
        }
      });
    });

    // 删除记录时同步清除对应缓存（尽力而为，事件已阻止默认后由表单提交）
    document.addEventListener('click', function (e) {
      var btn = e.target.closest('button[data-confirm]');
      if (!btn || !window.confirm) return;
      var card = btn.closest('.record-card');
      if (!card) return;
      var imgs = card.querySelectorAll('img[data-cache-key]');
      imgs.forEach(function (img) {
        cacheDelete(img.getAttribute('data-cache-key'));
      });
    });
  })();
})();