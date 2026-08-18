/* 兑换码管理页：兑换类型联动、批量选择/复制/备注/作废 */
(function () {
    var kindInputs = document.querySelectorAll('input[name="kind"]');
    var pointsField = document.getElementById('pointsField');
    var pointsInput = pointsField ? pointsField.querySelector('input[name="points"]') : null;
    function syncKind() {
        var isPoints = document.getElementById('kindPoints') && document.getElementById('kindPoints').checked;
        if (pointsField && pointsInput) {
            pointsField.style.display = isPoints ? '' : 'none';
            pointsInput.required = isPoints;
        }
    }
    kindInputs.forEach(function (el) { el.addEventListener('change', syncKind); });
    syncKind();

    var bulkBtn = document.getElementById('bulkCopyBtn');
    if (bulkBtn) {
        bulkBtn.addEventListener('click', function () {
            var ta = document.getElementById('bulkCodes');
            var text = ta ? ta.value : '';
            var done = function (ok) {
                bulkBtn.textContent = ok ? '已复制' : '复制失败';
                setTimeout(function () { bulkBtn.textContent = '一键复制全部'; }, 1600);
            };
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
                return;
            }
            ta.focus();
            ta.select();
            var ok = false;
            try { ok = document.execCommand('copy'); } catch (e) {}
            done(ok);
        });
    }

    /* ---------- 批量选择 / 复制 / 备注 / 作废 ---------- */
    var checks = Array.prototype.slice.call(document.querySelectorAll('.code-check'));
    var selCount = document.getElementById('selCount');
    var checkAll = document.getElementById('checkAll');
    var batchRemarkIds = document.getElementById('batchRemarkIds');
    var batchVoidIds = document.getElementById('batchVoidIds');

    function selected() {
        return checks.filter(function (c) { return c.checked; });
    }
    function refreshCount() {
        var n = selected().length;
        if (selCount) selCount.textContent = '已选 ' + n + ' 个';
        var ids = selected().map(function (c) {
            return c.closest('tr').getAttribute('data-id');
        }).join(',');
        if (batchRemarkIds) batchRemarkIds.value = ids;
        if (batchVoidIds) batchVoidIds.value = ids;
    }
    checks.forEach(function (c) {
        c.addEventListener('change', function () {
            if (checkAll) checkAll.checked = checks.length > 0 && selected().length === checks.length;
            refreshCount();
        });
    });
    if (checkAll) {
        checkAll.addEventListener('change', function () {
            checks.forEach(function (c) { c.checked = checkAll.checked; });
            refreshCount();
        });
    }
    refreshCount();

    function copyBatch(getText) {
        var sel = selected();
        if (!sel.length) {
            window.alert('请先勾选要复制的兑换码');
            return false;
        }
        var text = sel.map(getText).join('\n');
        var done = function (ok) {
            if (ok) {
                window.alert('已复制 ' + sel.length + ' 个码到剪贴板');
            } else {
                window.alert('复制失败，请重试');
            }
        };
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
            return true;
        }
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        var ok = false;
        try { ok = document.execCommand('copy'); } catch (e) {}
        document.body.removeChild(ta);
        done(ok);
        return true;
    }
    var copySelLine = document.getElementById('copySelLine');
    if (copySelLine) {
        copySelLine.addEventListener('click', function () {
            copyBatch(function (c) { return c.getAttribute('data-line'); });
        });
    }
    var copySelCode = document.getElementById('copySelCode');
    if (copySelCode) {
        copySelCode.addEventListener('click', function () {
            copyBatch(function (c) { return c.getAttribute('data-code'); });
        });
    }
    var batchRemarkForm = document.getElementById('batchRemarkForm');
    if (batchRemarkForm) {
        batchRemarkForm.addEventListener('submit', function (e) {
            if (!batchRemarkIds || !batchRemarkIds.value) {
                e.preventDefault();
                window.alert('请先勾选要备注的兑换码');
                return;
            }
            var remarkInput = batchRemarkForm.querySelector('input[name="remark"]');
            if (remarkInput && !remarkInput.value.trim()) {
                e.preventDefault();
                window.alert('请填写备注内容');
            }
        });
    }
    var batchVoidForm = document.getElementById('batchVoidForm');
    if (batchVoidForm) {
        batchVoidForm.addEventListener('submit', function (e) {
            if (!batchVoidIds || !batchVoidIds.value) {
                e.preventDefault();
                window.alert('请先勾选要作废的兑换码');
            }
        });
    }
})();