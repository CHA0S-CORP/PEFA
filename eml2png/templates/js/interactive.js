(function() {
    // === Print button ===
    var printBtn = document.querySelector('.print-btn');
    if (printBtn) {
        printBtn.addEventListener('click', function() { window.print(); });
    }

    // === Smooth widget collapse/expand ===
    document.querySelectorAll('.widget').forEach(w => {
        const header = w.querySelector('.widget-header');
        if (!header) return;
        const children = Array.from(w.children).filter(c => c !== header);
        if (children.length === 0) return;
        const wrapper = document.createElement('div');
        wrapper.className = 'widget-content';
        children.forEach(c => wrapper.appendChild(c));
        w.appendChild(wrapper);
        header.style.cursor = 'pointer';
        header.addEventListener('click', () => {
            wrapper.classList.toggle('collapsed');
            header.classList.toggle('collapsed-header');
        });
    });

    // === Gemini section collapse/expand ===
    document.querySelectorAll('.gemini-section-toggle').forEach(header => {
        header.addEventListener('click', () => {
            header.parentElement.classList.toggle('collapsed');
        });
    });

    // === Widget entrance animations (IntersectionObserver) ===
    const animObs = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                e.target.classList.add('visible');
                animObs.unobserve(e.target);
            }
        });
    }, { threshold: 0.08 });
    document.querySelectorAll('.widget, .envelope').forEach(w => {
        if (w.classList.contains('threat-widget')) {
            w.classList.add('visible');
        } else {
            animObs.observe(w);
        }
    });

    // === Threat gauge count-up + ring animation ===
    const gaugeObs = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (!e.isIntersecting) return;
            gaugeObs.unobserve(e.target);
            const scoreEl = e.target.querySelector('.gauge-score[data-target]');
            const ringEl = e.target.querySelector('circle[data-target-dash]');
            if (!scoreEl) return;
            const target = parseInt(scoreEl.dataset.target) || 0;
            const targetDash = parseFloat(ringEl ? ringEl.dataset.targetDash : 0);
            const duration = 1200;
            const start = performance.now();
            function easeOut(t) { return 1 - Math.pow(1 - t, 3); }
            function tick(now) {
                const elapsed = now - start;
                const progress = Math.min(elapsed / duration, 1);
                const eased = easeOut(progress);
                scoreEl.textContent = Math.round(target * eased);
                if (ringEl) ringEl.setAttribute('stroke-dasharray', (targetDash * eased).toFixed(1) + ' 326.7');
                if (progress < 1) requestAnimationFrame(tick);
            }
            requestAnimationFrame(tick);
        });
    }, { threshold: 0.3 });
    const threatW = document.querySelector('.threat-widget');
    if (threatW) gaugeObs.observe(threatW);

    // === Copy-to-clipboard buttons ===
    function addCopyBtn(el, textFn) {
        const btn = document.createElement('button');
        btn.className = 'copy-btn';
        btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
        btn.title = 'Copy to clipboard';
        btn.addEventListener('click', (ev) => {
            ev.stopPropagation();
            const text = textFn();
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
            } else { fallbackCopy(text); }
            btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';
            const pill = document.createElement('span');
            pill.className = 'copy-feedback';
            pill.textContent = 'Copied!';
            btn.parentElement.style.position = 'relative';
            btn.parentElement.appendChild(pill);
            setTimeout(() => {
                btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>';
                if (pill.parentElement) pill.remove();
            }, 1500);
        });
        el.style.position = 'relative';
        el.appendChild(btn);
    }
    function fallbackCopy(text) {
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.cssText = 'position:fixed;left:-9999px';
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            ta.remove();
        } catch (err) {
            console.error('Fallback clipboard copy failed:', err);
        }
    }
    // IOC spans
    document.querySelectorAll('.ioc-wrap').forEach(el => {
        addCopyBtn(el, () => {
            const clone = el.cloneNode(true);
            clone.querySelectorAll('.ioc-badge, .copy-btn, .copy-feedback').forEach(x => x.remove());
            return clone.textContent.trim();
        });
    });
    // Attachment hashes
    document.querySelectorAll('.att-hash[data-full]').forEach(el => {
        addCopyBtn(el, () => el.dataset.full || el.textContent.trim());
    });

    // === Iframe auto-resize for email body ===
    function resizeIframe(iframe) {
        try {
            var doc = iframe.contentDocument || iframe.contentWindow.document;
            if (doc && doc.body) {
                var h = doc.documentElement.scrollHeight || doc.body.scrollHeight;
                iframe.style.height = Math.max(h, 200) + 'px';
            }
        } catch (e) { /* cross-origin blocked — keep min-height */ }
    }
    var bodyIframe = document.querySelector('.body-section iframe');
    if (bodyIframe) {
        bodyIframe.addEventListener('load', function() { resizeIframe(bodyIframe); });
        // Fallback resize after a delay (for slow-loading srcdoc)
        setTimeout(function() { resizeIframe(bodyIframe); }, 500);
    }

    // === Collapsible email body ===
    const bodySection = document.querySelector('.body-section');
    if (bodySection) {
        const container = document.createElement('div');
        container.className = 'body-collapse-container';
        bodySection.parentNode.insertBefore(container, bodySection);
        container.appendChild(bodySection);
        const overlay = document.createElement('div');
        overlay.className = 'body-fade-overlay';
        container.appendChild(overlay);
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'body-toggle-btn';
        toggleBtn.textContent = 'Show full email \u25BC';
        container.appendChild(toggleBtn);
        // Register click handler once (outside checkCollapse to avoid duplicates)
        toggleBtn.addEventListener('click', () => {
            const isCollapsed = bodySection.classList.contains('collapsed-body');
            bodySection.classList.toggle('collapsed-body');
            overlay.style.display = isCollapsed ? 'none' : '';
            toggleBtn.textContent = isCollapsed ? 'Collapse email \u25B2' : 'Show full email \u25BC';
            // Re-resize iframe when expanding
            if (isCollapsed && bodyIframe) resizeIframe(bodyIframe);
        });
        // Check height after iframe loads
        function checkCollapse() {
            if (bodySection.scrollHeight > 500) {
                bodySection.classList.add('collapsed-body');
                overlay.style.display = '';
                toggleBtn.style.display = '';
            } else {
                overlay.style.display = 'none';
                toggleBtn.style.display = 'none';
            }
        }
        if (bodyIframe) {
            bodyIframe.addEventListener('load', checkCollapse);
            setTimeout(checkCollapse, 600);
        } else {
            checkCollapse();
        }
    }

    // === Custom styled tooltips ===
    const tooltip = document.createElement('div');
    tooltip.className = 'custom-tooltip';
    document.body.appendChild(tooltip);
    document.querySelectorAll('[title]').forEach(el => {
        if (el.classList.contains('phish-hl-urgency') || el.classList.contains('phish-hl-link-warn')) return;
        const text = el.getAttribute('title');
        if (!text) return;
        el.setAttribute('data-tooltip', text);
        el.removeAttribute('title');
        el.addEventListener('mouseenter', (ev) => {
            tooltip.textContent = el.dataset.tooltip;
            tooltip.style.display = 'block';
            const rect = el.getBoundingClientRect();
            let top = rect.top - tooltip.offsetHeight - 8;
            let left = rect.left + rect.width / 2 - tooltip.offsetWidth / 2;
            if (top < 4) top = rect.bottom + 8;
            if (left < 4) left = 4;
            if (left + tooltip.offsetWidth > window.innerWidth - 4) left = window.innerWidth - tooltip.offsetWidth - 4;
            tooltip.style.top = top + 'px';
            tooltip.style.left = left + 'px';
            tooltip.style.opacity = '1';
        });
        el.addEventListener('mouseleave', () => {
            tooltip.style.display = 'none';
            tooltip.style.opacity = '0';
        });
    });

    // === Defang links inside email body iframe ===
    function defangIframeLinks() {
        if (!bodyIframe) return;
        try {
            var doc = bodyIframe.contentDocument || bodyIframe.contentWindow.document;
            if (!doc) return;
            doc.querySelectorAll('a').forEach(function(a) {
                a.removeAttribute('href');
                a.style.cursor = 'default';
                a.title = '(link disabled for safety)';
            });
        } catch (e) { /* cross-origin */ }
    }
    if (bodyIframe) {
        bodyIframe.addEventListener('load', defangIframeLinks);
        setTimeout(defangIframeLinks, 600);
    }
})();
