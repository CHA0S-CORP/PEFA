(function() {
    // Hide dots whose target section doesn't exist
    document.querySelectorAll('.nav-dot').forEach(dot => {
        const targetId = dot.dataset.section;
        if (!document.getElementById(targetId)) {
            dot.style.display = 'none';
        }
    });
    // Hide empty nav groups
    document.querySelectorAll('.nav-group').forEach(g => {
        const visibleDots = g.querySelectorAll('.nav-dot:not([style*="display: none"])');
        if (visibleDots.length === 0) g.style.display = 'none';
    });
    // Scroll-spy with IntersectionObserver
    const dots = document.querySelectorAll('.nav-dot');
    const sectionIds = Array.from(dots).map(d => d.dataset.section).filter(id => document.getElementById(id));
    const navObs = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            const dot = document.querySelector('.nav-dot[data-section="' + e.target.id + '"]');
            if (dot) {
                if (e.isIntersecting) dot.classList.add('active');
                else dot.classList.remove('active');
            }
        });
    }, { rootMargin: '-20% 0px -60% 0px', threshold: 0 });
    sectionIds.forEach(id => navObs.observe(document.getElementById(id)));
    // Click handlers with smooth scroll + offset
    dots.forEach(dot => {
        dot.addEventListener('click', (ev) => {
            ev.preventDefault();
            const target = document.getElementById(dot.dataset.section);
            if (target) {
                const y = target.getBoundingClientRect().top + window.pageYOffset - 20;
                window.scrollTo({ top: y, behavior: 'smooth' });
            }
        });
    });
})();
