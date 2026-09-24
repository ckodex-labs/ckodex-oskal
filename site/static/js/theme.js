// CKODEX-DS-3 Theme & Shell Controller
// Enforces: ledger (canonical default), vault (night shift), hc (high contrast)
(function() {
  const STORAGE_KEY = 'ckodex_theme';
  const MARGIN_KEY = 'ckodex_margin_collapsed';

  function applyTheme(theme) {
    if (!['ledger', 'vault', 'hc'].includes(theme)) {
      theme = 'ledger';
    }
    document.documentElement.setAttribute('data-theme', theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (e) {}

    // Update active button state
    document.querySelectorAll('.ck-theme-btn').forEach(btn => {
      if (btn.getAttribute('data-set-theme') === theme) {
        btn.setAttribute('aria-pressed', 'true');
        btn.classList.add('active');
      } else {
        btn.setAttribute('aria-pressed', 'false');
        btn.classList.remove('active');
      }
    });
  }

  // Initialize theme immediately
  let savedTheme = 'ledger';
  try {
    savedTheme = localStorage.getItem(STORAGE_KEY) || 'ledger';
  } catch (e) {}
  applyTheme(savedTheme);

  window.addEventListener('DOMContentLoaded', () => {
    // Theme toggle buttons
    document.querySelectorAll('.ck-theme-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        const targetTheme = btn.getAttribute('data-set-theme');
        applyTheme(targetTheme);
      });
    });

    // Evidence margin collapse / expand
    const marginToggle = document.getElementById('margin-toggle');
    const marginAside = document.querySelector('.ck-shell__margin');

    function setMarginCollapsed(collapsed) {
      if (!marginAside) return;
      if (collapsed) {
        marginAside.setAttribute('data-ck-margin-collapsed', 'true');
        if (marginToggle) marginToggle.setAttribute('aria-expanded', 'false');
      } else {
        marginAside.removeAttribute('data-ck-margin-collapsed');
        if (marginToggle) marginToggle.setAttribute('aria-expanded', 'true');
      }
      try {
        localStorage.setItem(MARGIN_KEY, collapsed ? 'true' : 'false');
      } catch (e) {}
    }

    if (marginToggle && marginAside) {
      marginToggle.addEventListener('click', () => {
        const isCollapsed = marginAside.getAttribute('data-ck-margin-collapsed') === 'true';
        setMarginCollapsed(!isCollapsed);
      });

      try {
        if (localStorage.getItem(MARGIN_KEY) === 'true') {
          setMarginCollapsed(true);
        }
      } catch (e) {}
    }

    // Copy digest utility
    document.querySelectorAll('.ck-hash[data-copy]').forEach(el => {
      el.addEventListener('click', () => {
        const text = el.getAttribute('data-copy');
        if (text) {
          navigator.clipboard.writeText(text).then(() => {
            const orig = el.innerText;
            el.innerText = 'COPIED';
            setTimeout(() => { el.innerText = orig; }, 1200);
          });
        }
      });
    });
  });
})();
