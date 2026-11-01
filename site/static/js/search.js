// CKODEX OSKAL - Interactive Client-Side Search & Code Copy Utilities
// Pure ASCII, Zero External Dependencies, Air-Gap Ready.
(function() {
  'use strict';

  var searchModal = null;
  var searchInput = null;
  var searchResults = null;
  var searchData = null;
  var activeIndex = -1;

  // Fetch search index once
  function loadSearchIndex(callback) {
    if (searchData) {
      if (callback) callback(searchData);
      return;
    }
    var relUrl = window.CKODEX_INDEX_URL || 'index.json';
    fetch(relUrl)
      .then(function(res) {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then(function(data) {
        searchData = data;
        if (callback) callback(searchData);
      })
      .catch(function(err) {
        console.error('Failed to load search index:', err);
      });
  }

  function openSearch() {
    if (!searchModal) return;
    searchModal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    loadSearchIndex(function() {
      if (searchInput) {
        searchInput.focus();
        renderResults(searchInput.value.trim());
      }
    });
  }

  function closeSearch() {
    if (!searchModal) return;
    searchModal.style.display = 'none';
    document.body.style.overflow = '';
    if (searchInput) searchInput.value = '';
    activeIndex = -1;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function renderResults(query) {
    if (!searchResults) return;
    activeIndex = -1;
    if (!searchData || !query) {
      searchResults.innerHTML = '<div class="ck-search-empty">Type keywords to search NIST OSCAL specs, CLI commands, tutorials, and invariants...</div>';
      return;
    }

    var terms = query.toLowerCase().split(/\s+/).filter(Boolean);
    var matches = [];

    for (var i = 0; i < searchData.length; i++) {
      var item = searchData[i];
      var title = (item.title || '').toLowerCase();
      var desc = (item.description || '').toLowerCase();
      var section = (item.section || '').toLowerCase();
      var summary = (item.summary || '').toLowerCase();

      var score = 0;
      var matchedAll = true;

      for (var t = 0; t < terms.length; t++) {
        var term = terms[t];
        if (title.indexOf(term) !== -1) {
          score += 10;
        } else if (desc.indexOf(term) !== -1) {
          score += 5;
        } else if (section.indexOf(term) !== -1) {
          score += 3;
        } else if (summary.indexOf(term) !== -1) {
          score += 1;
        } else {
          matchedAll = false;
          break;
        }
      }

      if (matchedAll) {
        matches.push({ item: item, score: score });
      }
    }

    matches.sort(function(a, b) {
      return b.score - a.score;
    });

    if (matches.length === 0) {
      searchResults.innerHTML = '<div class="ck-search-empty">No results found for "' + escapeHtml(query) + '"</div>';
      return;
    }

    var html = '';
    var limit = Math.min(matches.length, 12);
    for (var m = 0; m < limit; m++) {
      var it = matches[m].item;
      html += '<a href="' + escapeHtml(it.url) + '" class="ck-search-result-item" data-index="' + m + '">';
      html += '<div class="ck-search-result-header">';
      html += '<span class="ck-search-result-title">' + escapeHtml(it.title) + '</span>';
      html += '<span class="ck-search-result-section">[' + escapeHtml(it.section || 'DOC') + ']</span>';
      html += '</div>';
      if (it.description) {
        html += '<div class="ck-search-result-desc">' + escapeHtml(it.description) + '</div>';
      }
      html += '</a>';
    }
    searchResults.innerHTML = html;

    // Highlight first item
    if (limit > 0) {
      setActiveItem(0);
    }
  }

  function setActiveItem(idx) {
    var items = searchResults.querySelectorAll('.ck-search-result-item');
    if (!items || items.length === 0) return;
    if (idx < 0) idx = 0;
    if (idx >= items.length) idx = items.length - 1;
    activeIndex = idx;

    for (var i = 0; i < items.length; i++) {
      if (i === activeIndex) {
        items[i].classList.add('is-active');
        items[i].scrollIntoView({ block: 'nearest' });
      } else {
        items[i].classList.remove('is-active');
      }
    }
  }

  function initSearch() {
    searchModal = document.getElementById('ck-search-modal');
    searchInput = document.getElementById('ck-search-input');
    searchResults = document.getElementById('ck-search-results');

    var searchBtn = document.getElementById('ck-search-btn');
    if (searchBtn) {
      searchBtn.addEventListener('click', openSearch);
    }

    var closeBtn = document.getElementById('ck-search-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', closeSearch);
    }

    var backdrop = document.querySelector('.ck-search-backdrop');
    if (backdrop) {
      backdrop.addEventListener('click', closeSearch);
    }

    if (searchInput) {
      searchInput.addEventListener('input', function() {
        renderResults(searchInput.value.trim());
      });

      searchInput.addEventListener('keydown', function(e) {
        var items = searchResults.querySelectorAll('.ck-search-result-item');
        if (e.key === 'ArrowDown') {
          e.preventDefault();
          setActiveItem(activeIndex + 1);
        } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          setActiveItem(activeIndex - 1);
        } else if (e.key === 'Enter') {
          if (activeIndex >= 0 && items[activeIndex]) {
            e.preventDefault();
            items[activeIndex].click();
          }
        } else if (e.key === 'Escape') {
          e.preventDefault();
          closeSearch();
        }
      });
    }

    // Global keyboard listener for '/' and 'Cmd+K' / 'Ctrl+K'
    document.addEventListener('keydown', function(e) {
      var tag = (e.target && e.target.tagName) ? e.target.tagName.toLowerCase() : '';
      var isInput = tag === 'input' || tag === 'textarea' || (e.target && e.target.isContentEditable);

      if ((e.key === '/' && !isInput) || ((e.metaKey || e.ctrlKey) && e.key === 'k')) {
        e.preventDefault();
        openSearch();
      } else if (e.key === 'Escape' && searchModal && searchModal.style.display !== 'none') {
        e.preventDefault();
        closeSearch();
      }
    });
  }

  // Code Block Copy Button Feature
  function initCodeCopy() {
    var preBlocks = document.querySelectorAll('pre');
    preBlocks.forEach(function(pre) {
      // Don't duplicate
      if (pre.querySelector('.ck-code-copy-btn')) return;

      var btn = document.createElement('button');
      btn.className = 'ck-code-copy-btn';
      btn.type = 'button';
      btn.setAttribute('aria-label', 'Copy code snippet to clipboard');
      btn.innerText = 'COPY';

      btn.addEventListener('click', function() {
        var code = pre.querySelector('code');
        var text = (code ? code.innerText : pre.innerText).trim();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function() {
            btn.innerText = 'COPIED';
            btn.classList.add('is-copied');
            setTimeout(function() {
              btn.innerText = 'COPY';
              btn.classList.remove('is-copied');
            }, 2000);
          }).catch(function() {
            btn.innerText = 'ERR';
          });
        }
      });

      pre.style.position = 'relative';
      pre.appendChild(btn);
    });
  }

  window.addEventListener('DOMContentLoaded', function() {
    initSearch();
    initCodeCopy();
  });
})();
