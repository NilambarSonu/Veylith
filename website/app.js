/* global document, navigator, setTimeout, window, IntersectionObserver */
// Veylith Landing Page Client JavaScript
document.addEventListener('DOMContentLoaded', () => {
  // 1. Mobile Menu Toggle
  const mobileBtn = document.querySelector('.mobile-menu-btn');
  const navLinks =
    document.querySelector('.split-nav-container') || document.querySelector('.nav-links');

  if (mobileBtn && navLinks) {
    mobileBtn.addEventListener('click', () => {
      const isOpen = navLinks.classList.toggle('open');
      mobileBtn.setAttribute('aria-expanded', isOpen);
      mobileBtn.setAttribute('aria-label', isOpen ? 'Close navigation' : 'Open navigation');
    });

    // Close when clicking a nav link
    navLinks.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('open');
        mobileBtn.setAttribute('aria-expanded', 'false');
        mobileBtn.setAttribute('aria-label', 'Open navigation');
      });
    });

    document.addEventListener('keydown', (event) => {
      if (event.key !== 'Escape' || !navLinks.classList.contains('open')) return;
      navLinks.classList.remove('open');
      mobileBtn.setAttribute('aria-expanded', 'false');
      mobileBtn.setAttribute('aria-label', 'Open navigation');
      mobileBtn.focus();
    });
  }

  // 2. Tab Navigation
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  function activateTab(btn, moveFocus = false) {
    const targetId = btn.getAttribute('data-tab');

    tabButtons.forEach((b) => {
      b.classList.remove('active');
      b.setAttribute('aria-selected', 'false');
      b.tabIndex = -1;
    });
    tabContents.forEach((c) => {
      c.classList.remove('active');
      c.hidden = true;
    });

    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    btn.tabIndex = 0;
    const targetContent = document.getElementById(targetId);
    if (targetContent) {
      targetContent.classList.add('active');
      targetContent.hidden = false;
    }
    if (moveFocus) btn.focus();
  }

  tabButtons.forEach((btn, index) => {
    btn.addEventListener('click', () => activateTab(btn));
    btn.addEventListener('keydown', (event) => {
      let nextIndex;
      if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
        nextIndex = (index + 1) % tabButtons.length;
      } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
        nextIndex = (index - 1 + tabButtons.length) % tabButtons.length;
      } else if (event.key === 'Home') {
        nextIndex = 0;
      } else if (event.key === 'End') {
        nextIndex = tabButtons.length - 1;
      } else {
        return;
      }
      event.preventDefault();
      activateTab(tabButtons[nextIndex], true);
    });
  });

  // 3. Clipboard Copy Handling
  const copyButtons = document.querySelectorAll('.copy-btn, .code-copy-btn, .terminal-copy-btn');
  const copyStatus = document.querySelector('.copy-status');

  copyButtons.forEach((btn) => {
    btn.addEventListener('click', async () => {
      let textToCopy = btn.getAttribute('data-copy');

      if (!textToCopy) {
        // Fallback: look for sibling pre code or nearest code-container pre
        const container = btn.closest('.code-container, .terminal-row, .magic-terminal-card');
        if (container) {
          const pre = container.querySelector('pre, .terminal-code, .terminal-typing-text');
          if (pre) {
            textToCopy = pre.innerText.trim();
          }
        }
      }

      if (!textToCopy) return;

      let copiedSuccessfully = false;
      if (navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(textToCopy);
          copiedSuccessfully = true;
        } catch {
          // Fall through to execCommand fallback
        }
      }

      if (!copiedSuccessfully) {
        try {
          const textarea = document.createElement('textarea');
          textarea.value = textToCopy;
          textarea.style.position = 'fixed';
          textarea.style.top = '0';
          textarea.style.left = '0';
          textarea.style.opacity = '0';
          document.body.append(textarea);
          textarea.focus();
          textarea.select();
          textarea.setSelectionRange(0, textarea.value.length);
          copiedSuccessfully = document.execCommand('copy');
          textarea.remove();
        } catch {
          copiedSuccessfully = false;
        }
      }

      if (copiedSuccessfully) {
        const originalText = btn.textContent;
        const originalLabel = btn.getAttribute('aria-label') || 'Copy code';
        btn.textContent = 'Copied';
        btn.setAttribute('aria-label', 'Code copied');
        btn.classList.add('is-copied');
        if (copyStatus) copyStatus.textContent = 'Active code copied to clipboard.';

        setTimeout(() => {
          btn.textContent = originalText;
          btn.setAttribute('aria-label', originalLabel);
          btn.classList.remove('is-copied');
        }, 2000);
      } else {
        if (copyStatus)
          copyStatus.textContent = 'Could not copy code. Select the code and copy it manually.';
      }
    });
  });

  // 4. KokonutUI Split Navigation Engine (component_code_prompts.txt)
  const splitTrack = document.getElementById('split-nav-track');
  if (splitTrack) {
    const segments = Array.from(splitTrack.querySelectorAll('.split-segment'));
    const count = segments.length;
    let activeIndex = segments.findIndex((s) => s.classList.contains('active'));
    if (activeIndex === -1) activeIndex = 0;
    let hoverIndex = null;

    // KokonutUI constants from component_code_prompts.txt
    const SPLIT = 10; // Gap opened on each side of the active link in px
    const HOVER_SPLIT = 3; // Gap a hovered link opens around itself in px

    function bump(focus, k) {
      return Math.max(0, 1 - Math.abs(focus - k));
    }

    function calculateOffsets(focus, hover) {
      const cumulative = [0];
      let total = 0;
      for (let joint = 0; joint < count - 1; joint++) {
        let gap = SPLIT * Math.max(bump(focus, joint), bump(focus, joint + 1));
        const hoverJoint =
          hover !== null && hover !== Math.round(focus) && (joint === hover - 1 || joint === hover);
        if (hoverJoint) {
          gap = Math.max(gap, HOVER_SPLIT);
        }
        total += gap;
        cumulative.push(total);
      }
      return cumulative.map((x) => Math.round((x - total / 2) * 100) / 100);
    }

    function applyOffsets() {
      // Don't apply translate offsets on small mobile screens
      if (window.innerWidth <= 768) {
        segments.forEach((seg) => {
          seg.style.transform = '';
        });
        return;
      }
      const focus = hoverIndex !== null ? hoverIndex : activeIndex;
      const offsets = calculateOffsets(focus, hoverIndex);
      segments.forEach((seg, i) => {
        seg.style.transform = `translate3d(${offsets[i]}px, 0, 0)`;
      });
    }

    segments.forEach((seg, idx) => {
      seg.addEventListener('pointerenter', () => {
        hoverIndex = idx;
        applyOffsets();
      });

      seg.addEventListener('pointerleave', () => {
        hoverIndex = null;
        applyOffsets();
      });

      seg.querySelector('.split-link')?.addEventListener('click', () => {
        segments.forEach((s) => {
          s.classList.remove('active');
          s.querySelector('.split-link')?.removeAttribute('aria-current');
        });
        seg.classList.add('active');
        seg.querySelector('.split-link')?.setAttribute('aria-current', 'location');
        activeIndex = idx;
        applyOffsets();
      });
    });

    const sectionLinks = segments
      .map((segment) => segment.querySelector('.split-link'))
      .filter((link) => link?.hash && document.querySelector(link.hash));
    if ('IntersectionObserver' in window && sectionLinks.length) {
      const sectionObserver = new IntersectionObserver(
        (entries) => {
          const visibleEntry = entries
            .filter((entry) => entry.isIntersecting)
            .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];
          if (!visibleEntry) return;
          const current = sectionLinks.find((link) => link.hash === `#${visibleEntry.target.id}`);
          if (!current) return;
          segments.forEach((segment, i) => {
            const link = segment.querySelector('.split-link');
            const isCurrent = link === current;
            segment.classList.toggle('active', isCurrent);
            if (isCurrent) link.setAttribute('aria-current', 'location');
            else link.removeAttribute('aria-current');
            if (isCurrent) activeIndex = i;
          });
          if (hoverIndex === null) applyOffsets();
        },
        { rootMargin: '-25% 0px -60% 0px', threshold: [0, 0.2, 0.5] },
      );
      sectionLinks.forEach((link) => sectionObserver.observe(document.querySelector(link.hash)));
    }

    window.addEventListener('resize', applyOffsets, { passive: true });

    // Initial mount
    applyOffsets();
  }

  // 5. Magic UI Terminal Sequential Typing & Step Animation
  const typingEl = document.querySelector('.terminal-typing-text');
  const stepLines = document.querySelectorAll('.terminal-step-line');
  const commandToType =
    'npx veylith -- npx -y @modelcontextprotocol/server-filesystem ~/mcp-sandbox';

  if (typingEl) {
    let charIdx = 0;
    typingEl.textContent = '';

    function typeChar() {
      if (charIdx < commandToType.length) {
        typingEl.textContent += commandToType.charAt(charIdx);
        charIdx++;
        setTimeout(typeChar, 28);
      } else {
        // Once command is typed, sequentially reveal each execution step
        revealSteps(0);
      }
    }

    function revealSteps(stepIdx) {
      if (stepIdx < stepLines.length) {
        stepLines[stepIdx].classList.add('visible');
        setTimeout(() => revealSteps(stepIdx + 1), 220);
      }
    }

    // Trigger typing slightly after initial mount
    setTimeout(typeChar, 600);
  }
});
