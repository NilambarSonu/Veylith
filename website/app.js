/* global document, navigator, setTimeout, console */
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
    });

    // Close when clicking a nav link
    navLinks.querySelectorAll('a').forEach((link) => {
      link.addEventListener('click', () => {
        navLinks.classList.remove('open');
        mobileBtn.setAttribute('aria-expanded', 'false');
      });
    });
  }

  // 2. Tab Navigation
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');

      tabButtons.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      tabContents.forEach((c) => c.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }
    });
  });

  // 3. Clipboard Copy Handling
  const copyButtons = document.querySelectorAll('.copy-btn, .code-copy-btn, .terminal-copy-btn');

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

      try {
        await navigator.clipboard.writeText(textToCopy);
        const originalText = btn.innerHTML;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!`;
        btn.style.color = '#10B981';

        setTimeout(() => {
          btn.innerHTML = originalText;
          btn.style.color = '';
        }, 2000);
      } catch (err) {
        console.error('Failed to copy to clipboard:', err);
      }
    });
  });

  // 4. KokonutUI Split Navigation Interaction
  const splitNavList = document.querySelector('.split-nav-list');
  const splitItems = document.querySelectorAll('.split-nav-item');

  if (splitNavList && splitItems.length > 0) {
    splitItems.forEach((item, idx) => {
      item.addEventListener('mouseenter', () => {
        splitItems.forEach((other, oIdx) => {
          if (oIdx < idx) {
            other.style.transform = 'translateX(-3px)';
          } else if (oIdx > idx) {
            other.style.transform = 'translateX(3px)';
          } else {
            other.style.transform = 'translateX(0) scale(1.02)';
          }
        });
      });

      item.addEventListener('mouseleave', () => {
        splitItems.forEach((other) => {
          other.style.transform = '';
        });
      });

      item.addEventListener('click', () => {
        splitItems.forEach((other) => other.classList.remove('active'));
        item.classList.add('active');
      });
    });
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
