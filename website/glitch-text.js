/* global document, setTimeout */
/**
 * KokonutUI GlitchText (Signal Text) Engine
 * Ported from KokonutUI GlitchText component (component_code_prompts.txt)
 * Flat text that bursts into hard-cut horizontal bands with chromatic red/cyan channel split.
 * Engineered with clean single-source rendering to prevent any duplicate text bug.
 */

(function () {
  const HOLD = 'steps(1, end)';
  const MAX_BANDS = 4;
  const STILL_CHANCE = 0.25;

  const round = (n) => Math.round(n * 1000) / 1000;

  function randomCuts(count) {
    const weights = Array.from({ length: count }, () => 0.55 + Math.random());
    const total = weights.reduce((a, b) => a + b, 0);
    const cuts = [0];
    for (const w of weights) {
      cuts.push(round((cuts[cuts.length - 1] || 0) + (w / total) * 100));
    }
    return cuts;
  }

  function jump(max) {
    if (Math.random() < STILL_CHANCE) return 0;
    const sign = Math.random() < 0.5 ? -1 : 1;
    return round(sign * (0.25 + 0.75 * Math.random()) * max);
  }

  function held(frames) {
    return [
      ...frames.map((k, i) => ({ ...k, offset: i / frames.length, easing: HOLD })),
      { ...frames[frames.length - 1], offset: 1 },
    ];
  }

  function initGlitchText() {
    const elements = document.querySelectorAll('.kokonut-glitch-text');
    if (!elements || elements.length === 0) return;

    elements.forEach((el) => {
      // Prevent multiple initializations
      if (el.dataset.glitchInitialized) return;
      el.dataset.glitchInitialized = 'true';

      const text = el.getAttribute('data-text') || el.textContent.trim();
      el.setAttribute('aria-label', text);
      el.setAttribute('role', 'text');
      el.innerHTML = '';

      const layers = document.createElement('span');
      layers.className = 'glitch-layers';
      layers.setAttribute('aria-hidden', 'true');

      // 1. Red chromatic channel
      const redChan = document.createElement('span');
      redChan.className = 'glitch-layer glitch-channel-red';
      redChan.textContent = text;
      layers.appendChild(redChan);

      // 2. Cyan chromatic channel
      const cyanChan = document.createElement('span');
      cyanChan.className = 'glitch-layer glitch-channel-cyan';
      cyanChan.textContent = text;
      layers.appendChild(cyanChan);

      // 3. Horizontal slicing bands
      const bands = [];
      for (let i = 0; i < MAX_BANDS; i++) {
        const band = document.createElement('span');
        band.className = 'glitch-layer glitch-band';
        band.textContent = text;
        layers.appendChild(band);
        bands.push(band);
      }

      // 4. Base text — the ONLY visible element in rest state
      const baseText = document.createElement('span');
      baseText.className = 'glitch-layer glitch-base';
      baseText.textContent = text;
      layers.appendChild(baseText);

      el.appendChild(layers);

      let running = false;

      function burst() {
        if (running) return;
        running = true;

        const frames = 6;
        const frameMs = 45;
        const opts = { duration: frames * frameMs, fill: 'none' };
        const anims = [];

        // Base text hides during burst
        anims.push(
          baseText.animate(
            held(
              Array.from({ length: frames }, () => ({
                opacity: 0,
              })),
            ),
            opts,
          ),
        );

        // Chromatic split
        anims.push(
          redChan.animate(
            held(
              Array.from({ length: frames }, () => ({
                opacity: Math.random() < STILL_CHANCE ? 0 : 0.85,
                transform: `translate(${jump(6)}px, 0)`,
              })),
            ),
            opts,
          ),
        );

        anims.push(
          cyanChan.animate(
            held(
              Array.from({ length: frames }, () => ({
                opacity: Math.random() < STILL_CHANCE ? 0 : 0.85,
                transform: `translate(${jump(6)}px, 0)`,
              })),
            ),
            opts,
          ),
        );

        // Horizontal band cuts
        bands.forEach((band) => {
          anims.push(
            band.animate(
              held(
                Array.from({ length: frames }, () => {
                  const cuts = randomCuts(MAX_BANDS);
                  const idx = Math.floor(Math.random() * (cuts.length - 1));
                  const top = cuts[idx];
                  const bot = cuts[idx + 1];
                  return {
                    opacity: 1,
                    transform: `translate(${jump(10)}px, 0)`,
                    clipPath: `polygon(0% ${top}%, 100% ${top}%, 100% ${bot}%, 0% ${bot}%)`,
                  };
                }),
              ),
              opts,
            ),
          );
        });

        const lastAnim = anims[0];
        if (lastAnim) {
          lastAnim.onfinish = () => {
            running = false;
          };
        } else {
          running = false;
        }
      }

      // Hover trigger
      el.addEventListener('pointerenter', () => {
        burst();
      });

      // Periodic trigger (every 4 to 7 seconds)
      function scheduleNext() {
        const delay = 4500 + Math.random() * 3000;
        setTimeout(() => {
          burst();
          scheduleNext();
        }, delay);
      }
      scheduleNext();
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initGlitchText);
  } else {
    initGlitchText();
  }
})();
