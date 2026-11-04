/* global document, window, performance, IntersectionObserver, ResizeObserver */
/* Lightweight vanilla implementations of the architecture section effects. */
document.addEventListener('DOMContentLoaded', () => {
  const section = document.querySelector('.architecture-section');
  const canvas = section?.querySelector('.grid-pulse-canvas');
  const context = canvas?.getContext('2d');
  const title = section?.querySelector('.typewriter-title');
  const liveTitle = section?.querySelector('.typewriter-live');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');

  // Type the existing heading once, preserving the full text for assistive tech.
  if (title && liveTitle) {
    const fullText = title.textContent.trim();
    const caret = document.createElement('span');
    caret.className = 'typewriter-caret';
    caret.setAttribute('aria-hidden', 'true');
    liveTitle.append(caret);

    if (reduceMotion.matches) {
      liveTitle.insertBefore(document.createTextNode(fullText), caret);
    } else {
      let index = 0;
      const typeNext = () => {
        if (index >= fullText.length) return;
        liveTitle.insertBefore(document.createTextNode(fullText[index]), caret);
        index += 1;
        window.setTimeout(typeNext, 44);
      };
      window.setTimeout(typeNext, 320);
    }
  }

  if (!section || !canvas || !context || reduceMotion.matches) return;

  const cell = 25;
  const reach = 2.6;
  const maxLit = 180;
  const cells = new Map();
  let width = 0;
  let height = 0;
  let columns = 1;
  let rows = 1;
  let frame = 0;
  let paintFrame = 0;
  let visible = false;
  let pointer = null;
  let clearRects = [];

  const easeOut = (value) => 1 - (1 - value) ** 2;
  const easeIn = (value) => value * value;

  const measureText = () => {
    const bounds = section.getBoundingClientRect();
    clearRects = [...section.querySelectorAll('[data-grid-avoid]')].flatMap((node) => {
      const range = document.createRange();
      range.selectNodeContents(node);
      const lines = [...range.getClientRects()].filter((rect) => rect.width && rect.height);
      return (lines.length ? lines : [node.getBoundingClientRect()]).map((rect) => ({
        left: rect.left - bounds.left - 6,
        top: rect.top - bounds.top - 6,
        right: rect.right - bounds.left + 6,
        bottom: rect.bottom - bounds.top + 6,
      }));
    });
  };

  const resize = () => {
    const bounds = section.getBoundingClientRect();
    width = section.clientWidth;
    height = section.clientHeight;
    columns = Math.max(1, Math.ceil(width / cell));
    rows = Math.max(1, Math.ceil(height / cell));
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    canvas.style.width = `${bounds.width}px`;
    canvas.style.height = `${bounds.height}px`;
    context.setTransform(dpr, 0, 0, dpr, 0, 0);
    measureText();
    draw(performance.now());
  };

  const brightness = (col, row) => {
    const x = col * cell + cell / 2;
    const y = row * cell + cell / 2;
    let nearest = Infinity;
    for (const rect of clearRects) {
      const dx = Math.max(rect.left - x, 0, x - rect.right);
      const dy = Math.max(rect.top - y, 0, y - rect.bottom);
      nearest = Math.min(nearest, Math.hypot(dx, dy));
      if (nearest === 0) break;
    }
    if (!Number.isFinite(nearest)) return 1;
    return 0.13 + 0.87 * Math.min(1, nearest / (2.2 * cell));
  };

  const wake = () => {
    if (!frame) frame = window.requestAnimationFrame(draw);
  };

  const light = (col, row, hold) => {
    if (col < 0 || row < 0 || col >= columns || row >= rows || cells.size >= maxLit) return;
    const key = `${col},${row}`;
    const now = performance.now();
    const previous = cells.get(key);
    if (previous && now < previous.until) return;
    const faded = previous ? 1 - easeIn(Math.min(1, (now - previous.until) / 750)) : 0;
    const born = previous ? now - (1 - Math.sqrt(1 - faded)) * 160 : now;
    const hue = 205 + (row / Math.max(rows - 1, 1)) * 105;
    cells.set(key, {
      col,
      row,
      colour: previous?.colour ?? `hsl(${Math.round(hue)} 72% 78%)`,
      dim: brightness(col, row),
      born,
      until: now + hold,
    });
    wake();
  };

  function draw(now = performance.now()) {
    frame = 0;
    context.clearRect(0, 0, width, height);
    for (const [key, item] of cells) {
      let alpha;
      if (now < item.until) {
        alpha = easeOut(Math.min(1, (now - item.born) / 160));
      } else {
        const fade = (now - item.until) / 750;
        if (fade >= 1) {
          cells.delete(key);
          continue;
        }
        alpha = 1 - easeIn(fade);
      }
      context.globalAlpha = alpha * item.dim * 0.48;
      context.fillStyle = item.colour;
      context.fillRect(item.col * cell + 1, item.row * cell + 1, cell - 1, cell - 1);
    }
    context.globalAlpha = 1;
    if (cells.size) frame = window.requestAnimationFrame(draw);
  }

  const paint = () => {
    paintFrame = 0;
    if (!pointer || !visible) return;
    const centerCol = Math.floor(pointer.x / cell);
    const centerRow = Math.floor(pointer.y / cell);
    const span = Math.ceil(reach);
    for (let dy = -span; dy <= span; dy += 1) {
      for (let dx = -span; dx <= span; dx += 1) {
        const distance = Math.hypot(dx, dy);
        if (distance > reach || Math.random() > 1 - distance / (reach + 0.6)) continue;
        light(centerCol + dx, centerRow + dy, 260 + Math.random() * 900);
      }
    }
  };

  const onPointerMove = (event) => {
    const bounds = section.getBoundingClientRect();
    if (event.clientY < bounds.top || event.clientY > bounds.bottom) {
      pointer = null;
      return;
    }
    pointer = { x: event.clientX - bounds.left, y: event.clientY - bounds.top };
    if (!paintFrame) paintFrame = window.requestAnimationFrame(paint);
  };

  const drift = () => {
    window.setTimeout(drift, 1400 + Math.random() * 1800);
    if (!visible || document.hidden) return;
    for (let i = 0; i < 2; i += 1) {
      light(
        Math.floor(Math.random() * columns),
        Math.floor(Math.random() * rows),
        900 + Math.random() * 1600,
      );
    }
  };

  const visibility = new IntersectionObserver(([entry]) => {
    visible = entry.isIntersecting;
  });
  visibility.observe(section);
  const observer = new ResizeObserver(resize);
  observer.observe(section);
  window.addEventListener('pointermove', onPointerMove, { passive: true });
  window.addEventListener('resize', measureText, { passive: true });
  document.fonts?.ready.then(measureText).catch(() => {});
  window.setTimeout(drift, 500);
  resize();
});
