/* global document, window, performance, ResizeObserver, IntersectionObserver, requestAnimationFrame, cancelAnimationFrame */
/* Vanilla canvas port of the supplied Ridgeline Dither Footer component. */
(() => {
  const footer = document.querySelector('.rdf-root');
  const scene = footer?.querySelector('.rdf-scene');
  const canvas = scene?.querySelector('canvas');
  if (!footer || !scene || !canvas) return;

  const ctx = canvas.getContext('2d', { alpha: false });
  if (!ctx) return;
  footer.classList.add('rdf-enhanced');

  const tones = ['#f2f6fa', '#d6e6f4', '#a8cae7', '#6b9ecc', '#34679a', '#1a3e66', '#0b2140'];
  const seed = 27;
  const layers = 7;
  const pixel = 2;
  const mist = 0.78;
  const drift = 1;
  const radius = 130;
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const palette = new Uint32Array(tones.map((tone) => pack(hex(tone))));
  const bayer = [
    0, 32, 8, 40, 2, 34, 10, 42, 48, 16, 56, 24, 50, 18, 58, 26, 12, 44, 4, 36, 14, 46, 6, 38, 60,
    28, 52, 20, 62, 30, 54, 22, 3, 35, 11, 43, 1, 33, 9, 41, 51, 19, 59, 27, 49, 17, 57, 25, 15, 47,
    7, 39, 13, 45, 5, 37, 63, 31, 55, 23, 61, 29, 53, 21,
  ].map((value) => (value + 0.5) / 64);

  function hex(value) {
    const match = /^#?([\da-f]{3}|[\da-f]{6})$/i.exec(value.trim());
    if (!match) return [128, 128, 128];
    const full =
      match[1].length === 3
        ? match[1]
            .split('')
            .map((c) => c + c)
            .join('')
        : match[1];
    return [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
  }

  function pack(rgb) {
    return ((255 << 24) | (rgb[2] << 16) | (rgb[1] << 8) | rgb[0]) >>> 0;
  }

  function hash(x, y, salt) {
    let h =
      Math.imul(x | 0, 374761393) + Math.imul(y | 0, 668265263) + Math.imul(salt | 0, 1442695041);
    h = Math.imul(h ^ (h >>> 13), 1274126177);
    h ^= h >>> 16;
    return (h >>> 0) / 4294967296;
  }

  function noise(x, y, salt) {
    const xi = Math.floor(x);
    const yi = Math.floor(y);
    const xf = x - xi;
    const yf = y - yi;
    const u = xf * xf * (3 - 2 * xf);
    const v = yf * yf * (3 - 2 * yf);
    const a = hash(xi, yi, salt);
    const b = hash(xi + 1, yi, salt);
    const c = hash(xi, yi + 1, salt);
    const d = hash(xi + 1, yi + 1, salt);
    return a + (b - a) * u + (c - a) * v + (a - b - c + d) * u * v;
  }

  function fbm(x, y, salt, octaves) {
    let sum = 0;
    let amp = 0.5;
    let norm = 0;
    for (let octave = 0; octave < octaves; octave += 1) {
      sum += noise(x, y, salt + octave * 31) * amp;
      norm += amp;
      x *= 2.03;
      y *= 2.03;
      amp *= 0.5;
    }
    return norm ? sum / norm : 0;
  }

  function smooth(edge0, edge1, value) {
    const t =
      edge0 === edge1
        ? value < edge0
          ? 0
          : 1
        : Math.min(1, Math.max(0, (value - edge0) / (edge1 - edge0)));
    return t * t * (3 - 2 * t);
  }

  function ease(value) {
    return 1 - Math.pow(1 - Math.min(1, Math.max(0, value)), 3);
  }

  function ridge(cols, rows, index, count, baseSeed, margin) {
    const k = count > 1 ? index / (count - 1) : 1;
    const out = new Float32Array(cols + margin * 2);
    const base = rows * (0.38 + 0.66 * Math.pow(k, 1.4));
    const amp = rows * (0.2 + 0.24 * k);
    const freq = 6 - 3.8 * k;
    const flankL = rows * 0.5 * k ** 3 * (0.55 + 0.6 * hash(index, 11, baseSeed));
    const flankR = rows * 0.5 * k ** 3 * (0.55 + 0.6 * hash(index, 13, baseSeed));
    const ceiling = rows * 0.17;
    const tilt = (hash(index, 7, baseSeed) - 0.5) * rows * 0.34 * (0.4 + k);
    const salt = (baseSeed | 0) * 13 + index * 101;
    for (let x = 0; x < out.length; x += 1) {
      const u = (x - margin) / cols;
      const r1 = 1 - Math.abs(noise(u * freq + index * 3.7, 0.5, salt) * 2 - 1);
      const r2 = 1 - Math.abs(noise(u * freq * 2.3, 3.5, salt + 1) * 2 - 1);
      const fractal = fbm(u * freq * 4.1, 9.5, salt + 2, 3);
      const peak = r1 * r1 * 0.62 + r2 * 0.24 + fractal * 0.14;
      const edge = Math.min(1.2, Math.abs(u * 2 - 1));
      const y =
        base -
        peak * amp +
        tilt * (u - 0.5) * 2 -
        (u < 0.5 ? flankL : flankR) * edge ** 2 * Math.sqrt(edge);
      out[x] = y < ceiling ? ceiling - (ceiling - y) * 0.25 : y;
    }
    return out;
  }

  const elevation = (crest, rows, layer) =>
    Math.round(
      420 + (1 - Math.min(1, Math.max(0, crest / rows))) * 2600 + (layers - 1 - layer) * 140,
    );
  const altimeter = scene.querySelector('.rdf-alt');
  const altText = altimeter?.querySelector('span');
  const state = {
    cols: 1,
    rows: 1,
    margin: 2,
    image: null,
    pixels: null,
    tops: [],
    pools: [],
    colTop: new Float32Array(0),
    colSlope: new Float32Array(0),
    colPool: new Float32Array(0),
    fog: new Float32Array(0),
    fogWidth: 1,
    fogHeight: 1,
    ceil: 0,
    fadeTo: 1,
  };
  const pointer = {
    x: 0,
    y: 0,
    tx: 0,
    ty: 0,
    inside: false,
    clear: 0,
    parallax: 0,
    targetParallax: 0,
  };
  let revealAt = null;
  let windVelocity = 0;
  let windOffset = 0;
  let raf = 0;
  let visible = false;
  let lastTick = performance.now();
  let lastDraw = 0;
  let altShown = false;

  const layout = () => {
    const rect = scene.getBoundingClientRect();
    state.cols = Math.max(8, Math.ceil(rect.width / pixel));
    state.rows = Math.max(8, Math.ceil(rect.height / pixel));
    state.margin = Math.ceil(state.cols * 0.045) + 3;
    canvas.width = state.cols;
    canvas.height = state.rows;
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    state.image = ctx.createImageData(state.cols, state.rows);
    state.pixels = new Uint32Array(state.image.data.buffer);
    state.ceil = Math.max(state.rows * 0.17, 92 / pixel);
    state.fadeTo = Math.max(state.rows * 0.3, 128 / pixel);
    state.tops = [];
    state.pools = [];
    for (let i = 0; i < layers; i += 1) {
      const peaks = ridge(state.cols, state.rows, i, layers, seed, state.margin);
      for (let x = 0; x < peaks.length; x += 1) {
        if (peaks[x] < state.ceil) peaks[x] = state.ceil - (state.ceil - peaks[x]) * 0.2;
      }
      const pool = new Float32Array(peaks.length);
      for (let x = 0; x < peaks.length; x += 1) {
        pool[x] = 0.45 + 1.1 * fbm(((x - state.margin) / state.cols) * 4, i * 5.3, seed + 9, 2);
      }
      state.tops.push(peaks);
      state.pools.push(pool);
    }
    state.colTop = new Float32Array(layers * state.cols);
    state.colSlope = new Float32Array(layers * state.cols);
    state.colPool = new Float32Array(layers * state.cols);
    state.fogWidth = (state.cols >> 1) + 2;
    state.fogHeight = (state.rows >> 1) + 2;
    state.fog = new Float32Array(state.fogWidth * state.fogHeight);
  };

  function draw(now) {
    if (!state.image) return;
    const dt = Math.min(64, now - lastTick);
    lastTick = now;
    const age = revealAt === null ? -1 : now - revealAt;
    const easeFactor = 1 - Math.pow(0.82, dt / 16.7);
    const slowFactor = 1 - Math.pow(0.93, dt / 16.7);
    pointer.x += (pointer.tx - pointer.x) * easeFactor;
    pointer.y += (pointer.ty - pointer.y) * easeFactor;
    pointer.clear += ((pointer.inside ? 1 : 0) - pointer.clear) * slowFactor;
    pointer.parallax += (pointer.targetParallax - pointer.parallax) * slowFactor;
    windVelocity *= Math.pow(0.965, dt / 16.7);
    windOffset += (windVelocity * dt) / 1000;
    const fogTime = (reduced ? 0 : (now / 1000) * 0.045 * drift) + windOffset;

    const sx = 9 / state.cols;
    const sy = 4.4 / state.rows;
    for (let gy = 0; gy < state.fogHeight; gy += 1) {
      const ny = gy * sy;
      for (let gx = 0; gx < state.fogWidth; gx += 1) {
        const nx = gx * sx + fogTime;
        const warp = noise(nx * 0.45 - fogTime * 0.6, ny * 0.8, 77) * 0.6;
        state.fog[gy * state.fogWidth + gx] = smooth(
          0.3,
          0.74,
          fbm(nx + warp, ny + warp * 0.4, 31, 3),
        );
      }
    }

    const reveal = new Float32Array(layers);
    const depthTone = new Float32Array(layers);
    const fogDepth = new Float32Array(layers);
    for (let i = 0; i < layers; i += 1) {
      const k = i / (layers - 1);
      reveal[i] = age < 0 ? 0 : ease((age - 380 - i * 170) / 1300);
      depthTone[i] = 0.16 + 0.76 * Math.pow(k, 1.6);
      fogDepth[i] = state.rows * (0.08 + 0.42 * k);
      const rise = (1 - reveal[i]) * state.rows * 0.09;
      const shift = Math.round(pointer.parallax * (0.25 + k) * 0.75 * (state.margin - 3));
      const peaks = state.tops[i];
      for (let x = 0; x < state.cols; x += 1) {
        const at = x + state.margin + shift;
        state.colTop[i * state.cols + x] = peaks[at] + rise;
        state.colSlope[i * state.cols + x] =
          peaks[Math.min(peaks.length - 1, at + 2)] - peaks[Math.max(0, at - 2)];
        state.colPool[i * state.cols + x] = fogDepth[i] * state.pools[i][at];
      }
    }
    const lift = age < 0 ? 1 : 1 - ease((age - 900) / 1800);
    const radiusCells = Math.max(1, radius / pixel);
    const radiusSquared = radiusCells * radiusCells;

    for (let y = 0; y < state.rows; y += 1) {
      const fade = smooth(0, state.fadeTo, y);
      const fogRow = (y >> 1) * state.fogWidth;
      const bayerRow = (y & 7) * 8;
      const dy = (y - pointer.y) * 1.5;
      for (let x = 0; x < state.cols; x += 1) {
        let layer = -1;
        for (let i = layers - 1; i >= 0; i -= 1) {
          if (y >= state.colTop[i * state.cols + x]) {
            layer = i;
            break;
          }
        }
        let tone = 0;
        let mistK = 0.3;
        if (layer >= 0) {
          const k = layer / (layers - 1);
          const distance = y - state.colTop[layer * state.cols + x];
          const pool = state.colPool[layer * state.cols + x];
          const crest = 1 - smooth(0, pool, distance) * (0.88 - 0.45 * k);
          tone = depthTone[layer] * crest;
          const slope = state.colSlope[layer * state.cols + x] * 0.06;
          tone += Math.max(-0.2, Math.min(0.2, slope)) * (1 - smooth(0, pool * 0.5, distance));
          tone +=
            (hash(x + Math.round(state.colTop[layer * state.cols + x] * 7), distance | 0, layer) -
              0.5) *
            0.07 *
            k;
          tone *= reveal[layer];
          mistK = 0.95 - 0.5 * k;
        } else {
          tone = 0.05 * smooth(state.rows * 0.15, state.rows * 0.6, y);
        }
        let fog = state.fog[fogRow + (x >> 1)] * mist * mistK;
        if (pointer.clear > 0.01) {
          const dx = x - pointer.x;
          const q = (dx * dx + dy * dy) / radiusSquared;
          if (q < 4) {
            const clear = pointer.clear * Math.exp(-q);
            fog *= 1 - clear * 0.92;
            if (layer >= 0) tone += clear * 0.16 * reveal[layer];
          }
        }
        tone = Math.min(0.93, tone);
        fog = Math.min(1, fog + lift * 0.55);
        tone = (tone * (1 - fog) + 0.09 * fog * (1 - lift)) * fade;
        const toneIndex = Math.min(
          palette.length - 1,
          Math.floor(
            Math.max(0, Math.min(1, tone)) * (palette.length - 1) + bayer[bayerRow + (x & 7)],
          ),
        );
        state.pixels[y * state.cols + x] = palette[toneIndex];
      }
    }
    ctx.putImageData(state.image, 0, 0);

    let showAltitude = false;
    if (altimeter && altText && pointer.inside && age > 1600) {
      const x = Math.max(0, Math.min(state.cols - 1, Math.round(pointer.x)));
      for (let i = layers - 1; i >= 0; i -= 1) {
        const crest = state.colTop[i * state.cols + x];
        if (pointer.y >= crest - 6) {
          showAltitude = true;
          altimeter.style.transform = `translate(${(x * pixel).toFixed(1)}px, ${(crest * pixel).toFixed(1)}px)`;
          altText.textContent = `${elevation(crest, state.rows, i).toLocaleString('en-US')} m`;
          break;
        }
      }
    }
    if (altimeter && showAltitude !== altShown) {
      altShown = showAltitude;
      altimeter.style.opacity = showAltitude ? '1' : '0';
    }
    return age;
  }

  const wake = () => {
    if (!raf && visible) raf = requestAnimationFrame(loop);
  };

  function loop(now) {
    raf = 0;
    if (!visible) return;
    if (revealAt === null) return;
    const age = revealAt === -Infinity ? Infinity : now - revealAt;
    const busy =
      age < 3400 ||
      pointer.inside ||
      Math.abs(windVelocity) > 0.002 ||
      Math.abs(pointer.targetParallax - pointer.parallax) > 0.001;
    if (busy || now - lastDraw > 32) {
      draw(now);
      lastDraw = now;
    }
    const active =
      age < 3400 || pointer.inside || Math.abs(windVelocity) > 0.002 || (!reduced && drift > 0);
    if (active) raf = requestAnimationFrame(loop);
  }

  const onMove = (event) => {
    const rootRect = footer.getBoundingClientRect();
    pointer.targetParallax = rootRect.width
      ? ((event.clientX - rootRect.left) / rootRect.width) * 2 - 1
      : 0;
    const rect = scene.getBoundingClientRect();
    const x = (event.clientX - rect.left) / pixel;
    const y = (event.clientY - rect.top) / pixel;
    const wasInside = pointer.inside;
    pointer.inside = x >= 0 && y >= 0 && x < state.cols && y < state.rows;
    pointer.tx = x;
    pointer.ty = y;
    if (pointer.inside && !wasInside) {
      pointer.x = x;
      pointer.y = y;
    }
    wake();
  };

  const onLeave = () => {
    pointer.targetParallax = 0;
    pointer.inside = false;
    wake();
  };

  const onDown = (event) => {
    if (reduced || !pointer.inside || event.target.closest('a, button')) return;
    windVelocity += pointer.tx < state.cols / 2 ? 1.4 : -1.4;
    wake();
  };

  layout();
  const resizeObserver = new ResizeObserver(() => {
    layout();
    wake();
  });
  resizeObserver.observe(scene);
  const intersectionObserver = new IntersectionObserver(
    (entries) => {
      visible = entries.some((entry) => entry.isIntersecting);
      if (visible) {
        if (revealAt === null) revealAt = reduced ? -Infinity : performance.now();
        footer.classList.add('rdf-in');
        lastTick = performance.now();
        wake();
      } else if (raf) {
        cancelAnimationFrame(raf);
        raf = 0;
      }
    },
    { threshold: 0.12 },
  );
  intersectionObserver.observe(footer);
  footer.addEventListener('pointermove', onMove, { passive: true });
  footer.addEventListener('pointerleave', onLeave);
  footer.addEventListener('pointerdown', onDown, { passive: true });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      lastTick = performance.now();
      wake();
    }
  });
  window.addEventListener(
    'pagehide',
    () => {
      if (raf) cancelAnimationFrame(raf);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      footer.removeEventListener('pointermove', onMove);
      footer.removeEventListener('pointerleave', onLeave);
      footer.removeEventListener('pointerdown', onDown);
    },
    { once: true },
  );
})();
