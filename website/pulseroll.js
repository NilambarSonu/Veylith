/* global document, window, performance, requestAnimationFrame */
/**
 * OriginKit PulseRoll WebGL Engine — Major Attraction
 * Procedural 3D metallic coiled chrome helix spanning diagonally across Section 2.
 * Engineered for smooth, stately cadence with interactive mouse parallax and chrome matcap shading.
 */

(function () {
  const TAU = Math.PI * 2;
  const DPR_CAP = 2;
  const FOV = (42 * Math.PI) / 180;
  const NEAR = 0.1;
  const FAR = 200;
  const DISC_R = 2.6;
  const DISC_H = 0.48;
  const DISC_SEG = 54;
  const SPACING = 1.25;
  const DISC_Z = 2.0;
  const ROLL = (3 * Math.PI) / 4; // 135 deg diagonal slope
  const PERIOD = 3.4; // Slower, calmer yoyo wave cycle

  const PULSE_DEFAULTS = {
    count: 14,
    spacing: 100,
    minSize: 35,
    stagger: 130,
  };

  function easeSineInOut(x) {
    return -(Math.cos(Math.PI * x) - 1) / 2;
  }

  function parseColor(input, fb) {
    if (!input) return fb;
    let s = String(input).trim();
    if (s.charAt(0) === '#') {
      let h = s.slice(1);
      if (h.length === 3) h = h[0] + h[0] + h[1] + h[1] + h[2] + h[2];
      if (h.length < 6) return fb;
      const n = parseInt(h.slice(0, 6), 16);
      if (!isFinite(n)) return fb;
      return [((n >> 16) & 255) / 255, ((n >> 8) & 255) / 255, (n & 255) / 255];
    }
    return fb;
  }

  function m4() {
    const o = new Float32Array(16);
    o[0] = o[5] = o[10] = o[15] = 1;
    return o;
  }

  function m4Ident(o) {
    o.fill(0);
    o[0] = o[5] = o[10] = o[15] = 1;
    return o;
  }

  function m4Mul(a, b, out) {
    for (let c = 0; c < 4; c++) {
      const b0 = b[c * 4],
        b1 = b[c * 4 + 1],
        b2 = b[c * 4 + 2],
        b3 = b[c * 4 + 3];
      out[c * 4] = a[0] * b0 + a[4] * b1 + a[8] * b2 + a[12] * b3;
      out[c * 4 + 1] = a[1] * b0 + a[5] * b1 + a[9] * b2 + a[13] * b3;
      out[c * 4 + 2] = a[2] * b0 + a[6] * b1 + a[10] * b2 + a[14] * b3;
      out[c * 4 + 3] = a[3] * b0 + a[7] * b1 + a[11] * b2 + a[15] * b3;
    }
    return out;
  }

  const SCR_A = m4();
  const SCR_B = m4();

  function rotX(m, a) {
    if (a === 0) return;
    const c = Math.cos(a),
      s = Math.sin(a);
    m4Ident(SCR_A);
    SCR_A[5] = c;
    SCR_A[6] = s;
    SCR_A[9] = -s;
    SCR_A[10] = c;
    m.set(m4Mul(m, SCR_A, SCR_B));
  }

  function rotY(m, a) {
    if (a === 0) return;
    const c = Math.cos(a),
      s = Math.sin(a);
    m4Ident(SCR_A);
    SCR_A[0] = c;
    SCR_A[2] = -s;
    SCR_A[8] = s;
    SCR_A[10] = c;
    m.set(m4Mul(m, SCR_A, SCR_B));
  }

  function rotZ(m, a) {
    if (a === 0) return;
    const c = Math.cos(a),
      s = Math.sin(a);
    m4Ident(SCR_A);
    SCR_A[0] = c;
    SCR_A[1] = s;
    SCR_A[4] = -s;
    SCR_A[5] = c;
    m.set(m4Mul(m, SCR_A, SCR_B));
  }

  function trans(m, x, y, z) {
    m[12] = m[0] * x + m[4] * y + m[8] * z + m[12];
    m[13] = m[1] * x + m[5] * y + m[9] * z + m[13];
    m[14] = m[2] * x + m[6] * y + m[10] * z + m[14];
    m[15] = m[3] * x + m[7] * y + m[11] * z + m[15];
  }

  function scaleNU(m, sx, sy, sz) {
    m[0] *= sx;
    m[1] *= sx;
    m[2] *= sx;
    m[3] *= sx;
    m[4] *= sy;
    m[5] *= sy;
    m[6] *= sy;
    m[7] *= sy;
    m[8] *= sz;
    m[9] *= sz;
    m[10] *= sz;
    m[11] *= sz;
  }

  function persp(out, fovy, aspect, near, far) {
    const f = 1 / Math.tan(fovy / 2);
    out.fill(0);
    out[0] = f / aspect;
    out[5] = f;
    out[10] = (far + near) / (near - far);
    out[11] = -1;
    out[14] = (2 * far * near) / (near - far);
    return out;
  }

  function nm3(m, out) {
    const a = m[0],
      b = m[1],
      c = m[2];
    const d = m[4],
      e = m[5],
      f = m[6];
    const g = m[8],
      h = m[9],
      i = m[10];
    const C11 = e * i - h * f;
    const C12 = -(b * i - h * c);
    const C13 = b * f - e * c;
    const det = a * C11 + d * C12 + g * C13;
    if (!det) {
      out[0] = a;
      out[1] = b;
      out[2] = c;
      out[3] = d;
      out[4] = e;
      out[5] = f;
      out[6] = g;
      out[7] = h;
      out[8] = i;
      return;
    }
    const s = 1 / det;
    out[0] = C11 * s;
    out[1] = -(d * i - g * f) * s;
    out[2] = (d * h - g * e) * s;
    out[3] = C12 * s;
    out[4] = (a * i - g * c) * s;
    out[5] = -(a * h - g * b) * s;
    out[6] = C13 * s;
    out[7] = -(a * f - d * c) * s;
    out[8] = (a * e - d * b) * s;
  }

  function cylGeo(rTop, rBot, height, seg) {
    const pos = [],
      nrm = [],
      idx = [];
    const half = height / 2;
    const slope = (rBot - rTop) / height;

    for (let y = 0; y <= 1; y++) {
      const r = y * (rBot - rTop) + rTop;
      for (let x = 0; x <= seg; x++) {
        const th = (x / seg) * TAU;
        const st = Math.sin(th),
          ct = Math.cos(th);
        pos.push(r * st, -y * height + half, r * ct);
        const l = Math.sqrt(st * st + slope * slope + ct * ct);
        nrm.push(st / l, slope / l, ct / l);
      }
    }
    for (let x = 0; x < seg; x++) {
      const a = x,
        d = x + 1;
      const b = seg + 1 + x,
        c = seg + 1 + x + 1;
      if (rTop > 0) idx.push(a, b, d);
      if (rBot > 0) idx.push(b, c, d);
    }

    const cap = (top) => {
      const r = top ? rTop : rBot;
      if (r <= 0) return;
      const y = top ? half : -half;
      const centre = pos.length / 3;
      pos.push(0, y, 0);
      nrm.push(0, top ? 1 : -1, 0);
      for (let x = 0; x <= seg; x++) {
        const th = (x / seg) * TAU;
        pos.push(r * Math.sin(th), y, r * Math.cos(th));
        nrm.push(0, top ? 1 : -1, 0);
      }
      for (let x = 0; x < seg; x++) {
        const p0 = centre + 1 + x,
          p1 = centre + 1 + x + 1;
        if (top) idx.push(centre, p0, p1);
        else idx.push(centre, p1, p0);
      }
    };
    cap(true);
    cap(false);

    return {
      pos: new Float32Array(pos),
      nrm: new Float32Array(nrm),
      idx: new Uint16Array(idx),
    };
  }

  const VERT = `
precision highp float;
attribute vec3 aPos;
attribute vec3 aNrm;
uniform mat4 uMVP;
uniform mat3 uNM;
varying vec3 vN;
void main() {
    vN = uNM * aNrm;
    gl_Position = uMVP * vec4(aPos, 1.0);
}
`;

  const FRAG = `
precision highp float;
varying vec3 vN;
uniform vec3 uBase;
uniform vec3 uAcc;
const vec3 KEY  = vec3(-0.4364, 0.4601, 0.7733);
const vec3 FILL = vec3( 0.7831, 0.1309, 0.6080);
void main() {
    vec3 n = normalize(vN);
    if (!gl_FrontFacing) n = -n;
    float k = max(dot(n, KEY), 0.0);
    float f = max(dot(n, FILL), 0.0);
    float graze = 1.0 - clamp(abs(n.z), 0.0, 1.0);
    vec3 c = uBase * (0.12 + 0.65 * pow(k, 2.0));
    c += uAcc * 0.95 * pow(k, 8.0);
    c += uAcc * 0.48 * pow(f, 5.0);
    c += uAcc * 0.42 * pow(graze, 3.0) * (0.50 + 0.50 * max(n.y, 0.0));
    gl_FragColor = vec4(clamp(c, 0.0, 1.0), 0.94);
}
`;

  function initPulseRoll() {
    const canvas = document.getElementById('pulseroll-canvas');
    if (!canvas) return;

    const gl = canvas.getContext('webgl', {
      antialias: true,
      alpha: true,
      premultipliedAlpha: true,
      depth: true,
    });
    if (!gl) return;

    function compile(type, src) {
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      return s;
    }

    const vs = compile(gl.VERTEX_SHADER, VERT);
    const fs = compile(gl.FRAGMENT_SHADER, FRAG);
    const prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.linkProgram(prog);
    gl.useProgram(prog);

    const aPos = gl.getAttribLocation(prog, 'aPos');
    const aNrm = gl.getAttribLocation(prog, 'aNrm');
    gl.enableVertexAttribArray(aPos);
    gl.enableVertexAttribArray(aNrm);

    const uMVP = gl.getUniformLocation(prog, 'uMVP');
    const uNM = gl.getUniformLocation(prog, 'uNM');
    const uBase = gl.getUniformLocation(prog, 'uBase');
    const uAcc = gl.getUniformLocation(prog, 'uAcc');

    gl.enable(gl.DEPTH_TEST);
    gl.depthFunc(gl.LEQUAL);
    gl.clearColor(0, 0, 0, 0);

    const geo = cylGeo(DISC_R, DISC_R, DISC_H, DISC_SEG);

    const posBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, posBuf);
    gl.bufferData(gl.ARRAY_BUFFER, geo.pos, gl.STATIC_DRAW);

    const nrmBuf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, nrmBuf);
    gl.bufferData(gl.ARRAY_BUFFER, geo.nrm, gl.STATIC_DRAW);

    const idxBuf = gl.createBuffer();
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, idxBuf);
    gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, geo.idx, gl.STATIC_DRAW);

    const count = geo.idx.length;

    // High-contrast chrome metallic finish
    const baseColor = parseColor('#182438', [0.1, 0.14, 0.22]);
    const accColor = parseColor('#ffffff', [1.0, 1.0, 1.0]);

    let dpr = 1;
    function resize() {
      dpr = Math.min(window.devicePixelRatio || 1, DPR_CAP);
      const host = canvas.parentElement || window;
      const w = Math.max(1, Math.round((canvas.clientWidth || host.clientWidth) * dpr));
      const h = Math.max(1, Math.round((canvas.clientHeight || host.clientHeight) * dpr));
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
      }
      gl.viewport(0, 0, w, h);
    }
    resize();
    window.addEventListener('resize', resize, { passive: true });

    // Interactive mouse parallax across Section 2
    let mouseX = 0,
      mouseY = 0;
    const host = canvas.parentElement || document.body;
    host.addEventListener(
      'pointermove',
      (e) => {
        const r = host.getBoundingClientRect();
        mouseX = ((e.clientX - r.left) / r.width) * 2 - 1;
        mouseY = ((e.clientY - r.top) / r.height) * 2 - 1;
      },
      { passive: true },
    );

    const proj = m4(),
      view = m4(),
      pv = m4(),
      model = m4(),
      mvp = m4();
    const nrmMat = new Float32Array(9);
    let last = performance.now();
    let clock = 0;
    let smoothX = 0,
      smoothY = 0;

    const pulseCount = PULSE_DEFAULTS.count;
    const spacing = SPACING * (PULSE_DEFAULTS.spacing / 100);
    const minS = PULSE_DEFAULTS.minSize / 100;
    const stag = PULSE_DEFAULTS.stagger / 1000;
    const maxDelay = stag * (pulseCount - 1);

    function frame(now) {
      requestAnimationFrame(frame);
      const dt = Math.min(0.05, Math.max(0, (now - last) / 1000));
      last = now;

      // Slowed down smoothly as requested for an elegant, calm, premium cadence
      clock += dt * 0.38;
      if (clock > maxDelay + PERIOD) clock -= PERIOD;

      smoothX += (mouseX - smoothX) * 0.04;
      smoothY += (mouseY - smoothY) * 0.04;

      const aspect = canvas.width / canvas.height;
      persp(proj, FOV, aspect, NEAR, FAR);

      // Camera distance framed to stretch the coil boldly across the screen
      const dist = 11.2 / Math.min(1, aspect);
      m4Ident(view);
      trans(view, smoothX * 0.9, -smoothY * 0.6, -dist);
      rotX(view, smoothY * 0.09);
      rotY(view, smoothX * 0.12);
      m4Mul(proj, view, pv);

      gl.uniform3fv(uBase, baseColor);
      gl.uniform3fv(uAcc, accColor);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);

      const mid = (spacing * (pulseCount - 1)) / 2;
      const cx = -mid * Math.SQRT1_2;
      const cy = -mid * Math.SQRT1_2;

      gl.bindBuffer(gl.ARRAY_BUFFER, posBuf);
      gl.vertexAttribPointer(aPos, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ARRAY_BUFFER, nrmBuf);
      gl.vertexAttribPointer(aNrm, 3, gl.FLOAT, false, 0, 0);
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, idxBuf);

      for (let i = 0; i < pulseCount; i++) {
        const local = clock - i * stag;
        let s = 1;
        if (local > 0) {
          const ph = local % PERIOD;
          const e = ph < 1 ? easeSineInOut(ph) : easeSineInOut(PERIOD - ph);
          s = 1 + (minS - 1) * e;
        }
        m4Ident(model);
        trans(model, -cx, -cy, -DISC_Z);
        rotZ(model, ROLL);
        trans(model, 0, spacing * i, DISC_Z);
        scaleNU(model, s, 1, s);

        m4Mul(pv, model, mvp);
        nm3(model, nrmMat);
        gl.uniformMatrix4fv(uMVP, false, mvp);
        gl.uniformMatrix3fv(uNM, false, nrmMat);
        gl.drawElements(gl.TRIANGLES, count, gl.UNSIGNED_SHORT, 0);
      }
    }

    requestAnimationFrame(frame);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initPulseRoll);
  } else {
    initPulseRoll();
  }
})();
