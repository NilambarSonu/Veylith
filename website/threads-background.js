/* global document, window, console, ResizeObserver, IntersectionObserver, requestAnimationFrame, cancelAnimationFrame */
/* Vanilla WebGL 2 port of the supplied React Bits Threads background. */
(() => {
  const MAX_RENDER_DIM = 1920;
  const LINE_VERTEX = `#version 300 es
precision highp float;
in vec2 aPoint;
uniform float uTime;
uniform vec2 uResolution;
uniform vec2 uFrame;
uniform float uAmplitude;
uniform float uDistance;
uniform vec2 uMouse;
uniform float uCount;
uniform float uThickness;
uniform float uSoftness;
uniform float uWaves;
uniform float uSplit;
uniform float uFray;
uniform float uSeed;
uniform vec2 uTurn;
uniform vec4 uPart;
uniform float uTaper;
out float vEdge;
out float vBand;
out float vDraw;
out float vAlpha;
out float vIndex;

float Perlin2D(vec2 P) {
  vec2 Pi = floor(P);
  vec4 Pf_Pfmin1 = P.xyxy - vec4(Pi, Pi + 1.0);
  vec4 Pt = vec4(Pi.xy, Pi.xy + 1.0);
  Pt = Pt - floor(Pt * (1.0 / 71.0)) * 71.0;
  Pt += vec2(26.0, 161.0).xyxy;
  Pt *= Pt;
  Pt = Pt.xzxz * Pt.yyww;
  vec4 hash_x = fract(Pt * (1.0 / 951.135664));
  vec4 hash_y = fract(Pt * (1.0 / 642.949883));
  vec4 grad_x = hash_x - 0.49999;
  vec4 grad_y = hash_y - 0.49999;
  vec4 grad_results = inversesqrt(grad_x * grad_x + grad_y * grad_y) * (grad_x * Pf_Pfmin1.xzxz + grad_y * Pf_Pfmin1.yyww);
  grad_results *= 1.4142135623730950;
  vec2 blend = Pf_Pfmin1.xy * Pf_Pfmin1.xy * Pf_Pfmin1.xy * (Pf_Pfmin1.xy * (Pf_Pfmin1.xy * 6.0 - 15.0) + 10.0);
  vec4 blend2 = vec4(blend, vec2(1.0 - blend));
  return dot(grad_results, blend2.zxzx * blend2.wwyy);
}

void main() {
  float perc = float(gl_InstanceID) / uCount;
  float x = aPoint.x;
  float pixel = 1.0 / max(uResolution.x, uResolution.y);
  float splitPoint = uSplit + perc * uFray;
  float amplitudeNormal = smoothstep(splitPoint, max(0.7, splitPoint + 0.2), x);
  float finalAmplitude = amplitudeNormal * 0.5 * uAmplitude * (1.0 + (uMouse.y - 0.5) * 0.2);
  float timeScaled = uTime / 10.0 + (uMouse.x - 0.5);
  float blur = smoothstep(splitPoint, splitPoint + 0.05, x) * perc;
  float xnoise = mix(
    Perlin2D(vec2(timeScaled * 2.5 + uSeed, (x * uWaves + perc) * 2.5)),
    Perlin2D(vec2(timeScaled * 3.5 + uSeed, (x * uWaves + timeScaled) * 3.5)) / 1.5,
    x * 0.3
  );
  float y = 0.5 + (perc - 0.5) * uDistance + xnoise / 2.0 * finalAmplitude;
  vec2 local = vec2((x - 0.5) * uFrame.x, (y - 0.5) * uFrame.y);
  if (uPart.z > 0.0) {
    vec2 delta = local - uPart.xy;
    float reach = uPart.w;
    float pull = exp(-dot(delta, delta) / (reach * reach));
    local.y += delta.y * pull * uPart.z;
  }
  float width = 7.0 * uThickness * pixel * (1.0 - perc);
  float band = (width / 2.0 + 10.0 * uSoftness * pixel * blur) * uFrame.y;
  float draw = max(band, 1.0);
  local.y += aPoint.y * draw;
  vec2 turned = vec2(local.x * uTurn.x - local.y * uTurn.y, local.x * uTurn.y + local.y * uTurn.x);
  gl_Position = vec4(turned / (uResolution * 0.5), 0.0, 1.0);
  vEdge = aPoint.y * draw;
  vBand = band;
  vDraw = draw;
  vAlpha = 1.0 - smoothstep(0.0, 1.0, pow(perc, 0.3)) * uTaper;
  vIndex = perc;
}`;

  const LINE_FRAGMENT = `#version 300 es
precision highp float;
in float vEdge;
in float vBand;
in float vDraw;
in float vAlpha;
in float vIndex;
uniform vec3 uColor;
uniform vec3 uAccent;
out vec4 outColor;
void main() {
  float coverage = (1.0 - smoothstep(0.0, vDraw, abs(vEdge))) * (vBand / vDraw) * vAlpha;
  outColor = vec4(mix(uColor, uAccent, vIndex) * coverage, coverage);
}`;

  const SCREEN_VERTEX = `#version 300 es
in vec2 aPosition;
out vec2 vUv;
void main() {
  vUv = aPosition * 0.5 + 0.5;
  gl_Position = vec4(aPosition, 0.0, 1.0);
}`;

  const SCREEN_FRAGMENT = `#version 300 es
precision highp float;
in vec2 vUv;
uniform sampler2D uLines;
uniform vec2 uResolution;
uniform float uFade;
uniform float uOpacity;
uniform float uCurve;
out vec4 outColor;
float smootherstep(float edge, float x) {
  float t = clamp(x / edge, 0.0, 1.0);
  return t * t * t * (t * (t * 6.0 - 15.0) + 10.0);
}
void main() {
  vec4 lines = texture(uLines, vUv);
  float alpha = lines.a;
  vec3 color = alpha > 0.0001 ? lines.rgb / alpha : vec3(0.0);
  float mask = uOpacity;
  if (uFade > 0.0) {
    vec2 px = vUv * uResolution;
    float edge = uFade * min(uResolution.x, uResolution.y) * 0.5;
    mask *= smootherstep(edge, px.x) * smootherstep(edge, uResolution.x - px.x);
    mask *= smootherstep(edge, px.y) * smootherstep(edge, uResolution.y - px.y);
  }
  outColor = vec4(color * pow(alpha, uCurve), alpha) * mask;
}`;

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const compile = (gl, type, source) => {
    const shader = gl.createShader(type);
    if (!shader) return null;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return shader;
    console.error('Threads shader compile failed:', gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    return null;
  };
  const link = (gl, vertexSource, fragmentSource) => {
    const vertex = compile(gl, gl.VERTEX_SHADER, vertexSource);
    const fragment = compile(gl, gl.FRAGMENT_SHADER, fragmentSource);
    const program = gl.createProgram();
    if (!vertex || !fragment || !program) return null;
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (gl.getProgramParameter(program, gl.LINK_STATUS)) return program;
    console.error('Threads program link failed:', gl.getProgramInfoLog(program));
    gl.deleteProgram(program);
    return null;
  };
  const uniforms = (gl, program, names) =>
    Object.fromEntries(names.map((name) => [name, gl.getUniformLocation(program, name)]));

  const lineUniformNames = [
    'uTime',
    'uResolution',
    'uFrame',
    'uAmplitude',
    'uDistance',
    'uMouse',
    'uCount',
    'uThickness',
    'uSoftness',
    'uWaves',
    'uSplit',
    'uFray',
    'uSeed',
    'uTurn',
    'uPart',
    'uTaper',
    'uColor',
    'uAccent',
  ];

  const readColor = (value) => {
    const probe = document.createElement('canvas');
    probe.width = probe.height = 1;
    const context = probe.getContext('2d', { willReadFrequently: true });
    if (!context) return [1, 1, 1];
    context.fillStyle = '#fff';
    context.fillStyle = value;
    context.fillRect(0, 0, 1, 1);
    return Array.from(context.getImageData(0, 0, 1, 1).data)
      .slice(0, 3)
      .map((channel) => channel / 255);
  };

  document.querySelectorAll('.threads-layer').forEach((container) => {
    const canvas = container.querySelector('canvas');
    const gl = canvas?.getContext('webgl2', {
      alpha: true,
      premultipliedAlpha: true,
      antialias: false,
      depth: false,
      stencil: false,
    });
    if (!canvas || !gl) return;

    const settings = {
      color: readColor(container.dataset.color || '#075985'),
      accent: readColor(container.dataset.accent || '#67c7ed'),
      lineCount: clamp(Math.round(Number(container.dataset.lineCount) || 72), 1, 200),
      thickness: Number(container.dataset.thickness) || 0.55,
      softness: Number(container.dataset.softness) || 1,
      amplitude: Number(container.dataset.amplitude) || 1.25,
      distance: Number(container.dataset.distance) || 0.52,
      waves: Number(container.dataset.waves) || 1.05,
      speed: Number(container.dataset.speed) || 0.45,
      split: Number(container.dataset.split) || 0.04,
      fray: Number(container.dataset.fray) || 0.5,
      angle: Number(container.dataset.angle) || 25,
      seed: Number(container.dataset.seed) || 0,
      parting: Number(container.dataset.parting) || 0.45,
      taper: Number(container.dataset.taper) || 0.9,
      brightness: Number(container.dataset.brightness) || 1.4,
      fade: Number(container.dataset.fade) || 0.22,
      opacity: Number(container.dataset.opacity) || 0.8,
    };
    const lineProgram = link(gl, LINE_VERTEX, LINE_FRAGMENT);
    const screenProgram = link(gl, SCREEN_VERTEX, SCREEN_FRAGMENT);
    if (!lineProgram || !screenProgram) return;
    const lineU = uniforms(gl, lineProgram, lineUniformNames);
    const screenU = uniforms(gl, screenProgram, [
      'uLines',
      'uResolution',
      'uFade',
      'uOpacity',
      'uCurve',
    ]);

    const lineVao = gl.createVertexArray();
    const lineBuffer = gl.createBuffer();
    gl.bindVertexArray(lineVao);
    gl.bindBuffer(gl.ARRAY_BUFFER, lineBuffer);
    const pointLocation = gl.getAttribLocation(lineProgram, 'aPoint');
    gl.enableVertexAttribArray(pointLocation);
    gl.vertexAttribPointer(pointLocation, 2, gl.FLOAT, false, 0, 0);

    const screenVao = gl.createVertexArray();
    const screenBuffer = gl.createBuffer();
    gl.bindVertexArray(screenVao);
    gl.bindBuffer(gl.ARRAY_BUFFER, screenBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
    const screenLocation = gl.getAttribLocation(screenProgram, 'aPosition');
    gl.enableVertexAttribArray(screenLocation);
    gl.vertexAttribPointer(screenLocation, 2, gl.FLOAT, false, 0, 0);
    gl.bindVertexArray(null);

    const texture = gl.createTexture();
    const framebuffer = gl.createFramebuffer();
    gl.bindTexture(gl.TEXTURE_2D, texture);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);

    const state = {
      time: 0,
      width: 1,
      height: 1,
      segments: 0,
      mouse: [0.5, 0.5],
      targetMouse: [0.5, 0.5],
      pointer: [0, 0],
      targetPointer: [0, 0],
      presence: 0,
      inside: false,
    };
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let raf = 0;
    let last = 0;
    let visible = false;
    let alive = true;

    const buildStrip = (segments) => {
      if (segments === state.segments) return;
      state.segments = segments;
      const points = new Float32Array((segments + 1) * 4);
      for (let i = 0; i <= segments; i += 1) {
        const u = i / segments;
        points.set([u, -1, u, 1], i * 4);
      }
      gl.bindBuffer(gl.ARRAY_BUFFER, lineBuffer);
      gl.bufferData(gl.ARRAY_BUFFER, points, gl.STATIC_DRAW);
    };

    const render = () => {
      const width = canvas.width;
      const height = canvas.height;
      const radians = (settings.angle * Math.PI) / 180;
      const cos = Math.cos(radians);
      const sin = Math.sin(radians);
      const length = Math.abs(width * cos) + Math.abs(height * sin);
      const across = Math.abs(width * sin) + Math.abs(height * cos);
      const localPointer = [
        state.pointer[0] * cos + state.pointer[1] * sin,
        -state.pointer[0] * sin + state.pointer[1] * cos,
      ];

      gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
      gl.viewport(0, 0, width, height);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
      gl.useProgram(lineProgram);
      gl.uniform1f(lineU.uTime, state.time);
      gl.uniform2f(lineU.uResolution, width, height);
      gl.uniform2f(lineU.uFrame, length, across);
      gl.uniform1f(lineU.uAmplitude, settings.amplitude);
      gl.uniform1f(lineU.uDistance, settings.distance);
      gl.uniform2f(lineU.uMouse, state.mouse[0], state.mouse[1]);
      gl.uniform1f(lineU.uCount, settings.lineCount);
      gl.uniform1f(lineU.uThickness, settings.thickness);
      gl.uniform1f(lineU.uSoftness, settings.softness);
      gl.uniform1f(lineU.uWaves, settings.waves);
      gl.uniform1f(lineU.uSplit, settings.split);
      gl.uniform1f(lineU.uFray, settings.fray);
      gl.uniform1f(lineU.uSeed, settings.seed * 13.37);
      gl.uniform2f(lineU.uTurn, cos, sin);
      gl.uniform4f(
        lineU.uPart,
        localPointer[0],
        localPointer[1],
        settings.parting * state.presence * 2,
        Math.min(width, height) * 0.16,
      );
      gl.uniform1f(lineU.uTaper, settings.taper);
      gl.uniform3f(lineU.uColor, ...settings.color);
      gl.uniform3f(lineU.uAccent, ...settings.accent);
      gl.bindVertexArray(lineVao);
      gl.drawArraysInstanced(gl.TRIANGLE_STRIP, 0, (state.segments + 1) * 2, settings.lineCount);

      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      gl.viewport(0, 0, width, height);
      gl.disable(gl.BLEND);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.useProgram(screenProgram);
      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.uniform1i(screenU.uLines, 0);
      gl.uniform2f(screenU.uResolution, width, height);
      gl.uniform1f(screenU.uFade, settings.fade);
      gl.uniform1f(screenU.uOpacity, settings.opacity);
      gl.uniform1f(screenU.uCurve, 2 / settings.brightness);
      gl.bindVertexArray(screenVao);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.bindVertexArray(null);
    };

    const resize = () => {
      const width = Math.max(1, container.clientWidth);
      const height = Math.max(1, container.clientHeight);
      const baseDpr = Math.min(window.devicePixelRatio || 1, 2);
      const longest = Math.max(width, height) * baseDpr;
      const dpr = longest > MAX_RENDER_DIM ? (baseDpr * MAX_RENDER_DIM) / longest : baseDpr;
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      state.width = width;
      state.height = height;
      gl.bindTexture(gl.TEXTURE_2D, texture);
      gl.texImage2D(
        gl.TEXTURE_2D,
        0,
        gl.RGBA,
        canvas.width,
        canvas.height,
        0,
        gl.RGBA,
        gl.UNSIGNED_BYTE,
        null,
      );
      gl.bindFramebuffer(gl.FRAMEBUFFER, framebuffer);
      gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, texture, 0);
      gl.bindFramebuffer(gl.FRAMEBUFFER, null);
      buildStrip(clamp(Math.round(width / 3), 96, 640));
      render();
      wake();
    };

    function frame(now) {
      raf = 0;
      if (!alive || !visible || document.hidden) return;
      const dt = last ? Math.min(0.05, (now - last) / 1000) : 1 / 60;
      last = now;
      if (!reducedMotion) state.time += dt * settings.speed;
      const follow = 1 - Math.exp(-dt * 3);
      state.mouse[0] += (state.targetMouse[0] - state.mouse[0]) * follow;
      state.mouse[1] += (state.targetMouse[1] - state.mouse[1]) * follow;
      const glide = 1 - Math.exp(-dt * 10);
      state.pointer[0] += (state.targetPointer[0] - state.pointer[0]) * glide;
      state.pointer[1] += (state.targetPointer[1] - state.pointer[1]) * glide;
      state.presence += ((state.inside ? 1 : 0) - state.presence) * (1 - Math.exp(-dt * 4));
      render();
      const settling =
        Math.abs(state.targetMouse[0] - state.mouse[0]) > 0.0005 ||
        Math.abs(state.targetMouse[1] - state.mouse[1]) > 0.0005 ||
        Math.abs(state.targetPointer[0] - state.pointer[0]) > 0.05 ||
        Math.abs(state.targetPointer[1] - state.pointer[1]) > 0.05 ||
        Math.abs((state.inside ? 1 : 0) - state.presence) > 0.002;
      if (!reducedMotion || settling) raf = requestAnimationFrame(frame);
      else last = 0;
    }

    function wake() {
      if (!raf && alive && visible && !document.hidden) raf = requestAnimationFrame(frame);
    }

    const onPointerMove = (event) => {
      const rect = container.getBoundingClientRect();
      const x = (event.clientX - rect.left) / Math.max(1, rect.width);
      const y = (event.clientY - rect.top) / Math.max(1, rect.height);
      const inside = x >= 0 && x <= 1 && y >= 0 && y <= 1;
      if (inside) {
        state.targetMouse = [x, 1 - y];
        state.targetPointer = [
          event.clientX - rect.left - rect.width / 2,
          rect.height / 2 - (event.clientY - rect.top),
        ];
        if (!state.inside && state.presence < 0.01) state.pointer = [...state.targetPointer];
      } else if (state.inside) {
        state.targetMouse = [0.5, 0.5];
      }
      state.inside = inside;
      wake();
    };

    const onPointerLeave = () => {
      state.inside = false;
      state.targetMouse = [0.5, 0.5];
      wake();
    };
    const onVisibility = () => {
      last = 0;
      wake();
    };
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(container);
    const intersection = new IntersectionObserver((entries) => {
      visible = entries.some((entry) => entry.isIntersecting);
      if (visible) {
        last = 0;
        wake();
      } else if (raf) {
        cancelAnimationFrame(raf);
        raf = 0;
      }
    });
    intersection.observe(container);
    window.addEventListener('pointermove', onPointerMove, { passive: true });
    document.documentElement.addEventListener('pointerleave', onPointerLeave);
    document.addEventListener('visibilitychange', onVisibility);
    resize();

    window.addEventListener(
      'pagehide',
      () => {
        alive = false;
        if (raf) cancelAnimationFrame(raf);
        resizeObserver.disconnect();
        intersection.disconnect();
        window.removeEventListener('pointermove', onPointerMove);
        document.documentElement.removeEventListener('pointerleave', onPointerLeave);
        document.removeEventListener('visibilitychange', onVisibility);
        gl.deleteFramebuffer(framebuffer);
        gl.deleteTexture(texture);
        gl.deleteBuffer(lineBuffer);
        gl.deleteBuffer(screenBuffer);
        gl.deleteVertexArray(lineVao);
        gl.deleteVertexArray(screenVao);
        gl.deleteProgram(lineProgram);
        gl.deleteProgram(screenProgram);
      },
      { once: true },
    );
  });
})();
