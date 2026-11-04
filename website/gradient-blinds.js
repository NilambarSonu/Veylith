/* global document, window, console, ResizeObserver, IntersectionObserver */
/* Vanilla WebGL 2 port of the supplied GradientBlinds component. */
(() => {
  const MAX_COLORS = 8;
  const MAX_WAVES = 4;
  const INTRO_SECONDS = 1.8;
  const RIPPLE_SECONDS = 1.6;

  const VERTEX = `#version 300 es
void main() {
  vec2 p = vec2(float((gl_VertexID << 1) & 2), float(gl_VertexID & 2));
  gl_Position = vec4(p * 2.0 - 1.0, 0.0, 1.0);
}`;

  const FRAGMENT = `#version 300 es
precision highp float;
precision highp int;
uniform vec2 uResolution;
uniform float uTime;
uniform vec2 uMouse;
uniform float uAngle;
uniform float uNoise;
uniform float uBlindCount;
uniform float uSpotlightRadius;
uniform float uSpotlightSoftness;
uniform float uSpotlightOpacity;
uniform float uMirror;
uniform float uDistort;
uniform float uShineFlip;
uniform vec3 uColors[8];
uniform int uColorCount;
uniform float uLightMode;
uniform float uShine;
uniform float uRelief;
uniform float uGlow;
uniform float uSway;
uniform float uSwayTime;
uniform float uHover;
uniform vec4 uWaves[4];
uniform float uIntro;
uniform float uGrainTime;
uniform vec3 uLightColor;
uniform float uPerspective;
uniform float uGradientShift;
out vec4 outColor;

float hash(vec2 p) {
  vec3 q = fract(vec3(p.xyx) * 0.1031);
  q += dot(q, q.yzx + 33.33);
  return fract((q.x + q.y) * q.z);
}

vec2 rotate2D(vec2 p, float a) {
  float c = cos(a);
  float s = sin(a);
  return mat2(c, -s, s, c) * p;
}

vec2 blindSpace(vec2 uv0) {
  float aspect = uResolution.x / uResolution.y;
  vec2 p = uv0 * 2.0 - 1.0;
  p.x *= aspect;
  vec2 pr = rotate2D(p, uAngle);
  pr.x /= aspect;
  vec2 uv = pr * 0.5 + 0.5;
  if (abs(uPerspective) > 0.001) {
    float k = uPerspective * 2.2;
    uv.x = (exp(k * uv.x) - 1.0) / (exp(k) - 1.0);
  }
  if (uDistort > 0.0) {
    float a = uv.y * 6.0;
    float b = uv.x * 6.0;
    float w = 0.01 * uDistort;
    uv.x += sin(a) * w;
    uv.y += cos(b) * w;
  }
  return uv;
}

vec3 gradientColor(float t) {
  float tt = clamp(t, 0.0, 1.0);
  int count = max(uColorCount, 2);
  float scaled = tt * float(count - 1);
  int seg = min(int(floor(scaled)), count - 2);
  float f = scaled - float(seg);
  if (tt >= 1.0) return uColors[count - 1];
  return mix(uColors[seg], uColors[seg + 1], f);
}

void main() {
  vec2 frag = gl_FragCoord.xy;
  vec2 uv0 = frag / uResolution;
  vec2 uvMod = blindSpace(uv0);
  float count = max(uBlindCount, 1.0);
  float stripePhase = uvMod.x * count;
  float pixel = max(fwidth(stripePhase), 1e-5);
  float t = uvMod.x;
  if (uGradientShift != 0.0) {
    t = 1.0 - abs(1.0 - fract((t + uGradientShift) * 0.5) * 2.0);
  }
  if (uMirror > 0.5) t = 1.0 - abs(1.0 - 2.0 * fract(t));
  vec3 base = gradientColor(t);
  vec2 offset = uMouse / uResolution;
  float d = length(uv0 - offset);
  float r = max(uSpotlightRadius, 1e-4);
  float spot = (1.0 - 2.0 * pow(d / r, uSpotlightSoftness)) * uSpotlightOpacity;
  float slat = floor(stripePhase);
  float s = stripePhase - slat;
  float stripeAA = clamp(count * 1.25 / min(uResolution.x, uResolution.y), 0.001, 0.12);
  float edgeBlend = 1.0 - smoothstep(0.0, stripeAA, min(s, 1.0 - s));
  float across = mix(s, 0.5, edgeBlend);
  float ramp = uShineFlip > 0.5 ? 1.0 - across : across;
  float unit = min(uResolution.x, uResolution.y);
  float reach = max(uSpotlightRadius, 0.05) * unit;
  vec2 toLight = uMouse - frag;
  float nearLight = exp(-dot(toLight, toLight) / (reach * reach));
  float tilt = 0.0;
  float pulse = 0.0;
  if (uSway > 0.0) {
    tilt += uSway * 0.5 * sin(uSwayTime * 0.9 + slat * 0.55) *
      (0.6 + 0.4 * sin(uSwayTime * 0.37 + slat * 0.21));
  }
  tilt += uHover * nearLight * 0.7;
  for (int i = 0; i < 4; i++) {
    vec4 wave = uWaves[i];
    if (wave.w <= 0.0) continue;
    float age = uTime - wave.z;
    if (age < 0.0 || age > 1.6) continue;
    float life = age / 1.6;
    vec2 origin = blindSpace(wave.xy / uResolution);
    float slats = abs(slat + 0.5 - origin.x * count);
    float front = age * max(count, 4.0) * 0.95;
    float k = (slats - front) / (0.8 + life * 1.2);
    float along = (uvMod.y - origin.y) / max(0.42 + life * 0.5, 0.01);
    float fade = (1.0 - life) * (1.0 - life);
    float ring = exp(-k * k) * exp(-along * along) * fade * smoothstep(0.0, 0.2, age);
    tilt += ring * 0.9;
    pulse += ring;
  }
  if (uIntro < 1.0) {
    float settle = smoothstep(0.0, 1.0, clamp(uIntro * 1.5 - uv0.x * 0.5, 0.0, 1.0));
    tilt -= (1.0 - settle) * 1.2;
  }
  float edge = ramp;
  float calm = 1.0 - 0.6 * clamp(spot, 0.0, 1.0);
  ramp = pow(clamp(ramp, 0.0, 1.0), exp(tilt * 0.9));
  ramp *= 1.0 - 0.3 * min(pulse, 1.0) * calm;
  float crease = uRelief * 0.38 * smoothstep(0.62, 1.0, ramp);
  float sheen = uShine * exp(-pow((edge - 0.035) / 0.07, 2.0)) *
    (0.3 + 0.7 * nearLight) * (1.0 - edgeBlend);
  vec3 lit = spot > 0.0 ? uLightColor * spot : vec3(spot);
  lit += uLightColor * min(pulse, 1.0) * 0.35 * calm;
  vec3 revealSignal = lit + base - vec3(ramp + crease);
  vec3 col;
  if (uLightMode > 0.5) {
    vec3 luma = vec3(0.2126, 0.7152, 0.0722);
    float peak = max(base.r, max(base.g, base.b));
    float low = min(base.r, min(base.g, base.b));
    float chroma = (peak - low) / max(peak, 0.0001);
    vec3 hue = base / max(peak, 0.0001);
    hue = clamp(mix(vec3(dot(hue, luma)), hue, 1.3), 0.0, 1.0);
    hue *= mix(1.0, 0.82, smoothstep(0.55, 0.9, dot(hue, luma)));
    vec3 tint = mix(base, hue, smoothstep(0.06, 0.28, chroma));
    vec3 revealed = clamp(revealSignal, 0.0, 1.0);
    float coverage = max(revealed.r, max(revealed.g, revealed.b));
    float stroke = 1.0 - smoothstep(pixel, pixel * 2.2, edge);
    col = mix(vec3(1.0), tint, 0.72 * smoothstep(0.0, 1.0, coverage));
    col = mix(col, tint * 0.85, stroke * clamp(coverage * 1.5, 0.0, 1.0) * 0.7);
    col = mix(col, vec3(1.0), clamp(sheen, 0.0, 1.0) * 0.5);
    float grain = max(0.5 * (hash(frag + uGrainTime) + hash(frag.yx + uGrainTime * 1.7)) - 0.5, 0.0);
    col = clamp(col - vec3(grain * uNoise * 0.12 * coverage), 0.0, 1.0);
  } else {
    vec3 haze = base * uGlow * 0.4 * smoothstep(0.0, 1.0, spot) * (0.4 + 0.6 * ramp);
    col = revealSignal + haze + mix(base, uLightColor, 0.45) * sheen * 0.7;
    vec3 over = max(col - 0.8, 0.0);
    col = min(col, vec3(0.8)) + 0.2 * (1.0 - exp(-over / 0.2));
    float luma = dot(clamp(col, 0.0, 1.0), vec3(0.2126, 0.7152, 0.0722));
    float grain = 0.5 * (hash(frag + uGrainTime) + hash(frag.yx + uGrainTime * 1.7)) - 0.5;
    col += grain * uNoise * (0.45 + 0.55 * smoothstep(0.0, 0.5, luma));
  }
  float presence = smoothstep(0.0, 0.65, uIntro);
  col = uLightMode > 0.5 ? mix(vec3(1.0), col, presence) : col * presence;
  outColor = vec4(clamp(col, 0.0, 1.0), 1.0);
}`;

  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));
  const settings = {
    gradientColors: ['#000000', '#ffffff'],
    angle: 20,
    noise: 0.3,
    blindCount: 16,
    blindMinWidth: 60,
    mouseDampening: 0.15,
    mirrorGradient: false,
    spotlightRadius: 0.5,
    spotlightSoftness: 1,
    spotlightOpacity: 1,
    distortAmount: 0,
    shineDirection: 'left',
    lightColor: '#ffffff',
    perspective: 0,
    gradientSpeed: 0,
    shine: 0.4,
    relief: 0.5,
    glow: 0.4,
    sway: 0.35,
    speed: 1,
    hoverTilt: 0.6,
    clickEffect: 'ripple',
    idle: 'drift',
    intro: true,
    mixBlendMode: 'soft-light',
    lightMode: false,
  };

  const parseColor = (hex) => {
    const value = String(hex || '')
      .replace('#', '')
      .padEnd(6, '0');
    return [0, 2, 4].map((offset) => (parseInt(value.slice(offset, offset + 2), 16) || 0) / 255);
  };

  const prepareColors = (stops) => {
    const colors = (stops?.length ? stops : ['#0b132b', '#eaf7ff']).slice(0, MAX_COLORS);
    if (colors.length === 1) colors.push(colors[0]);
    while (colors.length < MAX_COLORS) colors.push(colors[colors.length - 1]);
    const flat = new Float32Array(MAX_COLORS * 3);
    for (let i = 0; i < MAX_COLORS; i += 1) flat.set(parseColor(colors[i]), i * 3);
    return { flat, count: Math.max(2, Math.min(MAX_COLORS, stops?.length ?? 2)) };
  };

  const compile = (gl, type, source) => {
    const shader = gl.createShader(type);
    if (!shader) return null;
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (gl.getShaderParameter(shader, gl.COMPILE_STATUS)) return shader;
    console.error('GradientBlinds shader failed:', gl.getShaderInfoLog(shader));
    gl.deleteShader(shader);
    return null;
  };

  const createProgram = (gl) => {
    const vertex = compile(gl, gl.VERTEX_SHADER, VERTEX);
    const fragment = compile(gl, gl.FRAGMENT_SHADER, FRAGMENT);
    if (!vertex || !fragment) return null;
    const program = gl.createProgram();
    if (!program) return null;
    gl.attachShader(program, vertex);
    gl.attachShader(program, fragment);
    gl.linkProgram(program);
    gl.deleteShader(vertex);
    gl.deleteShader(fragment);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
      console.error('GradientBlinds program failed:', gl.getProgramInfoLog(program));
      gl.deleteProgram(program);
      return null;
    }
    const uniforms = {};
    const count = gl.getProgramParameter(program, gl.ACTIVE_UNIFORMS);
    for (let i = 0; i < count; i += 1) {
      const info = gl.getActiveUniform(program, i);
      if (info)
        uniforms[info.name.replace(/\[0\]$/, '')] = gl.getUniformLocation(
          program,
          info.name.replace(/\[0\]$/, ''),
        );
    }
    return { program, uniforms };
  };

  document.addEventListener('DOMContentLoaded', () => {
    const container = document.querySelector('.gradient-blinds-layer');
    const canvas = container?.querySelector('.gradient-blinds-canvas');
    const gl = canvas?.getContext('webgl2', {
      alpha: false,
      antialias: false,
      depth: false,
      stencil: false,
      premultipliedAlpha: false,
    });
    if (!container || !canvas || !gl) return;

    const linked = createProgram(gl);
    if (!linked) return;
    const { program, uniforms: u } = linked;
    const vao = gl.createVertexArray();
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const view = { width: 1, height: 1, ratio: 1 };
    const pointer = { x: 0, y: 0, inside: false };
    const light = { x: 0, y: 0, vx: 0, vy: 0, tx: 0, ty: 0, ready: false };
    const waves = new Float32Array(MAX_WAVES * 4);
    let waveIndex = 0;
    let hover = 0;
    let time = 0;
    let swayTime = 0;
    let shift = 0;
    let grainTime = 0;
    let intro = settings.intro && !reduce ? 0 : 1;
    let raf = 0;
    let last = 0;
    let visible = false;
    const colorStops = prepareColors(settings.gradientColors);
    container.style.mixBlendMode = settings.mixBlendMode;

    const blindTotal = () => {
      const byWidth = Math.max(1, Math.floor(view.width / settings.blindMinWidth));
      return Math.max(1, Math.min(settings.blindCount, byWidth));
    };

    const draw = () => {
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.useProgram(program);
      gl.bindVertexArray(vao);
      gl.uniform2f(u.uResolution, canvas.width, canvas.height);
      gl.uniform1f(u.uTime, time);
      gl.uniform2f(u.uMouse, light.x * view.ratio, (view.height - light.y) * view.ratio);
      gl.uniform1f(u.uAngle, (settings.angle * Math.PI) / 180);
      gl.uniform1f(u.uNoise, settings.noise);
      gl.uniform1f(u.uBlindCount, blindTotal());
      gl.uniform1f(u.uSpotlightRadius, settings.spotlightRadius);
      gl.uniform1f(u.uSpotlightSoftness, settings.spotlightSoftness);
      gl.uniform1f(u.uSpotlightOpacity, settings.spotlightOpacity);
      gl.uniform1f(u.uMirror, settings.mirrorGradient ? 1 : 0);
      gl.uniform1f(u.uDistort, settings.distortAmount);
      gl.uniform1f(u.uShineFlip, settings.shineDirection === 'right' ? 1 : 0);
      gl.uniform3fv(u.uColors, colorStops.flat);
      gl.uniform1i(u.uColorCount, colorStops.count);
      gl.uniform1f(u.uLightMode, settings.lightMode ? 1 : 0);
      gl.uniform1f(u.uShine, settings.shine);
      gl.uniform1f(u.uRelief, settings.relief);
      gl.uniform1f(u.uGlow, settings.glow);
      gl.uniform1f(u.uSway, reduce ? 0 : settings.sway);
      gl.uniform1f(u.uSwayTime, swayTime);
      gl.uniform1f(u.uHover, hover * settings.hoverTilt);
      gl.uniform4fv(u.uWaves, waves);
      gl.uniform1f(u.uIntro, intro);
      gl.uniform1f(u.uGrainTime, grainTime);
      gl.uniform3fv(u.uLightColor, parseColor(settings.lightColor));
      gl.uniform1f(u.uPerspective, settings.perspective);
      gl.uniform1f(u.uGradientShift, shift);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      gl.bindVertexArray(null);
    };

    const aim = () => {
      if (pointer.inside) {
        light.tx = pointer.x;
        light.ty = pointer.y;
      } else if (settings.idle === 'center') {
        light.tx = view.width / 2;
        light.ty = view.height / 2;
      } else if (settings.idle === 'drift' && !reduce) {
        light.tx =
          view.width *
          (0.5 + 0.22 * Math.sin(swayTime * 0.23) + 0.05 * Math.sin(swayTime * 0.61 + 1.3));
        light.ty =
          view.height *
          (0.5 + 0.16 * Math.sin(swayTime * 0.31 + 0.7) + 0.04 * Math.sin(swayTime * 0.83));
      }
    };

    const follow = (dt) => {
      const tau = settings.mouseDampening;
      if (tau <= 0) {
        light.x = light.tx;
        light.y = light.ty;
        light.vx = 0;
        light.vy = 0;
        return;
      }
      const omega = 2.4 / tau;
      const k = omega * omega;
      const c = 2 * omega;
      const steps = Math.max(1, Math.ceil(dt / 0.008));
      const h = dt / steps;
      for (let i = 0; i < steps; i += 1) {
        light.vx += (k * (light.tx - light.x) - c * light.vx) * h;
        light.vy += (k * (light.ty - light.y) - c * light.vy) * h;
        light.x += light.vx * h;
        light.y += light.vy * h;
      }
    };

    const wake = () => {
      if (!raf && visible && !document.hidden) {
        last = 0;
        raf = window.requestAnimationFrame(frame);
      }
    };

    const resize = () => {
      view.width = Math.max(1, container.clientWidth);
      view.height = Math.max(1, container.clientHeight);
      view.ratio = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.max(1, Math.round(view.width * view.ratio));
      canvas.height = Math.max(1, Math.round(view.height * view.ratio));
      if (!light.ready) {
        light.ready = true;
        light.x = light.tx = view.width / 2;
        light.y = light.ty = view.height / 2;
      }
      draw();
      wake();
    };

    function frame(now) {
      raf = 0;
      if (!visible || document.hidden) return;
      const dt = last ? clamp((now - last) / 1000, 0.001, 1 / 20) : 1 / 60;
      last = now;
      time += dt;
      if (!reduce) {
        swayTime += dt * settings.speed;
        shift = (shift + dt * settings.gradientSpeed * 0.06) % 2;
      }
      grainTime = Math.floor(time * 24) * 17.13;
      if (intro < 1) intro = Math.min(1, intro + dt / INTRO_SECONDS);
      hover += ((pointer.inside ? 1 : 0) - hover) * (1 - Math.exp(-dt / 0.35));
      aim();
      follow(dt);
      for (let i = 0; i < MAX_WAVES; i += 1) {
        if (waves[i * 4 + 3] > 0 && time - waves[i * 4 + 2] > RIPPLE_SECONDS) waves[i * 4 + 3] = 0;
      }
      draw();
      const settling =
        Math.abs(light.tx - light.x) > 0.05 ||
        Math.abs(light.ty - light.y) > 0.05 ||
        Math.abs(light.vx) + Math.abs(light.vy) > 0.05 ||
        Math.abs((pointer.inside ? 1 : 0) - hover) > 0.002;
      const active =
        settling ||
        intro < 1 ||
        waves.some((value, index) => index % 4 === 3 && value > 0) ||
        (!reduce &&
          (settings.noise > 0 ||
            settings.gradientSpeed !== 0 ||
            (settings.sway > 0 && settings.speed > 0) ||
            (settings.idle === 'drift' && !pointer.inside)));
      if (active) raf = window.requestAnimationFrame(frame);
    }

    const locate = (event) => {
      const rect = container.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const y = event.clientY - rect.top;
      return { x, y, inside: x >= 0 && y >= 0 && x <= rect.width && y <= rect.height };
    };

    const onPointerMove = (event) => {
      const { x, y, inside } = locate(event);
      pointer.x = x;
      pointer.y = y;
      pointer.inside = inside;
      if (inside) wake();
    };

    const onPointerDown = (event) => {
      const { x, y, inside } = locate(event);
      if (!inside || reduce || settings.clickEffect !== 'ripple') return;
      const offset = waveIndex * 4;
      waves[offset] = x * view.ratio;
      waves[offset + 1] = (view.height - y) * view.ratio;
      waves[offset + 2] = time;
      waves[offset + 3] = 1;
      waveIndex = (waveIndex + 1) % MAX_WAVES;
      wake();
    };

    const onPointerLeave = () => {
      pointer.inside = false;
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
      if (visible) wake();
      else if (raf) {
        window.cancelAnimationFrame(raf);
        raf = 0;
      }
    });
    intersection.observe(container);
    window.addEventListener('pointermove', onPointerMove, { passive: true });
    window.addEventListener('pointerdown', onPointerDown, { passive: true });
    document.documentElement.addEventListener('pointerleave', onPointerLeave);
    document.addEventListener('visibilitychange', onVisibility);
    resize();

    window.addEventListener(
      'pagehide',
      () => {
        window.cancelAnimationFrame(raf);
        resizeObserver.disconnect();
        intersection.disconnect();
        window.removeEventListener('pointermove', onPointerMove);
        window.removeEventListener('pointerdown', onPointerDown);
        document.documentElement.removeEventListener('pointerleave', onPointerLeave);
        document.removeEventListener('visibilitychange', onVisibility);
        gl.deleteVertexArray(vao);
        gl.deleteProgram(program);
        gl.getExtension('WEBGL_lose_context')?.loseContext();
      },
      { once: true },
    );
  });
})();
