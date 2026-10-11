/* The night survey behind the page: a moon over a wireframe range of hills,
   the depscan wordmark standing in the landscape, embers drifting up through
   the haze. It also shows the state of a scan without words:
     idle     a vermilion moon, the land drifts slowly
     scan     a survey beam sweeps from the foreground to the horizon
     result   blocking packages stand on the land as vermilion markers,
              warnings as amber ones; the moon turns red when the build is
              blocked, amber with warnings, and pale when it passes
   WebGL2 with a depth buffer, so hills hide whatever is behind them. No
   libraries. Capped pixel ratio, 30 fps when idle, a governor that lowers
   resolution on slow machines, and no frames while the tab is hidden, motion
   is paused or the user prefers reduced motion (then a single still frame). */
(function () {
  'use strict';
  const DS = (window.DS = window.DS || {});
  const canvas = document.getElementById('field');
  const noop = () => {};
  DS.field = { set: noop, sweep: noop, setMotion: noop, retheme: noop, word: noop, active: false };
  if (!canvas) return;
  let gl = null;
  try { gl = canvas.getContext('webgl2', { antialias: true, alpha: false, depth: true, powerPreference: 'low-power' }); } catch (e) { gl = null; }
  if (!gl) return;
  document.documentElement.classList.add('gl');

  /* ---------------- shaders ---------------- */
  const NOISE = `
    float hash(vec2 p){ p = fract(p * vec2(123.34, 456.21)); p += dot(p, p + 45.32); return fract(p.x * p.y); }
    float noise(vec2 p){ vec2 i = floor(p), f = fract(p); vec2 u = f * f * (3.0 - 2.0 * f);
      return mix(mix(hash(i), hash(i + vec2(1, 0)), u.x), mix(hash(i + vec2(0, 1)), hash(i + vec2(1, 1)), u.x), u.y); }
    float fbm(vec2 p){ float a = 0.5, s = 0.0; for (int i = 0; i < 5; i++) { s += a * noise(p); p = p * 2.03 + vec2(1.7, 9.2); a *= 0.5; } return s; }`;
  const TERRAIN = NOISE + `
    uniform float u_time; uniform vec2 u_world;
    float terrain(vec2 xz){
      float d = clamp(xz.y / u_world.y, 0.0, 1.0);
      float side = smoothstep(0.12, 0.95, abs(xz.x) / (u_world.x * 0.5));
      float h = fbm(xz * 0.045 + vec2(0.0, u_time * 0.010));
      float r = 1.0 - abs(fbm(xz * 0.021 + vec2(5.0, u_time * 0.005)) * 2.0 - 1.0);
      float far = (h * 2.2 + r * r * 6.4 * (0.35 + side)) * (0.22 + d * d * 2.1 + d * 0.5);
      // a line of uneven hills across the middle distance, in front of the wordmark
      float k = (xz.y - 34.0) / 6.5;
      float m = fbm(vec2(xz.x * 0.045 + 3.0, 7.0 + u_time * 0.004));
      float hill = (0.9 + 5.2 * m * m) * exp(-k * k) * (0.72 + 0.28 * noise(xz * vec2(0.09, 0.2) + 3.0));
      return far + hill - 1.3;
    }`;
  const VS_LAND = `#version 300 es
    precision highp float;
    in vec2 a_uv;
    uniform mat4 u_mvp; uniform float u_psize; uniform float u_beamZ; uniform float u_beamOn;
    out float v_fog; out float v_beam; out float v_h; out float v_z;
    ${TERRAIN}
    void main(){
      vec2 xz = vec2((a_uv.x - 0.5) * u_world.x, a_uv.y * u_world.y);
      float h = terrain(xz);
      gl_Position = u_mvp * vec4(xz.x, h, -xz.y, 1.0);
      v_fog = smoothstep(u_world.y * 0.16, u_world.y * 1.02, xz.y);
      float bz = (xz.y - u_beamZ) / 1.8;
      v_beam = u_beamOn * exp(-bz * bz);
      v_h = h; v_z = xz.y;
      gl_PointSize = u_psize * (1.0 - v_fog * 0.7);
    }`;
  const FS_FILL = `#version 300 es
    precision highp float;
    in float v_fog; in float v_beam; in float v_h; in float v_z;
    uniform vec3 u_near; uniform vec3 u_far;
    out vec4 o;
    void main(){ o = vec4(mix(u_near, u_far, pow(v_fog, 1.4)), 1.0); }`;
  const FS_LINE = `#version 300 es
    precision highp float;
    in float v_fog; in float v_beam; in float v_h; in float v_z;
    uniform vec3 u_line; uniform vec3 u_beamCol; uniform vec3 u_glowCol; uniform float u_glowMix; uniform float u_alpha; uniform float u_point; uniform float u_nearFade; uniform float u_dim;
    out vec4 o;
    void main(){
      float a = u_alpha * (1.0 - v_fog * 0.82) * smoothstep(0.0, u_nearFade, v_z);
      a *= 0.45 + 0.55 * smoothstep(-1.6, 3.6, v_h);
      vec3 base = mix(u_line, u_glowCol, u_glowMix * smoothstep(0.1, 0.8, v_fog));
      vec3 c = mix(base, u_beamCol, clamp(v_beam * 1.4, 0.0, 1.0));
      a += v_beam * 0.9 * (1.0 - v_fog * 0.6);
      if (u_point > 0.5) { float r = length(gl_PointCoord - 0.5); a *= smoothstep(0.5, 0.05, r); }
      o = vec4(c, a * u_dim);
    }`;
  const VS_MARK = `#version 300 es
    precision highp float;
    in vec2 a_uv; in float a_lift; in float a_tone; in float a_seed;
    uniform mat4 u_mvp; uniform float u_psize; uniform float u_grow;
    out float v_tone; out float v_fog; out float v_pulse; out float v_top;
    ${TERRAIN}
    void main(){
      vec2 xz = vec2((a_uv.x - 0.5) * u_world.x, a_uv.y * u_world.y);
      float h = terrain(xz);
      float g = clamp(u_grow * 1.6 - a_seed * 0.6, 0.0, 1.0);
      gl_Position = u_mvp * vec4(xz.x, h + a_lift * g, -xz.y, 1.0);
      v_tone = a_tone; v_top = a_lift > 0.0 ? 1.0 : 0.0;
      v_fog = smoothstep(u_world.y * 0.35, u_world.y * 0.98, xz.y);
      v_pulse = 0.65 + 0.35 * sin(u_time * 2.2 + a_seed * 40.0);
      gl_PointSize = u_psize * g * (1.0 - v_fog * 0.6) * (0.85 + 0.3 * v_pulse);
    }`;
  const FS_MARK = `#version 300 es
    precision highp float;
    in float v_tone; in float v_fog; in float v_pulse; in float v_top;
    uniform vec3 u_c0; uniform vec3 u_c1; uniform vec3 u_c2; uniform float u_point; uniform float u_dim;
    out vec4 o;
    void main(){
      vec3 c = v_tone < 0.5 ? u_c0 : v_tone < 1.5 ? u_c1 : u_c2;
      float a = (1.0 - v_fog * 0.8);
      if (u_point > 0.5) { float r = length(gl_PointCoord - 0.5); a *= smoothstep(0.5, 0.0, r) * (0.55 + 0.45 * v_pulse); c = mix(c, vec3(1.0), smoothstep(0.18, 0.0, r) * 0.55); }
      else a *= mix(0.15, 0.85, v_top);
      o = vec4(c, a * u_dim);
    }`;
  const VS_SKY = `#version 300 es
    in vec2 a_p; out vec2 v_uv;
    void main(){ v_uv = a_p * 0.5 + 0.5; gl_Position = vec4(a_p, 0.9999, 1.0); }`;
  const FS_SKY = `#version 300 es
    precision highp float;
    in vec2 v_uv;
    uniform vec3 u_bg; uniform vec3 u_haze; uniform vec3 u_glow; uniform float u_glowA; uniform float u_hz; uniform float u_aspect; uniform float u_time; uniform float u_star;
    uniform vec2 u_moon; uniform float u_moonR; uniform vec3 u_moonCol; uniform float u_moonA; uniform float u_moonLit;
    out vec4 o;
    ${NOISE}
    void main(){
      float y = v_uv.y;
      vec2 p = vec2((v_uv.x - 0.5) * u_aspect, y);
      vec3 c = mix(u_bg, u_haze, smoothstep(1.05, u_hz - 0.05, y));
      float dy = (y - u_hz) / 0.11;
      c += u_glow * exp(-dy * dy) * u_glowA;
      // the moon: a lit sphere with maria and craters, and a soft halo
      vec2 mp = vec2((u_moon.x - 0.5) * u_aspect, u_moon.y);
      vec2 d = (p - mp) / u_moonR;
      float r = length(d);
      float halo = exp(-max(r - 1.0, 0.0) * 2.4) * 0.30 + exp(-max(r - 1.0, 0.0) * 0.55) * 0.10;
      c += u_moonCol * halo * u_moonA * u_moonLit;
      // stars, kept away from the moon and the haze
      vec2 g = floor(gl_FragCoord.xy / 3.0), f = fract(gl_FragCoord.xy / 3.0) - 0.5;
      float hs = fract(sin(dot(g, vec2(12.9898, 78.233))) * 43758.5453);
      float star = step(0.9991, hs) * smoothstep(0.42, 0.0, length(f)) * smoothstep(u_hz + 0.04, u_hz + 0.3, y) * smoothstep(1.0, 1.4, r);
      c += vec3(star * (0.5 + 0.5 * sin(u_time * 0.9 + hs * 90.0)) * 0.5 * u_star);
      if (r < 1.0) {
        float z = sqrt(1.0 - r * r);
        vec3 n = vec3(d.x, d.y, z);
        vec2 q = d / (1.0 + z * 0.45);
        float maria = smoothstep(0.42, 0.72, fbm(q * 1.7 + vec2(3.1, 1.7)));
        float crater = smoothstep(0.58, 0.8, fbm(q * 5.5 + vec2(11.0, 4.0)));
        float grain = fbm(q * 14.0) * 0.12;
        float light = 0.45 + 0.55 * clamp(dot(n, normalize(vec3(-0.45, 0.35, 0.82))), 0.0, 1.0);
        vec3 mc = u_moonCol * (1.08 - maria * 0.42 - crater * 0.16 - grain) * light;
        mc += u_moonCol * 0.22 * pow(1.0 - z, 2.0);
        c = mix(c, mc, smoothstep(1.0, 0.97, r) * u_moonA);
      }
      o = vec4(c, 1.0);
    }`;
  // The wordmark is placed in screen space, where the page leaves room for
  // it, but at the depth of a plane 50 units out, so the hills in front of
  // that plane still hide its lower edge.
  const VS_WORD = `#version 300 es
    in vec2 a_p; uniform vec4 u_box; uniform float u_z; out vec2 v_uv;
    void main(){ v_uv = vec2(a_p.x, 1.0 - a_p.y); gl_Position = vec4(u_box.x + a_p.x * u_box.z, u_box.y + a_p.y * u_box.w, u_z, 1.0); }`;
  const FS_WORD = `#version 300 es
    precision highp float;
    in vec2 v_uv; uniform sampler2D u_tex; uniform vec3 u_col; uniform vec3 u_haze; uniform float u_a;
    out vec4 o;
    void main(){
      float a = texture(u_tex, v_uv).a;
      vec3 c = mix(u_col, u_haze, 0.08 + 0.42 * smoothstep(0.35, 1.0, v_uv.y));
      o = vec4(c, a * u_a);
    }`;
  const VS_EMBER = `#version 300 es
    in vec3 a_seed; uniform mat4 u_mvp; uniform float u_time; uniform float u_psize;
    out float v_a; out float v_t;
    void main(){
      float life = fract(a_seed.z * 7.0 + u_time * (0.018 + a_seed.x * 0.022));
      float z = 8.0 + a_seed.y * 62.0;
      float x = (a_seed.x - 0.5) * 120.0 + sin(u_time * 0.35 + a_seed.y * 20.0) * 3.0 + life * 6.0;
      float y = -1.5 + life * 24.0;
      gl_Position = u_mvp * vec4(x, y, -z, 1.0);
      v_a = smoothstep(0.0, 0.12, life) * (1.0 - smoothstep(0.55, 1.0, life)) * (0.6 + 0.4 * sin(u_time * 3.0 + a_seed.z * 50.0));
      v_t = a_seed.x;
      gl_PointSize = u_psize * (1.4 + a_seed.z * 2.6) * (34.0 / (z + 8.0));
    }`;
  const FS_EMBER = `#version 300 es
    precision highp float;
    in float v_a; in float v_t; uniform vec3 u_c0; uniform vec3 u_c1; uniform float u_dim;
    out vec4 o;
    void main(){ float r = length(gl_PointCoord - 0.5); float a = smoothstep(0.5, 0.0, r) * v_a; o = vec4(mix(u_c0, u_c1, v_t), a * u_dim); }`;

  function compile(type, src) {
    const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
    return s;
  }
  function program(vs, fs) {
    const p = gl.createProgram();
    gl.attachShader(p, compile(gl.VERTEX_SHADER, vs)); gl.attachShader(p, compile(gl.FRAGMENT_SHADER, fs));
    gl.bindAttribLocation(p, 0, 'a_uv'); // the two land programs share one vertex array
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p));
    const u = {}, n = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
    for (let i = 0; i < n; i++) { const info = gl.getActiveUniform(p, i); u[info.name] = gl.getUniformLocation(p, info.name); }
    return { p, u, a: (name) => gl.getAttribLocation(p, name) };
  }
  let fill, lines, mark, sky, word, ember;
  try {
    fill = program(VS_LAND, FS_FILL); lines = program(VS_LAND, FS_LINE); mark = program(VS_MARK, FS_MARK);
    sky = program(VS_SKY, FS_SKY); word = program(VS_WORD, FS_WORD); ember = program(VS_EMBER, FS_EMBER);
  } catch (e) { console.warn('depscan: background disabled:', e.message); document.documentElement.classList.remove('gl'); return; }

  /* ---------------- geometry ---------------- */
  const small = Math.min(innerWidth, innerHeight) < 700;
  const COLS = small ? 100 : 156, ROWS = small ? 52 : 74;
  const WORLD = [150, 96];
  const uv = new Float32Array(COLS * ROWS * 2);
  for (let r = 0; r < ROWS; r++) for (let c = 0; c < COLS; c++) { const i = (r * COLS + c) * 2; uv[i] = c / (COLS - 1); uv[i + 1] = Math.pow(r / (ROWS - 1), 1.3); }
  const rowIdx = [], colIdx = [], dotIdx = [], triIdx = [];
  for (let r = 0; r < ROWS; r++) for (let c = 0; c < COLS - 1; c++) rowIdx.push(r * COLS + c, r * COLS + c + 1);
  for (let c = 0; c < COLS; c += 6) for (let r = 0; r < ROWS - 1; r++) colIdx.push(r * COLS + c, (r + 1) * COLS + c);
  for (let r = 0; r < ROWS; r += 2) for (let c = 3; c < COLS; c += 6) dotIdx.push(r * COLS + c);
  for (let r = 0; r < ROWS - 1; r++) for (let c = 0; c < COLS - 1; c++) { const a = r * COLS + c, b = a + 1, d = a + COLS, e = d + 1; triIdx.push(a, d, b, b, d, e); }

  const vaoLand = gl.createVertexArray();
  gl.bindVertexArray(vaoLand);
  const bUV = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, bUV); gl.bufferData(gl.ARRAY_BUFFER, uv, gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0); gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
  const mkIdx = (arr) => { const b = gl.createBuffer(); gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, b); gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint16Array(arr), gl.STATIC_DRAW); return { b, n: arr.length }; };
  const iRows = mkIdx(rowIdx), iCols = mkIdx(colIdx), iDots = mkIdx(dotIdx), iTris = mkIdx(triIdx);
  gl.bindVertexArray(null);

  const quad = (prog, attr, data) => {
    const v = gl.createVertexArray(); gl.bindVertexArray(v);
    const b = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, b); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(data), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(prog.a(attr)); gl.vertexAttribPointer(prog.a(attr), 2, gl.FLOAT, false, 0, 0);
    gl.bindVertexArray(null); return v;
  };
  const vaoSky = quad(sky, 'a_p', [-1, -1, 3, -1, -1, 3]);
  const vaoWord = quad(word, 'a_p', [0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1]);

  // Markers: one point and one vertical pin per flagged package.
  const MAXM = 64;
  const vaoMark = gl.createVertexArray(), bMark = gl.createBuffer();
  gl.bindVertexArray(vaoMark);
  gl.bindBuffer(gl.ARRAY_BUFFER, bMark); gl.bufferData(gl.ARRAY_BUFFER, MAXM * 2 * 5 * 4, gl.DYNAMIC_DRAW);
  [['a_uv', 2, 0], ['a_lift', 1, 8], ['a_tone', 1, 12], ['a_seed', 1, 16]].forEach(([n, s, o]) => { const l = mark.a(n); gl.enableVertexAttribArray(l); gl.vertexAttribPointer(l, s, gl.FLOAT, false, 20, o); });
  gl.bindVertexArray(null);
  let markCount = 0;

  // Embers: fixed random seeds; the shader moves them.
  const NEMB = small ? 70 : 150;
  const seeds = new Float32Array(NEMB * 3);
  for (let i = 0; i < seeds.length; i++) seeds[i] = Math.random();
  const vaoEmber = gl.createVertexArray(); gl.bindVertexArray(vaoEmber);
  const bEmber = gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER, bEmber); gl.bufferData(gl.ARRAY_BUFFER, seeds, gl.STATIC_DRAW);
  gl.enableVertexAttribArray(ember.a('a_seed')); gl.vertexAttribPointer(ember.a('a_seed'), 3, gl.FLOAT, false, 0, 0);
  gl.bindVertexArray(null);

  // The wordmark, drawn into a texture once the font has loaded.
  const tex = gl.createTexture();
  let texAspect = 0;
  function buildWord() {
    const c = document.createElement('canvas'), x = c.getContext('2d');
    const text = 'DEPSCAN', size = 300, track = 0.13;
    const font = '500 ' + size + 'px Onest, system-ui, sans-serif';
    x.font = font;
    let w = 0; for (const ch of text) w += x.measureText(ch).width + size * track;
    w -= size * track;
    const cap = size * 0.72, pad = 8;
    c.width = Math.ceil(w + pad * 2); c.height = Math.ceil(cap + pad * 2);
    x.font = font; x.fillStyle = '#fff'; x.textBaseline = 'alphabetic';
    let cx = pad; for (const ch of text) { x.fillText(ch, cx, c.height - pad); cx += x.measureText(ch).width + size * track; }
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, c);
    gl.generateMipmap(gl.TEXTURE_2D);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE); gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    texAspect = c.height / c.width;
    kick();
  }

  /* ---------------- camera ---------------- */
  function persp(fovy, aspect, near, far) {
    const f = 1 / Math.tan(fovy / 2), nf = 1 / (near - far);
    return [f / aspect, 0, 0, 0, 0, f, 0, 0, 0, 0, (far + near) * nf, -1, 0, 0, 2 * far * near * nf, 0];
  }
  function lookAt(e, t, up) {
    let zx = e[0] - t[0], zy = e[1] - t[1], zz = e[2] - t[2]; let l = Math.hypot(zx, zy, zz); zx /= l; zy /= l; zz /= l;
    let xx = up[1] * zz - up[2] * zy, xy = up[2] * zx - up[0] * zz, xz = up[0] * zy - up[1] * zx; l = Math.hypot(xx, xy, xz); xx /= l; xy /= l; xz /= l;
    const yx = zy * xz - zz * xy, yy = zz * xx - zx * xz, yz = zx * xy - zy * xx;
    return [xx, yx, zx, 0, xy, yy, zy, 0, xz, yz, zz, 0, -(xx * e[0] + xy * e[1] + xz * e[2]), -(yx * e[0] + yy * e[1] + yz * e[2]), -(zx * e[0] + zy * e[1] + zz * e[2]), 1];
  }
  function mul(a, b) {
    const o = new Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) { let s = 0; for (let k = 0; k < 4; k++) s += a[k * 4 + r] * b[c * 4 + k]; o[c * 4 + r] = s; }
    return o;
  }
  function project(m, p) {
    const x = m[0] * p[0] + m[4] * p[1] + m[8] * p[2] + m[12], y = m[1] * p[0] + m[5] * p[1] + m[9] * p[2] + m[13], z = m[2] * p[0] + m[6] * p[1] + m[10] * p[2] + m[14], w = m[3] * p[0] + m[7] * p[1] + m[11] * p[2] + m[15];
    return [x / w, y / w, z / w];
  }

  /* ---------------- colours ---------------- */
  let probe = null;
  function rgbOf(css, fb) {
    if (!probe) { const c = document.createElement('canvas'); c.width = c.height = 1; probe = c.getContext('2d', { willReadFrequently: true }); }
    probe.clearRect(0, 0, 1, 1); probe.fillStyle = '#000'; probe.fillStyle = css || fb; probe.fillRect(0, 0, 1, 1);
    const d = probe.getImageData(0, 0, 1, 1).data; return [d[0] / 255, d[1] / 255, d[2] / 255];
  }
  const mix3 = (a, b, t) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];

  /* ---------------- state ---------------- */
  let C = {};
  const S = { mode: 'idle', verdict: '', glow: [0, 0, 0], glowA: 0, beam: 0, grow: 0, sweepAt: -1, moonCol: null, wordA: 0, pitch: null };
  let wordEl = null;
  const target = { glow: null, glowA: 0.26, beam: 0, grow: 0, moon: null, wordA: 0 };
  let px = 0, py = 0, tpx = 0, tpy = 0, scrollK = 0, scrollT = 0;
  let running = false, raf = 0, last = 0, simT = 0, frameAvg = 10, scale = 1;
  const rmq = matchMedia('(prefers-reduced-motion: reduce)');
  let motionOn = !document.documentElement.classList.contains('still');

  function retheme() {
    const cs = getComputedStyle(document.documentElement), v = (n) => cs.getPropertyValue(n).trim();
    const bg = rgbOf(v('--bg'), '#06080b');
    const dark = 0.2126 * bg[0] + 0.7152 * bg[1] + 0.0722 * bg[2] < 0.4;
    C = {
      dark, bg,
      haze: dark ? mix3(bg, [0.11, 0.13, 0.19], 0.55) : mix3(bg, [0.86, 0.84, 0.8], 0.6),
      line: rgbOf(v('--text'), '#dfe7e0'), crit: rgbOf(v('--critical'), '#e0231c'), warn: rgbOf(v('--medium'), '#d3a13f'), pass: rgbOf(v('--clean'), '#6bab88'), brand: rgbOf(v('--brand'), '#e0231c'),
      moon: dark
        ? { idle: [0.74, 0.17, 0.14], block: [0.8, 0.13, 0.1], warn: [0.86, 0.6, 0.28], pass: [0.84, 0.87, 0.82] }
        : { idle: [0.9, 0.42, 0.36], block: [0.88, 0.32, 0.27], warn: [0.88, 0.66, 0.4], pass: [0.74, 0.78, 0.74] },
      word: dark ? [0.86, 0.9, 0.87] : [0.08, 0.1, 0.12]
    };
    if (!S.moonCol) S.moonCol = C.moon.idle.slice();
    // re-aim the targets at the new palette
    applyTargets();
    kick();
  }

  function seeded(str) {
    let h = 2166136261; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
    return () => { h += 0x6D2B79F5; let t = h; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  }
  function setMarkers(block, warn, seed) {
    const rnd = seeded(String(seed || 'depscan'));
    const n = Math.min(MAXM, block + warn);
    const data = new Float32Array(MAXM * 2 * 5);
    for (let i = 0; i < n; i++) {
      const u = 0.1 + rnd() * 0.8, w = 0.2 + rnd() * 0.46, tone = i < block ? 0 : 1, s = rnd();
      const lift = (tone === 0 ? 3.4 : 2.0) + rnd() * 1.8;
      data.set([u, w, 0, tone, s, u, w, lift, tone, s], i * 10);
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, bMark); gl.bufferSubData(gl.ARRAY_BUFFER, 0, data);
    markCount = n;
  }
  function applyTargets() {
    if (!C.moon) return;
    if (S.mode === 'result') {
      target.glow = S.verdict === 'block' ? C.crit : S.verdict === 'warn' ? C.warn : S.verdict === 'pass' ? C.pass : C.line;
      target.glowA = S.verdict === 'pass' ? 0.38 : S.verdict ? 0.5 : 0.2;
      target.moon = C.moon[S.verdict] || C.moon.idle;
      target.beam = 0;
    } else if (S.mode === 'scan') {
      target.glow = C.brand; target.glowA = 0.36; target.beam = 1; target.moon = C.moon.idle;
    } else {
      target.glow = C.brand; target.glowA = 0.26; target.beam = 0; target.moon = C.moon.idle;
    }
  }
  function set(o) {
    o = o || {};
    const prev = S.mode + S.verdict + (o.seed || '');
    S.mode = o.mode || 'idle';
    S.verdict = o.verdict || '';
    if (S.mode === 'result') {
      if (prev !== S.mode + S.verdict + (o.seed || '')) { setMarkers(o.block || 0, o.warn || 0, o.seed); S.grow = 0; }
      target.grow = 1;
    } else target.grow = 0;
    applyTargets();
    kick();
  }
  function sweep() { S.sweepAt = simT; kick(); }
  // The wordmark stands in the landscape on the landing view only. Pass the
  // element that marks its band on the page, or null to lower it.
  function showWord(el) { if (el) wordEl = el; target.wordA = el ? 1 : 0; kick(); }

  // Where the wordmark goes, in page pixels, and how far the camera tilts so
  // the hill line crosses the letters about three quarters of the way down.
  function wordLayout(narrow, eyeY, fov) {
    if (!wordEl || !texAspect || !wordEl.isConnected) return null;
    const r = wordEl.getBoundingClientRect();
    if (!r.height && !r.width) return null;
    const vw = innerWidth, vh = innerHeight, top = r.top + scrollY + (narrow ? 6 : 14), bottom = r.bottom + scrollY;
    let wpx = vw * (narrow ? 0.9 : 0.97), cap = wpx * texAspect;
    const room = bottom + (narrow ? 20 : 40) - top;
    if (cap * 0.74 > room) { cap = Math.max(24, room / 0.74); wpx = cap / texAspect; }
    const crest = Math.min(top + cap * 0.74, vh - 30);
    const T = Math.tan(fov * Math.PI / 360), yc = 1 - 2 * crest / vh;
    const pitch = Math.atan((2.2 - eyeY) / 42.5) - Math.atan(yc * T);
    return { pitch, box: [-wpx / vw, 1 - 2 * (top + cap) / vh, wpx / vw * 2, cap / vh * 2] };
  }

  /* ---------------- frame ---------------- */
  function resize() {
    const dpr = Math.min(1.5, devicePixelRatio || 1) * scale;
    const w = Math.max(1, Math.round(innerWidth * dpr)), h = Math.max(1, Math.round(innerHeight * dpr));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
    gl.viewport(0, 0, w, h);
  }
  const ease = (cur, tgt, k) => cur + (tgt - cur) * k;
  const easeV = (cur, tgt, k) => { for (let i = 0; i < 3; i++) cur[i] = ease(cur[i], tgt[i], k); };

  function draw(now) {
    const dt = Math.min(0.1, Math.max(0, (now - last) / 1000)); last = now;
    const still = rmq.matches || !motionOn;
    if (!still) simT += dt;
    const k = still ? 1 : 1 - Math.exp(-dt * 2.4), kp = still ? 1 : 1 - Math.exp(-dt * 3);
    easeV(S.glow, target.glow || C.brand, k);
    easeV(S.moonCol, target.moon || C.moon.idle, still ? 1 : 1 - Math.exp(-dt * 1.4));
    S.glowA = ease(S.glowA, target.glowA, k);
    S.beam = ease(S.beam, target.beam, k);
    S.grow = ease(S.grow, target.grow, still ? 1 : 1 - Math.exp(-dt * 1.1));
    S.wordA = ease(S.wordA, target.wordA, still ? 1 : 1 - Math.exp(-dt * 3.2));
    px = ease(px, tpx, kp); py = ease(py, tpy, kp);
    scrollK = ease(scrollK, scrollT, still ? 1 : 1 - Math.exp(-dt * 8));

    resize();
    const W = canvas.width, H = canvas.height, aspect = W / H;
    const narrow = aspect < 0.8;
    const fov = narrow ? 60 : 46, eyeY = narrow ? 7.2 : 5.8, hzNdc = narrow ? -0.2 : -0.14;
    const wl = target.wordA > 0 || S.wordA > 0.005 ? wordLayout(narrow, eyeY, fov) : null;
    const pitchT = wl && target.wordA > 0 ? wl.pitch : Math.atan(-hzNdc * Math.tan(fov * Math.PI / 360));
    S.pitchT = pitchT;
    S.pitch = S.pitch == null || still ? pitchT : ease(S.pitch, pitchT, 1 - Math.exp(-dt * 3));
    const eye = [px * 1.6, eyeY + py * 0.5, 8.5];
    const tgt = [px * 0.6, eyeY + 38.5 * Math.tan(S.pitch) - py * 0.4 + scrollK * 3.4, -30];
    const mvp = mul(persp(fov * Math.PI / 180, aspect, 0.5, 260), lookAt(eye, tgt, [0, 1, 0]));
    const hz = (project(mvp, [0, 0, -WORLD[1] * 1.6])[1] + 1) / 2;
    const dim = 1 - scrollK * 0.74;
    const pr = Math.min(1.5, devicePixelRatio || 1) * scale;

    gl.enable(gl.DEPTH_TEST); gl.depthFunc(gl.LEQUAL); gl.depthMask(true);
    gl.clearColor(C.bg[0], C.bg[1], C.bg[2], 1); gl.clearDepth(1); gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    gl.disable(gl.BLEND);

    // sky, moon and stars, at the far plane
    gl.depthMask(false);
    gl.useProgram(sky.p); gl.bindVertexArray(vaoSky);
    gl.uniform3fv(sky.u.u_bg, C.bg); gl.uniform3fv(sky.u.u_haze, C.haze); gl.uniform3fv(sky.u.u_glow, S.glow);
    gl.uniform1f(sky.u.u_glowA, S.glowA * (C.dark ? 0.42 : 0.18) * (0.55 + 0.45 * dim)); gl.uniform1f(sky.u.u_hz, hz); gl.uniform1f(sky.u.u_aspect, aspect);
    gl.uniform1f(sky.u.u_time, simT); gl.uniform1f(sky.u.u_star, C.dark ? dim : 0);
    const moonX = (narrow ? 0.76 : 0.7) + px * 0.008, moonY = Math.min(narrow ? 0.86 : 0.84, hz + (narrow ? 0.11 : 0.31)) - py * 0.006 - scrollK * 0.08;
    gl.uniform2f(sky.u.u_moon, moonX, moonY); gl.uniform1f(sky.u.u_moonR, narrow ? 0.062 : 0.13);
    gl.uniform3fv(sky.u.u_moonCol, S.moonCol); gl.uniform1f(sky.u.u_moonA, 0.14 + 0.86 * dim * dim); gl.uniform1f(sky.u.u_moonLit, C.dark ? 1 : 0.6);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    gl.depthMask(true);

    // land, filled: hides the moon and whatever stands behind each ridge
    const farCol = mix3(C.haze, S.glow, (C.dark ? 0.12 : 0.05) * S.glowA * 3);
    gl.useProgram(fill.p); gl.bindVertexArray(vaoLand);
    gl.uniformMatrix4fv(fill.u.u_mvp, false, mvp); gl.uniform1f(fill.u.u_time, simT); gl.uniform2fv(fill.u.u_world, WORLD);
    gl.uniform3fv(fill.u.u_near, C.dark ? mix3(C.bg, [0, 0, 0], 0.25) : mix3(C.bg, [1, 1, 1], 0.2)); gl.uniform3fv(fill.u.u_far, mix3(C.bg, farCol, C.dark ? 0.82 : 0.7));
    gl.enable(gl.POLYGON_OFFSET_FILL); gl.polygonOffset(1.5, 2);
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, iTris.b); gl.drawElements(gl.TRIANGLES, iTris.n, gl.UNSIGNED_SHORT, 0);
    gl.disable(gl.POLYGON_OFFSET_FILL);

    gl.enable(gl.BLEND); gl.depthMask(false);

    // the wordmark stands between the far range and the near hills
    if (wl && S.wordA > 0.005) {
      const b = wl.box, zNdc = project(mvp, [0, 0, -50])[2];
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
      gl.useProgram(word.p); gl.bindVertexArray(vaoWord);
      gl.uniform4f(word.u.u_box, b[0] - px * 0.006, b[1] + (1 - S.wordA) * -0.04, b[2], b[3]); gl.uniform1f(word.u.u_z, zNdc);
      gl.uniform3fv(word.u.u_col, C.word); gl.uniform3fv(word.u.u_haze, C.haze); gl.uniform1f(word.u.u_a, S.wordA * (C.dark ? 0.92 : 0.88) * dim);
      gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, tex); gl.uniform1i(word.u.u_tex, 0);
      gl.drawArrays(gl.TRIANGLES, 0, 6);
    }

    if (C.dark) gl.blendFunc(gl.SRC_ALPHA, gl.ONE); else gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

    // land: contour lines and survey points
    const period = WORLD[1] + 30;
    let beamZ = ((simT * 15) % period) - 12, beamOn = S.beam;
    if (S.sweepAt >= 0) {
      const sp = (simT - S.sweepAt) * 26 - 8;
      if (sp > WORLD[1] + 10 || still) S.sweepAt = -1; else { beamZ = sp; beamOn = Math.max(beamOn, 0.9); }
    }
    gl.useProgram(lines.p); gl.bindVertexArray(vaoLand);
    gl.uniformMatrix4fv(lines.u.u_mvp, false, mvp); gl.uniform1f(lines.u.u_time, simT); gl.uniform2fv(lines.u.u_world, WORLD);
    gl.uniform1f(lines.u.u_beamZ, beamZ); gl.uniform1f(lines.u.u_beamOn, beamOn);
    gl.uniform3fv(lines.u.u_line, C.line); gl.uniform3fv(lines.u.u_glowCol, S.glow); gl.uniform1f(lines.u.u_glowMix, Math.min(0.8, S.glowA * 1.5));
    gl.uniform3fv(lines.u.u_beamCol, S.mode === 'scan' || S.sweepAt >= 0 ? (S.verdict === 'pass' ? C.pass : C.brand) : C.line);
    gl.uniform1f(lines.u.u_nearFade, 9.0); gl.uniform1f(lines.u.u_dim, dim);
    gl.uniform1f(lines.u.u_point, 0); gl.uniform1f(lines.u.u_psize, 0);
    gl.uniform1f(lines.u.u_alpha, C.dark ? 0.24 : 0.2);
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, iRows.b); gl.drawElements(gl.LINES, iRows.n, gl.UNSIGNED_SHORT, 0);
    gl.uniform1f(lines.u.u_alpha, 0.08);
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, iCols.b); gl.drawElements(gl.LINES, iCols.n, gl.UNSIGNED_SHORT, 0);
    gl.uniform1f(lines.u.u_point, 1); gl.uniform1f(lines.u.u_psize, 3.2 * pr); gl.uniform1f(lines.u.u_alpha, C.dark ? 0.55 : 0.4);
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, iDots.b); gl.drawElements(gl.POINTS, iDots.n, gl.UNSIGNED_SHORT, 0);

    // markers for flagged packages
    if (markCount && S.grow > 0.01 && S.mode === 'result') {
      gl.useProgram(mark.p); gl.bindVertexArray(vaoMark);
      gl.uniformMatrix4fv(mark.u.u_mvp, false, mvp);
      gl.uniform1f(mark.u.u_time, simT); gl.uniform2fv(mark.u.u_world, WORLD); gl.uniform1f(mark.u.u_grow, S.grow);
      gl.uniform3fv(mark.u.u_c0, C.crit); gl.uniform3fv(mark.u.u_c1, C.warn); gl.uniform3fv(mark.u.u_c2, C.pass);
      gl.uniform1f(mark.u.u_dim, dim * dim);
      gl.uniform1f(mark.u.u_point, 0); gl.uniform1f(mark.u.u_psize, 0);
      gl.drawArrays(gl.LINES, 0, markCount * 2);
      gl.uniform1f(mark.u.u_point, 1); gl.uniform1f(mark.u.u_psize, 16 * pr);
      for (let i = 0; i < markCount; i++) gl.drawArrays(gl.POINTS, i * 2 + 1, 1);
    }

    // embers drifting up through the haze
    gl.useProgram(ember.p); gl.bindVertexArray(vaoEmber);
    gl.uniformMatrix4fv(ember.u.u_mvp, false, mvp); gl.uniform1f(ember.u.u_time, simT); gl.uniform1f(ember.u.u_psize, pr * (narrow ? 1.6 : 2.2));
    gl.uniform3fv(ember.u.u_c0, C.brand); gl.uniform3fv(ember.u.u_c1, C.warn); gl.uniform1f(ember.u.u_dim, dim * (C.dark ? 0.85 : 0.45));
    gl.drawArrays(gl.POINTS, 0, NEMB);

    gl.disable(gl.BLEND); gl.depthMask(true);
    gl.bindVertexArray(null);
  }

  function settling() {
    return S.mode === 'scan' || S.sweepAt >= 0 || Math.abs(S.grow - target.grow) > 0.01 || Math.abs(S.glowA - target.glowA) > 0.005 ||
      Math.abs(S.wordA - target.wordA) > 0.01 || Math.abs(scrollK - scrollT) > 0.002 || Math.abs((S.pitch || 0) - (S.pitchT || 0)) > 0.0005;
  }
  function frame(now) {
    raf = 0;
    const live = running && motionOn && !rmq.matches && !document.hidden;
    const minGap = settling() ? 0 : 1000 / 30 - 2;
    if (live && now - last < minGap) { raf = requestAnimationFrame(frame); return; }
    const t = performance.now();
    draw(now);
    // Governor: if frames take too long, render fewer pixels.
    frameAvg = frameAvg * 0.92 + (performance.now() - t) * 0.08;
    if (frameAvg > 14 && scale > 0.6) { scale = Math.max(0.6, scale - 0.1); frameAvg = 10; }
    if (live) raf = requestAnimationFrame(frame);
  }
  function kick() { if (!raf) { if (!last) last = performance.now(); raf = requestAnimationFrame(frame); } }
  function start() { running = true; last = performance.now(); kick(); }
  function setMotion(on) { motionOn = on; last = performance.now(); kick(); }

  /* ---------------- input ---------------- */
  if (matchMedia('(pointer: fine)').matches) {
    addEventListener('pointermove', (e) => { tpx = (e.clientX / innerWidth - 0.5) * 2; tpy = (e.clientY / innerHeight - 0.5) * 2; if (!raf && motionOn && !rmq.matches) kick(); }, { passive: true });
  }
  addEventListener('scroll', () => { scrollT = Math.min(1, scrollY / (innerHeight * 0.75)); kick(); }, { passive: true });
  addEventListener('resize', kick);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { last = performance.now(); kick(); } });
  rmq.addEventListener('change', kick);
  new MutationObserver(retheme).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', retheme);
  canvas.addEventListener('webglcontextlost', (e) => { e.preventDefault(); running = false; document.documentElement.classList.remove('gl'); });

  retheme();
  S.glow = C.brand.slice();
  if (document.fonts && document.fonts.load) document.fonts.load('500 120px Onest').then(buildWord, buildWord); else buildWord();
  start();

  DS.field = { set, sweep, setMotion, retheme, word: showWord, active: true };
})();
