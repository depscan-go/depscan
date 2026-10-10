/* Backdrop: a slow WebGL swirl gradient under a grid that bends toward the
   pointer and ripples on click. Both are tuned to stay cheap:
   - the gradient renders at half resolution and 30 fps, and stops when the
     tab is hidden or the person pauses it;
   - the grid only redraws while the pointer moves or a ripple is running;
   - with reduced motion, each draws one still frame. */
(function () {
  'use strict';
  const gl$ = document.getElementById('bgGl');
  const grid$ = document.getElementById('bgGrid');
  const grain$ = document.getElementById('bgGrain');
  const motionBtn = document.getElementById('motionBtn');
  if (!gl$ || !grid$) return;

  const rmq = matchMedia('(prefers-reduced-motion: reduce)');
  const dmq = matchMedia('(prefers-color-scheme: dark)');
  let paused = false;
  try { paused = localStorage.getItem('depscan.motion') === 'off'; } catch (e) { /* storage blocked: default on */ }
  const still = () => rmq.matches || paused;

  /* ---------- palettes ---------- */
  const THEMES = {
    dark: {
      c1: [7, 11, 34], c2: [86, 66, 232], c3: [10, 36, 92],
      line: [190, 200, 255, 0.09], active: [150, 132, 255, 0.95], dots: 'rgba(200,210,255,0.06)'
    },
    light: {
      c1: [240, 243, 252], c2: [196, 186, 255], c3: [206, 230, 255],
      line: [40, 50, 110, 0.075], active: [91, 75, 255, 0.85], dots: 'rgba(30,40,100,0.07)'
    }
  };
  const theme = () => THEMES[dmq.matches ? 'dark' : 'light'];

  /* ---------- grain ---------- */
  if (grain$) {
    const c = document.createElement('canvas'); c.width = c.height = 128;
    const x = c.getContext('2d'), img = x.createImageData(128, 128);
    for (let i = 0; i < img.data.length; i += 4) { const v = Math.random() * 255 | 0; img.data[i] = img.data[i + 1] = img.data[i + 2] = v; img.data[i + 3] = 255; }
    x.putImageData(img, 0, 0);
    grain$.style.backgroundImage = 'url(' + c.toDataURL('image/png') + ')';
  }

  /* ---------- swirl gradient (WebGL2) ---------- */
  const FRAG = `#version 300 es
precision highp float;
uniform float u_time; uniform float u_ratio; uniform vec2 u_res;
uniform vec3 u_c1; uniform vec3 u_c2; uniform vec3 u_c3;
out vec4 frag;
#define PI 3.14159265
vec2 rot(vec2 uv, float th) { return mat2(cos(th), sin(th), -sin(th), cos(th)) * uv; }
float rnd(vec2 st) { return fract(sin(dot(st, vec2(12.9898, 78.233))) * 43758.5453); }
float noise(vec2 st) {
  vec2 i = floor(st), f = fract(st);
  float a = rnd(i), b = rnd(i + vec2(1., 0.)), c = rnd(i + vec2(0., 1.)), d = rnd(i + vec2(1., 1.));
  vec2 u = f * f * (3. - 2. * f);
  return mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
}
void main() {
  vec2 uv = gl_FragCoord.xy / u_res;
  float t = .5 * u_time;
  float ns = .0005 + .006 * .55;
  uv -= .5; uv *= ns * u_res; uv = rot(uv, -.35 * PI); uv /= u_ratio; uv += .5;
  float n1 = noise(uv + t), n2 = noise(uv * 2. - t), ang = n1 * 6.2831853;
  uv += .48 * n2 * vec2(cos(ang), sin(ang));
  for (float i = 1.; i <= 6.; i++) {
    uv.x += .55 / i * cos(t + i * 1.5 * uv.y);
    uv.y += .55 / i * cos(t + i * uv.x);
  }
  vec2 cu = uv * (.5 + 3.5 * .3);
  float mixer = .5 + .5 * sin(cu.x) * cos(cu.y) - .1;
  float r1 = smoothstep(0., .7, mixer), r2 = smoothstep(.3, 1.01, mixer);
  vec3 col = mix(mix(u_c1, u_c2, r1), u_c3, r2);
  // Fade the colour toward the base near the top, where the app bar and
  // headline sit, so text keeps its contrast.
  float topFade = smoothstep(.55, 1., gl_FragCoord.y / u_res.y);
  col = mix(col, u_c1, topFade * .55);
  frag = vec4(col, 1.);
}`;
  const VERT = `#version 300 es
in vec2 p; void main() { gl_Position = vec4(p, 0., 1.); }`;

  const SCALE = 0.5;           // render at half the CSS resolution; the swirl is soft
  const FRAME_MS = 1000 / 30;  // 30 fps is plenty for a slow drift
  const SPEED = 0.16;

  let gl = null, prog = null, U = {}, raf = 0, last = 0, clock = 0;
  try { gl = gl$.getContext('webgl2', { alpha: false, antialias: false, depth: false, stencil: false, powerPreference: 'low-power' }); } catch (e) { gl = null; }

  function compile(type, src) {
    const s = gl.createShader(type); gl.shaderSource(s, src); gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s));
    return s;
  }
  if (gl) {
    try {
      prog = gl.createProgram();
      gl.attachShader(prog, compile(gl.VERTEX_SHADER, VERT));
      gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, FRAG));
      gl.linkProgram(prog);
      if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
      gl.useProgram(prog);
      const buf = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]), gl.STATIC_DRAW);
      const loc = gl.getAttribLocation(prog, 'p');
      gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
      ['u_time', 'u_ratio', 'u_res', 'u_c1', 'u_c2', 'u_c3'].forEach((n) => { U[n] = gl.getUniformLocation(prog, n); });
    } catch (e) {
      console.warn('backdrop: WebGL gradient disabled:', e);
      gl = null;
    }
  }

  function sizeGL() {
    if (!gl) return;
    const w = Math.max(1, Math.round(innerWidth * SCALE)), h = Math.max(1, Math.round(innerHeight * SCALE));
    if (gl$.width !== w || gl$.height !== h) { gl$.width = w; gl$.height = h; gl.viewport(0, 0, w, h); }
  }
  function drawGL() {
    if (!gl) return;
    const th = theme(), f = (c) => [c[0] / 255, c[1] / 255, c[2] / 255];
    gl.uniform1f(U.u_time, clock * SPEED + 3.1);
    gl.uniform1f(U.u_ratio, SCALE);
    gl.uniform2f(U.u_res, gl$.width, gl$.height);
    gl.uniform3fv(U.u_c1, f(th.c1)); gl.uniform3fv(U.u_c2, f(th.c2)); gl.uniform3fv(U.u_c3, f(th.c3));
    gl.drawArrays(gl.TRIANGLES, 0, 6);
  }
  function loopGL(now) {
    raf = 0;
    if (document.hidden || still()) return;
    if (now - last >= FRAME_MS) { clock += Math.min(0.1, (now - last) / 1000); last = now; drawGL(); }
    raf = requestAnimationFrame(loopGL);
  }
  function startGL() {
    if (!gl) return;
    sizeGL(); drawGL(); gl$.classList.add('on');
    if (!raf && !still() && !document.hidden) { last = performance.now(); raf = requestAnimationFrame(loopGL); }
  }

  /* ---------- kinetic grid (2D) ---------- */
  const CELL = 56, INFLUENCE = 260, MAX_WARP = 24, DOT = 28, LERP = 0.08;
  const g = grid$.getContext('2d');
  let W = 0, H = 0, dpr = 1, graf = 0;
  const mouse = { x: -9999, y: -9999 }, target = { x: -9999, y: -9999 };
  const ripples = [];

  function sizeGrid() {
    dpr = Math.min(2, devicePixelRatio || 1);
    W = innerWidth; H = innerHeight;
    grid$.width = Math.round(W * dpr); grid$.height = Math.round(H * dpr);
  }
  const lerp = (a, b, t) => a + (b - a) * t;
  const col = (a, b, t) => 'rgba(' + Math.round(lerp(a[0], b[0], t)) + ',' + Math.round(lerp(a[1], b[1], t)) + ',' + Math.round(lerp(a[2], b[2], t)) + ',' + lerp(a[3], b[3], t).toFixed(3) + ')';

  function warp(gx, gy, c, r, cols, rows, now) {
    // Pin the outer rows and columns so the edges never pull away from the window.
    const cp = Math.min(c / 1.5, (cols - 1 - c) / 1.5, 1), rp = Math.min(r / 1.5, (rows - 1 - r) / 1.5, 1);
    const pin = cp * cp * rp * rp;
    const dx = gx - mouse.x, dy = gy - mouse.y, dist = Math.hypot(dx, dy);
    const prox = Math.max(0, 1 - dist / INFLUENCE) * pin;
    let rx = 0, ry = 0;
    for (const rp2 of ripples) {
      const rdx = gx - rp2.x, rdy = gy - rp2.y, rd = Math.hypot(rdx, rdy), diff = rd - rp2.r;
      if (Math.abs(diff) < 55) {
        const s = (1 - Math.abs(diff) / 55) * rp2.o * 18 * pin, a = Math.atan2(rdy, rdx), sg = diff < 0 ? -1 : 1;
        rx -= Math.cos(a) * s * sg; ry -= Math.sin(a) * s * sg;
      }
    }
    if (dist < INFLUENCE && dist > 0 && pin > 0) {
      const t = dist / INFLUENCE, e = t < 0.01 ? 0 : (1 - t) * (1 - t) * Math.min(1, dist / 60), w = e * MAX_WARP * pin, a = Math.atan2(dy, dx);
      return [gx - Math.cos(a) * w + rx, gy - Math.sin(a) * w + ry, prox];
    }
    return [gx + rx, gy + ry, prox];
  }

  function drawGrid(now) {
    const th = theme();
    g.setTransform(dpr, 0, 0, dpr, 0, 0);
    g.clearRect(0, 0, W, H);
    g.fillStyle = th.dots;
    for (let x = DOT / 2; x < W; x += DOT) for (let y = DOT / 2; y < H; y += DOT) g.fillRect(x - 0.6, y - 0.6, 1.2, 1.2);

    for (let i = ripples.length - 1; i >= 0; i--) {
      const r = ripples[i], age = (now - r.t) / 1000;
      r.r = Math.max(0, age * 400); r.o = Math.max(0, 1 - age * 1.2);
      if (r.o <= 0) ripples.splice(i, 1);
    }
    const cols = Math.max(2, Math.ceil(W / CELL)) + 1, rows = Math.max(2, Math.ceil(H / CELL)) + 1;
    const cw = W / (cols - 1), ch = H / (rows - 1);
    const P = new Array(rows);
    for (let r = 0; r < rows; r++) { P[r] = new Array(cols); for (let c = 0; c < cols; c++) P[r][c] = warp(c * cw, r * ch, c, r, cols, rows, now); }

    const base = th.line, act = th.active;
    // Quiet lines in one batched path; only the lit ones get their own stroke.
    g.beginPath();
    const lit = [];
    const seg = (a, b) => {
      const p = (a[2] + b[2]) / 2;
      if (p < 0.01) { g.moveTo(a[0], a[1]); g.lineTo(b[0], b[1]); } else lit.push(a, b, p);
    };
    for (let r = 0; r < rows; r++) for (let c = 0; c < cols - 1; c++) seg(P[r][c], P[r][c + 1]);
    for (let c = 0; c < cols; c++) for (let r = 0; r < rows - 1; r++) seg(P[r][c], P[r + 1][c]);
    g.strokeStyle = col(base, base, 0); g.lineWidth = 0.8; g.stroke();
    for (let i = 0; i < lit.length; i += 3) {
      const a = lit[i], b = lit[i + 1], p = lit[i + 2], t = p * p * (3 - 2 * p);
      g.beginPath(); g.moveTo(a[0], a[1]); g.lineTo(b[0], b[1]);
      g.strokeStyle = col(base, act, t); g.lineWidth = lerp(0.8, 1.5, t); g.stroke();
    }
    for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
      const p = P[r][c], t = p[2] * p[2] * (3 - 2 * p[2]);
      if (t < 0.02) continue;
      const rad = lerp(1.6, 3.2, t);
      if (t > 0.3) {
        const gr = rad + lerp(0, 6, (t - 0.3) / 0.7), grd = g.createRadialGradient(p[0], p[1], rad * 0.5, p[0], p[1], gr);
        grd.addColorStop(0, 'rgba(' + act[0] + ',' + act[1] + ',' + act[2] + ',' + (t * 0.3).toFixed(3) + ')');
        grd.addColorStop(1, 'rgba(' + act[0] + ',' + act[1] + ',' + act[2] + ',0)');
        g.beginPath(); g.arc(p[0], p[1], gr, 0, Math.PI * 2); g.fillStyle = grd; g.fill();
      }
      g.beginPath(); g.arc(p[0], p[1], rad, 0, Math.PI * 2); g.fillStyle = col([act[0], act[1], act[2], 0.15], act, t); g.fill();
    }
    for (const r of ripples) {
      g.beginPath(); g.arc(r.x, r.y, r.r, 0, Math.PI * 2);
      g.strokeStyle = 'rgba(' + act[0] + ',' + act[1] + ',' + act[2] + ',' + (r.o * 0.3).toFixed(3) + ')'; g.lineWidth = 1.5; g.stroke();
    }
  }

  function loopGrid(now) {
    graf = 0;
    mouse.x = lerp(mouse.x, target.x, LERP); mouse.y = lerp(mouse.y, target.y, LERP);
    drawGrid(now);
    const settled = Math.abs(mouse.x - target.x) < 0.5 && Math.abs(mouse.y - target.y) < 0.5;
    if (!settled || ripples.length) graf = requestAnimationFrame(loopGrid);
  }
  const kickGrid = () => { if (!graf) graf = requestAnimationFrame(loopGrid); };

  addEventListener('pointermove', (e) => {
    if (e.pointerType !== 'mouse' || still()) return;
    if (mouse.x < -9000) { mouse.x = e.clientX; mouse.y = e.clientY; }
    target.x = e.clientX; target.y = e.clientY; kickGrid();
  }, { passive: true });
  document.addEventListener('pointerleave', () => { target.x = target.y = -9999; mouse.x = mouse.y = -9999; kickGrid(); });
  addEventListener('pointerdown', (e) => {
    if (still() || e.button !== 0) return;
    ripples.push({ x: e.clientX, y: e.clientY, r: 0, o: 1, t: performance.now() });
    if (ripples.length > 6) ripples.shift();
    kickGrid();
  }, { passive: true });

  /* ---------- lifecycle ---------- */
  function relayout() { sizeGrid(); sizeGL(); drawGrid(performance.now()); drawGL(); }
  let rt = 0;
  addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(relayout, 80); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) startGL(); });
  dmq.addEventListener('change', () => { drawGL(); drawGrid(performance.now()); });
  rmq.addEventListener('change', () => { syncBtn(); startGL(); });

  function syncBtn() {
    if (!motionBtn) return;
    motionBtn.setAttribute('aria-pressed', String(paused));
    motionBtn.title = paused ? 'Play the background animation' : 'Pause the background animation';
    motionBtn.hidden = rmq.matches;
  }
  if (motionBtn) motionBtn.addEventListener('click', () => {
    paused = !paused;
    try { localStorage.setItem('depscan.motion', paused ? 'off' : 'on'); } catch (e) { /* not saved; still applies now */ }
    syncBtn();
    if (paused) { target.x = target.y = mouse.x = mouse.y = -9999; ripples.length = 0; drawGrid(performance.now()); }
    startGL();
  });

  sizeGrid(); drawGrid(performance.now());
  syncBtn();
  startGL();
})();
