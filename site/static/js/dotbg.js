/* ============================================================
 * CKODEX-DS-3 · DotBg v3 — premium engineering canvas
 * "Evidence Editorial": paper is FLAT; the canvas is drafting
 * furniture in ink/tone. The semantic budget (rust / violet /
 * red) NEVER appears in a background.
 *
 * v3 raises the fidelity from a single flat dot grid to a
 * layered drafting surface:
 *   ① Solid base fill          theme ground
 *   ② Minor dot grid           whisper-fine, r 0.6, spacing 24
 *   ③ Major crosshair ticks    + marks every 4th node (96pt)
 *   ④ Corner accent clusters   graded lattice in TONE, fades in
 *   ⑤ Engineering L-brackets   precise corner registration
 *   ⑥ Tonal lift               barely-there top sheen (premium
 *                              depth, not a heavy vignette)
 *
 * Usage (vanilla):
 *   el.innerHTML = CkDotBg({ w: 320, h: 200, theme: 'ledger' });
 * Usage (React):
 *   <div dangerouslySetInnerHTML={{__html: CkDotBg({w,h,theme})}} />
 *
 * themes: 'ledger' (default) · 'vault' · 'hc'
 * Back-compat aliases: light → ledger, dark → vault.
 * `accent` overrides the furniture color — structural use only;
 * never pass rust/violet/red (the budget is for assertions).
 * forced-colors: wrap in an element that maps fills to ButtonText.
 * ============================================================ */
(function (root) {
  const THEMES = {
    /* dotOp = minor grid · crossOp = major crosshair · furOp scales clusters
       liftOp = premium top sheen (0 = flat). HC keeps full ink, no sheen. */
    ledger: {
      base: '#F6F1E8', dot: '#211B14', dotOp: 0.07,
      cross: '#211B14', crossOp: 0.16,
      fur: '#6E6457', brkOp: 0.38, furScale: 0.7,
      lift: '#FFFFFF', liftOp: 0.05, vig: false, vigCol: '#211B14', vigOp: 0,
    },
    vault: {
      base: '#0A1322', dot: '#EAE5DA', dotOp: 0.08,
      cross: '#EAE5DA', crossOp: 0.18,
      fur: '#9A9284', brkOp: 0.34, furScale: 0.7,
      lift: '#22304A', liftOp: 0.22, vig: true, vigCol: '#02060E', vigOp: 0.34,
    },
    hc: {
      base: '#000000', dot: '#FFFFFF', dotOp: 0.45,
      cross: '#FFFFFF', crossOp: 0.85,
      fur: '#FFFFFF', brkOp: 1.00, furScale: 1.0,
      lift: '#000000', liftOp: 0, vig: false, vigCol: '#000000', vigOp: 0,
    },
  };
  const ALIAS = { light: 'ledger', dark: 'vault' };

  function CkDotBg(opts) {
    opts = opts || {};
    const w = opts.w || 320;
    const h = opts.h || 200;
    const key = ALIAS[opts.theme] || opts.theme;
    const t = THEMES[key] || THEMES.ledger;
    const fur = opts.accent || t.fur;            /* furniture color — structural only */
    const S = 24;                                /* minor dot spacing (pt) */
    const MAJ = S * 4;                           /* major crosshair spacing (96pt) */
    const R = 0.6;                               /* minor dot radius — finer than v2 */
    const isHc = key === 'hc';
    const uid = 'dbg' + Math.random().toString(36).slice(2, 8);

    /* ③ major crosshair ticks — a precise + at every 4th node.
          Built as a second <pattern> so it tiles crisply at any size. */
    const ca = 2.4;                              /* crosshair arm length */
    const cw = isHc ? 1.0 : 0.75;                /* crosshair stroke width */
    const cc = MAJ / 2;
    const crosshair =
      `<path d="M ${cc - ca} ${cc} H ${cc + ca} M ${cc} ${cc - ca} V ${cc + ca}" ` +
      `stroke="${t.cross}" stroke-width="${cw}" opacity="${t.crossOp}" ` +
      `stroke-linecap="square" fill="none"/>`;

    /* ④ corner clusters — 4×4 lattice anchored at each corner,
          graded radius + opacity, decays toward the interior. */
    const N = 4;
    const corners = [
      { x: S * 0.5,     y: S * 0.5,     dx:  1, dy:  1 },
      { x: w - S * 0.5, y: S * 0.5,     dx: -1, dy:  1 },
      { x: S * 0.5,     y: h - S * 0.5, dx:  1, dy: -1 },
      { x: w - S * 0.5, y: h - S * 0.5, dx: -1, dy: -1 },
    ];
    let clusters = '';
    corners.forEach(c => {
      for (let i = 0; i < N; i++) {
        for (let j = 0; j < N; j++) {
          const dist = Math.sqrt(i * i + j * j);
          const r = 1.5 - dist * 0.28;
          const op = 0.72 - dist * 0.18;
          if (r <= 0.2 || op <= 0.04) continue;
          const cx = c.x + c.dx * i * S;
          const cy = c.y + c.dy * j * S;
          clusters += `<circle cx="${cx.toFixed(1)}" cy="${cy.toFixed(1)}" r="${r.toFixed(2)}" fill="${fur}" opacity="${(op * t.furScale).toFixed(3)}"/>`;
        }
      }
    });

    /* ⑤ engineering L-brackets — corner registration, inset 14pt */
    const ins = 14, arm = 8, bw = isHc ? 1.5 : 1.1;
    const brk = (x, y, sx, sy) =>
      `<path d="M ${x} ${y + sy * arm} V ${y} H ${x + sx * arm}" fill="none" stroke="${fur}" stroke-width="${bw}" opacity="${t.brkOp}" stroke-linecap="square"/>`;
    const brackets =
      brk(ins, ins, 1, 1) +
      brk(w - ins, ins, -1, 1) +
      brk(ins, h - ins, 1, -1) +
      brk(w - ins, h - ins, -1, -1);

    /* ⑥ premium tonal lift — a soft sheen from the top, gives the
          surface depth without a heavy gallery vignette. */
    const lift = t.liftOp > 0
      ? `<linearGradient id="${uid}-lift" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${t.lift}" stop-opacity="${t.liftOp}"/>
      <stop offset="42%" stop-color="${t.lift}" stop-opacity="0"/>
    </linearGradient>`
      : '';
    const liftRect = t.liftOp > 0 ? `<rect width="${w}" height="${h}" fill="url(#${uid}-lift)"/>` : '';

    /* vignette — Vault only; paper and HC stay flat */
    const vig = t.vig
      ? `<radialGradient id="${uid}-vig" cx="50%" cy="46%" r="74%">
      <stop offset="52%" stop-color="${t.vigCol}" stop-opacity="0"/>
      <stop offset="100%" stop-color="${t.vigCol}" stop-opacity="${t.vigOp}"/>
    </radialGradient>`
      : '';
    const vigRect = t.vig ? `<rect width="${w}" height="${h}" fill="url(#${uid}-vig)"/>` : '';

    return `
<svg class="ck-dotbg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="none" aria-hidden="true">
  <defs>
    <pattern id="${uid}-dots" width="${S}" height="${S}" patternUnits="userSpaceOnUse">
      <circle class="ck-dotbg__dot" cx="${S / 2}" cy="${S / 2}" r="${R}" fill="${t.dot}" opacity="${t.dotOp}"/>
    </pattern>
    <pattern id="${uid}-cross" width="${MAJ}" height="${MAJ}" patternUnits="userSpaceOnUse">
      ${crosshair}
    </pattern>
    ${lift}
    ${vig}
  </defs>
  <rect width="${w}" height="${h}" fill="${t.base}"/>
  <rect width="${w}" height="${h}" fill="url(#${uid}-dots)"/>
  <rect width="${w}" height="${h}" fill="url(#${uid}-cross)"/>
  ${clusters}
  ${liftRect}
  ${vigRect}
  ${brackets}
</svg>`.trim();
  }

  root.CkDotBg = CkDotBg;
})(typeof window !== 'undefined' ? window : this);
