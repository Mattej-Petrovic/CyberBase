/* attack-flow-vis.js — Network visualization for Attack Flow detail pages
 * Reads _AF = { phases, slug, labels } injected by Jinja before this script.
 * Registers window.attackFlow() as an Alpine.js component.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Topology definitions — one per attack slug
// Each node: { id, ic, label, x, y }
// Each edge: { id, from, to }
// pm (phaseMap): array aligned to phase order; each entry { n:[nodeIds], e:[edgeIds] }
// ─────────────────────────────────────────────────────────────────────────────
const AF_TOPOLOGIES = {
  'phishing': {
    nodes: [
      { id:'atk',  ic:'laptop',   label:'Attacker',    x:80,  y:200 },
      { id:'mail', ic:'envelope', label:'Mail Server', x:290, y:100 },
      { id:'inet', ic:'cloud',    label:'Internet',    x:510, y:200 },
      { id:'usr',  ic:'person',   label:'Victim',      x:730, y:200 },
      { id:'fake', ic:'browser',  label:'Fake Login',  x:730, y:330 },
      { id:'c2',   ic:'server',   label:'C2 Server',   x:940, y:200 },
    ],
    edges:[
      {id:'e1',from:'atk', to:'mail'},
      {id:'e2',from:'mail',to:'inet'},
      {id:'e3',from:'inet',to:'usr'},
      {id:'e4',from:'usr', to:'fake'},
      {id:'e5',from:'fake',to:'c2'},
    ],
    pm:[
      {n:['atk'],              e:[]},
      {n:['atk','mail'],       e:['e1']},
      {n:['mail','inet','usr'],e:['e2','e3']},
      {n:['usr','fake'],       e:['e4']},
      {n:['fake','c2'],        e:['e5']},
      {n:['c2','atk'],         e:['e5']},
    ]
  },

  'brute-force': {
    nodes: [
      { id:'atk',  ic:'laptop',   label:'Attacker',     x:80,  y:200 },
      { id:'lst',  ic:'database', label:'Wordlist',     x:80,  y:340 },
      { id:'lgn',  ic:'browser',  label:'Login Portal', x:380, y:200 },
      { id:'auth', ic:'server',   label:'Auth Server',  x:650, y:100 },
      { id:'db',   ic:'database', label:'Database',     x:900, y:200 },
    ],
    edges:[
      {id:'e1',from:'lst', to:'atk'},
      {id:'e2',from:'atk', to:'lgn'},
      {id:'e3',from:'lgn', to:'auth'},
      {id:'e4',from:'auth',to:'db'},
    ],
    pm:[
      {n:['atk','lgn'],  e:['e2']},
      {n:['atk','lst'],  e:['e1']},
      {n:['atk','lgn'],  e:['e2']},
      {n:['lgn','auth'], e:['e3']},
      {n:['auth','db'],  e:['e4']},
    ]
  },

  'sql-injection': {
    nodes: [
      { id:'atk', ic:'laptop',   label:'Attacker',   x:80,  y:200 },
      { id:'web', ic:'browser',  label:'Web App',    x:320, y:200 },
      { id:'srv', ic:'server',   label:'Web Server', x:580, y:100 },
      { id:'app', ic:'gear',     label:'Backend',    x:580, y:320 },
      { id:'db',  ic:'database', label:'Database',   x:860, y:200 },
    ],
    edges:[
      {id:'e1',from:'atk',to:'web'},
      {id:'e2',from:'web',to:'srv'},
      {id:'e3',from:'web',to:'app'},
      {id:'e4',from:'srv',to:'db'},
      {id:'e5',from:'app',to:'db'},
    ],
    pm:[
      {n:['atk','web'],       e:['e1']},
      {n:['web','srv','app'], e:['e2','e3']},
      {n:['atk','web'],       e:['e1']},
      {n:['app','db'],        e:['e5']},
      {n:['srv','db'],        e:['e4']},
      {n:['db'],              e:['e4','e5']},
    ]
  },

  'man-in-the-middle': {
    nodes: [
      { id:'vic', ic:'person', label:'Victim',         x:100, y:200 },
      { id:'rtr', ic:'router', label:'Router / AP',    x:360, y:330 },
      { id:'atk', ic:'laptop', label:'Attacker (MitM)',x:560, y:200 },
      { id:'srv', ic:'server', label:'Target Server',  x:880, y:200 },
    ],
    edges:[
      {id:'e1',from:'vic',to:'rtr'},
      {id:'e2',from:'rtr',to:'atk'},
      {id:'e3',from:'atk',to:'srv'},
      {id:'e4',from:'vic',to:'atk'},
    ],
    pm:[
      {n:['atk','rtr'],  e:['e1','e2']},
      {n:['vic','rtr'],  e:['e1']},
      {n:['atk','srv'],  e:['e3']},
      {n:['vic','atk'],  e:['e4']},
      {n:['atk','srv'],  e:['e3']},
      {n:['atk'],        e:[]},
    ]
  },

  'ransomware': {
    nodes: [
      { id:'atk', ic:'laptop',   label:'Attacker',    x:70,  y:200 },
      { id:'vic', ic:'person',   label:'Victim PC',   x:270, y:200 },
      { id:'c2',  ic:'server',   label:'C2 Server',   x:490, y:90  },
      { id:'fs',  ic:'database', label:'File Server', x:700, y:200 },
      { id:'dc',  ic:'shield',   label:'Domain Ctrl', x:900, y:100 },
      { id:'enc', ic:'server',   label:'Encrypted',   x:900, y:320 },
    ],
    edges:[
      {id:'e1',from:'atk',to:'vic'},
      {id:'e2',from:'vic',to:'c2'},
      {id:'e3',from:'c2', to:'dc'},
      {id:'e4',from:'vic',to:'fs'},
      {id:'e5',from:'fs', to:'enc'},
      {id:'e6',from:'dc', to:'enc'},
    ],
    pm:[
      {n:['atk','vic'],     e:['e1']},
      {n:['vic','c2'],      e:['e2']},
      {n:['c2','dc'],       e:['e3']},
      {n:['vic'],           e:[]},
      {n:['vic','fs'],      e:['e4']},
      {n:['fs'],            e:['e4']},
      {n:['fs','enc','dc'], e:['e5','e6']},
    ]
  },

  'lateral-movement': {
    nodes: [
      { id:'atk', ic:'laptop',   label:'Attacker',    x:70,  y:200 },
      { id:'h1',  ic:'person',   label:'Foothold PC', x:270, y:200 },
      { id:'ad',  ic:'server',   label:'AD Server',   x:490, y:100 },
      { id:'dc',  ic:'shield',   label:'Domain Ctrl', x:720, y:80  },
      { id:'h2',  ic:'monitor',  label:'Workstation', x:490, y:330 },
      { id:'fs',  ic:'database', label:'File Server', x:900, y:210 },
    ],
    edges:[
      {id:'e1',from:'atk',to:'h1'},
      {id:'e2',from:'h1', to:'ad'},
      {id:'e3',from:'ad', to:'dc'},
      {id:'e4',from:'h1', to:'h2'},
      {id:'e5',from:'dc', to:'fs'},
      {id:'e6',from:'h2', to:'fs'},
    ],
    pm:[
      {n:['atk','h1'], e:['e1']},
      {n:['h1','ad'],  e:['e2']},
      {n:['h1','ad'],  e:['e2']},
      {n:['h1','h2'],  e:['e4']},
      {n:['ad','dc'],  e:['e3']},
      {n:['dc','fs'],  e:['e5']},
    ]
  },

  'supply-chain-attack': {
    nodes: [
      { id:'atk', ic:'laptop', label:'Attacker',       x:70,  y:200 },
      { id:'ci',  ic:'gear',   label:'CI/CD Pipeline', x:300, y:200 },
      { id:'pkg', ic:'box',    label:'Pkg Registry',   x:560, y:200 },
      { id:'oa',  ic:'server', label:'Org A',          x:820, y:80  },
      { id:'ob',  ic:'server', label:'Org B',          x:820, y:210 },
      { id:'oc',  ic:'server', label:'Org C',          x:820, y:340 },
    ],
    edges:[
      {id:'e1',from:'atk',to:'ci'},
      {id:'e2',from:'ci', to:'pkg'},
      {id:'e3',from:'pkg',to:'oa'},
      {id:'e4',from:'pkg',to:'ob'},
      {id:'e5',from:'pkg',to:'oc'},
    ],
    pm:[
      {n:['atk'],                e:[]},
      {n:['atk','ci'],           e:['e1']},
      {n:['ci','pkg'],           e:['e2']},
      {n:['pkg','oa','ob','oc'], e:['e3','e4','e5']},
      {n:['oa','ob','oc'],       e:['e3','e4','e5']},
    ]
  },
};


// ─────────────────────────────────────────────────────────────────────────────
// AFRenderer — SVG drawing engine
// ─────────────────────────────────────────────────────────────────────────────
class AFRenderer {
  constructor(svgId = 'af-diagram') {
    this.svg      = document.getElementById(svgId);
    this.egGroup  = document.getElementById('af-g-edges');
    this.ngGroup  = document.getElementById('af-g-nodes');
    this.ogGroup  = document.getElementById('af-g-overlays');
    this.NS       = 'http://www.w3.org/2000/svg';
    this.R        = 30;

    // Tooltip element (shared, repositioned on hover)
    this._tooltip = this._buildTooltip();
    this._scanAnim = null;
  }

  // ── public: redraw everything ────────────────────────────────────────────
  render(topo, phaseIndex, perspective) {
    if (!topo || !this.egGroup) return;

    const pm      = topo.pm[Math.min(phaseIndex, topo.pm.length - 1)] || {n:[],e:[]};
    const actN    = new Set(pm.n);
    const actE    = new Set(pm.e);
    const colors  = this._colors(perspective);
    const nmap    = Object.fromEntries(topo.nodes.map(n => [n.id, n]));

    this._drawEdges(topo, actE, nmap, colors);
    this._drawNodes(topo, actN, nmap, colors);
    this._drawOverlays(perspective, actN, nmap, colors);
  }

  // ── private: color palette per perspective ───────────────────────────────
  _colors(perspective) {
    if (perspective === 'attacker') return {
      accent:  '#ef4444',
      accentBg:'rgba(239,68,68,.09)',
      glow:    'glow-r',
      arr:     'arr-r',
    };
    if (perspective === 'defender') return {
      accent:  '#3b82f6',
      accentBg:'rgba(59,130,246,.09)',
      glow:    'glow-b',
      arr:     'arr-b',
    };
    return {
      accent:  '#f59e0b',
      accentBg:'rgba(245,158,11,.08)',
      glow:    'glow-a',
      arr:     'arr-a',
    };
  }

  // ── private: edges ───────────────────────────────────────────────────────
  _drawEdges(topo, actE, nmap, colors) {
    this.egGroup.innerHTML = '';
    const R   = this.R;
    const NS  = this.NS;

    // Remove stale edge gradients so perspective color change takes effect
    if (this.svg) {
      const defs = this.svg.querySelector('defs');
      if (defs) {
        defs.querySelectorAll('[id^="eg-"]').forEach(el => el.remove());
      }
    }

    topo.edges.forEach(ed => {
      const a = nmap[ed.from], b = nmap[ed.to];
      if (!a || !b) return;
      const isAct = actE.has(ed.id);

      // Direction vector, padded away from node circles
      const dx = b.x - a.x, dy = b.y - a.y;
      const len = Math.sqrt(dx*dx + dy*dy) || 1;
      const pad = R + 5;
      const x1 = a.x + dx/len*pad, y1 = a.y + dy/len*pad;
      const x2 = b.x - dx/len*pad, y2 = b.y - dy/len*pad;

      const g = document.createElementNS(NS, 'g');

      if (isAct) {
        // Soft glow halo
        const halo = document.createElementNS(NS, 'line');
        this._setAttrs(halo, {x1,y1,x2,y2,
          stroke:colors.accent, 'stroke-width':'7',
          'stroke-opacity':'.15', 'stroke-linecap':'round'
        });
        g.appendChild(halo);

        // Gradient defs per edge (unique id)
        this._ensureEdgeGradient(ed.id, x1,y1,x2,y2, colors.accent);
      }

      // Main line — gradient stroke when active, flat dim when idle
      const line = document.createElementNS(NS, 'line');
      this._setAttrs(line, {x1,y1,x2,y2,
        stroke: isAct ? `url(#eg-${ed.id})` : '#1a2e48',
        'stroke-width': isAct ? '2.5' : '1.5',
        'stroke-linecap': 'round',
        'marker-end': `url(#${isAct ? colors.arr : 'arr-idle'})`,
      });
      if (isAct) {
        line.setAttribute('stroke-dasharray', '10 6');
        line.classList.add('af-edge-active');
      }
      g.appendChild(line);

      // Traveling packets — two staggered dots per active edge
      if (isAct) {
        [0, 0.5].forEach(delay => {
          const dot = document.createElementNS(NS, 'circle');
          const dur  = (1.4 + Math.random() * 0.4).toFixed(2) + 's';
          const beg  = delay > 0 ? `-${(parseFloat(dur) * delay).toFixed(2)}s` : '0s';
          dot.setAttribute('r', '4');
          dot.setAttribute('fill', colors.accent);
          dot.setAttribute('cx', String(x1));
          dot.setAttribute('cy', String(y1));

          const animX = this._smil('cx', `${x1};${x2}`, dur, beg);
          const animY = this._smil('cy', `${y1};${y2}`, dur, beg);
          const animO = document.createElementNS(NS, 'animate');
          this._setAttrs(animO, {
            attributeName:'opacity', values:'0;1;1;0',
            keyTimes:'0;.08;.88;1', dur, begin:beg, repeatCount:'indefinite'
          });

          dot.append(animX, animY, animO);
          g.appendChild(dot);
        });
      }

      this.egGroup.appendChild(g);
    });
  }

  // ── private: nodes ───────────────────────────────────────────────────────
  _drawNodes(topo, actN, nmap, colors) {
    this.ngGroup.innerHTML = '';
    const allActive = actN.size > 0;
    const R  = this.R;
    const NS = this.NS;

    topo.nodes.forEach(node => {
      const isAct = actN.has(node.id);
      const isDim = allActive && !isAct;

      const g = document.createElementNS(NS, 'g');
      g.setAttribute('transform', `translate(${node.x},${node.y})`);
      g.style.opacity    = isDim ? '0.14' : '1';
      g.style.transition = 'opacity .4s';

      // Breathing glow ring on active nodes
      if (isAct) {
        const ring = document.createElementNS(NS, 'circle');
        this._setAttrs(ring, {r:'40', fill:colors.accentBg,
          stroke:colors.accent, 'stroke-width':'1.5', 'stroke-opacity':'.5',
          filter:`url(#${colors.glow})`
        });
        ring.classList.add('af-ring-active');
        g.appendChild(ring);
      }

      // Node background circle
      const bg = document.createElementNS(NS, 'circle');
      this._setAttrs(bg, {
        r: String(R),
        fill:   isAct ? colors.accentBg : '#0d1b2e',
        stroke: isAct ? colors.accent   : '#1e3a52',
        'stroke-width': '2',
      });
      bg.style.transition = 'fill .4s, stroke .4s';
      g.appendChild(bg);

      // Icon via <use> + currentColor
      const sz = 20;
      const ic = document.createElementNS(NS, 'use');
      this._setAttrs(ic, {
        href: `#ic-${node.ic}`,
        x: String(-sz/2), y: String(-sz/2 - 3),
        width: String(sz), height: String(sz),
      });
      ic.style.color      = isAct ? colors.accent : '#2d4a6a';
      ic.style.transition = 'color .4s';
      g.appendChild(ic);

      // Label text below node
      const txt = document.createElementNS(NS, 'text');
      this._setAttrs(txt, {
        y: String(R + 15), 'text-anchor':'middle',
        'font-size':'11', 'font-family':'ui-monospace,monospace',
        fill: isAct ? '#cbd5e1' : '#334e6a',
      });
      txt.style.transition = 'fill .4s';
      txt.textContent = node.label;
      g.appendChild(txt);

      // Hover interaction
      g.style.cursor = 'default';
      g.addEventListener('mouseenter', e => this._showTooltip(e, node, isAct, colors));
      g.addEventListener('mouseleave', () => this._hideTooltip());

      this.ngGroup.appendChild(g);
    });
  }

  // ── private: overlays ────────────────────────────────────────────────────
  _drawOverlays(perspective, actN, nmap, colors) {
    this.ogGroup.innerHTML = '';
    this._stopScanBeam();

    if (perspective === 'defender' && actN.size > 0) {
      // Alert badge on first active node
      const firstId = [...actN][0];
      const node    = nmap[firstId];
      if (node) {
        const g = document.createElementNS(this.NS, 'g');
        g.setAttribute('transform', `translate(${node.x + this.R - 2},${node.y - this.R + 2})`);
        g.classList.add('af-alert-badge');

        const c = document.createElementNS(this.NS, 'circle');
        this._setAttrs(c, {r:'9', fill:'#ef4444', stroke:'#060d18', 'stroke-width':'2'});

        const t = document.createElementNS(this.NS, 'text');
        this._setAttrs(t, {'text-anchor':'middle', dy:'4', 'font-size':'10',
          'font-weight':'bold', fill:'white', 'font-family':'sans-serif'});
        t.textContent = '!';

        g.append(c, t);
        this.ogGroup.appendChild(g);
      }

      // Defender scan beam — horizontal sweep line across SVG
      this._startScanBeam(colors.accent);
    }

    if (perspective === 'victim' && actN.size > 0) {
      // Victim view: amber vignette overlay around edges of SVG
      const rect = document.createElementNS(this.NS, 'rect');
      const svgW = this.svg ? (this.svg.viewBox.baseVal.width || 1000) : 1000;
      const svgH = this.svg ? (this.svg.viewBox.baseVal.height || 400)  : 400;
      this._setAttrs(rect, {
        x:'0', y:'0', width: String(svgW), height: String(svgH),
        fill:'url(#victim-vignette)', opacity:'0.55',
        style:'pointer-events:none',
      });
      this._ensureVignetteGradient(svgW, svgH);
      this.ogGroup.appendChild(rect);
    }
  }

  // ── private: defender scan beam ─────────────────────────────────────────
  _startScanBeam(accentColor) {
    const svg = this.svg;
    if (!svg) return;
    const svgH = svg.viewBox.baseVal.height || 400;
    const svgW = svg.viewBox.baseVal.width  || 1000;

    const beam = document.createElementNS(this.NS, 'rect');
    beam.id = 'af-scan-beam';
    this._setAttrs(beam, {
      x:'0', y:'-20', width: String(svgW), height:'20',
      fill: accentColor, opacity:'0.07',
      style:'pointer-events:none',
    });

    const animY = document.createElementNS(this.NS, 'animate');
    this._setAttrs(animY, {
      attributeName:'y', from:'-20', to: String(svgH),
      dur:'2.8s', repeatCount:'indefinite', calcMode:'linear',
    });
    beam.appendChild(animY);
    this.ogGroup.appendChild(beam);
  }

  _stopScanBeam() {
    const old = document.getElementById('af-scan-beam');
    if (old) old.remove();
  }

  // ── private: tooltip ────────────────────────────────────────────────────
  _buildTooltip() {
    let tip = document.getElementById('af-tooltip');
    if (!tip) {
      tip = document.createElement('div');
      tip.id = 'af-tooltip';
      tip.style.cssText = [
        'position:fixed','z-index:9999','pointer-events:none',
        'background:#0d1b2e','border:1px solid rgba(255,255,255,.12)',
        'border-radius:10px','padding:8px 12px',
        'font-size:12px','color:#cbd5e1','line-height:1.5',
        'box-shadow:0 8px 24px rgba(0,0,0,.6)',
        'opacity:0','transition:opacity .15s',
        'max-width:180px',
      ].join(';');
      document.body.appendChild(tip);
    }
    return tip;
  }

  _showTooltip(e, node, isActive, colors) {
    const tip = this._tooltip;
    const activeText = isActive
      ? `<span style="color:${colors.accent};font-weight:600">● Active</span><br>`
      : `<span style="color:#334e6a">○ Idle</span><br>`;
    tip.innerHTML = `<div style="font-weight:600;color:#f1f5f9;margin-bottom:2px">${node.label}</div>${activeText}<span style="color:#64748b;font-size:11px">${node.ic}</span>`;
    tip.style.opacity = '1';
    this._moveTooltip(e);
    document.addEventListener('mousemove', this._boundMove = ev => this._moveTooltip(ev), {passive:true});
  }

  _moveTooltip(e) {
    const tip = this._tooltip;
    const x = e.clientX + 14, y = e.clientY - 10;
    const right = window.innerWidth  - x - 200;
    const below = window.innerHeight - y - 80;
    tip.style.left = (right < 0 ? e.clientX - 200 : x) + 'px';
    tip.style.top  = (below < 0 ? e.clientY - 80  : y) + 'px';
  }

  _hideTooltip() {
    this._tooltip.style.opacity = '0';
    if (this._boundMove) {
      document.removeEventListener('mousemove', this._boundMove);
      this._boundMove = null;
    }
  }

  // ── private: per-edge gradient (linearGradient in SVG defs) ─────────────
  _ensureEdgeGradient(edgeId, x1, y1, x2, y2, color) {
    const NS  = this.NS;
    const svg = this.svg;
    if (!svg) return;

    let defs = svg.querySelector('defs');
    if (!defs) { defs = document.createElementNS(NS, 'defs'); svg.prepend(defs); }

    const gid = `eg-${edgeId}`;
    const grad = document.createElementNS(NS, 'linearGradient');
    grad.id = gid;
    grad.setAttribute('gradientUnits', 'userSpaceOnUse');
    grad.setAttribute('x1', String(x1)); grad.setAttribute('y1', String(y1));
    grad.setAttribute('x2', String(x2)); grad.setAttribute('y2', String(y2));

    const s1 = document.createElementNS(NS, 'stop');
    s1.setAttribute('offset', '0%');
    s1.setAttribute('stop-color', color);
    s1.setAttribute('stop-opacity', '0.3');

    const s2 = document.createElementNS(NS, 'stop');
    s2.setAttribute('offset', '100%');
    s2.setAttribute('stop-color', color);
    s2.setAttribute('stop-opacity', '1');

    grad.append(s1, s2);
    defs.appendChild(grad);
  }

  // ── private: victim vignette radialGradient ──────────────────────────────
  _ensureVignetteGradient(w, h) {
    const NS  = this.NS;
    const svg = this.svg;
    if (!svg) return;

    const gid = 'victim-vignette';
    let defs = svg.querySelector('defs');
    if (!defs) { defs = document.createElementNS(NS, 'defs'); svg.prepend(defs); }
    if (defs.querySelector(`#${gid}`)) return;

    const grad = document.createElementNS(NS, 'radialGradient');
    grad.id = gid;
    grad.setAttribute('cx', '50%'); grad.setAttribute('cy', '50%');
    grad.setAttribute('r',  '50%');
    grad.setAttribute('gradientUnits', 'userSpaceOnUse');
    grad.setAttribute('fx', String(w * 0.5)); grad.setAttribute('fy', String(h * 0.5));

    const s1 = document.createElementNS(NS, 'stop');
    s1.setAttribute('offset', '40%');
    s1.setAttribute('stop-color', '#f59e0b');
    s1.setAttribute('stop-opacity', '0');

    const s2 = document.createElementNS(NS, 'stop');
    s2.setAttribute('offset', '100%');
    s2.setAttribute('stop-color', '#f59e0b');
    s2.setAttribute('stop-opacity', '0.18');

    grad.append(s1, s2);
    defs.appendChild(grad);
  }

  // ── private: helpers ─────────────────────────────────────────────────────
  _setAttrs(el, attrs) {
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  }

  _smil(attrName, values, dur, begin) {
    const anim = document.createElementNS(this.NS, 'animate');
    this._setAttrs(anim, {
      attributeName: attrName, values, dur,
      begin: begin || '0s',
      repeatCount: 'indefinite',
      calcMode: 'spline',
      keySplines: '.4 0 .6 1',
      keyTimes: '0;1',
    });
    return anim;
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Alpine.js component factory — registered as window.attackFlow
// ─────────────────────────────────────────────────────────────────────────────
window.attackFlow = function attackFlow() {
  return {
    perspective:  'attacker',
    currentPhase: 0,
    phases:       (_AF || {}).phases || [],
    topo:         AF_TOPOLOGIES[(_AF || {}).slug] || AF_TOPOLOGIES['phishing'],
    _renderer:    null,

    tabs: [
      { id:'attacker', label: (_AF.labels || {}).attacker || 'Attacker', icon:'M13 10V3L4 14h7v7l9-11h-7z' },
      { id:'defender', label: (_AF.labels || {}).defender || 'Defender', icon:'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
      { id:'victim',   label: (_AF.labels || {}).victim   || 'Victim',   icon:'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
    ],

    get currentData() {
      const ph = this.phases[this.currentPhase];
      return ph ? ph[this.perspective] : null;
    },
    get accentColor() {
      return this.perspective === 'attacker' ? '#ef4444'
           : this.perspective === 'defender' ? '#3b82f6' : '#f59e0b';
    },
    get accentDim() {
      return this.perspective === 'attacker' ? 'rgba(239,68,68,.08)'
           : this.perspective === 'defender' ? 'rgba(59,130,246,.08)' : 'rgba(245,158,11,.07)';
    },

    setPerspective(p) { this.perspective = p; this._refresh(); },
    setPhase(i)       { this.currentPhase = i; this._refresh(); },
    nextPhase() {
      if (this.currentPhase < this.phases.length - 1) { this.currentPhase++; this._refresh(); }
    },
    prevPhase() {
      if (this.currentPhase > 0) { this.currentPhase--; this._refresh(); }
    },

    _refresh() {
      this.$nextTick(() => {
        this._renderDiagram();
        this._animateNarrative();
      });
    },

    _animateNarrative() {
      const el = document.getElementById('af-narrative');
      if (!el) return;
      el.style.animation = 'none';
      void el.offsetHeight;
      el.style.animation = 'narrativeIn .28s ease forwards';
    },

    init() {
      this.$nextTick(() => {
        this._renderer = new AFRenderer('af-diagram');
        this._renderDiagram();
      });
    },

    _renderDiagram() {
      if (!this._renderer) return;
      this._renderer.render(this.topo, this.currentPhase, this.perspective);
    },
  };
};
