/* attack-flow-vis.js — Network visualization for Attack Flow detail pages
 * Reads _AF = { phases, slug, labels } injected by Jinja before this script.
 * Registers window.attackFlow() as an Alpine.js component.
 *
 * Topology schema per attack slug:
 *   nodes: { base: [{id,type,label,sublabel,x,y}], defender: [...] }
 *   edges: [{id,from,to,label,defenderOnly?}]
 *   phases: [{attacker:{activeNodes[],activeEdges[],tools[]},
 *             defender:{activeNodes[],activeEdges[],detectionNodes[]},
 *             victim:  {activeNodes[],activeEdges[],compromisedNodes[],unaware}}]
 */

// ─────────────────────────────────────────────────────────────────────────────
// Icon map: node type → symbol id
// ─────────────────────────────────────────────────────────────────────────────
const AF_ICONS = {
  attacker:    'ic-laptop',
  server:      'ic-server',
  cloud:       'ic-cloud',
  victim:      'ic-person',
  firewall:    'ic-firewall',
  siem:        'ic-siem',
  edr:         'ic-edr',
  database:    'ic-database',
  c2:          'ic-c2',
  router:      'ic-router',
  workstation: 'ic-monitor',
  registry:    'ic-box',
  browser:     'ic-browser',
  envelope:    'ic-envelope',
};

// ─────────────────────────────────────────────────────────────────────────────
// Topology definitions — populated below
// ─────────────────────────────────────────────────────────────────────────────
const AF_TOPOLOGIES = {};

// ─────────────────────────────────────────────────────────────────────────────
// AFRenderer — SVG drawing engine
// ─────────────────────────────────────────────────────────────────────────────
class AFRenderer {
  constructor(svgId = 'af-diagram') {
    this.svg     = document.getElementById(svgId);
    this.egGroup = document.getElementById('af-g-edges');
    this.ngGroup = document.getElementById('af-g-nodes');
    this.ogGroup = document.getElementById('af-g-overlays');
    this.NS      = 'http://www.w3.org/2000/svg';
    this._tooltip = this._buildTooltip();
  }

  // ── public ────────────────────────────────────────────────────────────────
  render(topo, phaseIndex, perspective) {
    if (!topo || !this.egGroup) return;

    const colors = this._colors(perspective);
    const nodes  = this._resolveNodes(topo, perspective);
    const edges  = this._resolveEdges(topo, perspective);
    const state  = this._getPhaseState(topo, phaseIndex, perspective);
    const nmap   = Object.fromEntries(nodes.map(n => [n.id, n]));

    this._drawEdges(edges, state, nmap, colors);
    this._drawNodes(nodes, state, perspective, colors);
    this._drawOverlays(state, perspective, colors, nmap);
  }

  // ── node/edge resolution ──────────────────────────────────────────────────
  _resolveNodes(topo, perspective) {
    const base = topo.nodes.base || [];
    if (perspective === 'defender') {
      return [...base, ...(topo.nodes.defender || [])];
    }
    return base;
  }

  _resolveEdges(topo, perspective) {
    return (topo.edges || []).filter(e =>
      perspective === 'defender' ? true : !e.defenderOnly
    );
  }

  _getPhaseState(topo, phaseIndex, perspective) {
    const idx = Math.min(phaseIndex, topo.phases.length - 1);
    const ph  = topo.phases[idx];
    if (!ph) return { activeNodes: new Set(), activeEdges: new Set(), detectionNodes: new Set(), compromisedNodes: new Set(), unaware: false, tools: [] };
    const pv  = ph[perspective] || {};
    return {
      activeNodes:     new Set(pv.activeNodes    || []),
      activeEdges:     new Set(pv.activeEdges    || []),
      detectionNodes:  new Set(pv.detectionNodes || []),
      compromisedNodes:new Set(pv.compromisedNodes || []),
      unaware: !!pv.unaware,
      tools:   pv.tools || [],
    };
  }

  // ── draw edges ────────────────────────────────────────────────────────────
  _drawEdges(edges, state, nmap, colors) {
    this.egGroup.innerHTML = '';
    const NS  = this.NS;
    const svg = this.svg;

    // Purge stale per-edge gradients
    svg?.querySelector('defs')?.querySelectorAll('[id^="eg-"]').forEach(el => el.remove());

    edges.forEach(ed => {
      const a = nmap[ed.from], b = nmap[ed.to];
      if (!a || !b) return;

      const isAct    = state.activeEdges.has(ed.id);
      const isDefOnly = !!ed.defenderOnly;

      const dx = b.x - a.x, dy = b.y - a.y;
      const len = Math.sqrt(dx*dx + dy*dy) || 1;
      const pad = 30;
      const x1 = a.x + dx/len*pad, y1 = a.y + dy/len*pad;
      const x2 = b.x - dx/len*pad, y2 = b.y - dy/len*pad;

      const g = document.createElementNS(NS, 'g');

      if (isAct) {
        const halo = document.createElementNS(NS, 'line');
        this._attrs(halo, {x1,y1,x2,y2,
          stroke:colors.accent,'stroke-width':'8','stroke-opacity':'.12','stroke-linecap':'round'});
        g.appendChild(halo);
        this._ensureEdgeGradient(ed.id, x1, y1, x2, y2, colors.accent);
      }

      const line = document.createElementNS(NS, 'line');
      this._attrs(line, {x1,y1,x2,y2,
        stroke: isAct ? `url(#eg-${ed.id})` : (isDefOnly ? colors.accent : '#21262d'),
        'stroke-width': isAct ? '2' : '1',
        'stroke-linecap': 'round',
        'stroke-dasharray': isDefOnly ? '6 4' : (isAct ? '10 6' : 'none'),
        'marker-end': `url(#${isAct ? colors.arr : (isDefOnly ? colors.arr : 'arr-idle')})`,
      });
      if (isAct) line.classList.add('af-edge-active');
      g.appendChild(line);

      if (isAct && !isDefOnly) {
        [0, 0.55].forEach(offset => {
          const dot = document.createElementNS(NS, 'circle');
          dot.setAttribute('r', '4');
          dot.setAttribute('fill', colors.accent);
          dot.setAttribute('cx', String(x1));
          dot.setAttribute('cy', String(y1));
          const dur = '1.5s';
          const beg = offset > 0 ? `-${(1.5 * offset).toFixed(2)}s` : '0s';
          const ao  = document.createElementNS(NS, 'animate');
          this._attrs(ao, {attributeName:'opacity',values:'0;1;1;0',
            keyTimes:'0;.08;.88;1',dur,begin:beg,repeatCount:'indefinite'});
          dot.append(this._smil('cx',`${x1};${x2}`,dur,beg), this._smil('cy',`${y1};${y2}`,dur,beg), ao);
          g.appendChild(dot);
        });
      }

      if (isAct && ed.label && !isDefOnly) {
        const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
        const labelLen = ed.label.length * 5.5 + 8;
        const lbg = document.createElementNS(NS, 'rect');
        this._attrs(lbg, {
          x:String(mx - labelLen/2), y:String(my - 14),
          width:String(labelLen), height:'13', rx:'3',
          fill:'#0d1117', opacity:'.85',
        });
        const ltxt = document.createElementNS(NS, 'text');
        this._attrs(ltxt, {
          x:String(mx), y:String(my - 4),
          'text-anchor':'middle','font-size':'9','font-family':'ui-monospace,monospace',
          fill:colors.accent,'font-weight':'500',
        });
        ltxt.textContent = ed.label;
        g.append(lbg, ltxt);
      }

      this.egGroup.appendChild(g);
    });
  }

  // ── draw nodes ────────────────────────────────────────────────────────────
  _drawNodes(nodes, state, perspective, colors) {
    this.ngGroup.innerHTML = '';
    const NS = this.NS;
    const W = 72, H = 52, RX = 4;

    nodes.forEach(node => {
      const isDefNode = !!node._isDefender;
      const isAct     = state.activeNodes.has(node.id);
      const isDet     = state.detectionNodes.has(node.id);
      const isComp    = state.compromisedNodes.has(node.id);
      const isGhost   = perspective === 'victim' && state.unaware && !isAct && !isDefNode;
      const isDim     = !isGhost && !isAct && state.activeNodes.size > 0 && !isDefNode;

      const g = document.createElementNS(NS, 'g');
      g.setAttribute('transform', `translate(${node.x - W/2},${node.y - H/2})`);
      g.style.opacity    = isGhost ? '0.1' : isDim ? '0.2' : '1';
      g.style.transition = 'opacity .35s';
      g.style.cursor     = 'default';

      let borderColor, bgColor, iconColor;
      if (isComp)                  { borderColor='#f59e0b'; bgColor='rgba(245,158,11,.1)'; iconColor='#f59e0b'; }
      else if (isDet || isDefNode) { borderColor='#3b82f6'; bgColor='rgba(59,130,246,.08)'; iconColor='#3b82f6'; }
      else if (isAct)              { borderColor=colors.accent; bgColor=colors.accentBg; iconColor=colors.accent; }
      else                         { borderColor='#21262d'; bgColor='#0d1117'; iconColor='#2d4460'; }

      if (isDet) {
        const ring = document.createElementNS(NS, 'rect');
        this._attrs(ring, {x:'-4',y:'-4',width:String(W+8),height:String(H+8),rx:String(RX+2),
          fill:'none',stroke:'#3b82f6','stroke-width':'1.5','stroke-opacity':'.6'});
        ring.classList.add('af-detect-ring');
        g.appendChild(ring);
      }

      if (isAct && !isDefNode) {
        const glow = document.createElementNS(NS, 'rect');
        this._attrs(glow, {x:'-3',y:'-3',width:String(W+6),height:String(H+6),rx:String(RX+2),
          fill:colors.accentBg,stroke:colors.accent,'stroke-width':'1','stroke-opacity':'.35',
          filter:`url(#${colors.glowFilter})`});
        glow.classList.add('af-node-glow');
        g.appendChild(glow);
      }

      const box = document.createElementNS(NS, 'rect');
      this._attrs(box, {x:'0',y:'0',width:String(W),height:String(H),rx:String(RX),
        fill:bgColor,stroke:borderColor,'stroke-width':isAct||isDet||isComp?'1.5':'1'});
      g.appendChild(box);

      const iconId = AF_ICONS[node.type] || 'ic-server';
      const ic = document.createElementNS(NS, 'use');
      this._attrs(ic, {href:`#${iconId}`,x:String(W/2-10),y:'6',width:'20',height:'20'});
      ic.style.color = iconColor;
      g.appendChild(ic);

      const lbl = document.createElementNS(NS, 'text');
      this._attrs(lbl, {x:String(W/2),y:'36','text-anchor':'middle',
        'font-size':'7.5','font-family':'ui-monospace,monospace',
        fill:isAct||isDet||isComp?'#e2e8f0':'#4a5568','font-weight':'600','letter-spacing':'0.3'});
      lbl.textContent = node.label.toUpperCase();
      g.appendChild(lbl);

      if (node.sublabel) {
        const sub = document.createElementNS(NS, 'text');
        this._attrs(sub, {x:String(W/2),y:'47','text-anchor':'middle',
          'font-size':'7','font-family':'ui-monospace,monospace',fill:'#8b949e'});
        sub.textContent = node.sublabel;
        g.appendChild(sub);
      }

      if (isComp) {
        const bg = document.createElementNS(NS, 'g');
        bg.setAttribute('transform', `translate(${W-7},-7)`);
        const bc = document.createElementNS(NS, 'circle');
        this._attrs(bc, {r:'7',fill:'#ef4444',stroke:'#0d1117','stroke-width':'1.5'});
        const bt = document.createElementNS(NS, 'text');
        this._attrs(bt, {'text-anchor':'middle',dy:'4','font-size':'9','font-weight':'bold',fill:'white','font-family':'sans-serif'});
        bt.textContent = '!';
        bg.append(bc, bt);
        g.appendChild(bg);
      }

      if (isDet) {
        const bg = document.createElementNS(NS, 'g');
        bg.setAttribute('transform', `translate(${W/2},${H+10})`);
        const bw = 38;
        const br = document.createElementNS(NS, 'rect');
        this._attrs(br, {x:String(-bw/2),y:'-7',width:String(bw),height:'12',rx:'3',
          fill:'rgba(59,130,246,.15)',stroke:'rgba(59,130,246,.5)','stroke-width':'1'});
        const bt = document.createElementNS(NS, 'text');
        this._attrs(bt, {'text-anchor':'middle',dy:'4','font-size':'7',
          'font-family':'ui-monospace,monospace',fill:'#93c5fd','letter-spacing':'0.5'});
        bt.textContent = 'DETECT';
        bg.append(br, bt);
        g.appendChild(bg);
      }

      g.addEventListener('mouseenter', e => this._showTooltip(e, node, isAct, isDet, isComp, colors));
      g.addEventListener('mouseleave', () => this._hideTooltip());

      this.ngGroup.appendChild(g);
    });
  }

  // ── draw overlays ─────────────────────────────────────────────────────────
  _drawOverlays(state, perspective, colors, nmap) {
    this.ogGroup.innerHTML = '';
    this._stopScanBeam();

    if (perspective === 'defender' && state.activeNodes.size > 0) {
      this._startScanBeam(colors.accent);
    }

    if (perspective === 'victim' && state.activeNodes.size > 0) {
      const svgW = this.svg?.viewBox.baseVal.width  || 1100;
      const svgH = this.svg?.viewBox.baseVal.height || 520;
      this._ensureVignetteGradient(svgW, svgH);
      const rect = document.createElementNS(this.NS, 'rect');
      this._attrs(rect, {x:'0',y:'0',width:String(svgW),height:String(svgH),
        fill:'url(#victim-vignette)',opacity:'0.6',style:'pointer-events:none'});
      this.ogGroup.appendChild(rect);
    }

    if (perspective === 'attacker' && state.tools.length > 0) {
      const atkNode = [...state.activeNodes]
        .map(id => nmap[id]).filter(Boolean)
        .find(n => n.type === 'attacker');
      if (atkNode) {
        state.tools.slice(0, 3).forEach((tool, i) => {
          const tw = tool.length * 6 + 12;
          const tx = atkNode.x - tw/2 + (i - 1) * (tw + 4);
          const ty = atkNode.y - 44;
          const bg = document.createElementNS(this.NS, 'rect');
          this._attrs(bg, {x:String(tx),y:String(ty-10),width:String(tw),height:'14',rx:'3',
            fill:'rgba(239,68,68,.18)',stroke:'rgba(239,68,68,.4)','stroke-width':'1'});
          const txt = document.createElementNS(this.NS, 'text');
          this._attrs(txt, {x:String(tx+tw/2),y:String(ty+1),'text-anchor':'middle',
            'font-size':'8','font-family':'ui-monospace,monospace',fill:'#fca5a5'});
          txt.textContent = tool;
          this.ogGroup.append(bg, txt);
        });
      }
    }
  }

  // ── scan beam ─────────────────────────────────────────────────────────────
  _startScanBeam(color) {
    const svg = this.svg;
    if (!svg) return;
    const svgH = svg.viewBox.baseVal.height || 520;
    const svgW = svg.viewBox.baseVal.width  || 1100;
    const beam = document.createElementNS(this.NS, 'rect');
    beam.id = 'af-scan-beam';
    this._attrs(beam, {x:'0',y:'-20',width:String(svgW),height:'20',
      fill:color,opacity:'0.06',style:'pointer-events:none'});
    const anim = document.createElementNS(this.NS, 'animate');
    this._attrs(anim, {attributeName:'y',from:'-20',to:String(svgH),
      dur:'3s',repeatCount:'indefinite',calcMode:'linear'});
    beam.appendChild(anim);
    this.ogGroup.appendChild(beam);
  }

  _stopScanBeam() { document.getElementById('af-scan-beam')?.remove(); }

  // ── tooltip ───────────────────────────────────────────────────────────────
  _buildTooltip() {
    let tip = document.getElementById('af-tooltip');
    if (!tip) {
      tip = document.createElement('div');
      tip.id = 'af-tooltip';
      tip.style.cssText = 'position:fixed;z-index:9999;pointer-events:none;background:#0d1117;border:1px solid rgba(255,255,255,.12);border-radius:8px;padding:7px 11px;font-size:11px;color:#cbd5e1;line-height:1.5;box-shadow:0 8px 24px rgba(0,0,0,.6);opacity:0;transition:opacity .15s;max-width:160px;';
      document.body.appendChild(tip);
    }
    return tip;
  }

  _showTooltip(e, node, isAct, isDet, isComp, colors) {
    const status = isComp ? `<span style="color:#f59e0b">⚠ Compromised</span>`
      : isDet  ? `<span style="color:#3b82f6">● Monitoring</span>`
      : isAct  ? `<span style="color:${colors.accent}">● Active</span>`
      : `<span style="color:#374151">○ Idle</span>`;
    this._tooltip.innerHTML = `<div style="font-weight:600;color:#f1f5f9;margin-bottom:2px">${node.label}</div>${status}${node.sublabel?`<br><span style="color:#6b7280;font-size:10px">${node.sublabel}</span>`:''}`;
    this._tooltip.style.opacity = '1';
    this._moveTooltip(e);
    document.addEventListener('mousemove', this._boundMove = ev => this._moveTooltip(ev), {passive:true});
  }

  _moveTooltip(e) {
    const tip = this._tooltip;
    const x = e.clientX + 14, y = e.clientY - 10;
    tip.style.left = (window.innerWidth  - x - 200 < 0 ? e.clientX - 200 : x) + 'px';
    tip.style.top  = (window.innerHeight - y - 80  < 0 ? e.clientY - 80  : y) + 'px';
  }

  _hideTooltip() {
    this._tooltip.style.opacity = '0';
    if (this._boundMove) { document.removeEventListener('mousemove', this._boundMove); this._boundMove = null; }
  }

  // ── gradient helpers ──────────────────────────────────────────────────────
  _ensureEdgeGradient(edgeId, x1, y1, x2, y2, color) {
    const NS = this.NS, svg = this.svg;
    if (!svg) return;
    let defs = svg.querySelector('defs');
    if (!defs) { defs = document.createElementNS(NS,'defs'); svg.prepend(defs); }
    const grad = document.createElementNS(NS,'linearGradient');
    grad.id = `eg-${edgeId}`;
    this._attrs(grad, {gradientUnits:'userSpaceOnUse',x1:String(x1),y1:String(y1),x2:String(x2),y2:String(y2)});
    const s1 = document.createElementNS(NS,'stop');
    this._attrs(s1, {offset:'0%','stop-color':color,'stop-opacity':'0.25'});
    const s2 = document.createElementNS(NS,'stop');
    this._attrs(s2, {offset:'100%','stop-color':color,'stop-opacity':'1'});
    grad.append(s1,s2);
    defs.appendChild(grad);
  }

  _ensureVignetteGradient(w, h) {
    const NS = this.NS, svg = this.svg;
    if (!svg || svg.querySelector('#victim-vignette')) return;
    let defs = svg.querySelector('defs');
    if (!defs) { defs = document.createElementNS(NS,'defs'); svg.prepend(defs); }
    const grad = document.createElementNS(NS,'radialGradient');
    grad.id = 'victim-vignette';
    this._attrs(grad, {cx:'50%',cy:'50%',r:'50%',gradientUnits:'userSpaceOnUse',fx:String(w*.5),fy:String(h*.5)});
    const s1 = document.createElementNS(NS,'stop');
    this._attrs(s1, {offset:'35%','stop-color':'#f59e0b','stop-opacity':'0'});
    const s2 = document.createElementNS(NS,'stop');
    this._attrs(s2, {offset:'100%','stop-color':'#f59e0b','stop-opacity':'0.2'});
    grad.append(s1,s2);
    defs.appendChild(grad);
  }

  // ── util ──────────────────────────────────────────────────────────────────
  _colors(perspective) {
    if (perspective === 'attacker') return {accent:'#ef4444',accentBg:'rgba(239,68,68,.08)',glowFilter:'glow-r',arr:'arr-r'};
    if (perspective === 'defender') return {accent:'#3b82f6',accentBg:'rgba(59,130,246,.08)',glowFilter:'glow-b',arr:'arr-b'};
    return {accent:'#f59e0b',accentBg:'rgba(245,158,11,.07)',glowFilter:'glow-a',arr:'arr-a'};
  }

  _attrs(el, map) {
    for (const [k,v] of Object.entries(map)) el.setAttribute(k, v);
  }

  _smil(attrName, values, dur, begin) {
    const a = document.createElementNS(this.NS,'animate');
    this._attrs(a, {attributeName:attrName,values,dur,begin:begin||'0s',
      repeatCount:'indefinite',calcMode:'spline',keySplines:'.4 0 .6 1',keyTimes:'0;1'});
    return a;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Alpine.js component factory
// ─────────────────────────────────────────────────────────────────────────────
window.attackFlow = function attackFlow() {
  return {
    perspective:  'attacker',
    currentPhase: 0,
    phases:       (_AF || {}).phases || [],
    topo:         null,
    _renderer:    null,

    tabs: [
      { id:'attacker', label:(_AF.labels||{}).attacker||'Attacker', icon:'M13 10V3L4 14h7v7l9-11h-7z' },
      { id:'defender', label:(_AF.labels||{}).defender||'Defender', icon:'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
      { id:'victim',   label:(_AF.labels||{}).victim  ||'Victim',   icon:'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z' },
    ],

    get currentData() {
      const ph = this.phases[this.currentPhase];
      return ph ? ph[this.perspective] : null;
    },
    get accentColor() {
      return this.perspective==='attacker'?'#ef4444':this.perspective==='defender'?'#3b82f6':'#f59e0b';
    },
    get accentDim() {
      return this.perspective==='attacker'?'rgba(239,68,68,.08)':this.perspective==='defender'?'rgba(59,130,246,.08)':'rgba(245,158,11,.07)';
    },

    setPerspective(p) { this.perspective = p; this._refresh(); },
    setPhase(i)       { this.currentPhase = i; this._refresh(); },
    nextPhase() { if (this.currentPhase < this.phases.length-1) { this.currentPhase++; this._refresh(); } },
    prevPhase() { if (this.currentPhase > 0) { this.currentPhase--; this._refresh(); } },

    _refresh() { this.$nextTick(() => { this._renderDiagram(); this._animateNarrative(); }); },
    _animateNarrative() {
      const el = document.getElementById('af-narrative');
      if (!el) return;
      el.style.animation = 'none'; void el.offsetHeight; el.style.animation = 'narrativeIn .28s ease forwards';
    },
    init() {
      this.$nextTick(() => {
        this.topo      = AF_TOPOLOGIES[(_AF||{}).slug] || null;
        this._renderer = new AFRenderer('af-diagram');
        this._renderDiagram();
      });
    },
    _renderDiagram() {
      if (!this._renderer || !this.topo) return;
      this._renderer.render(this.topo, this.currentPhase, this.perspective);
    },
  };
};
