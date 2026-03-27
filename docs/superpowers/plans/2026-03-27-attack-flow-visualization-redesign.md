# Attack Flow Visualization Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the attack flow SVG visualization so the diagram is the primary teacher — inline edge labels, per-perspective node sets (attacker/defender/victim), defender overlay nodes (Firewall/SIEM/EDR), and victim ghosting, across all 7 attack types.

**Architecture:** Full rewrite of `static/js/attack-flow-vis.js` with a new topology schema that stores per-perspective phase state, plus defender-only nodes. `templates/attack_flow_detail.html` gets targeted updates: larger SVG viewBox, 4 new icon symbols, and 2 new CSS animation classes. The Alpine.js component API is unchanged — same `_AF` injection, same tab/phase navigation.

**Tech Stack:** Vanilla JS (ES2020), SVG DOM API, Alpine.js v3 (already loaded), Jinja2 (Flask template), Tailwind CSS (already loaded)

---

## File Map

| File | Change | Responsibility |
|---|---|---|
| `static/js/attack-flow-vis.js` | Full rewrite | Topology data for all 7 attacks + AFRenderer class + Alpine component |
| `templates/attack_flow_detail.html` | Targeted edits | SVG viewBox size, 4 new `<symbol>` defs, 2 new CSS animation classes |

No other files change. No Flask routes change. No `attack_flows.json` changes.

---

## Task 1: Update the template — SVG canvas and new icons

**Files:**
- Modify: `templates/attack_flow_detail.html`

This task only touches the HTML/SVG shell. No JS changes yet. After this task the diagram will render blank (the old JS topology uses different coordinate space) but the template scaffolding is correct.

- [ ] **Step 1: Expand the SVG viewBox and remove the height cap**

In `templates/attack_flow_detail.html`, find line 106–107:
```html
      <svg id="af-diagram" viewBox="0 0 1000 400" class="w-full block"
           style="min-height:200px;max-height:400px;" preserveAspectRatio="xMidYMid meet">
```
Replace with:
```html
      <svg id="af-diagram" viewBox="0 0 1100 520" class="w-full block"
           style="min-height:260px;" preserveAspectRatio="xMidYMid meet">
```

- [ ] **Step 2: Update the background grid and vignette rects to match new viewBox**

Find line 197–203 (background grid rect and vignette rect):
```html
        <!-- Background grid -->
        <rect width="1000" height="400" fill="url(#af-grid)"/>
        <!-- Subtle vignette -->
        <radialGradient id="vignette" cx="50%" cy="50%" r="70%">
          <stop offset="0%" stop-color="transparent"/>
          <stop offset="100%" stop-color="rgba(0,0,0,.45)"/>
        </radialGradient>
        <rect width="1000" height="400" fill="url(#vignette)"/>
```
Replace with:
```html
        <!-- Background grid -->
        <rect width="1100" height="520" fill="url(#af-grid)"/>
        <!-- Subtle vignette -->
        <radialGradient id="vignette" cx="50%" cy="50%" r="70%">
          <stop offset="0%" stop-color="transparent"/>
          <stop offset="100%" stop-color="rgba(0,0,0,.45)"/>
        </radialGradient>
        <rect width="1100" height="520" fill="url(#vignette)"/>
```

- [ ] **Step 3: Add 4 new SVG icon symbols to the `<defs>` block**

Find the closing `</symbol>` of the last existing symbol (`ic-monitor`, around line 193), and insert these four new symbols immediately after it, before `</defs>`:

```html
          <symbol id="ic-firewall" viewBox="0 0 40 40">
            <path d="M20 4L7 10v10c0 8.5 5.5 16 13 18.5C27.5 36 33 28.5 33 20V10L20 4z" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linejoin="round"/>
            <line x1="10" y1="16" x2="30" y2="16" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <line x1="10" y1="21" x2="30" y2="21" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <line x1="10" y1="26" x2="24" y2="26" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
          </symbol>
          <symbol id="ic-siem" viewBox="0 0 40 40">
            <rect x="4" y="4" width="32" height="32" rx="2" stroke="currentColor" fill="none" stroke-width="2.5"/>
            <line x1="4" y1="13" x2="36" y2="13" stroke="currentColor" stroke-width="1.5"/>
            <rect x="9" y="19" width="4" height="10" rx="1" fill="currentColor" opacity=".7"/>
            <rect x="16" y="23" width="4" height="6" rx="1" fill="currentColor" opacity=".7"/>
            <rect x="23" y="17" width="4" height="12" rx="1" fill="currentColor" opacity=".7"/>
            <rect x="30" y="21" width="4" height="8" rx="1" fill="currentColor" opacity=".7"/>
          </symbol>
          <symbol id="ic-edr" viewBox="0 0 40 40">
            <path d="M20 4L7 10v10c0 8.5 5.5 16 13 18.5C27.5 36 33 28.5 33 20V10L20 4z" stroke="currentColor" fill="none" stroke-width="2.5" stroke-linejoin="round"/>
            <path d="M14 20l4 4 8-8" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
          </symbol>
          <symbol id="ic-c2" viewBox="0 0 40 40">
            <rect x="4" y="10" width="32" height="20" rx="2" stroke="currentColor" fill="none" stroke-width="2.5"/>
            <circle cx="30" cy="14" r="2" fill="currentColor"/>
            <circle cx="25" cy="14" r="2" fill="currentColor"/>
            <line x1="20" y1="4" x2="20" y2="10" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            <line x1="20" y1="4" x2="14" y2="7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <line x1="20" y1="4" x2="26" y2="7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          </symbol>
```

- [ ] **Step 4: Add 2 new CSS animation classes to the `<style>` block**

Find the existing `<style>` block (lines 18–38). Add these two new rules inside it, after the existing `.af-scanlines::after` rule:

```css
@keyframes detectPulse { 0%,100%{opacity:.5} 50%{opacity:1} }
@keyframes nodeGlowPulse { 0%,100%{opacity:.4} 50%{opacity:.9} }
.af-detect-ring { transform-box:fill-box; transform-origin:center; animation:detectPulse 1.4s ease-in-out infinite; }
.af-node-glow   { transform-box:fill-box; transform-origin:center; animation:nodeGlowPulse 2s ease-in-out infinite; }
```

- [ ] **Step 5: Verify the page loads without JS errors**

Run the Flask dev server:
```bash
cd c:/Users/Matqk/Desktop/W/Grind/School/Github/CyberBase
python app.py
```
Open `http://localhost:5000/attack-flows/phishing` in a browser. The diagram area should show the grid background. The old nodes/edges may render in the wrong positions or not at all — that's expected. No console errors about missing elements.

- [ ] **Step 6: Commit**

```bash
git add templates/attack_flow_detail.html
git commit -m "feat: expand SVG canvas and add new icon symbols for attack flow redesign"
```

---

## Task 2: Write the new JS file skeleton and AFRenderer class

**Files:**
- Modify: `static/js/attack-flow-vis.js` (full rewrite — replace entire file contents)

This task produces a working renderer with no topology data yet. The page will show a blank canvas with no nodes until Task 3 adds the topologies.

- [ ] **Step 1: Replace the entire file with the new skeleton**

Replace the full contents of `static/js/attack-flow-vis.js` with:

```js
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
// Topology definitions — populated in Tasks 3–9
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

    const colors    = this._colors(perspective);
    const nodes     = this._resolveNodes(topo, perspective);
    const edges     = this._resolveEdges(topo, perspective);
    const state     = this._getPhaseState(topo, phaseIndex, perspective);
    const nmap      = Object.fromEntries(nodes.map(n => [n.id, n]));

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
    if (!ph) return { activeNodes: [], activeEdges: [], detectionNodes: [], compromisedNodes: [], unaware: false, tools: [] };
    const pv  = ph[perspective] || {};
    return {
      activeNodes:    new Set(pv.activeNodes   || []),
      activeEdges:    new Set(pv.activeEdges   || []),
      detectionNodes: new Set(pv.detectionNodes|| []),
      compromisedNodes:new Set(pv.compromisedNodes||[]),
      unaware: !!pv.unaware,
      tools:   pv.tools || [],
    };
  }

  // ── draw edges ────────────────────────────────────────────────────────────
  _drawEdges(edges, state, nmap, colors) {
    this.egGroup.innerHTML = '';
    const NS = this.NS;
    const svg = this.svg;

    // Purge stale per-edge gradients
    if (svg) {
      svg.querySelector('defs')?.querySelectorAll('[id^="eg-"]').forEach(el => el.remove());
    }

    edges.forEach(ed => {
      const a = nmap[ed.from], b = nmap[ed.to];
      if (!a || !b) return;

      const isAct  = state.activeEdges.has(ed.id);
      const isDefOnly = !!ed.defenderOnly;

      const dx = b.x - a.x, dy = b.y - a.y;
      const len = Math.sqrt(dx*dx + dy*dy) || 1;
      // Pad away from the 36×28 node rect edges (half-diagonal ~23px + 6 margin)
      const pad = 30;
      const x1 = a.x + dx/len*pad, y1 = a.y + dy/len*pad;
      const x2 = b.x - dx/len*pad, y2 = b.y - dy/len*pad;

      const g = document.createElementNS(NS, 'g');

      if (isAct) {
        // Glow halo
        const halo = document.createElementNS(NS, 'line');
        this._attrs(halo, {x1,y1,x2,y2,
          stroke:colors.accent, 'stroke-width':'8',
          'stroke-opacity':'.12', 'stroke-linecap':'round'});
        g.appendChild(halo);
        this._ensureEdgeGradient(ed.id, x1, y1, x2, y2, colors.accent);
      }

      // Main line
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

      // Traveling packet dot (active non-defender-only edges)
      if (isAct && !isDefOnly) {
        [0, 0.55].forEach(offset => {
          const dot = document.createElementNS(NS, 'circle');
          dot.setAttribute('r', '4');
          dot.setAttribute('fill', colors.accent);
          dot.setAttribute('cx', String(x1));
          dot.setAttribute('cy', String(y1));
          const dur  = '1.5s';
          const beg  = offset > 0 ? `-${(1.5 * offset).toFixed(2)}s` : '0s';
          dot.append(
            this._smil('cx', `${x1};${x2}`, dur, beg),
            this._smil('cy', `${y1};${y2}`, dur, beg),
            (() => {
              const ao = document.createElementNS(NS, 'animate');
              this._attrs(ao, {attributeName:'opacity', values:'0;1;1;0',
                keyTimes:'0;.08;.88;1', dur, begin:beg, repeatCount:'indefinite'});
              return ao;
            })()
          );
          g.appendChild(dot);
        });
      }

      // Inline edge label (active edges only, not defender monitoring edges)
      if (isAct && ed.label && !isDefOnly) {
        const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
        // Background rect for legibility
        const lbg = document.createElementNS(NS, 'rect');
        const labelLen = ed.label.length * 5.5 + 8;
        this._attrs(lbg, {
          x: String(mx - labelLen/2), y: String(my - 14),
          width: String(labelLen), height: '13',
          rx: '3', fill: '#0d1117', opacity: '.85',
        });
        const ltxt = document.createElementNS(NS, 'text');
        this._attrs(ltxt, {
          x: String(mx), y: String(my - 4),
          'text-anchor': 'middle',
          'font-size': '9', 'font-family': 'ui-monospace,monospace',
          fill: colors.accent, 'font-weight': '500',
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
    // Node box dimensions
    const W = 72, H = 52, RX = 4;

    nodes.forEach(node => {
      const isDefenderNode = node._isDefender;
      const isAct   = state.activeNodes.has(node.id);
      const isDet   = state.detectionNodes.has(node.id);
      const isComp  = state.compromisedNodes.has(node.id);
      // Ghosted: victim perspective, node not active, unaware flag set
      const isGhost = perspective === 'victim' && state.unaware && !isAct && !isDefenderNode;
      const isDim   = !isGhost && !isAct && state.activeNodes.size > 0 && !isDefenderNode;

      const g = document.createElementNS(NS, 'g');
      g.setAttribute('transform', `translate(${node.x - W/2},${node.y - H/2})`);
      g.style.opacity    = isGhost ? '0.1' : isDim ? '0.2' : '1';
      g.style.transition = 'opacity .35s';
      g.style.cursor     = 'default';

      // Choose border color
      let borderColor, bgColor, iconColor;
      if (isComp) {
        borderColor = '#f59e0b'; bgColor = 'rgba(245,158,11,.1)'; iconColor = '#f59e0b';
      } else if (isDet || isDefenderNode) {
        borderColor = '#3b82f6'; bgColor = 'rgba(59,130,246,.08)'; iconColor = '#3b82f6';
      } else if (isAct) {
        borderColor = colors.accent; bgColor = colors.accentBg; iconColor = colors.accent;
      } else {
        borderColor = '#21262d'; bgColor = '#0d1117'; iconColor = '#2d4460';
      }

      // Detection pulsing ring (defender view)
      if (isDet) {
        const ring = document.createElementNS(NS, 'rect');
        this._attrs(ring, {
          x: '-4', y: '-4', width: String(W+8), height: String(H+8), rx: String(RX+2),
          fill: 'none', stroke: '#3b82f6', 'stroke-width': '1.5', 'stroke-opacity': '.6',
        });
        ring.classList.add('af-detect-ring');
        g.appendChild(ring);
      }

      // Node glow ring (active non-defender nodes)
      if (isAct && !isDefenderNode) {
        const glow = document.createElementNS(NS, 'rect');
        this._attrs(glow, {
          x: '-3', y: '-3', width: String(W+6), height: String(H+6), rx: String(RX+2),
          fill: colors.accentBg, stroke: colors.accent,
          'stroke-width': '1', 'stroke-opacity': '.35',
          filter: `url(#${colors.glowFilter})`,
        });
        glow.classList.add('af-node-glow');
        g.appendChild(glow);
      }

      // Main box
      const box = document.createElementNS(NS, 'rect');
      this._attrs(box, {
        x:'0', y:'0', width:String(W), height:String(H), rx:String(RX),
        fill: bgColor, stroke: borderColor, 'stroke-width': isAct || isDet || isComp ? '1.5' : '1',
      });
      g.appendChild(box);

      // Icon — 20×20, centered horizontally, top portion of box
      const iconId = AF_ICONS[node.type] || 'ic-server';
      const ic = document.createElementNS(NS, 'use');
      this._attrs(ic, {
        href: `#${iconId}`,
        x: String(W/2 - 10), y: '6',
        width: '20', height: '20',
      });
      ic.style.color = iconColor;
      g.appendChild(ic);

      // Label (node type/name, 8px caps monospace)
      const lbl = document.createElementNS(NS, 'text');
      this._attrs(lbl, {
        x: String(W/2), y: '36',
        'text-anchor': 'middle',
        'font-size': '7.5', 'font-family': 'ui-monospace,monospace',
        fill: isAct || isDet || isComp ? '#e2e8f0' : '#4a5568',
        'font-weight': '600',
        'letter-spacing': '0.3',
      });
      lbl.textContent = node.label.toUpperCase();
      g.appendChild(lbl);

      // Sublabel (tool/OS/protocol, 7px muted)
      if (node.sublabel) {
        const sub = document.createElementNS(NS, 'text');
        this._attrs(sub, {
          x: String(W/2), y: '47',
          'text-anchor': 'middle',
          'font-size': '7', 'font-family': 'ui-monospace,monospace',
          fill: '#8b949e',
        });
        sub.textContent = node.sublabel;
        g.appendChild(sub);
      }

      // Compromised badge (!) — top-right corner
      if (isComp) {
        const badgeG = document.createElementNS(NS, 'g');
        badgeG.setAttribute('transform', `translate(${W - 7}, -7)`);
        const bc = document.createElementNS(NS, 'circle');
        this._attrs(bc, {r:'7', fill:'#ef4444', stroke:'#0d1117', 'stroke-width':'1.5'});
        const bt = document.createElementNS(NS, 'text');
        this._attrs(bt, {'text-anchor':'middle', dy:'4', 'font-size':'9',
          'font-weight':'bold', fill:'white', 'font-family':'sans-serif'});
        bt.textContent = '!';
        badgeG.append(bc, bt);
        g.appendChild(badgeG);
      }

      // DETECT badge — bottom of detection nodes
      if (isDet) {
        const badgeG = document.createElementNS(NS, 'g');
        badgeG.setAttribute('transform', `translate(${W/2}, ${H + 10})`);
        const bw = 38;
        const br = document.createElementNS(NS, 'rect');
        this._attrs(br, {
          x:String(-bw/2), y:'-7', width:String(bw), height:'12', rx:'3',
          fill:'rgba(59,130,246,.15)', stroke:'rgba(59,130,246,.5)', 'stroke-width':'1',
        });
        const bt = document.createElementNS(NS, 'text');
        this._attrs(bt, {'text-anchor':'middle', dy:'4', 'font-size':'7',
          'font-family':'ui-monospace,monospace', fill:'#93c5fd', 'letter-spacing':'0.5'});
        bt.textContent = 'DETECT';
        badgeG.append(br, bt);
        g.appendChild(badgeG);
      }

      // Hover tooltip
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
      this._attrs(rect, {
        x:'0',y:'0', width:String(svgW), height:String(svgH),
        fill:'url(#victim-vignette)', opacity:'0.6', style:'pointer-events:none',
      });
      this.ogGroup.appendChild(rect);
    }

    // Attacker: tool badges above attacker node
    if (perspective === 'attacker' && state.tools.length > 0) {
      // Find first active attacker-type node
      const atkNode = [...state.activeNodes]
        .map(id => nmap[id])
        .filter(Boolean)
        .find(n => n.type === 'attacker');
      if (atkNode) {
        state.tools.slice(0, 3).forEach((tool, i) => {
          const tw  = tool.length * 6 + 12;
          const tx  = atkNode.x - tw/2 + (i - 1) * (tw + 4);
          const ty  = atkNode.y - 44 - i * 0;
          const bg  = document.createElementNS(this.NS, 'rect');
          this._attrs(bg, {
            x:String(tx), y:String(ty - 10), width:String(tw), height:'14', rx:'3',
            fill:'rgba(239,68,68,.18)', stroke:'rgba(239,68,68,.4)', 'stroke-width':'1',
          });
          const txt = document.createElementNS(this.NS, 'text');
          this._attrs(txt, {
            x:String(tx + tw/2), y:String(ty + 1),
            'text-anchor':'middle', 'font-size':'8',
            'font-family':'ui-monospace,monospace', fill:'#fca5a5',
          });
          txt.textContent = tool;
          this.ogGroup.append(bg, txt);
        });
      }
    }
  }

  // ── defender scan beam ────────────────────────────────────────────────────
  _startScanBeam(color) {
    const svg  = this.svg;
    if (!svg) return;
    const svgH = svg.viewBox.baseVal.height || 520;
    const svgW = svg.viewBox.baseVal.width  || 1100;
    const beam = document.createElementNS(this.NS, 'rect');
    beam.id = 'af-scan-beam';
    this._attrs(beam, {
      x:'0', y:'-20', width:String(svgW), height:'20',
      fill: color, opacity:'0.06', style:'pointer-events:none',
    });
    const anim = document.createElementNS(this.NS, 'animate');
    this._attrs(anim, {
      attributeName:'y', from:'-20', to:String(svgH),
      dur:'3s', repeatCount:'indefinite', calcMode:'linear',
    });
    beam.appendChild(anim);
    this.ogGroup.appendChild(beam);
  }

  _stopScanBeam() {
    document.getElementById('af-scan-beam')?.remove();
  }

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
    const status = isComp
      ? `<span style="color:#f59e0b">⚠ Compromised</span>`
      : isDet
      ? `<span style="color:#3b82f6">● Monitoring</span>`
      : isAct
      ? `<span style="color:${colors.accent}">● Active</span>`
      : `<span style="color:#374151">○ Idle</span>`;
    this._tooltip.innerHTML = `<div style="font-weight:600;color:#f1f5f9;margin-bottom:2px">${node.label}</div>${status}${node.sublabel ? `<br><span style="color:#6b7280;font-size:10px">${node.sublabel}</span>` : ''}`;
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

  // ── SVG gradient helpers ──────────────────────────────────────────────────
  _ensureEdgeGradient(edgeId, x1, y1, x2, y2, color) {
    const NS = this.NS, svg = this.svg;
    if (!svg) return;
    let defs = svg.querySelector('defs');
    if (!defs) { defs = document.createElementNS(NS,'defs'); svg.prepend(defs); }
    const grad = document.createElementNS(NS,'linearGradient');
    grad.id = `eg-${edgeId}`;
    this._attrs(grad, {gradientUnits:'userSpaceOnUse', x1:String(x1), y1:String(y1), x2:String(x2), y2:String(y2)});
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
    if (perspective === 'attacker') return { accent:'#ef4444', accentBg:'rgba(239,68,68,.08)', glowFilter:'glow-r', arr:'arr-r' };
    if (perspective === 'defender') return { accent:'#3b82f6', accentBg:'rgba(59,130,246,.08)', glowFilter:'glow-b', arr:'arr-b' };
    return { accent:'#f59e0b', accentBg:'rgba(245,158,11,.07)', glowFilter:'glow-a', arr:'arr-a' };
  }

  _attrs(el, map) {
    for (const [k,v] of Object.entries(map)) el.setAttribute(k, v);
  }

  _smil(attrName, values, dur, begin) {
    const a = document.createElementNS(this.NS,'animate');
    this._attrs(a, {attributeName:attrName, values, dur, begin:begin||'0s',
      repeatCount:'indefinite', calcMode:'spline', keySplines:'.4 0 .6 1', keyTimes:'0;1'});
    return a;
  }
}


// ─────────────────────────────────────────────────────────────────────────────
// Alpine.js component factory — registered as window.attackFlow
// (interface unchanged from previous version)
// ─────────────────────────────────────────────────────────────────────────────
window.attackFlow = function attackFlow() {
  return {
    perspective:  'attacker',
    currentPhase: 0,
    phases:       (_AF || {}).phases || [],
    topo:         null, // set in init() after AF_TOPOLOGIES is populated
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
        this.topo     = AF_TOPOLOGIES[(_AF||{}).slug] || null;
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
```

- [ ] **Step 2: Verify page loads without JS errors**

Reload `http://localhost:5000/attack-flows/phishing`. The diagram should be blank (no topology defined yet). No JS console errors. Phase navigation and perspective tabs should work without crashing.

- [ ] **Step 3: Commit**

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: rewrite AFRenderer with new schema — blank canvas, no topologies yet"
```

---

## Task 3: Add phishing topology (6 phases)

**Files:**
- Modify: `static/js/attack-flow-vis.js` — add to `AF_TOPOLOGIES`

Phases: Reconnaissance, Weaponization, Delivery, Exploitation, Credential Harvesting, Persistence

In `AF_TOPOLOGIES`, add:

- [ ] **Step 1: Add the phishing topology**

Insert after the `const AF_TOPOLOGIES = {};` line (replacing the `{}` with the full object, or appending if you structured it differently):

```js
AF_TOPOLOGIES['phishing'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker',    label:'Attacker',          sublabel:'Kali Linux',     x:90,  y:260 },
      { id:'mail', type:'envelope',    label:'Mail Server',       sublabel:'SMTP/587',       x:290, y:260 },
      { id:'inet', type:'cloud',       label:'Internet',          sublabel:'Public Routing', x:510, y:260 },
      { id:'usr',  type:'victim',      label:'Victim Workstation',sublabel:'Windows 11',     x:730, y:260 },
      { id:'fake', type:'browser',     label:'Fake Login Page',   sublabel:'Evilginx2',      x:730, y:420 },
      { id:'c2',   type:'c2',          label:'C2 Server',         sublabel:'VPS/TOR',        x:960, y:260 },
    ],
    defender: [
      { id:'fw',   type:'firewall',    label:'Email Gateway',     sublabel:'Proofpoint',     x:400, y:120, _isDefender:true },
      { id:'siem', type:'siem',        label:'SIEM',              sublabel:'Splunk',         x:730, y:120, _isDefender:true },
      { id:'edr',  type:'edr',         label:'EDR Agent',         sublabel:'CrowdStrike',    x:960, y:420, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk',  to:'mail', label:'spoofed email' },
    { id:'e2', from:'mail', to:'inet', label:'relayed message' },
    { id:'e3', from:'inet', to:'usr',  label:'delivered to inbox' },
    { id:'e4', from:'usr',  to:'fake', label:'clicks link' },
    { id:'e5', from:'fake', to:'c2',   label:'stolen credentials' },
    { id:'e6', from:'c2',   to:'atk',  label:'exfil data' },
    { id:'de1', from:'fw',  to:'mail', label:'header scan',      defenderOnly:true },
    { id:'de2', from:'siem',to:'usr',  label:'log ingestion',    defenderOnly:true },
    { id:'de3', from:'edr', to:'usr',  label:'process monitor',  defenderOnly:true },
  ],
  phases: [
    { // 1: Reconnaissance
      attacker: { activeNodes:['atk'],                    activeEdges:[],           tools:['theHarvester','LinkedIn'] },
      defender: { activeNodes:['atk'],                    activeEdges:[],           detectionNodes:[] },
      victim:   { activeNodes:[],                         activeEdges:[],           compromisedNodes:[], unaware:true },
    },
    { // 2: Weaponization
      attacker: { activeNodes:['atk'],                    activeEdges:[],           tools:['GoPhish','Evilginx2'] },
      defender: { activeNodes:['atk'],                    activeEdges:[],           detectionNodes:[] },
      victim:   { activeNodes:[],                         activeEdges:[],           compromisedNodes:[], unaware:true },
    },
    { // 3: Delivery
      attacker: { activeNodes:['atk','mail','inet'],       activeEdges:['e1','e2'],  tools:['GoPhish'] },
      defender: { activeNodes:['atk','mail','fw'],         activeEdges:['e1','de1'], detectionNodes:['fw'] },
      victim:   { activeNodes:['usr'],                    activeEdges:['e3'],       compromisedNodes:[], unaware:false },
    },
    { // 4: Exploitation
      attacker: { activeNodes:['usr','fake'],              activeEdges:['e4'],       tools:['Evilginx2'] },
      defender: { activeNodes:['usr','siem'],              activeEdges:['de2'],      detectionNodes:['siem'] },
      victim:   { activeNodes:['usr','fake'],              activeEdges:['e4'],       compromisedNodes:[], unaware:false },
    },
    { // 5: Credential Harvesting
      attacker: { activeNodes:['fake','c2'],               activeEdges:['e5'],       tools:['Evilginx2'] },
      defender: { activeNodes:['usr','siem','edr'],        activeEdges:['de2','de3'],detectionNodes:['siem','edr'] },
      victim:   { activeNodes:['usr','fake'],              activeEdges:['e5'],       compromisedNodes:['usr'], unaware:false },
    },
    { // 6: Persistence
      attacker: { activeNodes:['c2','atk'],                activeEdges:['e6'],       tools:['OAuth abuse'] },
      defender: { activeNodes:['siem','edr'],              activeEdges:['de3'],      detectionNodes:['siem','edr'] },
      victim:   { activeNodes:['usr','c2'],                activeEdges:['e5','e6'],  compromisedNodes:['usr','fake'], unaware:false },
    },
  ],
};
```

- [ ] **Step 2: Verify phishing renders correctly**

Reload `http://localhost:5000/attack-flows/phishing`. Check:
- Attacker tab, phase 1: only attacker node lit red, "theHarvester" and "LinkedIn" tool badges visible above it
- Attacker tab, phase 3: atk→mail→inet active in red, edge labels "spoofed email" / "relayed message" visible
- Defender tab, phase 3: Email Gateway node appears in blue with "DETECT" badge, scan beam sweeps
- Victim tab, phase 1: all nodes ghosted at ~10% opacity (victim unaware)
- Victim tab, phase 5: victim workstation has amber glow + red `!` badge

- [ ] **Step 3: Commit**

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: add phishing attack topology (6 phases, all 3 perspectives)"
```

---

## Task 4: Add brute-force topology (5 phases)

**Files:**
- Modify: `static/js/attack-flow-vis.js`

Phases: Target Identification, Credential List Preparation, Automated Attack Execution, Authentication Bypass, Post-Access Exploitation

- [ ] **Step 1: Add the brute-force topology**

```js
AF_TOPOLOGIES['brute-force'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker',  label:'Attacker',      sublabel:'Kali Linux',    x:90,  y:260 },
      { id:'lst',  type:'database',  label:'Credential List',sublabel:'rockyou.txt',  x:90,  y:420 },
      { id:'lgn',  type:'browser',   label:'Login Portal',  sublabel:'Target App',    x:380, y:260 },
      { id:'auth', type:'server',    label:'Auth Server',   sublabel:'LDAP/AD',       x:650, y:160 },
      { id:'db',   type:'database',  label:'User Database', sublabel:'PostgreSQL',    x:900, y:260 },
      { id:'acc',  type:'victim',    label:'Victim Account',sublabel:'Compromised',   x:900, y:420 },
    ],
    defender: [
      { id:'waf',  type:'firewall',  label:'WAF',           sublabel:'ModSecurity',   x:380, y:100, _isDefender:true },
      { id:'rate', type:'firewall',  label:'Rate Limiter',  sublabel:'Nginx',         x:650, y:380, _isDefender:true },
      { id:'siem', type:'siem',      label:'SIEM',          sublabel:'Splunk',        x:900, y:100, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'lst',  to:'atk',  label:'wordlist loaded' },
    { id:'e2', from:'atk',  to:'lgn',  label:'auth requests' },
    { id:'e3', from:'lgn',  to:'auth', label:'credential check' },
    { id:'e4', from:'auth', to:'db',   label:'user lookup' },
    { id:'e5', from:'auth', to:'acc',  label:'session granted' },
    { id:'de1', from:'waf', to:'lgn',  label:'rate check',    defenderOnly:true },
    { id:'de2', from:'rate',to:'auth', label:'throttle',      defenderOnly:true },
    { id:'de3', from:'siem',to:'auth', label:'log analysis',  defenderOnly:true },
  ],
  phases: [
    { // 1: Target Identification
      attacker: { activeNodes:['atk','lgn'],         activeEdges:['e2'],           tools:['nmap','Shodan'] },
      defender: { activeNodes:['lgn','waf'],          activeEdges:['de1'],          detectionNodes:['waf'] },
      victim:   { activeNodes:['lgn'],               activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 2: Credential List Preparation
      attacker: { activeNodes:['atk','lst'],          activeEdges:['e1'],           tools:['CeWL','hashcat'] },
      defender: { activeNodes:['siem'],               activeEdges:[],               detectionNodes:[] },
      victim:   { activeNodes:[],                    activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 3: Automated Attack Execution
      attacker: { activeNodes:['atk','lgn','auth'],   activeEdges:['e2','e3'],      tools:['Hydra','Medusa'] },
      defender: { activeNodes:['lgn','waf','rate'],   activeEdges:['de1','de2'],    detectionNodes:['waf','rate'] },
      victim:   { activeNodes:['lgn'],               activeEdges:['e2'],           compromisedNodes:[], unaware:true },
    },
    { // 4: Authentication Bypass
      attacker: { activeNodes:['lgn','auth','db'],    activeEdges:['e3','e4'],      tools:['Hydra'] },
      defender: { activeNodes:['auth','siem','rate'], activeEdges:['de2','de3'],    detectionNodes:['siem','rate'] },
      victim:   { activeNodes:['lgn','auth'],         activeEdges:['e3'],           compromisedNodes:[], unaware:true },
    },
    { // 5: Post-Access Exploitation
      attacker: { activeNodes:['auth','acc'],         activeEdges:['e5'],           tools:['session abuse'] },
      defender: { activeNodes:['siem','auth'],        activeEdges:['de3'],          detectionNodes:['siem'] },
      victim:   { activeNodes:['acc'],               activeEdges:['e5'],           compromisedNodes:['acc'], unaware:false },
    },
  ],
};
```

- [ ] **Step 2: Verify brute-force renders**

Open `http://localhost:5000/attack-flows/brute-force`. Check phase 3 attacker view shows "auth requests" edge label and Hydra/Medusa tool badges. Defender phase 3 shows WAF + Rate Limiter with DETECT badges.

- [ ] **Step 3: Commit**

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: add brute-force attack topology (5 phases)"
```

---

## Task 5: Add SQL injection topology (6 phases)

**Files:**
- Modify: `static/js/attack-flow-vis.js`

Phases: Application Reconnaissance, Injection Point Discovery, Payload Crafting, Data Extraction, Privilege Escalation, Data Exfiltration or Destruction

- [ ] **Step 1: Add the SQL injection topology**

```js
AF_TOPOLOGIES['sql-injection'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker',  label:'Attacker',      sublabel:'sqlmap/manual', x:90,  y:260 },
      { id:'web',  type:'browser',   label:'Web Application',sublabel:'Target Site',  x:320, y:260 },
      { id:'srv',  type:'server',    label:'Web Server',    sublabel:'Apache/Nginx',  x:560, y:160 },
      { id:'app',  type:'server',    label:'App Server',    sublabel:'Python/PHP',    x:560, y:380 },
      { id:'db',   type:'database',  label:'Database',      sublabel:'MySQL/MSSQL',   x:820, y:260 },
      { id:'exf',  type:'c2',        label:'Exfil Target',  sublabel:'Attacker Host', x:960, y:420 },
    ],
    defender: [
      { id:'waf',  type:'firewall',  label:'WAF',           sublabel:'Cloudflare',    x:320, y:100, _isDefender:true },
      { id:'ids',  type:'edr',       label:'IDS',           sublabel:'Snort',         x:820, y:100, _isDefender:true },
      { id:'siem', type:'siem',      label:'SIEM',          sublabel:'Splunk',        x:560, y:100, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk',  to:'web',  label:'HTTP request' },
    { id:'e2', from:'web',  to:'srv',  label:'forwarded request' },
    { id:'e3', from:'web',  to:'app',  label:'app logic' },
    { id:'e4', from:'app',  to:'db',   label:'SQL payload' },
    { id:'e5', from:'srv',  to:'db',   label:'SQL query' },
    { id:'e6', from:'db',   to:'exf',  label:'data exfiltrated' },
    { id:'de1', from:'waf', to:'web',  label:'input filter',   defenderOnly:true },
    { id:'de2', from:'ids', to:'db',   label:'query analysis', defenderOnly:true },
    { id:'de3', from:'siem',to:'app',  label:'anomaly log',    defenderOnly:true },
  ],
  phases: [
    { // 1: Application Reconnaissance
      attacker: { activeNodes:['atk','web'],           activeEdges:['e1'],           tools:['Burp Suite','nikto'] },
      defender: { activeNodes:['web','waf'],            activeEdges:['de1'],          detectionNodes:['waf'] },
      victim:   { activeNodes:['web'],                 activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 2: Injection Point Discovery
      attacker: { activeNodes:['atk','web','app'],      activeEdges:['e1','e3'],      tools:['sqlmap','Burp'] },
      defender: { activeNodes:['web','waf','siem'],     activeEdges:['de1','de3'],    detectionNodes:['waf'] },
      victim:   { activeNodes:['web'],                 activeEdges:['e1'],           compromisedNodes:[], unaware:true },
    },
    { // 3: Payload Crafting
      attacker: { activeNodes:['atk'],                 activeEdges:[],               tools:['sqlmap','manual'] },
      defender: { activeNodes:['siem'],                activeEdges:[],               detectionNodes:[] },
      victim:   { activeNodes:[],                      activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 4: Data Extraction
      attacker: { activeNodes:['app','db'],             activeEdges:['e4'],           tools:['sqlmap'] },
      defender: { activeNodes:['app','db','ids','siem'],activeEdges:['de2','de3'],    detectionNodes:['ids','siem'] },
      victim:   { activeNodes:['app','db'],             activeEdges:['e4'],           compromisedNodes:['db'], unaware:false },
    },
    { // 5: Privilege Escalation
      attacker: { activeNodes:['app','db'],             activeEdges:['e4','e5'],      tools:['xp_cmdshell','UDF'] },
      defender: { activeNodes:['db','ids','siem'],      activeEdges:['de2'],          detectionNodes:['ids'] },
      victim:   { activeNodes:['db'],                  activeEdges:[],               compromisedNodes:['db'], unaware:false },
    },
    { // 6: Data Exfiltration or Destruction
      attacker: { activeNodes:['db','exf'],             activeEdges:['e6'],           tools:['DNS exfil','DROP TABLE'] },
      defender: { activeNodes:['db','ids','siem'],      activeEdges:['de2'],          detectionNodes:['ids','siem'] },
      victim:   { activeNodes:['db'],                  activeEdges:['e6'],           compromisedNodes:['db','exf'], unaware:false },
    },
  ],
};
```

- [ ] **Step 2: Verify and commit**

Open `http://localhost:5000/attack-flows/sql-injection`. Check phase 4 attacker view shows "SQL payload" edge label. Defender phase 4 shows IDS + SIEM with DETECT badges.

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: add SQL injection topology (6 phases)"
```

---

## Task 6: Add man-in-the-middle topology (6 phases)

**Files:**
- Modify: `static/js/attack-flow-vis.js`

Phases: Network Positioning, Traffic Interception, SSL/TLS Downgrade, Session Hijacking, Data Manipulation, Covering Tracks

- [ ] **Step 1: Add the MitM topology**

```js
AF_TOPOLOGIES['man-in-the-middle'] = {
  nodes: {
    base: [
      { id:'vic',  type:'victim',    label:'Victim Device',  sublabel:'Windows/Mac',   x:90,  y:260 },
      { id:'rtr',  type:'router',    label:'Router / AP',    sublabel:'802.11',        x:350, y:380 },
      { id:'atk',  type:'attacker',  label:'Attacker',       sublabel:'MitM Position', x:560, y:260 },
      { id:'srv',  type:'server',    label:'Target Server',  sublabel:'HTTPS',         x:870, y:260 },
      { id:'cert', type:'browser',   label:'Fake Cert',      sublabel:'Self-Signed',   x:560, y:420 },
    ],
    defender: [
      { id:'ids',  type:'edr',       label:'IDS/IPS',        sublabel:'Suricata',      x:350, y:130, _isDefender:true },
      { id:'ca',   type:'server',    label:'Cert Monitor',   sublabel:'HSTS Preload',  x:870, y:120, _isDefender:true },
      { id:'siem', type:'siem',      label:'SIEM',           sublabel:'Splunk',        x:560, y:100, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'vic', to:'rtr',  label:'network traffic' },
    { id:'e2', from:'rtr', to:'atk',  label:'ARP poisoned' },
    { id:'e3', from:'atk', to:'srv',  label:'forwarded traffic' },
    { id:'e4', from:'atk', to:'cert', label:'fake cert served' },
    { id:'e5', from:'vic', to:'atk',  label:'intercepted session' },
    { id:'e6', from:'atk', to:'vic',  label:'manipulated response' },
    { id:'de1', from:'ids',to:'rtr',  label:'ARP watch',      defenderOnly:true },
    { id:'de2', from:'ca', to:'srv',  label:'cert validation', defenderOnly:true },
    { id:'de3', from:'siem',to:'atk', label:'anomaly detect', defenderOnly:true },
  ],
  phases: [
    { // 1: Network Positioning
      attacker: { activeNodes:['atk','rtr'],          activeEdges:['e2'],           tools:['arpspoof','Ettercap'] },
      defender: { activeNodes:['rtr','ids'],           activeEdges:['de1'],          detectionNodes:['ids'] },
      victim:   { activeNodes:['vic'],                activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 2: Traffic Interception
      attacker: { activeNodes:['vic','rtr','atk'],    activeEdges:['e1','e2'],      tools:['Ettercap','Wireshark'] },
      defender: { activeNodes:['rtr','ids','siem'],   activeEdges:['de1','de3'],    detectionNodes:['ids'] },
      victim:   { activeNodes:['vic','rtr'],          activeEdges:['e1'],           compromisedNodes:[], unaware:true },
    },
    { // 3: SSL/TLS Downgrade
      attacker: { activeNodes:['atk','cert'],         activeEdges:['e4'],           tools:['sslstrip','mitmproxy'] },
      defender: { activeNodes:['ca','siem'],          activeEdges:['de2'],          detectionNodes:['ca'] },
      victim:   { activeNodes:['vic','cert'],         activeEdges:['e4'],           compromisedNodes:[], unaware:false },
    },
    { // 4: Session Hijacking
      attacker: { activeNodes:['vic','atk'],          activeEdges:['e5'],           tools:['Burp Suite'] },
      defender: { activeNodes:['siem','ids'],         activeEdges:['de3'],          detectionNodes:['siem'] },
      victim:   { activeNodes:['vic'],               activeEdges:['e5'],           compromisedNodes:['vic'], unaware:false },
    },
    { // 5: Data Manipulation
      attacker: { activeNodes:['atk','vic','srv'],    activeEdges:['e3','e6'],      tools:['mitmproxy'] },
      defender: { activeNodes:['siem','ca'],          activeEdges:['de2','de3'],    detectionNodes:['siem','ca'] },
      victim:   { activeNodes:['vic'],               activeEdges:['e6'],           compromisedNodes:['vic'], unaware:false },
    },
    { // 6: Covering Tracks
      attacker: { activeNodes:['atk'],               activeEdges:[],               tools:['log wipe'] },
      defender: { activeNodes:['siem'],              activeEdges:['de3'],          detectionNodes:['siem'] },
      victim:   { activeNodes:['vic'],               activeEdges:[],               compromisedNodes:['vic'], unaware:false },
    },
  ],
};
```

- [ ] **Step 2: Verify and commit**

Open `http://localhost:5000/attack-flows/man-in-the-middle`. Check phase 2 shows "ARP poisoned" edge label. Victim phase 4 shows victim device with `!` badge.

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: add man-in-the-middle topology (6 phases)"
```

---

## Task 7: Add ransomware topology (7 phases)

**Files:**
- Modify: `static/js/attack-flow-vis.js`

Phases: Initial Access, Establishing Foothold, Privilege Escalation, Network Discovery, Lateral Movement, Data Staging & Exfiltration, Encryption & Ransom Demand

- [ ] **Step 1: Add the ransomware topology**

```js
AF_TOPOLOGIES['ransomware'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker',    label:'Attacker',         sublabel:'Threat Actor',    x:90,  y:260 },
      { id:'vic',  type:'victim',      label:'Victim Workstation',sublabel:'Windows',        x:290, y:260 },
      { id:'c2',   type:'c2',          label:'C2 Server',        sublabel:'TOR/VPS',         x:490, y:120 },
      { id:'dc',   type:'server',      label:'Domain Controller',sublabel:'Active Directory',x:720, y:120 },
      { id:'fs',   type:'database',    label:'File Server',      sublabel:'SMB Share',       x:720, y:260 },
      { id:'bak',  type:'server',      label:'Backup Server',    sublabel:'Network Backup',  x:720, y:420 },
      { id:'enc',  type:'database',    label:'Encrypted Files',  sublabel:'Locked Data',     x:960, y:260 },
    ],
    defender: [
      { id:'edr',  type:'edr',         label:'EDR Agent',        sublabel:'CrowdStrike',     x:290, y:100, _isDefender:true },
      { id:'siem', type:'siem',        label:'SIEM',             sublabel:'Splunk',          x:960, y:120, _isDefender:true },
      { id:'bakm', type:'firewall',    label:'Backup Monitor',   sublabel:'Veeam',           x:960, y:420, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk',  to:'vic',  label:'phishing email' },
    { id:'e2', from:'vic',  to:'c2',   label:'beacon callback' },
    { id:'e3', from:'c2',   to:'dc',   label:'credential dump' },
    { id:'e4', from:'dc',   to:'vic',  label:'privilege escalated' },
    { id:'e5', from:'vic',  to:'fs',   label:'lateral movement' },
    { id:'e6', from:'fs',   to:'bak',  label:'shadow copy delete' },
    { id:'e7', from:'fs',   to:'enc',  label:'file encryption' },
    { id:'e8', from:'bak',  to:'enc',  label:'backup encrypted' },
    { id:'de1', from:'edr', to:'vic',  label:'behaviour monitor', defenderOnly:true },
    { id:'de2', from:'siem',to:'dc',   label:'log analysis',      defenderOnly:true },
    { id:'de3', from:'bakm',to:'bak',  label:'integrity check',   defenderOnly:true },
  ],
  phases: [
    { // 1: Initial Access
      attacker: { activeNodes:['atk','vic'],              activeEdges:['e1'],           tools:['GoPhish','macros'] },
      defender: { activeNodes:['vic','edr'],              activeEdges:['de1'],          detectionNodes:['edr'] },
      victim:   { activeNodes:['vic'],                   activeEdges:['e1'],           compromisedNodes:[], unaware:false },
    },
    { // 2: Establishing Foothold
      attacker: { activeNodes:['vic','c2'],               activeEdges:['e2'],           tools:['Cobalt Strike','Metasploit'] },
      defender: { activeNodes:['vic','edr','siem'],       activeEdges:['de1','de2'],    detectionNodes:['edr','siem'] },
      victim:   { activeNodes:['vic'],                   activeEdges:['e2'],           compromisedNodes:['vic'], unaware:false },
    },
    { // 3: Privilege Escalation
      attacker: { activeNodes:['c2','dc'],                activeEdges:['e3'],           tools:['Mimikatz','BloodHound'] },
      defender: { activeNodes:['dc','siem'],              activeEdges:['de2'],          detectionNodes:['siem'] },
      victim:   { activeNodes:['vic'],                   activeEdges:[],               compromisedNodes:['vic'], unaware:false },
    },
    { // 4: Network Discovery
      attacker: { activeNodes:['vic','dc'],               activeEdges:['e4'],           tools:['ADRecon','nmap'] },
      defender: { activeNodes:['dc','siem','edr'],        activeEdges:['de1','de2'],    detectionNodes:['siem'] },
      victim:   { activeNodes:['vic','dc'],               activeEdges:[],               compromisedNodes:['vic'], unaware:false },
    },
    { // 5: Lateral Movement
      attacker: { activeNodes:['vic','fs'],               activeEdges:['e5'],           tools:['PsExec','WMI'] },
      defender: { activeNodes:['vic','edr','siem'],       activeEdges:['de1','de2'],    detectionNodes:['edr','siem'] },
      victim:   { activeNodes:['vic','fs'],               activeEdges:['e5'],           compromisedNodes:['vic','fs'], unaware:false },
    },
    { // 6: Data Staging & Exfiltration
      attacker: { activeNodes:['fs','bak'],               activeEdges:['e6'],           tools:['rclone','Rclone'] },
      defender: { activeNodes:['bak','bakm','siem'],      activeEdges:['de2','de3'],    detectionNodes:['bakm','siem'] },
      victim:   { activeNodes:['fs','bak'],               activeEdges:['e6'],           compromisedNodes:['fs','bak'], unaware:false },
    },
    { // 7: Encryption & Ransom Demand
      attacker: { activeNodes:['fs','bak','enc'],         activeEdges:['e7','e8'],      tools:['LockBit','REvil'] },
      defender: { activeNodes:['edr','siem','bakm'],      activeEdges:['de1','de3'],    detectionNodes:['edr','siem','bakm'] },
      victim:   { activeNodes:['fs','bak','enc'],         activeEdges:['e7','e8'],      compromisedNodes:['fs','bak','enc'], unaware:false },
    },
  ],
};
```

- [ ] **Step 2: Verify and commit**

Open `http://localhost:5000/attack-flows/ransomware`. Check phase 7 victim view shows all three file nodes with `!` badges.

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: add ransomware topology (7 phases)"
```

---

## Task 8: Add lateral-movement topology (6 phases)

**Files:**
- Modify: `static/js/attack-flow-vis.js`

Phases: Initial Compromise, Internal Reconnaissance, Credential Harvesting, Pivoting to Adjacent Systems, Privilege Escalation, Establishing Domain Dominance

- [ ] **Step 1: Add the lateral-movement topology**

```js
AF_TOPOLOGIES['lateral-movement'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker',    label:'Attacker Foothold', sublabel:'Compromised PC', x:90,  y:260 },
      { id:'h1',   type:'workstation', label:'Workstation A',     sublabel:'Internal PC',    x:310, y:260 },
      { id:'ad',   type:'server',      label:'Active Directory',  sublabel:'AD Server',      x:550, y:140 },
      { id:'dc',   type:'server',      label:'Domain Controller', sublabel:'DC',             x:780, y:140 },
      { id:'h2',   type:'workstation', label:'Workstation B',     sublabel:'Target PC',      x:550, y:400 },
      { id:'fs',   type:'database',    label:'File Server',       sublabel:'SMB',            x:960, y:260 },
    ],
    defender: [
      { id:'edr',  type:'edr',         label:'EDR Agent',         sublabel:'CrowdStrike',    x:310, y:100, _isDefender:true },
      { id:'ids',  type:'edr',         label:'Network IDS',       sublabel:'Suricata',       x:780, y:400, _isDefender:true },
      { id:'siem', type:'siem',        label:'SIEM',              sublabel:'Splunk',         x:960, y:100, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk',  to:'h1',  label:'initial compromise' },
    { id:'e2', from:'h1',   to:'ad',  label:'LDAP enumeration' },
    { id:'e3', from:'h1',   to:'h2',  label:'pass-the-hash' },
    { id:'e4', from:'ad',   to:'dc',  label:'Kerberoasting' },
    { id:'e5', from:'dc',   to:'fs',  label:'domain admin access' },
    { id:'e6', from:'h2',   to:'fs',  label:'remote execution' },
    { id:'de1', from:'edr', to:'h1',  label:'process watch',    defenderOnly:true },
    { id:'de2', from:'ids', to:'h2',  label:'lateral detect',   defenderOnly:true },
    { id:'de3', from:'siem',to:'dc',  label:'log correlation',  defenderOnly:true },
  ],
  phases: [
    { // 1: Initial Compromise
      attacker: { activeNodes:['atk','h1'],           activeEdges:['e1'],           tools:['Metasploit','phish'] },
      defender: { activeNodes:['h1','edr'],            activeEdges:['de1'],          detectionNodes:['edr'] },
      victim:   { activeNodes:['h1'],                 activeEdges:['e1'],           compromisedNodes:['h1'], unaware:false },
    },
    { // 2: Internal Reconnaissance
      attacker: { activeNodes:['h1','ad'],             activeEdges:['e2'],           tools:['BloodHound','ADRecon'] },
      defender: { activeNodes:['h1','edr','siem'],     activeEdges:['de1','de3'],    detectionNodes:['edr'] },
      victim:   { activeNodes:['h1'],                 activeEdges:[],               compromisedNodes:['h1'], unaware:false },
    },
    { // 3: Credential Harvesting
      attacker: { activeNodes:['h1','ad'],             activeEdges:['e2'],           tools:['Mimikatz','secretsdump'] },
      defender: { activeNodes:['h1','edr','siem'],     activeEdges:['de1'],          detectionNodes:['edr','siem'] },
      victim:   { activeNodes:['h1','ad'],             activeEdges:[],               compromisedNodes:['h1'], unaware:false },
    },
    { // 4: Pivoting to Adjacent Systems
      attacker: { activeNodes:['h1','h2'],             activeEdges:['e3'],           tools:['PsExec','WMI'] },
      defender: { activeNodes:['h1','h2','ids','edr'], activeEdges:['de1','de2'],    detectionNodes:['ids','edr'] },
      victim:   { activeNodes:['h1','h2'],             activeEdges:['e3'],           compromisedNodes:['h1','h2'], unaware:false },
    },
    { // 5: Privilege Escalation
      attacker: { activeNodes:['ad','dc'],             activeEdges:['e4'],           tools:['Rubeus','Kerberoast'] },
      defender: { activeNodes:['dc','siem'],           activeEdges:['de3'],          detectionNodes:['siem'] },
      victim:   { activeNodes:['h1','h2'],             activeEdges:[],               compromisedNodes:['h1','h2'], unaware:false },
    },
    { // 6: Establishing Domain Dominance
      attacker: { activeNodes:['dc','fs','h2'],        activeEdges:['e5','e6'],      tools:['DCSync','Golden Ticket'] },
      defender: { activeNodes:['dc','siem','ids'],     activeEdges:['de2','de3'],    detectionNodes:['siem'] },
      victim:   { activeNodes:['h1','h2','fs'],        activeEdges:['e5','e6'],      compromisedNodes:['h1','h2','fs'], unaware:false },
    },
  ],
};
```

- [ ] **Step 2: Verify and commit**

Open `http://localhost:5000/attack-flows/lateral-movement`. Check phase 4 shows "pass-the-hash" edge label.

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: add lateral-movement topology (6 phases)"
```

---

## Task 9: Add supply-chain-attack topology (5 phases)

**Files:**
- Modify: `static/js/attack-flow-vis.js`

Phases: Vendor/Dependency Identification, Compromise of Build Pipeline, Malicious Payload Injection, Distribution via Trusted Channels, Downstream Exploitation

- [ ] **Step 1: Add the supply-chain-attack topology**

```js
AF_TOPOLOGIES['supply-chain-attack'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker',  label:'Attacker',        sublabel:'Threat Actor',      x:90,  y:260 },
      { id:'repo', type:'browser',   label:'OSS Repository',  sublabel:'GitHub',            x:310, y:260 },
      { id:'ci',   type:'server',    label:'CI/CD Pipeline',  sublabel:'GitHub Actions',    x:560, y:260 },
      { id:'pkg',  type:'registry',  label:'Package Registry',sublabel:'npm/PyPI',          x:780, y:260 },
      { id:'oa',   type:'victim',    label:'Org A',           sublabel:'Downstream Victim', x:960, y:140 },
      { id:'ob',   type:'victim',    label:'Org B',           sublabel:'Downstream Victim', x:960, y:260 },
      { id:'oc',   type:'victim',    label:'Org C',           sublabel:'Downstream Victim', x:960, y:400 },
    ],
    defender: [
      { id:'scan', type:'edr',       label:'Dep Scanner',     sublabel:'Snyk',              x:560, y:100, _isDefender:true },
      { id:'sign', type:'firewall',  label:'Code Signing',    sublabel:'Sigstore',          x:780, y:100, _isDefender:true },
      { id:'siem', type:'siem',      label:'SIEM',            sublabel:'Splunk',            x:960, y:100, _isDefender:true }, // Note: x=960 same col as victims — place at y=100 top row
    ],
  },
  edges: [
    { id:'e1', from:'atk',  to:'repo', label:'malicious commit' },
    { id:'e2', from:'repo', to:'ci',   label:'triggers build' },
    { id:'e3', from:'ci',   to:'pkg',  label:'poisoned package' },
    { id:'e4', from:'pkg',  to:'oa',   label:'trojanized binary' },
    { id:'e5', from:'pkg',  to:'ob',   label:'trojanized binary' },
    { id:'e6', from:'pkg',  to:'oc',   label:'trojanized binary' },
    { id:'de1', from:'scan',to:'ci',   label:'dep audit',      defenderOnly:true },
    { id:'de2', from:'sign',to:'pkg',  label:'sig verify',     defenderOnly:true },
    { id:'de3', from:'siem',to:'oa',   label:'call-home detect',defenderOnly:true },
  ],
  phases: [
    { // 1: Vendor/Dependency Identification
      attacker: { activeNodes:['atk','repo'],              activeEdges:[],               tools:['GitHub search','deps.dev'] },
      defender: { activeNodes:['scan'],                    activeEdges:[],               detectionNodes:[] },
      victim:   { activeNodes:[],                          activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 2: Compromise of Build Pipeline
      attacker: { activeNodes:['atk','repo','ci'],         activeEdges:['e1','e2'],      tools:['git commit','Actions inject'] },
      defender: { activeNodes:['repo','ci','scan'],        activeEdges:['de1'],          detectionNodes:['scan'] },
      victim:   { activeNodes:[],                          activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 3: Malicious Payload Injection
      attacker: { activeNodes:['ci','pkg'],                activeEdges:['e3'],           tools:['npm publish','typosquatting'] },
      defender: { activeNodes:['ci','scan','sign'],        activeEdges:['de1','de2'],    detectionNodes:['scan','sign'] },
      victim:   { activeNodes:[],                          activeEdges:[],               compromisedNodes:[], unaware:true },
    },
    { // 4: Distribution via Trusted Channels
      attacker: { activeNodes:['pkg','oa','ob','oc'],      activeEdges:['e4','e5','e6'], tools:['npm install','pip install'] },
      defender: { activeNodes:['pkg','sign','siem'],       activeEdges:['de2','de3'],    detectionNodes:['sign','siem'] },
      victim:   { activeNodes:['oa','ob','oc'],            activeEdges:['e4','e5','e6'], compromisedNodes:[], unaware:false },
    },
    { // 5: Downstream Exploitation
      attacker: { activeNodes:['oa','ob','oc'],            activeEdges:['e4','e5','e6'], tools:['backdoor call-home'] },
      defender: { activeNodes:['siem','oa'],               activeEdges:['de3'],          detectionNodes:['siem'] },
      victim:   { activeNodes:['oa','ob','oc'],            activeEdges:[],               compromisedNodes:['oa','ob','oc'], unaware:false },
    },
  ],
};
```

- [ ] **Step 2: Verify and commit**

Open `http://localhost:5000/attack-flows/supply-chain-attack`. Check phase 4 shows "trojanized binary" labels on the three fan-out edges. Phase 5 victim view shows all 3 org nodes with `!` badges.

```bash
git add static/js/attack-flow-vis.js
git commit -m "feat: add supply-chain-attack topology (5 phases)"
```

---

## Task 10: Final cross-attack verification and polish

**Files:**
- Modify: `static/js/attack-flow-vis.js` (minor fixes only if needed)
- Modify: `templates/attack_flow_detail.html` (minor fixes only if needed)

- [ ] **Step 1: Walk every attack through all phases in all 3 perspectives**

Visit each URL and step through all phases in attacker → defender → victim order:

```
http://localhost:5000/attack-flows/phishing
http://localhost:5000/attack-flows/brute-force
http://localhost:5000/attack-flows/sql-injection
http://localhost:5000/attack-flows/man-in-the-middle
http://localhost:5000/attack-flows/ransomware
http://localhost:5000/attack-flows/lateral-movement
http://localhost:5000/attack-flows/supply-chain-attack
```

Checklist per attack:
- [ ] All phase edge labels visible and not overlapping nodes
- [ ] Defender nodes appear only in defender perspective
- [ ] Victim ghosting works (early phases show faded infrastructure)
- [ ] Compromised badges appear in victim perspective at correct phases
- [ ] Tool badges appear in attacker perspective on correct phases
- [ ] DETECT badges appear on correct defender nodes
- [ ] Scan beam animates in defender perspective
- [ ] Amber vignette appears in victim perspective
- [ ] Phase navigation steps through correct number of phases
- [ ] No JS console errors on any attack

- [ ] **Step 2: Fix any edge label overlap issues**

If edge labels overlap nodes or each other, adjust `x/y` positions on the relevant nodes in that topology. For example, if the phishing "stolen credentials" label overlaps the Fake Login Page node, shift `fake` node slightly: change `y:420` to `y:440`.

- [ ] **Step 3: Fix any defender node positioning issues**

If defender nodes overlap the main attack path, adjust their `x/y` coordinates. Defender nodes should sit clearly above (`y:80–130`) or below (`y:420–460`) the main path (`y:260`).

- [ ] **Step 4: Commit any fixes**

```bash
git add static/js/attack-flow-vis.js templates/attack_flow_detail.html
git commit -m "fix: polish node positions and edge label placement across all attacks"
```

---

## Self-Review Against Spec

**Spec requirement → Task coverage:**

| Spec requirement | Covered in |
|---|---|
| Diagram fills container (no cramped layout) | Task 1 (viewBox 1100×520, no max-height) |
| Inline edge labels | Task 2 (renderer `_drawEdges` inline text) |
| Specific node labels + sublabels | Task 2 (renderer `_drawNodes` label+sublabel) |
| Dark theme `#0d1117` | Task 2 (bgColor fallback `#0d1117`) |
| Animated active path | Task 2 (`af-edge-active` dash animation, traveling dots) |
| Node type icons | Task 2 (`AF_ICONS` map, 14 types) |
| Attacker: red path, tool badges | Task 2 (`_drawOverlays` attacker branch) |
| Defender: blue detection nodes, SIEM/Firewall/EDR | Task 2 (`_resolveNodes` defender branch, `_drawNodes` detection) |
| Defender: scan beam | Task 2 (`_startScanBeam`) |
| Victim: ghosting of unknown infrastructure | Task 2 (`isGhost` at 10% opacity) |
| Victim: compromised badges | Task 2 (red `!` badge on `compromisedNodes`) |
| Victim: amber vignette | Task 2 (`_ensureVignetteGradient`) |
| Phishing topology (6 phases) | Task 3 |
| Brute force topology (5 phases) | Task 4 |
| SQL injection topology (6 phases) | Task 5 |
| Man-in-the-middle topology (6 phases) | Task 6 |
| Ransomware topology (7 phases) | Task 7 |
| Lateral movement topology (6 phases) | Task 8 |
| Supply chain attack topology (5 phases) | Task 9 |
| Cross-attack verification | Task 10 |
| New icon symbols (firewall, siem, edr, c2) | Task 1 |
| CSS animation classes (detectPulse, nodeGlowPulse) | Task 1 |
| No Flask changes | ✓ (no route files touched) |
| No `attack_flows.json` changes | ✓ (data file untouched) |
| Alpine component API unchanged | Task 2 (same methods, same `_AF` injection) |
