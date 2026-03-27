# Attack Flow Visualization Redesign

**Date:** 2026-03-27
**Status:** Approved
**Files affected:** `static/js/attack-flow-vis.js`, `templates/attack_flow_detail.html`

---

## Goal

Redesign the attack flow SVG visualization to be the primary teacher — a viewer should understand what is happening purely from the diagram, without reading the text panel. The current diagram is too small, node labels are generic, edges have no labels, and all three perspective tabs show the same visual state.

---

## Decisions Made

- **Layout:** 60% diagram / 40% narrative panel (stacked vertically)
- **Node style:** Network diagram boxes (rounded rectangles, 72×56px) with SVG stroke icon + type label inside + sublabel (tool/OS/protocol)
- **Perspective switching:** All three modes combined:
  - **A** — recolored path per perspective (red/blue/amber)
  - **B** — defender view adds extra nodes (Firewall, SIEM, EDR) that don't exist in other views
  - **C** — victim view ghosts out infrastructure the victim can't see; victim's machine glows amber with damage badges
- **Implementation approach:** Full rewrite of `attack-flow-vis.js` with a new schema. Template gets targeted updates (larger SVG, updated narrative panel). No Flask changes.

---

## New Topology Schema

Each attack slug maps to a topology object:

```js
'phishing': {
  nodes: {
    base: [
      // Always rendered in all perspectives
      { id, type, label, sublabel, x, y }
    ],
    defender: [
      // Only rendered in defender perspective, shown in blue
      { id, type, label, sublabel, x, y }
    ]
  },
  edges: [
    // defenderOnly:true edges only render in defender perspective
    { id, from, to, label, defenderOnly? }
  ],
  phases: [
    {
      attacker: { activeNodes[], activeEdges[], tools[] },
      defender: { activeNodes[], activeEdges[], detectionNodes[] },
      victim:   { activeNodes[], activeEdges[], compromisedNodes[], unaware }
    }
  ]
}
```

**Node types** (drives icon selection): `attacker`, `server`, `cloud`, `victim`, `firewall`, `siem`, `edr`, `database`, `c2`, `router`, `workstation`, `registry`

**`unaware: true`** — all base nodes not in `activeNodes` render at 12% opacity in victim perspective (victim can't see attacker infrastructure).

**`detectionNodes[]`** — in defender perspective, these nodes get a blue pulsing ring + `DETECT` badge overlay.

**`compromisedNodes[]`** — in victim perspective, these nodes get amber glow + red `!` badge overlay.

---

## Per-Attack Topology Plan

### Phishing (6 phases)
**Base nodes:** Attacker (Kali Linux), Mail Server (SMTP/587), Internet (Public Routing), Victim Workstation (Windows 11), Fake Login Page (Evilginx2), C2 Server (VPS/TOR)
**Defender nodes:** Email Gateway (Proofpoint), SIEM (Splunk), EDR Agent (CrowdStrike)
**Key edge labels:** spoofed email, relayed message, delivered to inbox, clicks link, stolen credentials, exfil data
**Defender edges:** scans headers (gateway→mail), log ingestion (SIEM→workstation), process monitor (EDR→workstation)

### Brute Force (5 phases)
**Base nodes:** Attacker (Kali Linux), Credential List (Wordlist), Login Portal (Web App), Auth Server (LDAP/AD), Victim Account (Compromised)
**Defender nodes:** WAF (ModSecurity), Rate Limiter (Nginx), SIEM (Splunk)
**Key edge labels:** credential list loaded, auth request, brute force attempt, account lockout bypass, session token stolen

### SQL Injection (5 phases)
**Base nodes:** Attacker (Browser/sqlmap), Web Application (Target Site), Web Server (Apache/Nginx), App Server (Python/PHP), Database (MySQL/MSSQL)
**Defender nodes:** WAF (Cloudflare), IDS (Snort), SIEM (Splunk)
**Key edge labels:** malicious input, HTTP request, parameterized query, SQL payload, data exfiltrated

### Man-in-the-Middle (6 phases — data has 6 phases, topology has 6 pm entries)
**Base nodes:** Victim Device (Windows), Router/AP (802.11), Attacker (MitM position), Target Server (HTTPS)
**Defender nodes:** IDS/IPS (Suricata), Certificate Monitor (HSTS), SIEM (Splunk)
**Key edge labels:** ARP spoof, poisoned ARP table, intercepted traffic, decrypted session, replayed request

### Ransomware (7 phases)
**Base nodes:** Attacker (Kali Linux), Victim Workstation (Windows), C2 Server (TOR/VPS), File Server (SMB Share), Domain Controller (Active Directory), Backup Server (Network Backup), Encrypted Files (Locked Data)
**Defender nodes:** EDR Agent (CrowdStrike), SIEM (Splunk), Backup Monitor (Veeam)
**Key edge labels:** phishing email, beacon callback, privilege escalation, lateral movement, shadow copy deletion, file encryption, ransom note

### Lateral Movement (6 phases)
**Base nodes:** Attacker Foothold (Compromised PC), Workstation A (Internal PC), Active Directory (AD Server), Domain Controller (DC), Workstation B (Target PC), File Server (SMB)
**Defender nodes:** EDR Agent (CrowdStrike), Network IDS (Suricata), SIEM (Splunk)
**Key edge labels:** initial compromise, credential dump, NTLM hash captured, pass-the-hash, remote execution, persistence established

### Supply Chain Attack (5 phases)
**Base nodes:** Attacker (Threat Actor), Open Source Repo (GitHub), CI/CD Pipeline (GitHub Actions), Package Registry (npm/PyPI), Org A / Org B / Org C (Downstream Victims)
**Defender nodes:** Dependency Scanner (Snyk), Code Signing Monitor (Sigstore), SIEM (Splunk)
**Key edge labels:** malicious commit, poisoned package published, trojanized binary distributed, backdoor call-home

---

## Renderer Architecture

**`AFRenderer` class — new render pipeline:**

```
render(attackTopo, phaseIndex, perspective)
  │
  ├─ _resolveNodes(topo, perspective)
  │    → base nodes always + defender nodes if perspective === 'defender'
  │
  ├─ _resolveEdges(topo, perspective)
  │    → all edges; defenderOnly edges filtered unless perspective === 'defender'
  │
  ├─ _getPhaseState(topo, phaseIndex, perspective)
  │    → { activeNodes, activeEdges, detectionNodes, compromisedNodes, unaware, tools }
  │
  ├─ _drawEdges(edges, state, colors)
  │    Active:   colored gradient stroke, 2px, dashed animation, traveling dot, inline label
  │    Inactive: #21262d, 1px, no label, no animation
  │    Defender-only: dashed style always, blue
  │
  ├─ _drawNodes(nodes, state, perspective, colors)
  │    Active base:      colored border+glow, icon colored, label white, sublabel muted
  │    Inactive base:    dim border, dim icon/label
  │    Ghosted (unaware):12% opacity entire node group
  │    Defender node:    blue border+glow, always full opacity in defender view
  │    Detection node:   blue pulsing ring + DETECT badge
  │    Compromised node: amber border+glow + red ! badge
  │
  └─ _drawOverlays(state, perspective, colors)
       Attacker: tool name badges floating above active attacker node
       Defender: blue scan beam sweep across SVG
       Victim:   amber vignette gradient around SVG edges
```

**Edge inline labels** — rendered as SVG `<text>` centered on the edge midpoint, 9px monospace, perspective accent color, only on active edges. Uses `dx/dy` offset to float slightly above the line (not on a textPath, to avoid rotation issues with bidirectional edges). Label has a semi-transparent dark background rect behind it for legibility over grid.

**Tooltip** — on node hover, shows: `label` (bold white), `sublabel` (muted), active/inactive status in perspective accent color. Same fixed-position div as before.

**Node rendering** (72×56px rounded rect, radius 4):
```
┌───────────────┐
│   [24px icon] │  stroke icon, colored per state
│  LABEL CAPS   │  9px monospace, white active / #4a5568 inactive
│   sublabel    │  8px monospace, #8b949e
└───────────────┘
```

**SVG viewBox:** `0 0 1100 520` (up from `0 0 1000 400`) — extra height accommodates defender nodes above/below attack path. Defender nodes positioned on y=80 (above main path at y=260) or y=440 (below).

---

## Visual Styling

**Per-perspective colors:**

| Perspective | Accent | Glow RGBA | Node bg | Badge bg |
|---|---|---|---|---|
| Attacker | `#ef4444` | `rgba(239,68,68,0.35)` | `#1a0000` | `#1a0000` |
| Defender | `#3b82f6` | `rgba(59,130,246,0.35)` | `#001020` | `#001020` |
| Victim | `#f59e0b` | `rgba(245,158,11,0.35)` | `#1a1000` | `#1a1000` |

**New CSS animations added to template:**
- `flowDash` — edge dash offset, 1.2s linear infinite (keep existing)
- `nodeBreath` — keep existing (animates the SVG `circle` r attribute for glow ring; SVG nodes are `<rect>` not HTML so `box-shadow` doesn't apply — glow is handled via existing `filter:url(#glow-r/b/a)` on the node group)
- `travelDot` — SMIL `<animate>` on dot `cx/cy` along edge, 1.5s (inline in JS, not CSS)
- `detectPulse` — opacity 0.6→1.0, 1.4s ease-in-out infinite (CSS class for defender detection ring elements)
- `narrativeIn` — opacity + translateY, 0.25s ease (keep existing)

**New SVG icon symbols needed** (added to template `<defs>`):
- `ic-firewall` — shield with horizontal bars
- `ic-siem` — document with bar chart lines
- `ic-edr` — shield with checkmark
- `ic-c2` — server with antenna/signal lines
- `ic-workstation` — desktop monitor (already exists as `ic-monitor`, reuse)
- `ic-registry` — package/box (already exists as `ic-box`, reuse)

Existing symbols kept: `ic-laptop`, `ic-server`, `ic-person`, `ic-envelope`, `ic-database`, `ic-shield`, `ic-cloud`, `ic-browser`, `ic-router`, `ic-gear`, `ic-box`, `ic-monitor`

---

## Template Changes (`attack_flow_detail.html`)

1. **SVG viewBox** → `0 0 1100 520`, remove `max-height:400px` constraint
2. **Background grid rect** → update to `1100 520`
3. **Vignette rect** → update to `1100 520`
4. **Add new `<symbol>` defs** for `ic-firewall`, `ic-siem`, `ic-edr`, `ic-c2`
5. **Add new CSS animations** `nodeGlow`, `detectPulse`
6. **Narrative panel** — no structural changes needed; existing layout works for 60/40

The Alpine component interface (`attackFlow()`) remains identical — same methods, same `_AF` injection, same tab structure. Only the renderer and topology data change.

---

## What Does NOT Change

- Flask routes
- `attack_flows.json` data (phases, descriptions, MITRE IDs, tools — all unchanged)
- Alpine.js component API (`setPerspective`, `setPhase`, `nextPhase`, `prevPhase`, `currentData`)
- `_AF` Jinja injection
- Narrative panel content (still reads from `_AF.phases[i][perspective]`)
- Related attacks section
- Header section
- Phase navigation bar

---

## File Change Summary

| File | Change type | Scope |
|---|---|---|
| `static/js/attack-flow-vis.js` | Full rewrite | New schema, new renderer, all 7 topologies |
| `templates/attack_flow_detail.html` | Targeted edits | SVG viewBox, new icon symbols, new CSS animations |
