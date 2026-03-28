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
// Node type descriptions — shown in tooltip for zero-knowledge comprehension
// ─────────────────────────────────────────────────────────────────────────────
const AF_NODE_DESC = {
  attacker:    'The threat actor performing the attack',
  server:      'A networked computer providing services',
  cloud:       'Internet or cloud infrastructure',
  victim:      'The targeted user or device',
  firewall:    'Security tool that filters network traffic',
  siem:        'SIEM — Security Information & Event Management; collects and analyzes security logs',
  edr:         'EDR — Endpoint Detection & Response; monitors devices for threats',
  database:    'Stores application or user data',
  c2:          'C2 — Command & Control; attacker\'s remote server for managing malware',
  router:      'Network device that routes traffic between systems',
  workstation: 'A user\'s desktop or laptop computer',
  registry:    'Package or software repository',
  browser:     'Web browser or web application',
  envelope:    'Email server or mail gateway',
};

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

AF_TOPOLOGIES['phishing'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker', label:'Attacker',           sublabel:'Kali Linux',     x:120, y:300 },
      { id:'mail', type:'envelope', label:'Mail Server',        sublabel:'SMTP/587',       x:360, y:300 },
      { id:'inet', type:'cloud',    label:'Internet',           sublabel:'Public Routing', x:600, y:300 },
      { id:'usr',  type:'victim',   label:'Victim Workstation', sublabel:'Windows 11',     x:840, y:300 },
      { id:'fake', type:'browser',  label:'Fake Login Page',    sublabel:'Evilginx2',      x:840, y:480 },
      { id:'c2',   type:'c2',       label:'C2 Server',          sublabel:'VPS/TOR',        x:840, y:120 },
    ],
    defender: [
      { id:'fw',   type:'firewall', label:'Email Gateway', sublabel:'Proofpoint',  x:480, y:120, _isDefender:true },
      { id:'siem', type:'siem',     label:'SIEM',          sublabel:'Splunk',      x:720, y:120, _isDefender:true },
      { id:'edr',  type:'edr',      label:'EDR Agent',     sublabel:'CrowdStrike', x:960, y:480, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk',  to:'mail', label:'spoofed email' },
    { id:'e2', from:'mail', to:'inet', label:'relayed message' },
    { id:'e3', from:'inet', to:'usr',  label:'delivered to inbox' },
    { id:'e4', from:'usr',  to:'fake', label:'clicks link' },
    { id:'e5', from:'fake', to:'c2',   label:'stolen credentials' },
    { id:'e6', from:'c2',   to:'atk',  label:'exfil data' },
    { id:'de1', from:'fw',   to:'mail', label:'header scan',     defenderOnly:true },
    { id:'de2', from:'siem', to:'usr',  label:'log ingestion',   defenderOnly:true },
    { id:'de3', from:'edr',  to:'usr',  label:'process monitor', defenderOnly:true },
  ],
  phases: [
    { attacker:{ activeNodes:['atk'],                  activeEdges:[],          tools:['theHarvester','LinkedIn'] },
      defender:{ activeNodes:['atk'],                  activeEdges:[],          detectionNodes:[] },
      victim:  { activeNodes:[],                       activeEdges:[],          compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk'],                  activeEdges:[],          tools:['GoPhish','Evilginx2'] },
      defender:{ activeNodes:['atk'],                  activeEdges:[],          detectionNodes:[] },
      victim:  { activeNodes:[],                       activeEdges:[],          compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk','mail','inet'],    activeEdges:['e1','e2'], tools:['GoPhish'] },
      defender:{ activeNodes:['atk','mail','fw'],      activeEdges:['e1','de1'],detectionNodes:['fw'] },
      victim:  { activeNodes:['usr'],                  activeEdges:['e3'],      compromisedNodes:[], unaware:false } },
    { attacker:{ activeNodes:['usr','fake'],           activeEdges:['e4'],      tools:['Evilginx2'] },
      defender:{ activeNodes:['usr','siem'],           activeEdges:['de2'],     detectionNodes:['siem'] },
      victim:  { activeNodes:['usr','fake'],           activeEdges:['e4'],      compromisedNodes:[], unaware:false } },
    { attacker:{ activeNodes:['fake','c2'],            activeEdges:['e5'],      tools:['Evilginx2'] },
      defender:{ activeNodes:['usr','siem','edr'],     activeEdges:['de2','de3'],detectionNodes:['siem','edr'] },
      victim:  { activeNodes:['usr','fake'],           activeEdges:['e5'],      compromisedNodes:['usr'], unaware:false } },
    { attacker:{ activeNodes:['c2','atk'],             activeEdges:['e6'],      tools:['OAuth abuse'] },
      defender:{ activeNodes:['siem','edr'],           activeEdges:['de3'],     detectionNodes:['siem','edr'] },
      victim:  { activeNodes:['usr','c2'],             activeEdges:['e5','e6'], compromisedNodes:['usr','fake'], unaware:false } },
  ],
};

AF_TOPOLOGIES['brute-force'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker',  label:'Attacker',       sublabel:'Kali Linux',  x:120, y:220 },
      { id:'lst',  type:'database',  label:'Credential List',sublabel:'rockyou.txt', x:120, y:460 },
      { id:'lgn',  type:'browser',   label:'Login Portal',   sublabel:'Target App',  x:400, y:340 },
      { id:'auth', type:'server',    label:'Auth Server',    sublabel:'LDAP/AD',     x:640, y:200 },
      { id:'db',   type:'database',  label:'User Database',  sublabel:'PostgreSQL',  x:880, y:280 },
      { id:'acc',  type:'victim',    label:'Victim Account', sublabel:'Compromised', x:880, y:480 },
    ],
    defender: [
      { id:'waf',  type:'firewall', label:'WAF',          sublabel:'ModSecurity', x:400, y:100, _isDefender:true },
      { id:'rate', type:'firewall', label:'Rate Limiter', sublabel:'Nginx',       x:640, y:460, _isDefender:true },
      { id:'siem', type:'siem',     label:'SIEM',         sublabel:'Splunk',      x:880, y:100, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'lst',  to:'atk',  label:'credential list loaded' },
    { id:'e2', from:'atk',  to:'lgn',  label:'brute force attempt' },
    { id:'e3', from:'lgn',  to:'auth', label:'credential check' },
    { id:'e4', from:'auth', to:'db',   label:'user lookup' },
    { id:'e5', from:'auth', to:'acc',  label:'session token stolen' },
    { id:'e6', from:'atk',  to:'auth', label:'account lockout bypass' },
    { id:'de1', from:'waf',  to:'lgn',  label:'rate check', defenderOnly:true },
    { id:'de2', from:'rate', to:'auth', label:'throttle',   defenderOnly:true },
    { id:'de3', from:'siem', to:'auth', label:'log analysis',defenderOnly:true },
  ],
  phases: [
    { attacker:{ activeNodes:['atk','lgn'],         activeEdges:['e2'],          tools:['nmap','Shodan'] },
      defender:{ activeNodes:['lgn','waf'],          activeEdges:['de1'],         detectionNodes:['waf'] },
      victim:  { activeNodes:['lgn'],                activeEdges:[],              compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk','lst'],          activeEdges:['e1'],          tools:['CeWL','hashcat'] },
      defender:{ activeNodes:['siem'],               activeEdges:[],              detectionNodes:[] },
      victim:  { activeNodes:[],                     activeEdges:[],              compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk','lgn','auth'],   activeEdges:['e2','e3'],     tools:['Hydra','Medusa'] },
      defender:{ activeNodes:['lgn','waf','rate'],   activeEdges:['de1','de2'],   detectionNodes:['waf','rate'] },
      victim:  { activeNodes:['lgn'],                activeEdges:['e2'],          compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['lgn','auth','db'],    activeEdges:['e3','e4','e6'],tools:['Hydra'] },
      defender:{ activeNodes:['auth','siem','rate'], activeEdges:['de2','de3'],   detectionNodes:['siem','rate'] },
      victim:  { activeNodes:['lgn','auth'],         activeEdges:['e3'],          compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['auth','acc'],         activeEdges:['e5'],          tools:['session abuse'] },
      defender:{ activeNodes:['siem','auth'],        activeEdges:['de3'],         detectionNodes:['siem'] },
      victim:  { activeNodes:['acc'],                activeEdges:['e5'],          compromisedNodes:['acc'], unaware:false } },
  ],
};

AF_TOPOLOGIES['sql-injection'] = {
  nodes: {
    base: [
      { id:'atk', type:'attacker', label:'Attacker',        sublabel:'sqlmap/manual', x:120, y:300 },
      { id:'web', type:'browser',  label:'Web Application', sublabel:'Target Site',   x:380, y:300 },
      { id:'srv', type:'server',   label:'Web Server',      sublabel:'Apache/Nginx',  x:620, y:150 },
      { id:'app', type:'server',   label:'App Server',      sublabel:'Python/PHP',    x:620, y:460 },
      { id:'db',  type:'database', label:'Database',        sublabel:'MySQL/MSSQL',   x:860, y:300 },
      { id:'exf', type:'c2',       label:'Exfil Target',    sublabel:'Attacker Host', x:860, y:490 },
    ],
    defender: [
      { id:'waf',  type:'firewall', label:'WAF',  sublabel:'Cloudflare', x:380, y:100, _isDefender:true },
      { id:'siem', type:'siem',     label:'SIEM', sublabel:'Splunk',     x:620, y:100, _isDefender:true },
      { id:'ids',  type:'edr',      label:'IDS',  sublabel:'Snort',      x:860, y:100, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk', to:'web', label:'malicious input' },
    { id:'e2', from:'web', to:'srv', label:'forwarded request' },
    { id:'e3', from:'web', to:'app', label:'app logic' },
    { id:'e4', from:'app', to:'db',  label:'SQL payload' },
    { id:'e5', from:'srv', to:'db',  label:'SQL query' },
    { id:'e6', from:'db',  to:'exf', label:'data exfiltrated' },
    { id:'e7', from:'app', to:'db',  label:'parameterized query', defenderOnly:true },
    { id:'de1', from:'waf',  to:'web', label:'input filter',   defenderOnly:true },
    { id:'de2', from:'ids',  to:'db',  label:'query analysis', defenderOnly:true },
    { id:'de3', from:'siem', to:'app', label:'anomaly log',    defenderOnly:true },
  ],
  phases: [
    { attacker:{ activeNodes:['atk','web'],            activeEdges:['e1'],            tools:['Burp Suite','nikto'] },
      defender:{ activeNodes:['web','waf'],             activeEdges:['de1'],           detectionNodes:['waf'] },
      victim:  { activeNodes:['web'],                  activeEdges:[],                compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk','web','app'],       activeEdges:['e1','e3'],       tools:['sqlmap','Burp'] },
      defender:{ activeNodes:['web','waf','siem'],      activeEdges:['de1','de3'],     detectionNodes:['waf'] },
      victim:  { activeNodes:['web'],                  activeEdges:['e1'],            compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk'],                  activeEdges:[],                tools:['sqlmap','manual'] },
      defender:{ activeNodes:['siem'],                 activeEdges:[],                detectionNodes:[] },
      victim:  { activeNodes:[],                       activeEdges:[],                compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['app','db'],              activeEdges:['e4'],            tools:['sqlmap'] },
      defender:{ activeNodes:['app','db','ids','siem'], activeEdges:['de2','de3','e7'],detectionNodes:['ids','siem'] },
      victim:  { activeNodes:['app','db'],              activeEdges:['e4'],            compromisedNodes:['db'], unaware:false } },
    { attacker:{ activeNodes:['app','db'],              activeEdges:['e4','e5'],       tools:['xp_cmdshell','UDF'] },
      defender:{ activeNodes:['db','ids','siem'],       activeEdges:['de2','e7'],      detectionNodes:['ids'] },
      victim:  { activeNodes:['db'],                   activeEdges:[],                compromisedNodes:['db'], unaware:false } },
    { attacker:{ activeNodes:['db','exf'],              activeEdges:['e6'],            tools:['DNS exfil','DROP TABLE'] },
      defender:{ activeNodes:['db','ids','siem'],       activeEdges:['de2'],           detectionNodes:['ids','siem'] },
      victim:  { activeNodes:['db'],                   activeEdges:['e6'],            compromisedNodes:['db','exf'], unaware:false } },
  ],
};

AF_TOPOLOGIES['man-in-the-middle'] = {
  nodes: {
    base: [
      { id:'vic',  type:'victim',   label:'Victim Device',  sublabel:'Windows/Mac',   x:120, y:300 },
      { id:'rtr',  type:'router',   label:'Router / AP',    sublabel:'802.11',        x:380, y:480 },
      { id:'atk',  type:'attacker', label:'Attacker',       sublabel:'MitM Position', x:600, y:300 },
      { id:'srv',  type:'server',   label:'Target Server',  sublabel:'HTTPS',         x:900, y:300 },
      { id:'cert', type:'browser',  label:'Fake Cert',      sublabel:'Self-Signed',   x:600, y:480 },
    ],
    defender: [
      { id:'ids',  type:'edr',     label:'IDS/IPS',      sublabel:'Suricata',    x:380, y:120, _isDefender:true },
      { id:'siem', type:'siem',    label:'SIEM',         sublabel:'Splunk',      x:600, y:120, _isDefender:true },
      { id:'ca',   type:'server',  label:'Cert Monitor', sublabel:'HSTS Preload',x:900, y:120, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'vic', to:'rtr',  label:'network traffic' },
    { id:'e2', from:'rtr', to:'atk',  label:'ARP spoof' },
    { id:'e3', from:'atk', to:'srv',  label:'forwarded traffic' },
    { id:'e4', from:'atk', to:'cert', label:'fake cert served' },
    { id:'e5', from:'vic', to:'atk',  label:'intercepted session' },
    { id:'e6', from:'atk', to:'vic',  label:'manipulated response' },
    { id:'e7', from:'rtr', to:'atk',  label:'poisoned ARP table' },
    { id:'e8', from:'vic', to:'atk',  label:'decrypted session' },
    { id:'e9', from:'atk', to:'srv',  label:'replayed request' },
    { id:'de1', from:'ids',  to:'rtr', label:'ARP watch',       defenderOnly:true },
    { id:'de2', from:'ca',   to:'srv', label:'cert validation', defenderOnly:true },
    { id:'de3', from:'siem', to:'atk', label:'anomaly detect',  defenderOnly:true },
  ],
  phases: [
    { attacker:{ activeNodes:['atk','rtr'],         activeEdges:['e2'],            tools:['arpspoof','Ettercap'] },
      defender:{ activeNodes:['rtr','ids'],          activeEdges:['de1'],           detectionNodes:['ids'] },
      victim:  { activeNodes:['vic'],               activeEdges:[],                compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['vic','rtr','atk'],   activeEdges:['e1','e2','e7'],  tools:['Ettercap','Wireshark'] },
      defender:{ activeNodes:['rtr','ids','siem'],  activeEdges:['de1','de3'],     detectionNodes:['ids'] },
      victim:  { activeNodes:['vic','rtr'],         activeEdges:['e1'],            compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk','cert'],        activeEdges:['e4'],            tools:['sslstrip','mitmproxy'] },
      defender:{ activeNodes:['ca','siem'],         activeEdges:['de2'],           detectionNodes:['ca'] },
      victim:  { activeNodes:['vic','cert'],        activeEdges:['e4'],            compromisedNodes:[], unaware:false } },
    { attacker:{ activeNodes:['vic','atk'],         activeEdges:['e5','e8'],       tools:['Burp Suite'] },
      defender:{ activeNodes:['siem','ids'],        activeEdges:['de3'],           detectionNodes:['siem'] },
      victim:  { activeNodes:['vic'],              activeEdges:['e5'],            compromisedNodes:['vic'], unaware:false } },
    { attacker:{ activeNodes:['atk','vic','srv'],   activeEdges:['e3','e6','e8','e9'],tools:['mitmproxy'] },
      defender:{ activeNodes:['siem','ca'],         activeEdges:['de2','de3'],     detectionNodes:['siem','ca'] },
      victim:  { activeNodes:['vic'],              activeEdges:['e6'],            compromisedNodes:['vic'], unaware:false } },
    { attacker:{ activeNodes:['atk'],              activeEdges:['e9'],            tools:['log wipe'] },
      defender:{ activeNodes:['siem'],             activeEdges:['de3'],           detectionNodes:['siem'] },
      victim:  { activeNodes:['vic'],              activeEdges:[],                compromisedNodes:['vic'], unaware:false } },
  ],
};

AF_TOPOLOGIES['ransomware'] = {
  nodes: {
    base: [
      { id:'atk', type:'attacker',  label:'Attacker',           sublabel:'Threat Actor',     x:120, y:300 },
      { id:'vic', type:'victim',    label:'Victim Workstation', sublabel:'Windows',           x:360, y:300 },
      { id:'c2',  type:'c2',        label:'C2 Server',          sublabel:'TOR/VPS',           x:560, y:140 },
      { id:'dc',  type:'server',    label:'Domain Controller',  sublabel:'Active Directory',  x:760, y:140 },
      { id:'fs',  type:'database',  label:'File Server',        sublabel:'SMB Share',         x:760, y:300 },
      { id:'bak', type:'server',    label:'Backup Server',      sublabel:'Network Backup',    x:760, y:480 },
      { id:'enc', type:'database',  label:'Encrypted Files',    sublabel:'Locked Data',       x:960, y:300 },
    ],
    defender: [
      { id:'edr',  type:'edr',      label:'EDR Agent',      sublabel:'CrowdStrike', x:360, y:110, _isDefender:true },
      { id:'siem', type:'siem',     label:'SIEM',           sublabel:'Splunk',      x:960, y:120, _isDefender:true },
      { id:'bakm', type:'firewall', label:'Backup Monitor', sublabel:'Veeam',       x:960, y:480, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk', to:'vic', label:'phishing email' },
    { id:'e2', from:'vic', to:'c2',  label:'beacon callback' },
    { id:'e3', from:'c2',  to:'dc',  label:'credential dump' },
    { id:'e4', from:'dc',  to:'vic', label:'privilege escalated' },
    { id:'e5', from:'vic', to:'fs',  label:'lateral movement' },
    { id:'e6', from:'fs',  to:'bak', label:'shadow copy delete' },
    { id:'e7', from:'fs',  to:'enc', label:'file encryption' },
    { id:'e8', from:'bak', to:'enc', label:'backup encrypted' },
    { id:'e9', from:'enc', to:'vic', label:'ransom note' },
    { id:'de1', from:'edr',  to:'vic', label:'behaviour monitor', defenderOnly:true },
    { id:'de2', from:'siem', to:'dc',  label:'log analysis',      defenderOnly:true },
    { id:'de3', from:'bakm', to:'bak', label:'integrity check',   defenderOnly:true },
  ],
  phases: [
    { attacker:{ activeNodes:['atk','vic'],             activeEdges:['e1'],           tools:['GoPhish','macros'] },
      defender:{ activeNodes:['vic','edr'],             activeEdges:['de1'],          detectionNodes:['edr'] },
      victim:  { activeNodes:['vic'],                  activeEdges:['e1'],           compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['vic','c2'],              activeEdges:['e2'],           tools:['Cobalt Strike','Metasploit'] },
      defender:{ activeNodes:['vic','edr','siem'],      activeEdges:['de1','de2'],    detectionNodes:['edr','siem'] },
      victim:  { activeNodes:['vic'],                  activeEdges:['e2'],           compromisedNodes:['vic'], unaware:false } },
    { attacker:{ activeNodes:['c2','dc'],               activeEdges:['e3'],           tools:['Mimikatz','BloodHound'] },
      defender:{ activeNodes:['dc','siem'],             activeEdges:['de2'],          detectionNodes:['siem'] },
      victim:  { activeNodes:['vic'],                  activeEdges:[],               compromisedNodes:['vic'], unaware:false } },
    { attacker:{ activeNodes:['vic','dc'],              activeEdges:['e4'],           tools:['ADRecon','nmap'] },
      defender:{ activeNodes:['dc','siem','edr'],       activeEdges:['de1','de2'],    detectionNodes:['siem'] },
      victim:  { activeNodes:['vic','dc'],              activeEdges:[],               compromisedNodes:['vic'], unaware:false } },
    { attacker:{ activeNodes:['vic','fs'],              activeEdges:['e5'],           tools:['PsExec','WMI'] },
      defender:{ activeNodes:['vic','edr','siem'],      activeEdges:['de1','de2'],    detectionNodes:['edr','siem'] },
      victim:  { activeNodes:['vic','fs'],              activeEdges:['e5'],           compromisedNodes:['vic','fs'], unaware:false } },
    { attacker:{ activeNodes:['fs','bak'],              activeEdges:['e6'],           tools:['rclone'] },
      defender:{ activeNodes:['bak','bakm','siem'],     activeEdges:['de2','de3'],    detectionNodes:['bakm','siem'] },
      victim:  { activeNodes:['fs','bak'],              activeEdges:['e6'],           compromisedNodes:['fs','bak'], unaware:false } },
    { attacker:{ activeNodes:['fs','bak','enc','vic'],  activeEdges:['e7','e8','e9'], tools:['LockBit','REvil'] },
      defender:{ activeNodes:['edr','siem','bakm'],     activeEdges:['de1','de3'],   detectionNodes:['edr','siem','bakm'] },
      victim:  { activeNodes:['fs','bak','enc','vic'],  activeEdges:['e7','e8','e9'],compromisedNodes:['fs','bak','enc'], unaware:false } },
  ],
};

AF_TOPOLOGIES['lateral-movement'] = {
  nodes: {
    base: [
      { id:'atk', type:'attacker',    label:'Attacker Foothold', sublabel:'Compromised PC', x:120, y:300 },
      { id:'h1',  type:'workstation', label:'Workstation A',     sublabel:'Internal PC',    x:360, y:300 },
      { id:'ad',  type:'server',      label:'Active Directory',  sublabel:'AD Server',      x:580, y:160 },
      { id:'dc',  type:'server',      label:'Domain Controller', sublabel:'DC',             x:800, y:160 },
      { id:'h2',  type:'workstation', label:'Workstation B',     sublabel:'Target PC',      x:580, y:460 },
      { id:'fs',  type:'database',    label:'File Server',       sublabel:'SMB',            x:960, y:300 },
    ],
    defender: [
      { id:'edr',  type:'edr',  label:'EDR Agent',    sublabel:'CrowdStrike', x:360, y:100, _isDefender:true },
      { id:'ids',  type:'edr',  label:'Network IDS',  sublabel:'Suricata',    x:800, y:460, _isDefender:true },
      { id:'siem', type:'siem', label:'SIEM',         sublabel:'Splunk',      x:960, y:100, _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk', to:'h1', label:'initial compromise' },
    { id:'e2', from:'h1',  to:'ad', label:'LDAP enumeration' },
    { id:'e3', from:'h1',  to:'h2', label:'pass-the-hash' },
    { id:'e4', from:'ad',  to:'dc', label:'Kerberoasting' },
    { id:'e5', from:'dc',  to:'fs', label:'domain admin access' },
    { id:'e6', from:'h2',  to:'fs', label:'remote execution' },
    { id:'e7', from:'h1', to:'atk', label:'credential dump' },
    { id:'e8', from:'ad',  to:'atk', label:'NTLM hash captured' },
    { id:'e9', from:'atk', to:'h2', label:'persistence established' },
    { id:'de1', from:'edr',  to:'h1', label:'process watch',   defenderOnly:true },
    { id:'de2', from:'ids',  to:'h2', label:'lateral detect',  defenderOnly:true },
    { id:'de3', from:'siem', to:'dc', label:'log correlation', defenderOnly:true },
  ],
  phases: [
    { attacker:{ activeNodes:['atk','h1'],           activeEdges:['e1'],           tools:['Metasploit','phish'] },
      defender:{ activeNodes:['h1','edr'],            activeEdges:['de1'],          detectionNodes:['edr'] },
      victim:  { activeNodes:['h1'],                 activeEdges:['e1'],           compromisedNodes:['h1'], unaware:false } },
    { attacker:{ activeNodes:['h1','ad'],             activeEdges:['e2'],           tools:['BloodHound','ADRecon'] },
      defender:{ activeNodes:['h1','edr','siem'],     activeEdges:['de1','de3'],    detectionNodes:['edr'] },
      victim:  { activeNodes:['h1'],                 activeEdges:[],               compromisedNodes:['h1'], unaware:false } },
    { attacker:{ activeNodes:['h1','ad','atk'],       activeEdges:['e2','e7','e8'], tools:['Mimikatz','secretsdump'] },
      defender:{ activeNodes:['h1','edr','siem'],     activeEdges:['de1'],          detectionNodes:['edr','siem'] },
      victim:  { activeNodes:['h1','ad'],             activeEdges:[],               compromisedNodes:['h1'], unaware:false } },
    { attacker:{ activeNodes:['h1','h2'],             activeEdges:['e3'],           tools:['PsExec','WMI'] },
      defender:{ activeNodes:['h1','h2','ids','edr'], activeEdges:['de1','de2'],    detectionNodes:['ids','edr'] },
      victim:  { activeNodes:['h1','h2'],             activeEdges:['e3'],           compromisedNodes:['h1','h2'], unaware:false } },
    { attacker:{ activeNodes:['ad','dc','atk','h2'],  activeEdges:['e4','e9'],      tools:['Rubeus','Kerberoast'] },
      defender:{ activeNodes:['dc','siem'],           activeEdges:['de3'],          detectionNodes:['siem'] },
      victim:  { activeNodes:['h1','h2'],             activeEdges:[],               compromisedNodes:['h1','h2'], unaware:false } },
    { attacker:{ activeNodes:['dc','fs','h2'],        activeEdges:['e5','e6'],      tools:['DCSync','Golden Ticket'] },
      defender:{ activeNodes:['dc','siem','ids'],     activeEdges:['de2','de3'],    detectionNodes:['siem'] },
      victim:  { activeNodes:['h1','h2','fs'],        activeEdges:['e5','e6'],      compromisedNodes:['h1','h2','fs'], unaware:false } },
  ],
};

AF_TOPOLOGIES['supply-chain-attack'] = {
  nodes: {
    base: [
      { id:'atk',  type:'attacker', label:'Attacker',         sublabel:'Threat Actor',      x:120, y:300 },
      { id:'repo', type:'browser',  label:'OSS Repository',   sublabel:'GitHub',            x:340, y:300 },
      { id:'ci',   type:'server',   label:'CI/CD Pipeline',   sublabel:'GitHub Actions',    x:560, y:300 },
      { id:'pkg',  type:'registry', label:'Package Registry', sublabel:'npm/PyPI',          x:780, y:300 },
      { id:'oa',   type:'victim',   label:'Org A',            sublabel:'Downstream Victim', x:960, y:180 },
      { id:'ob',   type:'victim',   label:'Org B',            sublabel:'Downstream Victim', x:960, y:320 },
      { id:'oc',   type:'victim',   label:'Org C',            sublabel:'Downstream Victim', x:960, y:460 },
    ],
    defender: [
      { id:'scan', type:'edr',      label:'Dep Scanner',  sublabel:'Snyk',     x:560, y:120, _isDefender:true },
      { id:'sign', type:'firewall', label:'Code Signing', sublabel:'Sigstore', x:780, y:120, _isDefender:true },
      { id:'siem', type:'siem',     label:'SIEM',         sublabel:'Splunk',   x:960, y:80,  _isDefender:true },
    ],
  },
  edges: [
    { id:'e1', from:'atk',  to:'repo', label:'malicious commit' },
    { id:'e2', from:'repo', to:'ci',   label:'triggers build' },
    { id:'e3', from:'ci',   to:'pkg',  label:'poisoned package' },
    { id:'e4', from:'pkg',  to:'oa',   label:'trojanized binary' },
    { id:'e5', from:'pkg',  to:'ob',   label:'trojanized binary' },
    { id:'e6', from:'pkg',  to:'oc',   label:'trojanized binary' },
    { id:'e7', from:'oa',   to:'atk', label:'backdoor call-home' },
    { id:'de1', from:'scan', to:'ci',  label:'dep audit',        defenderOnly:true },
    { id:'de2', from:'sign', to:'pkg', label:'sig verify',       defenderOnly:true },
    { id:'de3', from:'siem', to:'oa',  label:'call-home detect', defenderOnly:true },
  ],
  phases: [
    { attacker:{ activeNodes:['atk','repo'],             activeEdges:[],               tools:['GitHub search','deps.dev'] },
      defender:{ activeNodes:['scan'],                   activeEdges:[],               detectionNodes:[] },
      victim:  { activeNodes:[],                         activeEdges:[],               compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['atk','repo','ci'],        activeEdges:['e1','e2'],      tools:['git commit','Actions inject'] },
      defender:{ activeNodes:['repo','ci','scan'],       activeEdges:['de1'],          detectionNodes:['scan'] },
      victim:  { activeNodes:[],                         activeEdges:[],               compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['ci','pkg'],               activeEdges:['e3'],           tools:['npm publish','typosquatting'] },
      defender:{ activeNodes:['ci','scan','sign'],       activeEdges:['de1','de2'],    detectionNodes:['scan','sign'] },
      victim:  { activeNodes:[],                         activeEdges:[],               compromisedNodes:[], unaware:true } },
    { attacker:{ activeNodes:['pkg','oa','ob','oc'],     activeEdges:['e4','e5','e6'], tools:['npm install','pip install'] },
      defender:{ activeNodes:['pkg','sign','siem'],      activeEdges:['de2','de3'],    detectionNodes:['sign','siem'] },
      victim:  { activeNodes:['oa','ob','oc'],           activeEdges:['e4','e5','e6'], compromisedNodes:[], unaware:false } },
    { attacker:{ activeNodes:['oa','ob','oc','atk'],      activeEdges:['e4','e5','e6','e7'], tools:['backdoor call-home'] },
      defender:{ activeNodes:['siem','oa'],              activeEdges:['de3'],              detectionNodes:['siem'] },
      victim:  { activeNodes:['oa','ob','oc','atk'],      activeEdges:['e7'],               compromisedNodes:['oa','ob','oc'], unaware:false } },
  ],
};

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
      const pad = 72;
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
        // Perpendicular offset: push label above/beside the line so it never overlaps nodes
        const nx = -dy / len, ny = dx / len; // unit normal (rotated 90° CCW)
        const off = 22; // offset distance in px
        const lx = mx + nx * off, ly = my + ny * off;
        const labelLen = ed.label.length * 6 + 24;
        const lbg = document.createElementNS(NS, 'rect');
        this._attrs(lbg, {
          x:String(lx - labelLen/2), y:String(ly - 13),
          width:String(labelLen), height:'18', rx:'3',
          fill:'#0d1117', opacity:'.92',
        });
        const ltxt = document.createElementNS(NS, 'text');
        this._attrs(ltxt, {
          x:String(lx), y:String(ly + 1),
          'text-anchor':'middle','font-size':'10','font-family':'ui-monospace,monospace',
          fill:colors.accent,'font-weight':'600',
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
    const W = 130, H = 72, RX = 4;

    // Unique clipPath id counter per render pass (reset each call)
    let clipIdx = 0;
    const defs = this.svg?.querySelector('defs') || (() => {
      const d = document.createElementNS(NS, 'defs'); this.svg?.prepend(d); return d;
    })();
    // Remove stale node clipPaths
    defs.querySelectorAll('[id^="nc-"]').forEach(el => el.remove());

    nodes.forEach(node => {
      const isDefNode = !!node._isDefender;
      const isAct     = state.activeNodes.has(node.id);
      const isDet     = state.detectionNodes.has(node.id);
      const isComp    = state.compromisedNodes.has(node.id);
      const isGhost   = perspective === 'victim' && state.unaware && !isAct && !isDefNode;
      const isDim     = !isGhost && !isAct && state.activeNodes.size > 0 && !isDefNode;

      const g = document.createElementNS(NS, 'g');
      g.setAttribute('transform', `translate(${node.x - W/2},${node.y - H/2})`);
      g.style.opacity    = isGhost ? '0.25' : isDim ? '0.2' : '1';
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
        fill:bgColor,stroke:borderColor,'stroke-width':isAct||isDet||isComp?'2.5':'1'});
      g.appendChild(box);

      // clipPath for text — prevents label/sublabel overflow beyond node rect
      const clipId = `nc-${node.id}-${clipIdx++}`;
      const cp = document.createElementNS(NS, 'clipPath');
      cp.setAttribute('id', clipId);
      const cpr = document.createElementNS(NS, 'rect');
      this._attrs(cpr, {x:'3',y:'32',width:String(W-6),height:String(H-34)});
      cp.appendChild(cpr);
      defs.appendChild(cp);

      const iconId = AF_ICONS[node.type] || 'ic-server';
      const ic = document.createElementNS(NS, 'use');
      this._attrs(ic, {href:`#${iconId}`,x:String(W/2-14),y:'7',width:'28',height:'28'});
      ic.style.color = iconColor;
      g.appendChild(ic);

      const textG = document.createElementNS(NS, 'g');
      textG.setAttribute('clip-path', `url(#${clipId})`);

      const lbl = document.createElementNS(NS, 'text');
      this._attrs(lbl, {x:String(W/2),y:'48','text-anchor':'middle',
        'font-size':'11','font-family':'ui-monospace,monospace',
        fill:isAct||isDet||isComp?'#e2e8f0':'#4a5568','font-weight':'700','letter-spacing':'0.3'});
      lbl.textContent = (node.label || '').toUpperCase();
      textG.appendChild(lbl);

      if (node.sublabel) {
        const sub = document.createElementNS(NS, 'text');
        this._attrs(sub, {x:String(W/2),y:'62','text-anchor':'middle',
          'font-size':'9','font-family':'ui-monospace,monospace',fill:'#8b949e'});
        sub.textContent = node.sublabel;
        textG.appendChild(sub);
      }

      g.appendChild(textG);

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

      if (isGhost) {
        const ht = document.createElementNS(NS, 'text');
        this._attrs(ht, {x:String(W/2),y:String(H+14),'text-anchor':'middle',
          'font-size':'7','font-family':'ui-monospace,monospace',fill:'#6b7280','letter-spacing':'0.3'});
        ht.textContent = '(hidden)';
        g.appendChild(ht);
      }

      g.addEventListener('mouseenter', e => this._showTooltip(e, node, isAct, isDet, isComp, colors));
      g.addEventListener('mouseleave', () => this._hideTooltip());

      this.ngGroup.appendChild(g);
    });
  }

  // ── draw overlays ─────────────────────────────────────────────────────────
  _drawOverlays(state, perspective, colors, nmap) {
    this._stopScanBeam();
    this.ogGroup.innerHTML = '';

    if (perspective === 'defender' && state.activeNodes.size > 0) {
      this._startScanBeam(colors.accent);
    }

    if (perspective === 'victim' && state.activeNodes.size > 0) {
      const svgW = this.svg?.viewBox.baseVal.width  || 1100;
      const svgH = this.svg?.viewBox.baseVal.height || 600;
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
        const BADGE_W = 80; // fixed badge slot width for consistent spacing
        const tools = state.tools.slice(0, 3);
        const totalW = tools.length * BADGE_W + (tools.length - 1) * 4;
        const startX = Math.max(10, atkNode.x - totalW / 2);
        tools.forEach((tool, i) => {
          const tw = tool.length * 6.5 + 16;
          const slotX = startX + i * (BADGE_W + 4);
          const tx = slotX + (BADGE_W - tw) / 2;
          const ty = atkNode.y - 60;
          const bg = document.createElementNS(this.NS, 'rect');
          this._attrs(bg, {x:String(tx),y:String(ty-10),width:String(tw),height:'20',rx:'3',
            fill:'rgba(239,68,68,.18)',stroke:'rgba(239,68,68,.4)','stroke-width':'1'});
          const txt = document.createElementNS(this.NS, 'text');
          this._attrs(txt, {x:String(tx+tw/2),y:String(ty+4),'text-anchor':'middle',
            'font-size':'10','font-family':'ui-monospace,monospace',fill:'#fca5a5','font-weight':'600'});
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
    const svgH = svg.viewBox.baseVal.height || 600;
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
      tip.style.cssText = 'position:fixed;z-index:9999;pointer-events:none;background:#0d1117;border:1px solid rgba(255,255,255,.12);border-radius:8px;padding:7px 11px;font-size:11px;color:#cbd5e1;line-height:1.5;box-shadow:0 8px 24px rgba(0,0,0,.6);opacity:0;transition:opacity .15s;max-width:220px;';
      document.body.appendChild(tip);
    }
    return tip;
  }

  _showTooltip(e, node, isAct, isDet, isComp, colors) {
    const status = isComp ? `<span style="color:#f59e0b">⚠ Compromised</span>`
      : isDet  ? `<span style="color:#3b82f6">● Monitoring</span>`
      : isAct  ? `<span style="color:${colors.accent}">● Active</span>`
      : `<span style="color:#374151">○ Idle</span>`;
    const desc = AF_NODE_DESC[node.type] || '';
    this._tooltip.innerHTML = `<div style="font-weight:600;color:#f1f5f9;margin-bottom:2px">${node.label}</div>${status}${node.sublabel?`<br><span style="color:#6b7280;font-size:10px">${node.sublabel}</span>`:''}${desc?`<br><span style="color:#64748b;font-size:10px;display:block;margin-top:3px">${desc}</span>`:''}`;
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
