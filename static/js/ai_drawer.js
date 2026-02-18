/* CyberBase AI Drawer Frontend

static/ai_drawer.js v4
static/ai_drawer.js v4 builds on v3

Key changes
- Persistent history in sessionStorage (global per tab)
- Floating AI button to reopen the drawer after closing
- Command explain button is only in the Command Library details panel
- Command explain sends better minimal context (title, syntax, short description)
- Selection explain works on Toolbox, Tools, Concepts, and Defend subpages
- Requests append to history and never reset it
- Transcript shows only You and AI lines
*/

(function () {
  const DRAWER_ID = "cb-ai-drawer";
  // Backdrop id varies across template versions.
  const BACKDROP_ID_PRIMARY = "cb-ai-backdrop";
  const BACKDROP_ID_FALLBACK = "cb-ai-overlay";
  const CONTEXT_ID = "cb-ai-context";
  const OUTPUT_ID = "cb-ai-output";
  const INPUT_ID = "cb-ai-input";
  const SEND_ID = "cb-ai-send";
  const CLOSE_ID = "cb-ai-close";

  const SELECTION_WRAP_ID = "cb-ai-selection-wrap";
  const SELECTION_BTN_ID = "cb-ai-selection-btn";

  const FAB_ID = "cb-ai-fab";

  const HISTORY_KEY = "cb_ai_history_v1";
  const MAX_HISTORY_ITEMS = 30;

  const API_PATH = "/api/ai";
  const CHAT_API_PATH = "/api/ai/chat";
  const SESSION_KEY = "cb_ai_session_id_v1";
  const AI_I18N = (window.cbI18n && window.cbI18n.ai) || {};

  function t(key, fallback) {
    const v = AI_I18N[key];
    return typeof v === "string" && v.trim().length ? v : fallback;
  }

  let drawerEl;
  let backdropEl;
  let contextEl;
  let outEl;
  let inputEl;
  let sendEl;
  let closeEl;

  let selectionWrapEl;
  let selectionBtnEl;
  let lastSelectionText = "";

  let statusLine = "";
  let isSending = false;
  let chatSessionId = null;

  function getPageUrl() {
    try {
      return window.location.pathname + window.location.search;
    } catch (e) {
      return "";
    }
  }

  function trimText(text, maxChars) {
    if (!text) return "";
    const t = String(text).trim();
    if (t.length <= maxChars) return t;
    return t.slice(0, Math.max(0, maxChars - 1)) + "...";
  }

  function inferPageTopic() {
    const path = (window.location.pathname || "").toLowerCase();

    let section = t("cyberbase", "CyberBase");
    if (path.startsWith("/command-library") || path.startsWith("/commands")) section = t("commandLibrary", "Command Library");
    else if (path.startsWith("/toolbox") || path.startsWith("/tools")) section = t("toolbox", "Toolbox");
    else if (path.startsWith("/concepts")) section = t("concepts", "Concepts");
    else if (path.startsWith("/defend")) section = t("defend", "Defend");

    const h1 = document.querySelector("main h1") || document.querySelector("h1");
    let title = (h1 && h1.textContent ? h1.textContent : "").trim();

    if (!title) {
      const dt = (document.title || "").trim();
      title = dt.replace(" - CyberBase", "").replace("CyberBase", "").trim();
    }

    const topic = title ? `${section}: ${title}` : section;
    return { section, title, topic };
  }

  function loadHistory() {
    try {
      const raw = sessionStorage.getItem(HISTORY_KEY);
      if (!raw) return [];
      const arr = JSON.parse(raw);
      if (!Array.isArray(arr)) return [];
      return arr
        .filter((x) => x && typeof x === "object")
        .map((x) => ({
          role: x.role === "assistant" ? "assistant" : "user",
          context: String(x.context || ""),
          content: String(x.content || ""),
          ts: Number.isFinite(Number(x.ts)) ? Number(x.ts) : Date.now(),
        }))
        .slice(-MAX_HISTORY_ITEMS);
    } catch (e) {
      return [];
    }
  }

  function saveHistory(history) {
    try {
      sessionStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(-MAX_HISTORY_ITEMS)));
    } catch (e) {
      /* ignore */
    }
  }

  let history = loadHistory();

  function formatHistory(historyItems) {
    const lines = [];

    for (const item of historyItems) {
      const who = item.role === "assistant" ? "AI" : t("youLabel", "You");
      const content = String(item.content || "").replace(/\r\n/g, "\n").trimEnd();
      if (!content) continue;

      lines.push(`${who}: ${content}`);
      lines.push("");
    }

    // Remove trailing blank line
    while (lines.length && lines[lines.length - 1] === "") lines.pop();

    if (statusLine) {
      if (lines.length) lines.push("");
      lines.push(`AI: ${statusLine}`);
    }

    return lines.join("\n");
  }

  function render() {
    if (!outEl) return;
    outEl.textContent = formatHistory(history);
    // Scroll only the drawer messages container (parent with overflow)
    try {
      const container = outEl.parentElement || outEl;
      // Defer to next tick to ensure DOM layout is updated
      window.setTimeout(() => {
        container.scrollTop = container.scrollHeight;
      }, 0);
    } catch (e) {
      /* ignore */
    }
  }

  function setStatus(text) {
    statusLine = text || "";
    render();
  }

  function setSending(sending) {
    isSending = !!sending;
    if (sendEl) sendEl.disabled = isSending;
    if (inputEl) inputEl.disabled = isSending;
  }

  function appendHistory(role, context, content) {
    const item = {
      role: role === "assistant" ? "assistant" : "user",
      context: String(context || ""),
      content: String(content || ""),
      ts: Date.now(),
    };

    history.push(item);
    if (history.length > MAX_HISTORY_ITEMS) history = history.slice(-MAX_HISTORY_ITEMS);
    saveHistory(history);
    render();
  }

  function openDrawer(contextTitle) {
    if (!drawerEl || !backdropEl) return;

    // Support both the old Tailwind translate class and the current cb-ai-open class.
    drawerEl.classList.add("cb-ai-open");
    drawerEl.classList.remove("translate-x-full");
    backdropEl.classList.remove("hidden");

    if (contextEl && contextTitle) contextEl.textContent = contextTitle;
    render();

    window.setTimeout(() => {
      if (inputEl) inputEl.focus();
    }, 0);
  }

  function closeDrawer() {
    if (!drawerEl || !backdropEl) return;

    drawerEl.classList.remove("cb-ai-open");
    drawerEl.classList.add("translate-x-full");
    backdropEl.classList.add("hidden");
  }

  async function postJson(payload, idToken) {
    const res = await fetch(API_PATH, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(idToken ? { Authorization: `Bearer ${idToken}` } : {}),
      },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });

    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      /* ignore */
    }

    if (!data || typeof data !== "object") {
      throw new Error(t("badResponse", "Bad response from server."));
    }

    return { status: res.status, data };
  }

  async function postChatJson(payload, idToken) {
    const res = await fetch(CHAT_API_PATH, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(idToken ? { Authorization: `Bearer ${idToken}` } : {}),
      },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });
    let data = null;
    try {
      data = await res.json();
    } catch (e) {
      /* ignore */
    }
    if (!data || typeof data !== "object") {
      throw new Error(t("badResponse", "Bad response from server."));
    }
    if (!res.ok) {
      if (res.status === 401 && data && data.error === "AUTH_REQUIRED") {
        const err = new Error(data.message || t("authRequired", "You need to be logged in to use the AI assistant."));
        err.code = "AUTH_REQUIRED";
        throw err;
      }
      const msg = data && (data.error || data.message) ? (data.error || data.message) : t("chatFailed", "Chat failed.");
      throw new Error(String(msg));
    }
    return data;
  }

  // Lightweight Firebase Auth loader for ID token retrieval
  let firebaseAuthCache = null;
  async function getFirebaseAuth() {
    if (firebaseAuthCache) return firebaseAuthCache;
    try {
      const [{ initializeApp }, { getAuth, onAuthStateChanged }] = await Promise.all([
        import("https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js"),
        import("https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js"),
      ]);
      const conf = (window.__FIREBASE_CONFIG__ && Object.keys(window.__FIREBASE_CONFIG__).length)
        ? window.__FIREBASE_CONFIG__
        : null;
      if (!conf) return null;
      const app = initializeApp(conf);
      const auth = getAuth(app);
      firebaseAuthCache = { auth, onAuthStateChanged };
      return firebaseAuthCache;
    } catch (e) {
      // If Firebase fails to load, treat as not logged in
      return null;
    }
  }

  async function getIdTokenOrNull() {
    const fb = await getFirebaseAuth();
    if (!fb) return null;
    const { auth } = fb;
    try {
      if (auth.currentUser) return await auth.currentUser.getIdToken();
      // Wait briefly for auth state
      return await new Promise((resolve) => {
        let unsub = null;
        const timer = setTimeout(() => {
          if (unsub) unsub();
          resolve(null);
        }, 300);
        unsub = fb.onAuthStateChanged(auth, async (user) => {
          clearTimeout(timer);
          if (unsub) unsub();
          if (user) {
            try { resolve(await user.getIdToken()); } catch { resolve(null); }
          } else {
            resolve(null);
          }
        });
      });
    } catch {
      return null;
    }
  }

  async function runAiRequest({ mode, contextTitle, userLine, snippetText, syntaxText, pageTopic, messageText, ctx }) {
    const pageUrl = getPageUrl();

    openDrawer(contextTitle);

    appendHistory("user", contextTitle, userLine);

    setSending(true);
    setStatus(t("thinking", "Thinking..."));

    try {
      // All AI requires login; check Firebase auth state first
      const idToken = await getIdTokenOrNull();
      if (!idToken) {
        setStatus("");
        appendHistory("assistant", contextTitle, t("authRequired", "You need to be logged in to use the AI assistant."));
        return;
      }

      if (mode === "chat") {
        // Use the new chat endpoint
        const payload = {
          prompt: messageText || "",
          pagePath: pageUrl,
        };
        const sid = chatSessionId || sessionStorage.getItem(SESSION_KEY);
        if (sid) payload.sessionId = sid;

        const data = await postChatJson(payload, idToken);
        setStatus("");
        if (data && data.sessionId && !sid) {
          chatSessionId = String(data.sessionId);
          try { sessionStorage.setItem(SESSION_KEY, chatSessionId); } catch (e) {}
        }
        if (data && data.reply) {
          appendHistory("assistant", contextTitle, String(data.reply || ""));
        } else {
          appendHistory("assistant", contextTitle, t("noReply", "No reply received."));
        }
      } else {
        // Legacy explain endpoints: block if not logged in (already checked)
        const payload = {
          mode,
          page_url: pageUrl,
        };
        if (pageTopic) payload.page_topic = pageTopic;
        payload.snippet_text = snippetText || "";
        if (syntaxText) payload.syntax_text = syntaxText;

        const { data } = await postJson(payload, idToken);
        setStatus("");
        if (data.ok) {
          appendHistory("assistant", contextTitle, String(data.text || ""));
        } else {
          const msg = (data.error && data.error.message) ? String(data.error.message) : t("aiRequestFailed", "AI request failed.");
          appendHistory("assistant", contextTitle, msg);
        }
      }
    } catch (e) {
      setStatus("");
      if (e && e.code === "AUTH_REQUIRED") {
        appendHistory("assistant", contextTitle, t("authRequired", "You need to be logged in to use the AI assistant."));
      } else {
        appendHistory("assistant", contextTitle, t("aiRequestFailedRetry", "AI request failed. Please try again."));
      }
    } finally {
      setSending(false);
    }
  }

  function getChatContext() {
    const ctx = [];
    const items = history.slice(-20).reverse();

    for (const it of items) {
      if (!it || !it.content) continue;
      if (it.role !== "user" && it.role !== "assistant") continue;

      ctx.push({
        role: it.role,
        content: trimText(it.content, 400),
      });

      if (ctx.length >= 6) break;
    }

    return ctx.reverse();
  }


  function explainSelection(selectionText) {
    const sel = trimText(selectionText || "", 5000);
    if (!sel) return;

    const page = inferPageTopic();
    const contextTitle = page.topic ? page.topic : t("selectedText", "Selected text");
    const userLine = `${t("explainPrefix", "Explain:")} "${trimText(sel, 140)}"`;

    runAiRequest({
      mode: "explain_selection",
      contextTitle,
      userLine,
      snippetText: sel,
      pageTopic: page.topic,
    });
  }

  function extractCommandDetailsFromDom(fromEl) {
    const root =
      (fromEl && fromEl.closest ? fromEl.closest("[data-cb-command-detail-root]") : null) ||
      document.querySelector("[data-cb-command-detail-root]") ||
      document;

    const titleEl = root.querySelector("[data-cb-command-title]") || root.querySelector("h2");
    const descEl = root.querySelector("[data-cb-command-desc]");
    const syntaxEl = root.querySelector("[data-cb-command-syntax]") || root.querySelector(".ct-codeblock code");

    const title = titleEl && titleEl.textContent ? titleEl.textContent.trim() : "";
    const desc = descEl && descEl.textContent ? descEl.textContent.trim() : "";
    const syntax = syntaxEl && syntaxEl.textContent ? syntaxEl.textContent.trim() : "";

    return {
      title: trimText(title, 140),
      desc: trimText(desc, 700),
      syntax: trimText(syntax, 1600),
    };
  }

  function explainCurrentCommand(fromEl) {
    const details = extractCommandDetailsFromDom(fromEl);
    const titleOrFallback = details.title || t("command", "Command");

    const contextTitle = `${t("commandLibrary", "Command Library")}: ${titleOrFallback}`;
    const userLine = `${t("explainPrefix", "Explain:")} ${titleOrFallback}`;

    const parts = [];
    if (details.title) parts.push(`${t("commandTitlePrefix", "Command title:")} ${details.title}`);
    if (details.desc) parts.push(`${t("shortDescriptionPrefix", "Short description:")} ${details.desc}`);
    if (details.syntax) parts.push(`${t("syntaxPrefix", "Syntax:")}\n${details.syntax}`);

    const snippetText = parts.join("\n\n").trim();

    runAiRequest({
      mode: "explain_command",
      contextTitle,
      userLine,
      snippetText,
      syntaxText: details.syntax,
      pageTopic: t("commandLibrary", "Command Library"),
    });
  }

  function sendChat() {
    if (!inputEl) return;
    const msg = (inputEl.value || "").trim();
    if (!msg) return;

    const page = inferPageTopic();
    const contextTitle = page.topic ? page.topic : t("cyberbase", "CyberBase");
    const userLine = msg;

    inputEl.value = "";

    runAiRequest({
      mode: "chat",
      contextTitle,
      userLine,
      messageText: msg,
      pageTopic: page.topic,
      ctx: getChatContext(),
    });
  }

  function getSelectedText() {
    const sel = window.getSelection ? window.getSelection() : null;
    if (!sel) return "";
    return (sel.toString() || "").trim();
  }

  function findScopeEl(node) {
    if (!node) return null;
    let el = node.nodeType === 1 ? node : node.parentElement;
    while (el) {
      if (el.getAttribute && el.getAttribute("data-ai-explain-scope") === "true") return el;
      el = el.parentElement;
    }
    return null;
  }

  function hasMeaningfulSelection(text) {
    const t = (text || "").trim();
    if (t.length < 5) return false; // too short
    const words = t.replace(/[\s\u00A0]+/g, " ").split(" ").filter(Boolean);
    if (words.length < 2) return false; // require at least two words
    return true;
  }

  function showSelectionButtonIfNeeded() {
    if (!selectionWrapEl || !selectionBtnEl) return;

    const sel = window.getSelection ? window.getSelection() : null;
    if (!sel || !sel.rangeCount) {
      selectionWrapEl.classList.add("hidden");
      lastSelectionText = "";
      return;
    }

    const text = getSelectedText();
    if (!hasMeaningfulSelection(text)) {
      selectionWrapEl.classList.add("hidden");
      lastSelectionText = "";
      return;
    }

    // Strict scope: both ends must be inside the same [data-ai-explain-scope="true"] container
    const range = sel.getRangeAt(0);
    const startScope = findScopeEl(range.startContainer);
    const endScope = findScopeEl(range.endContainer);
    if (!startScope || !endScope || startScope !== endScope) {
      selectionWrapEl.classList.add("hidden");
      lastSelectionText = "";
      return;
    }

    lastSelectionText = text;
    selectionWrapEl.classList.remove("hidden");

    const rect = range.getBoundingClientRect();
    const top = Math.max(10, rect.top + window.scrollY - 40);
    const left = Math.min(window.innerWidth - 220, Math.max(10, rect.left + window.scrollX));
    selectionWrapEl.style.top = `${top}px`;
    selectionWrapEl.style.left = `${left}px`;
  }

  function init() {
    drawerEl = document.getElementById(DRAWER_ID);
    backdropEl = document.getElementById(BACKDROP_ID_PRIMARY) || document.getElementById(BACKDROP_ID_FALLBACK);
    contextEl = document.getElementById(CONTEXT_ID);
    outEl = document.getElementById(OUTPUT_ID);
    inputEl = document.getElementById(INPUT_ID);
    sendEl = document.getElementById(SEND_ID);
    closeEl = document.getElementById(CLOSE_ID);

    selectionWrapEl = document.getElementById(SELECTION_WRAP_ID);
    selectionBtnEl = document.getElementById(SELECTION_BTN_ID);

    const fabEl = document.getElementById(FAB_ID);

    if (!drawerEl || !backdropEl || !outEl || !inputEl || !sendEl || !closeEl) return;
    // Restore chat session id if present
    try {
      const sid = sessionStorage.getItem(SESSION_KEY);
      if (sid) chatSessionId = sid;
    } catch (e) {}

    // No logging toggle; logging is always on server-side

    render();

    if (fabEl) {
      fabEl.addEventListener("click", (e) => {
        e.preventDefault();
        const page = inferPageTopic();
        openDrawer(page.topic || t("cyberbase", "CyberBase"));
      });
    }

    closeEl.addEventListener("click", (e) => {
      e.preventDefault();
      closeDrawer();
    });

    backdropEl.addEventListener("click", (e) => {
      if (e.target === backdropEl) closeDrawer();
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeDrawer();
    });

    sendEl.addEventListener("click", (e) => {
      e.preventDefault();
      if (!isSending) sendChat();
    });

    inputEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        if (!isSending) sendChat();
      }
    });

    if (selectionWrapEl && selectionBtnEl) {
      selectionBtnEl.addEventListener("click", (e) => {
        e.preventDefault();
        if (!lastSelectionText) return;

        explainSelection(lastSelectionText);

        try {
          const sel = window.getSelection ? window.getSelection() : null;
          if (sel) sel.removeAllRanges();
        } catch (err) {
          /* ignore */
        }

        lastSelectionText = "";
        selectionWrapEl.classList.add("hidden");
      });

      document.addEventListener("mouseup", showSelectionButtonIfNeeded);
      document.addEventListener("keyup", showSelectionButtonIfNeeded);
      document.addEventListener("scroll", () => {
        if (!selectionWrapEl.classList.contains("hidden")) showSelectionButtonIfNeeded();
      });
    }

    document.addEventListener("click", (e) => {
      const btn = e.target && e.target.closest ? e.target.closest("[data-cb-ai-explain-command]") : null;
      if (!btn) return;
      e.preventDefault();
      if (isSending) return;

      explainCurrentCommand(btn);
    });

    window.cbAi = {
      open: openDrawer,
      close: closeDrawer,
      explainSelection: explainSelection,
      explainCurrentCommand: explainCurrentCommand,
    };
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

