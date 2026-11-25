/* ==========================================================================
   Ordem de Arkan - Ficha de Agente (script.js)
   Segurança front-end (XSS, Prototype Pollution, validação de faixa/tipo,
   anti-spam de escrita, higiene de sessão, isTrusted guard e console guard)
   + Firebase Authentication & Cloud Firestore + Sessão Offline/Local temporária
   + Modo Administrador por UID (leitura e gravação de fichas alvo)
   + Exclusão de ficha e exclusão de conta
   + Sincronização precisa das seções no topo conforme a rolagem
   + Cores dinâmicas conforme a Categoria Principal de Afinidade de Nen
   + Interatividade do painel de detalhes LGPD no rodapé do criador
   + Cálculo automático da tabela de Perícias (#tabela-pericias)
   Criador: Lucas Ramalho Gavasso Trizote
   ========================================================================== */

"use strict";

const FIREBASE_CONFIG = Object.freeze({
  apiKey: "AIzaSyDnzpJLFYXxesm6ajmyfZW3CnxeEe9zol4",
  authDomain: "rpg-9ffa7.firebaseapp.com",
  projectId: "rpg-9ffa7",
  storageBucket: "rpg-9ffa7.firebasestorage.app",
  messagingSenderId: "937768309919",
  appId: "1:937768309919:web:d2af2a5247b4465ed97eaa"
});

const STORAGE_KEYS = Object.freeze({
  LOCAL_SHEET: "ordem_de_arkan_agente_v1",
  COOKIE_CONSENT: "ordem_de_arkan_lgpd_v1",
  ADMIN_TARGET_UID: "ordem_de_arkan_admin_target_uid_v1"
});

const ADMIN_UID = "TcudbnuOMcTySJWhz0JHaNDuNU22";
const UID_REGEX = /^[a-zA-Z0-9_-]{10,128}$/;

const FORBIDDEN_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);
const FIRESTORE_COLLECTION = "fichas_ordem_arkan";
const FIREBASE_SDK_VERSION = "10.14.1";
const MIN_CLOUD_SAVE_INTERVAL_MS = 1200;

const TRACKED_SECTIONS = Object.freeze([
  { id: "dados-agente", label: "Dados do Agente" },
  { id: "equipamentos-habilidades", label: "Equipamentos e Habilidades" },
  { id: "historico", label: "Histórico" },
  { id: "guilda", label: "Guilda" },
  { id: "privacidade-lgpd", label: "Privacidade (LGPD)" }
]);

const NEN_CATEGORIES_MAP = Object.freeze({
  reforco: "reforco",
  emissao: "emissao",
  transformacao: "transformacao",
  materializacao: "materializacao",
  manipulacao: "manipulacao",
  especializacao: "especializacao"
});

const SKILL_GRADE_BONUS = Object.freeze({
  destreinado: 0,
  treinado: 5,
  veterano: 10,
  expert: 15
});

const ATTR_LABEL_TO_INPUT_ID = Object.freeze({
  agilidade: "attr-agi",
  agi: "attr-agi",
  forca: "attr-for",
  "força": "attr-for",
  for: "attr-for",
  ca: "attr-ca",
  aura: "attr-ca",
  intelecto: "attr-int",
  int: "attr-int",
  vigor: "attr-vig",
  vig: "attr-vig"
});

const ALLOWED_RANKS = Object.freeze(["E", "D", "C", "B", "A", "S", "SS", "SSS"]);

const NUMERIC_BOUNDS = Object.freeze({
  "nv-val": { min: 1, max: 99, fallback: "1" },
  "espacos-max": { min: 0, max: 200, fallback: "5" },
  "def-total": { min: 0, max: 999, fallback: "11" },
  "def-esquiva": { min: 0, max: 999, fallback: "11" },
  "def-deslocamento": { min: 0, max: 999, fallback: "9" },
  "attr-agi": { min: -20, max: 99, fallback: "1" },
  "attr-for": { min: -20, max: 99, fallback: "1" },
  "attr-ca": { min: -20, max: 99, fallback: "1" },
  "attr-int": { min: -20, max: 99, fallback: "1" },
  "attr-vig": { min: -20, max: 99, fallback: "1" }
});

const state = {
  user: null,
  offlineMode: false,
  firebaseReady: false,
  auth: null,
  db: null,
  firebaseModules: null,
  authMode: "login",
  showPassword: false,
  cookieConsentAccepted: false,
  activeSectionId: "dados-agente",
  nenCategory: "",
  scrollRafId: null,
  saveTimer: null,
  isSaving: false,
  isDeleting: false,
  lastSavedSnapshot: "",
  lastCloudWriteAt: 0,
  adminTargetUid: ""
};

/* --------------------------------------------------------------------------
   Defesa contra Prototype Pollution, XSS, Faixa Inválida e Console Guard
   -------------------------------------------------------------------------- */
function isForbiddenKey(key) {
  return typeof key !== "string" || FORBIDDEN_KEYS.includes(key.toLowerCase());
}

function createSafeRecord() {
  return Object.create(null);
}

function sanitizeText(value, maxLength = 500) {
  if (typeof value !== "string") return "";
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/<\s*\/?\s*script\b[^>]*>/gi, "")
    .replace(/javascript\s*:/gi, "")
    .slice(0, maxLength);
}

function sanitizeSingleLine(value, maxLength = 140) {
  return sanitizeText(value, maxLength).replace(/[\r\n]+/g, " ").trim();
}

function isValidFieldKey(key) {
  if (typeof key !== "string" || isForbiddenKey(key)) return false;
  return /^(id:[a-zA-Z0-9_-]{1,64}|idx:\d{1,5})$/.test(key);
}

function normalizeNumericValue(id, rawValue) {
  const trimmed = sanitizeSingleLine(String(rawValue ?? ""), 24);
  if (trimmed === "") return "";

  const parsed = Number(trimmed.replace(",", "."));
  if (!Number.isFinite(parsed)) {
    return Object.prototype.hasOwnProperty.call(NUMERIC_BOUNDS, id)
      ? NUMERIC_BOUNDS[id].fallback
      : "0";
  }

  const intVal = Math.trunc(parsed);
  if (Object.prototype.hasOwnProperty.call(NUMERIC_BOUNDS, id)) {
    const { min, max } = NUMERIC_BOUNDS[id];
    return String(Math.min(max, Math.max(min, intVal)));
  }

  return String(Math.min(999999, Math.max(-999999, intVal)));
}

function normalizeRankValue(rawValue) {
  const clean = sanitizeSingleLine(String(rawValue ?? ""), 6).toUpperCase();
  if (!clean) return "E";
  return ALLOWED_RANKS.includes(clean) ? clean : clean.slice(0, 4);
}

function normalizeControlValue(ctrl, rawValue) {
  if (!ctrl) return "";
  if (ctrl.id === "rank-val") {
    return normalizeRankValue(rawValue);
  }
  if (ctrl.type === "number") {
    return normalizeNumericValue(ctrl.id || "", rawValue);
  }
  if (ctrl.tagName === "TEXTAREA") {
    return sanitizeText(String(rawValue ?? ""), 5000);
  }
  return sanitizeSingleLine(String(rawValue ?? ""), 250);
}

function renderSafeText(element, text, maxLength = 220) {
  if (!element) return;
  element.textContent = sanitizeSingleLine(text, maxLength);
}

function hardenExternalLinks() {
  const links = document.querySelectorAll('a[target="_blank"]');
  links.forEach((link) => {
    const currentRel = (link.getAttribute("rel") || "").split(/\s+/).filter(Boolean);
    if (!currentRel.includes("noopener")) currentRel.push("noopener");
    if (!currentRel.includes("noreferrer")) currentRel.push("noreferrer");
    link.setAttribute("rel", currentRel.join(" "));
  });
}

function clearAuthSensitiveInputs() {
  const emailEl = document.getElementById("auth-email");
  const passEl = document.getElementById("auth-password");
  if (emailEl) emailEl.value = "";
  if (passEl) passEl.value = "";
  state.showPassword = false;
  updatePasswordVisibilityUI();
}

function initConsoleSecurityGuard() {
  try {
    const warnStyle = "color: #ffd966; font-size: 13px; font-weight: bold;";
    const bodyStyle = "color: #e4e4ec; font-size: 12px;";
    console.warn("%cAVISO DE SEGURANÇA - ORDEM DE ARKAN", warnStyle);
    console.log(
      "%cNão cole ou execute códigos desconhecidos no console. Isso pode alterar sua ficha ou comprometer sua sessão.",
      bodyStyle
    );
  } catch {
    // Ignora caso console esteja restrito
  }
}

/* --------------------------------------------------------------------------
   Helpers de Modo Administrador por UID
   -------------------------------------------------------------------------- */
function isCurrentUserAdmin() {
  return Boolean(state.user && typeof state.user.uid === "string" && state.user.uid === ADMIN_UID);
}

function sanitizeTargetUid(rawUid) {
  const clean = sanitizeSingleLine(String(rawUid ?? ""), 128);
  return UID_REGEX.test(clean) ? clean : "";
}

function saveAdminTargetUidToStorage(uid) {
  try {
    if (uid) {
      sessionStorage.setItem(STORAGE_KEYS.ADMIN_TARGET_UID, uid);
    } else {
      sessionStorage.removeItem(STORAGE_KEYS.ADMIN_TARGET_UID);
    }
  } catch {
    // Ignora falha de armazenamento
  }
}

function loadAdminTargetUidFromStorage() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEYS.ADMIN_TARGET_UID) || "";
    return sanitizeTargetUid(raw);
  } catch {
    return "";
  }
}

function getActiveTargetUid() {
  if (!state.user || !state.user.uid) return "";
  if (isCurrentUserAdmin() && state.adminTargetUid) {
    return state.adminTargetUid;
  }
  return state.user.uid;
}

function updateAdminBarUI() {
  const bar = document.getElementById("admin-uid-bar");
  const input = document.getElementById("admin-target-uid-input");
  const badge = document.getElementById("admin-target-status");

  if (!isCurrentUserAdmin()) {
    if (bar) bar.hidden = true;
    return;
  }

  ensureAdminBarElement();
  const activeBar = document.getElementById("admin-uid-bar");
  const activeInput = document.getElementById("admin-target-uid-input");
  const activeBadge = document.getElementById("admin-target-status");

  if (activeBar) activeBar.hidden = false;
  if (activeInput && document.activeElement !== activeInput) {
    activeInput.value = state.adminTargetUid || "";
  }
  if (activeBadge) {
    if (state.adminTargetUid && state.adminTargetUid !== state.user.uid) {
      activeBadge.textContent = `Editando UID alvo: ${state.adminTargetUid}`;
    } else {
      activeBadge.textContent = `Editando própria ficha (${state.user.uid})`;
    }
  }
  void bar;
  void input;
  void badge;
}

function ensureAdminBarElement() {
  if (document.getElementById("admin-uid-bar")) return;
  const appFicha = document.getElementById("app-ficha");
  const mainEl = document.querySelector("main.container");
  const anchorParent = mainEl && mainEl.parentNode ? mainEl.parentNode : appFicha;
  if (!anchorParent) return;

  const bar = document.createElement("section");
  bar.id = "admin-uid-bar";
  bar.hidden = true;
  bar.setAttribute("aria-label", "Painel de Administrador por UID");
  bar.style.cssText = [
    "margin: 10px auto 12px",
    "padding: 12px 14px",
    "max-width: 1120px",
    "border-radius: 10px",
    "border: 1px solid rgba(255, 217, 102, 0.45)",
    "background: rgba(20, 28, 36, 0.94)",
    "color: #f2f4f8",
    "display: flex",
    "flex-wrap: wrap",
    "gap: 8px",
    "align-items: center",
    "justify-content: space-between"
  ].join(";");

  const title = document.createElement("strong");
  title.textContent = "Modo Admin (UID)";
  title.style.cssText = "color: #ffd966; font-size: 13px;";

  const controlsWrap = document.createElement("div");
  controlsWrap.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; flex: 1 1 280px; align-items: center;";

  const input = document.createElement("input");
  input.type = "text";
  input.id = "admin-target-uid-input";
  input.placeholder = "Cole o UID do jogador...";
  input.autocomplete = "off";
  input.spellcheck = false;
  input.setAttribute("aria-label", "UID do usuário alvo");
  input.style.cssText = [
    "flex: 1 1 190px",
    "min-width: 150px",
    "padding: 8px 10px",
    "border-radius: 8px",
    "border: 1px solid rgba(255,255,255,0.22)",
    "background: rgba(10,14,18,0.85)",
    "color: #fff",
    "font-size: 13px"
  ].join(";");

  const loadBtn = document.createElement("button");
  loadBtn.type = "button";
  loadBtn.id = "admin-load-uid-btn";
  loadBtn.textContent = "Carregar UID";
  loadBtn.style.cssText = [
    "padding: 8px 12px",
    "border-radius: 8px",
    "border: none",
    "background: #2b8a6e",
    "color: #fff",
    "font-weight: 600",
    "font-size: 13px",
    "cursor: pointer"
  ].join(";");

  const selfBtn = document.createElement("button");
  selfBtn.type = "button";
  selfBtn.id = "admin-self-uid-btn";
  selfBtn.textContent = "Minha ficha";
  selfBtn.style.cssText = [
    "padding: 8px 12px",
    "border-radius: 8px",
    "border: 1px solid rgba(255,255,255,0.25)",
    "background: transparent",
    "color: #e4e4ec",
    "font-size: 13px",
    "cursor: pointer"
  ].join(";");

  const statusSpan = document.createElement("span");
  statusSpan.id = "admin-target-status";
  statusSpan.style.cssText = "width: 100%; font-size: 12px; color: #b8c2cc; word-break: break-all;";

  controlsWrap.appendChild(input);
  controlsWrap.appendChild(loadBtn);
  controlsWrap.appendChild(selfBtn);
  bar.appendChild(title);
  bar.appendChild(controlsWrap);
  bar.appendChild(statusSpan);

  if (mainEl && mainEl.parentNode === anchorParent) {
    anchorParent.insertBefore(bar, mainEl);
  } else {
    anchorParent.appendChild(bar);
  }

  loadBtn.addEventListener("click", handleAdminLoadTargetUid);
  selfBtn.addEventListener("click", handleAdminReturnToOwnSheet);
}

async function handleAdminLoadTargetUid(event) {
  if (event && event.isTrusted === false) return;
  if (!isCurrentUserAdmin()) {
    setStatusBanner("Apenas o administrador autorizado pode carregar fichas por UID.", "error");
    return;
  }

  const input = document.getElementById("admin-target-uid-input");
  const uid = sanitizeTargetUid(input ? input.value : "");
  if (!uid) {
    setStatusBanner("Informe um UID válido para carregar a ficha do jogador.", "warning");
    return;
  }

  state.adminTargetUid = uid;
  saveAdminTargetUidToStorage(uid);
  state.lastSavedSnapshot = "";
  updateAdminBarUI();
  setStatusBanner(`Carregando ficha do UID ${uid}...`, "info");
  await loadFromFirestore(uid);
}

async function handleAdminReturnToOwnSheet(event) {
  if (event && event.isTrusted === false) return;
  if (!state.user || !state.user.uid) return;

  state.adminTargetUid = "";
  saveAdminTargetUidToStorage("");
  state.lastSavedSnapshot = "";
  updateAdminBarUI();
  setStatusBanner("Voltando para a sua própria ficha...", "info");
  await loadFromFirestore(state.user.uid);
}

/* --------------------------------------------------------------------------
   Cálculo Automático da Tabela de Perícias (#tabela-pericias)
   -------------------------------------------------------------------------- */
function getSkillAttributeBonus(attrText) {
  const normalized = sanitizeSingleLine(attrText || "", 24)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();

  const inputId = Object.prototype.hasOwnProperty.call(ATTR_LABEL_TO_INPUT_ID, normalized)
    ? ATTR_LABEL_TO_INPUT_ID[normalized]
    : "";
  if (!inputId) return 0;

  const attrEl = document.getElementById(inputId);
  if (!attrEl) return 0;

  const val = Number(String(attrEl.value ?? "0").replace(",", "."));
  return Number.isFinite(val) ? Math.trunc(val) : 0;
}

function getSkillGradeBonus(selectEl) {
  if (!selectEl) return 0;
  const raw = sanitizeSingleLine(
    selectEl.value || (selectEl.options && selectEl.options[selectEl.selectedIndex]?.textContent) || "",
    24
  )
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase();

  return Object.prototype.hasOwnProperty.call(SKILL_GRADE_BONUS, raw)
    ? SKILL_GRADE_BONUS[raw]
    : 0;
}

function recalculateSkillsTable() {
  const table = document.getElementById("tabela-pericias");
  if (!table) return;

  const rows = table.querySelectorAll("tbody tr");
  rows.forEach((row) => {
    const attrCell = row.querySelector(".attr-tag");
    const gradeSelect = row.querySelector("select");
    const numberInputs = Array.from(row.querySelectorAll('input[type="number"]'));
    if (!numberInputs.length) return;

    const totalInput = row.querySelector("input.total-cell") || numberInputs[numberInputs.length - 1];
    const bonusInputs = numberInputs.filter((inp) => inp !== totalInput);

    let extrasSum = getSkillGradeBonus(gradeSelect);
    for (let i = 0; i < bonusInputs.length; i += 1) {
      const n = Number(String(bonusInputs[i].value ?? "0").replace(",", "."));
      if (Number.isFinite(n)) {
        extrasSum += Math.trunc(n);
      }
    }

    const attrBonus = getSkillAttributeBonus(attrCell ? attrCell.textContent : "");
    const total = attrBonus + extrasSum;

    if (totalInput) {
      totalInput.value = String(total);
    }
  });
}

/* --------------------------------------------------------------------------
   Cores Dinâmicas por Categoria Principal de Afinidade de Nen
   -------------------------------------------------------------------------- */
function normalizeNenCategoryKey(value) {
  if (typeof value !== "string") return "";
  const normalized = value
    .normalize("NFD")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/[\u0300-\u036f]/g, "")
    .trim()
    .toLowerCase();

  return Object.prototype.hasOwnProperty.call(NEN_CATEGORIES_MAP, normalized)
    ? NEN_CATEGORIES_MAP[normalized]
    : "";
}

function highlightNenCategoryRow(categoryKey) {
  const nenSection = document.querySelector(".coluna-nen");
  if (!nenSection) return;

  const rows = nenSection.querySelectorAll(".tabela-nen tbody tr");
  rows.forEach((row) => {
    const firstCellText = row.cells && row.cells[0] ? row.cells[0].textContent || "" : "";
    const rowKey = normalizeNenCategoryKey(firstCellText);
    const isMatch = Boolean(categoryKey) && rowKey === categoryKey;
    row.classList.toggle("nen-linha-ativa", isMatch);
  });
}

function applyNenCategoryTheme(rawValue) {
  const key = normalizeNenCategoryKey(rawValue);
  state.nenCategory = key;

  if (key) {
    document.documentElement.setAttribute("data-nen-categoria", key);
  } else {
    document.documentElement.removeAttribute("data-nen-categoria");
  }

  highlightNenCategoryRow(key);
}

function syncNenCategoryFromSelect() {
  const selectEl = document.getElementById("categoria-principal-nen");
  if (!selectEl) {
    applyNenCategoryTheme("");
    return;
  }
  const selectedText =
    selectEl.options && selectEl.selectedIndex >= 0
      ? selectEl.options[selectEl.selectedIndex].textContent || ""
      : "";
  applyNenCategoryTheme(selectEl.value || selectedText);
}

function setStatusBanner(message, type = "info") {
  const banner = document.getElementById("status-banner");
  if (!banner) return;
  const cleanMessage = sanitizeSingleLine(message, 220);
  const allowedTypes = ["info", "success", "warning", "error"];
  banner.textContent = cleanMessage;
  banner.dataset.statusType = allowedTypes.includes(type) ? type : "info";
  banner.hidden = !cleanMessage;
}

function setEntradaStatus(message) {
  const statusEl = document.getElementById("entrada-status");
  if (!statusEl) return;
  const clean = sanitizeSingleLine(message, 220);
  statusEl.textContent = clean;
  statusEl.hidden = !clean;
}

function hasCookieConsent() {
  if (state.cookieConsentAccepted) return true;
  try {
    const accepted = localStorage.getItem(STORAGE_KEYS.COOKIE_CONSENT) === "accepted";
    if (accepted) state.cookieConsentAccepted = true;
    return accepted;
  } catch {
    return false;
  }
}

function setLgpdBannerVisibility(shouldHide) {
  const banner = document.getElementById("lgpd-banner");
  if (!banner) return;
  banner.hidden = Boolean(shouldHide);
  if (shouldHide) {
    banner.style.setProperty("display", "none", "important");
  } else {
    banner.style.removeProperty("display");
  }
}

function aceitarLgpdBanner() {
  state.cookieConsentAccepted = true;
  try {
    localStorage.setItem(STORAGE_KEYS.COOKIE_CONSENT, "accepted");
  } catch {
    // Mantém o aceite em memória caso o localStorage esteja bloqueado
  }
  setLgpdBannerVisibility(true);
  if (!state.offlineMode) {
    saveLocalData(collectSheetData());
  }
}

window.__aceitarLgpdArkan = aceitarLgpdBanner;

/* --------------------------------------------------------------------------
   Atualização da Seção Ativa no Topo Conforme Rolagem
   -------------------------------------------------------------------------- */
function setActiveSectionIndicator(sectionId) {
  const match = TRACKED_SECTIONS.find((item) => item.id === sectionId) || TRACKED_SECTIONS[0];
  state.activeSectionId = match.id;

  const indicatorEl = document.getElementById("secao-atual-topo");
  if (indicatorEl) {
    indicatorEl.textContent = match.label;
  }

  const navLinks = document.querySelectorAll(".abas .aba-btn[data-secao-alvo]");
  navLinks.forEach((link) => {
    const isCurrent = link.dataset.secaoAlvo === match.id;
    link.classList.toggle("aba-btn-ativa", isCurrent);
    if (isCurrent) {
      link.setAttribute("aria-current", "true");
    } else {
      link.removeAttribute("aria-current");
    }
  });
}

function resolveCurrentSectionByViewport() {
  const topoEl = document.querySelector(".topo");
  const topOffset = topoEl ? topoEl.getBoundingClientRect().height : 90;
  const viewportBottom = window.innerHeight;
  const anchorLine = topOffset + Math.min(140, (viewportBottom - topOffset) * 0.25);

  let bestId = TRACKED_SECTIONS[0].id;
  let bestScore = -1;

  for (let i = 0; i < TRACKED_SECTIONS.length; i += 1) {
    const secInfo = TRACKED_SECTIONS[i];
    const secEl = document.getElementById(secInfo.id);
    if (!secEl) continue;

    const rect = secEl.getBoundingClientRect();
    const visibleTop = Math.max(rect.top, topOffset);
    const visibleBottom = Math.min(rect.bottom, viewportBottom);
    const visibleHeight = Math.max(0, visibleBottom - visibleTop);

    const crossesAnchor = rect.top <= anchorLine && rect.bottom > topOffset + 12;
    const score = visibleHeight + (crossesAnchor ? viewportBottom : 0);

    if (score > bestScore) {
      bestScore = score;
      bestId = secInfo.id;
    }
  }

  return bestId;
}

function syncActiveSectionOnScroll() {
  const appFicha = document.getElementById("app-ficha");
  if (!appFicha || appFicha.hidden) return;

  const currentId = resolveCurrentSectionByViewport();
  if (currentId && currentId !== state.activeSectionId) {
    setActiveSectionIndicator(currentId);
  }
}

function scheduleScrollSectionSync() {
  if (state.scrollRafId !== null) return;
  state.scrollRafId = window.requestAnimationFrame(() => {
    state.scrollRafId = null;
    syncActiveSectionOnScroll();
  });
}

/* --------------------------------------------------------------------------
   Controle do Ecrã de Entrada (Login Firebase vs. Offline/Local Temporário)
   -------------------------------------------------------------------------- */
function updateScreenAccess() {
  const entradaScreen = document.getElementById("entrada-screen");
  const appFicha = document.getElementById("app-ficha");
  const hasSession = Boolean(state.user) || Boolean(state.offlineMode);

  if (entradaScreen) {
    entradaScreen.hidden = hasSession;
  }
  if (appFicha) {
    appFicha.hidden = !hasSession;
  }

  updateAdminBarUI();

  if (hasSession) {
    syncNenCategoryFromSelect();
    recalculateSkillsTable();
    window.requestAnimationFrame(() => {
      syncActiveSectionOnScroll();
    });
  }
}

function enterOfflineTemporaryMode() {
  state.offlineMode = true;
  state.lastSavedSnapshot = "";
  clearAuthSensitiveInputs();
  setEntradaStatus("");
  updateAuthUI();
  updateScreenAccess();
  setStatusBanner(
    "Modo offline/local ativo: as informações não ficam salvas se você carregar a página novamente.",
    "warning"
  );
  window.scrollTo({ top: 0, behavior: "smooth" });
}

/* --------------------------------------------------------------------------
   Coleta, Limpeza e Aplicação Segura de Dados na Ficha
   -------------------------------------------------------------------------- */
function buildFieldKey(ctrl, index) {
  if (ctrl.id && /^[a-zA-Z0-9_-]{1,64}$/.test(ctrl.id) && !isForbiddenKey(ctrl.id)) {
    return `id:${ctrl.id}`;
  }
  return `idx:${index}`;
}

function computeFieldsSnapshot(fieldsObj) {
  if (!fieldsObj || typeof fieldsObj !== "object") return "";
  const sortedKeys = Object.keys(fieldsObj).sort();
  const ordered = createSafeRecord();
  for (let i = 0; i < sortedKeys.length; i += 1) {
    const k = sortedKeys[i];
    if (!isValidFieldKey(k)) continue;
    ordered[k] = fieldsObj[k];
  }
  return JSON.stringify(ordered);
}

function collectSheetData() {
  recalculateSkillsTable();

  const fields = createSafeRecord();
  const mainEl = document.querySelector("main.container");
  if (!mainEl) {
    return { fields, atualizadoEm: new Date().toISOString() };
  }

  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl, index) => {
    if (!ctrl || ctrl.closest("#login-firebase")) return;
    const key = buildFieldKey(ctrl, index);
    if (!isValidFieldKey(key)) return;

    if (ctrl.type === "checkbox") {
      fields[key] = Boolean(ctrl.checked);
    } else {
      const normalized = normalizeControlValue(ctrl, ctrl.value);
      if (ctrl.value !== normalized && document.activeElement !== ctrl) {
        ctrl.value = normalized;
      }
      fields[key] = normalized;
    }
  });

  return {
    fields,
    atualizadoEm: new Date().toISOString()
  };
}

function buildSanitizedCloudPayload() {
  const raw = collectSheetData();
  const cleanFields = createSafeRecord();

  if (raw && raw.fields && typeof raw.fields === "object") {
    const entries = Object.entries(raw.fields).slice(0, 1500);
    for (let i = 0; i < entries.length; i += 1) {
      const [key, val] = entries[i];
      if (!isValidFieldKey(key)) continue;

      if (typeof val === "boolean") {
        cleanFields[key] = val;
      } else if (typeof val === "number" && Number.isFinite(val)) {
        cleanFields[key] = String(Math.trunc(val)).slice(0, 24);
      } else if (typeof val === "string") {
        cleanFields[key] =
          key.startsWith("id:anotacoes") ||
          key.startsWith("id:hist-") ||
          key.startsWith("id:proficiencias")
            ? sanitizeText(val, 5000)
            : sanitizeSingleLine(val, 250);
      }
    }
  }

  return {
    fields: cleanFields,
    atualizadoEm: new Date().toISOString()
  };
}

function applySheetData(data) {
  if (!data || typeof data !== "object" || !data.fields || typeof data.fields !== "object") {
    recalculateSkillsTable();
    syncNenCategoryFromSelect();
    return;
  }

  const mainEl = document.querySelector("main.container");
  if (!mainEl) return;

  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl, index) => {
    if (!ctrl || ctrl.closest("#login-firebase")) return;
    const key = buildFieldKey(ctrl, index);
    if (!isValidFieldKey(key)) return;
    if (!Object.prototype.hasOwnProperty.call(data.fields, key)) return;

    const savedVal = data.fields[key];
    if (ctrl.type === "checkbox") {
      ctrl.checked = Boolean(savedVal);
    } else if (typeof savedVal === "string" || typeof savedVal === "number") {
      ctrl.value = normalizeControlValue(ctrl, String(savedVal));
    }
  });

  recalculateSkillsTable();
  state.lastSavedSnapshot = computeFieldsSnapshot(collectSheetData().fields);
  syncNenCategoryFromSelect();
}

function resetSheetFieldsToDefault() {
  const mainEl = document.querySelector("main.container");
  if (!mainEl) return;

  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl) => {
    if (!ctrl || ctrl.closest("#login-firebase")) return;

    if (ctrl.type === "checkbox") {
      ctrl.checked = false;
    } else if (ctrl.tagName === "SELECT") {
      ctrl.selectedIndex = 0;
    } else if (ctrl.type === "number") {
      if (ctrl.id === "def-total" || ctrl.id === "def-esquiva") {
        ctrl.value = "11";
      } else if (ctrl.id === "def-deslocamento") {
        ctrl.value = "9";
      } else if (
        ctrl.id === "attr-agi" ||
        ctrl.id === "attr-for" ||
        ctrl.id === "attr-ca" ||
        ctrl.id === "attr-int" ||
        ctrl.id === "attr-vig" ||
        ctrl.id === "nv-val"
      ) {
        ctrl.value = "1";
      } else if (ctrl.id === "espacos-max") {
        ctrl.value = "5";
      } else {
        ctrl.value = "0";
      }
    } else if (ctrl.id === "rank-val") {
      ctrl.value = "E";
    } else {
      ctrl.value = "";
    }
  });

  recalculateSkillsTable();
  state.lastSavedSnapshot = "";
  syncNenCategoryFromSelect();
}

function saveLocalData(data) {
  if (state.offlineMode) return;
  if (!hasCookieConsent()) return;
  try {
    const serialized = JSON.stringify(data);
    if (serialized.length > 500000) return;
    localStorage.setItem(STORAGE_KEYS.LOCAL_SHEET, serialized);
  } catch (err) {
    console.warn("Não foi possível salvar localmente:", err);
  }
}

function loadLocalData() {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.LOCAL_SHEET);
    if (!raw || raw.length > 500000) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !parsed.fields || typeof parsed.fields !== "object") {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

function clearLocalData() {
  try {
    localStorage.removeItem(STORAGE_KEYS.LOCAL_SHEET);
  } catch {
    // Ignora falha de armazenamento
  }
}

/* --------------------------------------------------------------------------
   Firebase Authentication + Cloud Firestore
   -------------------------------------------------------------------------- */
function hasValidFirebaseConfig(cfg) {
  if (!cfg || typeof cfg !== "object") return false;
  return ["apiKey", "authDomain", "projectId", "appId"].every(
    (k) =>
      typeof cfg[k] === "string" &&
      cfg[k].trim().length > 5 &&
      !cfg[k].includes("SUBSTITUA_") &&
      !cfg[k].includes("SUA_")
  );
}

function mapFirebaseAuthError(err) {
  const code = err && typeof err.code === "string" ? err.code : "";
  switch (code) {
    case "auth/invalid-email":
      return "Formato de e-mail inválido.";
    case "auth/user-not-found":
    case "auth/wrong-password":
    case "auth/invalid-credential":
      return "E-mail ou senha incorretos.";
    case "auth/email-already-in-use":
      return "Este e-mail já está cadastrado. Alterne para Entrar.";
    case "auth/weak-password":
      return "Escolha uma senha mais forte (mínimo de 6 caracteres).";
    case "auth/too-many-requests":
      return "Muitas tentativas seguidas. Aguarde alguns instantes e tente novamente.";
    case "auth/network-request-failed":
      return "Erro de conexão ou bloqueio no GitHub Pages ao falar com o servidor.";
    default:
      return "Não foi possível autenticar. Confira e-mail, senha e o método E-mail/Senha no Firebase.";
  }
}

function formatDatabaseOrHostingError(err) {
  const code = err && typeof err.code === "string" ? err.code : "";
  if (navigator.onLine === false) {
    return "Sem conexão com a internet no momento. Verifique sua rede ou use o modo offline/local.";
  }
  if (code === "permission-denied") {
    return "Erro no banco de dados (Firestore): permissão negada pelas regras de segurança.";
  }
  if (code === "unavailable" || code === "deadline-exceeded") {
    return "Erro no banco de dados (Firestore): serviço temporariamente indisponível ou sem resposta.";
  }
  if (code === "failed-precondition") {
    return "Erro no banco de dados (Firestore): pré-condição ou índice pendente no projeto.";
  }
  if (code === "auth/network-request-failed") {
    return "Erro de rede / GitHub Pages ao comunicar com o Firebase.";
  }
  return "Não foi possível conectar ao banco de dados ou ao servidor do GitHub Pages ao tentar autenticar.";
}

async function checkEnvironmentAndFirestoreBeforeLogin() {
  if (navigator.onLine === false) {
    throw Object.assign(new Error("Offline"), { code: "offline-browser" });
  }
  if (state.db && state.firebaseModules && state.firebaseModules.firestoreMod) {
    const { doc, getDoc } = state.firebaseModules.firestoreMod;
    const probeRef = doc(state.db, FIRESTORE_COLLECTION, "__login_check__");
    try {
      await getDoc(probeRef);
    } catch (dbErr) {
      const dbCode = dbErr && typeof dbErr.code === "string" ? dbErr.code : "";
      if (dbCode === "unavailable" || dbCode === "deadline-exceeded" || dbCode === "failed-precondition") {
        throw dbErr;
      }
    }
  }
}

async function initFirebase() {
  if (!hasValidFirebaseConfig(FIREBASE_CONFIG)) {
    setEntradaStatus("Firebase não configurado. Use a opção Entrar offline/local.");
    return;
  }

  try {
    const baseUrl = `https://www.gstatic.com/firebasejs/${FIREBASE_SDK_VERSION}`;
    const [{ initializeApp }, authMod, firestoreMod] = await Promise.all([
      import(`${baseUrl}/firebase-app.js`),
      import(`${baseUrl}/firebase-auth.js`),
      import(`${baseUrl}/firebase-firestore.js`)
    ]);

    const app = initializeApp(FIREBASE_CONFIG);
    state.auth = authMod.getAuth(app);
    state.db = firestoreMod.getFirestore(app);
    state.firebaseModules = Object.freeze({ authMod, firestoreMod });
    state.firebaseReady = true;

    authMod.onAuthStateChanged(state.auth, async (user) => {
      state.user = user || null;
      if (user) {
        state.offlineMode = false;
        if (user.uid === ADMIN_UID) {
          state.adminTargetUid = loadAdminTargetUidFromStorage();
        } else {
          state.adminTargetUid = "";
          saveAdminTargetUidToStorage("");
        }
        clearAuthSensitiveInputs();
        setEntradaStatus("");
      } else {
        state.adminTargetUid = "";
        saveAdminTargetUidToStorage("");
      }
      updateAuthUI();
      updateScreenAccess();

      if (user) {
        if (!state.isDeleting) {
          const targetUid = getActiveTargetUid();
          const isRemoteTarget = user.uid === ADMIN_UID && targetUid && targetUid !== user.uid;
          setStatusBanner(
            isRemoteTarget
              ? `Admin conectado. Carregando ficha do UID ${targetUid}...`
              : `Conectado como ${sanitizeSingleLine(user.email || "agente", 160)}. Carregando ficha...`,
            "info"
          );
          await loadFromFirestore(targetUid || user.uid);
        }
      } else if (!state.isDeleting && !state.offlineMode) {
        setStatusBanner("Faça login para salvar e carregar sua ficha no Firebase.", "info");
      }
    });
  } catch {
    setEntradaStatus(
      "Falha ao carregar recursos no GitHub Pages ou conectar ao Firebase. Você pode entrar offline/local."
    );
  }
}

async function loadFromFirestore(uid) {
  if (!state.firebaseReady || !state.db || !uid) return;
  const { doc, getDoc, setDoc } = state.firebaseModules.firestoreMod;

  try {
    const docRef = doc(state.db, FIRESTORE_COLLECTION, uid);
    const snap = await getDoc(docRef);

    if (snap.exists()) {
      const cloudData = snap.data();
      applySheetData(cloudData);
      if (!isCurrentUserAdmin() || uid === state.user?.uid) {
        saveLocalData(cloudData);
      }
      setStatusBanner(
        isCurrentUserAdmin() && uid !== state.user?.uid
          ? `Ficha carregada do UID alvo (${uid}).`
          : "Ficha carregada do banco de dados Firebase.",
        "success"
      );
    } else {
      resetSheetFieldsToDefault();
      const initialData = buildSanitizedCloudPayload();
      await setDoc(docRef, initialData);
      state.lastSavedSnapshot = computeFieldsSnapshot(initialData.fields);
      state.lastCloudWriteAt = Date.now();
      if (!isCurrentUserAdmin() || uid === state.user?.uid) {
        saveLocalData(initialData);
      }
      setStatusBanner(
        isCurrentUserAdmin() && uid !== state.user?.uid
          ? `Nova ficha criada para o UID alvo (${uid}).`
          : "Nova ficha criada na sua conta do Firebase.",
        "success"
      );
    }
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    if (code === "permission-denied") {
      setStatusBanner("Permissão negada no Firestore ao ler este UID.", "error");
    } else {
      setStatusBanner("Erro ao ler dados do Firebase. Verifique as regras do Firestore.", "error");
    }
  }
}

async function saveToFirestore(uid, data) {
  if (!state.firebaseReady || !state.db || !uid || typeof uid !== "string") {
    return false;
  }
  const { doc, setDoc } = state.firebaseModules.firestoreMod;
  const docRef = doc(state.db, FIRESTORE_COLLECTION, uid);
  const safeData = data && data.fields ? data : buildSanitizedCloudPayload();
  await setDoc(docRef, safeData, { merge: true });
  state.lastCloudWriteAt = Date.now();
  return true;
}

async function handleClearSheetData(event) {
  if (event && event.isTrusted === false) return;
  if (state.isSaving || state.isDeleting) return;

  if (state.saveTimer) {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
  }

  const targetUid = getActiveTargetUid();
  const isRemoteTarget = Boolean(isCurrentUserAdmin() && targetUid && targetUid !== state.user?.uid);

  resetSheetFieldsToDefault();
  if (!isRemoteTarget) {
    clearLocalData();
  }

  const clearConfirmBox = document.getElementById("sheet-clear-confirm-box");
  if (clearConfirmBox) clearConfirmBox.hidden = true;

  if (state.firebaseReady && state.db && targetUid) {
    const { doc, deleteDoc } = state.firebaseModules.firestoreMod;
    try {
      await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, targetUid));
      setStatusBanner(
        isRemoteTarget
          ? `Ficha do UID ${targetUid} excluída da nuvem.`
          : "Ficha excluída da nuvem e do navegador.",
        "success"
      );
      return;
    } catch {
      setStatusBanner("Ficha limpa na tela, mas houve erro ao apagar na nuvem.", "error");
      return;
    }
  }

  setStatusBanner("Ficha limpa.", "warning");
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  if (event && event.isTrusted === false) return;
  if (!state.firebaseReady || !state.auth) {
    setEntradaStatus("Firebase ainda não foi inicializado ou houve falha no carregamento do GitHub Pages.");
    return;
  }

  const emailEl = document.getElementById("auth-email");
  const passEl = document.getElementById("auth-password");
  const email = sanitizeSingleLine(emailEl ? emailEl.value : "", 160);
  const password = passEl ? passEl.value : "";

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 6) {
    setEntradaStatus("Preencha um e-mail válido e uma senha com pelo menos 6 caracteres.");
    return;
  }

  const { signInWithEmailAndPassword, createUserWithEmailAndPassword } = state.firebaseModules.authMod;

  try {
    setEntradaStatus(state.authMode === "register" ? "Criando conta..." : "Entrando...");
    await checkEnvironmentAndFirestoreBeforeLogin();
    if (state.authMode === "register") {
      await createUserWithEmailAndPassword(state.auth, email, password);
    } else {
      await signInWithEmailAndPassword(state.auth, email, password);
    }
    clearAuthSensitiveInputs();
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    if (
      navigator.onLine === false ||
      code === "offline-browser" ||
      code === "unavailable" ||
      code === "deadline-exceeded" ||
      code === "failed-precondition" ||
      code === "permission-denied" ||
      code === "auth/network-request-failed"
    ) {
      setEntradaStatus(formatDatabaseOrHostingError(err));
    } else {
      setEntradaStatus(mapFirebaseAuthError(err));
    }
  }
}

async function handleLogout(event) {
  if (event && event.isTrusted === false) return;
  state.offlineMode = false;
  state.adminTargetUid = "";
  saveAdminTargetUidToStorage("");
  state.lastSavedSnapshot = "";
  clearAuthSensitiveInputs();

  if (state.firebaseReady && state.auth && state.user) {
    try {
      const { signOut } = state.firebaseModules.authMod;
      await signOut(state.auth);
    } catch {
      setStatusBanner("Erro ao encerrar a sessão.", "error");
      return;
    }
  }
  updateAuthUI();
  updateScreenAccess();
  setEntradaStatus("Você saiu da sessão. Escolha como deseja entrar novamente.");
}

async function handleDeleteAccount(event) {
  if (event && event.isTrusted === false) return;
  if (!state.firebaseReady || !state.auth || !state.auth.currentUser || state.isDeleting) {
    return;
  }

  const currentUser = state.auth.currentUser;
  const uid = currentUser.uid;
  const { deleteUser } = state.firebaseModules.authMod;
  const { doc, deleteDoc } = state.firebaseModules.firestoreMod;

  state.isDeleting = true;
  setStatusBanner("Excluindo conta e dados salvos...", "info");

  try {
    if (state.db && uid) {
      await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, uid));
    }

    await deleteUser(currentUser);
    clearLocalData();
    clearAuthSensitiveInputs();
    state.offlineMode = false;
    state.adminTargetUid = "";
    saveAdminTargetUidToStorage("");
    state.lastSavedSnapshot = "";

    const confirmBox = document.getElementById("auth-delete-confirm-box");
    if (confirmBox) confirmBox.hidden = true;

    updateAuthUI();
    updateScreenAccess();
    setEntradaStatus("Conta e ficha excluídas permanentemente do Firebase.");
  } catch (err) {
    if (err && err.code === "auth/requires-recent-login") {
      setStatusBanner("Por segurança, saia e entre novamente antes de excluir a conta.", "warning");
    } else {
      setStatusBanner("Não foi possível excluir a conta. Verifique as regras do Firestore e tente novamente.", "error");
    }
  } finally {
    state.isDeleting = false;
  }
}

/* --------------------------------------------------------------------------
   Salvamento da Ficha (com proteção contra gravação redundante e spam)
   -------------------------------------------------------------------------- */
async function persistSheet(forceWrite = false) {
  if (state.isSaving || state.isDeleting) return;
  state.isSaving = true;

  try {
    const payload = collectSheetData();
    const currentSnapshot = computeFieldsSnapshot(payload.fields);

    if (state.offlineMode && !state.user) {
      setStatusBanner(
        "Modo offline/local: alterações não ficam salvas se você carregar a página novamente.",
        "warning"
      );
      return;
    }

    if (!forceWrite && currentSnapshot === state.lastSavedSnapshot) {
      return;
    }

    const targetUid = getActiveTargetUid();
    const isRemoteTarget = Boolean(isCurrentUserAdmin() && targetUid && targetUid !== state.user?.uid);

    if (!isRemoteTarget) {
      saveLocalData(payload);
    }

    if (state.firebaseReady && state.user && targetUid) {
      const elapsed = Date.now() - state.lastCloudWriteAt;
      if (!forceWrite && elapsed < MIN_CLOUD_SAVE_INTERVAL_MS) {
        scheduleAutoSave();
        return;
      }

      const cloudPayload = buildSanitizedCloudPayload();
      await saveToFirestore(targetUid, cloudPayload);
      state.lastSavedSnapshot = computeFieldsSnapshot(cloudPayload.fields);
      setStatusBanner(
        isRemoteTarget
          ? `Ficha salva no Firestore para o UID ${targetUid}.`
          : "Ficha salva no banco de dados Firebase.",
        "success"
      );
    } else if (hasCookieConsent()) {
      state.lastSavedSnapshot = currentSnapshot;
      setStatusBanner("Alterações salvas localmente.", "info");
    } else {
      setStatusBanner("Aceite o banner LGPD para salvar localmente ou faça login no Firebase.", "info");
    }
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    if (code === "permission-denied") {
      setStatusBanner("Permissão negada no Firestore ao salvar a ficha.", "error");
    } else {
      setStatusBanner("Erro ao salvar no Firebase. Confira as permissões do Firestore.", "error");
    }
  } finally {
    state.isSaving = false;
  }
}

function scheduleAutoSave() {
  if (state.saveTimer) clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => {
    persistSheet(false);
  }, 750);
}

/* --------------------------------------------------------------------------
   Interface e Eventos
   -------------------------------------------------------------------------- */
function updatePasswordVisibilityUI() {
  const passEl = document.getElementById("auth-password");
  const togglePassBtn = document.getElementById("auth-toggle-password");
  const visible = Boolean(state.showPassword);

  if (passEl) {
    passEl.type = visible ? "text" : "password";
  }

  if (togglePassBtn) {
    togglePassBtn.setAttribute("aria-pressed", visible ? "true" : "false");
    togglePassBtn.setAttribute(
      "aria-label",
      visible ? "Ocultar senha enquanto digita" : "Mostrar senha enquanto digita"
    );
    togglePassBtn.textContent = visible ? "Ocultar" : "Mostrar";
  }
}

function updateAuthUI() {
  const loggedInBox = document.getElementById("auth-logged-in");
  const offlineBox = document.getElementById("offline-session-box");
  const userEmailEl = document.getElementById("auth-user-email");
  const submitBtn = document.getElementById("auth-submit-btn");
  const toggleBtn = document.getElementById("auth-toggle-mode");
  const confirmBox = document.getElementById("auth-delete-confirm-box");
  const clearConfirmBox = document.getElementById("sheet-clear-confirm-box");

  if (confirmBox) confirmBox.hidden = true;
  if (clearConfirmBox) clearConfirmBox.hidden = true;

  renderSafeText(
    submitBtn,
    state.authMode === "register" ? "Cadastrar" : "Entrar",
    40
  );
  renderSafeText(
    toggleBtn,
    state.authMode === "register" ? "Já tenho conta (Entrar)" : "Criar nova conta",
    60
  );

  if (state.user) {
    if (loggedInBox) loggedInBox.hidden = false;
    if (offlineBox) offlineBox.hidden = true;
    state.showPassword = false;
    updatePasswordVisibilityUI();
    renderSafeText(userEmailEl, state.user.email || "Conta ativa", 160);
  } else if (state.offlineMode) {
    if (loggedInBox) loggedInBox.hidden = true;
    if (offlineBox) offlineBox.hidden = false;
    updatePasswordVisibilityUI();
  } else {
    if (loggedInBox) loggedInBox.hidden = true;
    if (offlineBox) offlineBox.hidden = true;
    updatePasswordVisibilityUI();
  }

  updateAdminBarUI();
}

function initLgpdBanner() {
  setLgpdBannerVisibility(hasCookieConsent());

  const acceptBtn = document.getElementById("lgpd-accept-btn");
  if (!acceptBtn || acceptBtn.dataset.lgpdBound === "1") return;
  acceptBtn.dataset.lgpdBound = "1";

  acceptBtn.addEventListener("click", aceitarLgpdBanner);
}

function bindEvents() {
  window.addEventListener("scroll", scheduleScrollSectionSync, { passive: true });
  window.addEventListener("resize", scheduleScrollSectionSync, { passive: true });

  const rodapeDetalhesBtn = document.getElementById("btn-rodape-detalhes");
  const rodapePainelLgpd = document.getElementById("rodape-painel-lgpd");
  const rodapeEl = document.getElementById("rodape-criador");

  if (rodapeDetalhesBtn && rodapePainelLgpd) {
    rodapeDetalhesBtn.addEventListener("click", () => {
      const seraOcultado = !rodapePainelLgpd.hidden;
      rodapePainelLgpd.hidden = seraOcultado;
      rodapeDetalhesBtn.setAttribute("aria-expanded", seraOcultado ? "false" : "true");
      if (rodapeEl) {
        rodapeEl.classList.toggle("rodape-destacado", !seraOcultado);
      }
    });
  }

  const nenSelect = document.getElementById("categoria-principal-nen");
  if (nenSelect) {
    nenSelect.addEventListener("change", (event) => {
      const target = event.target;
      const selectedOptionText =
        target && target.options && target.selectedIndex >= 0
          ? target.options[target.selectedIndex].textContent || ""
          : "";
      applyNenCategoryTheme((target && target.value) || selectedOptionText);
    });
  }

  const navLinks = document.querySelectorAll(".abas .aba-btn[data-secao-alvo]");
  navLinks.forEach((link) => {
    link.addEventListener("click", () => {
      const targetId = link.dataset.secaoAlvo;
      if (targetId) {
        setActiveSectionIndicator(targetId);
      }
      window.setTimeout(syncActiveSectionOnScroll, 320);
    });
  });

  const offlineBtn = document.getElementById("btn-entrar-offline");
  if (offlineBtn) {
    offlineBtn.addEventListener("click", enterOfflineTemporaryMode);
  }

  const voltarEntradaBtn = document.getElementById("btn-voltar-entrada");
  if (voltarEntradaBtn) {
    voltarEntradaBtn.addEventListener("click", handleLogout);
  }

  const irLoginNuvemBtn = document.getElementById("btn-ir-login-nuvem");
  if (irLoginNuvemBtn) {
    irLoginNuvemBtn.addEventListener("click", () => {
      state.offlineMode = false;
      clearAuthSensitiveInputs();
      updateAuthUI();
      updateScreenAccess();
      setEntradaStatus("Entre com sua conta Firebase para salvar na nuvem.");
    });
  }

  const togglePassBtn = document.getElementById("auth-toggle-password");
  if (togglePassBtn) {
    togglePassBtn.addEventListener("click", () => {
      state.showPassword = !state.showPassword;
      updatePasswordVisibilityUI();
      const passEl = document.getElementById("auth-password");
      if (passEl) passEl.focus();
    });
  }

  const authForm = document.getElementById("auth-form");
  if (authForm) {
    authForm.addEventListener("submit", handleAuthSubmit);
  }

  const toggleBtn = document.getElementById("auth-toggle-mode");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      state.authMode = state.authMode === "login" ? "register" : "login";
      updateAuthUI();
    });
  }

  const logoutBtn = document.getElementById("auth-logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", handleLogout);
  }

  const clearOpenBtn = document.getElementById("sheet-clear-open-btn");
  const clearConfirmBox = document.getElementById("sheet-clear-confirm-box");
  const clearConfirmBtn = document.getElementById("sheet-clear-confirm-btn");
  const clearCancelBtn = document.getElementById("sheet-clear-cancel-btn");
  const clearOfflineBtn = document.getElementById("sheet-clear-offline-btn");

  const deleteOpenBtn = document.getElementById("auth-delete-open-btn");
  const deleteConfirmBox = document.getElementById("auth-delete-confirm-box");
  const deleteConfirmBtn = document.getElementById("auth-delete-confirm-btn");
  const deleteCancelBtn = document.getElementById("auth-delete-cancel-btn");

  if (clearOpenBtn && clearConfirmBox) {
    clearOpenBtn.addEventListener("click", () => {
      if (deleteConfirmBox) deleteConfirmBox.hidden = true;
      clearConfirmBox.hidden = !clearConfirmBox.hidden;
    });
  }

  if (clearCancelBtn && clearConfirmBox) {
    clearCancelBtn.addEventListener("click", () => {
      clearConfirmBox.hidden = true;
    });
  }

  if (clearConfirmBtn) {
    clearConfirmBtn.addEventListener("click", handleClearSheetData);
  }

  if (clearOfflineBtn) {
    clearOfflineBtn.addEventListener("click", handleClearSheetData);
  }

  if (deleteOpenBtn && deleteConfirmBox) {
    deleteOpenBtn.addEventListener("click", () => {
      if (clearConfirmBox) clearConfirmBox.hidden = true;
      deleteConfirmBox.hidden = !deleteConfirmBox.hidden;
    });
  }

  if (deleteCancelBtn && deleteConfirmBox) {
    deleteCancelBtn.addEventListener("click", () => {
      deleteConfirmBox.hidden = true;
    });
  }

  if (deleteConfirmBtn) {
    deleteConfirmBtn.addEventListener("click", handleDeleteAccount);
  }

  const saveBtn = document.getElementById("btn-save-sheet");
  if (saveBtn) {
    saveBtn.addEventListener("click", () => persistSheet(true));
  }

  const syncBtn = document.getElementById("auth-sync-btn");
  if (syncBtn) {
    syncBtn.addEventListener("click", () => persistSheet(true));
  }

  const mainEl = document.querySelector("main.container");
  if (mainEl) {
    const handleFieldUpdate = (event) => {
      if (event.target && event.target.closest("#login-firebase")) return;
      recalculateSkillsTable();
      scheduleAutoSave();
    };
    mainEl.addEventListener("input", handleFieldUpdate);
    mainEl.addEventListener("change", handleFieldUpdate);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initConsoleSecurityGuard();
  hardenExternalLinks();
  initLgpdBanner();

  const localData = loadLocalData();
  if (localData) {
    applySheetData(localData);
  } else {
    recalculateSkillsTable();
    syncNenCategoryFromSelect();
  }

  setActiveSectionIndicator("dados-agente");
  updateAuthUI();
  updateScreenAccess();
  bindEvents();
  initFirebase();
});
