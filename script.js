/* ==========================================================================
   Ordem de Arkan - Ficha de Agente (script.js)
   Módulos organizados por responsabilidade única:
   1. Configuração e Constantes
   2. Sanitização, Validação e Segurança de Entrada
   3. Animação de Escrita 3D na Tela de Login
   4. Cálculo de Perícias e Tema Dinâmico de Nen
   5. Privacidade (LGPD) e Navegação por Seção
   6. Coleta, Normalização e Persistência Local/Nuvem (Própria ou Alvo Admin)
   7. Autenticação Firebase, Permissão Admin Exclusiva e Mensagens
   8. Comandos do Administrador com "/" (1 comando = 1 função específica)
   9. Interface, Banners, Modo Somente Leitura e Inicialização
   ========================================================================== */

"use strict";

/* --------------------------------------------------------------------------
   1. Configuração e Constantes
   -------------------------------------------------------------------------- */
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
  COOKIE_CONSENT: "ordem_de_arkan_lgpd_v1"
});

const FORBIDDEN_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);
const FIRESTORE_COLLECTION = "fichas_ordem_arkan";
const FIRESTORE_MESSAGES_COLLECTION = "mensagens_ordem_arkan";
const FIREBASE_SDK_VERSION = "10.14.1";
const MIN_CLOUD_SAVE_INTERVAL_MS = 1200;
const AUTO_SAVE_DEBOUNCE_MS = 750;

// UID exclusivo autorizado a acessar a função de administrador
const ADMIN_EXCLUSIVE_UID = "TcudbnuOMcTySJWhz0JHaNDuNU22";

const LOGIN_TYPEWRITER_CONFIG = Object.freeze({
  defaultTitle: "Ordem de Arkan",
  initialDelayMs: 140,
  stepDelayMs: 95,
  letterAnimMs: 340,
  cursorFinishBufferMs: 420
});

const TRACKED_SECTIONS = Object.freeze([
  { id: "dados-agente", label: "Dados do Agente" },
  { id: "equipamentos-habilidades", label: "Equipamentos e Habilidades" },
  { id: "historico", label: "Histórico" },
  { id: "guilda", label: "Guilda" },
  { id: "privacidade-lgpd", label: "Privacidade (LGPD)" },
  { id: "admin-painel", label: "Admin" }
]);

const NEN_CATEGORIES_MAP = Object.freeze({
  reforco: "reforco",
  emissao: "emissao",
  transformacao: "transformacao",
  materializacao: "materializacao",
  manipulacao: "manipulacao",
  especializacao: "especializacao"
});

const NEN_SELECT_LABELS = Object.freeze({
  reforco: "Reforço",
  emissao: "Emissão",
  transformacao: "Transformação",
  materializacao: "Materialização",
  manipulacao: "Manipulação",
  especializacao: "Especialização"
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
  isAdmin: false,
  inspectedTargetUid: "",
  adminReadOnly: false,
  knownPlayerUids: [],
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
  loginTypewriterTimer: null,
  isSaving: false,
  isDeleting: false,
  lastSavedSnapshot: "",
  lastCloudWriteAt: 0
};

/* --------------------------------------------------------------------------
   2. Sanitização, Validação e Segurança de Entrada
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
  if (ctrl.id === "rank-val") return normalizeRankValue(rawValue);
  if (ctrl.type === "number") return normalizeNumericValue(ctrl.id || "", rawValue);
  if (ctrl.tagName === "TEXTAREA") return sanitizeText(String(rawValue ?? ""), 5000);
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
   3. Animação de Escrita 3D na Tela de Login
   -------------------------------------------------------------------------- */
function getLoginSiteTitleText(titleEl) {
  const fromAttr = sanitizeSingleLine(titleEl?.getAttribute("aria-label") || "", 60);
  if (fromAttr) return fromAttr;
  const fromText = sanitizeSingleLine(titleEl?.textContent || "", 60);
  return fromText || LOGIN_TYPEWRITER_CONFIG.defaultTitle;
}

function createAnimatedLetterNode(char, index) {
  const span = document.createElement("span");
  const delayMs = LOGIN_TYPEWRITER_CONFIG.initialDelayMs + index * LOGIN_TYPEWRITER_CONFIG.stepDelayMs;

  if (char === " ") {
    span.className = "espaco-3d";
    span.textContent = "\u00A0";
  } else {
    span.className = "letra-3d";
    span.textContent = char;
    span.style.setProperty("--delay-letra", `${delayMs}ms`);
  }

  span.setAttribute("aria-hidden", "true");
  return span;
}

function playLoginTitle3DWriting(forceReplay = false) {
  const entradaScreen = document.getElementById("entrada-screen");
  const titleEl = document.getElementById("entrada-titulo");
  if (!entradaScreen || entradaScreen.hidden || !titleEl) return;

  if (!forceReplay && titleEl.dataset.animacaoConcluida === "1") {
    return;
  }

  if (state.loginTypewriterTimer !== null) {
    clearTimeout(state.loginTypewriterTimer);
    state.loginTypewriterTimer = null;
  }

  const siteName = getLoginSiteTitleText(titleEl);
  const chars = Array.from(siteName);
  const fragment = document.createDocumentFragment();

  chars.forEach((char, idx) => {
    fragment.appendChild(createAnimatedLetterNode(char, idx));
  });

  const cursor = document.createElement("span");
  cursor.className = "cursor-escrita-3d";
  cursor.setAttribute("aria-hidden", "true");
  fragment.appendChild(cursor);

  titleEl.setAttribute("aria-label", siteName);
  titleEl.classList.add("titulo-3d-digitando");
  titleEl.dataset.animacaoConcluida = "1";
  titleEl.replaceChildren(fragment);

  const totalMs =
    LOGIN_TYPEWRITER_CONFIG.initialDelayMs +
    chars.length * LOGIN_TYPEWRITER_CONFIG.stepDelayMs +
    LOGIN_TYPEWRITER_CONFIG.letterAnimMs +
    LOGIN_TYPEWRITER_CONFIG.cursorFinishBufferMs;

  state.loginTypewriterTimer = window.setTimeout(() => {
    state.loginTypewriterTimer = null;
    cursor.classList.add("concluido");
  }, totalMs);
}

/* --------------------------------------------------------------------------
   4. Cálculo de Perícias e Tema Dinâmico de Nen
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
      if (Number.isFinite(n)) extrasSum += Math.trunc(n);
    }

    const attrBonus = getSkillAttributeBonus(attrCell ? attrCell.textContent : "");
    if (totalInput) totalInput.value = String(attrBonus + extrasSum);
  });
}

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
    row.classList.toggle("nen-linha-ativa", Boolean(categoryKey) && rowKey === categoryKey);
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

/* --------------------------------------------------------------------------
   5. Privacidade (LGPD) e Navegação por Seção
   -------------------------------------------------------------------------- */
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
    // Mantém em memória se storage estiver indisponível
  }
  setLgpdBannerVisibility(true);
  if (!state.offlineMode && !state.inspectedTargetUid) {
    saveLocalData(collectSheetData());
  }
}

window.__aceitarLgpdArkan = aceitarLgpdBanner;

function setActiveSectionIndicator(sectionId) {
  const match = TRACKED_SECTIONS.find((item) => item.id === sectionId) || TRACKED_SECTIONS[0];
  state.activeSectionId = match.id;

  const indicatorEl = document.getElementById("secao-atual-topo");
  if (indicatorEl) indicatorEl.textContent = match.label;

  const navLinks = document.querySelectorAll(".abas .aba-btn[data-secao-alvo]");
  navLinks.forEach((link) => {
    const isCurrent = link.dataset.secaoAlvo === match.id;
    link.classList.toggle("aba-btn-ativa", isCurrent);
    if (isCurrent) link.setAttribute("aria-current", "true");
    else link.removeAttribute("aria-current");
  });
}

function navigateToSection(sectionId) {
  const valid = TRACKED_SECTIONS.find((sec) => sec.id === sectionId);
  if (!valid) return false;
  if (valid.id === "admin-painel" && !state.isAdmin) return false;

  const targetEl = document.getElementById(valid.id);
  if (!targetEl || targetEl.hidden) return false;

  setActiveSectionIndicator(valid.id);
  targetEl.scrollIntoView({ behavior: "smooth", block: "start" });
  return true;
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
    if (secInfo.id === "admin-painel" && !state.isAdmin) continue;

    const secEl = document.getElementById(secInfo.id);
    if (!secEl || secEl.hidden) continue;

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
   6. Coleta, Normalização e Persistência Local/Nuvem
   -------------------------------------------------------------------------- */
function getActiveTargetUid() {
  if (state.isAdmin && state.inspectedTargetUid) {
    return state.inspectedTargetUid;
  }
  return state.user && state.user.uid ? state.user.uid : "";
}

function isEditingAnotherPlayerSheet() {
  return Boolean(
    state.isAdmin &&
      state.user &&
      state.inspectedTargetUid &&
      state.inspectedTargetUid !== state.user.uid
  );
}

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
  if (!mainEl) return { fields, atualizadoEm: new Date().toISOString() };

  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl, index) => {
    if (!ctrl || ctrl.closest("#login-firebase") || ctrl.closest("#admin-painel")) return;
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

  return { fields, atualizadoEm: new Date().toISOString() };
}

function buildSanitizedCloudPayload(sourceData = null) {
  const raw = sourceData && sourceData.fields ? sourceData : collectSheetData();
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

  return { fields: cleanFields, atualizadoEm: new Date().toISOString() };
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
    if (!ctrl || ctrl.closest("#login-firebase") || ctrl.closest("#admin-painel")) return;
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
    if (!ctrl || ctrl.closest("#login-firebase") || ctrl.closest("#admin-painel")) return;

    if (ctrl.type === "checkbox") {
      ctrl.checked = false;
    } else if (ctrl.tagName === "SELECT") {
      ctrl.selectedIndex = 0;
    } else if (ctrl.type === "number") {
      if (ctrl.id === "def-total" || ctrl.id === "def-esquiva") ctrl.value = "11";
      else if (ctrl.id === "def-deslocamento") ctrl.value = "9";
      else if (
        ctrl.id === "attr-agi" ||
        ctrl.id === "attr-for" ||
        ctrl.id === "attr-ca" ||
        ctrl.id === "attr-int" ||
        ctrl.id === "attr-vig" ||
        ctrl.id === "nv-val"
      ) {
        ctrl.value = "1";
      } else if (ctrl.id === "espacos-max") ctrl.value = "5";
      else ctrl.value = "0";
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
  if (state.offlineMode || isEditingAnotherPlayerSheet() || !hasCookieConsent()) return;
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

async function persistSheet(forceWrite = false) {
  if (state.isSaving || state.isDeleting) return false;

  if (state.isAdmin && state.adminReadOnly) {
    setStatusBanner("Modo somente leitura ativo: alterações bloqueadas para evitar edição acidental.", "warning");
    return false;
  }

  state.isSaving = true;

  try {
    const payload = collectSheetData();
    const currentSnapshot = computeFieldsSnapshot(payload.fields);

    if (state.offlineMode && !state.user) {
      setStatusBanner(
        "Modo offline/local: alterações não ficam salvas se você carregar a página novamente.",
        "warning"
      );
      return false;
    }

    if (!forceWrite && currentSnapshot === state.lastSavedSnapshot) return true;

    const targetUid = getActiveTargetUid();
    const editingOther = isEditingAnotherPlayerSheet();

    if (!editingOther) {
      saveLocalData(payload);
    }

    if (state.firebaseReady && state.user && targetUid) {
      const elapsed = Date.now() - state.lastCloudWriteAt;
      if (!forceWrite && elapsed < MIN_CLOUD_SAVE_INTERVAL_MS) {
        scheduleAutoSave();
        return true;
      }

      const cloudPayload = buildSanitizedCloudPayload(payload);
      await saveToFirestore(targetUid, cloudPayload);
      state.lastSavedSnapshot = computeFieldsSnapshot(cloudPayload.fields);
      setStatusBanner(
        editingOther
          ? `Ficha do jogador (${targetUid}) salva no Firebase.`
          : "Ficha salva no banco de dados Firebase.",
        "success"
      );
      return true;
    }

    if (hasCookieConsent() && !editingOther) {
      state.lastSavedSnapshot = currentSnapshot;
      setStatusBanner("Alterações salvas localmente.", "info");
      return true;
    }

    setStatusBanner("Aceite o banner LGPD para salvar localmente ou faça login no Firebase.", "info");
    return false;
  } catch {
    setStatusBanner("Erro ao salvar no Firebase. Confira as permissões do Firestore.", "error");
    return false;
  } finally {
    state.isSaving = false;
  }
}

function scheduleAutoSave() {
  if (state.isAdmin && state.adminReadOnly) return;
  if (state.saveTimer) clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => {
    persistSheet(false);
  }, AUTO_SAVE_DEBOUNCE_MS);
}

/* --------------------------------------------------------------------------
   7. Autenticação Firebase, Permissão Admin Exclusiva e Mensagens
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

function clearAuthSensitiveInputs() {
  const emailEl = document.getElementById("auth-email");
  const passEl = document.getElementById("auth-password");
  if (emailEl) emailEl.value = "";
  if (passEl) passEl.value = "";
  state.showPassword = false;
  updatePasswordVisibilityUI();
}

function resolveAdminPermission(user) {
  if (!user || state.offlineMode) return false;
  return sanitizeSingleLine(user.uid || "", 128) === ADMIN_EXCLUSIVE_UID;
}

function registerKnownPlayerUid(uid) {
  const clean = sanitizeSingleLine(uid || "", 128);
  if (!clean) return;
  if (!state.knownPlayerUids.includes(clean)) {
    state.knownPlayerUids.push(clean);
  }
  syncAdminTargetSelectOptions();
}

function syncAdminTargetSelectOptions() {
  const selectEl = document.getElementById("admin-target-uid");
  if (!selectEl) return;

  const ownUid = state.user?.uid || "";
  const frag = document.createDocumentFragment();

  const selfOpt = document.createElement("option");
  selfOpt.value = "";
  selfOpt.textContent = ownUid ? `Minha ficha (${ownUid})` : "Minha própria ficha";
  frag.appendChild(selfOpt);

  state.knownPlayerUids.forEach((uid) => {
    if (uid === ownUid) return;
    const opt = document.createElement("option");
    opt.value = uid;
    opt.textContent = uid;
    frag.appendChild(opt);
  });

  selectEl.replaceChildren(frag);
  selectEl.value = state.inspectedTargetUid || "";
}

async function refreshKnownPlayerUidsFromFirestore() {
  if (!state.isAdmin || !state.firebaseReady || !state.db) return;
  try {
    const { collection, getDocs } = state.firebaseModules.firestoreMod;
    const snap = await getDocs(collection(state.db, FIRESTORE_COLLECTION));
    const list = [];
    snap.forEach((docSnap) => {
      if (docSnap.id) list.push(docSnap.id);
    });
    state.knownPlayerUids = list;
    syncAdminTargetSelectOptions();
  } catch {
    // Mantém lista já conhecida caso listagem não seja necessária
  }
}

async function checkIncomingMessagesForUser(uid) {
  if (!state.firebaseReady || !state.db || !uid) return;
  try {
    const { collection, getDocs, query, where } = state.firebaseModules.firestoreMod;
    const msgCol = collection(state.db, FIRESTORE_MESSAGES_COLLECTION);

    const [directSnap, globalSnap] = await Promise.all([
      getDocs(query(msgCol, where("destinatarioUid", "==", uid))),
      getDocs(query(msgCol, where("destinatarioUid", "==", "ALL")))
    ]);

    const notices = [];
    directSnap.forEach((d) => {
      const data = d.data() || {};
      if (data.texto) notices.push(`[Direta] ${sanitizeSingleLine(String(data.texto), 200)}`);
    });
    globalSnap.forEach((d) => {
      const data = d.data() || {};
      if (data.texto) notices.push(`[Geral] ${sanitizeSingleLine(String(data.texto), 200)}`);
    });

    if (notices.length > 0) {
      setStatusBanner(`Mensagem da Ordem: ${notices[notices.length - 1]}`, "info");
    }
  } catch {
    // Ignora caso não haja mensagens ou regra esteja em configuração
  }
}

async function sendAdminMessage(recipientUid, scope, text) {
  if (!state.isAdmin || !state.firebaseReady || !state.db || !state.user) return false;
  const cleanText = sanitizeSingleLine(text, 600);
  if (!cleanText) return false;

  const { addDoc, collection } = state.firebaseModules.firestoreMod;
  await addDoc(collection(state.db, FIRESTORE_MESSAGES_COLLECTION), {
    remetenteUid: state.user.uid,
    destinatarioUid: recipientUid,
    escopo: scope,
    texto: cleanText,
    criadoEm: new Date().toISOString()
  });
  return true;
}

function updateAdminVisibilityUI() {
  const adminTab = document.getElementById("aba-admin");
  const adminSection = document.getElementById("admin-painel");
  const allowed = Boolean(state.user) && !state.offlineMode && Boolean(state.isAdmin);

  if (adminTab) adminTab.hidden = !allowed;
  if (adminSection) adminSection.hidden = !allowed;

  if (!allowed) {
    state.inspectedTargetUid = "";
    state.adminReadOnly = false;
    applySheetReadOnlyState(false);
    if (state.activeSectionId === "admin-painel") {
      setActiveSectionIndicator("dados-agente");
    }
  } else {
    syncAdminTargetSelectOptions();
    updateAdminReadOnlyBadge();
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
        state.inspectedTargetUid = "";
        clearAuthSensitiveInputs();
        setEntradaStatus("");
        state.isAdmin = resolveAdminPermission(user);
        if (!state.isAdmin) {
          state.adminReadOnly = false;
          applySheetReadOnlyState(false);
        }
      } else {
        state.isAdmin = false;
        state.inspectedTargetUid = "";
        state.adminReadOnly = false;
        applySheetReadOnlyState(false);
      }

      updateAuthUI();
      updateAdminVisibilityUI();
      updateScreenAccess();

      if (user && !state.isDeleting) {
        registerKnownPlayerUid(user.uid);
        setStatusBanner(
          `Conectado como ${sanitizeSingleLine(user.email || "agente", 160)}. Carregando ficha...`,
          "info"
        );
        await loadFromFirestore(user.uid, { createIfMissingForOwn: true });
        await checkIncomingMessagesForUser(user.uid);
        if (state.isAdmin) {
          await refreshKnownPlayerUidsFromFirestore();
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

async function loadFromFirestore(uid, options = {}) {
  const { createIfMissingForOwn = false, applyToForm = true } = options;
  if (!state.firebaseReady || !state.db || !uid) return { ok: false, data: null };
  const { doc, getDoc, setDoc } = state.firebaseModules.firestoreMod;

  try {
    const docRef = doc(state.db, FIRESTORE_COLLECTION, uid);
    const snap = await getDoc(docRef);

    if (snap.exists()) {
      const cloudData = snap.data();
      registerKnownPlayerUid(uid);
      if (applyToForm) {
        applySheetData(cloudData);
        if (!isEditingAnotherPlayerSheet()) {
          saveLocalData(cloudData);
        }
        setStatusBanner("Ficha carregada do banco de dados Firebase.", "success");
      }
      return { ok: true, data: cloudData };
    }

    if (createIfMissingForOwn && uid === state.user?.uid) {
      resetSheetFieldsToDefault();
      const initialData = buildSanitizedCloudPayload();
      state.lastCloudWriteAt = Date.now();
      await setDoc(docRef, initialData);
      state.lastSavedSnapshot = computeFieldsSnapshot(initialData.fields);
      saveLocalData(initialData);
      setStatusBanner("Nova ficha criada na sua conta do Firebase.", "success");
      return { ok: true, data: initialData };
    }

    return { ok: false, data: null };
  } catch {
    setStatusBanner("Erro ao ler dados do Firebase. Verifique as regras do Firestore.", "error");
    return { ok: false, data: null };
  }
}

async function saveToFirestore(uid, data) {
  if (!state.firebaseReady || !state.db || !uid) return false;
  const { doc, setDoc } = state.firebaseModules.firestoreMod;
  const docRef = doc(state.db, FIRESTORE_COLLECTION, uid);
  const safeData = data && data.fields ? data : buildSanitizedCloudPayload();
  state.lastCloudWriteAt = Date.now();
  await setDoc(docRef, safeData, { merge: true });
  registerKnownPlayerUid(uid);
  return true;
}

async function handleClearSheetData(event) {
  if (event && event.isTrusted === false) return;
  if (state.isSaving || state.isDeleting) return;

  if (state.isAdmin && state.adminReadOnly) {
    setStatusBanner("Desative o modo somente leitura (/somente_leitura off) antes de excluir a ficha.", "warning");
    return;
  }

  if (state.saveTimer) {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
  }

  const targetUid = getActiveTargetUid();
  const editingOther = isEditingAnotherPlayerSheet();

  resetSheetFieldsToDefault();
  if (!editingOther) {
    clearLocalData();
  }

  const clearConfirmBox = document.getElementById("sheet-clear-confirm-box");
  if (clearConfirmBox) clearConfirmBox.hidden = true;

  if (state.firebaseReady && state.db && state.user && targetUid) {
    const { doc, deleteDoc } = state.firebaseModules.firestoreMod;
    try {
      state.lastCloudWriteAt = Date.now();
      await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, targetUid));
      setStatusBanner(
        editingOther
          ? `Ficha do jogador (${targetUid}) excluída da nuvem.`
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
    setEntradaStatus("Firebase ainda não foi inicializado.");
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
    if (state.authMode === "register") {
      await createUserWithEmailAndPassword(state.auth, email, password);
    } else {
      await signInWithEmailAndPassword(state.auth, email, password);
    }
    clearAuthSensitiveInputs();
  } catch (err) {
    setEntradaStatus(mapFirebaseAuthError(err));
  }
}

async function handleLogout(event) {
  if (event && event.isTrusted === false) return;
  state.offlineMode = false;
  state.isAdmin = false;
  state.inspectedTargetUid = "";
  state.adminReadOnly = false;
  state.lastSavedSnapshot = "";
  applySheetReadOnlyState(false);
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
  updateAdminVisibilityUI();
  updateScreenAccess();
  setEntradaStatus("Você saiu da sessão. Escolha como deseja entrar novamente.");
}

async function handleDeleteAccount(event) {
  if (event && event.isTrusted === false) return;
  if (!state.firebaseReady || !state.auth || !state.auth.currentUser || state.isDeleting) return;

  const currentUser = state.auth.currentUser;
  const uid = currentUser.uid;
  const { deleteUser } = state.firebaseModules.authMod;
  const { doc, deleteDoc } = state.firebaseModules.firestoreMod;

  state.isDeleting = true;
  setStatusBanner("Excluindo conta e dados salvos...", "info");

  try {
    await deleteUser(currentUser);
    if (state.db && uid) {
      try {
        state.lastCloudWriteAt = Date.now();
        await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, uid));
      } catch {
        // Ignora erro pós-exclusão da conta
      }
    }

    clearLocalData();
    clearAuthSensitiveInputs();
    state.offlineMode = false;
    state.isAdmin = false;
    state.inspectedTargetUid = "";
    state.adminReadOnly = false;
    state.lastSavedSnapshot = "";
    applySheetReadOnlyState(false);

    const confirmBox = document.getElementById("auth-delete-confirm-box");
    if (confirmBox) confirmBox.hidden = true;

    updateAuthUI();
    updateAdminVisibilityUI();
    updateScreenAccess();
    setEntradaStatus("Conta e ficha excluídas permanentemente do Firebase.");
  } catch (err) {
    if (err && err.code === "auth/requires-recent-login") {
      setStatusBanner("Por segurança, saia e entre novamente antes de excluir a conta.", "warning");
    } else {
      setStatusBanner("Não foi possível excluir a conta. Tente novamente.", "error");
    }
  } finally {
    state.isDeleting = false;
  }
}

/* --------------------------------------------------------------------------
   8. Comandos do Administrador com "/" (1 comando = 1 função específica)
   -------------------------------------------------------------------------- */
function setAdminConsoleOutput(text) {
  const outEl = document.getElementById("admin-cmd-output");
  if (!outEl) return;
  outEl.textContent = sanitizeText(String(text ?? ""), 3000);
}

function cmdAdminAjuda() {
  return [
    "Comandos disponíveis (sempre iniciados com / — 1 comando = 1 função):",
    "• /ajuda                                   -> Lista todos os comandos disponíveis.",
    "• /limpar                                  -> Limpa a saída do console admin.",
    "• /status                                  -> Mostra UID, ficha alvo, modo somente leitura e seção atual.",
    "• /ver_ficha <uid>                         -> Carrega a ficha de outro jogador para visualizar e alterar.",
    "• /voltar_minha_ficha                      -> Volta o foco para a sua própria ficha.",
    "• /salvar                                  -> Salva a ficha carregada (sua ou do jogador alvo).",
    "• /resetar                                 -> Restaura os campos da ficha atual para o padrão.",
    "• /nen <categoria>                         -> Aplica reforco | emissao | transformacao | materializacao | manipulacao | especializacao.",
    "• /rank <E..SSS>                           -> Define o Rank do agente na ficha carregada.",
    "• /xp <número>                             -> Soma XP ao campo XP Atual da ficha carregada.",
    "• /ir <secao>                              -> Rola até a seção informada.",
    "• /msg <uid> <mensagem>                    -> Envia mensagem direcionada a um jogador específico.",
    "• /broadcast <mensagem>                    -> Envia mensagem para todos os jogadores.",
    "• /somente_leitura [on|off]                -> Ativa/desativa bloqueio contra alteração acidental.",
    "• /transferir_ficha <uid_origem> <uid_dst> -> Copia a ficha de um jogador para outro UID."
  ].join("\n");
}

function cmdAdminLimpar() {
  setAdminConsoleOutput("Console limpo.");
  return null;
}

function cmdAdminStatus() {
  const nomeVal = sanitizeSingleLine(document.getElementById("nome")?.value || "(sem nome)", 80);
  const rankVal = sanitizeSingleLine(document.getElementById("rank-val")?.value || "E", 10);
  const nenLabel = state.nenCategory ? NEN_SELECT_LABELS[state.nenCategory] : "Nenhuma";
  const targetUid = getActiveTargetUid();

  return [
    `Admin UID: ${state.user ? state.user.uid : "N/A"}`,
    `Ficha carregada UID: ${targetUid || "N/A"} ${isEditingAnotherPlayerSheet() ? "(OUTRO JOGADOR)" : "(PRÓPRIA)"}`,
    `Somente leitura: ${state.adminReadOnly ? "ATIVADO (bloqueado)" : "DESATIVADO (edição ativa)"}`,
    `Agente: ${nomeVal} | Rank: ${rankVal} | Nen: ${nenLabel}`,
    `Seção atual: ${state.activeSectionId}`
  ].join("\n");
}

async function cmdAdminVerFicha(args) {
  const targetUid = sanitizeSingleLine(args[0] || "", 128);
  if (!targetUid) return "Informe o UID do jogador. Ex: /ver_ficha <uid>";
  if (!state.firebaseReady || !state.db) return "Firestore não conectado.";

  const res = await loadFromFirestore(targetUid, { createIfMissingForOwn: false, applyToForm: true });
  if (!res.ok || !res.data) {
    return `Nenhuma ficha encontrada em fichas_ordem_arkan/${targetUid}.`;
  }

  state.inspectedTargetUid = targetUid === state.user?.uid ? "" : targetUid;
  syncAdminTargetSelectOptions();
  updateAdminReadOnlyBadge();

  return [
    `Ficha de "${targetUid}" carregada na tela.`,
    "Agora você pode alterar os campos e rodar /salvar para gravar na ficha desse jogador.",
    `Modo atual: ${state.adminReadOnly ? "SOMENTE LEITURA" : "EDIÇÃO LIBERADA"}.`
  ].join("\n");
}

async function cmdAdminVoltarMinhaFicha() {
  if (!state.user?.uid) return "Sessão Firebase não encontrada.";
  state.inspectedTargetUid = "";
  syncAdminTargetSelectOptions();
  updateAdminReadOnlyBadge();

  const res = await loadFromFirestore(state.user.uid, { createIfMissingForOwn: true, applyToForm: true });
  return res.ok ? "Foco retornado para a sua própria ficha." : "Não foi possível recarregar sua ficha.";
}

async function cmdAdminSalvar() {
  if (state.adminReadOnly) {
    return "Bloqueado: o modo somente leitura está ativo. Use /somente_leitura off para salvar alterações.";
  }
  const ok = await persistSheet(true);
  const targetUid = getActiveTargetUid();
  return ok
    ? `Ficha salva com sucesso em fichas_ordem_arkan/${targetUid || "local"}.`
    : "Não foi possível salvar a ficha.";
}

function cmdAdminResetar() {
  if (state.adminReadOnly) {
    return "Bloqueado: o modo somente leitura está ativo. Use /somente_leitura off para resetar.";
  }
  resetSheetFieldsToDefault();
  scheduleAutoSave();
  return "Campos da ficha restaurados para o padrão inicial.";
}

function cmdAdminDefinirNen(args) {
  if (state.adminReadOnly) {
    return "Bloqueado: o modo somente leitura está ativo. Use /somente_leitura off para alterar Nen.";
  }
  const rawArg = args.join(" ");
  const key = normalizeNenCategoryKey(rawArg);
  if (!key) {
    return "Categoria inválida. Use: /nen reforco | emissao | transformacao | materializacao | manipulacao | especializacao";
  }

  const selectEl = document.getElementById("categoria-principal-nen");
  if (selectEl) selectEl.value = NEN_SELECT_LABELS[key];
  applyNenCategoryTheme(key);
  scheduleAutoSave();
  return `Categoria de Nen definida para: ${NEN_SELECT_LABELS[key]}.`;
}

function cmdAdminDefinirRank(args) {
  if (state.adminReadOnly) {
    return "Bloqueado: o modo somente leitura está ativo. Use /somente_leitura off para alterar Rank.";
  }
  const rawRank = args[0] || "";
  if (!rawRank) return "Informe o Rank. Ex: /rank A";

  const rankEl = document.getElementById("rank-val");
  const normalized = normalizeRankValue(rawRank);
  if (rankEl) rankEl.value = normalized;
  scheduleAutoSave();
  return `Rank atualizado para: ${normalized}.`;
}

function cmdAdminAdicionarXp(args) {
  if (state.adminReadOnly) {
    return "Bloqueado: o modo somente leitura está ativo. Use /somente_leitura off para alterar XP.";
  }
  const delta = Number(String(args[0] ?? "").replace(",", "."));
  if (!Number.isFinite(delta)) return "Informe um número válido. Ex: /xp 150";

  const xpAtualEl = document.getElementById("xp-atual-val");
  if (!xpAtualEl) return "Campo XP Atual não encontrado.";

  const current = Number(String(xpAtualEl.value || "0").replace(",", ".")) || 0;
  const next = Math.trunc(current + delta);
  xpAtualEl.value = String(next);
  scheduleAutoSave();
  return `XP Atual alterado de ${Math.trunc(current)} para ${next}.`;
}

function cmdAdminIrParaSecao(args) {
  const targetId = sanitizeSingleLine(args[0] || "", 40).toLowerCase();
  if (!targetId) return "Informe a seção. Ex: /ir guilda";

  const moved = navigateToSection(targetId);
  return moved ? `Navegado para a seção: ${targetId}.` : `Seção não encontrada ou indisponível: ${targetId}.`;
}

async function cmdAdminMensagemDireta(args) {
  const targetUid = sanitizeSingleLine(args[0] || "", 128);
  const messageText = sanitizeSingleLine(args.slice(1).join(" "), 600);
  if (!targetUid || !messageText) {
    return "Uso correto: /msg <uid_jogador> <mensagem>";
  }

  try {
    await sendAdminMessage(targetUid, "direta", messageText);
    return `Mensagem enviada para o jogador "${targetUid}": "${messageText}"`;
  } catch {
    return "Erro ao enviar mensagem direcionada. Verifique as regras do Firestore para mensagens_ordem_arkan.";
  }
}

async function cmdAdminBroadcast(args) {
  const messageText = sanitizeSingleLine(args.join(" "), 600);
  if (!messageText) {
    return "Uso correto: /broadcast <mensagem para todos os jogadores>";
  }

  try {
    await sendAdminMessage("ALL", "global", messageText);
    return `Mensagem global enviada para todos os jogadores: "${messageText}"`;
  } catch {
    return "Erro ao enviar broadcast. Verifique as regras do Firestore para mensagens_ordem_arkan.";
  }
}

function cmdAdminSomenteLeitura(args) {
  const modeArg = sanitizeSingleLine(args[0] || "", 12).toLowerCase();

  if (modeArg === "on" || modeArg === "ativar" || modeArg === "true") {
    state.adminReadOnly = true;
  } else if (modeArg === "off" || modeArg === "desativar" || modeArg === "false") {
    state.adminReadOnly = false;
  } else {
    state.adminReadOnly = !state.adminReadOnly;
  }

  applySheetReadOnlyState(state.adminReadOnly);
  updateAdminReadOnlyBadge();
  return state.adminReadOnly
    ? "Modo SOMENTE LEITURA ATIVADO: alterações na ficha estão bloqueadas para evitar edições acidentais."
    : "Modo SOMENTE LEITURA DESATIVADO: edição da ficha liberada.";
}

async function cmdAdminTransferirFicha(args) {
  if (state.adminReadOnly) {
    return "Bloqueado: desative o modo somente leitura (/somente_leitura off) antes de transferir fichas.";
  }

  const sourceUid = sanitizeSingleLine(args[0] || "", 128);
  const destUid = sanitizeSingleLine(args[1] || "", 128);
  if (!sourceUid || !destUid) {
    return "Uso correto: /transferir_ficha <uid_origem> <uid_destino>";
  }
  if (sourceUid === destUid) {
    return "O UID de origem e o UID de destino devem ser diferentes.";
  }
  if (!state.firebaseReady || !state.db) {
    return "Firestore não conectado.";
  }

  const fetched = await loadFromFirestore(sourceUid, { createIfMissingForOwn: false, applyToForm: false });
  if (!fetched.ok || !fetched.data) {
    return `Ficha de origem "${sourceUid}" não encontrada.`;
  }

  const transferredPayload = buildSanitizedCloudPayload(fetched.data);
  await saveToFirestore(destUid, transferredPayload);

  state.inspectedTargetUid = destUid === state.user?.uid ? "" : destUid;
  syncAdminTargetSelectOptions();
  updateAdminReadOnlyBadge();
  applySheetData(transferredPayload);

  return `Ficha transferida com sucesso de "${sourceUid}" para "${destUid}" (ficha de destino carregada na tela).`;
}

const ADMIN_COMMAND_HANDLERS = Object.freeze({
  ajuda: cmdAdminAjuda,
  help: cmdAdminAjuda,
  limpar: cmdAdminLimpar,
  clear: cmdAdminLimpar,
  status: cmdAdminStatus,
  ver_ficha: cmdAdminVerFicha,
  voltar_minha_ficha: cmdAdminVoltarMinhaFicha,
  salvar: cmdAdminSalvar,
  resetar: cmdAdminResetar,
  nen: cmdAdminDefinirNen,
  rank: cmdAdminDefinirRank,
  xp: cmdAdminAdicionarXp,
  ir: cmdAdminIrParaSecao,
  msg: cmdAdminMensagemDireta,
  broadcast: cmdAdminBroadcast,
  somente_leitura: cmdAdminSomenteLeitura,
  transferir_ficha: cmdAdminTransferirFicha
});

async function executeAdminCommand(rawInput) {
  if (!state.isAdmin || !state.user || state.offlineMode || state.user.uid !== ADMIN_EXCLUSIVE_UID) {
    setAdminConsoleOutput("Acesso negado: função restrita ao administrador autorizado.");
    return;
  }

  const cleaned = sanitizeSingleLine(rawInput || "", 320);
  if (!cleaned) {
    setAdminConsoleOutput('Digite um comando começando com /. Ex: "/ajuda".');
    return;
  }

  if (!cleaned.startsWith("/")) {
    setAdminConsoleOutput(`Comandos exigem "/" no início. Ex: "/${cleaned.split(/\s+/)[0]}".`);
    return;
  }

  const parts = cleaned.slice(1).trim().split(/\s+/);
  const cmdName = (parts[0] || "").toLowerCase();
  const cmdArgs = parts.slice(1);

  if (!cmdName || !Object.prototype.hasOwnProperty.call(ADMIN_COMMAND_HANDLERS, cmdName)) {
    setAdminConsoleOutput(`Comando desconhecido "/${cmdName}". Digite "/ajuda" para ver os comandos.`);
    return;
  }

  const handler = ADMIN_COMMAND_HANDLERS[cmdName];
  const result = await handler(cmdArgs);
  if (typeof result === "string") {
    setAdminConsoleOutput(result);
  }
}

/* --------------------------------------------------------------------------
   9. Interface, Banners, Modo Somente Leitura e Inicialização
   -------------------------------------------------------------------------- */
function applySheetReadOnlyState(readOnly) {
  const locked = Boolean(readOnly);
  const mainEl = document.querySelector("main.container");
  if (!mainEl) return;

  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl) => {
    if (!ctrl || ctrl.closest("#login-firebase") || ctrl.closest("#admin-painel")) return;
    if (ctrl.tagName === "SELECT" || ctrl.type === "checkbox" || ctrl.type === "date") {
      ctrl.disabled = locked;
    } else {
      ctrl.readOnly = locked;
      ctrl.setAttribute("aria-readonly", locked ? "true" : "false");
    }
  });
}

function updateAdminReadOnlyBadge() {
  const badge = document.getElementById("admin-readonly-badge");
  if (!badge) return;
  if (state.adminReadOnly) {
    badge.textContent = "SOMENTE LEITURA (Bloqueado)";
  } else if (isEditingAnotherPlayerSheet()) {
    badge.textContent = `Editando Jogador: ${state.inspectedTargetUid}`;
  } else {
    badge.textContent = "Edição Liberada";
  }
}

function setStatusBanner(message, type = "info") {
  const banner = document.getElementById("status-banner");
  if (!banner) return;
  const cleanMessage = sanitizeSingleLine(message, 240);
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

function updatePasswordVisibilityUI() {
  const passEl = document.getElementById("auth-password");
  const togglePassBtn = document.getElementById("auth-toggle-password");
  const visible = Boolean(state.showPassword);

  if (passEl) passEl.type = visible ? "text" : "password";
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

  renderSafeText(submitBtn, state.authMode === "register" ? "Cadastrar" : "Entrar", 40);
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
}

function updateScreenAccess() {
  const entradaScreen = document.getElementById("entrada-screen");
  const appFicha = document.getElementById("app-ficha");
  const hasSession = Boolean(state.user) || Boolean(state.offlineMode);

  if (entradaScreen) entradaScreen.hidden = hasSession;
  if (appFicha) appFicha.hidden = !hasSession;

  if (hasSession) {
    updateAdminVisibilityUI();
    syncNenCategoryFromSelect();
    recalculateSkillsTable();
    window.requestAnimationFrame(() => syncActiveSectionOnScroll());
  } else {
    playLoginTitle3DWriting(true);
  }
}

function enterOfflineTemporaryMode() {
  state.offlineMode = true;
  state.isAdmin = false;
  state.inspectedTargetUid = "";
  state.adminReadOnly = false;
  state.lastSavedSnapshot = "";
  applySheetReadOnlyState(false);
  clearAuthSensitiveInputs();
  setEntradaStatus("");
  updateAuthUI();
  updateAdminVisibilityUI();
  updateScreenAccess();
  setStatusBanner(
    "Modo offline/local ativo: as informações não ficam salvas se você carregar a página novamente.",
    "warning"
  );
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function initLgpdBanner() {
  setLgpdBannerVisibility(hasCookieConsent());

  const acceptBtn = document.getElementById("lgpd-accept-btn");
  if (!acceptBtn || acceptBtn.dataset.lgpdBound === "1") return;
  acceptBtn.dataset.lgpdBound = "1";
  acceptBtn.addEventListener("click", aceitarLgpdBanner);
}

function handleSheetControlMutation(event) {
  const target = event.target;
  if (!target || target.closest("#login-firebase") || target.closest("#admin-painel")) return;

  if (state.isAdmin && state.adminReadOnly) {
    setStatusBanner("Modo somente leitura ativo: edições não são salvas.", "warning");
    return;
  }

  if (target.id === "categoria-principal-nen") {
    const selectedOptionText =
      target.options && target.selectedIndex >= 0
        ? target.options[target.selectedIndex].textContent || ""
        : "";
    applyNenCategoryTheme(target.value || selectedOptionText);
  }

  if (
    target.closest("#tabela-pericias") ||
    target.id === "attr-agi" ||
    target.id === "attr-for" ||
    target.id === "attr-ca" ||
    target.id === "attr-int" ||
    target.id === "attr-vig"
  ) {
    recalculateSkillsTable();
  }

  scheduleAutoSave();
}

function bindAdminEvents() {
  const cmdForm = document.getElementById("admin-cmd-form");
  const cmdInput = document.getElementById("admin-cmd-input");
  const targetSelect = document.getElementById("admin-target-uid");

  if (cmdForm && cmdInput) {
    cmdForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = cmdInput.value;
      cmdInput.value = "";
      await executeAdminCommand(value);
    });
  }

  if (targetSelect) {
    targetSelect.addEventListener("change", async () => {
      if (!state.isAdmin) return;
      const chosenUid = sanitizeSingleLine(targetSelect.value || "", 128);
      if (chosenUid) {
        await executeAdminCommand(`/ver_ficha ${chosenUid}`);
      } else {
        await executeAdminCommand("/voltar_minha_ficha");
      }
    });
  }

  const quickButtons = document.querySelectorAll("[data-admin-quick]");
  quickButtons.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const cmd = btn.getAttribute("data-admin-quick") || "";
      await executeAdminCommand(cmd);
    });
  });
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
      if (rodapeEl) rodapeEl.classList.toggle("rodape-destacado", !seraOcultado);
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
      if (targetId) setActiveSectionIndicator(targetId);
      window.setTimeout(syncActiveSectionOnScroll, 320);
    });
  });

  const offlineBtn = document.getElementById("btn-entrar-offline");
  if (offlineBtn) offlineBtn.addEventListener("click", enterOfflineTemporaryMode);

  const voltarEntradaBtn = document.getElementById("btn-voltar-entrada");
  if (voltarEntradaBtn) voltarEntradaBtn.addEventListener("click", handleLogout);

  const irLoginNuvemBtn = document.getElementById("btn-ir-login-nuvem");
  if (irLoginNuvemBtn) {
    irLoginNuvemBtn.addEventListener("click", () => {
      state.offlineMode = false;
      state.isAdmin = false;
      state.inspectedTargetUid = "";
      state.adminReadOnly = false;
      applySheetReadOnlyState(false);
      clearAuthSensitiveInputs();
      updateAuthUI();
      updateAdminVisibilityUI();
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
  if (authForm) authForm.addEventListener("submit", handleAuthSubmit);

  const toggleBtn = document.getElementById("auth-toggle-mode");
  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      state.authMode = state.authMode === "login" ? "register" : "login";
      updateAuthUI();
    });
  }

  const logoutBtn = document.getElementById("auth-logout-btn");
  if (logoutBtn) logoutBtn.addEventListener("click", handleLogout);

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

  if (clearConfirmBtn) clearConfirmBtn.addEventListener("click", handleClearSheetData);
  if (clearOfflineBtn) clearOfflineBtn.addEventListener("click", handleClearSheetData);

  if (deleteOpenBtn && deleteConfirmBox) {
    deleteOpenBtn.addEventListener("click", () => {
      if (clearConfirmBox) clearConfirmBox.hidden = true;
      deleteConfirmBox.hidden = !deleteConfirmBox.hidden;
    });
  }

  if (deleteCancelBtn && deleteConfirmBox) {
    deleteConfirmBox.hidden = true;
    deleteCancelBtn.addEventListener("click", () => {
      deleteConfirmBox.hidden = true;
    });
  }

  if (deleteConfirmBtn) deleteConfirmBtn.addEventListener("click", handleDeleteAccount);

  const saveBtn = document.getElementById("btn-save-sheet");
  if (saveBtn) saveBtn.addEventListener("click", () => persistSheet(true));

  const syncBtn = document.getElementById("auth-sync-btn");
  if (syncBtn) syncBtn.addEventListener("click", () => persistSheet(true));

  const mainEl = document.querySelector("main.container");
  if (mainEl) {
    mainEl.addEventListener("input", handleSheetControlMutation);
    mainEl.addEventListener("change", handleSheetControlMutation);
  }

  bindAdminEvents();
}

document.addEventListener("DOMContentLoaded", () => {
  initConsoleSecurityGuard();
  hardenExternalLinks();
  initLgpdBanner();
  bindEvents();
  setActiveSectionIndicator("dados-agente");
  updateAdminVisibilityUI();

  const localData = loadLocalData();
  if (localData) {
    applySheetData(localData);
  } else {
    recalculateSkillsTable();
    syncNenCategoryFromSelect();
  }

  updateAuthUI();
  updateScreenAccess();
  playLoginTitle3DWriting(true);
  initFirebase();
});
