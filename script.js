/* ==========================================================================
   Ordem de Arkan - Ficha de Agente (script.js)
   Segurança front-end (XSS, Prototype Pollution, validação de faixa/tipo,
   anti-spam de escrita, higiene de sessão, isTrusted guard e console guard)
   + Firebase Authentication & Cloud Firestore + Sessão Offline/Local temporária
   + Modo Administrador por UID (exclusivo): Prompt de Comando, Funções
     Dinâmicas do Comando Abaixo, Todos os Comandos Ativos, Mensagem até 24h
     (Normal/Urgente) para UID ou TODOS os jogadores, Admin Temporário até 24h
     (sem adicionar/remover admin), Aviso de Atualização 100% Funcional na
     Conta Master, Somente Leitura, UIDs Recentes, Ajuste Rápido, Modelos Base,
     Diff, Backup JSON e Log
   + Exclusão de ficha e exclusão de conta
   + Sincronização precisa das seções no topo conforme a rolagem
   + Cores dinâmicas conforme a Categoria Principal de Afinidade de Nen
   + Interatividade do painel de detalhes LGPD no rodapé do criador
   + Cálculo automático da tabela de Perícias (#tabela-pericias)
   + Animação 3D de digitação letra por letra no título (#entrada-titulo)
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
  ADMIN_TARGET_UID: "ordem_de_arkan_admin_target_uid_v1",
  ADMIN_RECENT_UIDS: "ordem_de_arkan_admin_recent_uids_v1",
  MASTER_SEEN_RELEASE: "ordem_de_arkan_master_seen_release_v1"
});

const ADMIN_UID = "TcudbnuOMcTySJWhz0JHaNDuNU22";
const GLOBAL_BROADCAST_DOC_ID = "__broadcast_global__";
const UID_REGEX = /^[a-zA-Z0-9_-]{10,128}$/;
const ADMIN_NOTICE_FIELD_KEY = "id:admin_recado_payload";
const TEMP_ADMIN_GRANT_FIELD_KEY = "id:admin_temp_grant_payload";
const MASTER_UPDATE_LOG_FIELD_KEY = "id:master_update_log_payload";
const RELEASE_MANIFEST_URL = "./release-manifest.json";
const MAX_NOTICE_HOURS = 24;
const MAX_NOTICE_MINUTES = MAX_NOTICE_HOURS * 60;
const MAX_TEMP_ADMIN_MINUTES = MAX_NOTICE_HOURS * 60;
const MAX_RECENT_UIDS = 6;
const MAX_ADMIN_LOGS = 25;

const ADMIN_COMMAND_CATALOG = Object.freeze([
  { cmd: "/admin", syntax: "/admin <UID> [min]", desc: "Dar admin até 24h (sem add/remover admin)", masterOnly: true },
  { cmd: "/uid", syntax: "/uid <UID>", desc: "Carregar ou trocar UID alvo" },
  { cmd: "/minha", syntax: "/minha", desc: "Voltar para a própria ficha" },
  { cmd: "/recado", syntax: "/recado <min> <texto>", desc: "Enviar recado normal para UID (até 24h)" },
  { cmd: "/urgente", syntax: "/urgente <min> <texto>", desc: "Enviar recado urgente para UID (até 24h)" },
  { cmd: "/todos", syntax: "/todos <min> <texto>", desc: "Enviar mensagem normal para TODOS os jogadores (até 24h)" },
  { cmd: "/todosurgente", syntax: "/todosurgente <min> <texto>", desc: "Enviar mensagem URGENTE para TODOS os jogadores (até 24h)" },
  { cmd: "/remover", syntax: "/remover", desc: "Remover recado ativo (UID ou global)" },
  { cmd: "/ler", syntax: "/ler [on|off]", desc: "Alternar modo somente leitura" },
  { cmd: "/stats", syntax: "/stats", desc: "Ajustar Nível, Rank e Espaços" },
  { cmd: "/modelo", syntax: "/modelo [iniciante|veterano|elite]", desc: "Clonar modelo base na ficha" },
  { cmd: "/diff", syntax: "/diff", desc: "Ver alterações pendentes" },
  { cmd: "/json", syntax: "/json", desc: "Exportar ou importar JSON" },
  { cmd: "/log", syntax: "/log", desc: "Ver log da sessão do admin" },
  { cmd: "/ajuda", syntax: "/ajuda", desc: "Listar todos os comandos" }
]);

const NOTICE_DURATION_PRESETS = Object.freeze([
  { minutes: 15, label: "15 minutos" },
  { minutes: 30, label: "30 minutos" },
  { minutes: 60, label: "1 hora (60 min)" },
  { minutes: 360, label: "6 horas" },
  { minutes: 720, label: "12 horas" },
  { minutes: 1440, label: "24 horas (máx.)" }
]);

const SHEET_TEMPLATES = Object.freeze({
  iniciante: Object.freeze({
    label: "Agente Iniciante (Nv 1 / Rank E)",
    fields: Object.freeze({
      "id:nv-val": "1",
      "id:rank-val": "E",
      "id:espacos-max": "5",
      "id:attr-agi": "1",
      "id:attr-for": "1",
      "id:attr-ca": "1",
      "id:attr-int": "1",
      "id:attr-vig": "1",
      "id:def-total": "11",
      "id:def-esquiva": "11",
      "id:def-deslocamento": "9"
    })
  }),
  veterano: Object.freeze({
    label: "Agente Veterano (Nv 10 / Rank C)",
    fields: Object.freeze({
      "id:nv-val": "10",
      "id:rank-val": "C",
      "id:espacos-max": "10",
      "id:attr-agi": "3",
      "id:attr-for": "2",
      "id:attr-ca": "3",
      "id:attr-int": "2",
      "id:attr-vig": "3",
      "id:def-total": "14",
      "id:def-esquiva": "14",
      "id:def-deslocamento": "10"
    })
  }),
  elite: Object.freeze({
    label: "Agente Elite / NPC Chefe (Nv 25 / Rank A)",
    fields: Object.freeze({
      "id:nv-val": "25",
      "id:rank-val": "A",
      "id:espacos-max": "18",
      "id:attr-agi": "5",
      "id:attr-for": "4",
      "id:attr-ca": "6",
      "id:attr-int": "4",
      "id:attr-vig": "5",
      "id:def-total": "18",
      "id:def-esquiva": "18",
      "id:def-deslocamento": "12"
    })
  })
});

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
  typewriterTimerId: null,
  typewriterPlayed: false,
  isSaving: false,
  isDeleting: false,
  lastSavedSnapshot: "",
  baselineFields: createSafeRecord(),
  lastCloudWriteAt: 0,
  tempAdminGrant: null,
  tempAdminExpiryTimer: null,
  masterUpdateNotice: null,
  masterReleaseNotice: null,
  adminTargetUid: "",
  adminRecentUids: [],
  adminReadOnly: false,
  adminLogs: [],
  adminActiveCommand: "",
  adminAllCommandsActive: false,
  adminDraftUid: "",
  adminDraftTempAdminUid: "",
  adminDraftTempAdminMinutes: MAX_TEMP_ADMIN_MINUTES,
  adminDraftNoticeText: "",
  adminDraftNoticeMinutes: MAX_NOTICE_MINUTES,
  adminDraftNoticePriority: "normal",
  adminDraftNoticeTargetMode: "uid",
  adminDraftNv: "1",
  adminDraftRank: "E",
  adminDraftSlots: "5",
  adminDraftTemplate: "iniciante",
  adminDraftJson: "",
  adminDiffText: "",
  activeNotice: null,
  globalNotice: null,
  noticeExpiryTimer: null
};

/* --------------------------------------------------------------------------
   Animação 3D de Digitação Letra por Letra no Título de Entrada
   -------------------------------------------------------------------------- */
function initTitulo3DDigitando(forceReplay = false) {
  const tituloEl = document.getElementById("entrada-titulo");
  if (!tituloEl) return;

  if (!forceReplay && state.typewriterPlayed && tituloEl.dataset.typewriterDone === "1") {
    return;
  }

  if (state.typewriterTimerId !== null) {
    clearTimeout(state.typewriterTimerId);
    state.typewriterTimerId = null;
  }

  const textoOriginal = sanitizeSingleLine(
    tituloEl.getAttribute("aria-label") || tituloEl.textContent || "Ordem de Arkan",
    80
  );
  if (!textoOriginal) return;

  state.typewriterPlayed = true;
  tituloEl.dataset.typewriterDone = "1";
  tituloEl.classList.add("titulo-3d-digitando");
  tituloEl.setAttribute("aria-label", textoOriginal);

  const fragment = document.createDocumentFragment();
  const atrasoPorLetraMs = 32;
  const atrasoInicialMs = 80;

  const cursor = document.createElement("span");
  cursor.className = "cursor-3d";
  cursor.setAttribute("aria-hidden", "true");

  Array.from(textoOriginal).forEach((caractere, index) => {
    const span = document.createElement("span");

    if (caractere === " ") {
      span.className = "char-space";
      span.textContent = "\u00A0";
    } else {
      span.className = "char-3d";
      span.textContent = caractere;
      span.style.setProperty("--char-delay", `${atrasoInicialMs + index * atrasoPorLetraMs}ms`);
    }

    span.setAttribute("aria-hidden", "true");
    fragment.appendChild(span);
  });

  fragment.appendChild(cursor);
  tituloEl.replaceChildren(fragment);

  const tempoTotalMs = atrasoInicialMs + textoOriginal.length * atrasoPorLetraMs + 320;
  state.typewriterTimerId = window.setTimeout(() => {
    state.typewriterTimerId = null;
    cursor.classList.add("is-done");
  }, tempoTotalMs);
}

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

function sanitizeStringArray(arr, maxItems = 12, maxLen = 180) {
  if (!Array.isArray(arr)) return [];
  return arr
    .slice(0, maxItems)
    .map((item) => sanitizeSingleLine(String(item ?? ""), maxLen))
    .filter(Boolean);
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
   Aviso de Atualização de HTML / CSS / JS na Conta do Administrador Master
   -------------------------------------------------------------------------- */
function verifySiteRuntimeHealth() {
  const hasAppContainer = Boolean(document.getElementById("app-ficha"));
  const hasMainSheet = Boolean(document.querySelector("main.container"));
  const hasCoreFunctions =
    typeof collectSheetData === "function" &&
    typeof persistSheet === "function" &&
    typeof applyNenCategoryTheme === "function";
  const hasLoadedStylesheet =
    Array.from(document.styleSheets || []).length > 0 ||
    Boolean(document.querySelector('link[rel="stylesheet"]'));

  return Boolean(hasAppContainer && hasMainSheet && hasCoreFunctions && hasLoadedStylesheet);
}

function getSeenMasterReleaseVersion() {
  try {
    return sanitizeSingleLine(localStorage.getItem(STORAGE_KEYS.MASTER_SEEN_RELEASE) || "", 60);
  } catch {
    return "";
  }
}

function markMasterReleaseAsSeen(version) {
  const cleanVer = sanitizeSingleLine(version || "", 60);
  if (!cleanVer) return;
  try {
    localStorage.setItem(STORAGE_KEYS.MASTER_SEEN_RELEASE, cleanVer);
  } catch {
    // Ignora falha de armazenamento
  }
}

function ensureMasterReleaseBannerElement() {
  if (document.getElementById("master-release-notice-banner")) return;
  const appFicha = document.getElementById("app-ficha");
  const mainEl = document.querySelector("main.container");
  const anchorParent = mainEl && mainEl.parentNode ? mainEl.parentNode : appFicha;
  if (!anchorParent) return;

  const box = document.createElement("aside");
  box.id = "master-release-notice-banner";
  box.hidden = true;
  box.setAttribute("role", "status");
  box.setAttribute("aria-live", "polite");
  box.style.cssText = [
    "margin: 10px auto 12px",
    "padding: 14px 16px",
    "max-width: 1120px",
    "border-radius: 10px",
    "border: 1px solid rgba(86, 211, 154, 0.8)",
    "background: rgba(16, 44, 36, 0.97)",
    "color: #effbf5"
  ].join(";");

  const masterBanner = document.getElementById("master-update-success-banner");
  const adminBar = document.getElementById("admin-uid-bar");
  const anchorAfter = masterBanner || adminBar;
  if (anchorAfter && anchorAfter.parentNode === anchorParent) {
    anchorParent.insertBefore(box, anchorAfter.nextSibling);
  } else if (mainEl && mainEl.parentNode === anchorParent) {
    anchorParent.insertBefore(box, mainEl);
  } else {
    anchorParent.appendChild(box);
  }
}

function renderMasterCodeReleaseBanner() {
  const banner = document.getElementById("master-release-notice-banner");
  const rel = state.masterReleaseNotice;

  if (!isMasterAdmin() || !rel || !rel.version) {
    if (banner) banner.hidden = true;
    return;
  }

  ensureMasterReleaseBannerElement();
  const activeBanner = document.getElementById("master-release-notice-banner");
  if (!activeBanner) return;

  const parsedDate = new Date(rel.publishedAt);
  const dateLabel = Number.isNaN(parsedDate.getTime())
    ? rel.publishedAt
    : parsedDate.toLocaleString("pt-BR", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      });

  activeBanner.innerHTML = "";

  const header = document.createElement("div");
  header.style.cssText =
    "display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px;";

  const title = document.createElement("strong");
  title.textContent = `ATUALIZAÇÃO DE CÓDIGO NO AR — 100% FUNCIONAL (v${rel.version})`;
  title.style.cssText = "color: #72efb3; font-size: 13px; letter-spacing: 0.3px;";

  const right = document.createElement("div");
  right.style.cssText = "display: flex; align-items: center; gap: 8px;";

  const timeInfo = document.createElement("span");
  timeInfo.textContent = dateLabel ? `Publicado: ${dateLabel}` : "Verificado no carregamento";
  timeInfo.style.cssText = "color: #bfead3; font-size: 12px;";

  const ackBtn = document.createElement("button");
  ackBtn.type = "button";
  ackBtn.textContent = "Marcar como conferida";
  ackBtn.style.cssText =
    "padding: 4px 10px; border-radius: 6px; border: 1px solid rgba(114,239,179,0.5); background: rgba(114,239,179,0.12); color: #b7f5d6; font-size: 11px; font-weight: 600; cursor: pointer;";
  ackBtn.addEventListener("click", () => {
    markMasterReleaseAsSeen(rel.version);
    state.masterReleaseNotice = null;
    renderMasterCodeReleaseBanner();
  });

  right.appendChild(timeInfo);
  right.appendChild(ackBtn);
  header.appendChild(title);
  header.appendChild(right);
  activeBanner.appendChild(header);

  const summary = document.createElement("p");
  summary.textContent =
    "A atualização de HTML, CSS e/ou JavaScript entrou no site e passou na verificação de funcionamento sem erros.";
  summary.style.cssText = "margin: 0 0 8px; font-size: 13px; color: #effbf5;";
  activeBanner.appendChild(summary);

  if (rel.filesUpdated.length) {
    const filesLine = document.createElement("p");
    filesLine.textContent = `Arquivos atualizados: ${rel.filesUpdated.join(", ")}`;
    filesLine.style.cssText = "margin: 0 0 8px; font-size: 12px; color: #9ce6c2; font-weight: 600;";
    activeBanner.appendChild(filesLine);
  }

  if (rel.addedFunctions.length) {
    const fnTitle = document.createElement("div");
    fnTitle.textContent = "Novas funções adicionadas:";
    fnTitle.style.cssText = "font-size: 12px; font-weight: 700; color: #ffd966; margin-bottom: 4px;";
    activeBanner.appendChild(fnTitle);

    const fnList = document.createElement("ul");
    fnList.style.cssText = "margin: 0 0 8px; padding-left: 18px; font-size: 12px; color: #effbf5;";
    rel.addedFunctions.forEach((fnText) => {
      const li = document.createElement("li");
      li.textContent = fnText;
      li.style.marginBottom = "2px";
      fnList.appendChild(li);
    });
    activeBanner.appendChild(fnList);
  }

  if (rel.improvements.length) {
    const impTitle = document.createElement("div");
    impTitle.textContent = "Outras coisas adicionadas e melhorias:";
    impTitle.style.cssText = "font-size: 12px; font-weight: 700; color: #ffd966; margin-bottom: 4px;";
    activeBanner.appendChild(impTitle);

    const impList = document.createElement("ul");
    impList.style.cssText = "margin: 0; padding-left: 18px; font-size: 12px; color: #d9f5e6;";
    rel.improvements.forEach((impText) => {
      const li = document.createElement("li");
      li.textContent = impText;
      li.style.marginBottom = "2px";
      impList.appendChild(li);
    });
    activeBanner.appendChild(impList);
  }

  activeBanner.hidden = false;
}

async function checkMasterCodeReleaseNotice() {
  if (!isMasterAdmin()) {
    state.masterReleaseNotice = null;
    renderMasterCodeReleaseBanner();
    return;
  }

  try {
    const res = await fetch(`${RELEASE_MANIFEST_URL}?cb=${Date.now()}`, {
      cache: "no-store"
    });
    if (!res.ok) return;

    const data = await res.json();
    if (!data || typeof data !== "object") return;

    const version = sanitizeSingleLine(String(data.version ?? ""), 60);
    if (!version) return;

    const seenVersion = getSeenMasterReleaseVersion();
    if (seenVersion === version) {
      state.masterReleaseNotice = null;
      renderMasterCodeReleaseBanner();
      return;
    }

    const healthy = verifySiteRuntimeHealth();
    if (!healthy) return;

    state.masterReleaseNotice = {
      version,
      publishedAt: sanitizeSingleLine(String(data.publishedAt ?? ""), 60),
      filesUpdated: sanitizeStringArray(data.filesUpdated, 10, 80),
      addedFunctions: sanitizeStringArray(data.addedFunctions, 12, 180),
      improvements: sanitizeStringArray(data.improvements, 12, 180)
    };

    renderMasterCodeReleaseBanner();
  } catch {
    // Falha silenciosa caso o manifest ainda não esteja disponível
  }
}

/* --------------------------------------------------------------------------
   Aviso de Ação Concluída na Conta do Administrador Master
   -------------------------------------------------------------------------- */
function parseMasterUpdateLogFromFields(fieldsObj) {
  if (!fieldsObj || typeof fieldsObj !== "object") return null;
  if (!Object.prototype.hasOwnProperty.call(fieldsObj, MASTER_UPDATE_LOG_FIELD_KEY)) return null;

  const raw = fieldsObj[MASTER_UPDATE_LOG_FIELD_KEY];
  if (typeof raw !== "string" || !raw.trim() || raw.length > 2500) return null;

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;

    const added = sanitizeSingleLine(String(parsed.added ?? ""), 240);
    const updatedAt = sanitizeSingleLine(String(parsed.updatedAt ?? ""), 60);
    const statusOk = parsed.ok === true;
    if (!added || !statusOk) return null;

    return {
      added,
      updatedAt: updatedAt || new Date().toISOString(),
      ok: true
    };
  } catch {
    return null;
  }
}

function ensureMasterUpdateBannerElement() {
  if (document.getElementById("master-update-success-banner")) return;
  const appFicha = document.getElementById("app-ficha");
  const mainEl = document.querySelector("main.container");
  const anchorParent = mainEl && mainEl.parentNode ? mainEl.parentNode : appFicha;
  if (!anchorParent) return;

  const box = document.createElement("aside");
  box.id = "master-update-success-banner";
  box.hidden = true;
  box.setAttribute("role", "status");
  box.setAttribute("aria-live", "polite");
  box.style.cssText = [
    "margin: 10px auto 12px",
    "padding: 12px 14px",
    "max-width: 1120px",
    "border-radius: 10px",
    "border: 1px solid rgba(72, 199, 142, 0.75)",
    "background: rgba(18, 46, 36, 0.96)",
    "color: #eefaf3"
  ].join(";");

  const adminBar = document.getElementById("admin-uid-bar");
  if (adminBar && adminBar.parentNode === anchorParent) {
    anchorParent.insertBefore(box, adminBar.nextSibling);
  } else if (mainEl && mainEl.parentNode === anchorParent) {
    anchorParent.insertBefore(box, mainEl);
  } else {
    anchorParent.appendChild(box);
  }
}

function renderMasterUpdateBanner() {
  const banner = document.getElementById("master-update-success-banner");
  if (!isMasterAdmin() || !state.masterUpdateNotice || !state.masterUpdateNotice.ok) {
    if (banner) banner.hidden = true;
    return;
  }

  ensureMasterUpdateBannerElement();
  const activeBanner = document.getElementById("master-update-success-banner");
  if (!activeBanner) return;

  const parsedDate = new Date(state.masterUpdateNotice.updatedAt);
  const timeFormatted = Number.isNaN(parsedDate.getTime())
    ? "agora"
    : parsedDate.toLocaleString("pt-BR", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
      });

  activeBanner.innerHTML = "";

  const topRow = document.createElement("div");
  topRow.style.cssText =
    "display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 6px;";

  const title = document.createElement("strong");
  title.textContent = "ATUALIZAÇÃO CONCLUÍDA — 100% FUNCIONAL";
  title.style.cssText = "color: #72efb3; font-size: 13px; letter-spacing: 0.3px;";

  const rightControls = document.createElement("div");
  rightControls.style.cssText = "display: flex; align-items: center; gap: 8px;";

  const timeSpan = document.createElement("span");
  timeSpan.textContent = `Confirmado em ${timeFormatted}`;
  timeSpan.style.cssText = "color: #bfead3; font-size: 12px;";

  const dismissBtn = document.createElement("button");
  dismissBtn.type = "button";
  dismissBtn.textContent = "Dispensar";
  dismissBtn.style.cssText =
    "padding: 3px 9px; border-radius: 6px; border: 1px solid rgba(114,239,179,0.45); background: transparent; color: #b7f5d6; font-size: 11px; cursor: pointer;";
  dismissBtn.addEventListener("click", () => {
    state.masterUpdateNotice = null;
    renderMasterUpdateBanner();
  });

  rightControls.appendChild(timeSpan);
  rightControls.appendChild(dismissBtn);
  topRow.appendChild(title);
  topRow.appendChild(rightControls);

  const body = document.createElement("p");
  body.textContent = `O que foi adicionado/atualizado: ${state.masterUpdateNotice.added}. Sistema validado e 100% funcional.`;
  body.style.cssText = "margin: 0; font-size: 13px; line-height: 1.45; color: #eefaf3;";

  activeBanner.appendChild(topRow);
  activeBanner.appendChild(body);
  activeBanner.hidden = false;
}

async function recordMasterSuccessUpdate(summaryText) {
  if (!isMasterAdmin() || !state.firebaseReady || !state.db || !state.user?.uid) return;
  const cleanSummary = sanitizeSingleLine(summaryText, 240);
  if (!cleanSummary) return;

  const isoNow = new Date().toISOString();
  const payloadObj = {
    added: cleanSummary,
    updatedAt: isoNow,
    ok: true
  };

  state.masterUpdateNotice = payloadObj;
  renderMasterUpdateBanner();

  const { doc, getDoc, setDoc } = state.firebaseModules.firestoreMod;
  const masterDocRef = doc(state.db, FIRESTORE_COLLECTION, ADMIN_UID);

  try {
    const snap = await getDoc(masterDocRef);
    const existingFields =
      snap.exists() && snap.data() && snap.data().fields && typeof snap.data().fields === "object"
        ? snap.data().fields
        : createSafeRecord();

    const nextFields = createSafeRecord();
    Object.entries(existingFields).forEach(([k, v]) => {
      if (isValidFieldKey(k)) {
        nextFields[k] = v;
      }
    });
    nextFields[MASTER_UPDATE_LOG_FIELD_KEY] = JSON.stringify(payloadObj);

    await setDoc(masterDocRef, {
      fields: nextFields,
      atualizadoEm: isoNow
    });
    state.lastCloudWriteAt = Date.now();

    if (getActiveTargetUid() === ADMIN_UID) {
      captureBaselineFields(nextFields);
      state.lastSavedSnapshot = computeFieldsSnapshot(nextFields);
    }
  } catch {
    // Não bloqueia a operação principal se o log extra falhar
  }
}

/* --------------------------------------------------------------------------
   Administrador Temporário até 24h (Sem Permissão de Adicionar/Remover Admin)
   -------------------------------------------------------------------------- */
function normalizeTempAdminMinutes(rawMinutes) {
  const num = Number(rawMinutes);
  if (!Number.isFinite(num) || num <= 0) return MAX_TEMP_ADMIN_MINUTES;
  return Math.min(MAX_TEMP_ADMIN_MINUTES, Math.max(1, Math.trunc(num)));
}

function buildEncodedTempAdminGrant(targetUid, minutesValue, grantedByUid) {
  const uid = sanitizeTargetUid(targetUid);
  const granter = sanitizeTargetUid(grantedByUid);
  if (!uid || granter !== ADMIN_UID) return "";

  const minutes = normalizeTempAdminMinutes(minutesValue);
  const nowMs = Date.now();
  const maxAllowedExpiryMs = nowMs + MAX_TEMP_ADMIN_MINUTES * 60 * 1000;
  const requestedExpiryMs = nowMs + minutes * 60 * 1000;
  const expiresAtMs = Math.min(maxAllowedExpiryMs, requestedExpiryMs);

  return JSON.stringify({
    uid,
    grantedBy: granter,
    minutes,
    grantedAt: nowMs,
    expiresAt: expiresAtMs
  });
}

function parseTempAdminGrantFromFields(fieldsObj, expectedUid = "") {
  if (!fieldsObj || typeof fieldsObj !== "object") return null;
  if (!Object.prototype.hasOwnProperty.call(fieldsObj, TEMP_ADMIN_GRANT_FIELD_KEY)) return null;

  const raw = fieldsObj[TEMP_ADMIN_GRANT_FIELD_KEY];
  if (typeof raw !== "string" || !raw.trim() || raw.length > 2000) return null;

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;

    const uid = sanitizeTargetUid(parsed.uid);
    const grantedBy = sanitizeTargetUid(parsed.grantedBy);
    const grantedAt = Number(parsed.grantedAt);
    const expiresAt = Number(parsed.expiresAt);
    const minutes = normalizeTempAdminMinutes(parsed.minutes);

    if (!uid || grantedBy !== ADMIN_UID || !Number.isFinite(expiresAt)) return null;
    if (expectedUid && uid !== expectedUid) return null;

    const nowMs = Date.now();
    const baseTime = Number.isFinite(grantedAt) ? grantedAt : nowMs;
    const hardCapMs = baseTime + MAX_TEMP_ADMIN_MINUTES * 60 * 1000;
    const effectiveExpiryMs = Math.min(expiresAt, hardCapMs);

    if (nowMs >= effectiveExpiryMs) {
      return null;
    }

    return {
      uid,
      grantedBy,
      minutes,
      grantedAt: baseTime,
      expiresAt: effectiveExpiryMs
    };
  } catch {
    return null;
  }
}

function scheduleTempAdminExpiryCheck() {
  if (state.tempAdminExpiryTimer) {
    clearTimeout(state.tempAdminExpiryTimer);
    state.tempAdminExpiryTimer = null;
  }

  if (!state.tempAdminGrant || !Number.isFinite(state.tempAdminGrant.expiresAt)) return;

  const remainingMs = state.tempAdminGrant.expiresAt - Date.now();
  if (remainingMs <= 0) {
    state.tempAdminGrant = null;
    updateAdminBarUI();
    return;
  }

  state.tempAdminExpiryTimer = setTimeout(() => {
    state.tempAdminExpiryTimer = null;
    if (state.tempAdminGrant && Date.now() >= state.tempAdminGrant.expiresAt) {
      state.tempAdminGrant = null;
      if (state.adminActiveCommand === "/admin") {
        state.adminActiveCommand = "";
      }
      updateAdminBarUI();
      setStatusBanner("A função temporária de administrador expirou (limite de 24h).", "warning");
    }
  }, Math.min(remainingMs + 250, 2147483647));
}

function isMasterAdmin() {
  return Boolean(state.user && typeof state.user.uid === "string" && state.user.uid === ADMIN_UID);
}

function hasActiveTempAdminRole() {
  if (!state.user || !state.user.uid) return false;
  if (isMasterAdmin()) return false;
  if (!state.tempAdminGrant || Date.now() >= (state.tempAdminGrant.expiresAt || 0)) {
    state.tempAdminGrant = null;
    return false;
  }
  return state.tempAdminGrant.uid === state.user.uid;
}

function isCurrentUserAdmin() {
  return isMasterAdmin() || hasActiveTempAdminRole();
}

function isInspectionReadOnlyActive() {
  return Boolean(isCurrentUserAdmin() && state.adminReadOnly);
}

/* --------------------------------------------------------------------------
   Mensagens Temporárias do Admin por UID ou Global (Normal/Urgente até 24h)
   -------------------------------------------------------------------------- */
function normalizeNoticeMinutes(rawMinutes) {
  const num = Number(rawMinutes);
  if (!Number.isFinite(num) || num <= 0) return MAX_NOTICE_MINUTES;
  return Math.min(MAX_NOTICE_MINUTES, Math.max(1, Math.trunc(num)));
}

function normalizeNoticePriority(rawPriority) {
  return rawPriority === "urgent" ? "urgent" : "normal";
}

function formatDurationLabel(minutes) {
  const safeMin = normalizeNoticeMinutes(minutes);
  if (safeMin < 60) {
    return `${safeMin} min`;
  }
  const wholeHours = Math.floor(safeMin / 60);
  const remMinutes = safeMin % 60;
  return remMinutes === 0 ? `${wholeHours}h` : `${wholeHours}h ${remMinutes}min`;
}

function formatRemainingTimeLabel(expiresAtMs) {
  const diffMs = Number(expiresAtMs) - Date.now();
  if (!Number.isFinite(diffMs) || diffMs <= 0) return "expirado";
  const totalMin = Math.max(1, Math.ceil(diffMs / 60000));
  return `restam ~${formatDurationLabel(totalMin)}`;
}

function buildEncodedNoticePayload(messageText, minutesValue, priorityValue = "normal", scope = "uid") {
  const cleanText = sanitizeText(String(messageText ?? ""), 600).trim();
  if (!cleanText) return "";

  const minutes = normalizeNoticeMinutes(minutesValue);
  const priority = normalizeNoticePriority(priorityValue);
  const nowMs = Date.now();
  const maxAllowedExpiryMs = nowMs + MAX_NOTICE_MINUTES * 60 * 1000;
  const requestedExpiryMs = nowMs + minutes * 60 * 1000;
  const expiresAtMs = Math.min(maxAllowedExpiryMs, requestedExpiryMs);

  return JSON.stringify({
    msg: cleanText,
    minutes,
    hours: Number((minutes / 60).toFixed(2)),
    priority,
    scope: scope === "all" ? "all" : "uid",
    sentAt: nowMs,
    expiresAt: expiresAtMs
  });
}

function parseNoticeObject(raw, fallbackScope = "uid") {
  if (typeof raw !== "string" || !raw.trim() || raw.length > 2000) return null;

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;

    const cleanMsg = sanitizeText(String(parsed.msg ?? ""), 600).trim();
    const sentAt = Number(parsed.sentAt);
    const expiresAt = Number(parsed.expiresAt);
    const rawMin =
      parsed.minutes !== undefined && parsed.minutes !== null
        ? parsed.minutes
        : Number(parsed.hours) * 60;
    const minutes = normalizeNoticeMinutes(rawMin);
    const priority = normalizeNoticePriority(parsed.priority);
    const scope = parsed.scope === "all" ? "all" : fallbackScope;

    if (!cleanMsg || !Number.isFinite(expiresAt)) return null;

    const nowMs = Date.now();
    const hardCapMs = (Number.isFinite(sentAt) ? sentAt : nowMs) + MAX_NOTICE_MINUTES * 60 * 1000;
    const effectiveExpiryMs = Math.min(expiresAt, hardCapMs);

    if (nowMs >= effectiveExpiryMs) {
      return null;
    }

    return {
      msg: cleanMsg,
      minutes,
      priority,
      scope,
      expiresAt: effectiveExpiryMs
    };
  } catch {
    return null;
  }
}

function parseActiveNoticeFromFields(fieldsObj) {
  if (!fieldsObj || typeof fieldsObj !== "object") return null;
  if (!Object.prototype.hasOwnProperty.call(fieldsObj, ADMIN_NOTICE_FIELD_KEY)) return null;
  return parseNoticeObject(fieldsObj[ADMIN_NOTICE_FIELD_KEY], "uid");
}

function getEffectiveDisplayedNotice() {
  const now = Date.now();
  const uidNotice =
    state.activeNotice && now < (state.activeNotice.expiresAt || 0) ? state.activeNotice : null;
  const globalNotice =
    state.globalNotice && now < (state.globalNotice.expiresAt || 0) ? state.globalNotice : null;

  if (uidNotice && globalNotice) {
    return uidNotice.expiresAt >= globalNotice.expiresAt ? uidNotice : globalNotice;
  }
  return uidNotice || globalNotice || null;
}

function scheduleNoticeExpiryCheck() {
  if (state.noticeExpiryTimer) {
    clearTimeout(state.noticeExpiryTimer);
    state.noticeExpiryTimer = null;
  }

  const now = Date.now();
  const expiries = [];
  if (state.activeNotice && state.activeNotice.expiresAt > now) expiries.push(state.activeNotice.expiresAt);
  if (state.globalNotice && state.globalNotice.expiresAt > now) expiries.push(state.globalNotice.expiresAt);

  if (!expiries.length) return;

  const nearestExpiry = Math.min(...expiries);
  const remainingMs = nearestExpiry - now;
  if (remainingMs <= 0) {
    if (state.activeNotice && now >= state.activeNotice.expiresAt) state.activeNotice = null;
    if (state.globalNotice && now >= state.globalNotice.expiresAt) state.globalNotice = null;
    renderPlayerNoticeBanner();
    renderAdminCommandFunctionsBelow();
    return;
  }

  state.noticeExpiryTimer = setTimeout(() => {
    state.noticeExpiryTimer = null;
    const checkNow = Date.now();
    if (state.activeNotice && checkNow >= state.activeNotice.expiresAt) state.activeNotice = null;
    if (state.globalNotice && checkNow >= state.globalNotice.expiresAt) state.globalNotice = null;
    renderPlayerNoticeBanner();
    renderAdminCommandFunctionsBelow();
    scheduleNoticeExpiryCheck();
  }, Math.min(remainingMs + 250, 2147483647));
}

function renderPlayerNoticeBanner() {
  const banner = document.getElementById("player-admin-notice-banner");
  const hasSession = Boolean(state.user) || Boolean(state.offlineMode);
  const currentNotice = getEffectiveDisplayedNotice();

  if (!hasSession || state.offlineMode || !currentNotice) {
    if (banner) banner.hidden = true;
    return;
  }

  ensurePlayerNoticeBannerElement();
  const activeBanner = document.getElementById("player-admin-notice-banner");
  if (!activeBanner) return;

  const isUrgent = currentNotice.priority === "urgent";
  const isGlobal = currentNotice.scope === "all";

  activeBanner.style.border = isUrgent
    ? "1px solid rgba(255, 99, 99, 0.85)"
    : "1px solid rgba(255, 217, 102, 0.55)";
  activeBanner.style.background = isUrgent
    ? "rgba(62, 22, 28, 0.96)"
    : "rgba(34, 42, 54, 0.96)";

  const expDate = new Date(currentNotice.expiresAt);
  const expFormatted = expDate.toLocaleString("pt-BR", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });

  activeBanner.innerHTML = "";

  const header = document.createElement("div");
  header.style.cssText = "display: flex; flex-wrap: wrap; justify-content: space-between; gap: 6px; margin-bottom: 6px;";

  const title = document.createElement("strong");
  if (isGlobal && isUrgent) {
    title.textContent = "AVISO URGENTE GLOBAL DO ADMINISTRADOR (TODOS OS JOGADORES)";
  } else if (isGlobal) {
    title.textContent = "Aviso Global do Administrador (Todos os Jogadores)";
  } else if (isUrgent) {
    title.textContent = "AVISO URGENTE DO ADMINISTRADOR";
  } else {
    title.textContent = "Recado do Administrador";
  }
  title.style.cssText = isUrgent
    ? "color: #ff8a80; font-size: 13px; letter-spacing: 0.4px;"
    : "color: #ffe082; font-size: 13px;";

  const meta = document.createElement("span");
  meta.textContent = `Duração: ${formatDurationLabel(currentNotice.minutes)} (${formatRemainingTimeLabel(currentNotice.expiresAt)} · expira em ${expFormatted})`;
  meta.style.cssText = "color: #d6dee6; font-size: 12px;";

  const body = document.createElement("p");
  body.textContent = currentNotice.msg;
  body.style.cssText = "margin: 0; white-space: pre-wrap; word-break: break-word; font-size: 14px; line-height: 1.45;";

  header.appendChild(title);
  header.appendChild(meta);
  activeBanner.appendChild(header);
  activeBanner.appendChild(body);
  activeBanner.hidden = false;
}

function ensurePlayerNoticeBannerElement() {
  if (document.getElementById("player-admin-notice-banner")) return;
  const appFicha = document.getElementById("app-ficha");
  const mainEl = document.querySelector("main.container");
  const anchorParent = mainEl && mainEl.parentNode ? mainEl.parentNode : appFicha;
  if (!anchorParent) return;

  const box = document.createElement("aside");
  box.id = "player-admin-notice-banner";
  box.hidden = true;
  box.setAttribute("role", "status");
  box.setAttribute("aria-live", "polite");
  box.style.cssText = [
    "margin: 10px auto 12px",
    "padding: 12px 14px",
    "max-width: 1120px",
    "border-radius: 10px",
    "border: 1px solid rgba(255, 217, 102, 0.55)",
    "background: rgba(34, 42, 54, 0.96)",
    "color: #f4f6f8"
  ].join(";");

  const releaseBanner = document.getElementById("master-release-notice-banner");
  const masterBanner = document.getElementById("master-update-success-banner");
  const adminBar = document.getElementById("admin-uid-bar");
  const anchorAfter = releaseBanner || masterBanner || adminBar;
  if (anchorAfter && anchorAfter.parentNode === anchorParent) {
    anchorParent.insertBefore(box, anchorAfter.nextSibling);
  } else if (mainEl && mainEl.parentNode === anchorParent) {
    anchorParent.insertBefore(box, mainEl);
  } else {
    anchorParent.appendChild(box);
  }
}

async function loadGlobalBroadcastNotice() {
  if (!state.firebaseReady || !state.db || !state.user) return;
  const { doc, getDoc } = state.firebaseModules.firestoreMod;

  try {
    const snap = await getDoc(doc(state.db, FIRESTORE_COLLECTION, GLOBAL_BROADCAST_DOC_ID));
    if (!snap.exists()) {
      state.globalNotice = null;
      scheduleNoticeExpiryCheck();
      renderPlayerNoticeBanner();
      return;
    }

    const fields = snap.data()?.fields;
    const raw = fields && Object.prototype.hasOwnProperty.call(fields, ADMIN_NOTICE_FIELD_KEY)
      ? fields[ADMIN_NOTICE_FIELD_KEY]
      : "";
    state.globalNotice = parseNoticeObject(raw, "all");
    scheduleNoticeExpiryCheck();
    renderPlayerNoticeBanner();
    if (
      state.adminActiveCommand === "/recado" ||
      state.adminActiveCommand === "/urgente" ||
      state.adminActiveCommand === "/todos" ||
      state.adminActiveCommand === "/todosurgente" ||
      state.adminActiveCommand === "/remover"
    ) {
      renderAdminCommandFunctionsBelow();
    }
  } catch {
    // Falha silenciosa caso documento global ainda não exista ou regras bloqueiem
  }
}

/* --------------------------------------------------------------------------
   Helpers da Conta Admin: Prompt, Funções Abaixo do Comando e
   Área de Todos os Comandos Ativos
   -------------------------------------------------------------------------- */
function sanitizeTargetUid(rawUid) {
  const clean = sanitizeSingleLine(String(rawUid ?? ""), 128);
  return UID_REGEX.test(clean) ? clean : "";
}

function getAvailableCommandsForCurrentUser() {
  if (isMasterAdmin()) {
    return ADMIN_COMMAND_CATALOG;
  }
  return ADMIN_COMMAND_CATALOG.filter((item) => !item.masterOnly);
}

function appendAdminLog(actionText) {
  if (!isCurrentUserAdmin()) return;
  const clean = sanitizeSingleLine(actionText, 180);
  if (!clean) return;
  const timeStr = new Date().toLocaleTimeString("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit"
  });
  state.adminLogs = [`[${timeStr}] ${clean}`, ...state.adminLogs].slice(0, MAX_ADMIN_LOGS);
  if (state.adminActiveCommand === "/log") {
    renderAdminCommandFunctionsBelow();
  }
}

function captureBaselineFields(fieldsObj) {
  const copy = createSafeRecord();
  if (!fieldsObj || typeof fieldsObj !== "object") {
    state.baselineFields = copy;
    return;
  }
  Object.entries(fieldsObj).forEach(([k, v]) => {
    if (isValidFieldKey(k)) {
      copy[k] = v;
    }
  });
  state.baselineFields = copy;
}

function computeSheetDiffList() {
  const current = collectSheetData().fields;
  const baseline = state.baselineFields || createSafeRecord();
  const allKeys = Array.from(new Set([...Object.keys(baseline), ...Object.keys(current)])).sort();
  const changes = [];

  for (let i = 0; i < allKeys.length; i += 1) {
    const key = allKeys[i];
    if (
      !isValidFieldKey(key) ||
      key === ADMIN_NOTICE_FIELD_KEY ||
      key === TEMP_ADMIN_GRANT_FIELD_KEY ||
      key === MASTER_UPDATE_LOG_FIELD_KEY
    ) {
      continue;
    }
    const oldVal = Object.prototype.hasOwnProperty.call(baseline, key) ? baseline[key] : "";
    const newVal = Object.prototype.hasOwnProperty.call(current, key) ? current[key] : "";
    if (String(oldVal) !== String(newVal)) {
      const label = key.startsWith("id:") ? key.slice(3) : key;
      changes.push(`${label}: "${String(oldVal)}" → "${String(newVal)}"`);
    }
  }
  return changes;
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

function recordRecentAdminUid(uid) {
  const clean = sanitizeTargetUid(uid);
  if (!clean) return;
  const next = [clean, ...state.adminRecentUids.filter((item) => item !== clean)].slice(0, MAX_RECENT_UIDS);
  state.adminRecentUids = next;
  try {
    sessionStorage.setItem(STORAGE_KEYS.ADMIN_RECENT_UIDS, JSON.stringify(next));
  } catch {
    // Ignora falha de armazenamento
  }
  if (state.adminActiveCommand === "/uid" || state.adminActiveCommand === "/minha") {
    renderAdminCommandFunctionsBelow();
  }
}

function loadRecentAdminUidsFromStorage() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEYS.ADMIN_RECENT_UIDS);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.map(sanitizeTargetUid).filter(Boolean).slice(0, MAX_RECENT_UIDS);
  } catch {
    return [];
  }
}

function getActiveTargetUid() {
  if (!state.user || !state.user.uid) return "";
  if (isMasterAdmin() && state.adminTargetUid) {
    return state.adminTargetUid;
  }
  return state.user.uid;
}

function applySheetReadOnlyState() {
  const mainEl = document.querySelector("main.container");
  if (!mainEl) return;

  const lock = isInspectionReadOnlyActive();
  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl) => {
    if (!ctrl || ctrl.closest("#login-firebase")) return;
    if (ctrl.tagName === "SELECT" || ctrl.type === "checkbox") {
      ctrl.disabled = lock;
    } else {
      ctrl.readOnly = lock;
      ctrl.setAttribute("aria-readonly", lock ? "true" : "false");
    }
  });
}

function syncAdminQuickInputsFromSheet() {
  const sheetNv = document.getElementById("nv-val");
  const sheetRank = document.getElementById("rank-val");
  const sheetSlots = document.getElementById("espacos-max");

  if (sheetNv && document.activeElement?.id !== "admin-fn-nv") {
    state.adminDraftNv = normalizeNumericValue("nv-val", sheetNv.value || "1");
  }
  if (sheetRank && document.activeElement?.id !== "admin-fn-rank") {
    const cleanRank = normalizeRankValue(sheetRank.value || "E");
    state.adminDraftRank = ALLOWED_RANKS.includes(cleanRank) ? cleanRank : "E";
  }
  if (sheetSlots && document.activeElement?.id !== "admin-fn-slots") {
    state.adminDraftSlots = normalizeNumericValue("espacos-max", sheetSlots.value || "5");
  }
}

function resolveCommandNameFromInput(rawInput) {
  const clean = sanitizeSingleLine(String(rawInput ?? ""), 120).trim();
  if (!clean) return "";
  const firstToken = clean.split(/\s+/)[0].toLowerCase();
  const normalizedToken = firstToken.startsWith("/") ? firstToken : `/${firstToken}`;

  if (normalizedToken === "/ajuste" || normalizedToken === "/nv" || normalizedToken === "/rank") {
    return "/stats";
  }
  if (normalizedToken === "/exportar" || normalizedToken === "/importar") {
    return "/json";
  }
  if (normalizedToken === "/help") {
    return "/ajuda";
  }

  const available = getAvailableCommandsForCurrentUser();
  const found = available.find((item) => item.cmd === normalizedToken);
  return found ? found.cmd : normalizedToken;
}

function renderActiveCommandsStrip() {
  const strip = document.getElementById("admin-all-commands-box");
  const toggleBtn = document.getElementById("admin-toggle-all-cmds-btn");
  if (!strip || !toggleBtn) return;

  toggleBtn.textContent = state.adminAllCommandsActive
    ? "Todos os comandos: ATIVOS (ON)"
    : "Ativar todos os comandos";
  toggleBtn.style.background = state.adminAllCommandsActive
    ? "rgba(255, 217, 102, 0.22)"
    : "transparent";
  toggleBtn.style.color = state.adminAllCommandsActive ? "#ffd966" : "#e4e4ec";
  toggleBtn.style.borderColor = state.adminAllCommandsActive
    ? "#ffd966"
    : "rgba(255,255,255,0.25)";

  if (!state.adminAllCommandsActive) {
    strip.hidden = true;
    strip.innerHTML = "";
    return;
  }

  strip.hidden = false;
  strip.innerHTML = "";

  const header = document.createElement("div");
  header.textContent = isMasterAdmin()
    ? "Comandos ativos (clique para carregar no prompt e exibir as funções abaixo):"
    : "Comandos ativos do admin temporário (sem permissão para adicionar ou remover admin):";
  header.style.cssText = "font-size: 12px; color: #ffd966; font-weight: 600; margin-bottom: 6px;";
  strip.appendChild(header);

  const grid = document.createElement("div");
  grid.style.cssText = "display: flex; flex-wrap: wrap; gap: 6px;";

  getAvailableCommandsForCurrentUser().forEach((item) => {
    const btn = document.createElement("button");
    btn.type = "button";
    const isSelected = state.adminActiveCommand === item.cmd;
    btn.textContent = `${item.cmd} — ${item.desc}`;
    btn.style.cssText = [
      "padding: 5px 9px",
      "border-radius: 7px",
      "font-size: 11px",
      "cursor: pointer",
      isSelected
        ? "border: 1px solid #ffd966; background: rgba(255,217,102,0.2); color: #ffd966; font-weight: 700;"
        : "border: 1px solid rgba(255,255,255,0.18); background: rgba(10,14,18,0.8); color: #e4e4ec;"
    ].join(";");

    btn.addEventListener("click", () => {
      const promptInput = document.getElementById("admin-prompt-input");
      if (promptInput) {
        promptInput.value = `${item.cmd} `;
        promptInput.focus();
      }
      state.adminActiveCommand = item.cmd;
      if (item.cmd === "/todos" || item.cmd === "/todosurgente") {
        state.adminDraftNoticeTargetMode = "all";
        state.adminDraftNoticePriority = item.cmd === "/todosurgente" ? "urgent" : "normal";
      } else if (item.cmd === "/recado" || item.cmd === "/urgente") {
        state.adminDraftNoticeTargetMode = "uid";
        state.adminDraftNoticePriority = item.cmd === "/urgente" ? "urgent" : "normal";
      }
      renderActiveCommandsStrip();
      renderAdminCommandFunctionsBelow();
    });

    grid.appendChild(btn);
  });

  strip.appendChild(grid);
}

function renderAdminCommandFunctionsBelow() {
  const box = document.getElementById("admin-command-functions-panel");
  if (!box) return;

  const cmd = state.adminActiveCommand;
  if (!cmd) {
    box.hidden = true;
    box.innerHTML = "";
    return;
  }

  if (cmd === "/admin" && !isMasterAdmin()) {
    box.hidden = false;
    box.innerHTML = "";
    const denied = document.createElement("div");
    denied.textContent =
      "Administrador temporário não pode adicionar ou remover administradores.";
    denied.style.cssText = "font-size: 12px; color: #ff8a80; font-weight: 600;";
    box.appendChild(denied);
    return;
  }

  box.hidden = false;
  box.innerHTML = "";

  const titleRow = document.createElement("div");
  titleRow.style.cssText = "display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px;";

  const title = document.createElement("strong");
  const spec = getAvailableCommandsForCurrentUser().find((c) => c.cmd === cmd);
  title.textContent = spec
    ? `Funções do comando ${spec.syntax} — ${spec.desc}`
    : `Funções do comando ${cmd}`;
  title.style.cssText = "color: #ffd966; font-size: 12px;";

  const hideBtn = document.createElement("button");
  hideBtn.type = "button";
  hideBtn.textContent = "Ocultar";
  hideBtn.style.cssText = "padding: 3px 8px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2); background: transparent; color: #ccc; font-size: 11px; cursor: pointer;";
  hideBtn.addEventListener("click", () => {
    state.adminActiveCommand = "";
    renderActiveCommandsStrip();
    renderAdminCommandFunctionsBelow();
  });

  titleRow.appendChild(title);
  titleRow.appendChild(hideBtn);
  box.appendChild(titleRow);

  if (cmd === "/admin" && isMasterAdmin()) {
    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

    const uidInput = document.createElement("input");
    uidInput.type = "text";
    uidInput.value = state.adminDraftTempAdminUid || "";
    uidInput.placeholder = "UID para receber admin temporário...";
    uidInput.style.cssText = "flex: 1 1 200px; padding: 7px 10px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    uidInput.addEventListener("input", () => {
      state.adminDraftTempAdminUid = uidInput.value;
    });

    const durSelect = document.createElement("select");
    durSelect.style.cssText = "padding: 7px 9px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #ffd966; font-size: 12px; font-weight: 600;";
    NOTICE_DURATION_PRESETS.forEach((opt) => {
      const optionEl = document.createElement("option");
      optionEl.value = String(opt.minutes);
      optionEl.textContent = opt.label;
      if (normalizeTempAdminMinutes(state.adminDraftTempAdminMinutes) === opt.minutes) {
        optionEl.selected = true;
      }
      durSelect.appendChild(optionEl);
    });
    durSelect.addEventListener("change", () => {
      state.adminDraftTempAdminMinutes = normalizeTempAdminMinutes(durSelect.value);
    });

    const grantBtn = document.createElement("button");
    grantBtn.type = "button";
    grantBtn.textContent = "Conceder admin (até 24h)";
    grantBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: none; background: #c48b1b; color: #111; font-weight: 700; font-size: 12px; cursor: pointer;";
    grantBtn.addEventListener("click", () =>
      handleAdminGrantTempRole({
        uid: uidInput.value,
        minutes: durSelect.value
      })
    );

    row.appendChild(uidInput);
    row.appendChild(durSelect);
    row.appendChild(grantBtn);
    box.appendChild(row);

    const note = document.createElement("div");
    note.textContent =
      "Concedido por até 24h. O administrador temporário não terá opção para adicionar ou remover administradores.";
    note.style.cssText = "margin-top: 7px; font-size: 11px; color: #b8c2cc;";
    box.appendChild(note);
    return;
  }

  if (cmd === "/uid" || cmd === "/minha") {
    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

    const uidInput = document.createElement("input");
    uidInput.type = "text";
    uidInput.value = state.adminDraftUid || state.adminTargetUid || "";
    uidInput.placeholder = "Cole o UID do jogador...";
    uidInput.style.cssText = "flex: 1 1 200px; padding: 7px 10px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    uidInput.addEventListener("input", () => {
      state.adminDraftUid = uidInput.value;
    });

    const loadBtn = document.createElement("button");
    loadBtn.type = "button";
    loadBtn.textContent = "Carregar UID";
    loadBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: none; background: #2b8a6e; color: #fff; font-weight: 600; font-size: 12px; cursor: pointer;";
    loadBtn.addEventListener("click", () => handleAdminLoadTargetUid(uidInput.value));

    const selfBtn = document.createElement("button");
    selfBtn.type = "button";
    selfBtn.textContent = "Minha ficha";
    selfBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.25); background: transparent; color: #e4e4ec; font-size: 12px; cursor: pointer;";
    selfBtn.addEventListener("click", handleAdminReturnToOwnSheet);

    row.appendChild(uidInput);
    row.appendChild(loadBtn);
    row.appendChild(selfBtn);
    box.appendChild(row);

    if (state.adminRecentUids.length) {
      const recentRow = document.createElement("div");
      recentRow.style.cssText = "display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; align-items: center;";
      const lbl = document.createElement("span");
      lbl.textContent = "Recentes:";
      lbl.style.cssText = "font-size: 11px; color: #b8c2cc;";
      recentRow.appendChild(lbl);

      state.adminRecentUids.forEach((u) => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.textContent = u.length > 14 ? `${u.slice(0, 10)}…` : u;
        chip.style.cssText = "padding: 4px 8px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.2); background: #0a0e12; color: #ffd966; font-size: 11px; cursor: pointer;";
        chip.addEventListener("click", () => {
          state.adminDraftUid = u;
          handleAdminLoadTargetUid(u);
        });
        recentRow.appendChild(chip);
      });
      box.appendChild(recentRow);
    }
    return;
  }

  if (
    cmd === "/recado" ||
    cmd === "/urgente" ||
    cmd === "/todos" ||
    cmd === "/todosurgente" ||
    cmd === "/remover"
  ) {
    const isAllCmd = cmd === "/todos" || cmd === "/todosurgente";
    const isUrgentCmd = cmd === "/urgente" || cmd === "/todosurgente";

    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

    const msgInput = document.createElement("input");
    msgInput.type = "text";
    msgInput.maxLength = 600;
    msgInput.value = state.adminDraftNoticeText || "";
    msgInput.placeholder = isAllCmd
      ? "Mensagem para TODOS os jogadores..."
      : "Escreva a mensagem para o UID alvo...";
    msgInput.style.cssText = "flex: 1 1 200px; padding: 7px 10px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    msgInput.addEventListener("input", () => {
      state.adminDraftNoticeText = msgInput.value;
    });

    const scopeSelect = document.createElement("select");
    scopeSelect.style.cssText = "padding: 7px 9px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #8ce0f0; font-size: 12px; font-weight: 600;";
    [
      { value: "uid", label: "UID alvo" },
      { value: "all", label: "TODOS os jogadores" }
    ].forEach((sc) => {
      const opt = document.createElement("option");
      opt.value = sc.value;
      opt.textContent = sc.label;
      if ((isAllCmd ? "all" : state.adminDraftNoticeTargetMode) === sc.value) {
        opt.selected = true;
      }
      scopeSelect.appendChild(opt);
    });
    scopeSelect.addEventListener("change", () => {
      state.adminDraftNoticeTargetMode = scopeSelect.value;
    });

    const prioSelect = document.createElement("select");
    prioSelect.style.cssText = "padding: 7px 9px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    [
      { value: "normal", label: "Normal" },
      { value: "urgent", label: "URGENTE" }
    ].forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p.value;
      opt.textContent = p.label;
      if ((isUrgentCmd ? "urgent" : state.adminDraftNoticePriority) === p.value) {
        opt.selected = true;
      }
      prioSelect.appendChild(opt);
    });
    prioSelect.addEventListener("change", () => {
      state.adminDraftNoticePriority = prioSelect.value;
    });

    const durSelect = document.createElement("select");
    durSelect.style.cssText = "padding: 7px 9px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #ffd966; font-size: 12px; font-weight: 600;";
    NOTICE_DURATION_PRESETS.forEach((opt) => {
      const optionEl = document.createElement("option");
      optionEl.value = String(opt.minutes);
      optionEl.textContent = opt.label;
      if (Number(state.adminDraftNoticeMinutes) === opt.minutes) optionEl.selected = true;
      durSelect.appendChild(optionEl);
    });
    durSelect.addEventListener("change", () => {
      state.adminDraftNoticeMinutes = normalizeNoticeMinutes(durSelect.value);
    });

    const sendBtn = document.createElement("button");
    sendBtn.type = "button";
    sendBtn.textContent = scopeSelect.value === "all" ? "Enviar para TODOS" : "Enviar recado";
    sendBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: none; background: #c48b1b; color: #111; font-weight: 700; font-size: 12px; cursor: pointer;";
    scopeSelect.addEventListener("change", () => {
      sendBtn.textContent = scopeSelect.value === "all" ? "Enviar para TODOS" : "Enviar recado";
    });
    sendBtn.addEventListener("click", () =>
      handleAdminSendNotice({
        text: msgInput.value,
        minutes: durSelect.value,
        priority: prioSelect.value,
        broadcastAll: scopeSelect.value === "all"
      })
    );

    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.textContent = "Remover recado";
    clearBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.25); background: transparent; color: #e4e4ec; font-size: 12px; cursor: pointer;";
    clearBtn.addEventListener("click", () =>
      handleAdminClearNotice({ broadcastAll: scopeSelect.value === "all" })
    );

    row.appendChild(msgInput);
    row.appendChild(scopeSelect);
    row.appendChild(prioSelect);
    row.appendChild(durSelect);
    row.appendChild(sendBtn);
    row.appendChild(clearBtn);
    box.appendChild(row);

    const preview = document.createElement("div");
    preview.style.cssText = "margin-top: 8px; font-size: 12px; color: #ffe082; display: flex; flex-direction: column; gap: 3px;";

    const uidActive =
      state.activeNotice && Date.now() < (state.activeNotice.expiresAt || 0) ? state.activeNotice : null;
    const globalActive =
      state.globalNotice && Date.now() < (state.globalNotice.expiresAt || 0) ? state.globalNotice : null;

    const uidLine = document.createElement("div");
    uidLine.textContent = uidActive
      ? `Recado no UID alvo ${uidActive.priority === "urgent" ? "[URGENTE]" : "[Normal]"} (${formatRemainingTimeLabel(uidActive.expiresAt)}): "${uidActive.msg}"`
      : "Recado no UID alvo: nenhum ativo.";

    const globalLine = document.createElement("div");
    globalLine.textContent = globalActive
      ? `Aviso GLOBAL (todos os jogadores) ${globalActive.priority === "urgent" ? "[URGENTE]" : "[Normal]"} (${formatRemainingTimeLabel(globalActive.expiresAt)}): "${globalActive.msg}"`
      : "Aviso GLOBAL (todos os jogadores): nenhum ativo.";

    preview.appendChild(uidLine);
    preview.appendChild(globalLine);
    box.appendChild(preview);
    return;
  }

  if (cmd === "/ler") {
    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";
    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.textContent = state.adminReadOnly
      ? "Somente leitura: ON (clique para liberar edição)"
      : "Somente leitura: OFF (clique para bloquear edição)";
    toggleBtn.style.cssText = "padding: 7px 12px; border-radius: 7px; border: 1px solid #ffd966; background: rgba(255,217,102,0.16); color: #ffd966; font-weight: 600; font-size: 12px; cursor: pointer;";
    toggleBtn.addEventListener("click", handleAdminToggleReadOnly);
    row.appendChild(toggleBtn);
    box.appendChild(row);
    return;
  }

  if (cmd === "/stats") {
    syncAdminQuickInputsFromSheet();
    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

    const nvInput = document.createElement("input");
    nvInput.type = "number";
    nvInput.id = "admin-fn-nv";
    nvInput.value = state.adminDraftNv;
    nvInput.min = "1";
    nvInput.max = "99";
    nvInput.style.cssText = "width: 66px; padding: 6px 8px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    nvInput.addEventListener("input", () => {
      state.adminDraftNv = nvInput.value;
    });

    const rankSelect = document.createElement("select");
    rankSelect.id = "admin-fn-rank";
    rankSelect.style.cssText = "padding: 6px 8px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    ALLOWED_RANKS.forEach((rk) => {
      const opt = document.createElement("option");
      opt.value = rk;
      opt.textContent = `Rank ${rk}`;
      if (state.adminDraftRank === rk) opt.selected = true;
      rankSelect.appendChild(opt);
    });
    rankSelect.addEventListener("change", () => {
      state.adminDraftRank = rankSelect.value;
    });

    const slotsInput = document.createElement("input");
    slotsInput.type = "number";
    slotsInput.id = "admin-fn-slots";
    slotsInput.value = state.adminDraftSlots;
    slotsInput.min = "0";
    slotsInput.max = "200";
    slotsInput.style.cssText = "width: 74px; padding: 6px 8px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    slotsInput.addEventListener("input", () => {
      state.adminDraftSlots = slotsInput.value;
    });

    const applyBtn = document.createElement("button");
    applyBtn.type = "button";
    applyBtn.textContent = "Aplicar e salvar";
    applyBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: none; background: #356899; color: #fff; font-weight: 600; font-size: 12px; cursor: pointer;";
    applyBtn.addEventListener("click", () =>
      handleAdminApplyQuickStats({
        nv: nvInput.value,
        rank: rankSelect.value,
        slots: slotsInput.value
      })
    );

    row.appendChild(nvInput);
    row.appendChild(rankSelect);
    row.appendChild(slotsInput);
    row.appendChild(applyBtn);
    box.appendChild(row);
    return;
  }

  if (cmd === "/modelo") {
    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

    const sel = document.createElement("select");
    sel.style.cssText = "flex: 1 1 200px; padding: 7px 9px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    Object.entries(SHEET_TEMPLATES).forEach(([key, tpl]) => {
      const opt = document.createElement("option");
      opt.value = key;
      opt.textContent = tpl.label;
      if (state.adminDraftTemplate === key) opt.selected = true;
      sel.appendChild(opt);
    });
    sel.addEventListener("change", () => {
      state.adminDraftTemplate = sel.value;
    });

    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Clonar modelo na ficha";
    btn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: none; background: #6b4c9a; color: #fff; font-weight: 600; font-size: 12px; cursor: pointer;";
    btn.addEventListener("click", () => handleAdminApplyTemplate(sel.value));

    row.appendChild(sel);
    row.appendChild(btn);
    box.appendChild(row);
    return;
  }

  if (cmd === "/diff") {
    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-direction: column; gap: 8px;";

    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = "Atualizar alterações pendentes";
    btn.style.cssText = "align-self: flex-start; padding: 6px 10px; border-radius: 7px; border: 1px solid rgba(255,217,102,0.45); background: transparent; color: #ffd966; font-size: 12px; cursor: pointer;";
    btn.addEventListener("click", handleAdminShowDiff);

    const out = document.createElement("div");
    out.textContent = state.adminDiffText || "Clique para verificar alterações pendentes.";
    out.style.cssText = "font-size: 12px; color: #d6dee6; white-space: pre-wrap; word-break: break-word;";

    row.appendChild(btn);
    row.appendChild(out);
    box.appendChild(row);
    return;
  }

  if (cmd === "/json") {
    const col = document.createElement("div");
    col.style.cssText = "display: flex; flex-direction: column; gap: 8px;";

    const btnRow = document.createElement("div");
    btnRow.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px;";

    const expBtn = document.createElement("button");
    expBtn.type = "button";
    expBtn.textContent = "Exportar JSON";
    expBtn.style.cssText = "padding: 6px 10px; border-radius: 7px; border: none; background: #2b8a6e; color: #fff; font-weight: 600; font-size: 12px; cursor: pointer;";

    const impBtn = document.createElement("button");
    impBtn.type = "button";
    impBtn.textContent = "Importar JSON colado";
    impBtn.style.cssText = "padding: 6px 10px; border-radius: 7px; border: none; background: #356899; color: #fff; font-weight: 600; font-size: 12px; cursor: pointer;";

    const ta = document.createElement("textarea");
    ta.rows = 3;
    ta.value = state.adminDraftJson || "";
    ta.placeholder = "JSON exportado ou colado para importar...";
    ta.style.cssText = "width: 100%; padding: 8px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.2); background: #0a0e12; color: #d6dee6; font-family: monospace; font-size: 11px;";
    ta.addEventListener("input", () => {
      state.adminDraftJson = ta.value;
    });

    expBtn.addEventListener("click", () => {
      handleAdminExportJson();
      ta.value = state.adminDraftJson;
    });
    impBtn.addEventListener("click", () => handleAdminImportJson(ta.value));

    btnRow.appendChild(expBtn);
    btnRow.appendChild(impBtn);
    col.appendChild(btnRow);
    col.appendChild(ta);
    box.appendChild(col);
    return;
  }

  if (cmd === "/log") {
    const ul = document.createElement("ul");
    ul.style.cssText = "margin: 0; padding-left: 16px; max-height: 120px; overflow-y: auto; font-size: 11px; color: #d6dee6;";
    if (!state.adminLogs.length) {
      const li = document.createElement("li");
      li.textContent = "Nenhuma ação registrada nesta sessão.";
      ul.appendChild(li);
    } else {
      state.adminLogs.forEach((entry) => {
        const li = document.createElement("li");
        li.textContent = entry;
        li.style.marginBottom = "3px";
        ul.appendChild(li);
      });
    }
    box.appendChild(ul);
    return;
  }

  const helpList = document.createElement("ul");
  helpList.style.cssText = "margin: 0; padding-left: 16px; font-size: 12px; color: #d6dee6;";
  getAvailableCommandsForCurrentUser().forEach((item) => {
    const li = document.createElement("li");
    li.textContent = `${item.syntax} — ${item.desc}`;
    li.style.marginBottom = "3px";
    helpList.appendChild(li);
  });
  box.appendChild(helpList);
}

function updateAdminBarUI() {
  const bar = document.getElementById("admin-uid-bar");

  if (!isCurrentUserAdmin()) {
    state.adminReadOnly = false;
    state.adminActiveCommand = "";
    state.adminAllCommandsActive = false;
    applySheetReadOnlyState();
    if (bar) bar.hidden = true;
    return;
  }

  ensureAdminBarElement();
  const activeBar = document.getElementById("admin-uid-bar");
  const activeBadge = document.getElementById("admin-target-status");

  if (activeBar) activeBar.hidden = false;
  if (activeBadge) {
    const modeLabel = state.adminReadOnly ? " · SOMENTE LEITURA" : " · Edição ativa";
    if (hasActiveTempAdminRole()) {
      const rem = formatRemainingTimeLabel(state.tempAdminGrant.expiresAt);
      activeBadge.textContent = `Admin Temporário (${rem}, sem add/remover admin)${modeLabel}`;
    } else if (state.adminTargetUid && state.adminTargetUid !== state.user.uid) {
      activeBadge.textContent = `Alvo: ${state.adminTargetUid}${modeLabel}`;
    } else {
      activeBadge.textContent = `Alvo: própria conta (${state.user.uid})${modeLabel}`;
    }
  }

  applySheetReadOnlyState();
  syncAdminQuickInputsFromSheet();
  renderActiveCommandsStrip();
  renderAdminCommandFunctionsBelow();
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
  bar.setAttribute("aria-label", "Prompt de Comando do Administrador");
  bar.style.cssText = [
    "margin: 10px auto 12px",
    "padding: 12px 14px",
    "max-width: 1120px",
    "border-radius: 10px",
    "border: 1px solid rgba(255, 217, 102, 0.45)",
    "background: rgba(18, 24, 32, 0.96)",
    "color: #f2f4f8",
    "display: flex",
    "flex-direction: column",
    "gap: 8px"
  ].join(";");

  const topRow = document.createElement("div");
  topRow.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between;";

  const title = document.createElement("strong");
  title.textContent = "Prompt de Comando Admin";
  title.style.cssText = "color: #ffd966; font-size: 13px;";

  const rightHeader = document.createElement("div");
  rightHeader.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

  const statusSpan = document.createElement("span");
  statusSpan.id = "admin-target-status";
  statusSpan.style.cssText = "font-size: 12px; color: #b8c2cc; word-break: break-all;";

  const allCmdsBtn = document.createElement("button");
  allCmdsBtn.type = "button";
  allCmdsBtn.id = "admin-toggle-all-cmds-btn";
  allCmdsBtn.textContent = "Ativar todos os comandos";
  allCmdsBtn.style.cssText = [
    "padding: 6px 10px",
    "border-radius: 8px",
    "border: 1px solid rgba(255,255,255,0.25)",
    "background: transparent",
    "color: #e4e4ec",
    "font-size: 12px",
    "cursor: pointer"
  ].join(";");

  rightHeader.appendChild(statusSpan);
  rightHeader.appendChild(allCmdsBtn);
  topRow.appendChild(title);
  topRow.appendChild(rightHeader);

  const promptForm = document.createElement("form");
  promptForm.id = "admin-prompt-form";
  promptForm.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

  const promptInput = document.createElement("input");
  promptInput.type = "text";
  promptInput.id = "admin-prompt-input";
  promptInput.placeholder = isMasterAdmin()
    ? "Digite um comando (ex: /todos 60 Aviso geral, /todosurgente 30 Atenção!, /recado 30 Oi, /uid, /ler, /stats)..."
    : "Digite um comando (ex: /todos 60 Aviso geral, /recado 30 Oi, /ler, /stats, /modelo, /diff, /json, /log)...";
  promptInput.autocomplete = "off";
  promptInput.spellcheck = false;
  promptInput.setAttribute("aria-label", "Prompt de comando do administrador");
  promptInput.style.cssText = [
    "flex: 1 1 220px",
    "min-width: 170px",
    "padding: 8px 10px",
    "border-radius: 8px",
    "border: 1px solid rgba(255,217,102,0.35)",
    "background: rgba(10,14,18,0.92)",
    "color: #fff",
    "font-size: 13px"
  ].join(";");

  const execBtn = document.createElement("button");
  execBtn.type = "submit";
  execBtn.textContent = "Executar";
  execBtn.style.cssText = [
    "padding: 8px 14px",
    "border-radius: 8px",
    "border: none",
    "background: #2b8a6e",
    "color: #fff",
    "font-weight: 700",
    "font-size: 13px",
    "cursor: pointer"
  ].join(";");

  promptForm.appendChild(promptInput);
  promptForm.appendChild(execBtn);

  const allCmdsBox = document.createElement("div");
  allCmdsBox.id = "admin-all-commands-box";
  allCmdsBox.hidden = true;
  allCmdsBox.style.cssText = "padding: 8px 10px; border-radius: 8px; background: rgba(10,14,18,0.72); border: 1px solid rgba(255,255,255,0.12);";

  const functionsBelowPanel = document.createElement("div");
  functionsBelowPanel.id = "admin-command-functions-panel";
  functionsBelowPanel.hidden = true;
  functionsBelowPanel.style.cssText = "padding: 10px 12px; border-radius: 8px; background: rgba(10,14,18,0.82); border: 1px solid rgba(255,217,102,0.3);";

  bar.appendChild(topRow);
  bar.appendChild(promptForm);
  bar.appendChild(allCmdsBox);
  bar.appendChild(functionsBelowPanel);

  if (mainEl && mainEl.parentNode === anchorParent) {
    anchorParent.insertBefore(bar, mainEl);
  } else {
    anchorParent.appendChild(bar);
  }

  allCmdsBtn.addEventListener("click", () => {
    state.adminAllCommandsActive = !state.adminAllCommandsActive;
    renderActiveCommandsStrip();
  });

  promptInput.addEventListener("input", () => {
    const resolved = resolveCommandNameFromInput(promptInput.value);
    state.adminActiveCommand = resolved;
    if (resolved === "/todos" || resolved === "/todosurgente") {
      state.adminDraftNoticeTargetMode = "all";
      state.adminDraftNoticePriority = resolved === "/todosurgente" ? "urgent" : "normal";
    } else if (resolved === "/recado" || resolved === "/urgente") {
      state.adminDraftNoticeTargetMode = "uid";
      state.adminDraftNoticePriority = resolved === "/urgente" ? "urgent" : "normal";
    }
    renderActiveCommandsStrip();
    renderAdminCommandFunctionsBelow();
  });

  promptForm.addEventListener("submit", handleAdminPromptSubmit);
}

async function handleAdminGrantTempRole(overrideData) {
  if (!isMasterAdmin() || !state.firebaseReady || !state.db) {
    setStatusBanner(
      "Apenas o administrador principal pode conceder função de administrador temporário.",
      "error"
    );
    return;
  }

  const targetUid = sanitizeTargetUid(
    overrideData && overrideData.uid !== undefined ? overrideData.uid : state.adminDraftTempAdminUid
  );
  if (!targetUid) {
    setStatusBanner("Informe um UID válido para conceder a função de administrador.", "warning");
    return;
  }

  if (targetUid === ADMIN_UID) {
    setStatusBanner("Este UID já é o administrador principal.", "info");
    return;
  }

  const minutes = normalizeTempAdminMinutes(
    overrideData && overrideData.minutes !== undefined
      ? overrideData.minutes
      : state.adminDraftTempAdminMinutes
  );
  const encodedGrant = buildEncodedTempAdminGrant(targetUid, minutes, state.user.uid);
  if (!encodedGrant) {
    setStatusBanner("Não foi possível gerar a concessão temporária.", "error");
    return;
  }

  const { doc, getDoc, setDoc } = state.firebaseModules.firestoreMod;
  const docRef = doc(state.db, FIRESTORE_COLLECTION, targetUid);

  try {
    const snap = await getDoc(docRef);
    const existingFields =
      snap.exists() && snap.data() && snap.data().fields && typeof snap.data().fields === "object"
        ? snap.data().fields
        : createSafeRecord();

    const nextFields = createSafeRecord();
    Object.entries(existingFields).forEach(([k, v]) => {
      if (isValidFieldKey(k)) {
        nextFields[k] = v;
      }
    });
    nextFields[TEMP_ADMIN_GRANT_FIELD_KEY] = encodedGrant;

    await setDoc(docRef, {
      fields: nextFields,
      atualizadoEm: new Date().toISOString()
    });
    state.lastCloudWriteAt = Date.now();

    state.adminDraftTempAdminUid = "";
    state.adminDraftTempAdminMinutes = minutes;
    recordRecentAdminUid(targetUid);
    appendAdminLog(`Admin temporário (${formatDurationLabel(minutes)}) dado ao UID ${targetUid}`);
    renderAdminCommandFunctionsBelow();
    await recordMasterSuccessUpdate(
      `Admin temporário de ${formatDurationLabel(minutes)} concedido ao UID ${targetUid} (sem permissão para adicionar ou remover admin)`
    );
    setStatusBanner(
      `Função de admin concedida ao UID ${targetUid} por ${formatDurationLabel(minutes)} (sem poder adicionar/remover admin).`,
      "success"
    );
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    setStatusBanner(
      code === "permission-denied"
        ? "Permissão negada no Firestore ao conceder admin temporário."
        : "Erro ao salvar admin temporário no Firestore.",
      "error"
    );
  }
}

async function handleAdminPromptSubmit(event) {
  event.preventDefault();
  if (event && event.isTrusted === false) return;
  if (!isCurrentUserAdmin()) return;

  const input = document.getElementById("admin-prompt-input");
  const raw = sanitizeText(input ? input.value : "", 700).trim();
  if (!raw) return;

  const parts = raw.split(/\s+/);
  const cmd = resolveCommandNameFromInput(parts[0]);
  state.adminActiveCommand = cmd;
  renderActiveCommandsStrip();

  if (cmd === "/admin") {
    if (!isMasterAdmin()) {
      setStatusBanner(
        "Administrador temporário não tem permissão para adicionar ou remover administradores.",
        "error"
      );
      renderAdminCommandFunctionsBelow();
      return;
    }
    if (parts[1]) {
      const uidArg = sanitizeTargetUid(parts[1]);
      const minArg = parts[2] !== undefined ? normalizeTempAdminMinutes(parts[2]) : MAX_TEMP_ADMIN_MINUTES;
      state.adminDraftTempAdminUid = parts[1];
      state.adminDraftTempAdminMinutes = minArg;
      if (uidArg) {
        await handleAdminGrantTempRole({ uid: uidArg, minutes: minArg });
      }
    }
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (cmd === "/uid" && parts[1]) {
    state.adminDraftUid = parts[1];
    await handleAdminLoadTargetUid(parts[1]);
    return;
  }

  if (cmd === "/minha") {
    await handleAdminReturnToOwnSheet();
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (cmd === "/ler") {
    const arg = (parts[1] || "").toLowerCase();
    if (arg === "on" && !state.adminReadOnly) handleAdminToggleReadOnly();
    else if (arg === "off" && state.adminReadOnly) handleAdminToggleReadOnly();
    else if (!arg) handleAdminToggleReadOnly();
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (
    (cmd === "/recado" || cmd === "/urgente" || cmd === "/todos" || cmd === "/todosurgente") &&
    parts.length >= 3
  ) {
    const minutes = normalizeNoticeMinutes(parts[1]);
    const text = parts.slice(2).join(" ");
    const broadcastAll = cmd === "/todos" || cmd === "/todosurgente";
    const priority = cmd === "/urgente" || cmd === "/todosurgente" ? "urgent" : state.adminDraftNoticePriority;
    state.adminDraftNoticeText = text;
    state.adminDraftNoticeMinutes = minutes;
    state.adminDraftNoticePriority = priority;
    state.adminDraftNoticeTargetMode = broadcastAll ? "all" : "uid";
    await handleAdminSendNotice({ text, minutes, priority, broadcastAll });
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (cmd === "/remover") {
    await handleAdminClearNotice({ broadcastAll: state.adminDraftNoticeTargetMode === "all" });
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (cmd === "/modelo" && parts[1]) {
    state.adminDraftTemplate = parts[1].toLowerCase();
    await handleAdminApplyTemplate(parts[1].toLowerCase());
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (cmd === "/diff") {
    handleAdminShowDiff();
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (cmd === "/json") {
    if ((parts[1] || "").toLowerCase() === "exportar") {
      handleAdminExportJson();
    }
    renderAdminCommandFunctionsBelow();
    return;
  }

  renderAdminCommandFunctionsBelow();
}

function handleAdminShowDiff() {
  const changes = computeSheetDiffList();
  state.adminDiffText = changes.length
    ? `Alterações detectadas (${changes.length}):\n• ${changes.slice(0, 25).join("\n• ")}`
    : "Nenhuma alteração pendente em relação à ficha carregada.";
  renderAdminCommandFunctionsBelow();
}

function handleAdminExportJson() {
  if (!isCurrentUserAdmin()) return;
  const payload = buildSanitizedCloudPayload();
  const exportObj = {
    alvoUid: getActiveTargetUid(),
    exportadoEm: new Date().toISOString(),
    fields: payload.fields
  };
  const serialized = JSON.stringify(exportObj, null, 2);
  state.adminDraftJson = serialized;

  try {
    const blob = new Blob([serialized], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ficha_arkan_${getActiveTargetUid() || "backup"}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch {
    // Fallback: JSON exibido na caixa abaixo do comando
  }

  appendAdminLog(`JSON exportado do UID ${getActiveTargetUid()}`);
  setStatusBanner("Backup JSON gerado com sucesso.", "success");
}

async function handleAdminImportJson(rawJsonText) {
  if (!isCurrentUserAdmin()) return;
  if (isInspectionReadOnlyActive()) {
    setStatusBanner("Desative 'Somente leitura' antes de importar um JSON.", "warning");
    return;
  }

  const raw = String(rawJsonText ?? state.adminDraftJson ?? "").trim();
  if (!raw || raw.length > 500000) {
    setStatusBanner("Cole um JSON válido antes de importar.", "warning");
    return;
  }

  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !parsed.fields || typeof parsed.fields !== "object") {
      setStatusBanner("Formato JSON inválido: objeto 'fields' ausente.", "error");
      return;
    }

    const safeFields = createSafeRecord();
    Object.entries(parsed.fields).slice(0, 1500).forEach(([k, v]) => {
      if (!isValidFieldKey(k)) return;
      if (k === TEMP_ADMIN_GRANT_FIELD_KEY && !isMasterAdmin()) return;
      if (k === MASTER_UPDATE_LOG_FIELD_KEY && !isMasterAdmin()) return;
      if (typeof v === "boolean") safeFields[k] = v;
      else if (typeof v === "string" || typeof v === "number") safeFields[k] = String(v).slice(0, 5000);
    });

    applySheetData({ fields: safeFields }, getActiveTargetUid());
    appendAdminLog(`JSON importado para UID ${getActiveTargetUid()}`);
    await persistSheet(true, `Importação de JSON aplicada no UID ${getActiveTargetUid()}`);
  } catch {
    setStatusBanner("Erro ao ler o JSON colado. Verifique a sintaxe.", "error");
  }
}

async function handleAdminApplyTemplate(templateKey) {
  if (!isCurrentUserAdmin()) return;
  if (isInspectionReadOnlyActive()) {
    setStatusBanner("Desative 'Somente leitura' antes de aplicar um modelo.", "warning");
    return;
  }

  const tpl = Object.prototype.hasOwnProperty.call(SHEET_TEMPLATES, templateKey)
    ? SHEET_TEMPLATES[templateKey]
    : null;
  if (!tpl) {
    setStatusBanner("Modelo inválido. Use: iniciante, veterano ou elite.", "warning");
    return;
  }

  const currentData = collectSheetData();
  const mergedFields = createSafeRecord();
  Object.entries(currentData.fields).forEach(([k, v]) => {
    if (isValidFieldKey(k)) mergedFields[k] = v;
  });
  Object.entries(tpl.fields).forEach(([k, v]) => {
    if (isValidFieldKey(k)) mergedFields[k] = v;
  });

  applySheetData({ fields: mergedFields }, getActiveTargetUid());
  appendAdminLog(`Modelo "${tpl.label}" aplicado ao UID ${getActiveTargetUid()}`);
  await persistSheet(true, `Modelo base "${tpl.label}" aplicado no UID ${getActiveTargetUid()}`);
}

function handleAdminToggleReadOnly(event) {
  if (event && event.isTrusted === false) return;
  if (!isCurrentUserAdmin()) return;

  state.adminReadOnly = !state.adminReadOnly;
  if (state.adminReadOnly && state.saveTimer) {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
  }
  updateAdminBarUI();
  appendAdminLog(`Somente leitura alterado para ${state.adminReadOnly ? "ON" : "OFF"}`);
  setStatusBanner(
    state.adminReadOnly
      ? "Modo somente leitura ativado: edição e auto-salvamento pausados."
      : "Modo somente leitura desativado: edição liberada.",
    "info"
  );
}

async function handleAdminApplyQuickStats(overrideValues) {
  if (!isCurrentUserAdmin()) return;

  const nvVal = overrideValues && overrideValues.nv !== undefined ? overrideValues.nv : state.adminDraftNv;
  const rankVal = overrideValues && overrideValues.rank !== undefined ? overrideValues.rank : state.adminDraftRank;
  const slotsVal = overrideValues && overrideValues.slots !== undefined ? overrideValues.slots : state.adminDraftSlots;

  const sheetNv = document.getElementById("nv-val");
  const sheetRank = document.getElementById("rank-val");
  const sheetSlots = document.getElementById("espacos-max");

  if (sheetNv) sheetNv.value = normalizeNumericValue("nv-val", nvVal);
  if (sheetRank) sheetRank.value = normalizeRankValue(rankVal);
  if (sheetSlots) sheetSlots.value = normalizeNumericValue("espacos-max", slotsVal);

  recalculateSkillsTable();
  appendAdminLog(`Ajuste rápido salvo no UID ${getActiveTargetUid()}`);
  await persistSheet(
    true,
    `Ajuste rápido de Nível/Rank/Espaços salvo no UID ${getActiveTargetUid()}`
  );
}

async function handleAdminLoadTargetUid(rawUidOverride) {
  if (!isMasterAdmin()) {
    setStatusBanner("Apenas o administrador principal pode carregar fichas de outros UIDs.", "error");
    return;
  }

  const uid = sanitizeTargetUid(rawUidOverride !== undefined ? rawUidOverride : state.adminDraftUid);
  if (!uid) {
    setStatusBanner("Informe um UID válido para carregar a ficha do jogador.", "warning");
    return;
  }

  state.adminDraftUid = uid;
  state.adminTargetUid = uid;
  saveAdminTargetUidToStorage(uid);
  recordRecentAdminUid(uid);
  state.lastSavedSnapshot = "";
  updateAdminBarUI();
  appendAdminLog(`Ficha carregada do UID ${uid}`);
  setStatusBanner(`Carregando ficha do UID ${uid}...`, "info");
  await loadFromFirestore(uid);
}

async function handleAdminReturnToOwnSheet(event) {
  if (event && event.isTrusted === false) return;
  if (!state.user || !state.user.uid) return;

  state.adminTargetUid = "";
  state.adminDraftUid = "";
  saveAdminTargetUidToStorage("");
  state.lastSavedSnapshot = "";
  updateAdminBarUI();
  appendAdminLog("Retornou para a própria ficha");
  setStatusBanner("Voltando para a sua própria ficha...", "info");
  await loadFromFirestore(state.user.uid);
}

async function handleAdminSendNotice(overrideData) {
  if (!isCurrentUserAdmin() || !state.firebaseReady || !state.db) {
    setStatusBanner("Apenas um admin conectado ao Firebase pode enviar recados.", "error");
    return;
  }

  const broadcastAll = Boolean(
    overrideData && overrideData.broadcastAll !== undefined
      ? overrideData.broadcastAll
      : state.adminDraftNoticeTargetMode === "all"
  );

  const rawText = overrideData && overrideData.text !== undefined ? overrideData.text : state.adminDraftNoticeText;
  const rawMin = overrideData && overrideData.minutes !== undefined ? overrideData.minutes : state.adminDraftNoticeMinutes;
  const rawPrio = overrideData && overrideData.priority !== undefined ? overrideData.priority : state.adminDraftNoticePriority;

  const minutes = normalizeNoticeMinutes(rawMin);
  const priority = normalizeNoticePriority(rawPrio);
  const encodedPayload = buildEncodedNoticePayload(
    rawText,
    minutes,
    priority,
    broadcastAll ? "all" : "uid"
  );
  if (!encodedPayload) {
    setStatusBanner("Escreva uma mensagem antes de enviar.", "warning");
    return;
  }

  const { doc, getDoc, setDoc } = state.firebaseModules.firestoreMod;

  if (broadcastAll) {
    const globalRef = doc(state.db, FIRESTORE_COLLECTION, GLOBAL_BROADCAST_DOC_ID);
    try {
      const globalFields = createSafeRecord();
      globalFields[ADMIN_NOTICE_FIELD_KEY] = encodedPayload;

      await setDoc(globalRef, {
        fields: globalFields,
        atualizadoEm: new Date().toISOString()
      });
      state.lastCloudWriteAt = Date.now();
      state.adminDraftNoticeText = "";
      state.globalNotice = parseNoticeObject(encodedPayload, "all");
      scheduleNoticeExpiryCheck();
      renderPlayerNoticeBanner();
      renderAdminCommandFunctionsBelow();

      appendAdminLog(
        `Aviso GLOBAL (${priority === "urgent" ? "Urgente" : "Normal"}, ${formatDurationLabel(minutes)}) enviado para TODOS os jogadores`
      );
      await recordMasterSuccessUpdate(
        `Aviso GLOBAL (${priority === "urgent" ? "Urgente" : "Normal"}, ${formatDurationLabel(minutes)}) enviado para todos os jogadores`
      );
      setStatusBanner(
        `Mensagem enviada para TODOS os jogadores (duração: ${formatDurationLabel(minutes)}).`,
        "success"
      );
    } catch (err) {
      const code = err && typeof err.code === "string" ? err.code : "";
      setStatusBanner(
        code === "permission-denied"
          ? "Permissão negada no Firestore ao enviar aviso global."
          : "Erro ao enviar mensagem global para o Firestore.",
        "error"
      );
    }
    return;
  }

  const targetUid = sanitizeTargetUid(
    isMasterAdmin()
      ? state.adminTargetUid || state.adminDraftUid || state.user.uid
      : state.user.uid
  );
  if (!targetUid) {
    setStatusBanner("Carregue ou informe um UID válido para enviar a mensagem.", "warning");
    return;
  }

  if (isMasterAdmin()) {
    state.adminTargetUid = targetUid;
    saveAdminTargetUidToStorage(targetUid);
    recordRecentAdminUid(targetUid);
  }

  const docRef = doc(state.db, FIRESTORE_COLLECTION, targetUid);

  try {
    const snap = await getDoc(docRef);
    const existingFields =
      snap.exists() && snap.data() && snap.data().fields && typeof snap.data().fields === "object"
        ? snap.data().fields
        : createSafeRecord();

    const nextFields = createSafeRecord();
    Object.entries(existingFields).forEach(([k, v]) => {
      if (isValidFieldKey(k)) {
        nextFields[k] = v;
      }
    });
    nextFields[ADMIN_NOTICE_FIELD_KEY] = encodedPayload;

    await setDoc(docRef, {
      fields: nextFields,
      atualizadoEm: new Date().toISOString()
    });
    state.lastCloudWriteAt = Date.now();

    state.adminDraftNoticeText = "";
    if (getActiveTargetUid() === targetUid) {
      state.activeNotice = parseActiveNoticeFromFields(nextFields);
      scheduleNoticeExpiryCheck();
      renderPlayerNoticeBanner();
    }

    renderAdminCommandFunctionsBelow();
    appendAdminLog(`Recado (${priority === "urgent" ? "Urgente" : "Normal"}, ${formatDurationLabel(minutes)}) enviado para ${targetUid}`);
    await recordMasterSuccessUpdate(
      `Recado (${priority === "urgent" ? "Urgente" : "Normal"}, ${formatDurationLabel(minutes)}) enviado para o UID ${targetUid}`
    );
    setStatusBanner(
      `Mensagem enviada para o UID ${targetUid} (duração: ${formatDurationLabel(minutes)}).`,
      "success"
    );
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    setStatusBanner(
      code === "permission-denied"
        ? "Permissão negada no Firestore ao enviar o recado."
        : "Erro ao enviar mensagem para o Firestore.",
      "error"
    );
  }
}

async function handleAdminClearNotice(overrideData) {
  if (overrideData && overrideData.isTrusted === false) return;
  if (!isCurrentUserAdmin() || !state.firebaseReady || !state.db) return;

  const broadcastAll = Boolean(
    overrideData && overrideData.broadcastAll !== undefined
      ? overrideData.broadcastAll
      : state.adminDraftNoticeTargetMode === "all"
  );

  const { doc, getDoc, setDoc, deleteDoc } = state.firebaseModules.firestoreMod;

  if (broadcastAll) {
    try {
      await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, GLOBAL_BROADCAST_DOC_ID));
      state.lastCloudWriteAt = Date.now();
      state.globalNotice = null;
      scheduleNoticeExpiryCheck();
      renderPlayerNoticeBanner();
      renderAdminCommandFunctionsBelow();
      appendAdminLog("Aviso GLOBAL removido para todos os jogadores");
      await recordMasterSuccessUpdate("Aviso GLOBAL removido para todos os jogadores");
      setStatusBanner("Aviso global removido para todos os jogadores.", "success");
    } catch {
      setStatusBanner("Erro ao remover o aviso global no Firestore.", "error");
    }
    return;
  }

  const targetUid = sanitizeTargetUid(
    isMasterAdmin()
      ? state.adminTargetUid || state.adminDraftUid || state.user.uid
      : state.user.uid
  );
  if (!targetUid) {
    setStatusBanner("Informe um UID válido para remover o recado.", "warning");
    return;
  }

  const docRef = doc(state.db, FIRESTORE_COLLECTION, targetUid);

  try {
    const snap = await getDoc(docRef);
    if (!snap.exists()) {
      setStatusBanner("Nenhuma ficha encontrada para esse UID.", "info");
      return;
    }

    const existingFields =
      snap.exists() && snap.data() && snap.data().fields && typeof snap.data().fields === "object"
        ? snap.data().fields
        : createSafeRecord();

    const nextFields = createSafeRecord();
    Object.entries(existingFields).forEach(([k, v]) => {
      if (isValidFieldKey(k) && k !== ADMIN_NOTICE_FIELD_KEY) {
        nextFields[k] = v;
      }
    });

    await setDoc(docRef, {
      fields: nextFields,
      atualizadoEm: new Date().toISOString()
    });
    state.lastCloudWriteAt = Date.now();

    if (getActiveTargetUid() === targetUid) {
      state.activeNotice = null;
      scheduleNoticeExpiryCheck();
      renderPlayerNoticeBanner();
    }

    renderAdminCommandFunctionsBelow();
    appendAdminLog(`Recado removido do UID ${targetUid}`);
    await recordMasterSuccessUpdate(`Recado removido do UID ${targetUid}`);
    setStatusBanner(`Recado removido do UID ${targetUid}.`, "success");
  } catch {
    setStatusBanner("Erro ao remover o recado no Firestore.", "error");
  }
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
  renderMasterCodeReleaseBanner();
  renderMasterUpdateBanner();
  renderPlayerNoticeBanner();

  if (hasSession) {
    syncNenCategoryFromSelect();
    recalculateSkillsTable();
    window.requestAnimationFrame(() => {
      syncActiveSectionOnScroll();
    });
  } else {
    initTitulo3DDigitando(false);
  }
}

function enterOfflineTemporaryMode() {
  state.offlineMode = true;
  state.activeNotice = null;
  state.globalNotice = null;
  state.tempAdminGrant = null;
  state.masterUpdateNotice = null;
  state.masterReleaseNotice = null;
  scheduleTempAdminExpiryCheck();
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

  if (state.activeNotice && Date.now() < (state.activeNotice.expiresAt || 0)) {
    const remainingMinutes = Math.max(
      1,
      Math.min(MAX_NOTICE_MINUTES, Math.ceil((state.activeNotice.expiresAt - Date.now()) / 60000))
    );
    const reEncoded = buildEncodedNoticePayload(
      state.activeNotice.msg,
      remainingMinutes,
      state.activeNotice.priority,
      "uid"
    );
    if (reEncoded) {
      fields[ADMIN_NOTICE_FIELD_KEY] = reEncoded;
    }
  }

  if (state.tempAdminGrant && Date.now() < (state.tempAdminGrant.expiresAt || 0)) {
    const remainingMin = Math.max(
      1,
      Math.min(MAX_TEMP_ADMIN_MINUTES, Math.ceil((state.tempAdminGrant.expiresAt - Date.now()) / 60000))
    );
    fields[TEMP_ADMIN_GRANT_FIELD_KEY] = JSON.stringify({
      uid: state.tempAdminGrant.uid,
      grantedBy: ADMIN_UID,
      minutes: remainingMin,
      grantedAt: state.tempAdminGrant.grantedAt,
      expiresAt: state.tempAdminGrant.expiresAt
    });
  }

  if (state.masterUpdateNotice && state.masterUpdateNotice.ok) {
    fields[MASTER_UPDATE_LOG_FIELD_KEY] = JSON.stringify(state.masterUpdateNotice);
  }

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

      if (key === ADMIN_NOTICE_FIELD_KEY && typeof val === "string") {
        const parsedNotice = parseActiveNoticeFromFields({ [ADMIN_NOTICE_FIELD_KEY]: val });
        if (parsedNotice) {
          cleanFields[key] = JSON.stringify({
            msg: parsedNotice.msg,
            minutes: parsedNotice.minutes,
            hours: Number((parsedNotice.minutes / 60).toFixed(2)),
            priority: parsedNotice.priority,
            scope: "uid",
            sentAt: Date.now(),
            expiresAt: parsedNotice.expiresAt
          });
        }
        continue;
      }

      if (key === TEMP_ADMIN_GRANT_FIELD_KEY && typeof val === "string") {
        const parsedGrant = parseTempAdminGrantFromFields({ [TEMP_ADMIN_GRANT_FIELD_KEY]: val });
        if (parsedGrant) {
          cleanFields[key] = JSON.stringify(parsedGrant);
        }
        continue;
      }

      if (key === MASTER_UPDATE_LOG_FIELD_KEY && typeof val === "string") {
        const parsedLog = parseMasterUpdateLogFromFields({ [MASTER_UPDATE_LOG_FIELD_KEY]: val });
        if (parsedLog) {
          cleanFields[key] = JSON.stringify(parsedLog);
        }
        continue;
      }

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

function applySheetData(data, expectedUidForGrant = "") {
  if (!data || typeof data !== "object" || !data.fields || typeof data.fields !== "object") {
    state.activeNotice = null;
    state.tempAdminGrant = null;
    state.masterUpdateNotice = null;
    scheduleNoticeExpiryCheck();
    scheduleTempAdminExpiryCheck();
    renderMasterUpdateBanner();
    renderPlayerNoticeBanner();
    recalculateSkillsTable();
    syncNenCategoryFromSelect();
    syncAdminQuickInputsFromSheet();
    captureBaselineFields(collectSheetData().fields);
    updateAdminBarUI();
    return;
  }

  state.activeNotice = parseActiveNoticeFromFields(data.fields);
  scheduleNoticeExpiryCheck();
  renderPlayerNoticeBanner();

  if (expectedUidForGrant === ADMIN_UID) {
    state.tempAdminGrant = null;
    scheduleTempAdminExpiryCheck();
    state.masterUpdateNotice = parseMasterUpdateLogFromFields(data.fields);
    renderMasterUpdateBanner();
  } else if (expectedUidForGrant) {
    state.tempAdminGrant = parseTempAdminGrantFromFields(data.fields, expectedUidForGrant);
    scheduleTempAdminExpiryCheck();
    state.masterUpdateNotice = null;
    renderMasterUpdateBanner();
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
  const normalizedFields = collectSheetData().fields;
  captureBaselineFields(normalizedFields);
  state.lastSavedSnapshot = computeFieldsSnapshot(normalizedFields);
  syncNenCategoryFromSelect();
  syncAdminQuickInputsFromSheet();
  updateAdminBarUI();
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
  captureBaselineFields(collectSheetData().fields);
  syncNenCategoryFromSelect();
  syncAdminQuickInputsFromSheet();
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
          state.tempAdminGrant = null;
          scheduleTempAdminExpiryCheck();
          state.adminTargetUid = loadAdminTargetUidFromStorage();
          state.adminDraftUid = state.adminTargetUid;
          state.adminRecentUids = loadRecentAdminUidsFromStorage();
          if (state.adminTargetUid) recordRecentAdminUid(state.adminTargetUid);
        } else {
          state.masterUpdateNotice = null;
          state.masterReleaseNotice = null;
          state.adminTargetUid = "";
          state.adminDraftUid = "";
          state.adminRecentUids = [];
          state.adminReadOnly = false;
          state.adminActiveCommand = "";
          state.adminAllCommandsActive = false;
          saveAdminTargetUidToStorage("");
        }
        clearAuthSensitiveInputs();
        setEntradaStatus("");
      } else {
        state.masterUpdateNotice = null;
        state.masterReleaseNotice = null;
        state.adminTargetUid = "";
        state.adminDraftUid = "";
        state.adminRecentUids = [];
        state.adminReadOnly = false;
        state.adminActiveCommand = "";
        state.adminAllCommandsActive = false;
        state.activeNotice = null;
        state.globalNotice = null;
        state.tempAdminGrant = null;
        scheduleNoticeExpiryCheck();
        scheduleTempAdminExpiryCheck();
        saveAdminTargetUidToStorage("");
      }
      updateAuthUI();
      updateScreenAccess();

      if (user) {
        await loadGlobalBroadcastNotice();
        if (user.uid === ADMIN_UID) {
          await checkMasterCodeReleaseNotice();
        }
        if (!state.isDeleting) {
          const targetUid = getActiveTargetUid();
          const isRemoteTarget = isMasterAdmin() && targetUid && targetUid !== user.uid;
          setStatusBanner(
            isRemoteTarget
              ? `Admin conectado. Carregando ficha do UID ${targetUid}...`
              : `Conectado como ${sanitizeSingleLine(user.email || "agente", 160)}. Carregando ficha...`,
            "info"
          );
          await loadFromFirestore(targetUid || user.uid);
          if (isMasterAdmin() && targetUid !== ADMIN_UID) {
            try {
              const masterSnap = await firestoreMod.getDoc(
                firestoreMod.doc(state.db, FIRESTORE_COLLECTION, ADMIN_UID)
              );
              if (masterSnap.exists()) {
                state.masterUpdateNotice = parseMasterUpdateLogFromFields(
                  masterSnap.data()?.fields
                );
                renderMasterUpdateBanner();
              }
            } catch {
              // Ignora falha ao buscar log master
            }
          }
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
      applySheetData(cloudData, uid);
      if (!isMasterAdmin() || uid === state.user?.uid) {
        saveLocalData(cloudData);
      }
      setStatusBanner(
        isMasterAdmin() && uid !== state.user?.uid
          ? `Ficha carregada do UID alvo (${uid}).`
          : hasActiveTempAdminRole()
            ? "Ficha carregada (Admin Temporário ativo, sem poder adicionar/remover admin)."
            : "Ficha carregada do banco de dados Firebase.",
        "success"
      );
    } else {
      state.activeNotice = null;
      state.tempAdminGrant = null;
      if (uid === ADMIN_UID) state.masterUpdateNotice = null;
      scheduleNoticeExpiryCheck();
      scheduleTempAdminExpiryCheck();
      renderMasterUpdateBanner();
      renderPlayerNoticeBanner();
      resetSheetFieldsToDefault();
      const initialData = buildSanitizedCloudPayload();
      await setDoc(docRef, initialData);
      captureBaselineFields(initialData.fields);
      state.lastSavedSnapshot = computeFieldsSnapshot(initialData.fields);
      state.lastCloudWriteAt = Date.now();
      if (!isMasterAdmin() || uid === state.user?.uid) {
        saveLocalData(initialData);
      }
      updateAdminBarUI();
      setStatusBanner(
        isMasterAdmin() && uid !== state.user?.uid
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
  if (isInspectionReadOnlyActive()) {
    setStatusBanner("Desative 'Somente leitura' para limpar ou excluir fichas.", "warning");
    return;
  }

  if (state.saveTimer) {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
  }

  const targetUid = getActiveTargetUid();
  const isRemoteTarget = Boolean(isMasterAdmin() && targetUid && targetUid !== state.user?.uid);

  state.activeNotice = null;
  scheduleNoticeExpiryCheck();
  renderPlayerNoticeBanner();
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
      appendAdminLog(`Ficha excluída da nuvem para UID ${targetUid}`);
      await recordMasterSuccessUpdate(`Ficha removida da nuvem para o UID ${targetUid}`);
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
  state.adminDraftUid = "";
  state.adminRecentUids = [];
  state.adminReadOnly = false;
  state.adminActiveCommand = "";
  state.adminAllCommandsActive = false;
  state.activeNotice = null;
  state.globalNotice = null;
  state.tempAdminGrant = null;
  state.masterUpdateNotice = null;
  state.masterReleaseNotice = null;
  scheduleNoticeExpiryCheck();
  scheduleTempAdminExpiryCheck();
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
  initTitulo3DDigitando(true);
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
    state.adminDraftUid = "";
    state.adminRecentUids = [];
    state.adminReadOnly = false;
    state.adminActiveCommand = "";
    state.adminAllCommandsActive = false;
    state.activeNotice = null;
    state.globalNotice = null;
    state.tempAdminGrant = null;
    state.masterUpdateNotice = null;
    state.masterReleaseNotice = null;
    scheduleNoticeExpiryCheck();
    scheduleTempAdminExpiryCheck();
    saveAdminTargetUidToStorage("");
    state.lastSavedSnapshot = "";

    const confirmBox = document.getElementById("auth-delete-confirm-box");
    if (confirmBox) confirmBox.hidden = true;

    updateAuthUI();
    updateScreenAccess();
    initTitulo3DDigitando(true);
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
   Salvamento da Ficha (com proteção contra gravação redundante, inspeção e spam)
   -------------------------------------------------------------------------- */
async function persistSheet(forceWrite = false, masterSummaryLabel = "") {
  if (state.isSaving || state.isDeleting) return;
  if (!forceWrite && isInspectionReadOnlyActive()) {
    return;
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
      return;
    }

    if (!forceWrite && currentSnapshot === state.lastSavedSnapshot) {
      return;
    }

    const targetUid = getActiveTargetUid();
    const isRemoteTarget = Boolean(isMasterAdmin() && targetUid && targetUid !== state.user?.uid);

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
      captureBaselineFields(cloudPayload.fields);
      state.lastSavedSnapshot = computeFieldsSnapshot(cloudPayload.fields);
      syncAdminQuickInputsFromSheet();

      if (isMasterAdmin() && masterSummaryLabel) {
        await recordMasterSuccessUpdate(masterSummaryLabel);
      }

      setStatusBanner(
        isRemoteTarget
          ? `Ficha salva no Firestore para o UID ${targetUid}.`
          : "Ficha salva no banco de dados Firebase.",
        "success"
      );
    } else if (hasCookieConsent()) {
      captureBaselineFields(payload.fields);
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
  if (isInspectionReadOnlyActive()) return;
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
  renderMasterCodeReleaseBanner();
  renderMasterUpdateBanner();
  renderPlayerNoticeBanner();
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
      initTitulo3DDigitando(true);
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
    mainEl.addEventListener("input", (event) => {
      const target = event.target;
      if (!target || target.closest("#login-firebase")) return;
      if (isInspectionReadOnlyActive()) {
        event.preventDefault();
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

      if (target.id === "nv-val" || target.id === "rank-val" || target.id === "espacos-max") {
        syncAdminQuickInputsFromSheet();
        if (state.adminActiveCommand === "/stats") {
          renderAdminCommandFunctionsBelow();
        }
      }

      scheduleAutoSave();
    });

    mainEl.addEventListener("change", (event) => {
      const target = event.target;
      if (!target || target.closest("#login-firebase")) return;
      if (isInspectionReadOnlyActive()) {
        event.preventDefault();
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

      if (target.id === "nv-val" || target.id === "rank-val" || target.id === "espacos-max") {
        syncAdminQuickInputsFromSheet();
        if (state.adminActiveCommand === "/stats") {
          renderAdminCommandFunctionsBelow();
        }
      }

      scheduleAutoSave();
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initConsoleSecurityGuard();
  hardenExternalLinks();
  initLgpdBanner();
  bindEvents();
  setActiveSectionIndicator("dados-agente");

  const localData = loadLocalData();
  if (localData) {
    applySheetData(localData);
  } else {
    recalculateSkillsTable();
    syncNenCategoryFromSelect();
    captureBaselineFields(collectSheetData().fields);
  }

  updateAuthUI();
  updateScreenAccess();
  initFirebase();
});
