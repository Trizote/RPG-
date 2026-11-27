/* ==========================================================================
   Ordem de Arkan - Ficha de Agente (script.js)
   Segurança front-end (XSS, Prototype Pollution, validação de faixa/tipo,
   anti-spam de escrita, higiene de sessão, isTrusted guard e console guard)
   + Firebase Authentication & Cloud Firestore + Sessão Offline/Local temporária
   + Múltiplas Fichas por Conta (slots na mesma conta do Firebase)
   + Hexágono Visual Interativo de Nen (100%, 80%, 60%, 40%)
   + Catálogo de Habilidades (Hatsu) e Princípios com gasto automático de PE
   + Cálculo Automático de Status (Vida, PE, Sanidade, Defesa) com edição manual
   + Alerta de Sobrecarga e redutor automático (-5) nas perícias com (*)
   + Exportar e Importar JSON / Impressão PDF para jogadores e modo offline
   + Loja e Banco da Guilda (Gastar Moedas e catálogo rápido de itens)
   + Modo Administrador por UID (exclusivo)
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
  ADMIN_RECENT_UIDS: "ordem_de_arkan_admin_recent_uids_v1"
});

const ADMIN_UID = "TcudbnuOMcTySJWhz0JHaNDuNU22";
const UID_REGEX = /^[a-zA-Z0-9_-]{10,128}$/;
const ADMIN_NOTICE_FIELD_KEY = "id:admin_recado_payload";
const MULTI_SLOTS_FIELD_KEY = "id:multi_fichas_registry";
const MAX_ACCOUNT_SLOTS = 8;
const MAX_NOTICE_HOURS = 24;
const MAX_NOTICE_MINUTES = MAX_NOTICE_HOURS * 60;
const MAX_RECENT_UIDS = 6;
const MAX_ADMIN_LOGS = 25;
const OVERLOAD_SKILL_PENALTY = -5;

const NEN_RING_ORDER = Object.freeze([
  "reforco",
  "emissao",
  "manipulacao",
  "especializacao",
  "materializacao",
  "transformacao"
]);

const NEN_LABELS = Object.freeze({
  reforco: "Reforço",
  emissao: "Emissão",
  manipulacao: "Manipulação",
  especializacao: "Especialização",
  materializacao: "Materialização",
  transformacao: "Transformação"
});

const GUILD_SHOP_CATALOG = Object.freeze([
  { id: "kit-medico", name: "Kit Médico de Campo", category: 1, space: 1, price: 25, desc: "Suprimentos para Medicina" },
  { id: "kit-pericia", name: "Kit de Perícia Tático", category: 1, space: 1, price: 30, desc: "Ferramentas para testes com #" },
  { id: "corda-gancho", name: "Corda Tática e Gancho", category: 0, space: 1, price: 15, desc: "Auxílio em escalada e Atletismo" },
  { id: "comunicador", name: "Comunicador Criptografado", category: 1, space: 0, price: 40, desc: "Rádio de curto/médio alcance" },
  { id: "estimulante", name: "Tônico Revitalizante", category: 2, space: 1, price: 60, desc: "Recuperação emergencial de vigor" }
]);

const ADMIN_COMMAND_CATALOG = Object.freeze([
  { cmd: "/uid", syntax: "/uid <UID>", desc: "Carregar ou trocar UID alvo" },
  { cmd: "/minha", syntax: "/minha", desc: "Voltar para a própria ficha" },
  { cmd: "/recado", syntax: "/recado <min> <texto>", desc: "Enviar recado normal (até 24h)" },
  { cmd: "/urgente", syntax: "/urgente <min> <texto>", desc: "Enviar recado urgente (até 24h)" },
  { cmd: "/remover", syntax: "/remover", desc: "Remover recado ativo do UID" },
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
  isSaving: false,
  isDeleting: false,
  lastSavedSnapshot: "",
  baselineFields: createSafeRecord(),
  lastCloudWriteAt: 0,
  adminTargetUid: "",
  adminRecentUids: [],
  adminReadOnly: false,
  adminLogs: [],
  adminActiveCommand: "",
  adminAllCommandsActive: false,
  adminDraftUid: "",
  adminDraftNoticeText: "",
  adminDraftNoticeMinutes: MAX_NOTICE_MINUTES,
  adminDraftNoticePriority: "normal",
  adminDraftNv: "1",
  adminDraftRank: "E",
  adminDraftSlots: "5",
  adminDraftTemplate: "iniciante",
  adminDraftJson: "",
  adminDiffText: "",
  activeNotice: null,
  noticeExpiryTimer: null,
  nenAbilities: [],
  accountSlots: {
    activeSlotId: "slot-1",
    slots: {
      "slot-1": { name: "Agente Principal", fields: createSafeRecord() }
    }
  }
};

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
  if (ctrl.id === "habilidades-nen-json") {
    return sanitizeText(String(rawValue ?? "[]"), 15000);
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
   Mecânicas de Nen Interativas: Hexágono Visual + Catálogo de Habilidades
   -------------------------------------------------------------------------- */
function computeNenEfficiencyMap(mainCategoryKey) {
  const result = createSafeRecord();
  if (!mainCategoryKey || !NEN_RING_ORDER.includes(mainCategoryKey)) {
    NEN_RING_ORDER.forEach((cat) => {
      result[cat] = "—";
    });
    return result;
  }

  const mainIdx = NEN_RING_ORDER.indexOf(mainCategoryKey);
  NEN_RING_ORDER.forEach((cat, idx) => {
    const rawDiff = Math.abs(mainIdx - idx);
    const ringDistance = Math.min(rawDiff, NEN_RING_ORDER.length - rawDiff);

    if (mainCategoryKey === "especializacao") {
      if (ringDistance === 0) result[cat] = "100%";
      else if (ringDistance === 1) result[cat] = "80%";
      else if (ringDistance === 2) result[cat] = "60%";
      else result[cat] = "40%";
      return;
    }

    if (cat === "especializacao") {
      result[cat] = "0% / Esp.";
      return;
    }

    if (ringDistance === 0) result[cat] = "100%";
    else if (ringDistance === 1) result[cat] = "80%";
    else if (ringDistance === 2) result[cat] = "60%";
    else result[cat] = "40%";
  });

  return result;
}

function updateNenHexagonDiagram(categoryKey) {
  const effMap = computeNenEfficiencyMap(categoryKey);
  const legendaEl = document.getElementById("nen-hex-legenda");

  NEN_RING_ORDER.forEach((cat) => {
    const pctEl = document.getElementById(`hex-pct-${cat}`);
    const nodeEl = document.querySelector(`.nen-node[data-nen-node="${cat}"]`);
    const pctStr = effMap[cat] || "—";

    if (pctEl) {
      pctEl.textContent = pctStr;
    }

    if (nodeEl) {
      nodeEl.classList.remove("ef-100", "ef-80", "ef-60", "ef-40");
      if (pctStr === "100%") nodeEl.classList.add("ef-100");
      else if (pctStr === "80%") nodeEl.classList.add("ef-80");
      else if (pctStr === "60%") nodeEl.classList.add("ef-60");
      else if (pctStr === "40%" || pctStr.startsWith("0%")) nodeEl.classList.add("ef-40");
    }
  });

  if (legendaEl) {
    if (categoryKey && NEN_LABELS[categoryKey]) {
      legendaEl.textContent = `Categoria Principal: ${NEN_LABELS[categoryKey]} (100%) · Adjacentes: 80% · Distantes: 60% · Oposta: 40%.`;
    } else {
      legendaEl.textContent = "Selecione uma categoria principal (ou clique em um vértice) para destacar 100%, 80%, 60% e 40%.";
    }
  }
}

function parseAbilitiesFromHiddenInput() {
  const hiddenInput = document.getElementById("habilidades-nen-json");
  if (!hiddenInput || !hiddenInput.value) {
    state.nenAbilities = [];
    return;
  }

  try {
    const parsed = JSON.parse(hiddenInput.value);
    if (!Array.isArray(parsed)) {
      state.nenAbilities = [];
      return;
    }
    state.nenAbilities = parsed
      .slice(0, 40)
      .filter((item) => item && typeof item === "object")
      .map((item, idx) => ({
        id: sanitizeSingleLine(String(item.id || `hab-${idx}-${Date.now()}`), 48),
        name: sanitizeSingleLine(String(item.name || "Técnica"), 80),
        type: sanitizeSingleLine(String(item.type || "Princípio Básico"), 40),
        cost: Math.min(999, Math.max(0, Math.trunc(Number(item.cost) || 0))),
        desc: sanitizeSingleLine(String(item.desc || ""), 220)
      }));
  } catch {
    state.nenAbilities = [];
  }
}

function syncAbilitiesToHiddenInput() {
  const hiddenInput = document.getElementById("habilidades-nen-json");
  if (hiddenInput) {
    hiddenInput.value = JSON.stringify(state.nenAbilities);
  }
}

function useNenAbility(ability) {
  if (!ability || isInspectionReadOnlyActive()) return;
  const peAtualEl = document.getElementById("pe-atual");
  const peGastoEl = document.getElementById("pe-gasto");
  if (!peAtualEl) return;

  const currentPe = Math.trunc(Number(peAtualEl.value) || 0);
  const cost = Math.max(0, Math.trunc(Number(ability.cost) || 0));

  if (currentPe < cost) {
    setStatusBanner(
      `PE insuficiente para usar "${ability.name}" (custo: ${cost} PE · atual: ${currentPe} PE).`,
      "warning"
    );
    return;
  }

  peAtualEl.value = String(currentPe - cost);
  if (peGastoEl) {
    const spentPe = Math.trunc(Number(peGastoEl.value) || 0);
    peGastoEl.value = String(spentPe + cost);
  }

  setStatusBanner(
    `Habilidade "${ability.name}" ativada (-${cost} PE). Restante: ${currentPe - cost} PE.`,
    "success"
  );
  scheduleAutoSave();
}

function renderNenAbilitiesList() {
  const container = document.getElementById("lista-habilidades-nen");
  if (!container) return;

  container.innerHTML = "";
  if (!state.nenAbilities.length) {
    const empty = document.createElement("p");
    empty.className = "texto-nen";
    empty.textContent = "Nenhuma técnica cadastrada ainda. Adicione Ten, Zetsu, Ren ou seu Hatsu acima.";
    container.appendChild(empty);
    return;
  }

  state.nenAbilities.forEach((hab) => {
    const card = document.createElement("div");
    card.className = "hab-item-card";

    const info = document.createElement("div");
    info.className = "hab-item-info";

    const title = document.createElement("div");
    title.className = "hab-item-titulo";
    title.textContent = hab.name;

    const meta = document.createElement("div");
    meta.className = "hab-item-meta";
    meta.textContent = `${hab.type} · Custo: ${hab.cost} PE`;

    info.appendChild(title);
    info.appendChild(meta);

    if (hab.desc) {
      const desc = document.createElement("div");
      desc.className = "hab-item-desc";
      desc.textContent = hab.desc;
      info.appendChild(desc);
    }

    const actions = document.createElement("div");
    actions.className = "hab-item-acoes";

    const useBtn = document.createElement("button");
    useBtn.type = "button";
    useBtn.className = "btn-arkan btn-azul btn-mini";
    useBtn.textContent = `Usar Habilidade (-${hab.cost} PE)`;
    useBtn.addEventListener("click", () => useNenAbility(hab));

    const delBtn = document.createElement("button");
    delBtn.type = "button";
    delBtn.className = "btn-arkan btn-perigo btn-mini";
    delBtn.textContent = "Remover";
    delBtn.addEventListener("click", () => {
      if (isInspectionReadOnlyActive()) return;
      state.nenAbilities = state.nenAbilities.filter((item) => item.id !== hab.id);
      syncAbilitiesToHiddenInput();
      renderNenAbilitiesList();
      scheduleAutoSave();
    });

    actions.appendChild(useBtn);
    actions.appendChild(delBtn);

    card.appendChild(info);
    card.appendChild(actions);
    container.appendChild(card);
  });
}

function handleAddNenAbility() {
  if (isInspectionReadOnlyActive()) return;
  const nameEl = document.getElementById("hab-nome-input");
  const typeEl = document.getElementById("hab-tipo-input");
  const costEl = document.getElementById("hab-custo-input");
  const descEl = document.getElementById("hab-desc-input");

  const name = sanitizeSingleLine(nameEl ? nameEl.value : "", 80);
  if (!name) {
    setStatusBanner("Informe o nome da técnica ou Hatsu antes de adicionar.", "warning");
    return;
  }

  const type = sanitizeSingleLine(typeEl ? typeEl.value : "Princípio Básico", 40);
  const cost = Math.min(999, Math.max(0, Math.trunc(Number(costEl ? costEl.value : 0) || 0)));
  const desc = sanitizeSingleLine(descEl ? descEl.value : "", 220);

  state.nenAbilities.push({
    id: `hab-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
    name,
    type,
    cost,
    desc
  });

  if (nameEl) nameEl.value = "";
  if (descEl) descEl.value = "";

  syncAbilitiesToHiddenInput();
  renderNenAbilitiesList();
  setStatusBanner(`Técnica "${name}" adicionada ao catálogo de Nen.`, "success");
  scheduleAutoSave();
}

/* --------------------------------------------------------------------------
   Automação e QoL: Status Automáticos + Alerta de Sobrecarga + JSON/PDF
   -------------------------------------------------------------------------- */
function recalculateAutoStatusValues() {
  const autoCheck = document.getElementById("auto-calc-status");
  if (!autoCheck || !autoCheck.checked) return;

  const nv = Math.max(1, Math.trunc(Number(document.getElementById("nv-val")?.value) || 1));
  const agi = Math.trunc(Number(document.getElementById("attr-agi")?.value) || 1);
  const ca = Math.trunc(Number(document.getElementById("attr-ca")?.value) || 1);
  const vig = Math.trunc(Number(document.getElementById("attr-vig")?.value) || 1);

  const vidaMaxEl = document.getElementById("vida-max");
  const peMaxEl = document.getElementById("pe-max");
  const sanMaxEl = document.getElementById("san-max");
  const defTotalEl = document.getElementById("def-total");
  const defEsquivaEl = document.getElementById("def-esquiva");

  const calcVidaMax = Math.max(1, 16 + vig * 4 + (nv - 1) * (4 + Math.max(0, vig)));
  const calcPeMax = Math.max(1, 4 + ca * 3 + (nv - 1) * (2 + Math.max(0, ca)));
  const calcSanMax = Math.max(1, 12 + ca * 3 + (nv - 1) * 3);
  const defOutros = Math.trunc(Number(document.getElementById("def-total-outros")?.value) || 0);
  const esqOutros = Math.trunc(Number(document.getElementById("def-esquiva-outros")?.value) || 0);
  const calcDef = 10 + agi + defOutros;
  const calcEsq = 10 + agi + esqOutros;

  if (vidaMaxEl && document.activeElement !== vidaMaxEl) vidaMaxEl.value = String(calcVidaMax);
  if (peMaxEl && document.activeElement !== peMaxEl) peMaxEl.value = String(calcPeMax);
  if (sanMaxEl && document.activeElement !== sanMaxEl) sanMaxEl.value = String(calcSanMax);
  if (defTotalEl && document.activeElement !== defTotalEl) defTotalEl.value = String(calcDef);
  if (defEsquivaEl && document.activeElement !== defEsquivaEl) defEsquivaEl.value = String(calcEsq);
}

function evaluateOverloadState() {
  const sumIntCheck = document.getElementById("somar-intelecto");
  const espacosAtualEl = document.getElementById("espacos-atual");
  const espacosMaxEl = document.getElementById("espacos-max");
  const intAttrEl = document.getElementById("attr-int");

  const currentLoad = Math.trunc(Number(espacosAtualEl?.value) || 0);
  const baseMaxSlots = Math.trunc(Number(espacosMaxEl?.value) || 5);
  const intBonus = sumIntCheck && sumIntCheck.checked ? Math.max(0, Math.trunc(Number(intAttrEl?.value) || 0)) : 0;
  const effectiveMaxSlots = baseMaxSlots + intBonus;

  const isOverloaded = currentLoad > effectiveMaxSlots;

  const alertSkills = document.getElementById("alerta-sobrecarga-pericias");
  const alertEquip = document.getElementById("alerta-sobrecarga-equip");
  const cargaBar = document.getElementById("barra-carga-container");

  if (alertSkills) alertSkills.hidden = !isOverloaded;
  if (alertEquip) alertEquip.hidden = !isOverloaded;
  if (cargaBar) cargaBar.classList.toggle("em-sobrecarga", isOverloaded);

  return isOverloaded;
}

function handleUserExportJson() {
  const payload = buildSanitizedCloudPayload();
  const exportObj = {
    sistema: "Ordem de Arkan",
    exportadoEm: new Date().toISOString(),
    nomeAgente: sanitizeSingleLine(document.getElementById("nome")?.value || "agente", 60) || "agente",
    fields: payload.fields
  };

  const serialized = JSON.stringify(exportObj, null, 2);
  const safeFileSlug = exportObj.nomeAgente
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9_-]+/g, "_")
    .toLowerCase();

  try {
    const blob = new Blob([serialized], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ficha_arkan_${safeFileSlug || "agente"}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    setStatusBanner("Arquivo JSON da ficha baixado com sucesso.", "success");
  } catch {
    setStatusBanner("Não foi possível baixar o arquivo JSON neste navegador.", "error");
  }
}

function handleUserImportJsonFile(event) {
  if (isInspectionReadOnlyActive()) {
    setStatusBanner("Desative 'Somente leitura' antes de importar uma ficha.", "warning");
    return;
  }

  const fileInput = event.target;
  const file = fileInput && fileInput.files ? fileInput.files[0] : null;
  if (!file) return;

  if (file.size > 500000) {
    setStatusBanner("Arquivo JSON muito grande (limite: 500 KB).", "error");
    fileInput.value = "";
    return;
  }

  const reader = new FileReader();
  reader.onload = async () => {
    try {
      const parsed = JSON.parse(String(reader.result || ""));
      if (!parsed || typeof parsed !== "object" || !parsed.fields || typeof parsed.fields !== "object") {
        setStatusBanner("Arquivo JSON inválido: estrutura de ficha não reconhecida.", "error");
        return;
      }

      const safeFields = createSafeRecord();
      Object.entries(parsed.fields).slice(0, 1500).forEach(([k, v]) => {
        if (!isValidFieldKey(k) || k === ADMIN_NOTICE_FIELD_KEY || k === MULTI_SLOTS_FIELD_KEY) return;
        if (typeof v === "boolean") safeFields[k] = v;
        else if (typeof v === "string" || typeof v === "number") safeFields[k] = String(v).slice(0, 5000);
      });

      applySheetData({ fields: safeFields });
      setStatusBanner("Ficha importada com sucesso a partir do arquivo JSON.", "success");
      await persistSheet(true);
    } catch {
      setStatusBanner("Erro ao ler o arquivo JSON selecionado.", "error");
    } finally {
      fileInput.value = "";
    }
  };
  reader.readAsText(file);
}

/* --------------------------------------------------------------------------
   Recursos para Aba Guilda (Loja/Banco) e Múltiplas Fichas por Conta
   -------------------------------------------------------------------------- */
function renderGuildShopCatalog() {
  const listEl = document.getElementById("guilda-loja-lista");
  if (!listEl) return;

  listEl.innerHTML = "";
  GUILD_SHOP_CATALOG.forEach((item) => {
    const row = document.createElement("div");
    row.className = "guilda-loja-item";

    const info = document.createElement("div");
    info.innerHTML = `<strong>${item.name}</strong> · Cat. ${item.category} · Espaço ${item.space} · <strong>${item.price} moedas</strong><br><small>${item.desc}</small>`;

    const buyBtn = document.createElement("button");
    buyBtn.type = "button";
    buyBtn.className = "btn-arkan btn-azul btn-mini";
    buyBtn.textContent = `Comprar (${item.price})`;
    buyBtn.addEventListener("click", () => handleBuyGuildShopItem(item));

    row.appendChild(info);
    row.appendChild(buyBtn);
    listEl.appendChild(row);
  });
}

function spendGuildCoins(amount, reasonText) {
  if (isInspectionReadOnlyActive()) return false;
  const coinsEl = document.getElementById("guilda-moedas-total");
  if (!coinsEl) return false;

  const currentCoins = Math.trunc(Number(coinsEl.value) || 0);
  const cost = Math.max(1, Math.trunc(Number(amount) || 0));

  if (currentCoins < cost) {
    setStatusBanner(
      `Moedas insuficientes na Guilda (necessário: ${cost} · saldo atual: ${currentCoins}).`,
      "warning"
    );
    return false;
  }

  coinsEl.value = String(currentCoins - cost);
  setStatusBanner(
    `Gasto registrado: -${cost} moedas (${sanitizeSingleLine(reasonText, 80)}). Saldo restante: ${currentCoins - cost}.`,
    "success"
  );
  scheduleAutoSave();
  return true;
}

function addItemToInventoryFirstFreeRow(item) {
  const rows = document.querySelectorAll("#tabela-itens tbody tr");
  for (let i = 0; i < rows.length; i += 1) {
    const inputs = rows[i].querySelectorAll("input");
    if (inputs.length >= 4 && !inputs[0].value.trim()) {
      inputs[0].value = item.name;
      inputs[1].value = item.desc;
      inputs[2].value = String(item.category);
      inputs[3].value = String(item.space);
      return true;
    }
  }
  return false;
}

function handleBuyGuildShopItem(item) {
  if (!spendGuildCoins(item.price, `Compra: ${item.name}`)) return;

  const added = addItemToInventoryFirstFreeRow(item);
  const espacosAtualEl = document.getElementById("espacos-atual");
  if (espacosAtualEl && item.space > 0) {
    const cur = Math.trunc(Number(espacosAtualEl.value) || 0);
    espacosAtualEl.value = String(cur + item.space);
  }

  recalculateSkillsTable();
  if (!added) {
    setStatusBanner(
      `Compra de "${item.name}" debitada (-${item.price} moedas), mas a tabela de itens está cheia.`,
      "warning"
    );
  }
  scheduleAutoSave();
}

function syncSlotDropdownUI() {
  const selectEl = document.getElementById("ficha-slot-select");
  if (!selectEl) return;

  const slotEntries = Object.entries(state.accountSlots.slots || {});
  selectEl.innerHTML = "";

  slotEntries.forEach(([slotId, slotData], idx) => {
    const opt = document.createElement("option");
    opt.value = slotId;
    const displayName = sanitizeSingleLine(slotData?.name || `Agente ${idx + 1}`, 45) || `Agente ${idx + 1}`;
    opt.textContent = `${idx + 1}. ${displayName}`;
    if (slotId === state.accountSlots.activeSlotId) {
      opt.selected = true;
    }
    selectEl.appendChild(opt);
  });
}

function extractCurrentFormFieldsOnly() {
  const raw = collectSheetData().fields;
  const clean = createSafeRecord();
  Object.entries(raw).forEach(([k, v]) => {
    if (isValidFieldKey(k) && k !== ADMIN_NOTICE_FIELD_KEY && k !== MULTI_SLOTS_FIELD_KEY) {
      clean[k] = v;
    }
  });
  return clean;
}

function saveCurrentFormIntoActiveSlotMemory() {
  const activeId = state.accountSlots.activeSlotId || "slot-1";
  const currentFields = extractCurrentFormFieldsOnly();
  const agentName = sanitizeSingleLine(currentFields["id:nome"] || "", 45) || "Agente sem nome";
  state.accountSlots.slots[activeId] = {
    name: agentName,
    fields: currentFields
  };
  syncSlotDropdownUI();
}

async function handleSwitchAccountSlot(nextSlotId) {
  if (!nextSlotId || nextSlotId === state.accountSlots.activeSlotId) return;
  if (!Object.prototype.hasOwnProperty.call(state.accountSlots.slots, nextSlotId)) return;

  saveCurrentFormIntoActiveSlotMemory();
  state.accountSlots.activeSlotId = nextSlotId;

  const targetSlot = state.accountSlots.slots[nextSlotId];
  resetSheetFieldsToDefault();
  applySheetData({ fields: targetSlot.fields || createSafeRecord() }, true);
  syncSlotDropdownUI();
  setStatusBanner(`Ficha alternada para "${targetSlot.name}".`, "info");
  await persistSheet(true);
}

async function handleCreateNewAccountSlot() {
  if (isInspectionReadOnlyActive()) return;
  const existingKeys = Object.keys(state.accountSlots.slots || {});
  if (existingKeys.length >= MAX_ACCOUNT_SLOTS) {
    setStatusBanner(`Limite máximo de ${MAX_ACCOUNT_SLOTS} fichas por conta atingido.`, "warning");
    return;
  }

  saveCurrentFormIntoActiveSlotMemory();
  const newId = `slot-${Date.now()}`;
  const label = `Novo Agente #${existingKeys.length + 1}`;

  resetSheetFieldsToDefault();
  const nomeEl = document.getElementById("nome");
  if (nomeEl) nomeEl.value = label;

  state.accountSlots.activeSlotId = newId;
  state.accountSlots.slots[newId] = {
    name: label,
    fields: extractCurrentFormFieldsOnly()
  };

  syncSlotDropdownUI();
  setStatusBanner(`Nova ficha "${label}" criada na sua conta.`, "success");
  await persistSheet(true);
}

async function handleDeleteCurrentAccountSlot() {
  if (isInspectionReadOnlyActive()) return;
  const keys = Object.keys(state.accountSlots.slots || {});
  if (keys.length <= 1) {
    setStatusBanner("Você precisa manter pelo menos 1 ficha na conta. Use 'Excluir ficha' para zerá-la.", "warning");
    return;
  }

  const currentId = state.accountSlots.activeSlotId;
  delete state.accountSlots.slots[currentId];

  const remainingKeys = Object.keys(state.accountSlots.slots);
  const fallbackId = remainingKeys[0];
  state.accountSlots.activeSlotId = fallbackId;

  resetSheetFieldsToDefault();
  applySheetData({ fields: state.accountSlots.slots[fallbackId].fields || createSafeRecord() }, true);
  syncSlotDropdownUI();
  setStatusBanner("Ficha removida da lista da conta.", "success");
  await persistSheet(true);
}

/* --------------------------------------------------------------------------
   Mensagens Temporárias do Admin por UID (Normal/Urgente até 24h)
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

function buildEncodedNoticePayload(messageText, minutesValue, priorityValue = "normal") {
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
    sentAt: nowMs,
    expiresAt: expiresAtMs
  });
}

function parseActiveNoticeFromFields(fieldsObj) {
  if (!fieldsObj || typeof fieldsObj !== "object") return null;
  if (!Object.prototype.hasOwnProperty.call(fieldsObj, ADMIN_NOTICE_FIELD_KEY)) return null;

  const raw = fieldsObj[ADMIN_NOTICE_FIELD_KEY];
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
      expiresAt: effectiveExpiryMs
    };
  } catch {
    return null;
  }
}

function scheduleNoticeExpiryCheck() {
  if (state.noticeExpiryTimer) {
    clearTimeout(state.noticeExpiryTimer);
    state.noticeExpiryTimer = null;
  }

  if (!state.activeNotice || !Number.isFinite(state.activeNotice.expiresAt)) return;

  const remainingMs = state.activeNotice.expiresAt - Date.now();
  if (remainingMs <= 0) {
    state.activeNotice = null;
    renderPlayerNoticeBanner();
    renderAdminCommandFunctionsBelow();
    return;
  }

  state.noticeExpiryTimer = setTimeout(() => {
    state.noticeExpiryTimer = null;
    if (state.activeNotice && Date.now() >= state.activeNotice.expiresAt) {
      state.activeNotice = null;
      renderPlayerNoticeBanner();
      renderAdminCommandFunctionsBelow();
    }
  }, Math.min(remainingMs + 250, 2147483647));
}

function renderPlayerNoticeBanner() {
  const banner = document.getElementById("player-admin-notice-banner");
  const hasSession = Boolean(state.user) || Boolean(state.offlineMode);

  if (!hasSession || state.offlineMode || !state.activeNotice || Date.now() >= (state.activeNotice.expiresAt || 0)) {
    if (banner) banner.hidden = true;
    return;
  }

  ensurePlayerNoticeBannerElement();
  const activeBanner = document.getElementById("player-admin-notice-banner");
  if (!activeBanner) return;

  const isUrgent = state.activeNotice.priority === "urgent";
  activeBanner.style.border = isUrgent
    ? "1px solid rgba(255, 99, 99, 0.85)"
    : "1px solid rgba(255, 217, 102, 0.55)";
  activeBanner.style.background = isUrgent
    ? "rgba(62, 22, 28, 0.96)"
    : "rgba(34, 42, 54, 0.96)";

  const expDate = new Date(state.activeNotice.expiresAt);
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
  title.textContent = isUrgent
    ? "AVISO URGENTE DO ADMINISTRADOR"
    : "Recado do Administrador";
  title.style.cssText = isUrgent
    ? "color: #ff8a80; font-size: 13px; letter-spacing: 0.4px;"
    : "color: #ffe082; font-size: 13px;";

  const meta = document.createElement("span");
  meta.textContent = `Duração: ${formatDurationLabel(state.activeNotice.minutes)} (${formatRemainingTimeLabel(state.activeNotice.expiresAt)} · expira em ${expFormatted})`;
  meta.style.cssText = "color: #d6dee6; font-size: 12px;";

  const body = document.createElement("p");
  body.textContent = state.activeNotice.msg;
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

  const adminBar = document.getElementById("admin-uid-bar");
  if (adminBar && adminBar.parentNode === anchorParent) {
    anchorParent.insertBefore(box, adminBar.nextSibling);
  } else if (mainEl && mainEl.parentNode === anchorParent) {
    anchorParent.insertBefore(box, mainEl);
  } else {
    anchorParent.appendChild(box);
  }
}

/* --------------------------------------------------------------------------
   Helpers Exclusivos da Conta Admin
   -------------------------------------------------------------------------- */
function isCurrentUserAdmin() {
  return Boolean(state.user && typeof state.user.uid === "string" && state.user.uid === ADMIN_UID);
}

function isInspectionReadOnlyActive() {
  return Boolean(isCurrentUserAdmin() && state.adminReadOnly);
}

function sanitizeTargetUid(rawUid) {
  const clean = sanitizeSingleLine(String(rawUid ?? ""), 128);
  return UID_REGEX.test(clean) ? clean : "";
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
    if (!isValidFieldKey(key) || key === ADMIN_NOTICE_FIELD_KEY || key === MULTI_SLOTS_FIELD_KEY) continue;
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
    // Ignora falha
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
    // Ignora falha
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
  if (isCurrentUserAdmin() && state.adminTargetUid) {
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

  const found = ADMIN_COMMAND_CATALOG.find((item) => item.cmd === normalizedToken);
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
  header.textContent = "Comandos ativos (clique para carregar no prompt e exibir as funções abaixo):";
  header.style.cssText = "font-size: 12px; color: #ffd966; font-weight: 600; margin-bottom: 6px;";
  strip.appendChild(header);

  const grid = document.createElement("div");
  grid.style.cssText = "display: flex; flex-wrap: wrap; gap: 6px;";

  ADMIN_COMMAND_CATALOG.forEach((item) => {
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

  box.hidden = false;
  box.innerHTML = "";

  const titleRow = document.createElement("div");
  titleRow.style.cssText = "display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 8px;";

  const title = document.createElement("strong");
  const spec = ADMIN_COMMAND_CATALOG.find((c) => c.cmd === cmd);
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

  if (cmd === "/recado" || cmd === "/urgente" || cmd === "/remover") {
    const row = document.createElement("div");
    row.style.cssText = "display: flex; flex-wrap: wrap; gap: 8px; align-items: center;";

    const msgInput = document.createElement("input");
    msgInput.type = "text";
    msgInput.maxLength = 600;
    msgInput.value = state.adminDraftNoticeText || "";
    msgInput.placeholder = "Escreva a mensagem para o UID alvo...";
    msgInput.style.cssText = "flex: 1 1 200px; padding: 7px 10px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.22); background: #0a0e12; color: #fff; font-size: 12px;";
    msgInput.addEventListener("input", () => {
      state.adminDraftNoticeText = msgInput.value;
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
      if ((cmd === "/urgente" ? "urgent" : state.adminDraftNoticePriority) === p.value) {
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
    sendBtn.textContent = "Enviar recado";
    sendBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: none; background: #c48b1b; color: #111; font-weight: 700; font-size: 12px; cursor: pointer;";
    sendBtn.addEventListener("click", () =>
      handleAdminSendNotice({
        text: msgInput.value,
        minutes: durSelect.value,
        priority: prioSelect.value
      })
    );

    const clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.textContent = "Remover recado";
    clearBtn.style.cssText = "padding: 7px 11px; border-radius: 7px; border: 1px solid rgba(255,255,255,0.25); background: transparent; color: #e4e4ec; font-size: 12px; cursor: pointer;";
    clearBtn.addEventListener("click", handleAdminClearNotice);

    row.appendChild(msgInput);
    row.appendChild(prioSelect);
    row.appendChild(durSelect);
    row.appendChild(sendBtn);
    row.appendChild(clearBtn);
    box.appendChild(row);

    const preview = document.createElement("div");
    preview.style.cssText = "margin-top: 8px; font-size: 12px; color: #ffe082;";
    if (!state.activeNotice || Date.now() >= (state.activeNotice.expiresAt || 0)) {
      preview.textContent = "Recado ativo no alvo: nenhum recado ativo no momento.";
    } else {
      const tag = state.activeNotice.priority === "urgent" ? "[URGENTE]" : "[Normal]";
      preview.textContent = `Recado ativo no alvo ${tag} (${formatRemainingTimeLabel(state.activeNotice.expiresAt)}): "${state.activeNotice.msg}"`;
    }
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
  ADMIN_COMMAND_CATALOG.forEach((item) => {
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
    if (state.adminTargetUid && state.adminTargetUid !== state.user.uid) {
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
  promptInput.placeholder = "Digite um comando (ex: /uid, /recado 30 Oi, /ler, /stats, /modelo, /diff, /json, /log)...";
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
    renderActiveCommandsStrip();
    renderAdminCommandFunctionsBelow();
  });

  promptForm.addEventListener("submit", handleAdminPromptSubmit);
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

  if ((cmd === "/recado" || cmd === "/urgente") && parts.length >= 3) {
    const minutes = normalizeNoticeMinutes(parts[1]);
    const text = parts.slice(2).join(" ");
    const priority = cmd === "/urgente" ? "urgent" : state.adminDraftNoticePriority;
    state.adminDraftNoticeText = text;
    state.adminDraftNoticeMinutes = minutes;
    state.adminDraftNoticePriority = priority;
    await handleAdminSendNotice({ text, minutes, priority });
    renderAdminCommandFunctionsBelow();
    return;
  }

  if (cmd === "/remover") {
    await handleAdminClearNotice();
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
    // Fallback
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
      if (typeof v === "boolean") safeFields[k] = v;
      else if (typeof v === "string" || typeof v === "number") safeFields[k] = String(v).slice(0, 5000);
    });

    applySheetData({ fields: safeFields });
    appendAdminLog(`JSON importado para UID ${getActiveTargetUid()}`);
    await persistSheet(true);
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

  applySheetData({ fields: mergedFields });
  appendAdminLog(`Modelo "${tpl.label}" aplicado ao UID ${getActiveTargetUid()}`);
  await persistSheet(true);
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
  await persistSheet(true);
}

async function handleAdminLoadTargetUid(rawUidOverride) {
  if (!isCurrentUserAdmin()) {
    setStatusBanner("Apenas o administrador autorizado pode carregar fichas por UID.", "error");
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
  appendAdminLog("Retornou para a própria ficha do Admin");
  setStatusBanner("Voltando para a sua própria ficha...", "info");
  await loadFromFirestore(state.user.uid);
}

async function handleAdminSendNotice(overrideData) {
  if (!isCurrentUserAdmin() || !state.firebaseReady || !state.db) {
    setStatusBanner("Apenas o admin conectado ao Firebase pode enviar recados.", "error");
    return;
  }

  const targetUid = sanitizeTargetUid(state.adminTargetUid || state.adminDraftUid || state.user.uid);
  if (!targetUid) {
    setStatusBanner("Carregue ou informe um UID válido para enviar a mensagem.", "warning");
    return;
  }

  const rawText = overrideData && overrideData.text !== undefined ? overrideData.text : state.adminDraftNoticeText;
  const rawMin = overrideData && overrideData.minutes !== undefined ? overrideData.minutes : state.adminDraftNoticeMinutes;
  const rawPrio = overrideData && overrideData.priority !== undefined ? overrideData.priority : state.adminDraftNoticePriority;

  const minutes = normalizeNoticeMinutes(rawMin);
  const priority = normalizeNoticePriority(rawPrio);
  const encodedPayload = buildEncodedNoticePayload(rawText, minutes, priority);
  if (!encodedPayload) {
    setStatusBanner("Escreva uma mensagem antes de enviar.", "warning");
    return;
  }

  state.adminTargetUid = targetUid;
  saveAdminTargetUidToStorage(targetUid);
  recordRecentAdminUid(targetUid);

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

async function handleAdminClearNotice(event) {
  if (event && event.isTrusted === false) return;
  if (!isCurrentUserAdmin() || !state.firebaseReady || !state.db) return;

  const targetUid = sanitizeTargetUid(state.adminTargetUid || state.adminDraftUid || state.user.uid);
  if (!targetUid) {
    setStatusBanner("Informe um UID válido para remover o recado.", "warning");
    return;
  }

  const { doc, getDoc, setDoc } = state.firebaseModules.firestoreMod;
  const docRef = doc(state.db, FIRESTORE_COLLECTION, targetUid);

  try {
    const snap = await getDoc(docRef);
    if (!snap.exists()) {
      setStatusBanner("Nenhuma ficha encontrada para esse UID.", "info");
      return;
    }

    const existingFields =
      snap.data() && snap.data().fields && typeof snap.data().fields === "object"
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
    setStatusBanner(`Recado removido do UID ${targetUid}.`, "success");
  } catch {
    setStatusBanner("Erro ao remover o recado no Firestore.", "error");
  }
}

/* --------------------------------------------------------------------------
   Cálculo Automático da Tabela de Perícias (#tabela-pericias) + Sobrecarga
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
  recalculateAutoStatusValues();
  const isOverloaded = evaluateOverloadState();

  const table = document.getElementById("tabela-pericias");
  if (!table) return;

  const rows = table.querySelectorAll("tbody tr");
  rows.forEach((row) => {
    const nameCell = row.querySelector(".pericia-nome");
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

    const hasCargoPenaltyTag = Boolean(nameCell && (nameCell.textContent || "").includes("*"));
    const overloadPenalty = isOverloaded && hasCargoPenaltyTag ? OVERLOAD_SKILL_PENALTY : 0;

    const attrBonus = getSkillAttributeBonus(attrCell ? attrCell.textContent : "");
    const total = attrBonus + extrasSum + overloadPenalty;

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
  updateNenHexagonDiagram(key);
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
    // Mantém o aceite em memória
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
  renderPlayerNoticeBanner();

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
  state.activeNotice = null;
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
  syncAbilitiesToHiddenInput();

  const fields = createSafeRecord();
  const mainEl = document.querySelector("main.container");
  if (!mainEl) {
    return { fields, atualizadoEm: new Date().toISOString() };
  }

  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl, index) => {
    if (!ctrl || ctrl.closest("#login-firebase")) return;
    if (
      ctrl.id === "hab-nome-input" ||
      ctrl.id === "hab-tipo-input" ||
      ctrl.id === "hab-custo-input" ||
      ctrl.id === "hab-desc-input" ||
      ctrl.id === "guilda-gasto-valor" ||
      ctrl.id === "guilda-gasto-motivo"
    ) {
      return;
    }

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

  if (state.user && !state.offlineMode) {
    const activeId = state.accountSlots.activeSlotId || "slot-1";
    const slotFields = createSafeRecord();
    Object.entries(fields).forEach(([k, v]) => {
      if (k !== ADMIN_NOTICE_FIELD_KEY && k !== MULTI_SLOTS_FIELD_KEY) {
        slotFields[k] = v;
      }
    });
    const agentName = sanitizeSingleLine(slotFields["id:nome"] || "", 45) || "Agente Principal";
    state.accountSlots.slots[activeId] = {
      name: agentName,
      fields: slotFields
    };
    syncSlotDropdownUI();

    const serializedRegistry = JSON.stringify({
      activeSlotId: activeId,
      slots: state.accountSlots.slots
    });
    if (serializedRegistry.length <= 280000) {
      fields[MULTI_SLOTS_FIELD_KEY] = serializedRegistry;
    }
  }

  if (state.activeNotice && Date.now() < (state.activeNotice.expiresAt || 0)) {
    const remainingMinutes = Math.max(
      1,
      Math.min(MAX_NOTICE_MINUTES, Math.ceil((state.activeNotice.expiresAt - Date.now()) / 60000))
    );
    const reEncoded = buildEncodedNoticePayload(
      state.activeNotice.msg,
      remainingMinutes,
      state.activeNotice.priority
    );
    if (reEncoded) {
      fields[ADMIN_NOTICE_FIELD_KEY] = reEncoded;
    }
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

      if (key === MULTI_SLOTS_FIELD_KEY && typeof val === "string") {
        if (val.length <= 280000) {
          cleanFields[key] = val;
        }
        continue;
      }

      if (key === ADMIN_NOTICE_FIELD_KEY && typeof val === "string") {
        const parsedNotice = parseActiveNoticeFromFields({ [ADMIN_NOTICE_FIELD_KEY]: val });
        if (parsedNotice) {
          cleanFields[key] = JSON.stringify({
            msg: parsedNotice.msg,
            minutes: parsedNotice.minutes,
            hours: Number((parsedNotice.minutes / 60).toFixed(2)),
            priority: parsedNotice.priority,
            sentAt: Date.now(),
            expiresAt: parsedNotice.expiresAt
          });
        }
        continue;
      }

      if (typeof val === "boolean") {
        cleanFields[key] = val;
      } else if (typeof val === "number" && Number.isFinite(val)) {
        cleanFields[key] = String(Math.trunc(val)).slice(0, 24);
      } else if (typeof val === "string") {
        cleanFields[key] =
          key === "id:habilidades-nen-json"
            ? sanitizeText(val, 15000)
            : key.startsWith("id:anotacoes") ||
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

function hydrateAccountSlotsFromFields(fieldsObj) {
  const defaultSlotFields = createSafeRecord();
  Object.entries(fieldsObj || {}).forEach(([k, v]) => {
    if (isValidFieldKey(k) && k !== ADMIN_NOTICE_FIELD_KEY && k !== MULTI_SLOTS_FIELD_KEY) {
      defaultSlotFields[k] = v;
    }
  });
  const defaultName = sanitizeSingleLine(defaultSlotFields["id:nome"] || "", 45) || "Agente Principal";

  if (!fieldsObj || !Object.prototype.hasOwnProperty.call(fieldsObj, MULTI_SLOTS_FIELD_KEY)) {
    state.accountSlots = {
      activeSlotId: "slot-1",
      slots: {
        "slot-1": { name: defaultName, fields: defaultSlotFields }
      }
    };
    syncSlotDropdownUI();
    return null;
  }

  try {
    const parsed = JSON.parse(String(fieldsObj[MULTI_SLOTS_FIELD_KEY] || ""));
    if (!parsed || typeof parsed !== "object" || !parsed.slots || typeof parsed.slots !== "object") {
      throw new Error("Invalid slots");
    }

    const safeSlots = createSafeRecord();
    Object.entries(parsed.slots).slice(0, MAX_ACCOUNT_SLOTS).forEach(([slotId, slotVal], idx) => {
      if (isForbiddenKey(slotId) || !/^[a-zA-Z0-9_-]{1,40}$/.test(slotId)) return;
      if (!slotVal || typeof slotVal !== "object" || !slotVal.fields || typeof slotVal.fields !== "object") return;

      const cleanSlotFields = createSafeRecord();
      Object.entries(slotVal.fields).slice(0, 1500).forEach(([fk, fv]) => {
        if (!isValidFieldKey(fk) || fk === ADMIN_NOTICE_FIELD_KEY || fk === MULTI_SLOTS_FIELD_KEY) return;
        if (typeof fv === "boolean") cleanSlotFields[fk] = fv;
        else if (typeof fv === "string" || typeof fv === "number") cleanSlotFields[fk] = String(fv).slice(0, 15000);
      });

      const slotName =
        sanitizeSingleLine(String(slotVal.name || cleanSlotFields["id:nome"] || `Agente ${idx + 1}`), 45) ||
        `Agente ${idx + 1}`;
      safeSlots[slotId] = { name: slotName, fields: cleanSlotFields };
    });

    const slotKeys = Object.keys(safeSlots);
    if (!slotKeys.length) {
      throw new Error("Empty slots");
    }

    const activeId = slotKeys.includes(parsed.activeSlotId) ? parsed.activeSlotId : slotKeys[0];
    state.accountSlots = {
      activeSlotId: activeId,
      slots: safeSlots
    };
    syncSlotDropdownUI();
    return safeSlots[activeId].fields;
  } catch {
    state.accountSlots = {
      activeSlotId: "slot-1",
      slots: {
        "slot-1": { name: defaultName, fields: defaultSlotFields }
      }
    };
    syncSlotDropdownUI();
    return null;
  }
}

function applySheetData(data, skipSlotHydration = false) {
  if (!data || typeof data !== "object" || !data.fields || typeof data.fields !== "object") {
    state.activeNotice = null;
    state.nenAbilities = [];
    syncAbilitiesToHiddenInput();
    renderNenAbilitiesList();
    scheduleNoticeExpiryCheck();
    renderPlayerNoticeBanner();
    recalculateSkillsTable();
    syncNenCategoryFromSelect();
    syncAdminQuickInputsFromSheet();
    captureBaselineFields(collectSheetData().fields);
    renderAdminCommandFunctionsBelow();
    return;
  }

  let effectiveFields = data.fields;
  if (!skipSlotHydration) {
    const slotFields = hydrateAccountSlotsFromFields(data.fields);
    if (slotFields) {
      effectiveFields = slotFields;
    }
  }

  state.activeNotice = parseActiveNoticeFromFields(data.fields);
  scheduleNoticeExpiryCheck();
  renderPlayerNoticeBanner();

  const mainEl = document.querySelector("main.container");
  if (!mainEl) return;

  const controls = mainEl.querySelectorAll("input, select, textarea");
  controls.forEach((ctrl, index) => {
    if (!ctrl || ctrl.closest("#login-firebase")) return;
    const key = buildFieldKey(ctrl, index);
    if (!isValidFieldKey(key)) return;
    if (!Object.prototype.hasOwnProperty.call(effectiveFields, key)) return;

    const savedVal = effectiveFields[key];
    if (ctrl.type === "checkbox") {
      ctrl.checked = Boolean(savedVal);
    } else if (typeof savedVal === "string" || typeof savedVal === "number") {
      ctrl.value = normalizeControlValue(ctrl, String(savedVal));
    }
  });

  parseAbilitiesFromHiddenInput();
  renderNenAbilitiesList();

  recalculateSkillsTable();
  const normalizedFields = collectSheetData().fields;
  captureBaselineFields(normalizedFields);
  state.lastSavedSnapshot = computeFieldsSnapshot(normalizedFields);
  syncNenCategoryFromSelect();
  syncAdminQuickInputsFromSheet();
  applySheetReadOnlyState();
  renderAdminCommandFunctionsBelow();
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
      } else if (ctrl.id === "hab-custo-input") {
        ctrl.value = "2";
      } else if (ctrl.id === "guilda-gasto-valor") {
        ctrl.value = "10";
      } else {
        ctrl.value = "0";
      }
    } else if (ctrl.id === "rank-val") {
      ctrl.value = "E";
    } else if (ctrl.id === "habilidades-nen-json") {
      ctrl.value = "[]";
    } else {
      ctrl.value = "";
    }
  });

  state.nenAbilities = [];
  renderNenAbilitiesList();
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
    // Ignora falha
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
          state.adminDraftUid = state.adminTargetUid;
          state.adminRecentUids = loadRecentAdminUidsFromStorage();
          if (state.adminTargetUid) recordRecentAdminUid(state.adminTargetUid);
        } else {
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
        state.adminTargetUid = "";
        state.adminDraftUid = "";
        state.adminRecentUids = [];
        state.adminReadOnly = false;
        state.adminActiveCommand = "";
        state.adminAllCommandsActive = false;
        state.activeNotice = null;
        scheduleNoticeExpiryCheck();
        saveAdminTargetUidToStorage("");
      }
      updateAuthUI();
      updateScreenAccess();
      if (user) {
        if (!state.isDeleting) {
          const targetUid = getActiveTargetUid();
          const isRemoteTarget = user.uid === ADMIN_UID && targetUid && targetUid !== user.uid;
          await loadFromFirestore(targetUid || user.uid, isRemoteTarget);
        }
      } else if (!state.offlineMode) {
        resetSheetFieldsToDefault();
      }
    });
  } catch (err) {
    state.firebaseReady = false;
    setEntradaStatus(formatDatabaseOrHostingError(err));
  }
}

/* --------------------------------------------------------------------------
   Persistência no Cloud Firestore + LocalStorage
   -------------------------------------------------------------------------- */
async function loadFromFirestore(uidToLoad, isRemoteTarget = false) {
  const targetUid = sanitizeTargetUid(uidToLoad);
  if (!targetUid) return;

  if (!state.firebaseReady || !state.db || !state.firebaseModules) {
    if (!isRemoteTarget) {
      const localData = loadLocalData();
      if (localData) applySheetData(localData);
    }
    return;
  }

  const { doc, getDoc } = state.firebaseModules.firestoreMod;
  const docRef = doc(state.db, FIRESTORE_COLLECTION, targetUid);

  try {
    const snap = await getDoc(docRef);
    if (snap.exists()) {
      const cloudData = snap.data();
      resetSheetFieldsToDefault();
      applySheetData(cloudData);
      if (!isRemoteTarget) {
        saveLocalData(cloudData);
      }
      setStatusBanner(
        isRemoteTarget
          ? `Ficha do UID ${targetUid} carregada da nuvem.`
          : "Ficha carregada e sincronizada com a nuvem.",
        "success"
      );
    } else {
      resetSheetFieldsToDefault();
      if (!isRemoteTarget) {
        const localData = loadLocalData();
        if (localData && localData.fields && Object.keys(localData.fields).length > 0) {
          applySheetData(localData);
          setStatusBanner("Dados locais restaurados. Clique em 'Salvar na nuvem' para sincronizar.", "info");
        } else {
          setStatusBanner("Nova ficha pronta. Preencha os campos para salvar automaticamente.", "info");
        }
      } else {
        setStatusBanner(`Nenhuma ficha salva encontrada para o UID ${targetUid}.`, "info");
      }
    }
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    if (!isRemoteTarget) {
      const localData = loadLocalData();
      if (localData) applySheetData(localData);
    }
    setStatusBanner(
      code === "permission-denied"
        ? "Permissão negada no Firestore ao carregar a ficha."
        : "Não foi possível carregar da nuvem agora. Verifique sua conexão.",
      "error"
    );
  }
}

async function persistSheet(forceImmediate = false) {
  if (isInspectionReadOnlyActive()) {
    setStatusBanner("Modo somente leitura ativo: alterações não foram salvas.", "warning");
    return;
  }

  if (state.saveTimer) {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
  }

  const payload = buildSanitizedCloudPayload();
  const snapshot = computeFieldsSnapshot(payload.fields);

  if (!forceImmediate && snapshot && snapshot === state.lastSavedSnapshot) {
    return;
  }

  if (state.offlineMode || !state.user) {
    state.lastSavedSnapshot = snapshot;
    captureBaselineFields(payload.fields);
    if (forceImmediate) {
      setStatusBanner(
        "Modo offline/local ativo: os dados permanecem apenas nesta aba e serão perdidos ao recarregar.",
        "warning"
      );
    }
    return;
  }

  const targetUid = getActiveTargetUid();
  const isRemoteTarget = isCurrentUserAdmin() && targetUid !== state.user.uid;
  if (!isRemoteTarget) {
    saveLocalData(payload);
  }

  if (!state.firebaseReady || !state.db || !state.firebaseModules) {
    state.lastSavedSnapshot = snapshot;
    captureBaselineFields(payload.fields);
    if (forceImmediate) {
      setStatusBanner("Salvo localmente no navegador (nuvem indisponível).", "warning");
    }
    return;
  }

  const now = Date.now();
  const elapsed = now - state.lastCloudWriteAt;
  if (!forceImmediate && elapsed < MIN_CLOUD_SAVE_INTERVAL_MS) {
    scheduleAutoSave(MIN_CLOUD_SAVE_INTERVAL_MS - elapsed + 100);
    return;
  }

  if (state.isSaving) {
    scheduleAutoSave(900);
    return;
  }

  state.isSaving = true;
  try {
    const { doc, setDoc } = state.firebaseModules.firestoreMod;
    const docRef = doc(state.db, FIRESTORE_COLLECTION, targetUid);
    await setDoc(docRef, payload);

    state.lastCloudWriteAt = Date.now();
    state.lastSavedSnapshot = snapshot;
    captureBaselineFields(payload.fields);

    if (state.adminActiveCommand === "/diff") {
      handleAdminShowDiff();
    }

    if (forceImmediate) {
      setStatusBanner(
        isRemoteTarget
          ? `Alterações salvas na nuvem para o UID ${targetUid}.`
          : "Ficha salva na nuvem com sucesso.",
        "success"
      );
    }
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    setStatusBanner(
      code === "permission-denied"
        ? "Permissão negada no Firestore ao salvar a ficha."
        : "Erro ao sincronizar ficha com a nuvem.",
      "error"
    );
  } finally {
    state.isSaving = false;
  }
}

function scheduleAutoSave(delayMs = 1300) {
  if (isInspectionReadOnlyActive()) return;
  if (state.saveTimer) {
    clearTimeout(state.saveTimer);
  }
  state.saveTimer = setTimeout(() => {
    state.saveTimer = null;
    persistSheet(false);
  }, delayMs);
}

/* --------------------------------------------------------------------------
   Autenticação Firebase (Login, Cadastro, Sair, Limpar Ficha, Excluir Conta)
   -------------------------------------------------------------------------- */
function updatePasswordVisibilityUI() {
  const passInput = document.getElementById("auth-password");
  const toggleBtn = document.getElementById("auth-toggle-password");
  if (passInput) {
    passInput.type = state.showPassword ? "text" : "password";
  }
  if (toggleBtn) {
    toggleBtn.textContent = state.showPassword ? "Ocultar" : "Mostrar";
    toggleBtn.setAttribute("aria-pressed", state.showPassword ? "true" : "false");
  }
}

function updateAuthModeUI() {
  const submitBtn = document.getElementById("auth-submit-btn");
  const toggleModeBtn = document.getElementById("auth-toggle-mode");
  const passInput = document.getElementById("auth-password");

  const isRegister = state.authMode === "register";
  if (submitBtn) {
    submitBtn.textContent = isRegister ? "Criar conta e entrar" : "Entrar";
  }
  if (toggleModeBtn) {
    toggleModeBtn.textContent = isRegister ? "Já tenho conta (Entrar)" : "Criar nova conta";
  }
  if (passInput) {
    passInput.setAttribute("autocomplete", isRegister ? "new-password" : "current-password");
  }
}

function updateAuthUI() {
  const loggedInBox = document.getElementById("auth-logged-in");
  const offlineBox = document.getElementById("offline-session-box");
  const userEmailEl = document.getElementById("auth-user-email");

  if (state.user) {
    if (loggedInBox) loggedInBox.hidden = false;
    if (offlineBox) offlineBox.hidden = true;
    if (userEmailEl) {
      renderSafeText(userEmailEl, state.user.email || state.user.uid || "Agente", 120);
    }
  } else if (state.offlineMode) {
    if (loggedInBox) loggedInBox.hidden = true;
    if (offlineBox) offlineBox.hidden = false;
    if (userEmailEl) userEmailEl.textContent = "";
  } else {
    if (loggedInBox) loggedInBox.hidden = true;
    if (offlineBox) offlineBox.hidden = true;
    if (userEmailEl) userEmailEl.textContent = "";
  }
}

async function handleAuthFormSubmit(event) {
  event.preventDefault();
  if (event && event.isTrusted === false) return;

  const emailEl = document.getElementById("auth-email");
  const passEl = document.getElementById("auth-password");
  const submitBtn = document.getElementById("auth-submit-btn");

  const email = sanitizeSingleLine(emailEl ? emailEl.value : "", 160);
  const password = String(passEl ? passEl.value : "");

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    setEntradaStatus("Informe um endereço de e-mail válido.");
    if (emailEl) emailEl.focus();
    return;
  }

  if (password.length < 6) {
    setEntradaStatus("A senha deve ter pelo menos 6 caracteres.");
    if (passEl) passEl.focus();
    return;
  }

  if (!state.firebaseReady || !state.auth || !state.firebaseModules) {
    setEntradaStatus("Conectando ao Firebase... Aguarde um instante ou use o modo offline/local.");
    await initFirebase();
    if (!state.firebaseReady || !state.auth || !state.firebaseModules) {
      return;
    }
  }

  if (submitBtn) submitBtn.disabled = true;
  setEntradaStatus(
    state.authMode === "register" ? "Criando sua conta no Firebase..." : "Entrando na sua conta..."
  );

  try {
    await checkEnvironmentAndFirestoreBeforeLogin();
    const { signInWithEmailAndPassword, createUserWithEmailAndPassword } =
      state.firebaseModules.authMod;

    if (state.authMode === "register") {
      await createUserWithEmailAndPassword(state.auth, email, password);
    } else {
      await signInWithEmailAndPassword(state.auth, email, password);
    }
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    if (
      code === "offline-browser" ||
      code === "unavailable" ||
      code === "deadline-exceeded" ||
      code === "failed-precondition"
    ) {
      setEntradaStatus(formatDatabaseOrHostingError(err));
    } else {
      setEntradaStatus(mapFirebaseAuthError(err));
    }
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

async function handleSignOut(event) {
  if (event && event.isTrusted === false) return;

  if (state.saveTimer) {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
  }

  if (state.user && state.firebaseReady && state.auth && state.firebaseModules) {
    try {
      await persistSheet(true);
      await state.firebaseModules.authMod.signOut(state.auth);
    } catch {
      setStatusBanner("Erro ao encerrar sessão no Firebase.", "error");
      return;
    }
  }

  state.user = null;
  state.offlineMode = false;
  state.adminTargetUid = "";
  state.adminDraftUid = "";
  state.adminReadOnly = false;
  state.activeNotice = null;
  scheduleNoticeExpiryCheck();
  saveAdminTargetUidToStorage("");
  clearAuthSensitiveInputs();
  setStatusBanner("");
  setEntradaStatus("");
  updateAuthUI();
  updateScreenAccess();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function handleConfirmClearSheet(event) {
  if (event && event.isTrusted === false) return;

  const confirmBox = document.getElementById("sheet-clear-confirm-box");
  if (confirmBox) confirmBox.hidden = true;

  if (isInspectionReadOnlyActive()) {
    setStatusBanner("Desative 'Somente leitura' antes de excluir a ficha.", "warning");
    return;
  }

  resetSheetFieldsToDefault();
  state.activeNotice = null;
  scheduleNoticeExpiryCheck();
  renderPlayerNoticeBanner();

  if (state.offlineMode || !state.user) {
    clearLocalData();
    setStatusBanner("Ficha limpa na sessão offline/local.", "success");
    return;
  }

  const targetUid = getActiveTargetUid();
  const isRemoteTarget = isCurrentUserAdmin() && targetUid !== state.user.uid;
  if (!isRemoteTarget) {
    clearLocalData();
  }

  if (state.firebaseReady && state.db && state.firebaseModules && targetUid) {
    try {
      const { doc, deleteDoc } = state.firebaseModules.firestoreMod;
      await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, targetUid));
      state.lastSavedSnapshot = "";
      setStatusBanner("Ficha excluída da nuvem e zerada com sucesso.", "success");
    } catch (err) {
      const code = err && typeof err.code === "string" ? err.code : "";
      setStatusBanner(
        code === "permission-denied"
          ? "Permissão negada no Firestore ao excluir a ficha."
          : "Ficha zerada na tela, mas houve erro ao apagar no Firestore.",
        "error"
      );
    }
  }
}

async function handleConfirmDeleteAccount(event) {
  if (event && event.isTrusted === false) return;
  if (!state.user || !state.firebaseReady || !state.auth || !state.firebaseModules) return;

  const confirmBox = document.getElementById("auth-delete-confirm-box");
  if (confirmBox) confirmBox.hidden = true;

  const currentUser = state.user;
  const uid = currentUser.uid;
  state.isDeleting = true;

  try {
    if (state.db) {
      const { doc, deleteDoc } = state.firebaseModules.firestoreMod;
      await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, uid));
    }

    await state.firebaseModules.authMod.deleteUser(currentUser);
    clearLocalData();
    resetSheetFieldsToDefault();
    state.user = null;
    state.offlineMode = false;
    state.adminTargetUid = "";
    saveAdminTargetUidToStorage("");
    updateAuthUI();
    updateScreenAccess();
    setEntradaStatus("Conta e ficha excluídas permanentemente.");
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "";
    if (code === "auth/requires-recent-login") {
      setStatusBanner(
        "Por segurança, saia e entre novamente antes de excluir sua conta.",
        "warning"
      );
    } else {
      setStatusBanner("Não foi possível excluir a conta agora.", "error");
    }
  } finally {
    state.isDeleting = false;
  }
}

/* --------------------------------------------------------------------------
   Inicialização e Eventos da Interface
   -------------------------------------------------------------------------- */
function bindUIEvents() {
  const authForm = document.getElementById("auth-form");
  if (authForm) {
    authForm.addEventListener("submit", handleAuthFormSubmit);
  }

  const togglePassBtn = document.getElementById("auth-toggle-password");
  if (togglePassBtn) {
    togglePassBtn.addEventListener("click", () => {
      state.showPassword = !state.showPassword;
      updatePasswordVisibilityUI();
    });
  }

  const toggleModeBtn = document.getElementById("auth-toggle-mode");
  if (toggleModeBtn) {
    toggleModeBtn.addEventListener("click", () => {
      state.authMode = state.authMode === "login" ? "register" : "login";
      setEntradaStatus("");
      updateAuthModeUI();
    });
  }

  const offlineBtn = document.getElementById("btn-entrar-offline");
  if (offlineBtn) {
    offlineBtn.addEventListener("click", enterOfflineTemporaryMode);
  }

  const voltarEntradaBtn = document.getElementById("btn-voltar-entrada");
  if (voltarEntradaBtn) {
    voltarEntradaBtn.addEventListener("click", handleSignOut);
  }

  const irLoginNuvemBtn = document.getElementById("btn-ir-login-nuvem");
  if (irLoginNuvemBtn) {
    irLoginNuvemBtn.addEventListener("click", handleSignOut);
  }

  const logoutBtn = document.getElementById("auth-logout-btn");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", handleSignOut);
  }

  const saveSheetBtn = document.getElementById("btn-save-sheet");
  if (saveSheetBtn) {
    saveSheetBtn.addEventListener("click", () => persistSheet(true));
  }

  const syncBtn = document.getElementById("auth-sync-btn");
  if (syncBtn) {
    syncBtn.addEventListener("click", () => persistSheet(true));
  }

  const clearOpenBtn = document.getElementById("sheet-clear-open-btn");
  const clearBox = document.getElementById("sheet-clear-confirm-box");
  const clearConfirmBtn = document.getElementById("sheet-clear-confirm-btn");
  const clearCancelBtn = document.getElementById("sheet-clear-cancel-btn");
  if (clearOpenBtn && clearBox) {
    clearOpenBtn.addEventListener("click", () => {
      clearBox.hidden = !clearBox.hidden;
    });
  }
  if (clearCancelBtn && clearBox) {
    clearCancelBtn.addEventListener("click", () => {
      clearBox.hidden = true;
    });
  }
  if (clearConfirmBtn) {
    clearConfirmBtn.addEventListener("click", handleConfirmClearSheet);
  }

  const clearOfflineBtn = document.getElementById("sheet-clear-offline-btn");
  if (clearOfflineBtn) {
    clearOfflineBtn.addEventListener("click", handleConfirmClearSheet);
  }

  const deleteOpenBtn = document.getElementById("auth-delete-open-btn");
  const deleteBox = document.getElementById("auth-delete-confirm-box");
  const deleteConfirmBtn = document.getElementById("auth-delete-confirm-btn");
  const deleteCancelBtn = document.getElementById("auth-delete-cancel-btn");
  if (deleteOpenBtn && deleteBox) {
    deleteOpenBtn.addEventListener("click", () => {
      deleteBox.hidden = !deleteBox.hidden;
    });
  }
  if (deleteCancelBtn && deleteBox) {
    deleteCancelBtn.addEventListener("click", () => {
      deleteBox.hidden = true;
    });
  }
  if (deleteConfirmBtn) {
    deleteConfirmBtn.addEventListener("click", handleConfirmDeleteAccount);
  }

  const nenSelect = document.getElementById("categoria-principal-nen");
  if (nenSelect) {
    nenSelect.addEventListener("change", () => {
      syncNenCategoryFromSelect();
      scheduleAutoSave();
    });
  }

  document.querySelectorAll(".nen-node[data-nen-node]").forEach((node) => {
    node.addEventListener("click", () => {
      if (isInspectionReadOnlyActive()) return;
      const key = node.getAttribute("data-nen-node") || "";
      if (nenSelect && key) {
        nenSelect.value = key;
      }
      applyNenCategoryTheme(key);
      scheduleAutoSave();
    });
  });

  const addHabBtn = document.getElementById("btn-adicionar-habilidade");
  if (addHabBtn) {
    addHabBtn.addEventListener("click", handleAddNenAbility);
  }

  const exportJsonBtn = document.getElementById("btn-exportar-json-usuario");
  if (exportJsonBtn) {
    exportJsonBtn.addEventListener("click", handleUserExportJson);
  }

  const printPdfBtn = document.getElementById("btn-imprimir-ficha-pdf");
  if (printPdfBtn) {
    printPdfBtn.addEventListener("click", () => {
      window.print();
    });
  }

  const autoCalcCheck = document.getElementById("auto-calc-status");
  if (autoCalcCheck) {
    autoCalcCheck.addEventListener("change", () => {
      recalculateSkillsTable();
      scheduleAutoSave();
    });
  }

  const spendGuildBtn = document.getElementById("btn-guilda-gastar-moedas");
  if (spendGuildBtn) {
    spendGuildBtn.addEventListener("click", () => {
      const valEl = document.getElementById("guilda-gasto-valor");
      const reasonEl = document.getElementById("guilda-gasto-motivo");
      const amount = Math.max(1, Math.trunc(Number(valEl ? valEl.value : 0) || 0));
      const reason = sanitizeSingleLine(reasonEl ? reasonEl.value : "", 80) || "Gasto na Guilda";
      if (spendGuildCoins(amount, reason)) {
        if (reasonEl) reasonEl.value = "";
      }
    });
  }

  const importJsonInput = document.getElementById("input-arquivo-json-usuario");
  if (importJsonInput) {
    importJsonInput.addEventListener("change", handleUserImportJsonFile);
  }

  const importJsonBtn = document.getElementById("btn-importar-json-usuario");
  if (importJsonBtn && importJsonInput) {
    importJsonBtn.addEventListener("click", () => {
      importJsonInput.click();
    });
  }

  const slotSelect = document.getElementById("ficha-slot-select");
  if (slotSelect) {
    slotSelect.addEventListener("change", (e) => handleSwitchAccountSlot(e.target.value));
  }

  const newSlotBtn = document.getElementById("btn-novo-slot-ficha");
  if (newSlotBtn) {
    newSlotBtn.addEventListener("click", handleCreateNewAccountSlot);
  }

  const delSlotBtn = document.getElementById("btn-excluir-slot-ficha");
  if (delSlotBtn) {
    delSlotBtn.addEventListener("click", handleDeleteCurrentAccountSlot);
  }

  const lgpdBtn = document.getElementById("lgpd-accept-btn");
  if (lgpdBtn) {
    lgpdBtn.addEventListener("click", aceitarLgpdBanner);
  }

  const footerDetailsBtn = document.getElementById("btn-rodape-detalhes");
  const footerPanel = document.getElementById("rodape-painel-lgpd");
  if (footerDetailsBtn && footerPanel) {
    footerDetailsBtn.addEventListener("click", () => {
      const nextHidden = !footerPanel.hidden;
      footerPanel.hidden = nextHidden;
      footerDetailsBtn.setAttribute("aria-expanded", nextHidden ? "false" : "true");
    });
  }

  const mainEl = document.querySelector("main.container");
  if (mainEl) {
    mainEl.addEventListener("input", (e) => {
      const target = e.target;
      if (!target || target.closest("#login-firebase")) return;
      recalculateSkillsTable();
      scheduleAutoSave();
    });

    mainEl.addEventListener("change", (e) => {
      const target = e.target;
      if (!target || target.closest("#login-firebase")) return;
      recalculateSkillsTable();
      scheduleAutoSave();
    });
  }

  document.querySelectorAll(".abas .aba-btn[data-secao-alvo]").forEach((link) => {
    link.addEventListener("click", () => {
      const targetId = link.dataset.secaoAlvo || "dados-agente";
      setActiveSectionIndicator(targetId);
    });
  });

  window.addEventListener("scroll", scheduleScrollSectionSync, { passive: true });
  window.addEventListener("resize", scheduleScrollSectionSync, { passive: true });
}

document.addEventListener("DOMContentLoaded", () => {
  initConsoleSecurityGuard();
  hardenExternalLinks();
  setLgpdBannerVisibility(hasCookieConsent());
  renderGuildShopCatalog();
  syncSlotDropdownUI();
  updatePasswordVisibilityUI();
  updateAuthModeUI();
  updateAuthUI();
  updateScreenAccess();
  bindUIEvents();
  initFirebase();
});
