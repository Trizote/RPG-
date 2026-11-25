/* ==========================================================================
   Ordem de Arkan - Ficha de Agente (script.js)
   Segurança front-end (XSS, Prototype Pollution, integridade e console guard)
   + Firebase Authentication & Cloud Firestore + Sessão Offline/Local temporária
   + Exclusão de ficha e exclusão de conta
   + Sincronização precisa das seções no topo conforme a rolagem
   + Cores dinâmicas conforme a Categoria Principal de Afinidade de Nen
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
  COOKIE_CONSENT: "ordem_de_arkan_lgpd_v1"
});

const FORBIDDEN_KEYS = Object.freeze(["__proto__", "constructor", "prototype"]);
const FIRESTORE_COLLECTION = "fichas_ordem_arkan";
const FIREBASE_SDK_VERSION = "10.14.1";

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
  isDeleting: false
};

/* --------------------------------------------------------------------------
   Defesa contra Prototype Pollution, XSS e Injeção via Console
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
    .slice(0, maxLength);
}

function sanitizeSingleLine(value, maxLength = 140) {
  return sanitizeText(value, maxLength).replace(/[\r\n]+/g, " ").trim();
}

function isValidFieldKey(key) {
  if (typeof key !== "string" || isForbiddenKey(key)) return false;
  return /^(id:[a-zA-Z0-9_-]{1,64}|idx:\d{1,5})$/.test(key);
}

function renderSafeText(element, text, maxLength = 220) {
  if (!element) return;
  element.textContent = sanitizeSingleLine(text, maxLength);
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

  if (hasSession) {
    syncNenCategoryFromSelect();
    window.requestAnimationFrame(() => {
      syncActiveSectionOnScroll();
    });
  }
}

function enterOfflineTemporaryMode() {
  state.offlineMode = true;
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

function collectSheetData() {
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
    } else if (ctrl.tagName === "TEXTAREA") {
      fields[key] = sanitizeText(ctrl.value, 5000);
    } else {
      fields[key] = sanitizeSingleLine(ctrl.value, 250);
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
        cleanFields[key] = String(val).slice(0, 60);
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
      ctrl.value = ctrl.tagName === "TEXTAREA"
        ? sanitizeText(String(savedVal), 5000)
        : sanitizeSingleLine(String(savedVal), 250);
    }
  });

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

  syncNenCategoryFromSelect();
}

function saveLocalData(data) {
  if (state.offlineMode) return;
  if (!hasCookieConsent()) return;
  try {
    localStorage.setItem(STORAGE_KEYS.LOCAL_SHEET, JSON.stringify(data));
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
        setEntradaStatus("");
      }
      updateAuthUI();
      updateScreenAccess();

      if (user) {
        if (!state.isDeleting) {
          setStatusBanner(
            `Conectado como ${sanitizeSingleLine(user.email || "agente", 160)}. Carregando ficha...`,
            "info"
          );
          await loadFromFirestore(user.uid);
        }
      } else if (!state.isDeleting && !state.offlineMode) {
        setStatusBanner("Faça login para salvar e carregar sua ficha no Firebase.", "info");
      }
    });
  } catch (err) {
    console.error("Erro ao iniciar Firebase:", err);
    setEntradaStatus("Sem conexão com o Firebase no momento. Você pode entrar offline/local.");
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
      saveLocalData(cloudData);
      setStatusBanner("Ficha carregada do banco de dados Firebase.", "success");
    } else {
      const initialData = buildSanitizedCloudPayload();
      await setDoc(docRef, initialData);
      saveLocalData(initialData);
      setStatusBanner("Nova ficha criada na sua conta do Firebase.", "success");
    }
  } catch (err) {
    console.error("Erro ao carregar ficha do Firestore:", err);
    setStatusBanner("Erro ao ler dados do Firebase. Verifique as regras do Firestore.", "error");
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
  return true;
}

async function handleClearSheetData() {
  if (state.isSaving || state.isDeleting) return;

  if (state.saveTimer) {
    clearTimeout(state.saveTimer);
    state.saveTimer = null;
  }

  resetSheetFieldsToDefault();
  clearLocalData();

  const clearConfirmBox = document.getElementById("sheet-clear-confirm-box");
  if (clearConfirmBox) clearConfirmBox.hidden = true;

  if (state.firebaseReady && state.db && state.user && state.user.uid) {
    const { doc, deleteDoc } = state.firebaseModules.firestoreMod;
    try {
      await deleteDoc(doc(state.db, FIRESTORE_COLLECTION, state.user.uid));
      setStatusBanner("Ficha excluída da nuvem e do navegador.", "success");
      return;
    } catch (err) {
      console.error("Erro ao excluir ficha no Firestore:", err);
      setStatusBanner("Ficha limpa na tela, mas houve erro ao apagar na nuvem.", "error");
      return;
    }
  }

  setStatusBanner("Ficha limpa.", "warning");
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  if (!state.firebaseReady || !state.auth) {
    setEntradaStatus("Firebase ainda não foi inicializado.");
    return;
  }

  const emailEl = document.getElementById("auth-email");
  const passEl = document.getElementById("auth-password");
  const email = sanitizeSingleLine(emailEl ? emailEl.value : "", 160);
  const password = passEl ? passEl.value : "";

  if (!email || password.length < 6) {
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
    if (passEl) passEl.value = "";
    state.showPassword = false;
    updatePasswordVisibilityUI();
  } catch (err) {
    console.error("Falha na autenticação:", err);
    setEntradaStatus("Não foi possível autenticar. Confira e-mail, senha e o método E-mail/Senha no Firebase.");
  }
}

async function handleLogout() {
  state.offlineMode = false;
  if (state.firebaseReady && state.auth && state.user) {
    try {
      const { signOut } = state.firebaseModules.authMod;
      await signOut(state.auth);
    } catch (err) {
      console.error("Erro ao sair:", err);
      setStatusBanner("Erro ao encerrar a sessão.", "error");
      return;
    }
  }
  updateAuthUI();
  updateScreenAccess();
  setEntradaStatus("Você saiu da sessão. Escolha como deseja entrar novamente.");
}

async function handleDeleteAccount() {
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
    state.offlineMode = false;

    const confirmBox = document.getElementById("auth-delete-confirm-box");
    if (confirmBox) confirmBox.hidden = true;

    updateAuthUI();
    updateScreenAccess();
    setEntradaStatus("Conta e ficha excluídas permanentemente do Firebase.");
  } catch (err) {
    console.error("Erro ao excluir conta:", err);
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
   Salvamento da Ficha
   -------------------------------------------------------------------------- */
async function persistSheet() {
  if (state.isSaving || state.isDeleting) return;
  state.isSaving = true;

  try {
    const payload = collectSheetData();

    if (state.offlineMode && !state.user) {
      setStatusBanner(
        "Modo offline/local: alterações não ficam salvas se você carregar a página novamente.",
        "warning"
      );
      return;
    }

    saveLocalData(payload);

    if (state.firebaseReady && state.user) {
      const cloudPayload = buildSanitizedCloudPayload();
      await saveToFirestore(state.user.uid, cloudPayload);
      setStatusBanner("Ficha salva no banco de dados Firebase.", "success");
    } else if (hasCookieConsent()) {
      setStatusBanner("Alterações salvas localmente.", "info");
    } else {
      setStatusBanner("Aceite o banner LGPD para salvar localmente ou faça login no Firebase.", "info");
    }
  } catch (err) {
    console.error("Erro ao salvar ficha:", err);
    setStatusBanner("Erro ao salvar no Firebase. Confira as permissões do Firestore.", "error");
  } finally {
    state.isSaving = false;
  }
}

function scheduleAutoSave() {
  if (state.saveTimer) clearTimeout(state.saveTimer);
  state.saveTimer = setTimeout(() => {
    persistSheet();
  }, 700);
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
    saveBtn.addEventListener("click", () => persistSheet());
  }

  const syncBtn = document.getElementById("auth-sync-btn");
  if (syncBtn) {
    syncBtn.addEventListener("click", () => persistSheet());
  }

  const mainEl = document.querySelector("main.container");
  if (mainEl) {
    const handleFieldUpdate = (event) => {
      if (event.target && event.target.closest("#login-firebase")) return;
      scheduleAutoSave();
    };
    mainEl.addEventListener("input", handleFieldUpdate);
    mainEl.addEventListener("change", handleFieldUpdate);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  initConsoleSecurityGuard();
  initLgpdBanner();

  const localData = loadLocalData();
  if (localData) {
    applySheetData(localData);
  } else {
    syncNenCategoryFromSelect();
  }

  setActiveSectionIndicator("dados-agente");
  updateAuthUI();
  updateScreenAccess();
  bindEvents();
  initFirebase();
});
