/* ==========================================================================
   Ordem de Arkan - Ficha de Agente (script.js)
   Segurança front-end (XSS, Prototype Pollution, integridade e console guard)
   + Firebase Authentication & Cloud Firestore + conformidade LGPD
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

const state = {
  user: null,
  firebaseReady: false,
  auth: null,
  db: null,
  firebaseModules: null,
  authMode: "login",
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

function setStatusBanner(message, type = "info") {
  const banner = document.getElementById("status-banner");
  if (!banner) return;
  const cleanMessage = sanitizeSingleLine(message, 220);
  const allowedTypes = ["info", "success", "warning", "error"];
  banner.textContent = cleanMessage;
  banner.dataset.statusType = allowedTypes.includes(type) ? type : "info";
  banner.hidden = !cleanMessage;
}

function hasCookieConsent() {
  try {
    return localStorage.getItem(STORAGE_KEYS.COOKIE_CONSENT) === "accepted";
  } catch {
    return false;
  }
}

/* --------------------------------------------------------------------------
   Coleta e Aplicação Segura de Dados na Ficha
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

function applySheetData(data) {
  if (!data || typeof data !== "object" || !data.fields || typeof data.fields !== "object") {
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
}

function saveLocalData(data) {
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
    setStatusBanner(
      "Configure a apiKey no script.js para conectar ao Firebase. Salvando localmente.",
      "warning"
    );
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
      updateAuthUI();

      if (user) {
        if (!state.isDeleting) {
          setStatusBanner(
            `Conectado como ${sanitizeSingleLine(user.email || "agente", 160)}. Carregando ficha...`,
            "info"
          );
          await loadFromFirestore(user.uid);
        }
      } else if (!state.isDeleting) {
        setStatusBanner("Faça login para salvar e carregar sua ficha no Firebase.", "info");
      }
    });
  } catch (err) {
    console.error("Erro ao iniciar Firebase:", err);
    setStatusBanner("Sem conexão com o Firebase no momento. Dados locais disponíveis.", "warning");
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
      const initialData = collectSheetData();
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
  if (!state.firebaseReady || !state.db || !uid) return false;
  const { doc, setDoc } = state.firebaseModules.firestoreMod;
  const docRef = doc(state.db, FIRESTORE_COLLECTION, uid);
  await setDoc(docRef, data, { merge: true });
  return true;
}

async function handleAuthSubmit(event) {
  event.preventDefault();
  if (!state.firebaseReady || !state.auth) {
    setStatusBanner("Firebase ainda não foi inicializado.", "warning");
    return;
  }

  const emailEl = document.getElementById("auth-email");
  const passEl = document.getElementById("auth-password");
  const email = sanitizeSingleLine(emailEl ? emailEl.value : "", 160);
  const password = passEl ? passEl.value : "";

  if (!email || password.length < 6) {
    setStatusBanner("Preencha um e-mail válido e uma senha com pelo menos 6 caracteres.", "warning");
    return;
  }

  const { signInWithEmailAndPassword, createUserWithEmailAndPassword } = state.firebaseModules.authMod;

  try {
    setStatusBanner(state.authMode === "register" ? "Criando conta..." : "Entrando...", "info");
    if (state.authMode === "register") {
      await createUserWithEmailAndPassword(state.auth, email, password);
    } else {
      await signInWithEmailAndPassword(state.auth, email, password);
    }
    if (passEl) passEl.value = "";
  } catch (err) {
    console.error("Falha na autenticação:", err);
    setStatusBanner("Não foi possível autenticar. Confira e-mail, senha e o método E-mail/Senha no Firebase.", "error");
  }
}

async function handleLogout() {
  if (!state.firebaseReady || !state.auth) return;
  try {
    const { signOut } = state.firebaseModules.authMod;
    await signOut(state.auth);
    setStatusBanner("Você saiu da conta Firebase.", "info");
  } catch (err) {
    console.error("Erro ao sair:", err);
    setStatusBanner("Erro ao encerrar a sessão.", "error");
  }
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

    const confirmBox = document.getElementById("auth-delete-confirm-box");
    if (confirmBox) confirmBox.hidden = true;

    setStatusBanner("Conta e ficha excluídas permanentemente do Firebase.", "success");
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
    saveLocalData(payload);

    if (state.firebaseReady && state.user) {
      await saveToFirestore(state.user.uid, payload);
      setStatusBanner("Ficha salva no banco de dados Firebase.", "success");
    } else if (hasCookieConsent()) {
      setStatusBanner("Alterações salvas localmente. Faça login para salvar no Firebase.", "info");
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
function updateAuthUI() {
  const loggedOutBox = document.getElementById("auth-logged-out");
  const loggedInBox = document.getElementById("auth-logged-in");
  const userEmailEl = document.getElementById("auth-user-email");
  const submitBtn = document.getElementById("auth-submit-btn");
  const toggleBtn = document.getElementById("auth-toggle-mode");
  const confirmBox = document.getElementById("auth-delete-confirm-box");

  if (confirmBox) confirmBox.hidden = true;

  if (state.user) {
    if (loggedOutBox) loggedOutBox.hidden = true;
    if (loggedInBox) loggedInBox.hidden = false;
    renderSafeText(userEmailEl, state.user.email || "Conta ativa", 160);
  } else {
    if (loggedOutBox) loggedOutBox.hidden = false;
    if (loggedInBox) loggedInBox.hidden = true;
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
  }
}

function initLgpdBanner() {
  const banner = document.getElementById("lgpd-banner");
  const acceptBtn = document.getElementById("lgpd-accept-btn");
  if (!banner) return;

  banner.hidden = hasCookieConsent();

  if (acceptBtn) {
    acceptBtn.addEventListener("click", () => {
      try {
        localStorage.setItem(STORAGE_KEYS.COOKIE_CONSENT, "accepted");
      } catch {
        // Ignora falha de armazenamento
      }
      banner.hidden = true;
      saveLocalData(collectSheetData());
    });
  }
}

function bindEvents() {
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

  const deleteOpenBtn = document.getElementById("auth-delete-open-btn");
  const deleteConfirmBox = document.getElementById("auth-delete-confirm-box");
  const deleteConfirmBtn = document.getElementById("auth-delete-confirm-btn");
  const deleteCancelBtn = document.getElementById("auth-delete-cancel-btn");

  if (deleteOpenBtn && deleteConfirmBox) {
    deleteOpenBtn.addEventListener("click", () => {
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
  }

  updateAuthUI();
  bindEvents();
  initFirebase();
});
