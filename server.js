// VETRINA-AURORA-HTML - backend minimo: static + auth (JSON file DB)
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const PORT = process.env.PORT || 3003;
const SITE_URL = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const DATA_FILE = path.join(__dirname, "data", "vetrina.json");
const COOKIE = "vetrina_session";

function load() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return { users: [], sessions: [], resets: [], anunci: [], conversas: [],
      promo: [{ code: "BENVENUTO", dias: 7, maxUsos: 100, usos: 0 }] };
  }
}
function save(db) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const nowHm = () => new Date().toTimeString().slice(0, 5);

let resend = null;
if (process.env.RESEND_API_KEY) {
  const { Resend } = require("resend");
  resend = new Resend(process.env.RESEND_API_KEY);
}
const FROM = process.env.EMAIL_FROM || "Aurora <onboarding@resend.dev>";

const app = express();
app.disable("x-powered-by");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// anti-bruteforce simples (memória): 15 tentativas / 15 min por IP nas rotas auth
const tentativas = new Map();
function rateLimit(req, res, next) {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
  const agora = Date.now();
  const lista = (tentativas.get(ip) || []).filter((t) => agora - t < 15 * 60 * 1000);
  if (lista.length >= 15) return res.status(429).json({ error: "Troppe richieste. Riprova tra 15 minuti." });
  lista.push(agora);
  tentativas.set(ip, lista);
  next();
}
app.use("/api/login", rateLimit);
app.use("/api/signup", rateLimit);
app.use("/api/forgot", rateLimit);
app.use("/api/reset", rateLimit);

function currentUser(req) {
  const t = req.cookies[COOKIE];
  if (!t) return null;
  const db = load();
  const s = db.sessions.find((x) => x.token === sha(t));
  if (!s || new Date(s.expiresAt) < new Date()) return null;
  return db.users.find((u) => u.id === s.userId) || null;
}

app.post("/api/signup", async (req, res) => {
  const { email, password, confirm } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email e password richiesti" });
  if (password.length < 8) return res.status(400).json({ error: "Min 8 caratteri" });
  if (confirm && password !== confirm) return res.status(400).json({ error: "Le password non corrispondono" });
  const db = load();
  if (db.users.find((u) => u.email.toLowerCase() === email.toLowerCase()))
    return res.status(400).json({ error: "Esiste già un account" });
  const u = { id: crypto.randomUUID(), email, hash: bcrypt.hashSync(password, 10), createdAt: new Date().toISOString() };
  db.users.push(u);
  const raw = crypto.randomUUID();
  db.sessions.push({ token: sha(raw), userId: u.id, expiresAt: new Date(Date.now() + 30 * 864e5).toISOString() });
  save(db);
  res.cookie(COOKIE, raw, { httpOnly: true, maxAge: 30 * 864e5, sameSite: "lax" });
  res.json({ ok: true });
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const db = load();
  const u = db.users.find((x) => x.email.toLowerCase() === (email || "").toLowerCase());
  if (!u || !bcrypt.compareSync(password || "", u.hash))
    return res.status(401).json({ error: "Email o password non validi" });
  const raw = crypto.randomUUID();
  db.sessions.push({ token: sha(raw), userId: u.id, expiresAt: new Date(Date.now() + 30 * 864e5).toISOString() });
  save(db);
  res.cookie(COOKIE, raw, { httpOnly: true, maxAge: 30 * 864e5, sameSite: "lax" });
  res.json({ ok: true });
});

app.post("/api/logout", (req, res) => {
  const t = req.cookies[COOKIE];
  if (t) {
    const db = load();
    db.sessions = db.sessions.filter((x) => x.token !== sha(t));
    save(db);
  }
  res.clearCookie(COOKIE);
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const u = currentUser(req);
  res.json({ user: u ? { email: u.email } : null });
});

// ---- ANUNCI: solo annunci reali pubblicati (niente seed/demo) ----
app.get("/api/anunci", (req, res) => {
  const db = load();
  const agora = new Date().toISOString();
  const mine = (db.anunci || []).slice().reverse();
  mine.sort((a, b) => {
    const da = a.destaqueAte && a.destaqueAte > agora ? 0 : 1;
    const dbb = b.destaqueAte && b.destaqueAte > agora ? 0 : 1;
    return da - dbb;
  });
  res.json(mine);
});

// ---- PROMO (codici lancio: evidenza gratis) ----
app.post("/api/promo", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  const { code, anuncioId } = req.body;
  if (!code || !anuncioId) return res.status(400).json({ error: "Codice e annuncio richiesti" });
  const db = load();
  const p = (db.promo || []).find((x) => x.code.toLowerCase() === String(code).toLowerCase());
  if (!p) return res.status(400).json({ error: "Codice non valido" });
  if (p.usos >= p.maxUsos) return res.status(400).json({ error: "Codice esaurito" });
  const a = (db.anunci || []).find((x) => String(x.id) === String(anuncioId));
  if (!a) return res.status(404).json({ error: "Annuncio non trovato" });
  if (a.email !== u.email) return res.status(403).json({ error: "Non tuo" });
  const agora = new Date().toISOString();
  if (a.destaqueAte && a.destaqueAte > agora) return res.status(400).json({ error: "Già in evidenza" });
  a.destaqueAte = new Date(Date.now() + p.dias * 864e5).toISOString();
  p.usos += 1;
  save(db);
  res.json({ ok: true, finoAl: a.destaqueAte });
});

let upload = null;
try {
  const multer = require("multer");
  const storage = multer.diskStorage({
    destination: (req, file, cb) => { fs.mkdirSync(path.join(__dirname, "fotos"), { recursive: true }); cb(null, path.join(__dirname, "fotos")); },
    filename: (req, file, cb) => {
      const ext = (path.extname(file.originalname) || ".jpg").toLowerCase();
      cb(null, crypto.randomUUID() + ext);
    },
  });
  upload = multer({
    storage,
    limits: { fileSize: 5 * 1024 * 1024, files: 5 },
    fileFilter: (req, file, cb) => cb(null, /^image\//.test(file.mimetype)),
  });
} catch (e) { console.log("[ANUNCI] upload disabilitato:", e.message); }

app.post("/api/anunci", upload ? upload.array("fotos", 5) : (req, res, next) => next(), (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  const { titolo, citta, servizi, prezzo, descrizione } = req.body;
  if (!titolo || !citta) return res.status(400).json({ error: "Titolo e città richiesti" });
  const db = load();
  const fotos = (req.files || []).map((f) => `/fotos/${f.filename}`);
  const a = {
    id: crypto.randomUUID(),
    titolo: String(titolo).slice(0, 80),
    citta: String(citta).slice(0, 60),
    servizi: String(servizi || "").split(",").map((s) => s.trim()).filter(Boolean).slice(0, 10),
    prezzo: Number(prezzo) || 0,
    descrizione: String(descrizione || "").slice(0, 2000),
    foto: fotos[0] || "",
    fotos,
    email: u.email,
    createdAt: new Date().toISOString(),
  };
  db.anunci = db.anunci || [];
  db.anunci.push(a);
  save(db);
  res.json({ ok: true, id: a.id });
});

app.put("/api/anunci/:id", upload ? upload.array("fotos", 5) : (req, res, next) => next(), (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  const db = load();
  const a = (db.anunci || []).find((x) => String(x.id) === String(req.params.id));
  if (!a) return res.status(404).json({ error: "Non trovato" });
  if (a.email !== u.email) return res.status(403).json({ error: "Non tuo" });
  const { titolo, citta, servizi, prezzo, descrizione } = req.body;
  if (titolo) a.titolo = String(titolo).slice(0, 80);
  if (citta) a.citta = String(citta).slice(0, 60);
  if (servizi !== undefined) a.servizi = String(servizi).split(",").map((s) => s.trim()).filter(Boolean).slice(0, 10);
  if (prezzo !== undefined && prezzo !== "") a.prezzo = Number(prezzo) || 0;
  if (descrizione !== undefined) a.descrizione = String(descrizione).slice(0, 2000);
  // remove fotos marcadas
  let rm = req.body.remove || [];
  if (!Array.isArray(rm)) rm = [rm];
  a.fotos = a.fotos || [];
  rm.forEach((f) => {
    a.fotos = a.fotos.filter((x) => x !== f);
    const fp = path.join(__dirname, "." + f);
    if (f.startsWith("/fotos/") && fp.startsWith(path.join(__dirname, "fotos")) && fs.existsSync(fp)) fs.unlinkSync(fp);
  });
  // adiciona novas (máx 5 no total)
  const novas = (req.files || []).map((f) => `/fotos/${f.filename}`);
  const espaco = Math.max(0, 5 - a.fotos.length);
  novas.slice(0, espaco).forEach((f) => a.fotos.push(f));
  novas.slice(espaco).forEach((f) => {
    const fp = path.join(__dirname, "." + f);
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
  });
  if (!a.fotos.includes(a.foto)) a.foto = a.fotos[0] || "";
  save(db);
  res.json({ ok: true });
});

app.delete("/api/anunci/:id", (req, res) => {  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  const db = load();
  const a = (db.anunci || []).find((x) => String(x.id) === String(req.params.id));
  if (!a) return res.status(404).json({ error: "Non trovato" });
  if (a.email !== u.email) return res.status(403).json({ error: "Non tuo" });
  db.anunci = db.anunci.filter((x) => String(x.id) !== String(req.params.id));
  save(db);
  (a.fotos || []).forEach((f) => {
    const fp = path.join(__dirname, "." + f);
    if (fp.startsWith(path.join(__dirname, "fotos")) && fs.existsSync(fp)) fs.unlinkSync(fp);
  });
  res.json({ ok: true });
});

app.post("/api/forgot", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email richiesta" });
  const db = load();
  const u = db.users.find((x) => x.email.toLowerCase() === email.toLowerCase());
  // resposta generica anti-enumeracao, mas gera token se existe
  if (!u) return res.json({ ok: true });
  db.resets = db.resets.filter((r) => r.userId !== u.id || r.usedAt);
  const raw = crypto.randomUUID();
  db.resets.push({ hash: sha(raw), userId: u.id, expiresAt: new Date(Date.now() + 36e5).toISOString(), usedAt: null });
  save(db);
  const link = `${SITE_URL}/reset.html?token=${raw}`;
  try {
    if (!resend) throw new Error("RESEND_API_KEY ausente");
    await resend.emails.send({
      from: FROM,
      to: email,
      subject: "Reimposta la tua password — Aurora",
      html: `<p>Ciao, clicca qui per reimpostare: <a href="${link}">Reimposta password</a> (vale 1 ora).</p>`,
    });
  } catch (e) {
    console.log(`[RESET] link para ${email}: ${link} (email falhou: ${e.message})`);
    return res.status(500).json({ error: "Email non configurata: " + e.message });
  }
  res.json({ ok: true });
});

app.post("/api/reset", async (req, res) => {
  const { token, password, confirm } = req.body;
  if (!token) return res.status(400).json({ error: "Token richiesto" });
  if (!password || password.length < 8) return res.status(400).json({ error: "Min 8 caratteri" });
  if (confirm && password !== confirm) return res.status(400).json({ error: "Le password non corrispondono" });
  const db = load();
  const r = db.resets.find((x) => x.hash === sha(token));
  if (!r) return res.status(400).json({ error: "Token non valido" });
  if (r.usedAt) return res.status(400).json({ error: "Token già utilizzato" });
  if (new Date(r.expiresAt) < new Date()) return res.status(400).json({ error: "Token scaduto" });
  const u = db.users.find((x) => x.id === r.userId);
  if (!u) return res.status(400).json({ error: "Utente non trovato" });
  u.hash = bcrypt.hashSync(password, 10);
  r.usedAt = new Date().toISOString();
  db.sessions = db.sessions.filter((s) => s.userId !== u.id);
  save(db);
  res.json({ ok: true });
});

// ---- CONVERSAS / MESSAGGI (caixa de entrada) ----
const LINK_RE = /(https?:\/\/|www\.|hxxps?:\/\/|\b[a-z0-9-]+(\.[a-z]{2,})+\b|\b(punto|dot)\s?(com|net|org|it|me|info|online|site|top|click|link)\b)/i;
const temLink = (t) => LINK_RE.test(t || "");
const LINK_ERR = "Link non consentiti in chat";
function minhasConversas(db, email) {
  return (db.conversas || [])
    .filter((c) => c.buyer === email || c.seller === email)
    .map((c) => {
      const outro = c.buyer === email ? c.seller : c.buyer;
      const last = (c.msgs || [])[(c.msgs || []).length - 1] || null;
      const seen = (c.seen || {})[email] || "1970-01-01";
      const naolidas = (c.msgs || []).filter((m) => m.from !== email && m.at > seen).length;
      return { id: c.id, anuncioId: c.anuncioId, anuncioTitolo: c.anuncioTitolo, outro, ultima: last ? last.texto : "", mia: last ? last.from === email : false, quando: last ? last.at : c.createdAt, naolidas };
    })
    .sort((a, b) => (a.quando < b.quando ? 1 : -1));
}

app.get("/api/conversas", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  res.json(minhasConversas(load(), u.email));
});

app.post("/api/conversas", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  const { anuncioId, texto } = req.body;
  if (!anuncioId || !texto || !texto.trim()) return res.status(400).json({ error: "Messaggio richiesto" });
  if (temLink(texto)) return res.status(400).json({ error: LINK_ERR });
  const db = load();
  const all = [...(db.anunci || [])];
  const a = all.find((x) => String(x.id) === String(anuncioId));
  if (!a) return res.status(404).json({ error: "Annuncio non trovato" });
  if (!a.email) return res.status(400).json({ error: "Annuncio di esempio, non contattabile" });
  if (a.email === u.email) return res.status(400).json({ error: "È il tuo annuncio" });
  db.conversas = db.conversas || [];
  let c = db.conversas.find((x) => x.anuncioId === a.id && x.buyer === u.email);
  if (!c) {
    c = { id: crypto.randomUUID(), anuncioId: a.id, anuncioTitolo: a.titolo, buyer: u.email, seller: a.email, createdAt: new Date().toISOString(), seen: {}, msgs: [] };
    db.conversas.push(c);
  }
  c.msgs.push({ id: crypto.randomUUID(), from: u.email, texto: String(texto).slice(0, 1000), at: new Date().toISOString() });
  c.seen[u.email] = new Date().toISOString();
  save(db);
  res.json({ ok: true, id: c.id });
});

app.get("/api/conversas/:id", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  const db = load();
  const c = (db.conversas || []).find((x) => String(x.id) === String(req.params.id));
  if (!c || (c.buyer !== u.email && c.seller !== u.email)) return res.status(404).json({ error: "Non trovata" });
  c.seen = c.seen || {};
  c.seen[u.email] = new Date().toISOString();
  save(db);
  res.json({ id: c.id, anuncioId: c.anuncioId, anuncioTitolo: c.anuncioTitolo, outro: c.buyer === u.email ? c.seller : c.buyer, msgs: c.msgs, eu: u.email });
});

app.post("/api/conversas/:id/msgs", (req, res) => {
  const u = currentUser(req);
  if (!u) return res.status(401).json({ error: "Devi accedere" });
  const { texto } = req.body;
  if (!texto || !texto.trim()) return res.status(400).json({ error: "Messaggio richiesto" });
  if (temLink(texto)) return res.status(400).json({ error: LINK_ERR });
  const db = load();
  const c = (db.conversas || []).find((x) => String(x.id) === String(req.params.id));
  if (!c || (c.buyer !== u.email && c.seller !== u.email)) return res.status(404).json({ error: "Non trovata" });
  c.msgs.push({ id: crypto.randomUUID(), from: u.email, texto: String(texto).slice(0, 1000), at: new Date().toISOString() });
  c.seen[u.email] = new Date().toISOString();
  save(db);
  res.json({ ok: true });
});

// ---- SEGNALAZIONI (Termini/Privacy/Segnala) ----
app.post("/api/segnalazioni", (req, res) => {
  const { anuncio, motivo, dettagli, email } = req.body || {};
  if (!dettagli || !String(dettagli).trim()) return res.status(400).json({ error: "Descrivi il problema" });
  const db = load();
  db.segnalazioni = db.segnalazioni || [];
  db.segnalazioni.push({
    id: crypto.randomUUID(),
    anuncio: String(anuncio || "").slice(0, 200),
    motivo: String(motivo || "").slice(0, 60),
    dettagli: String(dettagli).slice(0, 2000),
    email: String(email || "").slice(0, 120),
    createdAt: new Date().toISOString(),
  });
  save(db);
  res.json({ ok: true });
});

// ---- SSR home (niente flash al reload): pagina esce già filtrata ----
const HOME_FILE = path.join(__dirname, "index.html");
const escH = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function cardHTML(a) {
  return `<article class="card"><a href="anuncio.html?id=${escH(a.id)}"><div class="foto">${a.foto ? `<img src="${escH(a.foto)}" alt="">` : "<span>Nessuna foto</span>"}</div></a><div class="card-corpo"><h3><a href="anuncio.html?id=${escH(a.id)}">${escH(a.titolo)}</a></h3><p class="citta">${escH(a.citta)}</p><p class="preco">${escH(a.prezzo)} €</p><a class="ver" href="anuncio.html?id=${escH(a.id)}">Vedi annuncio →</a></div></article>`;
}
app.get(["/", "/index.html"], (req, res) => {
  try {
    let html = fs.readFileSync(HOME_FILE, "utf8");
    const u = currentUser(req);
    const lista = (load().anunci || []).slice().reverse();
    const qRaw = String(req.query.q || "");
    const q = qRaw.toLowerCase().trim();
    const citta = String(req.query.citta || "");
    const filtrati = lista.filter((a) => {
      const testo = `${a.titolo} ${a.descrizione || ""} ${a.citta}`.toLowerCase();
      if (q && !testo.includes(q)) return false;
      if (citta && a.citta !== citta) return false;
      return true;
    });
    const nris = `${filtrati.length} ${filtrati.length === 1 ? "annuncio trovato" : "annunci trovati"}`;
    const corpo = filtrati.length ? filtrati.map(cardHTML).join("") : "<p>Nessun annuncio trovato. Prova a cambiare i filtri.</p>";
    const opts = [...new Set(lista.map((a) => a.citta).filter(Boolean))].sort()
      .map((c) => `<option value="${escH(c)}"${c === citta ? " selected" : ""}>${escH(c)}</option>`).join("");
    if (u) html = html.replace('<section class="hero" id="guest-hero">', '<section class="hero is-logged" id="guest-hero">');
    if (u) {
      // Menu logado già dal server: niente "Accedi" nemmeno per un istante.
      html = html.replace('<a href="dashboard.html" hidden>', '<a href="dashboard.html">');
      html = html.replace('<span class="email" hidden></span>', `<span class="email">${escH(u.email)}</span>`);
      html = html.replace('<a href="login.html" class="btn">Accedi</a>', '<a href="login.html" class="btn" hidden>Accedi</a>');
      html = html.replace('<button class="btn link-btn" id="esci" hidden>Esci</button>', '<button class="btn link-btn" id="esci">Esci</button>');
    }
    if (qRaw) html = html.replace('name="q" id="fq"', `name="q" id="fq" value="${escH(qRaw)}"`);
    html = html.replace('<select name="citta" id="fcitta">\n        <option value="">Tutte le città</option>',
      `<select name="citta" id="fcitta">\n        <option value="">Tutte le città</option>${opts}`);
    html = html.replace('<p id="nris" style="color:#aaa">Ricerca in corso…</p>', `<p id="nris" style="color:#aaa">${nris}</p>`);
    const ini = html.indexOf("<!--GRADE-INI-->");
    const fim = html.indexOf("<!--GRADE-FIM-->");
    if (ini !== -1 && fim !== -1) html = html.slice(0, ini) + corpo + html.slice(fim + "<!--GRADE-FIM-->".length);
    res.set("Cache-Control", "no-store").type("html").send(html);
  } catch {
    res.sendFile(HOME_FILE);
  }
});

// static por ultimo
app.use("/fotos", express.static(path.join(__dirname, "fotos")));
app.use(express.static(__dirname));

app.listen(PORT, () => console.log(`VETRINA on :${PORT} SITE=${SITE_URL}`));
