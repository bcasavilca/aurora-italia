// Menu hamburguer + icones: abre/fecha, mostra itens por estado, badge ✉️
document.addEventListener("DOMContentLoaded", async () => {
  const ham = document.getElementById("ham");
  const drop = document.getElementById("drop");
  if (ham && drop) {
    ham.addEventListener("click", (e) => {
      e.stopPropagation();
      drop.hidden = !drop.hidden;
      ham.setAttribute("aria-expanded", String(!drop.hidden));
    });
    document.addEventListener("click", (e) => {
      if (!drop.hidden && !drop.contains(e.target)) {
        drop.hidden = true;
        ham.setAttribute("aria-expanded", "false");
      }
    });
    drop.querySelectorAll("a").forEach((a) =>
      a.addEventListener("click", () => { drop.hidden = true; })
    );
  }

  let user = null;
  try {
    const r = await fetch("/api/me", { credentials: "same-origin" });
    user = (await r.json()).user;
  } catch { user = null; }
  if (!drop) return;

  const show = (sel, on) =>
    drop.querySelectorAll(sel).forEach((el) => { el.hidden = !on; });

  if (!user) {
    // visitante: só Accedi + Crea account
    show('a[href="index.html"], a[href="publicar.html"], a[href="chat.html"], a[href="dashboard.html"], .email, #esci', false);
    show('a[href="login.html"], a[href="registrar.html"]', true);
    return;
  }

  // logado: icones + dashboard + email + esci
  show('a[href="index.html"], a[href="publicar.html"], a[href="chat.html"], a[href="dashboard.html"], .email, #esci', true);
  show('a[href="login.html"], a[href="registrar.html"]', false);
  const em = drop.querySelector(".email");
  if (em) { em.hidden = false; em.textContent = user.email; em.title = user.email; }
  const out = document.getElementById("esci");
  if (out) {
    out.hidden = false;
    out.onclick = async () => {
      await fetch("/api/logout", { method: "POST", credentials: "same-origin" });
      location.href = "index.html";
    };
  }
  try {
    const r = await fetch("/api/conversas", { credentials: "same-origin" });
    if (r.ok) {
      const n = (await r.json()).reduce((s, c) => s + (c.naolidas || 0), 0);
      const badge = drop.querySelector(".msg-badge");
      if (badge && n > 0) {
        badge.hidden = false;
        badge.textContent = n > 9 ? "9+" : String(n);
      }
    }
  } catch {}
});
