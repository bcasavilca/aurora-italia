// Email Aurora — layout compatível com o tema vibrante do site.
// HTML de email usa estilo inline + tabelas (a maioria dos clientes ignora <style>).
function base({ titulo, corpo, botao }) {
  const btn = botao
    ? `<table role="presentation" cellpadding="0" cellspacing="0" style="margin:24px 0 8px 0;"><tr><td align="center" bgcolor="#ff2e63" style="border-radius:999px;background-color:#ff2e63;"><a href="${botao.url}" style="display:inline-block;padding:14px 32px;color:#ffffff;font-family:Arial,sans-serif;font-size:16px;font-weight:bold;text-decoration:none;border-radius:999px;">${botao.texto}</a></td></tr></table>
       <p style="margin:8px 0 0 0;font-size:12px;color:#a08090;font-family:Arial,sans-serif;">Se il pulsante non funziona, copia questo link:<br><a href="${botao.url}" style="color:#ff6b9d;word-break:break-all;">${botao.url}</a></p>`
    : "";
  return `<!DOCTYPE html><html lang="it"><body style="margin:0;padding:0;background-color:#14060d;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#14060d;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background-color:#1f0a14;border:1px solid #3d1425;border-radius:16px;">
<tr><td style="padding:28px 28px 8px 28px;text-align:center;">
<p style="margin:0;font-family:Georgia,serif;font-size:26px;font-weight:bold;letter-spacing:4px;color:#ffffff;">AURORA</p>
<p style="margin:6px 0 0 0;font-family:Arial,sans-serif;font-size:12px;color:#ff6b9d;">Solo maggiorenni 18+</p>
</td></tr>
<tr><td style="padding:16px 28px 8px 28px;">
<h1 style="margin:0 0 12px 0;font-family:Arial,sans-serif;font-size:22px;color:#ffffff;">${titulo}</h1>
<div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.6;color:#e8c4d0;">${corpo}</div>
${btn}
</td></tr>
<tr><td style="padding:20px 28px 28px 28px;border-top:1px solid #3d1425;text-align:center;">
<p style="margin:0;font-family:Arial,sans-serif;font-size:12px;color:#a08090;">© 2026 Aurora — Solo maggiorenni 18+</p>
</td></tr>
</table>
</td></tr>
</table>
</body></html>`;
}

function resetPassword(url) {
  return base({
    titulo: "Reimposta la tua password",
    corpo: `<p style="margin:0 0 12px 0;">Ciao, hai chiesto di reimpostare la password del tuo account Aurora.</p><p style="margin:0;">Il link vale <strong style="color:#ffffff;">1 ora</strong>. Se non sei stato tu, ignora questa email.</p>`,
    botao: { texto: "Reimposta password →", url },
  });
}

module.exports = { base, resetPassword };
