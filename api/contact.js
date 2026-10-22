// /api/contact.js — univerzální kontaktní formulář pro Vercel (Node.js serverless function)
// Vyžaduje env proměnné: RESEND_API_KEY, TO_EMAIL (viz .env.example)

export default async function handler(req, res) {
  // CORS (pro případ, že frontend běží na jiné doméně než API)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  try {
    const { name, email, phone, message, website } = req.body || {};

    // Honeypot — pole "website" musí zůstat prázdné (bot ho vyplní)
    if (website) {
      return res.status(200).json({ ok: true }); // tichy "success" pro bota
    }

    // Validace
    const errors = {};
    if (!name || !name.trim()) errors.name = 'Vyplňte jméno.';
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'Zadejte platný e-mail.';
    if (!message || !message.trim()) errors.message = 'Vyplňte zprávu.';

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ ok: false, error: 'Neplatná data.', fields: errors });
    }

    const toEmail = process.env.TO_EMAIL;
    const apiKey = process.env.RESEND_API_KEY;
    if (!toEmail || !apiKey) {
      console.error('Chybí RESEND_API_KEY nebo TO_EMAIL v env.');
      return res.status(500).json({ ok: false, error: 'Server není nakonfigurován.' });
    }

    const html = `
      <h2>Nová poptávka z webu</h2>
      <p><strong>Jméno:</strong> ${escapeHtml(name)}</p>
      <p><strong>E-mail:</strong> ${escapeHtml(email)}</p>
      <p><strong>Telefon:</strong> ${escapeHtml(phone || '-')}</p>
      <p><strong>Zpráva:</strong></p>
      <p>${escapeHtml(message).replace(/\n/g, '<br>')}</p>
    `;

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: process.env.FROM_EMAIL || 'Kontaktní formulář <onboarding@resend.dev>',
        to: [toEmail],
        reply_to: email,
        subject: `Nová poptávka od ${name}`,
        html,
      }),
    });

    if (!resendRes.ok) {
      const errText = await resendRes.text();
      console.error('Resend error:', errText);
      return res.status(502).json({ ok: false, error: 'Odeslání e-mailu se nezdařilo.' });
    }

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('Contact form error:', err);
    return res.status(500).json({ ok: false, error: 'Interní chyba serveru.' });
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
