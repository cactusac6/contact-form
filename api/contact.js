// /api/contact.js — univerzální kontaktní formulář pro Vercel (Node.js serverless function)
// Vyžaduje env proměnné: RESEND_API_KEY, TO_EMAIL (viz .env.example)
// Umí JSON (application/json) i multipart/form-data s přílohami fotek (pole "foto", JPG/PNG, max 5 MB, max 3 ks).
// Rozumí jak obecným polím (name/email/phone/message/website), tak polím ve tvaru
// jmeno/prijmeni/email/telefon/zprava/_honeypot/_subject/_site (použitým na webu Noellle Servis).

import Busboy from 'busboy';

const MAX_FILES = 3;
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const ALLOWED_MIME = ['image/jpeg', 'image/png'];

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  try {
    const contentType = req.headers['content-type'] || '';
    let fields = {};
    let files = [];
    let tooManyFiles = false;
    let oversizedFile = null;

    if (contentType.startsWith('multipart/form-data')) {
      ({ fields, files, tooManyFiles, oversizedFile } = await parseMultipart(req, contentType));
    } else if (req.body && typeof req.body === 'object') {
      fields = req.body; // Vercel už naparsoval application/json automaticky
    } else {
      fields = await parseJsonBody(req);
    }

    // Honeypot — tiché "success" pro boty
    const honeypot = fields._honeypot || fields.website;
    if (honeypot) {
      return res.status(200).json({ ok: true });
    }

    const name = (fields.name || `${fields.jmeno || ''} ${fields.prijmeni || ''}`).trim();
    const email = (fields.email || '').trim();
    const phone = (fields.telefon || fields.phone || '').trim();
    const message = (fields.zprava || fields.message || '').trim();

    if (oversizedFile) {
      return res.status(400).json({ ok: false, error: `Soubor „${oversizedFile}“ je větší než 5 MB.` });
    }
    if (tooManyFiles) {
      return res.status(400).json({ ok: false, error: 'Maximálně 3 soubory.' });
    }
    for (const f of files) {
      if (!ALLOWED_MIME.includes(f.mimetype)) {
        return res.status(400).json({ ok: false, error: `Soubor „${f.filename}“ musí být JPG nebo PNG.` });
      }
    }

    const errors = {};
    if (!name) errors.name = 'Vyplňte jméno.';
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'Zadejte platný e-mail.';
    if (!email && !phone) errors.contact = 'Vyplňte e-mail nebo telefon.';
    if (!message) errors.message = 'Vyplňte zprávu.';

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ ok: false, error: 'Neplatná data.', fields: errors });
    }

    const toEmail = process.env.TO_EMAIL;
    const apiKey = process.env.RESEND_API_KEY;
    if (!toEmail || !apiKey) {
      console.error('Chybí RESEND_API_KEY nebo TO_EMAIL v env.');
      return res.status(500).json({ ok: false, error: 'Server není nakonfigurován.' });
    }

    const siteTag = fields._site ? ` (${escapeHtml(fields._site)})` : '';
    const subject = fields._subject || `Nová poptávka od ${name}`;

    const html = `
      <h2>Nová poptávka z webu${siteTag}</h2>
      <p><strong>Jméno:</strong> ${escapeHtml(name)}</p>
      <p><strong>E-mail:</strong> ${escapeHtml(email || '-')}</p>
      <p><strong>Telefon:</strong> ${escapeHtml(phone || '-')}</p>
      <p><strong>Zpráva:</strong></p>
      <p>${escapeHtml(message).replace(/\n/g, '<br>')}</p>
      ${files.length ? `<p><strong>Přílohy:</strong> ${files.length} foto v příloze tohoto e-mailu.</p>` : ''}
    `;

    const payload = {
      from: process.env.FROM_EMAIL || 'Kontaktní formulář <onboarding@resend.dev>',
      to: [toEmail],
      subject,
      html,
    };
    if (email) payload.reply_to = email;
    if (files.length) {
      payload.attachments = files.map((f) => ({
        filename: f.filename || 'foto.jpg',
        content: f.buffer.toString('base64'),
      }));
    }

    const resendRes = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
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

function parseMultipart(req, contentType) {
  return new Promise((resolve, reject) => {
    const bb = Busboy({
      headers: { 'content-type': contentType },
      limits: { fileSize: MAX_FILE_BYTES, files: MAX_FILES + 1 },
    });
    const fields = {};
    const files = [];
    let tooManyFiles = false;
    let oversizedFile = null;
    let fileCount = 0;

    bb.on('field', (name, val) => {
      fields[name] = val;
    });

    bb.on('file', (name, stream, info) => {
      fileCount += 1;
      if (fileCount > MAX_FILES) {
        tooManyFiles = true;
        stream.resume();
        return;
      }
      const chunks = [];
      stream.on('data', (chunk) => chunks.push(chunk));
      stream.on('limit', () => {
        oversizedFile = info.filename;
      });
      stream.on('end', () => {
        if (!oversizedFile || oversizedFile !== info.filename) {
          files.push({ field: name, filename: info.filename, mimetype: info.mimeType, buffer: Buffer.concat(chunks) });
        }
      });
    });

    bb.on('error', reject);
    bb.on('finish', () => resolve({ fields, files, tooManyFiles, oversizedFile }));
    req.pipe(bb);
  });
}

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
