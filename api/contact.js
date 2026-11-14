// /api/contact.js — univerzální kontaktní formulář pro Vercel (Node.js serverless function)
// Vyžaduje env proměnné: RESEND_API_KEY, TO_EMAIL (viz .env.example)
// Umí JSON (application/json) i multipart/form-data s přílohami fotek (pole "foto", JPG/PNG, max 5 MB, max 3 ks).
// Rozumí jak obecným polím (name/email/phone/message/website), tak polím ve tvaru
// jmeno/prijmeni/email/telefon/zprava/_honeypot/_subject/_site (použitým na webu Noellle Servis).

import Busboy from 'busboy';

const MAX_FILES = 3;
const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB
const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
const MAX_JSON_BYTES = 100 * 1024; // 100 kB
const MAX_FIELD_CHARS = 5000;      // jedno pole (zpráva)
const MAX_NAME_CHARS = 100;

// Povolené domény webů (env ALLOWED_ORIGINS="abuildcz.cz,elrad.cz,..."; "*.domena.cz" = i subdomény).
// Prázdné = bez omezení (zpětná kompatibilita). Povoluje i variantu s www.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
function originAllowed(origin) {
  if (!ALLOWED_ORIGINS.length) return true;
  if (!origin) return false; // prohlížeče posílají Origin u každého POST; chybí = skript/curl
  let host;
  try { host = new URL(origin).hostname.toLowerCase(); } catch { return false; }
  return ALLOWED_ORIGINS.some((a) => {
    if (a.startsWith('*.')) return host === a.slice(2) || host.endsWith(a.slice(1));
    return host === a || host === `www.${a}`;
  });
}

// Rate limit v paměti: na IP, na web i celkově (běží jeden kontejner).
const RL = { ip: new Map(), site: new Map(), all: [] };
const LIMITS = { ipMax: 30, ipWindow: 10 * 60e3, siteMax: 40, siteWindow: 60 * 60e3, allMax: 300, allWindow: 60 * 60e3 };
function hit(map, key, max, windowMs, now) {
  const arr = (map.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) { map.set(key, arr); return false; }
  arr.push(now); map.set(key, arr); return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, arr] of RL.ip) { const f = arr.filter((t) => now - t < LIMITS.ipWindow); f.length ? RL.ip.set(k, f) : RL.ip.delete(k); }
  for (const [k, arr] of RL.site) { const f = arr.filter((t) => now - t < LIMITS.siteWindow); f.length ? RL.site.set(k, f) : RL.site.delete(k); }
  RL.all = RL.all.filter((t) => now - t < LIMITS.allWindow);
}, 5 * 60e3).unref();
function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((x) => x.trim()).filter(Boolean);
  return xff[xff.length - 1] || req.socket?.remoteAddress || 'unknown'; // poslední = to, co viděl proxy (nelze podvrhnout)
}

// Kontrola skutečného typu souboru (ne jen deklarovaného prohlížečem)
function magicOk(buf, mime) {
  if (!buf || buf.length < 12) return false;
  if (mime === 'image/jpeg') return buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
  if (mime === 'image/png') return buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
  if (mime === 'image/webp') return buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP';
  if (mime === 'application/pdf') return buf.slice(0, 5).toString() === '%PDF-';
  return false;
}
const safeFilename = (n) => String(n || 'priloha').replace(/[^\w.\- ]+/g, '_').slice(0, 80) || 'priloha';

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowed = originAllowed(origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGINS.length ? (allowed ? origin : 'null') : '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method === 'OPTIONS') return res.status(allowed ? 200 : 403).end();
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }
  if (!allowed) {
    console.warn('Zamítnuto: nepovolený Origin', origin || '(žádný)');
    return res.status(403).json({ ok: false, error: 'Odeslání z této adresy není povoleno.' });
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

    // Honeypot — tiché "success" pro boty (PŘED rate limitem, aby boti neblokovali reálné uživatele)
    const honeypot = fields._honeypot || fields._honey || fields.website;
    if (honeypot) {
      return res.status(200).json({ ok: true, success: true });
    }

    // Rate limit na IP a celkově (až po honeypotu — boti se nepočítají)
    {
      const now = Date.now();
      const ok = hit(RL.ip, clientIp(req), LIMITS.ipMax, LIMITS.ipWindow, now)
        && RL.all.filter((t) => now - t < LIMITS.allWindow).length < LIMITS.allMax;
      if (!ok) {
        res.setHeader('Retry-After', '600');
        return res.status(429).json({ ok: false, error: 'Příliš mnoho odeslání. Zkuste to prosím za chvíli.' });
      }
      RL.all.push(now);
    }

    // Pole hledáme bez ohledu na velikost písmen a diakritiku (Jméno, E-mail, Telefon, Zpráva…)
    const norm = (k) => String(k).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().trim();
    const nf = {};
    for (const [k, v] of Object.entries(fields)) nf[norm(k)] = String(v ?? '').trim();
    const pick = (...keys) => { for (const k of keys) if (nf[k]) return nf[k]; return ''; };

    const name = (pick('name', 'jmeno') && !nf.prijmeni ? pick('name', 'jmeno') : `${pick('name', 'jmeno')} ${nf.prijmeni || ''}`).trim();
    const email = pick('email', 'e-mail');
    const phone = pick('telefon', 'phone', 'tel');
    const message = pick('zprava', 'message', 'popis poptavky', 'popis projektu', 'motiv', 'poznamka', 'dotaz');

    // Všechna ostatní (viditelná) pole půjdou do e-mailu jako tabulka
    const extraRows = Object.entries(fields)
      .filter(([k, v]) => !k.startsWith('_') && k !== 'website' && String(v ?? '').trim())
      .map(([k, v]) => [k, String(v).trim()]);

    if (oversizedFile) {
      return res.status(400).json({ ok: false, error: `Soubor „${oversizedFile}“ je větší než 5 MB.` });
    }
    if (tooManyFiles) {
      return res.status(400).json({ ok: false, error: 'Maximálně 3 soubory.' });
    }
    for (const f of files) {
      if (!ALLOWED_MIME.includes(f.mimetype) || !magicOk(f.buffer, f.mimetype)) {
        return res.status(400).json({ ok: false, error: `Soubor „${f.filename}“ musí být JPG, PNG, WebP nebo PDF.` });
      }
    }

    const errors = {};
    if (name.length > MAX_NAME_CHARS) errors.name = 'Jméno je příliš dlouhé.';
    if (email.length > 254 || phone.length > 40) errors.contact = 'Kontakt je příliš dlouhý.';
    if (extraRows.length > 40 || extraRows.some(([k, v]) => k.length > 100 || v.length > MAX_FIELD_CHARS)) errors.message = 'Text je příliš dlouhý.';
    if (!name) errors.name = 'Vyplňte jméno.';
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'Zadejte platný e-mail.';
    if (!email && !phone) errors.contact = 'Vyplňte e-mail nebo telefon.';
    if (!message && extraRows.length < 3) errors.message = 'Vyplňte zprávu.';

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ ok: false, error: 'Neplatná data.', fields: errors });
    }

    // Příjemce podle webu: SITE_RECIPIENTS = {"sedlacek":"klient@firma.cz", ...}, fallback TO_EMAIL
    let recipients = {};
    try { recipients = JSON.parse(process.env.SITE_RECIPIENTS || '{}'); } catch { /* špatný JSON → fallback */ }
    const siteKey = String(fields._site || '').trim().toLowerCase();
    const knownSite = Object.prototype.hasOwnProperty.call(recipients, siteKey);
    if (!hit(RL.site, siteKey || '_none', LIMITS.siteMax, LIMITS.siteWindow, Date.now())) {
      res.setHeader('Retry-After', '3600');
      return res.status(429).json({ ok: false, error: 'Příliš mnoho odeslání. Zkuste to prosím později.' });
    }
    if (!knownSite) console.warn('Neznámý _site:', JSON.stringify(siteKey).slice(0, 60));
    const toEmail = knownSite ? recipients[siteKey] : process.env.TO_EMAIL;
    const apiKey = process.env.RESEND_API_KEY;
    if (!toEmail || !apiKey) {
      console.error('Chybí RESEND_API_KEY nebo TO_EMAIL v env.');
      return res.status(500).json({ ok: false, error: 'Server není nakonfigurován.' });
    }

    const siteTag = fields._site ? ` (${escapeHtml(String(fields._site).slice(0, 40))})` : '';
    const cleanSubject = String(fields._subject || '').replace(/[\r\n\u2028\u2029]+/g, ' ').trim().slice(0, 120);
    const subject = `${knownSite ? '' : '[NEZNÁMÝ WEB] '}${cleanSubject || `Nová poptávka od ${name}`.slice(0, 120)}`;

    const rows = extraRows
      .map(([k, v]) => `<tr><td style="padding:6px 14px 6px 0;color:#666;vertical-align:top"><strong>${escapeHtml(k)}</strong></td><td style="padding:6px 0">${escapeHtml(v).replace(/\n/g, '<br>')}</td></tr>`)
      .join('');
    const html = `
      <h2>Nová poptávka z webu${siteTag}</h2>
      <table style="border-collapse:collapse;font-family:sans-serif;font-size:15px">${rows}</table>
      ${files.length ? `<p><strong>Přílohy:</strong> ${files.length} foto v příloze tohoto e-mailu.</p>` : ''}
    `;

    const payload = {
      from: process.env.FROM_EMAIL || 'Kontaktní formulář <onboarding@resend.dev>',
      to: [toEmail],
      subject,
      html,
    };
    if (email) payload.reply_to = email;
    if (process.env.BCC_EMAIL && process.env.BCC_EMAIL !== toEmail) payload.bcc = [process.env.BCC_EMAIL];
    if (files.length) {
      payload.attachments = files.map((f) => ({
        filename: safeFilename(f.filename),
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

    return res.status(200).json({ ok: true, success: true });
  } catch (err) {
    console.error('Contact form error:', err);
    return res.status(500).json({ ok: false, error: 'Interní chyba serveru.' });
  }
}

function parseMultipart(req, contentType) {
  return new Promise((resolve, reject) => {
    const bb = Busboy({
      headers: { 'content-type': contentType },
      defCharset: 'utf8',
      defParamCharset: 'utf8', // názvy polí s diakritikou (Jméno, Zpráva) z FormData
      limits: { fileSize: MAX_FILE_BYTES, files: MAX_FILES + 1, fields: 60, fieldSize: 20000, parts: 70 },
    });
    const fields = {};
    const files = [];
    let tooManyFiles = false;
    let oversizedFile = null;
    let fileCount = 0;

    bb.on('field', (name, val) => {
      fields[name] = fields[name] ? `${fields[name]}, ${val}` : val; // více hodnot (checkboxy)
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
      if (data.length > MAX_JSON_BYTES) { data = ''; req.destroy(); }
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
