# Univerzální kontaktní formulář (Vercel + Resend)

## Nasazení (jednou, jako vlastní projekt)
1. `vercel.com` → New Project → nahraj tuto složku (nebo repo s `api/contact.js`).
2. Project Settings → Environment Variables → přidej `RESEND_API_KEY` a `TO_EMAIL` (podle `.env.example`).
3. Deploy. Endpoint bude `https://tvuj-projekt.vercel.app/api/contact`.

> Jeden nasazený projekt můžeš používat pro všechny klienty — stačí měnit `TO_EMAIL`
> buď přes query param (viz níže), nebo mít pro každého klienta vlastní env/deploy.

### Varianta: jeden endpoint pro víc klientů
Pokud chceš jeden deploy sdílet napříč projekty s různým cílovým e-mailem, uprav `contact.js`
tak, aby `TO_EMAIL` bral z `req.body.to` (whitelist domén doporučen), nebo si pro každého
klienta udělej samostatný Vercel projekt (2 min, zero config) — jednodušší a bezpečnější.

## Použití na klientském webu
1. Zkopíruj obsah `form.html` (HTML + JS + styly) do stránky.
2. Uprav `FORM_ENDPOINT` v `<script>` na URL svého nasazení.
3. Hotovo — formulář odesílá přes fetch, bez reloadu, s honeypotem proti spamu.

## Resend setup
- Registrace na resend.com, vygeneruj API klíč.
- Pro produkci doporučeno ověřit vlastní doménu (Resend → Domains), jinak použij
  defaultní `onboarding@resend.dev` jako `FROM_EMAIL` (funguje, ale vypadá méně profesionálně).

## Poznámky
- Validace probíhá na serveru (jméno, e-mail formát, zpráva povinná).
- Honeypot pole `website` — skryté CSS, boti ho vyplní, lidé ne → tichý fake-success.
- Žádná databáze, žádný storage — jen odeslání e-mailu.
