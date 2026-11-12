// Express obal pro Coolify/Docker — stejný handler jako na Vercelu (api/contact.js)
import express from 'express';
import handler from './api/contact.js';

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);

app.get('/', (_req, res) => res.type('text/plain').send('contact-form OK'));
app.all('/api/contact', (req, res) => handler(req, res)); // bez body parseru: handler si JSON/multipart čte sám

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => console.log(`contact-form listening on ${port}`));
