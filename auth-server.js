import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
app.use(cors());
app.use(express.json());

// ---- ENV VARS (you'll set these on Render) ----
const STORE         = process.env.SHOPIFY_STORE;          // e.g. "z4huee-wa.myshopify.com"
const CLIENT_ID     = process.env.SHOPIFY_CLIENT_ID;      // from your "custom app" API key (Customer Accounts)
const CLIENT_SECRET = process.env.SHOPIFY_CLIENT_SECRET;  // from your "custom app" API secret
const BACKEND_BASE  = process.env.BACKEND_BASE;           // e.g. "https://shopify-auth-server.onrender.com"

// In-memory session map (fine for a simple demo)
const SESS = new Map();

// Kick off OAuth with Shopify Accounts
app.get('/customer-auth/start', (req, res) => {
  const store = (req.query.store || STORE || '').trim();
  const redirectUri = req.query.redirect_uri; // your app deep link, e.g. shroomffee://auth-complete
  if (!store || !redirectUri) return res.status(400).send('Missing store or redirect_uri');

  const sessionId = crypto.randomBytes(16).toString('hex');
  const state = crypto.randomBytes(8).toString('hex');
  SESS.set(sessionId, { state, redirectUri, createdAt: Date.now() });

  const authorizeUrl = new URL('https://accounts.shopify.com/oauth/authorize');
  authorizeUrl.searchParams.set('client_id', CLIENT_ID);
  authorizeUrl.searchParams.set('scope', 'openid email');
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('store', store);
  authorizeUrl.searchParams.set('redirect_uri', `${BACKEND_BASE}/customer-auth/callback?session=${sessionId}`);

  res.redirect(authorizeUrl.toString());
});

// OAuth callback from Shopify, exchange code → token
app.get('/customer-auth/callback', async (req, res) => {
  const { code, state, session } = req.query;
  const rec = SESS.get(session);
  if (!rec || rec.state !== state) return res.status(400).send('Invalid session/state');

  const tokenRes = await fetch('https://accounts.shopify.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: `${BACKEND_BASE}/customer-auth/callback?session=${session}`
    })
  });

  if (!tokenRes.ok) {
    const txt = await tokenRes.text();
    return res.status(400).send(`Token exchange failed: ${txt}`);
  }

  const tokenJson = await tokenRes.json(); // { access_token, id_token, ... }
  SESS.set(session, { ...rec, token: tokenJson.access_token, when: Date.now() });

  // Send back into your app via deep link
  const appRedirect = `${rec.redirectUri}?session=${session}`;
  res.redirect(appRedirect);
});

// App polls this to get the final token
app.get('/customer-auth/result', (req, res) => {
  const { session } = req.query;
  const rec = SESS.get(session);
  if (!rec || !rec.token) return res.json({ status: 'pending' });
  res.json({ status: 'ok', token: rec.token });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Auth server listening on :${PORT}`));
