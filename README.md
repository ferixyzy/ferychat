# TsynchaT
Run: `node server.js` (Node 18+, no npm install needed). Open http://localhost:3000
- PORT sets the port; DATA_DIR sets where users are stored (db.json). Docker: `docker build -t tsynchat . && docker run -p 3000:3000 -v tsyn:/data tsynchat`
- Login/sign-up: username + password only (Google removed).
- Put it behind HTTPS (nginx/Caddy/Cloudflare) so the session cookie is Secure.
