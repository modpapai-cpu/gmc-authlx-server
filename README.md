# GMC AuthLX Render Proxy

## Render
1. Create a new Web Service from this folder/repository.
2. Build: `npm install`
3. Start: `npm start`
4. Add environment variables: `AUTHLX_NAME`, `AUTHLX_OWNERID`, `AUTHLX_VERSION`, `AUTHLX_URL`, `AUTHLX_SECRET`.
5. Set `AUTHLX_SECRET` to your current AuthLX secret in Render Environment. Never commit it.
6. After deployment, use the service URL ending in `.onrender.com`.

## Extension
Replace `YOUR-RENDER-SERVICE.onrender.com` in `manifest.json` and `authlx-gate.js` with the actual Render hostname.
