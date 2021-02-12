1. `yarn install`
2. Create the file apps.json, e.g. `cp config/apps.json.dev config/apps.json`
   - You have the possibility to add/remove modules from `apps.json`
   - The selected modules have to be running at the specified endpoints/ports
3. To make API-calls from your application, you need correct google-tokens, which are created using env-variables. If you go to `src/auth.js`, open the `common` library, then the `auth.js` file in common, you can see it's trying to fetch `process.env.API_TOKEN_SECRET`. You need to set this env-variable (either directly in this file, or any other way you prefer), otherwise querying the API won't work. These are stored in 1password.
4. `yarn start`

Env vars `GOOGLE_AUTH_CLIENT_ID`, `GOOGLE_AUTH_CLIENT_SECRET` and `GOOGLE_AUTH_REDIRECT_URI` are required for log in.
The values can be found here: https://console.developers.google.com/apis/credentials?project=marine-cycle-97212