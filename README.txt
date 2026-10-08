MyDrive – deploy on Netlify
===========================
Default admin login:  nirjon / nirjon   (CHANGE IT after first login via "Password" in the sidebar,
or set env vars ADMIN_USER and ADMIN_PASS in Netlify BEFORE the first login.)

Deploy (needs the backend function, so plain drag-and-drop of public/ is NOT enough):
  Option A – Git:   push this folder to GitHub -> Netlify "Add new site" -> Import from Git -> Deploy.
  Option B – CLI:   npm i -g netlify-cli ; npm install ; netlify deploy --prod
Photos and users are stored in Netlify Blobs (built in, no extra setup).
