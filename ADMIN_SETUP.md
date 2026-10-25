# Mohsin Tools admin backend: setup
1. Create a free project at supabase.com.
2. SQL Editor: paste and run `supabase-schema.sql`.
3. Project Settings > API: copy the Project URL and anon public key into `window.MT_AUTH` in index.html (see `.env.example`). Never use the service_role key in the site.
4. Sign up on your site, then run the "FIRST ADMIN" line at the bottom of the SQL file with your email.
5. Authentication > URL Configuration: add your site address as a redirect URL.
6. Test: sign in as a normal user and confirm that `update tools ...` and reading `audit_log` are refused.

## What this does and does not give you
Done here: database, roles, row-level security, revision history, audit log, media bucket.
Not done: the admin screens in index.html that read and write these tables. The current "Admin panel" button only edits logo and text in this browser and is not secure.
