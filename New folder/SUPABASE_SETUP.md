# Supabase setup

This app can run in local demo mode or connect to Supabase for real authentication and shared resource listings.

## Configure the project

1. Create a Supabase project.
2. Open the SQL Editor and run `supabase-setup.sql`.
3. In Project Settings → API, copy the Project URL and the `anon` / publishable public key into `supabase-config.js`.
4. In Authentication → URL Configuration, add the deployed site URL to the allowed redirect URLs.
5. Leave email confirmation enabled for real accounts. Configure the campus email domain and SMTP settings before opening registration to students.
6. Create your first administrator account through Supabase Auth, then promote its profile in the SQL Editor:

```sql
update public.profiles
set role = 'Administrator'
where email = 'your-admin-campus-email@example.edu';
```

Promote staff accounts the same way, using `role = 'Staff'`. Public registration can only create Student or Faculty profiles.

## Public browser configuration

`supabase-config.js` is loaded by the browser, so its URL and anon/publishable key are public. This is expected for Supabase browser clients; database access must be protected by the row-level security policies in the setup SQL. Never put a Supabase service-role key in this file or any frontend code.

With both config fields blank, the app continues to use its browser-only demo mode. Once configured, auth and resource data use Supabase. Existing demo posts are not uploaded automatically.
