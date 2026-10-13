## Initialize the database

After installing dependencies, initialize the app's database from PowerShell:

```powershell
.\.venv\Scripts\python.exe -m flask --app app init-db
```

This creates any missing tables, including the table used to store blocked IP
addresses. It can be rerun without deleting existing tables or records.

## Admin controls

Sign in with an administrator account and open `/admin`. The admin navigation
includes website branding, user management, IP blocks, categories, email
settings, and audit logs. Event forms include Bangladesh Standard Time
(`Asia/Dhaka`).

IP blocks apply to the address Flask receives as `request.remote_addr`. If the
app is deployed behind a reverse proxy, configure trusted proxy handling before
relying on IP blocks.