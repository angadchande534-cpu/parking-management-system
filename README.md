# ParkSmart — Vehicle Parking Management System

A complete local Python Full Stack project using **FastAPI + SQLite + HTML/CSS/JavaScript**.

## Included Features

- User Registration, Login & Logout
- Vehicle Registration
- Car/Bike Parking Slot Separation
- Live Available / Occupied Slot Status
- Automatic Slot Assignment
- Automatic Vehicle Entry Time
- Vehicle Exit + Parking Duration
- Automatic & Dynamic Parking Fee
- Digital Printable Receipt
- Vehicle Number Search
- Parking & Payment History
- Watchman Dashboard
- Admin Dashboard
- User / Watchman Role Management
- Parking Slot Management
- Editable Car/Bike Pricing
- Daily Parking Reports
- Revenue Analytics
- Overstay Alerts
- Notifications
- Mobile Responsive UI

## Default Staff Accounts

### Admin
- Email: `admin@parking.local`
- Password: `Admin@123`

### Watchman
- Email: `watchman@parking.local`
- Password: `Watchman@123`

Change demo passwords before real deployment.

## Run on Windows (easy)

1. Extract the ZIP.
2. Open the folder in VS Code.
3. Open Terminal / PowerShell.
4. Run:

```powershell
py -m venv .venv
.\.venv\Scripts\activate
py -m pip install -r requirements.txt
py -m uvicorn app:app --reload
```

5. Open:

`http://127.0.0.1:8000`

You can also double-click `run.bat` after Python is installed.

## Database

The app automatically creates `parking.db` on first run and seeds:
- 15 Car slots
- 20 Bike slots
- Admin account
- Watchman account
- Default pricing

To fully reset demo data, stop the server and delete `parking.db`, then start the server again.

## Main Routes

- `/` — Landing page
- `/register` — User registration
- `/login` — Login
- `/dashboard` — Role-based dashboard
- `/vehicles` — Vehicle registration/list
- `/parking/entry` — Watchman/Admin entry screen
- `/slots` — Live slot management
- `/search` — Vehicle number search
- `/history` — Parking/payment history
- `/reports` — Reports & revenue
- `/admin` — Admin controls
- `/health` — Health check

## Notes

This project is designed for college/internship demonstration and local deployment.
For production deployment, use HTTPS, a production database such as PostgreSQL, stronger account recovery, CSRF protection, audit logs, backups, and proper payment-gateway integration.
