from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "parking.db"
SECRET_FILE = BASE_DIR / ".secret_key"

if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
SECRET_KEY = SECRET_FILE.read_text(encoding="utf-8").strip()

app = FastAPI(title="ParkSmart - Vehicle Parking Management System")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

jinja = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"])
)


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def money(value) -> str:
    return f"₹{float(value or 0):,.2f}"


jinja.filters["money"] = money


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), 200_000
        ).hex()
        return hmac.compare_digest(candidate, digest_hex)
    except Exception:
        return False


def make_session(user_id: int) -> str:
    payload = json.dumps({"uid": user_id}, separators=(",", ":")).encode()
    body = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def read_session(token: str | None) -> Optional[int]:
    if not token or "." not in token:
        return None
    body, sig = token.rsplit(".", 1)
    expected = hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        padded = body + "=" * (-len(body) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        return int(data["uid"])
    except Exception:
        return None


def current_user(request: Request):
    uid = read_session(request.cookies.get("session"))
    if not uid:
        return None
    with get_db() as db:
        row = db.execute(
            "SELECT id, name, email, role, created_at FROM users WHERE id=?",
            (uid,),
        ).fetchone()
        return dict(row) if row else None


def require_user(request: Request):
    user = current_user(request)
    if not user:
        return None
    return user


def require_role(request: Request, *roles):
    user = current_user(request)
    if not user or user["role"] not in roles:
        return None
    return user


def redirect(path: str, msg: str | None = None):
    if msg:
        sep = "&" if "?" in path else "?"
        path = f"{path}{sep}msg={quote(msg)}"
    return RedirectResponse(path, status_code=303)


def notify(user_id: int, message: str):
    with get_db() as db:
        db.execute(
            "INSERT INTO notifications(user_id, message, created_at) VALUES(?,?,?)",
            (user_id, message, now_str()),
        )
        db.commit()


def render(request: Request, template_name: str, **context):
    user = current_user(request)
    notifications = []
    if user:
        with get_db() as db:
            rows = db.execute(
                """SELECT * FROM notifications
                   WHERE user_id=? ORDER BY id DESC LIMIT 6""",
                (user["id"],),
            ).fetchall()
            notifications = [dict(r) for r in rows]
    template = jinja.get_template(template_name)
    html = template.render(
        request=request,
        user=user,
        notifications=notifications,
        message=request.query_params.get("msg"),
        current_path=request.url.path,
        now=datetime.now(),
        **context,
    )
    return HTMLResponse(html)


def init_db():
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vehicles(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                vehicle_number TEXT UNIQUE NOT NULL,
                vehicle_type TEXT NOT NULL CHECK(vehicle_type IN ('Car','Bike')),
                model TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                owner_phone TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS slots(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                slot_number TEXT UNIQUE NOT NULL,
                vehicle_type TEXT NOT NULL CHECK(vehicle_type IN ('Car','Bike')),
                status TEXT NOT NULL DEFAULT 'Available'
                    CHECK(status IN ('Available','Occupied'))
            );

            CREATE TABLE IF NOT EXISTS pricing(
                vehicle_type TEXT PRIMARY KEY,
                hourly_rate REAL NOT NULL,
                minimum_charge REAL NOT NULL,
                overstay_hours INTEGER NOT NULL DEFAULT 8,
                overstay_multiplier REAL NOT NULL DEFAULT 1.25
            );

            CREATE TABLE IF NOT EXISTS parking_records(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                vehicle_id INTEGER NOT NULL,
                slot_id INTEGER NOT NULL,
                entry_time TEXT NOT NULL,
                exit_time TEXT,
                duration_minutes INTEGER,
                amount REAL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'Parked'
                    CHECK(status IN ('Parked','Exited')),
                payment_status TEXT NOT NULL DEFAULT 'Pending'
                    CHECK(payment_status IN ('Pending','Paid')),
                created_by INTEGER,
                FOREIGN KEY(vehicle_id) REFERENCES vehicles(id),
                FOREIGN KEY(slot_id) REFERENCES slots(id),
                FOREIGN KEY(created_by) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS notifications(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )

        # Seed accounts
        if not db.execute("SELECT 1 FROM users WHERE email=?", ("admin@parking.local",)).fetchone():
            db.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                ("System Admin", "admin@parking.local", hash_password("Admin@123"), "admin", now_str()),
            )
        if not db.execute("SELECT 1 FROM users WHERE email=?", ("watchman@parking.local",)).fetchone():
            db.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                ("Main Watchman", "watchman@parking.local", hash_password("Watchman@123"), "watchman", now_str()),
            )

        # Seed pricing
        db.execute(
            """INSERT OR IGNORE INTO pricing(vehicle_type,hourly_rate,minimum_charge,overstay_hours,overstay_multiplier)
               VALUES('Car',40,40,8,1.25)"""
        )
        db.execute(
            """INSERT OR IGNORE INTO pricing(vehicle_type,hourly_rate,minimum_charge,overstay_hours,overstay_multiplier)
               VALUES('Bike',20,20,8,1.25)"""
        )

        # Seed slots
        for i in range(1, 16):
            db.execute(
                "INSERT OR IGNORE INTO slots(slot_number,vehicle_type,status) VALUES(?,?,?)",
                (f"C-{i:02d}", "Car", "Available"),
            )
        for i in range(1, 21):
            db.execute(
                "INSERT OR IGNORE INTO slots(slot_number,vehicle_type,status) VALUES(?,?,?)",
                (f"B-{i:02d}", "Bike", "Available"),
            )
        db.commit()


init_db()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    with get_db() as db:
        stats = {
            "total_slots": db.execute("SELECT COUNT(*) FROM slots").fetchone()[0],
            "available_slots": db.execute("SELECT COUNT(*) FROM slots WHERE status='Available'").fetchone()[0],
            "occupied_slots": db.execute("SELECT COUNT(*) FROM slots WHERE status='Occupied'").fetchone()[0],
            "parked": db.execute("SELECT COUNT(*) FROM parking_records WHERE status='Parked'").fetchone()[0],
        }
    if user:
        return redirect("/dashboard")
    return render(request, "home.html", stats=stats)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    if current_user(request):
        return redirect("/dashboard")
    return render(request, "register.html")


@app.post("/register")
def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    email = email.strip().lower()
    name = name.strip()
    if len(name) < 2:
        return redirect("/register", "Please enter your full name.")
    if "@" not in email:
        return redirect("/register", "Please enter a valid email.")
    if len(password) < 6:
        return redirect("/register", "Password must be at least 6 characters.")
    if password != confirm_password:
        return redirect("/register", "Passwords do not match.")
    try:
        with get_db() as db:
            cur = db.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                (name, email, hash_password(password), "user", now_str()),
            )
            db.commit()
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return redirect("/register", "An account with this email already exists.")

    response = redirect("/dashboard", "Account created successfully.")
    response.set_cookie(
        "session", make_session(uid), httponly=True, samesite="lax", max_age=60 * 60 * 24 * 7
    )
    return response


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if current_user(request):
        return redirect("/dashboard")
    return render(request, "login.html")


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return redirect("/login", "Invalid email or password.")
    response = redirect("/dashboard", f"Welcome back, {row['name']}!")
    response.set_cookie(
        "session", make_session(row["id"]), httponly=True, samesite="lax", max_age=60 * 60 * 24 * 7
    )
    return response


@app.get("/logout")
def logout():
    response = redirect("/", "Logged out successfully.")
    response.delete_cookie("session")
    return response


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = require_user(request)

    if not user:
        return redirect("/login", "Please login first.")

    user_stats = None

    with get_db() as db:

        stats = {
            "total_slots": db.execute(
                "SELECT COUNT(*) FROM slots"
            ).fetchone()[0],

            "available_slots": db.execute(
                "SELECT COUNT(*) FROM slots WHERE status='Available'"
            ).fetchone()[0],

            "occupied_slots": db.execute(
                "SELECT COUNT(*) FROM slots WHERE status='Occupied'"
            ).fetchone()[0],

            "cars_available": db.execute(
                """
                SELECT COUNT(*)
                FROM slots
                WHERE vehicle_type='Car'
                AND status='Available'
                """
            ).fetchone()[0],

            "bikes_available": db.execute(
                """
                SELECT COUNT(*)
                FROM slots
                WHERE vehicle_type='Bike'
                AND status='Available'
                """
            ).fetchone()[0],

            "today_entries": db.execute(
                """
                SELECT COUNT(*)
                FROM parking_records
                WHERE date(entry_time)=date('now','localtime')
                """
            ).fetchone()[0],

            "today_revenue": db.execute(
                """
                SELECT COALESCE(SUM(amount),0)
                FROM parking_records
                WHERE payment_status='Paid'
                AND date(exit_time)=date('now','localtime')
                """
            ).fetchone()[0],
        }

        pricing = [
            dict(r)
            for r in db.execute(
                "SELECT * FROM pricing ORDER BY vehicle_type"
            ).fetchall()
        ]

        if user["role"] == "user":

            user_stats = {
                "total_vehicles": db.execute(
                    """
                    SELECT COUNT(*)
                    FROM vehicles
                    WHERE user_id=?
                    """,
                    (user["id"],)
                ).fetchone()[0],

                "total_visits": db.execute(
                    """
                    SELECT COUNT(*)
                    FROM parking_records p
                    JOIN vehicles v
                    ON v.id = p.vehicle_id
                    WHERE v.user_id=?
                    """,
                    (user["id"],)
                ).fetchone()[0],

                "active_parking": db.execute(
                    """
                    SELECT COUNT(*)
                    FROM parking_records p
                    JOIN vehicles v
                    ON v.id = p.vehicle_id
                    WHERE v.user_id=?
                    AND p.status='Parked'
                    """,
                    (user["id"],)
                ).fetchone()[0],

                "total_spent": db.execute(
                    """
                    SELECT COALESCE(SUM(p.amount),0)
                    FROM parking_records p
                    JOIN vehicles v
                    ON v.id=p.vehicle_id
                    WHERE v.user_id=?
                    AND p.payment_status='Paid'
                    """,
                    (user["id"],)
                ).fetchone()[0],
            }

           vehicles = [
    dict(r)
    for r in db.execute(
        """
        SELECT
            v.*,

            EXISTS(
                SELECT 1
                FROM parking_records p
                WHERE p.vehicle_id=v.id
                AND p.status='Parked'
            ) AS is_parked,

            (
                SELECT p.id
                FROM parking_records p
                WHERE p.vehicle_id=v.id
                AND p.status='Parked'
                ORDER BY p.id DESC
                LIMIT 1
            ) AS current_parking_id,

            (
                SELECT s.slot_number
                FROM parking_records p
                JOIN slots s
                ON s.id=p.slot_id
                WHERE p.vehicle_id=v.id
                AND p.status='Parked'
                ORDER BY p.id DESC
                LIMIT 1
            ) AS current_slot

        FROM vehicles v

        WHERE v.user_id=?

        ORDER BY v.id DESC
        """,
        (user["id"],)
    ).fetchall()
]

            recent = [
                dict(r)
                for r in db.execute(
                    """
                    SELECT
                        p.*,
                        v.vehicle_number,
                        v.vehicle_type,
                        s.slot_number
                    FROM parking_records p
                    JOIN vehicles v ON v.id=p.vehicle_id
                    JOIN slots s ON s.id=p.slot_id
                    WHERE v.user_id=?
                    ORDER BY p.id DESC
                    LIMIT 8
                    """,
                    (user["id"],)
                ).fetchall()
            ]

        else:

            vehicles = []

            recent = [
                dict(r)
                for r in db.execute(
                    """
                    SELECT
                        p.*,
                        v.vehicle_number,
                        v.vehicle_type,
                        v.owner_name,
                        s.slot_number
                    FROM parking_records p
                    JOIN vehicles v ON v.id=p.vehicle_id
                    JOIN slots s ON s.id=p.slot_id
                    ORDER BY p.id DESC
                    LIMIT 10
                    """
                ).fetchall()
            ]

        active = [
            dict(r)
            for r in db.execute(
                """
                SELECT
                    p.*,
                    v.vehicle_number,
                    v.vehicle_type,
                    v.owner_name,
                    s.slot_number,
                    pr.overstay_hours
                FROM parking_records p
                JOIN vehicles v ON v.id=p.vehicle_id
                JOIN slots s ON s.id=p.slot_id
                JOIN pricing pr ON pr.vehicle_type=v.vehicle_type
                WHERE p.status='Parked'
                ORDER BY p.entry_time
                """
            ).fetchall()
        ]

    for record in active:
        entered = datetime.strptime(
            record["entry_time"],
            "%Y-%m-%d %H:%M:%S"
        )

        hours = (
            datetime.now() - entered
        ).total_seconds() / 3600

        record["overstay"] = hours > record["overstay_hours"]
        record["parked_hours"] = max(0, hours)

    return render(
        request,
        "dashboard.html",
        stats=stats,
        vehicles=vehicles,
        recent=recent,
        active=active,
        user_stats=user_stats,
        pricing=pricing
    )

@app.get("/vehicles", response_class=HTMLResponse)
def vehicles_page(request: Request):
    user = require_user(request)
    if not user:
        return redirect("/login")
    with get_db() as db:
        if user["role"] == "user":
            rows = db.execute(
                "SELECT * FROM vehicles WHERE user_id=? ORDER BY id DESC", (user["id"],)
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT v.*, u.email AS user_email
                   FROM vehicles v JOIN users u ON u.id=v.user_id
                   ORDER BY v.id DESC"""
            ).fetchall()
    return render(request, "vehicles.html", vehicles=[dict(r) for r in rows])


@app.post("/vehicles/add")
def add_vehicle(
    request: Request,
    vehicle_number: str = Form(...),
    vehicle_type: str = Form(...),
    model: str = Form(...),
    owner_name: str = Form(...),
    owner_phone: str = Form(""),
):
    user = require_user(request)
    if not user:
        return redirect("/login")
    vehicle_number = vehicle_number.strip().upper().replace(" ", "")
    if vehicle_type not in ("Car", "Bike"):
        return redirect("/vehicles", "Invalid vehicle type.")
    try:
        with get_db() as db:
            db.execute(
                """INSERT INTO vehicles(user_id,vehicle_number,vehicle_type,model,owner_name,owner_phone,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (
                    user["id"], vehicle_number, vehicle_type, model.strip(),
                    owner_name.strip(), owner_phone.strip(), now_str()
                ),
            )
            db.commit()
    except sqlite3.IntegrityError:
        return redirect("/vehicles", "Vehicle number is already registered.")
    return redirect("/vehicles", "Vehicle registered successfully.")
@app.post("/park-now/{vehicle_id}")
def park_now(request: Request, vehicle_id: int):

    user = require_user(request)

    if not user:
        return redirect("/login", "Please login first.")

    with get_db() as db:

        # Find user's vehicle
        vehicle = db.execute(
            """
            SELECT *
            FROM vehicles
            WHERE id=?
            AND user_id=?
            """,
            (vehicle_id, user["id"])
        ).fetchone()

        if not vehicle:
            return redirect(
                "/dashboard",
                "Vehicle not found."
            )

        # Check whether already parked
        already_parked = db.execute(
            """
            SELECT 1
            FROM parking_records
            WHERE vehicle_id=?
            AND status='Parked'
            """,
            (vehicle_id,)
        ).fetchone()

        if already_parked:
            return redirect(
                "/dashboard",
                "Vehicle is already parked."
            )

        # Find matching available slot
        slot = db.execute(
            """
            SELECT *
            FROM slots
            WHERE vehicle_type=?
            AND status='Available'
            ORDER BY slot_number
            LIMIT 1
            """,
            (vehicle["vehicle_type"],)
        ).fetchone()

        if not slot:
            return redirect(
                "/dashboard",
                f"No {vehicle['vehicle_type']} parking slot available."
            )

        # Create parking entry
        db.execute(
            """
            INSERT INTO parking_records(
                vehicle_id,
                slot_id,
                entry_time,
                status,
                payment_status,
                created_by
            )
            VALUES(
                ?,
                ?,
                ?,
                'Parked',
                'Pending',
                ?
            )
            """,
            (
                vehicle_id,
                slot["id"],
                now_str(),
                user["id"]
            )
        )

        # Occupy slot
        db.execute(
            """
            UPDATE slots
            SET status='Occupied'
            WHERE id=?
            """,
            (slot["id"],)
        )

        db.commit()

    return redirect(
        "/dashboard",
        f"Vehicle parked successfully in {slot['slot_number']}."
    )

vehicles = 
@app.get("/parking/entry", response_class=HTMLResponse)
def parking_entry_page(request: Request):
    user = require_role(request, "admin", "watchman")
    if not user:
        return redirect("/dashboard", "Only Admin/Watchman can manage entries.")
    with get_db() as db:
        [
            dict(r) for r in db.execute(
                """SELECT v.* FROM vehicles v
                   WHERE NOT EXISTS(
                       SELECT 1 FROM parking_records p
                       WHERE p.vehicle_id=v.id AND p.status='Parked'
                   )
                   ORDER BY v.vehicle_number"""
            ).fetchall()
        ]
    return render(request, "entry.html", vehicles=vehicles)


@app.post("/parking/entry")
def parking_entry(request: Request, vehicle_id: int = Form(...)):
    staff = require_role(request, "admin", "watchman")
    if not staff:
        return redirect("/dashboard", "Not allowed.")
    with get_db() as db:
        vehicle = db.execute("SELECT * FROM vehicles WHERE id=?", (vehicle_id,)).fetchone()
        if not vehicle:
            return redirect("/parking/entry", "Vehicle not found.")
        already = db.execute(
            "SELECT 1 FROM parking_records WHERE vehicle_id=? AND status='Parked'", (vehicle_id,)
        ).fetchone()
        if already:
            return redirect("/parking/entry", "This vehicle is already parked.")
        slot = db.execute(
            """SELECT * FROM slots
               WHERE vehicle_type=? AND status='Available'
               ORDER BY slot_number LIMIT 1""",
            (vehicle["vehicle_type"],),
        ).fetchone()
        if not slot:
            return redirect("/parking/entry", f"No {vehicle['vehicle_type']} slots are available.")

        cur = db.execute(
            """INSERT INTO parking_records(vehicle_id,slot_id,entry_time,status,payment_status,created_by)
               VALUES(?,?,?,'Parked','Pending',?)""",
            (vehicle_id, slot["id"], now_str(), staff["id"]),
        )
        db.execute("UPDATE slots SET status='Occupied' WHERE id=?", (slot["id"],))
        db.commit()

    notify(vehicle["user_id"], f"Parking confirmed: {vehicle['vehicle_number']} assigned to {slot['slot_number']}.")
    return redirect("/dashboard", f"Entry recorded. Slot {slot['slot_number']} assigned.")


def calculate_fee(vehicle_type: str, entry_time: str):
    with get_db() as db:
        price = db.execute("SELECT * FROM pricing WHERE vehicle_type=?", (vehicle_type,)).fetchone()

    entry_dt = datetime.strptime(entry_time, "%Y-%m-%d %H:%M:%S")
    exit_dt = datetime.now()
    seconds = max(60, (exit_dt - entry_dt).total_seconds())
    minutes = max(1, math.ceil(seconds / 60))
    billed_hours = max(1, math.ceil(minutes / 60))
    rate = float(price["hourly_rate"])
    amount = billed_hours * rate

    overstay_hours = int(price["overstay_hours"])
    multiplier = float(price["overstay_multiplier"])
    if billed_hours > overstay_hours:
        normal = overstay_hours * rate
        extra = (billed_hours - overstay_hours) * rate * multiplier
        amount = normal + extra

    amount = max(float(price["minimum_charge"]), amount)
    return exit_dt.strftime("%Y-%m-%d %H:%M:%S"), minutes, round(amount, 2)


@app.post("/parking/exit/{record_id}")
def parking_exit(request: Request, record_id: int):
    staff = require_role(request, "admin", "watchman")
    if not staff:
        return redirect("/dashboard", "Not allowed.")
    with get_db() as db:
        record = db.execute(
            """SELECT p.*, v.vehicle_number, v.vehicle_type, v.user_id, s.slot_number
               FROM parking_records p
               JOIN vehicles v ON v.id=p.vehicle_id
               JOIN slots s ON s.id=p.slot_id
               WHERE p.id=?""",
            (record_id,),
        ).fetchone()
        if not record or record["status"] != "Parked":
            return redirect("/dashboard", "Active parking record not found.")

        exit_time, duration, amount = calculate_fee(record["vehicle_type"], record["entry_time"])
        db.execute(
            """UPDATE parking_records
               SET exit_time=?,duration_minutes=?,amount=?,status='Exited',payment_status='Paid'
               WHERE id=?""",
            (exit_time, duration, amount, record_id),
        )
        db.execute("UPDATE slots SET status='Available' WHERE id=?", (record["slot_id"],))
        db.commit()

    notify(
        record["user_id"],
        f"Exit completed for {record['vehicle_number']}. Paid {money(amount)}. Receipt #{record_id}.",
    )
    return redirect(f"/receipt/{record_id}", "Exit completed and payment recorded.")


@app.get("/receipt/{record_id}", response_class=HTMLResponse)
def receipt(request: Request, record_id: int):
    user = require_user(request)
    if not user:
        return redirect("/login")
    with get_db() as db:
        row = db.execute(
            """SELECT p.*, v.vehicle_number, v.vehicle_type, v.model, v.owner_name, v.user_id,
                      s.slot_number
               FROM parking_records p
               JOIN vehicles v ON v.id=p.vehicle_id
               JOIN slots s ON s.id=p.slot_id
               WHERE p.id=?""",
            (record_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Receipt not found")
    if user["role"] == "user" and row["user_id"] != user["id"]:
        raise HTTPException(403, "Not allowed")
    return render(request, "receipt.html", record=dict(row))


@app.get("/search", response_class=HTMLResponse)
def search_vehicle(request: Request, q: str = ""):
    user = require_user(request)
    if not user:
        return redirect("/login")
    results = []
    if q.strip():
        with get_db() as db:
            rows = db.execute(
                """SELECT v.*, u.email AS account_email,
                          p.id AS parking_id, p.entry_time, p.status AS parking_status,
                          s.slot_number
                   FROM vehicles v
                   JOIN users u ON u.id=v.user_id
                   LEFT JOIN parking_records p ON p.id = (
                       SELECT id FROM parking_records
                       WHERE vehicle_id=v.id
                       ORDER BY id DESC LIMIT 1
                   )
                   LEFT JOIN slots s ON s.id=p.slot_id
                   WHERE v.vehicle_number LIKE ?
                   ORDER BY v.vehicle_number""",
                (f"%{q.strip().upper().replace(' ', '')}%",),
            ).fetchall()
            results = [dict(r) for r in rows]
    return render(request, "search.html", q=q, results=results)


@app.get("/history", response_class=HTMLResponse)
def history(request: Request):
    user = require_user(request)
    if not user:
        return redirect("/login")
    with get_db() as db:
        if user["role"] == "user":
            rows = db.execute(
                """SELECT p.*, v.vehicle_number, v.vehicle_type, s.slot_number
                   FROM parking_records p
                   JOIN vehicles v ON v.id=p.vehicle_id
                   JOIN slots s ON s.id=p.slot_id
                   WHERE v.user_id=?
                   ORDER BY p.id DESC""",
                (user["id"],),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT p.*, v.vehicle_number, v.vehicle_type, v.owner_name, s.slot_number
                   FROM parking_records p
                   JOIN vehicles v ON v.id=p.vehicle_id
                   JOIN slots s ON s.id=p.slot_id
                   ORDER BY p.id DESC"""
            ).fetchall()
    return render(request, "history.html", records=[dict(r) for r in rows])


@app.get("/slots", response_class=HTMLResponse)
def slots_page(request: Request):
    user = require_user(request)
    if not user:
        return redirect("/login")
    with get_db() as db:
        rows = [dict(r) for r in db.execute("SELECT * FROM slots ORDER BY vehicle_type,slot_number").fetchall()]
    return render(request, "slots.html", slots=rows)


@app.post("/admin/slots/add")
def add_slot(request: Request, slot_number: str = Form(...), vehicle_type: str = Form(...)):
    admin = require_role(request, "admin")
    if not admin:
        return redirect("/slots", "Admin access required.")
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO slots(slot_number,vehicle_type,status) VALUES(?,?,'Available')",
                (slot_number.strip().upper(), vehicle_type),
            )
            db.commit()
    except sqlite3.IntegrityError:
        return redirect("/slots", "Slot number already exists.")
    return redirect("/slots", "Parking slot added.")


@app.post("/admin/slots/delete/{slot_id}")
def delete_slot(request: Request, slot_id: int):
    admin = require_role(request, "admin")
    if not admin:
        return redirect("/slots", "Admin access required.")
    with get_db() as db:
        slot = db.execute("SELECT * FROM slots WHERE id=?", (slot_id,)).fetchone()
        if not slot:
            return redirect("/slots", "Slot not found.")
        if slot["status"] == "Occupied":
            return redirect("/slots", "Occupied slot cannot be deleted.")
        used = db.execute("SELECT 1 FROM parking_records WHERE slot_id=? LIMIT 1", (slot_id,)).fetchone()
        if used:
            return redirect("/slots", "This slot has parking history and cannot be deleted.")
        db.execute("DELETE FROM slots WHERE id=?", (slot_id,))
        db.commit()
    return redirect("/slots", "Slot deleted.")


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    admin = require_role(request, "admin")
    if not admin:
        return redirect("/dashboard", "Admin access required.")
    with get_db() as db:
        users = [dict(r) for r in db.execute(
            "SELECT id,name,email,role,created_at FROM users ORDER BY id DESC"
        ).fetchall()]
        pricing = [dict(r) for r in db.execute("SELECT * FROM pricing ORDER BY vehicle_type").fetchall()]
    return render(request, "admin.html", users=users, pricing=pricing)


@app.post("/admin/users/add")
def admin_add_user(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
):
    admin = require_role(request, "admin")
    if not admin:
        return redirect("/dashboard")
    if role not in ("user", "watchman", "admin"):
        return redirect("/admin", "Invalid role.")
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)",
                (name.strip(), email.strip().lower(), hash_password(password), role, now_str()),
            )
            db.commit()
    except sqlite3.IntegrityError:
        return redirect("/admin", "Email already exists.")
    return redirect("/admin", f"{role.title()} account created.")


@app.post("/admin/users/role/{user_id}")
def admin_change_role(request: Request, user_id: int, role: str = Form(...)):
    admin = require_role(request, "admin")
    if not admin:
        return redirect("/dashboard")
    if role not in ("user", "watchman", "admin"):
        return redirect("/admin", "Invalid role.")
    if user_id == admin["id"] and role != "admin":
        return redirect("/admin", "You cannot remove your own admin role.")
    with get_db() as db:
        db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
        db.commit()
    return redirect("/admin", "User role updated.")


@app.post("/admin/pricing")
def update_pricing(
    request: Request,
    vehicle_type: str = Form(...),
    hourly_rate: float = Form(...),
    minimum_charge: float = Form(...),
    overstay_hours: int = Form(...),
    overstay_multiplier: float = Form(...),
):
    admin = require_role(request, "admin")
    if not admin:
        return redirect("/dashboard")
    with get_db() as db:
        db.execute(
            """UPDATE pricing
               SET hourly_rate=?, minimum_charge=?, overstay_hours=?, overstay_multiplier=?
               WHERE vehicle_type=?""",
            (hourly_rate, minimum_charge, overstay_hours, overstay_multiplier, vehicle_type),
        )
        db.commit()
    return redirect("/admin", f"{vehicle_type} pricing updated.")


@app.get("/reports", response_class=HTMLResponse)
def reports(request: Request):
    staff = require_role(request, "admin", "watchman")
    if not staff:
        return redirect("/dashboard", "Staff access required.")
    with get_db() as db:
        summary = {
            "total_vehicles": db.execute("SELECT COUNT(*) FROM vehicles").fetchone()[0],
            "total_records": db.execute("SELECT COUNT(*) FROM parking_records").fetchone()[0],
            "parked": db.execute("SELECT COUNT(*) FROM parking_records WHERE status='Parked'").fetchone()[0],
            "available": db.execute("SELECT COUNT(*) FROM slots WHERE status='Available'").fetchone()[0],
            "revenue": db.execute(
                "SELECT COALESCE(SUM(amount),0) FROM parking_records WHERE payment_status='Paid'"
            ).fetchone()[0],
            "today_revenue": db.execute(
                """SELECT COALESCE(SUM(amount),0) FROM parking_records
                   WHERE payment_status='Paid' AND date(exit_time)=date('now','localtime')"""
            ).fetchone()[0],
        }
        daily = [
            dict(r) for r in db.execute(
                """SELECT date(COALESCE(exit_time,entry_time)) AS day,
                          COUNT(*) AS vehicles,
                          ROUND(COALESCE(SUM(CASE WHEN payment_status='Paid' THEN amount ELSE 0 END),0),2) AS revenue
                   FROM parking_records
                   GROUP BY date(COALESCE(exit_time,entry_time))
                   ORDER BY day DESC LIMIT 14"""
            ).fetchall()
        ]
        by_type = [
            dict(r) for r in db.execute(
                """SELECT v.vehicle_type, COUNT(*) AS records,
                          ROUND(COALESCE(SUM(CASE WHEN p.payment_status='Paid' THEN p.amount ELSE 0 END),0),2) AS revenue
                   FROM parking_records p
                   JOIN vehicles v ON v.id=p.vehicle_id
                   GROUP BY v.vehicle_type"""
            ).fetchall()
        ]
    return render(request, "reports.html", summary=summary, daily=daily, by_type=by_type)


@app.get("/notifications/read")
def notifications_read(request: Request):
    user = require_user(request)
    if not user:
        return redirect("/login")
    with get_db() as db:
        db.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (user["id"],))
        db.commit()
    return redirect("/dashboard", "Notifications marked as read.")


@app.get("/api/availability")
def api_availability():
    with get_db() as db:
        data = {
            "car_available": db.execute(
                "SELECT COUNT(*) FROM slots WHERE vehicle_type='Car' AND status='Available'"
            ).fetchone()[0],
            "bike_available": db.execute(
                "SELECT COUNT(*) FROM slots WHERE vehicle_type='Bike' AND status='Available'"
            ).fetchone()[0],
            "total_available": db.execute(
                "SELECT COUNT(*) FROM slots WHERE status='Available'"
            ).fetchone()[0],
            "occupied": db.execute(
                "SELECT COUNT(*) FROM slots WHERE status='Occupied'"
            ).fetchone()[0],
            "updated_at": datetime.now().strftime("%H:%M:%S"),
        }
    return JSONResponse(data)


@app.get("/health")
def health():
    return {"status": "ok", "app": "ParkSmart"}
