import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

supabase = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)

email = "parkingtest123@gmail.com"
password = "Test@123456"

try:
    response = supabase.auth.sign_up({
        "email": email,
        "password": password
    })

    print("✅ USER CREATED")
    print("Email:", response.user.email if response.user else "No user")
    print("ID:", response.user.id if response.user else "No ID")

except Exception as e:
    print("❌ ERROR:", e)