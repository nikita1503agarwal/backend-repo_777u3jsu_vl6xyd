import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext

from database import db, create_document
from schemas import User, Message, Block, AdminLog

app = FastAPI(title="Slash Messenger API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Simple token store (demo). In real apps use JWT. Here we map token->username
TOKENS: dict[str, str] = {}

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "online911")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "onlinE@911")


class SignupRequest(BaseModel):
    name: str
    username: str
    password: str
    phone: str

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    name: str
    avatar_url: Optional[str] = None

class UpdateProfileRequest(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    password: Optional[str] = None
    bio: Optional[str] = None

class MessageRequest(BaseModel):
    recipient: str
    msg_type: str = "text"
    text: Optional[str] = None
    media_url: Optional[str] = None

class SuspendRequest(BaseModel):
    username: str
    reason: Optional[str] = None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


@app.get("/")
def read_root():
    return {"message": "Slash Messenger Backend Running"}


# Auth endpoints
@app.post("/auth/signup", response_model=LoginResponse)
def signup(payload: SignupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Check username uniqueness
    existing = db["user"].find_one({"username": payload.username})
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    role = "admin" if payload.username == ADMIN_USERNAME else "user"

    user_doc = User(
        username=payload.username,
        name=payload.name,
        password_hash=hash_password(payload.password),
        phone=payload.phone,
        role=role,
        is_active=True,
    )
    uid = create_document("user", user_doc)

    token = f"tok_{uid}"
    TOKENS[token] = payload.username

    return LoginResponse(access_token=token, role=role, username=payload.username, name=payload.name)


@app.post("/auth/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    # Admin access using provided fixed creds
    if payload.username == ADMIN_USERNAME and payload.password == ADMIN_PASSWORD:
        token = f"admin_{datetime.now(timezone.utc).timestamp()}"
        TOKENS[token] = ADMIN_USERNAME
        # ensure admin user exists
        admin_user = db["user"].find_one({"username": ADMIN_USERNAME})
        if not admin_user:
            create_document("user", User(username=ADMIN_USERNAME, name="Admin", password_hash=hash_password(ADMIN_PASSWORD), phone="N/A", role="admin", is_active=True))
        return LoginResponse(access_token=token, role="admin", username=ADMIN_USERNAME, name="Admin")

    user = db["user"].find_one({"username": payload.username})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is suspended")

    if not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = f"tok_{user['_id']}"
    TOKENS[token] = user["username"]

    return LoginResponse(access_token=token, role=user.get("role", "user"), username=user["username"], name=user.get("name"), avatar_url=user.get("avatar_url"))


def get_current_username(token: str = Depends(oauth2_scheme)) -> str:
    username = TOKENS.get(token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    # Check suspension on each authenticated call
    user = db["user"].find_one({"username": username})
    if not user or not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account is suspended")
    return username


# Profile routes
@app.get("/me")
def get_me(username: str = Depends(get_current_username)):
    u = db["user"].find_one({"username": username}, {"password_hash": 0})
    return u


@app.patch("/me")
def update_me(payload: UpdateProfileRequest, username: str = Depends(get_current_username)):
    update = {k: v for k, v in payload.model_dump(exclude_none=True).items()}
    if "password" in update:
        update["password_hash"] = hash_password(update.pop("password"))
    update["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"username": username}, {"$set": update})
    return {"status": "ok"}


# Search users
@app.get("/users/search")
def search_users(q: str, username: str = Depends(get_current_username)):
    query = {"$or": [
        {"username": {"$regex": q, "$options": "i"}},
        {"phone": {"$regex": q, "$options": "i"}},
        {"name": {"$regex": q, "$options": "i"}},
    ], "is_active": True}
    users = list(db["user"].find(query, {"password_hash": 0}).limit(20))
    blocked_me = set([b["blocker"] for b in db["block"].find({"blocked": username})])
    for u in users:
        if u["username"] in blocked_me:
            u.pop("avatar_url", None)
    return users


# Messaging and blocks
@app.post("/messages/send")
def send_message(payload: MessageRequest, username: str = Depends(get_current_username)):
    if db["block"].find_one({"blocker": username, "blocked": payload.recipient}):
        raise HTTPException(status_code=403, detail="You have blocked this user")
    if db["block"].find_one({"blocker": payload.recipient, "blocked": username}):
        raise HTTPException(status_code=403, detail="You are blocked by this user")

    recipient = db["user"].find_one({"username": payload.recipient, "is_active": True})
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found")

    msg = Message(
        sender=username,
        recipient=payload.recipient,
        msg_type=payload.msg_type,
        text=payload.text,
        media_url=payload.media_url,
        created_at=datetime.now(timezone.utc),
    )
    mid = create_document("message", msg)
    return {"status": "sent", "id": mid}


@app.get("/messages/thread")
def get_thread(with_user: str, username: str = Depends(get_current_username)):
    you_blocked = db["block"].find_one({"blocker": username, "blocked": with_user})
    they_blocked = db["block"].find_one({"blocker": with_user, "blocked": username})

    msgs = list(db["message"].find({
        "$or": [
            {"sender": username, "recipient": with_user},
            {"sender": with_user, "recipient": username}
        ]
    }).sort("created_at", 1))

    other = db["user"].find_one({"username": with_user}, {"password_hash": 0})
    if other and they_blocked:
        other.pop("avatar_url", None)
    return {"messages": msgs, "other": other, "you_blocked": bool(you_blocked), "they_blocked": bool(they_blocked)}


@app.post("/block")
def block_user(target: str, username: str = Depends(get_current_username)):
    if username == target:
        raise HTTPException(status_code=400, detail="Cannot block yourself")
    if not db["user"].find_one({"username": target}):
        raise HTTPException(status_code=404, detail="User not found")
    if db["block"].find_one({"blocker": username, "blocked": target}):
        return {"status": "already_blocked"}
    create_document("block", Block(blocker=username, blocked=target, created_at=datetime.now(timezone.utc)))
    return {"status": "blocked"}


@app.delete("/block")
def unblock_user(target: str, username: str = Depends(get_current_username)):
    db["block"].delete_one({"blocker": username, "blocked": target})
    return {"status": "unblocked"}


# Admin panel
@app.get("/admin/users")
def admin_list_users(username: str = Depends(get_current_username)):
    me = db["user"].find_one({"username": username})
    if me.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    users = list(db["user"].find({}, {"password_hash": 0}).sort("created_at", -1))
    return users


@app.post("/admin/suspend")
def admin_suspend(payload: SuspendRequest, username: str = Depends(get_current_username)):
    me = db["user"].find_one({"username": username})
    if me.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    db["user"].update_one({"username": payload.username}, {"$set": {"is_active": False, "suspended_reason": payload.reason, "updated_at": datetime.now(timezone.utc)}})
    create_document("adminlog", AdminLog(actor=username, action="suspend", target=payload.username, metadata={"reason": payload.reason}, created_at=datetime.now(timezone.utc)))
    tokens_to_remove = [t for t,u in TOKENS.items() if u == payload.username]
    for t in tokens_to_remove:
        TOKENS.pop(t, None)
    return {"status": "suspended"}


@app.post("/admin/activate")
def admin_activate(payload: SuspendRequest, username: str = Depends(get_current_username)):
    me = db["user"].find_one({"username": username})
    if me.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    db["user"].update_one({"username": payload.username}, {"$set": {"is_active": True, "suspended_reason": None, "updated_at": datetime.now(timezone.utc)}})
    create_document("adminlog", AdminLog(actor=username, action="activate", target=payload.username, created_at=datetime.now(timezone.utc)))
    return {"status": "activated"}


@app.patch("/admin/user")
def admin_edit_user(data: dict, username: str = Depends(get_current_username)):
    me = db["user"].find_one({"username": username})
    if me.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    target_username = data.get("username")
    if not target_username:
        raise HTTPException(status_code=400, detail="username required")
    update = data.copy()
    update.pop("username", None)
    if "password" in update:
        update["password_hash"] = hash_password(update.pop("password"))
    update["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"username": target_username}, {"$set": update})
    create_document("adminlog", AdminLog(actor=username, action="edit_user", target=target_username, metadata={"fields": list(update.keys())}, created_at=datetime.now(timezone.utc)))
    return {"status": "updated"}


@app.get("/admin/logs")
def admin_logs(limit: int = 100, username: str = Depends(get_current_username)):
    me = db["user"].find_one({"username": username})
    if me.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    logs = list(db["adminlog"].find({}).sort("created_at", -1).limit(limit))
    return logs


from fpdf import FPDF
import json
from fastapi.responses import Response

@app.get("/admin/backup.pdf")
def admin_backup_pdf(username: str = Depends(get_current_username)):
    me = db["user"].find_one({"username": username})
    if me.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")

    users = list(db["user"].find({}, {"password_hash": 0}))
    messages = list(db["message"].find({}))

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt="Slash Messenger Backup", ln=True)
    pdf.ln(5)

    def add_section(title: str, data: list):
        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(0, 10, txt=title, ln=True)
        pdf.set_font("Arial", size=8)
        chunk = json.dumps(data, default=str)[:8000]
        for line in chunk.split("\n"):
            pdf.multi_cell(0, 5, line)
        pdf.ln(5)

    add_section("Users", users)
    add_section("Messages", messages)

    pdf_bytes = pdf.output(dest='S').encode('latin1')
    return Response(content=pdf_bytes, media_type="application/pdf")


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
