from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tldextract, dateparser, re, hashlib, sqlite3
from datetime import datetime
from passlib.hash import pbkdf2_sha256

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)')
    conn.commit()
    conn.close()

init_db()

# --- MODELS ---
class UserAuth(BaseModel):
    username: str
    password: str

class OpportunityRequest(BaseModel):
    content: str

# --- AUTH ENDPOINTS ---
@app.post("/signup")
async def signup(user: UserAuth):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        hashed_pw = pbkdf2_sha256.hash(user.password)
        c.execute("INSERT INTO users VALUES (?, ?)", (user.username, hashed_pw))
        conn.commit()
        return {"message": "Account created! Now please Login."}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()

@app.post("/login")
async def login(user: UserAuth):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (user.username,))
    result = c.fetchone()
    conn.close()
    if result and pbkdf2_sha256.verify(user.password, result[0]):
        return {"message": "Success", "username": user.username}
    raise HTTPException(status_code=401, detail="Invalid username or password")

# --- VERIFICATION LOGIC ---
TRUSTED_DOMAINS = ["google.com", "microsoft.com", "tcs.com", "internshala.com", "unstop.com", "mlrit.ac.in"]
seen_hashes = {}

@app.post("/verify")
async def verify(request: OpportunityRequest):
    text = request.content
    score, warnings = 0, []
    
    # URL Logic with Punctuation Fix
    urls = re.findall(r'(https?://\S+)', text)
    if urls:
        raw_url = urls[0].strip('.,")\'!<>') 
        ext = tldextract.extract(raw_url)
        domain = f"{ext.domain}.{ext.suffix}".lower()
        if domain in TRUSTED_DOMAINS: score += 40
        else: warnings.append(f"Domain '{domain}' is not in our trusted list.")
    else: warnings.append("No official link found.")

    # Date Logic
    date_match = re.search(r'(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})|([A-Z][a-z]+ \d{1,2})', text)
    if date_match:
        deadline = dateparser.parse(date_match.group(0))
        if deadline and deadline > datetime.now(): score += 40
        else: warnings.append("This appears to have expired.")
    else: warnings.append("No deadline date detected.")

    # Duplicate Logic
    h = hashlib.md5("".join(text.lower().split()).encode()).hexdigest()
    if h in seen_hashes:
        seen_hashes[h] += 1
        warnings.append(f"Duplicate alert: Checked {seen_hashes[h]} times.")
    else:
        seen_hashes[h] = 1
        score += 20

    status = "LEGITIMATE" if score >= 80 else "SUSPICIOUS"
    if score < 40: status = "SCAM"

    return {"score": score, "status": status, "warnings": warnings}