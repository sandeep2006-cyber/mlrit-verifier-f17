from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import tldextract
import dateparser
from datetime import datetime
import re
import hashlib

app = FastAPI()

# Enable CORS so your HTML file can talk to this Python server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mock Database for Duplicate Detection (Hiding in memory for now)
seen_hashes = {}

# OFFICIAL TRUSTED DOMAINS
TRUSTED_DOMAINS = [
    "google.com", "microsoft.com", "amazon.jobs", "amazon.com", "tcs.com",
    "infosys.com", "wipro.com", "accenture.com", "internshala.com",
    "unstop.com", "linkedin.com", "mlrit.ac.in", "github.com", "scholarships.gov.in"
]


class OpportunityRequest(BaseModel):
    content: str


def get_text_hash(text):
    """Creates a fingerprint of the text to detect viral spam."""
    clean_text = "".join(text.lower().split())
    return hashlib.md5(clean_text.encode()).hexdigest()


@app.post("/verify")
async def verify(request: OpportunityRequest):
    text = request.content
    score = 0
    warnings = []

    # 1. URL EXTRACTION & SANITIZATION (The Fix for the "in"." error)
    urls = re.findall(r'(https?://\S+)', text)
    if urls:
        # CLEANING: Removes trailing dots, quotes, brackets, etc.
        raw_url = urls[0].strip('.,")\'!<>')
        ext = tldextract.extract(raw_url)
        domain = f"{ext.domain}.{ext.suffix}".lower()

        if domain in TRUSTED_DOMAINS:
            score += 40
        else:
            warnings.append(f"Domain '{domain}' is not in our trusted list.")
    else:
        warnings.append("No official link detected.")

    # 2. NLP DATE EXTRACTION
    # Looks for dates like 12/05/2026 or Dec 31
    date_match = re.search(r'(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})|([A-Z][a-z]+ \d{1,2})', text)
    if date_match:
        deadline = dateparser.parse(date_match.group(0))
        if deadline and deadline > datetime.now():
            score += 40
        else:
            warnings.append("This opportunity appears to have expired.")
    else:
        warnings.append("No valid deadline found.")

    # 3. DUPLICATE DETECTION
    text_hash = get_text_hash(text)
    if text_hash in seen_hashes:
        seen_hashes[text_hash] += 1
        warnings.append(f"Spam Alert: This text was verified {seen_hashes[text_hash]} times.")
    else:
        seen_hashes[text_hash] = 1
        score += 20  # Points for being unique content

    # FINAL STATUS
    status = "LEGITIMATE" if score >= 80 else "SUSPICIOUS"
    if score < 40: status = "SCAM / EXPIRED"

    return {
        "score": score,
        "status": status,
        "warnings": warnings,
        "extracted_domain": domain if urls else None
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)