import re
import joblib
import os
from urllib.parse import urlparse

# ==============================
# LOAD MODEL
# ==============================

base_path = os.path.dirname(__file__)
model = joblib.load(os.path.join(base_path, "model", "phishing_model.pkl"))
vectorizer = joblib.load(os.path.join(base_path, "model", "vectorizer.pkl"))

# ==============================
# DATA
# ==============================

suspicious_keywords = [
    "urgent","verify","account","click","login","password","bank",
    "free","winner","claim","limited","offer","credit","suspended",
    "confidential","immediately","action required",
    "reset","security alert","denied","resolve"
]

brands = ["google","amazon","irctc","microsoft","paypal","bank","transport"]

template_patterns = [
    "security footage","attached powerpoint","review the footage",
    "refund","scan the qr","confirm your identity",
    "click below","reset your password","unusual activity",
    "account suspended","login to continue","important notice",
    "shared via","google drive","driver licence","found your bag",
    "overcharge","pending refund","verify mobile",
    "lost item","claim your refund"
]

# 🔥 TRUSTED DOMAINS
trusted_domains = [
    "loyolacollege.edu",
    "google.com",
    "amazon.com",
    "microsoft.com"
]

# ==============================
# CLEAN
# ==============================

def clean_input(text):
    text = text.lower()
    text = re.sub(r'http\S+', ' url ', text)
    text = re.sub(r'\d+', ' number ', text)
    text = re.sub(r'[^\w\s₹]', '', text)
    return text

# ==============================
# TRUST CHECK
# ==============================

def is_trusted_link(text):
    urls = re.findall(r'https?://\S+', text)

    for url in urls:
        domain = urlparse(url).netloc.lower()

        for trusted in trusted_domains:
            if trusted in domain:
                return True
    return False

# ==============================
# ATTACK TYPE
# ==============================

def detect_attack_type(text):
    t = text.lower()

    if "₹" in text or "refund" in t:
        return "Financial Scam"
    if "password" in t or "login" in t or "verify" in t:
        return "Credential Theft"
    if "qr" in t:
        return "QR Phishing"
    if "drive" in t or "attachment" in t:
        return "File Phishing"
    if "review" in t or "help" in t or "footage" in t:
        return "Social Engineering"

    return "General"

# ==============================
# MAIN FUNCTION
# ==============================

def predict_text(text):

    cleaned = clean_input(text)
    vectorized = vectorizer.transform([cleaned])

    # ML SCORE
    if hasattr(model, "predict_proba"):
        ml_score = model.predict_proba(vectorized)[0][1] * 100
    else:
        decision_score = model.decision_function(vectorized)[0]
        ml_score = min(abs(decision_score) * 10, 100)

    # RULE SCORE
    rule_score = 0
    detected_words = []
    t = text.lower()

    for word in suspicious_keywords:
        if word in t:
            rule_score += 8
            detected_words.append(word)

    for b in brands:
        if b in t:
            rule_score += 15
            detected_words.append("brand impersonation")

    if "₹" in text or "refund" in t:
        rule_score += 25
        detected_words.append("financial scam")

    if "qr" in t:
        rule_score += 25
        detected_words.append("QR phishing")

    if re.search(r'(http|\[\.\])', text):
        rule_score += 25
        detected_words.append("suspicious link")

    if "drive" in t or "attachment" in t or "shared" in t:
        rule_score += 25
        detected_words.append("file phishing")

    if "@" in text and ".com" in t:
        rule_score += 20
        detected_words.append("suspicious domain")

    # TEMPLATE DETECTION
    template_flag = any(p in t for p in template_patterns)
    if template_flag:
        rule_score += 35
        detected_words.append("phishing template detected")

    # 🔥 TRUSTED DOMAIN REDUCTION
    if is_trusted_link(text):
        rule_score -= 20
        detected_words.append("trusted domain")

    rule_score = max(0, min(rule_score, 100))

    # FINAL SCORE
    final_score = (0.4 * ml_score + 0.6 * rule_score)
    final_score = min(final_score, 100)

    # ==============================
    # CLASSIFICATION
    # ==============================

    if template_flag:
        if final_score >= 65:
            category = "Phishing"
        else:
            category = "Suspicious"
            final_score = max(final_score, 50)

    else:
        if final_score < 30:
            category = "Safe"
        elif final_score < 65:
            category = "Suspicious"
        else:
            category = "Phishing"

    # 🔥 TRUST OVERRIDE
    if "trusted domain" in detected_words and final_score < 40:
        category = "Safe"

    attack_type = detect_attack_type(text)

    return (
        category,
        round(final_score, 2),
        round(ml_score, 2),
        rule_score,
        list(set(detected_words)),
        len(re.findall(r'(http|\[\.\])', text)),
        0,
        len(text.split()),
        attack_type
    )