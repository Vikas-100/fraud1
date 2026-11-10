import re
from urllib.parse import urlparse

# Threat Indicator Rules with weighted threat scoring
INDICATORS = [
    # 1. OTP & Credential Harvesting (High Risk)
    (r"\b(?:otp|one[- ]time password|verification code)\b", 3, "OTP / Verification Code request detected"),
    (r"\b(?:password|passwd|netbanking password)\b", 3, "Sensitive password requested"),
    (r"\b(?:pin|mpin|upi pin|atm pin)\b", 3, "Financial PIN request detected"),
    (r"\b(?:cvv|card expiry|credit card details|debit card number)\b", 3, "Credit/Debit Card credential theft pattern"),

    # 2. Banking, KYC & Account Blocking Scams
    (r"\b(?:bank|banking)\s*(?:details|account)\b|\baccount number\b", 2, "Bank account details requested"),
    (r"\b(?:verify|verification|update)\b.*\b(?:account|bank|kyc|pan|aadhaar)\b|\bkyc\b", 3, "Urgent Account / KYC / Aadhaar verification trap detected"),
    (r"\b(?:account|debit card|netbanking)\s*(?:blocked|suspended|deactivated|frozen|terminated)\b", 3, "Account deactivation / suspension threat detected"),

    # 3. Fabricated Urgency & Disconnection Scams
    (r"\b(?:urgent|urgently|immediately|within \d+ hours?|act now|hurry|final notice)\b", 2, "Fabricated urgency / pressure tactics detected"),
    (r"\b(?:electricity|power|bill)\s*(?:will be disconnected|disconnected tonight|unpaid bill)\b", 3, "Electricity / Utility disconnection threat scam detected"),
    (r"\b(?:police|arrest warrant|court summons|legal action|customs)\b", 3, "Intimidation / Authority impersonation detected"),

    # 4. Lottery, Prize & Jackpot Schemes
    (r"\b(?:lottery|jackpot|lucky draw|bumper prize)\b", 3, "Lottery or Jackpot scheme detected"),
    (r"\b(?:congratulations|congrats)\b.*\b(?:winner|won|prize|selected)\b", 2, "Unsolicited prize winner notification detected"),
    (r"\b(?:claim now|claim your prize|redeem reward)\b", 2, "Urgent prize redemption instruction detected"),

    # 5. Financial Transfers & Advance-Fee Fraud
    (r"\b(?:send money|transfer funds|pay now|registration fee|processing fee|security deposit)\b", 2, "Advance payment / money transfer demand detected"),
    (r"\b(?:refund|cashback)\b.*\b(?:claim|click|approved)\b", 2, "Suspicious refund / cashback lure detected"),

    # 6. Work-From-Home & Fake Job Scams
    (r"\b(?:work from home|part[- ]time job|earn daily|earn \d+|telegram task|youtube like task)\b", 3, "Part-time task / fake job scam detected"),
    (r"\b(?:double your money|guaranteed returns|crypto investment|binance bonus|free crypto)\b", 3, "High-yield investment / crypto scam pattern detected"),

    # 7. Suspicious Links & Shorteners
    (r"\b(?:click here|click the link|tap here|open link|download apk)\b", 2, "Instruction to click external link or download APK"),
    (r"https?://\S+|www\.\S+", 2, "Contains web hyperlink"),
    (r"\b(?:bit\.ly|tinyurl\.com|t\.me|wa\.me|is\.gd|cutt\.ly|rb\.gy)\b", 3, "URL shortener or redirector commonly used to mask malicious sites"),
    (r"https?://(?:\d{1,3}\.){3}\d{1,3}", 3, "Direct IP address link detected (high indicator of phishing)")
]

USER_MANDATED_ALERT = "Your message is very suspicious, don't give any respond to that message, that is fraud message"

def analyze_message_content(message: str) -> dict:
    """
    Evaluates message against security indicators.
    Returns structured analysis with risk score (0-10), status, indicators, and safety advice.
    """
    if not message or not isinstance(message, str):
        return {
            "status": "SAFE",
            "score": 0,
            "title": "✅ NO CONTENT PROVIDED",
            "warnings": [],
            "advice": "Please provide a valid text message to classify."
        }

    text = message.strip()
    score = 0
    warnings = []
    matched_warnings = set()

    # Rule checks
    for pattern, points, warning in INDICATORS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            score += points
            if warning not in matched_warnings:
                warnings.append(warning)
                matched_warnings.add(warning)

    # Normalize score to 0 - 10 scale
    score = min(score, 10)

    # Decision Matrix
    if score >= 6:
        status = "FRAUD"
        title = "🚨 FRAUD MESSAGE DETECTED"
        advice = USER_MANDATED_ALERT
        risk_level = "CRITICAL"
    elif score >= 3:
        status = "SUSPICIOUS"
        title = "⚠️ SUSPICIOUS MESSAGE DETECTED"
        advice = USER_MANDATED_ALERT
        risk_level = "ELEVATED"
    else:
        status = "SAFE"
        title = "✅ MESSAGE APPEARS SAFE"
        advice = "No fraud indicators detected. This message appears normal and safe."
        risk_level = "LOW"

    return {
        "status": status,
        "score": score,
        "risk_level": risk_level,
        "title": title,
        "warnings": warnings,
        "advice": advice,
        "character_count": len(text)
    }
