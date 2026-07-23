"""
PhishRadar — Africa Threat Signatures
Africa-specific phishing patterns, IOCs, and brand impersonation signatures.
Maintained by: Abdulmajid Imam
GitHub: github.com/Abdul-Itas/phishradar
"""

# ── Nigerian & African Banks ──────────────────────────────────────────────────
AFRICAN_BANKS = [
    "gtbank", "guaranty trust", "gtco",
    "zenith bank", "zenithbank",
    "access bank", "accessbank",
    "first bank", "firstbank", "firstbanknigeria",
    "uba", "united bank for africa",
    "fidelity bank", "fidelitybank",
    "union bank", "unionbank",
    "sterling bank", "sterlingbank",
    "polaris bank", "polarisbank",
    "wema bank", "wemabank", "alat",
    "stanbic ibtc", "stanbicibtc",
    "fcmb", "first city monument bank",
    "ecobank", "ecobanknigeria",
    "keystone bank", "keystonebank",
    "heritage bank", "heritagebank",
    "jaiz bank", "jaizbank",
    "providus bank", "providusbank",
    # Ghana
    "gcb bank", "gcbbank",
    "absa ghana", "calbank",
    "ecobank ghana",
    # Kenya
    "equity bank", "equitybank",
    "kcb", "kenya commercial bank",
    "cooperative bank", "coopbank",
    # South Africa
    "fnb", "first national bank",
    "absa", "nedbank", "standard bank",
]

# ── Nigerian Fintechs & Mobile Money ─────────────────────────────────────────
AFRICAN_FINTECHS = [
    "opay", "opayweb",
    "palmpay", "palmpaynigeria",
    "kuda", "kudabank",
    "piggyvest", "piggyvestapp",
    "cowrywise",
    "carbon", "getcarbonapp",
    "flutterwave",
    "paystack",
    "chipper cash", "chippercash",
    "paga", "mypaga",
    "moniepoint",
    "vbank", "vfdmicrofinancebank",
    "fairmoney",
    "branch", "branchinternational",
    "mtn momo", "mtnmomo", "momo",
    "airtel money", "airtelmoney",
    "glo mifi",
]

# ── Nigerian Government & Regulatory Bodies ───────────────────────────────────
AFRICAN_GOV_BODIES = [
    "efcc", "economic and financial crimes commission",
    "cbn", "central bank of nigeria",
    "firs", "federal inland revenue service",
    "nitda", "national information technology development agency",
    "ncc", "nigerian communications commission",
    "frsc", "federal road safety commission",
    "nafdac",
    "nimc", "national identity management commission",
    "inec",
    "nnpc", "nigerian national petroleum",
    "dpr",
    "customs", "nigeria customs service",
    "immigration", "nigeria immigration service",
]

# ── Nigerian Telcos ───────────────────────────────────────────────────────────
AFRICAN_TELCOS = [
    "mtn", "mtnng", "mtn nigeria",
    "airtel", "airtel nigeria", "airtelnigeria",
    "glo", "globacom",
    "9mobile", "9mobileng", "etisalat nigeria",
    "smile", "smile communications",
    "spectranet",
]

# ── Common Nigerian Phishing Keywords ────────────────────────────────────────
NIGERIA_PHISHING_KEYWORDS = [
    # BVN/NIN fraud
    "bvn", "bvn verification", "bvn update", "bvn expired",
    "nin", "nin update", "nin verification", "nin linkage",
    "link your nin", "update your bvn",
    # Account fraud
    "cbn directive", "cbn regulation", "cbn policy",
    "your account will be blocked", "your account has been flagged",
    "your account will be restricted", "suspended due to",
    "central bank directive",
    # Prize/lottery scams
    "you have won", "lottery winner", "prize winner",
    "beneficiary", "next of kin", "inheritance",
    "million naira", "million dollars",
    "claim your prize", "claim your winnings",
    # Investment scams
    "double your investment", "guaranteed returns",
    "ponzi", "investment opportunity",
    "forex trading", "crypto investment",
    # Job scams
    "work from home", "earn from home",
    "daily income", "make money online",
    # KYC fraud
    "kyc update", "kyc verification", "kyc expired",
    "complete your kyc", "kyc deadline",
    # Loan fraud
    "instant loan", "quick loan", "loan approved",
    "loan offer", "no collateral",
]

# ── African Phishing Domain Patterns ─────────────────────────────────────────
AFRICA_SUSPICIOUS_DOMAIN_PATTERNS = [
    # Common typosquatting patterns
    "gtb-bank", "gtbank-ng", "gt-bank",
    "zenith-bank", "zenithbank-ng",
    "accessbank-ng", "access-bank",
    "firstbank-ng", "first-bank-ng",
    "uba-ng", "ubagroup-ng",
    "cbn-gov", "cbn-nigeria", "cbn-ng",
    "efcc-ng", "efcc-gov",
    "mtn-ng", "mtn-nigeria",
    "opay-ng", "opayweb-ng",
    "palmpay-ng",
    "kuda-bank",
    # Generic patterns used in Nigerian phishing
    "ng-verify", "nigeria-verify",
    "naija-bank", "naijabank",
    "nigeria-bank", "nigeriabank",
]

# ── Legitimate African Domain Whitelist ───────────────────────────────────────
TRUSTED_AFRICAN_DOMAINS = [
    # Banks
    "gtbank.com", "gtco.com",
    "zenithbank.com",
    "accessbankplc.com",
    "firstbanknigeria.com",
    "ubagroup.com",
    "fidelitybank.ng",
    "unionbankng.com",
    "sterlingbank.com",
    "wemabank.com",
    "stanbicibtc.com",
    "fcmb.com",
    "ecobank.com",
    "keystonebankng.com",
    # Fintechs
    "opayweb.com",
    "palmpay.com",
    "kuda.com",
    "piggyvest.com",
    "cowrywise.com",
    "getcarbon.co",
    "flutterwave.com",
    "paystack.com",
    "chippercash.com",
    "mypaga.com",
    "moniepoint.com",
    # Government
    "cbn.gov.ng",
    "efcc.gov.ng",
    "firs.gov.ng",
    "nitda.gov.ng",
    "ncc.gov.ng",
    "nimc.gov.ng",
    # Telcos
    "mtnonline.com",
    "airtel.com.ng",
    "gloworld.com",
    "9mobile.com.ng",
]

# ── Full brand map for lookalike detection ────────────────────────────────────
AFRICA_BRAND_MAP = {
    "gtbank": "GTBank (gtbank.com)",
    "zenithbank": "Zenith Bank (zenithbank.com)",
    "accessbank": "Access Bank (accessbankplc.com)",
    "firstbank": "First Bank (firstbanknigeria.com)",
    "uba": "UBA (ubagroup.com)",
    "fcmb": "FCMB (fcmb.com)",
    "stanbicibtc": "Stanbic IBTC (stanbicibtc.com)",
    "ecobank": "Ecobank (ecobank.com)",
    "opay": "OPay (opayweb.com)",
    "palmpay": "PalmPay (palmpay.com)",
    "kuda": "Kuda Bank (kuda.com)",
    "piggyvest": "PiggyVest (piggyvest.com)",
    "flutterwave": "Flutterwave (flutterwave.com)",
    "paystack": "Paystack (paystack.com)",
    "moniepoint": "Moniepoint (moniepoint.com)",
    "chippercash": "Chipper Cash (chippercash.com)",
    "cbn": "Central Bank of Nigeria (cbn.gov.ng)",
    "efcc": "EFCC (efcc.gov.ng)",
    "firs": "FIRS (firs.gov.ng)",
    "nimc": "NIMC (nimc.gov.ng)",
    "mtn": "MTN Nigeria (mtnonline.com)",
    "airtel": "Airtel Nigeria (airtel.com.ng)",
    "glo": "Glo (gloworld.com)",
    "9mobile": "9mobile (9mobile.com.ng)",
}