"""
Certificate Store — certificados raiz suspeitos.

Cheaters e loaders instalam certificado raiz falso pra:
  - HTTPS MitM: interceptar tráfego do Roblox / servidor de licença
  - Assinar loaders custom pra evadir SmartScreen (com cert self-signed
    reconhecido como trusted na máquina do próprio suspeito)
  - Bypass do Defender que valida assinatura de binários baixados

Diferente de scan_dse_state (que verifica se DSE está desligado no BCD) —
este verifica se INSTALARAM cert malicioso enquanto DSE está ligado.

Ler direto do registro exigiria parse ASN.1 do blob. Delegamos ao PowerShell
que já parseia (`Get-ChildItem Cert:\\LocalMachine\\Root`).

Requer admin pra HKLM completa; parcial sem admin (só HKCU cert store).
"""

from models import _result, _item
import subprocess
from datetime import datetime, timedelta

try:
    import win_tools
    HAS_WIN_TOOLS = True
except ImportError:
    HAS_WIN_TOOLS = False


# CAs raiz conhecidas — Microsoft, Google, DigiCert, Let's Encrypt, GoDaddy, etc.
# Se Subject/Issuer contém qualquer um destes, é legítimo.
_TRUSTED_CA_MARKERS = (
    "microsoft", "windows", "google", "digicert", "letsencrypt",
    "let's encrypt", "internet security research group", "isrg root",
    "globalsign", "godaddy", "go daddy", "verisign", "entrust",
    "identrust", "comodo", "amazon", "starfield", "usertrust",
    "addtrust", "addtrust external",  # legado Comodo/Sectigo (ainda em stores)
    "sectigo", "quovadis", "swisssign", "buypass", "wosign",
    "geotrust", "thawte", "symantec", "iso 27001", "iso27001",
    "affirmtrust", "certum", "cybertrust", "network solutions",
    "hongkong post", "e-tugra", "netlock", "unizeto certum",
    "so.g.e.i.", "d-trust", "trustcor", "actalis", "izenpe",
    "hellenic academic", "atos", "camerfirma", "chunghwa telecom",
    "e-me", "asseco", "tw ca", "quovadis root", "certsign",
    # CAs também comuns em Win11 baseline / OEM
    "baltimore", "t-systems", "teliasonera", "telia sonera", "swisscom",
    "ssl.com", "dst root", "dfn-verein", "starcom",
    "ac raiz fnmt-rcm", "fnmt", "izenpe", "acraiz",
    "certigna", "certinomis", "e-guven", "government of turkey",
    "türkiye", "hongkong", "microsec e-szigno",
    "sslcom", "gigatrust", "digital signature trust",
    "consorci aoc", "cca india", "camerasoft",
    # Enterprises / tools comuns
    "cisco", "juniper", "ibm", "oracle", "vmware", "citrix",
    "logmein", "teamviewer", "anydesk", "zoom",
    # Autohotkey / dev tools que instalam self-signed local (dual-use, não MitM)
    "autohotkey",
    # Dev/localhost self-signed (mkcert, dotnet dev-certs, IIS Express, docker)
    "mkcert", "localhost", "iis express", "development",
    "dotnet-httpsdevcert", "asp.net core", "kestrel",
    "docker", "kubernetes", "minikube",
    # Antivirus
    "kaspersky", "eset", "bitdefender", "avast", "avg",
    "malwarebytes", "sophos", "trend micro",
    # Government / generic CA naming
    "root ca", "certificate authority", "root certification",
)

_SUSPICIOUS_CERT_TOKENS = (
    "hack", "cheat", "bypass", "loader", "keyauth",
    "solara", "winter", "wave", "krnl",
)

# Considera cert "recente" se foi criado nos últimos N dias
_RECENT_CERT_DAYS = 90


def _powershell():
    if HAS_WIN_TOOLS:
        return win_tools.powershell()
    return "powershell.exe"


def _is_trusted_subject(subject: str) -> bool:
    s = (subject or "").lower()
    return any(m in s for m in _TRUSTED_CA_MARKERS)


def _has_suspicious_token(text: str) -> str | None:
    s = (text or "").lower()
    for t in _SUSPICIOUS_CERT_TOKENS:
        if t in s:
            return t
    return None


def scan_certificate_store() -> dict:
    """
    Lista certificados raiz (LocalMachine\\Root e CurrentUser\\Root) e flagga:
      - Cert auto-assinado (Subject == Issuer) que não é de CA conhecida
      - Cert com Subject/Issuer contendo tokens suspeitos (cheat/hack/bypass)
      - Cert instalado recentemente (últimos 90 dias) fora de CAs de update
    """
    name = "Certificate Store (root CA injection)"
    desc = ("Certificados raiz falsos = MitM HTTPS e bypass de SmartScreen. "
            "Flagga auto-assinados + recentes fora de CAs reconhecidas.")

    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$stores = @('Cert:\\LocalMachine\\Root', 'Cert:\\CurrentUser\\Root');"
        "foreach ($store in $stores) {"
        "  Get-ChildItem $store | ForEach-Object {"
        "    $line = 'CERT::' + $store + '::';"
        "    $line += 'SUBJ=' + $_.Subject + '::';"
        "    $line += 'ISSUER=' + $_.Issuer + '::';"
        "    $line += 'NBEF=' + $_.NotBefore.ToString('yyyy-MM-dd') + '::';"
        "    $line += 'NAFT=' + $_.NotAfter.ToString('yyyy-MM-dd') + '::';"
        "    $line += 'THUMB=' + $_.Thumbprint;"
        "    Write-Output $line"
        "  }"
        "}"
    )
    try:
        result = subprocess.run(
            [_powershell(), "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=45,
            encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return _result(name, desc, [], error=str(e))

    if result.returncode != 0 and not result.stdout.strip():
        return _result(name, desc, [], error="Cert store inacessível")

    items = []
    cutoff_recent = datetime.now() - timedelta(days=_RECENT_CERT_DAYS)

    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("CERT::"):
            continue
        parts = line[6:].split("::")
        if len(parts) < 6:
            continue

        store = parts[0]
        fields = {}
        for p in parts[1:]:
            if "=" in p:
                k, _, v = p.partition("=")
                fields[k.strip()] = v.strip()

        subject = fields.get("SUBJ", "")
        issuer = fields.get("ISSUER", "")
        nbef = fields.get("NBEF", "")
        naft = fields.get("NAFT", "")
        thumb = fields.get("THUMB", "")

        if not subject:
            continue

        # 1. Token suspeito no Subject ou Issuer = flagga direto
        susp = _has_suspicious_token(subject) or _has_suspicious_token(issuer)
        if susp:
            items.append(_item(
                label=f"[CertStore] Token suspeito: {subject[:60]}",
                detail=(f"Store: {store}\nSubject: {subject}\n"
                        f"Issuer: {issuer}\nValid: {nbef} → {naft}\n"
                        f"Thumbprint: {thumb}\n"
                        f"Token '{susp}' no Subject/Issuer — cert nomeado como "
                        f"cheat/hack/bypass = install óbvio pra MitM ou "
                        f"self-signed pra loaders."),
                severity="critical", matched=f"cert-suspicious-token:{susp}",
            ))
            continue

        # 2. Auto-assinado + não é CA conhecida
        is_self_signed = subject.strip().lower() == issuer.strip().lower()
        is_trusted = _is_trusted_subject(subject) or _is_trusted_subject(issuer)

        if is_self_signed and not is_trusted:
            # Se é recente = high; se é antigo = medium (pode ser corp legado)
            severity = "medium"
            reason = "Auto-assinado + não é CA conhecida"

            try:
                nbef_dt = datetime.strptime(nbef, "%Y-%m-%d")
                if nbef_dt >= cutoff_recent:
                    severity = "high"
                    reason += f" + instalado recentemente ({nbef})"
            except (ValueError, TypeError):
                pass

            items.append(_item(
                label=f"[CertStore] Self-signed: {subject[:60]}",
                detail=(f"Store: {store}\nSubject: {subject}\n"
                        f"Issuer: {issuer}\nValid: {nbef} → {naft}\n"
                        f"Thumbprint: {thumb}\n"
                        f"Motivo: {reason}\n"
                        f"Cert self-signed fora de CA reconhecida na raiz = "
                        f"vetor de MitM (HTTPS interceptado) e bypass de "
                        f"SmartScreen (loaders custom passam como assinados)."),
                severity=severity, matched="cert-selfsigned-unknown",
            ))

    return _result(name, desc, items)


ALL_CERT_STORE_SCANNERS = [
    scan_certificate_store,
]
