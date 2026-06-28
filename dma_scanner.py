"""
Detecção (PARCIAL, heurística) de cheat de HARDWARE DMA.

DMA cheat = placa FPGA num slot PCIe (ou ligada por USB3) que lê a RAM do PC sem
software rodando do lado do jogo, + às vezes um kmbox no USB pra emular mouse. É o
método mais difícil de pegar: o cheat está no HARDWARE/firmware, não há processo
nem arquivo pra varrer. Boa parte fica genuinamente fora do alcance de software —
o firmware das placas boas até SPOOFA o device ID pra imitar um dispositivo legítimo.

O que dá pra fazer por software (e é o que este scanner faz): enumerar os
dispositivos PCIe/USB que o Windows registrou (HKLM\\...\\Enum\\PCI e \\USB) e
flaggar IDs de alta confiança:
  - FPGA Xilinx no PCIe (VEN_10EE) — base da esmagadora maioria das placas DMA
    (PCIeScreamer, LeetDMA, CaptainDMA). Num PC de jogador, é bandeira vermelha.
  - chip USB3 FT601 (VID_0403&PID_601F) — a "ponte" USB típica das placas DMA.
  - FPGA Altera/Lattice (sinal mais fraco — também aparece em hardware legítimo).

NÃO é bala de prata: placa com ID spoofado pra um NIC/som conhecido passa batido,
e um dev board de FPGA legítimo daria falso positivo. Por isso o veredito é
heurístico (corrobora no Confidence Engine, não crava sozinho). A lista de IDs é
fácil de estender — some aqui os que aprender (canais detecting-dma-fusers /
detecting-pcies).
"""

from models import _result, _item
import re

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ============================ Tabelas de IDs ============================
# VEN_ do PCIe -> (fabricante, severidade). Hex em UPPERCASE.
DMA_PCI_VENDORS = {
    "10EE": ("Xilinx", "high"),          # PCIeScreamer / LeetDMA / CaptainDMA
    "1172": ("Altera/Intel FPGA", "medium"),
    "1204": ("Lattice", "medium"),
}

# (VID, PID) do USB -> (descrição, severidade). Hex em UPPERCASE.
DMA_USB_IDS = {
    ("0403", "601F"): ("FTDI FT601 (USB3 FIFO — ponte típica de placa DMA)", "high"),
    ("0403", "601E"): ("FTDI FT600 (USB3 FIFO)", "medium"),
}

_VEN_RE = re.compile(r"VEN_([0-9A-Fa-f]{4})")
_VID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})")
_PID_RE = re.compile(r"PID_([0-9A-Fa-f]{4})")


# ============================ Classificadores puros ============================

def _classify_pci(hwid: str):
    """(severity, fabricante, ven) se o ID PCIe casa um FPGA conhecido; senão None.
    Casa SÓ o campo VEN_ (não o SUBSYS, que carrega o subvendor e poderia
    conter os mesmos 4 dígitos por acaso)."""
    m = _VEN_RE.search(hwid or "")
    if not m:
        return None
    ven = m.group(1).upper()
    info = DMA_PCI_VENDORS.get(ven)
    if not info:
        return None
    fab, sev = info
    return sev, fab, ven


def _classify_usb(hwid: str):
    """(severity, descrição, 'VID:PID') se o ID USB casa; senão None."""
    mv, mp = _VID_RE.search(hwid or ""), _PID_RE.search(hwid or "")
    if not (mv and mp):
        return None
    vid, pid = mv.group(1).upper(), mp.group(1).upper()
    info = DMA_USB_IDS.get((vid, pid))
    if not info:
        return None
    desc, sev = info
    return sev, desc, f"{vid}:{pid}"


# ============================ Enumeração (registro) ============================

_PCI_BRANCH = r"SYSTEM\CurrentControlSet\Enum\PCI"
_USB_BRANCH = r"SYSTEM\CurrentControlSet\Enum\USB"


def _friendly_name(dev_key) -> str:
    """FriendlyName/DeviceDesc do primeiro instance subkey, ou '' se indisponível."""
    try:
        inst_name = winreg.EnumKey(dev_key, 0)
        with winreg.OpenKey(dev_key, inst_name) as inst:
            for val in ("FriendlyName", "DeviceDesc"):
                try:
                    raw, _ = winreg.QueryValueEx(inst, val)
                except OSError:
                    continue
                # DeviceDesc costuma vir "@file,#id;Nome" — fica com o que vem após ';'
                return str(raw).split(";")[-1].strip()
    except OSError:
        pass
    return ""


def _iter_enum_subkeys(branch: str):
    """Itera (hardware_id, friendly_name) dos dispositivos sob uma branch Enum.
    Isolado e mockável — o teste real exercita o registro; os unit tests mockam."""
    if not HAS_WINREG:
        return
    try:
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, branch)
    except OSError:
        return
    try:
        i = 0
        while True:
            try:
                hwid = winreg.EnumKey(root, i)
            except OSError:
                break
            i += 1
            friendly = ""
            try:
                with winreg.OpenKey(root, hwid) as dev_key:
                    friendly = _friendly_name(dev_key)
            except OSError:
                pass
            yield hwid, friendly
    finally:
        winreg.CloseKey(root)


def scan_dma_devices() -> dict:
    """Enumera dispositivos PCIe/USB e flagga IDs de placa DMA / ponte conhecidos."""
    name = "Hardware DMA (placa FPGA / fuser)"
    desc = "Dispositivo PCIe/USB compatível com cheat de DMA (heurístico)"
    if not HAS_WINREG:
        return _result(name, desc, [], error="registro indisponível (não-Windows)")

    items = []

    for hwid, friendly in _iter_enum_subkeys(_PCI_BRANCH):
        res = _classify_pci(hwid)
        if not res:
            continue
        sev, fab, ven = res
        items.append(_item(
            label=f"PCIe FPGA suspeito: {friendly or fab}",
            detail=f"{hwid}\n"
                   f"Dispositivo PCIe com VEN_{ven} ({fab}). Placas de cheat DMA "
                   f"são FPGAs — a esmagadora maioria é Xilinx. Num PC de jogador "
                   f"isso é bandeira vermelha. Pode ser dev board / placa de captura "
                   f"legítima — confirme fisicamente. (Firmware que SPOOFA o ID passa "
                   f"batido: ausência aqui NÃO inocenta.)",
            severity=sev, matched=f"dma-pci:{ven}",
        ))

    for hwid, friendly in _iter_enum_subkeys(_USB_BRANCH):
        res = _classify_usb(hwid)
        if not res:
            continue
        sev, udesc, vidpid = res
        items.append(_item(
            label=f"USB suspeito (DMA): {friendly or udesc}",
            detail=f"{hwid}\n"
                   f"Dispositivo USB {vidpid} — {udesc}. É a interface USB típica "
                   f"das placas DMA. Confirme o que é fisicamente. (Heurístico — "
                   f"esse chip também tem uso industrial legítimo.)",
            severity=sev, matched=f"dma-usb:{vidpid}",
        ))

    return _result(name, desc, items)


ALL_DMA_SCANNERS = [
    scan_dma_devices,
]
