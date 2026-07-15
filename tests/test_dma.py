"""
Testes do scanner de hardware DMA (scan_dma_devices).

Prova:
  - Classificadores puros: VEN_ de FPGA conhecido casa (e SÓ o VEN_, não o
    SUBSYS); VID&PID de ponte USB conhecida casa; o resto não.
  - O scanner monta item HIGH p/ Xilinx no PCIe e p/ FT601 no USB, e fica clean
    quando os dispositivos são comuns.
  - Integração: registrado, roteia p/ dma_hardware, alimenta o cluster engine.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telador import dma_scanner as dma  # noqa: E402
# ----------------------------- classificadores puros -----------------------------

def test_pci_xilinx_is_high():
    res = dma._classify_pci("VEN_10EE&DEV_7024&SUBSYS_000710EE&REV_00")
    assert res is not None
    sev, fab, ven = res
    assert sev == "high" and ven == "10EE" and "Xilinx" in fab


def test_pci_subsys_does_not_false_match():
    """Os 4 dígitos do FPGA aparecendo no SUBSYS (subvendor) NÃO podem casar —
    só o campo VEN_ vale."""
    # VEN legítimo (Intel 8086), mas SUBSYS contém '10EE' por acaso
    assert dma._classify_pci("VEN_8086&DEV_1234&SUBSYS_10EE1234&REV_01") is None


def test_pci_common_vendor_clean():
    assert dma._classify_pci("VEN_10DE&DEV_2208&SUBSYS_...&REV_A1") is None  # NVIDIA


def test_pci_altera_is_medium():
    res = dma._classify_pci("VEN_1172&DEV_0004")
    assert res and res[0] == "medium"


def test_usb_ft601_is_high():
    res = dma._classify_usb("VID_0403&PID_601F")
    assert res is not None
    sev, desc, matched = res
    assert sev == "high" and matched == "dma-usb:0403:601F"


def test_usb_common_device_clean():
    """Mouse/teclado comum não casa."""
    assert dma._classify_usb("VID_046D&PID_C52B") is None  # Logitech receiver


def test_usb_missing_pid_clean():
    assert dma._classify_usb("VID_0403") is None


def test_kmbox_hook_extensible(monkeypatch):
    """KMBOX_USB_IDS vem vazio (anti-FP), mas o hook funciona: ao popular com um
    ID verificado, casa como kmbox-usb (distinto de dma-usb)."""
    assert dma.KMBOX_USB_IDS == {}  # default seguro
    monkeypatch.setitem(dma.KMBOX_USB_IDS, ("1234", "5678"),
                        ("kmbox B+ (verificado)", "high"))
    res = dma._classify_usb("VID_1234&PID_5678")
    assert res and res[0] == "high" and res[2] == "kmbox-usb:1234:5678"


# ----------------------------- scanner (mockado) -----------------------------

def _patch(monkeypatch, pci=(), usb=()):
    def fake_iter(branch):
        if branch == dma._PCI_BRANCH:
            return iter(pci)
        if branch == dma._USB_BRANCH:
            return iter(usb)
        return iter(())
    monkeypatch.setattr(dma, "HAS_WINREG", True)
    monkeypatch.setattr(dma, "_iter_enum_subkeys", fake_iter)


def test_scanner_flags_xilinx_pcie(monkeypatch):
    _patch(monkeypatch,
           pci=[("VEN_10EE&DEV_7024&SUBSYS_000710EE&REV_00", "PCIe FPGA Device")])
    r = dma.scan_dma_devices()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "dma-pci:10EE"
    assert "PCIe FPGA Device" in it["label"]


def test_scanner_flags_ft601_usb(monkeypatch):
    _patch(monkeypatch, usb=[("VID_0403&PID_601F", "USB Serial Converter")])
    r = dma.scan_dma_devices()
    it = r["items"][0]
    assert it["severity"] == "high"
    assert it["matched"] == "dma-usb:0403:601F"


def test_scanner_clean_on_normal_devices(monkeypatch):
    _patch(monkeypatch,
           pci=[("VEN_10DE&DEV_2208", "NVIDIA GPU"),
                ("VEN_8086&DEV_a3af", "Intel USB Controller")],
           usb=[("VID_046D&PID_C52B", "Logitech Receiver")])
    assert dma.scan_dma_devices()["status"] == "clean"


def test_scanner_falls_back_to_id_without_friendly_name(monkeypatch):
    """Sem FriendlyName, usa o fabricante/descrição no label."""
    _patch(monkeypatch, pci=[("VEN_10EE&DEV_0001", "")])
    it = dma.scan_dma_devices()["items"][0]
    assert "Xilinx" in it["label"]


# ----------------------------- integração -----------------------------

def test_registered_in_scanner_list():
    assert dma.scan_dma_devices in dma.ALL_DMA_SCANNERS


def test_slug_maps_to_dma_hardware():
    from telador import evidence as ev
    from telador import report_assets
    assert ev._source_slug_from_name("Hardware DMA (placa FPGA / fuser)") == "dma_hardware"
    assert "dma_hardware" in ev.SOURCE_WEIGHTS
    # label próprio no relatório (senão cai no fallback feio "Dma Hardware")
    assert "dma_hardware" in report_assets.SOURCE_LABELS


def test_feeds_cluster_engine():
    from telador import evidence as ev
    findings = [{
        "name": "Hardware DMA (placa FPGA / fuser)",
        "status": "suspicious",
        "items": [{
            "label": "PCIe FPGA suspeito: PCIe FPGA Device",
            "detail": "VEN_10EE&DEV_7024",
            "matched": "dma-pci:10EE", "severity": "high",
            "timestamp": "", "confidence": 80,
        }],
    }]
    clusters = ev.build_clusters(ev.findings_to_evidences(findings))
    assert len(clusters) == 1


def test_real_machine_no_crash():
    """No PC real: enumera o registro de verdade, não pode crashar."""
    r = dma.scan_dma_devices()
    assert r["status"] in ("clean", "suspicious", "error")
    for it in r["items"]:
        assert it["severity"] in ("high", "medium")
