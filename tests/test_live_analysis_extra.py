"""
Testes adicionais do live_analysis para scan_roblox_debuggers e scan_roblox_manual_map.
"""

import os
import sys
import ctypes
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import live_analysis as la  # noqa: E402


class FakeProcess:
    def __init__(self, pid, name):
        self.info = {"pid": pid, "name": name}


def _fake_pe(size=0x200, e_lfanew=0x40, valid_sig=True):
    """Constrói uma imagem PE de teste: 'MZ' + e_lfanew + 'PE\\0\\0'."""
    img = bytearray(b"\x00" * size)
    img[0:2] = b"MZ"
    img[0x3C:0x40] = int(e_lfanew).to_bytes(4, "little")
    img[e_lfanew:e_lfanew + 4] = b"PE\x00\x00" if valid_sig else b"XX\x00\x00"
    return bytes(img)


class MockKernel32:
    def __init__(self):
        self.is_dbg = False
        self.query_mbi = None
        self.read_data = None
        # Imagem servida byte-a-byte por endereço (pra validar PE completo)
        self.mem_image = None
        self.mem_base = 0

    def OpenProcess(self, mask, inherit, pid):
        return 12345

    def CloseHandle(self, handle):
        return True

    def CheckRemoteDebuggerPresent(self, handle, is_dbg_ptr):
        is_dbg_ptr.contents.value = self.is_dbg
        return True

    def VirtualQueryEx(self, handle, addr, mbi_ptr, size):
        if self.query_mbi:
            mbi_ptr.contents.BaseAddress = self.query_mbi.BaseAddress
            mbi_ptr.contents.RegionSize = self.query_mbi.RegionSize
            mbi_ptr.contents.State = self.query_mbi.State
            mbi_ptr.contents.Type = self.query_mbi.Type
            mbi_ptr.contents.Protect = self.query_mbi.Protect
            self.query_mbi = None
            return size
        return 0

    def ReadProcessMemory(self, handle, addr, buf_ptr, size, bytes_read_ptr):
        # Serve de uma imagem em memória (mem_base/mem_image) quando setada —
        # respeita offset por endereço e tamanho pedido (pra validar PE inteiro).
        if self.mem_image is not None:
            off = (getattr(addr, "value", None) or 0) - self.mem_base
            chunk = self.mem_image[off:off + size] if off >= 0 else b""
            if len(chunk) < size:
                bytes_read_ptr.contents.value = 0
                return False
            bytes_read_ptr.contents.value = len(chunk)
            ctypes.memmove(buf_ptr, chunk, len(chunk))
            return True
        if self.read_data:
            n = min(len(self.read_data), size)
            bytes_read_ptr.contents.value = n
            ctypes.memmove(buf_ptr, self.read_data, n)
            return True
        bytes_read_ptr.contents.value = 0
        return False


class MockNtdll:
    def __init__(self):
        self.dbg_port = 0

    def NtQueryInformationProcess(self, handle, info_class, info_ptr, info_len, ret_len_ptr):
        if info_class == 7:  # ProcessDebugPort
            val_ptr = ctypes.cast(info_ptr, ctypes.POINTER(wintypes.DWORD))
            val_ptr.contents.value = self.dbg_port
            return 0  # STATUS_SUCCESS
        return -1


def test_scan_roblox_debuggers_clean(monkeypatch):
    """Sem processo Roblox, deve retornar clean."""
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [])
    
    r = la.scan_roblox_debuggers()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_scan_roblox_debuggers_detected_by_present(monkeypatch):
    """Presença de debugger detectada por CheckRemoteDebuggerPresent."""
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [
        FakeProcess(9999, "RobloxPlayerBeta.exe")
    ])
    
    mock_k32 = MockKernel32()
    mock_k32.is_dbg = True
    monkeypatch.setattr(la, "kernel32", mock_k32)
    
    r = la.scan_roblox_debuggers()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["severity"] == "high"
    assert r["items"][0]["matched"] == "roblox-debugger-present"


def test_scan_roblox_debuggers_detected_by_port(monkeypatch):
    """Presença de debugger detectada por NtQueryInformationProcess (ProcessDebugPort)."""
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [
        FakeProcess(9999, "RobloxPlayerBeta.exe")
    ])
    
    mock_k32 = MockKernel32()
    mock_k32.is_dbg = False
    monkeypatch.setattr(la, "kernel32", mock_k32)
    
    mock_nt = MockNtdll()
    mock_nt.dbg_port = 0xFFFFFFFF
    monkeypatch.setattr(la, "ntdll", mock_nt)
    
    r = la.scan_roblox_debuggers()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    assert r["items"][0]["severity"] == "high"
    assert r["items"][0]["matched"] == "roblox-debug-port"


def test_scan_roblox_manual_map_clean(monkeypatch):
    """Sem manual map e sem páginas executáveis com 'MZ', deve ser clean."""
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [
        FakeProcess(9999, "RobloxPlayerBeta.exe")
    ])
    
    mock_k32 = MockKernel32()
    # Cria uma página não-executável
    mbi = la.MEMORY_BASIC_INFORMATION()
    mbi.BaseAddress = 0x1000
    mbi.RegionSize = 0x1000
    mbi.State = la.MEM_COMMIT
    mbi.Type = la.MEM_PRIVATE
    mbi.Protect = 0x04  # PAGE_READWRITE (não-executável)
    mock_k32.query_mbi = mbi
    
    monkeypatch.setattr(la, "kernel32", mock_k32)
    
    r = la.scan_roblox_manual_map()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def _exec_priv_mbi(base=0x5000, size=0x10000):
    mbi = la.MEMORY_BASIC_INFORMATION()
    mbi.BaseAddress = base
    mbi.RegionSize = size
    mbi.State = la.MEM_COMMIT
    mbi.Type = la.MEM_PRIVATE
    mbi.Protect = la.PAGE_EXECUTE_READWRITE
    return mbi


def test_scan_roblox_manual_map_detected(monkeypatch):
    """Página executável privada com imagem PE COMPLETA -> manual map (MEDIUM)."""
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [
        FakeProcess(9999, "RobloxPlayerBeta.exe")
    ])

    mock_k32 = MockKernel32()
    mock_k32.query_mbi = _exec_priv_mbi(base=0x5000)
    mock_k32.mem_base = 0x5000
    mock_k32.mem_image = _fake_pe()          # MZ + e_lfanew + 'PE\0\0'
    monkeypatch.setattr(la, "kernel32", mock_k32)

    r = la.scan_roblox_manual_map()
    assert r["status"] == "suspicious"
    assert len(r["items"]) == 1
    # FIX v3.36.3: MEDIUM (precisa corroboração; Hyperion também aloca código)
    assert r["items"][0]["severity"] == "medium"
    assert r["items"][0]["matched"] == "manual-map-dll"


def test_scan_roblox_manual_map_coincidental_mz_not_flagged(monkeypatch):
    """FIX FP v3.36.3: região executável com 'MZ' solto mas SEM assinatura PE
    válida (código JIT / bytes coincidentes) NÃO é mais flaggada."""
    monkeypatch.setattr(la, "HAS_PSUTIL", True)
    import psutil
    monkeypatch.setattr(psutil, "process_iter", lambda attrs=None: [
        FakeProcess(9999, "RobloxPlayerBeta.exe")
    ])

    mock_k32 = MockKernel32()
    mock_k32.query_mbi = _exec_priv_mbi(base=0x5000)
    mock_k32.mem_base = 0x5000
    # 'MZ' no início mas o ponteiro PE aponta pra 'XX\0\0' (assinatura inválida)
    mock_k32.mem_image = _fake_pe(valid_sig=False)
    monkeypatch.setattr(la, "kernel32", mock_k32)

    r = la.scan_roblox_manual_map()
    assert r["status"] == "clean"
    assert len(r["items"]) == 0


def test_region_is_pe_helper(monkeypatch):
    """Núcleo da validação: PE completo = True; só 'MZ' / sig inválida = False."""
    mock_k32 = MockKernel32()
    mock_k32.mem_base = 0x1000
    monkeypatch.setattr(la, "kernel32", mock_k32)

    mock_k32.mem_image = _fake_pe()
    assert la._region_is_pe(1, 0x1000, 0x10000) is True

    mock_k32.mem_image = _fake_pe(valid_sig=False)
    assert la._region_is_pe(1, 0x1000, 0x10000) is False

    # e_lfanew apontando pra fora da região = rejeitado
    mock_k32.mem_image = _fake_pe(e_lfanew=0x100)
    assert la._region_is_pe(1, 0x1000, 0x80) is False
