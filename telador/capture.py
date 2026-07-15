"""
Captura de tela e da janela do Roblox usando GDI nativo (sem PIL).
Salva como BMP e converte pra PNG inline (compressão zlib + chunks PNG manuais).
"""

import os
import ctypes
import struct
import zlib
import tempfile
from ctypes import wintypes
from datetime import datetime


user32   = ctypes.windll.user32
gdi32    = ctypes.windll.gdi32
kernel32 = ctypes.windll.kernel32

SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", wintypes.DWORD * 3),
    ]


def _capture_rect(left, top, width, height) -> tuple[int, int, bytes] | None:
    """
    Captura uma região da tela. Retorna (width, height, bgra_bytes) ou None.
    """
    if width <= 0 or height <= 0:
        return None

    hdesktop = user32.GetDesktopWindow()
    src_dc   = user32.GetWindowDC(hdesktop)
    mem_dc   = gdi32.CreateCompatibleDC(src_dc)
    bitmap   = gdi32.CreateCompatibleBitmap(src_dc, width, height)
    old_obj  = gdi32.SelectObject(mem_dc, bitmap)

    try:
        ok = gdi32.BitBlt(mem_dc, 0, 0, width, height, src_dc, left, top, SRCCOPY)
        if not ok:
            return None

        bmi = BITMAPINFO()
        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
        bmi.bmiHeader.biWidth = width
        bmi.bmiHeader.biHeight = -height  # negativo → top-down
        bmi.bmiHeader.biPlanes = 1
        bmi.bmiHeader.biBitCount = 32
        bmi.bmiHeader.biCompression = 0  # BI_RGB

        buf_size = width * height * 4
        buf = (ctypes.c_ubyte * buf_size)()

        rows = gdi32.GetDIBits(mem_dc, bitmap, 0, height, buf,
                               ctypes.byref(bmi), DIB_RGB_COLORS)
        if rows == 0:
            return None

        return (width, height, bytes(buf))
    finally:
        gdi32.SelectObject(mem_dc, old_obj)
        gdi32.DeleteObject(bitmap)
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(hdesktop, src_dc)


def _bgra_to_png_bytes(width, height, bgra) -> bytes:
    """
    Converte BGRA top-down em PNG (RGB) sem usar PIL.
    PNG specification: signature + IHDR + IDAT + IEND.
    """
    # 1. Sinal PNG
    signature = b"\x89PNG\r\n\x1a\n"

    # 2. IHDR
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # bit_depth=8, color_type=2 (RGB)
    ihdr = _png_chunk(b"IHDR", ihdr_data)

    # 3. IDAT — converte BGRA→RGB + adiciona filter byte por linha
    stride = width * 4
    rgb_rows = []
    for y in range(height):
        row = bgra[y * stride:(y + 1) * stride]
        # Filtragem: 0 (None) seguido de RGB bytes
        rgb = bytearray([0])
        for x in range(width):
            b = row[x * 4]
            g = row[x * 4 + 1]
            r = row[x * 4 + 2]
            rgb.extend([r, g, b])
        rgb_rows.append(bytes(rgb))

    compressed = zlib.compress(b"".join(rgb_rows), level=6)
    idat = _png_chunk(b"IDAT", compressed)

    # 4. IEND
    iend = _png_chunk(b"IEND", b"")

    return signature + ihdr + idat + iend


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    length = struct.pack(">I", len(data))
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return length + chunk_type + data + struct.pack(">I", crc)


def capture_desktop(output_dir: str = None) -> str | None:
    """Captura toda a tela primária. Retorna o caminho do PNG, ou None."""
    width = user32.GetSystemMetrics(0)
    height = user32.GetSystemMetrics(1)
    cap = _capture_rect(0, 0, width, height)
    if cap is None:
        return None

    if output_dir is None:
        output_dir = tempfile.gettempdir()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(output_dir, f"telador_screen_{ts}.png")

    try:
        png_bytes = _bgra_to_png_bytes(*cap)
        with open(out_path, "wb") as fh:
            fh.write(png_bytes)
        return out_path
    except (OSError, MemoryError):
        return None


def capture_roblox_window(output_dir: str = None) -> str | None:
    """
    Tenta achar a janela do Roblox e capturar só ela.
    Roblox usa classes "WINDOWSCLIENT" ou title contendo "Roblox".
    """
    # Procura por title
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, ctypes.c_void_p)
    target_hwnd = [None]

    def callback(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value or ""
        if "roblox" in title.lower():
            target_hwnd[0] = hwnd
            return False
        return True

    user32.EnumWindows(EnumWindowsProc(callback), 0)
    if target_hwnd[0] is None:
        return None

    rect = wintypes.RECT()
    user32.GetWindowRect(target_hwnd[0], ctypes.byref(rect))
    width = rect.right - rect.left
    height = rect.bottom - rect.top
    if width <= 0 or height <= 0:
        return None

    cap = _capture_rect(rect.left, rect.top, width, height)
    if cap is None:
        return None

    if output_dir is None:
        output_dir = tempfile.gettempdir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(output_dir, f"telador_roblox_{ts}.png")

    try:
        png_bytes = _bgra_to_png_bytes(*cap)
        with open(out_path, "wb") as fh:
            fh.write(png_bytes)
        return out_path
    except (OSError, MemoryError):
        return None


def _enum_monitors() -> list[tuple[int, int, int, int]]:
    """Retorna lista de rects de todos os monitores: [(left, top, width, height), ...]"""
    monitors = []

    MonitorEnumProc = ctypes.WINFUNCTYPE(
        ctypes.c_bool,
        wintypes.HMONITOR,
        wintypes.HDC,
        ctypes.POINTER(wintypes.RECT),
        ctypes.c_void_p,
    )

    def callback(_hmonitor, _hdc, lprect, _data):
        r = lprect.contents
        monitors.append((r.left, r.top, r.right - r.left, r.bottom - r.top))
        return True

    user32.EnumDisplayMonitors(None, None, MonitorEnumProc(callback), 0)
    return monitors


def capture_all_monitors(output_dir: str = None) -> list[str]:
    """
    Captura TODOS os monitores conectados separadamente.
    Cheater experiente bota cheat no monitor 2 (HUD externo, mira, etc.) —
    capturar só primary não pega.
    """
    monitors = _enum_monitors()
    paths = []

    if output_dir is None:
        output_dir = tempfile.gettempdir()

    base_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    for i, (left, top, w, h) in enumerate(monitors, 1):
        cap = _capture_rect(left, top, w, h)
        if cap is None:
            continue
        out_path = os.path.join(output_dir, f"telador_monitor{i}_{base_ts}.png")
        try:
            png_bytes = _bgra_to_png_bytes(*cap)
            with open(out_path, "wb") as fh:
                fh.write(png_bytes)
            paths.append(out_path)
        except (OSError, MemoryError):
            continue

    return paths


def capture_all() -> dict:
    """
    Captura desktop primário + janela do Roblox + TODOS os monitores secundários.
    Retorna dict ordenado:
      {"monitor_1": ..., "monitor_2": ..., ..., "roblox": ...}
    """
    result = {}

    monitor_paths = capture_all_monitors()
    for i, path in enumerate(monitor_paths, 1):
        result[f"monitor_{i}"] = path

    # Se não conseguiu pegar nada via EnumDisplayMonitors, cai pra desktop primary
    if not monitor_paths:
        result["desktop"] = capture_desktop()

    result["roblox"] = capture_roblox_window()
    return result
