#!/usr/bin/env python3
"""
BB Map Viewer - standalone live map window for Bloodborne on Windows (read only).

Reads the player's position from the running game's memory (ReadProcessMemory), using the same
1.09 eboot offsets and pointer chain as Hunter's Atlas / runtime_atlas.c, and draws it on the
vector floor plans that Hunter's Atlas generated from your own game files (maps/m??_??_??_??.json
inside assets.atlaslite, or in <Atlas>\\state\\runtime-assets\\maps). Drag the window to your
external monitor and press F (or use the menu). Nothing is written to the game.

Setup:    python -m pip install pillow        (Atlas' bundled runtime\\python\\python.exe works too:
                                              run  runtime\\python\\python.exe -m ensurepip  first)
Run:      python bb_map_viewer.py --maps "C:\\path\\to\\assets.atlaslite"
          (a folder with the map json files also works; if the pack sits next to this script
          you can leave --maps out)
Options:  --proc NAME   game process name (default: auto-detect a process using > 1.5 GB)
          --pid N       attach to this process id
Keys:     F fullscreen (on the external monitor if present; F or Esc leaves)   A always on top   wheel / + - zoom   T clear trail
          L show lamp names (ALL lamps, undiscovered too)   V flip north/south
          C re-learn arrow direction (walk around)
          R rotate arrow 90 deg   M mirror arrow   Q quit (manual fixes)
The bright floor is the 3 m band you are standing on (plus the one below); other levels are dim.
"""
import argparse
import ctypes
import json
import math
import os
import struct
import subprocess
import sys
import threading
import time

# ---- offsets for the 1.09 eboot (from runtime_atlas.c / Hunter's Atlas) -------------------------
BUILD_OFF = 0x18DB3C0
WORLD_SLOT = 0x553E878
MENU_SLOT = 0x5562878
MENU_GUARD_OFF = 0x176B89B
FOCUS_GUARD_OFF = 0x1BDF835
BUILD_GUARD = bytes([
    0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53, 0x48, 0x83, 0xec,
    0x38, 0x89, 0x55, 0xd4, 0x41, 0x89, 0xf7, 0x48, 0x89, 0xfb, 0x4c, 0x8d, 0x35, 0x97, 0x34, 0xc6,
    0x03, 0x49, 0x8b, 0x0e, 0x48, 0x85, 0xc9, 0x75, 0x24, 0x48, 0x8d, 0x3d, 0x79, 0xff, 0x05, 0x03,
    0x48, 0x8d, 0x15, 0xc6, 0xff, 0x05, 0x03, 0x48, 0x8d, 0x0d, 0x6d, 0xfe, 0x05, 0x03, 0xbe, 0xb1])
MENU_GUARD = bytes([0x48, 0x8b, 0x05, 0xd6, 0x6f, 0xdf, 0x03, 0x83, 0x78, 0x3c, 0x00])
FOCUS_GUARD = bytes([0x8b, 0x8b, 0xe8, 0x0a, 0, 0, 0x85, 0xc9, 0x79, 0x06, 0x8b, 0x8b, 0xe4, 0x0a, 0, 0])


def u32(b, o=0):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o=0):
    return struct.unpack_from("<Q", b, o)[0]


# ---- memory access ---------------------------------------------------------------------------------
class WinMem:
    """Read-only access to another process on Windows."""

    def __init__(self, pid):
        import ctypes.wintypes as wt
        self.k = k = ctypes.WinDLL("kernel32", use_last_error=True)

        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD),
                        ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
                        ("Protect", wt.DWORD), ("Type", wt.DWORD)]
        self.MBI = MBI
        k.OpenProcess.restype = ctypes.c_void_p
        k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k.ReadProcessMemory.restype = wt.BOOL
        k.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        k.VirtualQueryEx.restype = ctypes.c_size_t
        k.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        self.h = k.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFORMATION | VM_READ
        if not self.h:
            raise OSError("OpenProcess failed (error %d)" % ctypes.get_last_error())

    def read(self, addr, size):
        if addr < 0x10000 or size <= 0 or addr + size > 0x7FFFFFFFFFFF:
            return None
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        ok = self.k.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
        return buf.raw if ok and n.value == size else None

    def regions(self):
        """Yield (base, size, state, protect) for the whole address space."""
        addr = 0
        mbi = self.MBI()
        while addr < 0x7FFFFFFF0000:
            if not self.k.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            yield base, mbi.RegionSize, mbi.State, mbi.Protect
            nxt = base + mbi.RegionSize
            if nxt <= addr:
                break
            addr = nxt

    def close(self):
        if self.h:
            self.k.CloseHandle(self.h)
            self.h = None


def ptr(mem, at):
    d = mem.read(at, 8)
    return u64(d) if d else 0


def find_base(mem, log=print):
    """Find the guest executable image by its byte fingerprint. Returns the image base or None."""
    chunk = 4 << 20
    readable = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80
    for executable_only in (True, False):
        for base, size, state, prot in mem.regions():
            if state != 0x1000 or not (prot & readable) or (prot & 0x101):
                continue
            if executable_only and not (prot & 0xF0):
                continue
            if size < len(BUILD_GUARD):
                continue
            off = 0
            while off < size:
                n = min(chunk + len(BUILD_GUARD), size - off)
                data = mem.read(base + off, n)
                if data is None:
                    off += chunk
                    continue
                i = data.find(BUILD_GUARD)
                if i >= 0:
                    img = base + off + i - BUILD_OFF
                    log("fingerprint found at 0x%x -> image base 0x%x" % (base + off + i, img))
                    return img
                off += chunk
    return None


def read_position(mem, img):
    """Port of read_position() from runtime_atlas.c. Returns dict or None."""
    world = ptr(mem, img + WORLD_SLOT)
    chr_ = ptr(mem, world + 0x60) if world else 0
    if not chr_:
        return None
    c = mem.read(chr_ + 0x288, 0x174)
    if not c:
        return None
    modules = u64(c, 0x3B0 - 0x288)
    block = u32(c, 0x3F8 - 0x288)
    transform = ptr(mem, modules + 0x68) if modules else 0
    if not transform or not u64(c, 0):
        return None
    t = mem.read(transform + 0x1D4, 24)
    if not t:
        return None
    if chr_ != ptr(mem, world + 0x60) or transform != ptr(mem, modules + 0x68):
        return None
    yaw = struct.unpack_from("<f", t, 0)[0]
    x, y, z = struct.unpack_from("<3f", t, 12)
    area = block >> 24
    vals = (yaw, x, y, z)
    if not (21 <= area <= 36) or block == 0xFFFFFFFF or any(not math.isfinite(v) for v in vals):
        return None
    if max(abs(x), abs(y), abs(z)) > 20000:
        return None
    return {"x": x, "y": y, "z": z, "yaw": yaw, "block": block, "area": area}


def read_menu_open(mem, img):
    menu = ptr(mem, img + MENU_SLOT)
    d = mem.read(menu + 0x54, 4) if menu else None
    return bool(d and u32(d) == 2)


# ---- process discovery -----------------------------------------------------------------------------
def candidate_pids(proc_name=None, pid=None):
    if pid:
        return [pid]
    out = []
    try:
        txt = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)).stdout
    except Exception:
        return out
    import csv
    for row in csv.reader(txt.splitlines()):
        if len(row) < 5:
            continue
        name, p, mem_k = row[0], row[1], row[4]
        try:
            kb = int("".join(ch for ch in mem_k if ch.isdigit()) or 0)
            p = int(p)
        except ValueError:
            continue
        if proc_name:
            if name.lower() == proc_name.lower():
                out.append((kb, p))
        elif kb > 1_500_000:  # only processes using > ~1.5 GB: the game is one of them
            out.append((kb, p))
    out.sort(reverse=True)
    return [p for _, p in out]


# ---- map data (assets.atlaslite / state/runtime-assets/maps) -----------------------------------
import zipfile


class MapStore:
    """Loads m??_??_??_??.json floor plans (vector, world coordinates) and features.json lamps."""

    def __init__(self, source):
        self.zip = None
        self.dir = None
        if os.path.isdir(source):
            cand = os.path.join(source, "maps")
            self.dir = cand if os.path.isdir(cand) else source
        else:
            self.zip = zipfile.ZipFile(source)
        self.cache = {}
        self.ids = sorted(n for n in self._names() if n.startswith("m") and n.endswith(".json")
                          and n[1:3].isdigit())
        self.ids = [n[:-5] for n in self.ids]
        try:
            self.features = json.loads(self._read("features.json")).get("areas", {})
        except Exception:
            self.features = {}

    def _names(self):
        if self.zip:
            return [os.path.basename(n) for n in self.zip.namelist() if n.startswith("maps/")]
        return os.listdir(self.dir)

    def _read(self, name):
        if self.zip:
            return self.zip.read("maps/" + name).decode("utf-8")
        with open(os.path.join(self.dir, name), encoding="utf-8") as f:
            return f.read()

    def pick(self, block):
        """Map id for a block value: m<area>_<sub>_<x>_<y>, falling back to the same area."""
        a, b, c, d = block >> 24, (block >> 16) & 255, (block >> 8) & 255, block & 255
        want = "m%02d_%02d_%02d_%02d" % (a, b, c, d)
        if want in self.ids:
            return want
        for cand in ("m%02d_%02d_00_00" % (a, b), "m%02d_00_00_00" % a):
            if cand in self.ids:
                return cand
        same = [i for i in self.ids if i.startswith("m%02d_" % a)]
        return same[0] if same else None

    def load(self, mid):
        if mid not in self.cache:
            self.cache[mid] = json.loads(self._read(mid + ".json"))
        return self.cache[mid]


def build_composite(Image, ImageDraw, data, S, flipz, focus_lo, focus_hi, size_cap=7000):
    """Draw every 3 m floor layer; layers inside [focus_lo, focus_hi] bright, others dim.
    Returns (image, minx, minz, maxz, scale)."""
    minx, minz, maxx, maxz = data["bounds"]
    pad = 4.0
    minx, minz, maxx, maxz = minx - pad, minz - pad, maxx + pad, maxz + pad
    W, H = (maxx - minx) * S, (maxz - minz) * S
    if max(W, H) > size_cap:
        S *= size_cap / max(W, H)
        W, H = (maxx - minx) * S, (maxz - minz) * S
    W, H = int(W) + 1, int(H) + 1
    img = Image.new("RGB", (W, H), (14, 14, 16))
    dr = ImageDraw.Draw(img)

    def px(x, z):
        return (x - minx) * S, ((maxz - z) if flipz else (z - minz)) * S

    layers = sorted(data["layers"], key=lambda L: L["height"])
    if not layers:
        return img, minx, minz, maxz, S
    lo, hi = layers[0]["height"], layers[-1]["height"] + layers[-1]["span"]
    focus = []
    for L in layers:
        if focus_lo <= L["height"] + L["span"] and L["height"] <= focus_hi:
            focus.append(L)
            continue
        t = (L["height"] - lo) / max(1.0, hi - lo)
        c = (int(46 + 44 * t), int(46 + 42 * t), int(50 + 36 * t))
        for tri in L["triangles"]:
            dr.polygon([px(tri[0], tri[1]), px(tri[2], tri[3]), px(tri[4], tri[5])], fill=c)
    for L in focus:
        for tri in L["triangles"]:
            dr.polygon([px(tri[0], tri[1]), px(tri[2], tri[3]), px(tri[4], tri[5])], fill=(196, 184, 152))
    for L in focus:
        for w in L.get("walls", ()):
            dr.line([px(w[0], w[1]), px(w[2], w[3])], fill=(60, 52, 42), width=1)
        for o in L.get("outlines", ()):
            if len(o) > 1:
                dr.line([px(p[0], p[1]) for p in o], fill=(40, 34, 28), width=2)
    return img, minx, minz, maxz, S


# ---- viewer ----------------------------------------------------------------------------------------
def fit_heading(samples):
    """samples: [(yaw, move_angle)] where move_angle = atan2(dz, dx) of the actual movement.
    Fits move_angle = s*yaw + c (s = +1 or -1). Returns (s, c, quality 0..1)."""
    best = None
    for sgn in (1, -1):
        sx = sum(math.cos(m - sgn * y) for y, m in samples)
        sy = sum(math.sin(m - sgn * y) for y, m in samples)
        r = math.hypot(sx, sy) / len(samples)
        if best is None or r > best[2]:
            best = (sgn, math.atan2(sy, sx), r)
    return best


def app_dir():
    """Folder of the exe when frozen (PyInstaller), else of this script."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def config_path():
    """bb_map_viewer.json next to the exe; falls back to %APPDATA% when that folder is read-only."""
    p = os.path.join(app_dir(), "bb_map_viewer.json")
    try:
        with open(p, "a"):
            pass
        return p
    except OSError:
        d = os.path.join(os.environ.get("APPDATA", app_dir()), "BBMapViewer")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, "bb_map_viewer.json")


def make_appwindow(root):
    """Borderless (overrideredirect) windows get no taskbar / Alt-Tab entry; this sets WS_EX_APPWINDOW
    (and clears WS_EX_TOOLWINDOW) on the real top-level window so they do. Call while withdrawn."""
    try:
        u = ctypes.windll.user32
        u.GetParent.restype = ctypes.c_void_p
        u.GetParent.argtypes = [ctypes.c_void_p]
        u.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        u.GetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int]
        u.SetWindowLongPtrW.restype = ctypes.c_ssize_t
        u.SetWindowLongPtrW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_ssize_t]
        root.update_idletasks()
        hwnd = u.GetParent(root.winfo_id()) or root.winfo_id()
        ex = u.GetWindowLongPtrW(hwnd, -20)  # GWL_EXSTYLE
        ex = (ex & ~0x00000080) | 0x00040000  # no TOOLWINDOW, yes APPWINDOW
        u.SetWindowLongPtrW(hwnd, -20, ex)
    except Exception:
        pass


def find_game_window(pid):
    """Largest visible top-level window owned by the game process (or None)."""
    best = []
    try:
        import ctypes.wintypes as wt
        u = ctypes.windll.user32
        proc_t = ctypes.WINFUNCTYPE(wt.BOOL, ctypes.c_void_p, ctypes.c_void_p)
        u.EnumWindows.argtypes = [proc_t, ctypes.c_void_p]
        u.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD)]
        u.IsWindowVisible.argtypes = [ctypes.c_void_p]
        u.GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.RECT)]

        def cb(hwnd, _lp):
            p = wt.DWORD(0)
            u.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
            if p.value == pid and u.IsWindowVisible(hwnd):
                r = wt.RECT()
                u.GetWindowRect(hwnd, ctypes.byref(r))
                area = (r.right - r.left) * (r.bottom - r.top)
                if r.right - r.left > 200 and r.bottom - r.top > 150:
                    best.append((area, hwnd))
            return True
        u.EnumWindows(proc_t(cb), None)
    except Exception:
        return None
    return max(best)[1] if best else None


def focus_window(hwnd):
    """Bring a window to the foreground, like Alt-Tab."""
    try:
        u = ctypes.windll.user32
        k = ctypes.windll.kernel32
        u.IsIconic.argtypes = [ctypes.c_void_p]
        u.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
        u.BringWindowToTop.argtypes = [ctypes.c_void_p]
        u.SetForegroundWindow.argtypes = [ctypes.c_void_p]
        u.GetForegroundWindow.restype = ctypes.c_void_p
        u.GetWindowThreadProcessId.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        if u.IsIconic(hwnd):
            u.ShowWindow(hwnd, 9)  # SW_RESTORE
        fg = u.GetForegroundWindow()
        t_fg = u.GetWindowThreadProcessId(fg, None) if fg else 0
        t_me = k.GetCurrentThreadId()
        attached = bool(t_fg and t_fg != t_me and u.AttachThreadInput(t_me, t_fg, True))
        u.BringWindowToTop(hwnd)
        u.SetForegroundWindow(hwnd)
        if attached:
            u.AttachThreadInput(t_me, t_fg, False)
    except Exception:
        pass


def list_monitors():
    """[(x, y, w, h, is_primary)] for every attached monitor."""
    out = []
    try:
        import ctypes.wintypes as wt
        u = ctypes.windll.user32

        class MI(ctypes.Structure):
            _fields_ = [("cbSize", wt.DWORD), ("rcMonitor", wt.RECT), ("rcWork", wt.RECT), ("dwFlags", wt.DWORD)]
        proc_t = ctypes.WINFUNCTYPE(wt.BOOL, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wt.RECT), ctypes.c_void_p)
        u.GetMonitorInfoW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MI)]
        u.EnumDisplayMonitors.argtypes = [ctypes.c_void_p, ctypes.c_void_p, proc_t, ctypes.c_void_p]

        def cb(hmon, _hdc, _rect, _lp):
            mi = MI()
            mi.cbSize = ctypes.sizeof(MI)
            if u.GetMonitorInfoW(hmon, ctypes.byref(mi)):
                r = mi.rcMonitor
                out.append((r.left, r.top, r.right - r.left, r.bottom - r.top, bool(mi.dwFlags & 1)))
            return True
        u.EnumDisplayMonitors(None, None, proc_t(cb), None)
    except Exception:
        pass
    return out


def pick_fullscreen_monitor(root):
    """External monitor if there is one (the one the window is on if that is external, else the first
    non-primary); otherwise the monitor the window is on. Returns (x, y, w, h) or None."""
    mons = list_monitors()
    if len(mons) > 1:
        root.update_idletasks()
        cx, cy = root.winfo_rootx() + root.winfo_width() // 2, root.winfo_rooty() + root.winfo_height() // 2
        for x, y, w, h, primary in mons:
            if not primary and x <= cx < x + w and y <= cy < y + h:
                return x, y, w, h
        for x, y, w, h, primary in mons:
            if not primary:
                return x, y, w, h
    return monitor_rect(root)


def monitor_rect(root):
    """(x, y, w, h) of the monitor that holds the centre of the window, in virtual-screen pixels."""
    try:
        import ctypes.wintypes as wt
        u = ctypes.windll.user32

        class MI(ctypes.Structure):
            _fields_ = [("cbSize", wt.DWORD), ("rcMonitor", wt.RECT), ("rcWork", wt.RECT), ("dwFlags", wt.DWORD)]
        u.MonitorFromPoint.restype = ctypes.c_void_p
        u.MonitorFromPoint.argtypes = [wt.POINT, wt.DWORD]
        u.GetMonitorInfoW.argtypes = [ctypes.c_void_p, ctypes.POINTER(MI)]
        root.update_idletasks()
        pt = wt.POINT(root.winfo_rootx() + root.winfo_width() // 2, root.winfo_rooty() + root.winfo_height() // 2)
        hm = u.MonitorFromPoint(pt, 2)  # MONITOR_DEFAULTTONEAREST
        mi = MI()
        mi.cbSize = ctypes.sizeof(MI)
        if hm and u.GetMonitorInfoW(hm, ctypes.byref(mi)):
            r = mi.rcMonitor
            return r.left, r.top, r.right - r.left, r.bottom - r.top
    except Exception:
        pass
    return None


def work_area(root):
    """(left, top, right, bottom) of the primary screen without the taskbar."""
    try:
        import ctypes.wintypes as wt
        r = wt.RECT()
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(r), 0):  # SPI_GETWORKAREA
            return r.left, r.top, r.right, r.bottom
    except Exception:
        pass
    return 0, 0, root.winfo_screenwidth(), root.winfo_screenheight()


def place_bottom_right(root):
    """Small window (one third of the screen height) in the bottom-right corner, above the taskbar."""
    L, T, R, B = work_area(root)
    oh = (B - T) // 3
    ow = oh
    try:
        gm = ctypes.windll.user32.GetSystemMetrics
        bx = gm(32) + gm(92)                      # SM_CXSIZEFRAME + SM_CXPADDEDBORDER
        ty = gm(4) + gm(33) + gm(92) + gm(15)     # caption + frame + padded border + menu bar
    except Exception:
        bx, ty = 8, 55
    root.geometry("%dx%d%+d%+d" % (max(200, ow - 2 * bx), max(150, oh - ty - bx), R - ow, B - oh))


def refine_placement(root):
    """Nudge the window so its visible edge (not the invisible resize border) touches the corner."""
    try:
        import ctypes.wintypes as wt
        u = ctypes.windll.user32
        u.GetParent.restype = ctypes.c_void_p
        u.GetParent.argtypes = [ctypes.c_void_p]
        u.GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.RECT)]
        hwnd = u.GetParent(root.winfo_id()) or root.winfo_id()
        wr, fr = wt.RECT(), wt.RECT()
        u.GetWindowRect(hwnd, ctypes.byref(wr))
        ctypes.windll.dwmapi.DwmGetWindowAttribute(ctypes.c_void_p(hwnd), 9, ctypes.byref(fr), ctypes.sizeof(fr))
        _L, _T, R, B = work_area(root)
        dx, dy = R - fr.right, B - fr.bottom
        if (dx or dy) and abs(dx) < 60 and abs(dy) < 60:
            root.geometry("%+d%+d" % (wr.left + dx, wr.top + dy))
    except Exception:
        pass


PACK_NAME = "assets.atlaslite"


def valid_pack(path):
    """True when path is an Atlas map pack: a file named assets.atlaslite holding maps/atlas.json."""
    try:
        if os.path.basename(path).lower() != PACK_NAME or not os.path.isfile(path):
            return False
        with zipfile.ZipFile(path) as z:
            return "maps/atlas.json" in z.namelist()
    except Exception:
        return False


def ask_for_pack(tk, filedialog, messagebox):
    """Dialog that accepts only a file called assets.atlaslite. Returns the path or None."""
    while True:
        path = filedialog.askopenfilename(
            title="Select Hunter's Atlas map pack (assets.atlaslite)",
            filetypes=[("Atlas map pack (assets.atlaslite)", PACK_NAME)])
        if not path:
            return None
        if valid_pack(path):
            return path
        messagebox.showerror("Wrong file", "Please select the file named assets.atlaslite from your "
                                           "Hunter's Atlas folder (it must contain the maps).")


def find_maps_default():
    here = app_dir()
    p = os.path.join(here, PACK_NAME)
    return p if valid_pack(p) else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--proc")
    ap.add_argument("--pid", type=int)
    ap.add_argument("--maps", help="assets.atlaslite file, or the folder holding the maps "
                                   "(e.g. <Atlas>\\state\\runtime-assets\\maps)")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()

    try:  # real pixel coordinates, so monitor rectangles match what Tk reports
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass
    import tkinter as tk
    from tkinter import filedialog, messagebox
    args.config = args.config or config_path()
    try:
        from PIL import Image, ImageDraw, ImageTk
    except Exception:
        Image = None
    cfg = {"rot": 0.0, "arrow_s": 1, "arrow_c": 0.0, "arrow_fit": False, "flipz": True, "zoom": 3.0,
           "show_lamps": False, "topmost": True}
    if os.path.exists(args.config):
        try:
            cfg.update(json.load(open(args.config, encoding="utf-8")))
        except Exception:
            pass

    def save_cfg():
        try:
            json.dump(cfg, open(args.config, "w", encoding="utf-8"), indent=2)
        except Exception:
            pass

    root = tk.Tk()
    root.withdraw()  # hidden while the file dialog may be shown
    src = args.maps
    if not src:
        remembered = cfg.get("maps")
        if remembered and valid_pack(remembered):
            src = remembered
        else:
            src = find_maps_default() or ask_for_pack(tk, filedialog, messagebox)
    if src and os.path.isfile(src) and valid_pack(src):
        cfg["maps"] = os.path.abspath(src)
        save_cfg()
    store = None
    if src:
        try:
            store = MapStore(src)
        except Exception as e:
            print("cannot read maps from %s: %s" % (src, e))
    notes = []
    if Image is None:
        notes.append("Pillow missing: run  python -m pip install pillow  (shapes need it)")
    if store is None:
        notes.append("no maps selected: delete the \"maps\" entry in bb_map_viewer.json to be asked again")

    S = 3.0  # composite resolution, pixels per world metre
    st = {"mem": None, "img": None, "status": "searching for the game...", "pos": None, "menu": False,
          "trail": [], "mid": None, "zoom": cfg["zoom"], "stop": False, "notes": notes,
          "comp": None, "comp_key": None, "building": None, "photo": None, "data": None,
          "fit": [], "prev": None, "fs": False, "fs_prev": None, "pid": None, "teleported": False, "mouse": (0, 9999), "hits": []}

    def attach_loop():
        while not st["stop"]:
            if st["mem"] is not None:
                if st["mem"].read(st["img"] + BUILD_OFF, 8) is None:
                    st["mem"].close()
                    st["mem"], st["img"] = None, None
                    st["status"] = "game closed, searching..."
                time.sleep(1)
                continue
            for p in candidate_pids(args.proc, args.pid):
                try:
                    m = WinMem(p)
                except OSError as e:
                    st["status"] = "cannot open pid %d: %s" % (p, e)
                    continue
                st["status"] = "scanning pid %d..." % p
                img = find_base(m, log=lambda s: None)
                if img is not None:
                    st["mem"], st["img"], st["pid"] = m, img, p
                    st["status"] = "connected (pid %d)" % p
                    if not st["teleported"]:  # first connection: switch to the game, like Alt-Tab
                        st["teleported"] = True
                        gw = find_game_window(p)
                        if gw:
                            focus_window(gw)
                    break
                m.close()
            if st["mem"] is None:
                time.sleep(3)
    threading.Thread(target=attach_loop, daemon=True).start()

    root.title("BB Map Viewer")
    cv = tk.Canvas(root, bg="#0b0b0c", highlightthickness=0)
    cv.pack(fill="both", expand=True)

    def floor_key(y):
        # floor bands are 3 m high; the band of the player plus the one just below (stairs, steps)
        return int(math.floor((y - 1.0) / 3.0))

    def request_composite(mid, y):
        key = (mid, cfg["flipz"], floor_key(y))
        if st["comp_key"] == key or st["building"] == key or Image is None or store is None:
            return
        st["building"] = key

        def work():
            try:
                data = st["data"] if st["data"] and st["data"]["id"] == mid else store.load(mid)
                st["data"] = data
                band = key[2] * 3.0 + 1.0
                img, minx, minz, maxz, sc = build_composite(Image, ImageDraw, data, S, cfg["flipz"],
                                                           band - 3.0, band + 3.5)
                st["comp"] = (img, minx, minz, maxz, sc, key)
                st["comp_key"] = key
            except Exception as e:
                st["status"] = "map build failed: %s" % e
            finally:
                st["building"] = None
        threading.Thread(target=work, daemon=True).start()

    def arrow(sx, sy, yaw, size=14):
        h = cfg["arrow_s"] * yaw + cfg["arrow_c"] + cfg["rot"]
        dx, dy = math.cos(h), math.sin(h)
        if cfg["flipz"]:
            dy = -dy
        px_, py_ = -dy, dx
        return [sx + dx * size * 1.4, sy + dy * size * 1.4,
                sx - dx * size + px_ * size * 0.8, sy - dy * size + py_ * size * 0.8,
                sx - dx * size * 0.4, sy - dy * size * 0.4,
                sx - dx * size - px_ * size * 0.8, sy - dy * size - py_ * size * 0.8]

    def draw():
        cv.delete("all")
        w, h = cv.winfo_width(), cv.winfo_height()
        pos = st["pos"]
        z = st["zoom"]  # screen pixels per world metre
        lines = []
        if not st["status"].startswith("connected"):
            lines.append(st["status"])  # only shown while not attached to the game
        lines += st["notes"]
        comp = st["comp"]
        mid = st["mid"]
        place = ""
        if mid and store:
            place = store.load(mid).get("name", mid)
        if pos and not cfg["arrow_fit"]:
            lines.append("walk around to calibrate the arrow (%d/40)" % len(st["fit"]))

        def to_world_px(x, zz):
            # world metres -> composite pixels
            _, minx, minz, maxz, sc, _k = comp
            return (x - minx) * sc, ((maxz - zz) if cfg["flipz"] else (zz - minz)) * sc

        cam = (pos["x"], pos["z"]) if pos else (0.0, 0.0)
        if comp and pos:
            img, minx, minz, maxz, sc, _k = comp
            cxp, cyp = to_world_px(*cam)
            # screen px per composite px
            k = z / sc
            x0, y0 = cxp - w / 2 / k, cyp - h / 2 / k
            x1, y1 = cxp + w / 2 / k, cyp + h / 2 / k
            bx0, by0, bx1, by1 = max(0, int(x0)), max(0, int(y0)), min(img.width, int(x1) + 1), min(img.height, int(y1) + 1)
            if bx1 > bx0 and by1 > by0:
                crop = img.crop((bx0, by0, bx1, by1))
                tw, th = max(1, int((bx1 - bx0) * k)), max(1, int((by1 - by0) * k))
                if tw * th < 25_000_000:
                    st["photo"] = ImageTk.PhotoImage(crop.resize((tw, th)))
                    cv.create_image((bx0 - cxp) * k + w / 2, (by0 - cyp) * k + h / 2, image=st["photo"], anchor="nw")

            def wp(x, zz):
                a, b = to_world_px(x, zz)
                return (a - cxp) * k + w / 2, (b - cyp) * k + h / 2
        else:
            def wp(x, zz):
                return (x - cam[0]) * z + w / 2, ((cam[1] - zz) if cfg["flipz"] else (zz - cam[1])) * z + h / 2
        trail = st["trail"]
        if len(trail) > 1:
            pts = []
            for tx, tz in trail[-1500:]:
                pts.extend(wp(tx, tz))
            cv.create_line(*pts, fill="#c98a2a", width=2)
        if cfg["show_lamps"] and store and mid and mid in store.features:
            for lamp in store.features[mid].get("lamps", []):
                lx, _ly, lz = lamp["pos"]
                sx, sy = wp(lx, lz)
                cv.create_oval(sx - 5, sy - 5, sx + 5, sy + 5, fill="#e8c35a", outline="#000000")
                cv.create_text(sx + 8, sy, anchor="w", fill="#e8c35a", font=("Segoe UI", 9), text=lamp.get("name", ""))
        if pos:
            sx, sy = wp(pos["x"], pos["z"])
            cv.create_polygon(arrow(sx, sy, pos["yaw"]), fill="#000000", outline="#ffffff", width=3,
                              joinstyle="round")
        st["hits"] = []
        bar = st["fs"] and st["mouse"][1] < 48
        if bar:  # auto-hiding menu bar while fullscreen
            cv.create_rectangle(0, 0, w, 40, fill="#1b1b1d", outline="")
            items = [("Exit Full Screen (F)", lambda: set_fullscreen(False)),
                     (("\u2713 " if cfg["topmost"] else "") + "Always On Top (A)", lambda: set_topmost(not cfg["topmost"])),
                     ("Quit (Q)", do_quit)]
            bx = 8
            for label, fn in items:
                bw = 22 + 9 * len(label)
                cv.create_rectangle(bx, 5, bx + bw, 35, fill="#2c2c30", outline="#4a4a50")
                cv.create_text(bx + bw / 2, 20, fill="#e8e8e8", font=("Segoe UI", 10), text=label)
                st["hits"].append((bx, 5, bx + bw, 35, fn))
                bx += bw + 8
        elif place:
            cv.create_text(12, 8, anchor="nw", fill="#e0e0e0", font=("Segoe UI", 16, "bold"), text=place)
        if lines:
            cv.create_text(12, 48 if bar else (40 if place else 8), anchor="nw", fill="#b8b8b8", font=("Segoe UI", 10),
                           text="\n".join(lines))

    def tick():
        mem, img = st["mem"], st["img"]
        pos = None
        if mem is not None:
            pos = read_position(mem, img)
            st["menu"] = read_menu_open(mem, img)
        if pos:
            mid = store.pick(pos["block"]) if store else None
            if mid != st["mid"]:
                st["mid"] = mid
                st["trail"] = []
                st["comp"], st["comp_key"], st["data"] = None, None, None
            prev = st["prev"]
            if prev and prev[2] == mid and not cfg["arrow_fit"]:
                ddx, ddz = pos["x"] - prev[0], pos["z"] - prev[1]
                dist = math.hypot(ddx, ddz)
                if 0.12 < dist < 3.0:  # moving, not teleporting
                    st["fit"].append((pos["yaw"], math.atan2(ddz, ddx)))
                    if len(st["fit"]) > 300:
                        del st["fit"][:100]
                    if len(st["fit"]) >= 40:
                        sgn, c, q = fit_heading(st["fit"])
                        if q > 0.75:
                            cfg.update(arrow_s=sgn, arrow_c=c, rot=0.0, arrow_fit=True)
                            save_cfg()
                        else:
                            del st["fit"][:20]
            st["prev"] = (pos["x"], pos["z"], mid)
            last = st["trail"][-1] if st["trail"] else None
            if last is None or math.hypot(pos["x"] - last[0], pos["z"] - last[1]) > 0.5:
                st["trail"].append((pos["x"], pos["z"]))
                if len(st["trail"]) > 5000:
                    del st["trail"][:1000]
            if mid:
                request_composite(mid, pos["y"])
        st["pos"] = pos
        draw()
        root.after(66, tick)

    def do_quit():
        cfg["zoom"] = st["zoom"]
        save_cfg()
        st["stop"] = True
        root.destroy()

    menubar = tk.Menu(root)

    def switch_to_game():
        if st["pid"]:
            gw = find_game_window(st["pid"])
            if gw:
                focus_window(gw)

    def set_fullscreen(on):
        on = bool(on)
        if on == st["fs"]:
            return
        if on:
            rect = pick_fullscreen_monitor(root)
            st["fs_prev"] = root.geometry()
            if rect:
                x, y, w, h = rect
                root.withdraw()
                root.config(menu="")
                root.overrideredirect(True)
                root.geometry("%dx%d%+d%+d" % (w, h, x, y))
                make_appwindow(root)  # keep it in Alt-Tab and the taskbar
                root.deiconify()
                root.focus_force()
            else:  # no Win32 info: let Tk do it
                root.attributes("-fullscreen", True)
            st["fs"] = True
        else:
            root.attributes("-fullscreen", False)
            root.withdraw()
            root.overrideredirect(False)
            root.config(menu=menubar)
            if st["fs_prev"]:
                root.geometry(st["fs_prev"])
            root.deiconify()
            root.focus_force()
            st["fs"] = False
        root.attributes("-topmost", cfg["topmost"])
        menubar.entryconfigure(0, label="Exit Full Screen (F)" if st["fs"] else "Full Screen (F)")
        root.after(200, switch_to_game)

    def set_topmost(on):
        cfg["topmost"] = bool(on)
        root.attributes("-topmost", bool(on))
        menubar.entryconfigure(1, label=("\u2713 " if on else "") + "Always On Top (A)")
        save_cfg()

    menubar.add_command(label="Full Screen (F)", command=lambda: set_fullscreen(not st["fs"]))
    menubar.add_command(label="Always On Top (A)", command=lambda: set_topmost(not cfg["topmost"]))
    menubar.add_command(label="Quit (Q)", command=do_quit)
    root.config(menu=menubar)
    set_topmost(cfg["topmost"])
    place_bottom_right(root)
    root.deiconify()
    root.after(250, lambda: None if st["fs"] else refine_placement(root))

    def on_key(ev):
        k = ev.keysym.lower()
        if k in ("f", "f11"):
            set_fullscreen(not st["fs"])
        elif k == "a":
            set_topmost(not cfg["topmost"])
        elif k == "escape":
            set_fullscreen(False)
        elif k in ("plus", "equal", "kp_add"):
            st["zoom"] = min(st["zoom"] * 1.25, 30)
        elif k in ("minus", "kp_subtract"):
            st["zoom"] = max(st["zoom"] / 1.25, 0.3)
        elif k == "t":
            st["trail"] = []
        elif k == "l":
            cfg["show_lamps"] = not cfg["show_lamps"]
            save_cfg()
        elif k == "v":
            cfg["flipz"] = not cfg["flipz"]
            st["comp"], st["comp_key"] = None, None
            save_cfg()
        elif k == "r":
            cfg["rot"] += math.pi / 2
            save_cfg()
        elif k == "m":
            cfg["arrow_s"] *= -1
            save_cfg()
        elif k == "c":
            cfg.update(arrow_fit=False, rot=0.0)
            st["fit"] = []
        elif k == "q":
            do_quit()

    def on_wheel(ev):
        st["zoom"] = min(max(st["zoom"] * (1.15 if ev.delta > 0 else 1 / 1.15), 0.3), 30)

    def on_motion(ev):
        st["mouse"] = (ev.x, ev.y)

    def on_leave(_ev):
        st["mouse"] = (0, 9999)

    def on_click(ev):
        for x0, y0, x1, y1, fn in st["hits"]:
            if x0 <= ev.x <= x1 and y0 <= ev.y <= y1:
                fn()
                return

    cv.bind("<Motion>", on_motion)
    cv.bind("<Leave>", on_leave)
    cv.bind("<Button-1>", on_click)
    root.bind("<Key>", on_key)
    root.bind("<MouseWheel>", on_wheel)
    root.protocol("WM_DELETE_WINDOW", do_quit)
    tick()
    root.mainloop()


if __name__ == "__main__":
    if os.name != "nt":
        print("This tool reads a Windows process; run it on Windows.")
        sys.exit(1)
    try:
        main()
    except Exception:  # a windowed exe has no console: keep the error in a log file
        import traceback
        text = traceback.format_exc()
        try:
            with open(os.path.join(app_dir(), "bb_map_viewer_error.log"), "w", encoding="utf-8") as f:
                f.write(text)
        except OSError:
            pass
        try:
            import tkinter
            from tkinter import messagebox
            r = tkinter.Tk()
            r.withdraw()
            messagebox.showerror("BB Map Viewer crashed", text[-1500:])
        except Exception:
            pass
        raise
