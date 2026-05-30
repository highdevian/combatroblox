"""
Banco de assinaturas conhecidas — executores Roblox, ferramentas auxiliares,
sinais de VM/Sandbox e padrões em scripts Lua.

Severity:
  high   = match direto (quase certeza)
  medium = ferramenta auxiliar ou bypass
  low    = palavra-chave ambígua
"""

EXECUTOR_KEYWORDS = {
    # PC Executors
    "synapse":          "high",
    "synapsex":         "high",
    "synapse x":        "high",
    "krnl":             "high",
    "krnl.exe":         "high",
    "krnl.dll":         "high",
    "fluxus":           "high",
    "wave executor":    "high",
    "wave.exe":         "high",
    "wave.cx":          "high",
    "solara":           "high",
    "velocity executor":"high",
    "electron exploit": "high",
    "sentinel exploit": "high",
    "trigon evo":       "high",
    "argon executor":   "high",
    "awp.gg":           "high",
    "zorara":           "high",
    "volcano executor": "high",
    "vegax":            "high",
    "swift executor":   "high",
    "nezur":            "high",
    # "nihon" (solto) removido — substring pega Nihon Falcom (dev de Ys/Trails)
    # e pastas de jogos JP. "nihon.exe" exact-match cobre o executor.
    "calamari executor":"high",
    "pandadev":         "high",
    "frontier executor":"high",
    "oxygen u":         "high",
    "comet executor":   "high",
    "jjsploit":         "high",
    "jjsploitv":        "high",
    "wearedevs":        "high",
    "wrd-api":          "high",
    "hydrogen-m":       "high",
    "hydrogen.exe":     "high",
    "codex executor":   "high",
    "codex.lol":        "high",
    "arceus x":         "high",
    "arceusx":          "high",
    "delta executor":   "high",
    "delta exploit":    "high",
    "ronin executor":   "high",
    "potassium executor":"high",
    "evon executor":    "high",
    "scriptware":       "high",
    "protosmasher":     "high",
    "sirhurt":          "high",
    # "calamari" (solto) removido — palavra comum (comida / Splatoon "Calamari Inkantation").
    # "calamari executor" cobre o executor real.
    "byfron bypass":    "high",
    "hyperion bypass":  "high",
    "bypass roblox":    "high",
    "v3rmillion":       "medium",
    "rscripts":         "low",
    "scriptblox":       "low",
    "cheat engine":     "medium",
    "cheatengine":      "medium",
    "process hacker":   "medium",
    "system informer":  "medium",
    "extreme injector": "medium",
    "xenos injector":   "medium",
    "manualmap":        "medium",
    "dll injector":     "medium",
    "roblox account manager": "low",
    "ram-master":       "low",

    # ===== Executores 2024-2026 =====
    # Xeno (open-source, muito popular)
    # "xeno" (solto) removido — substring pega Xenoblade, Xenonauts, XenoBot,
    # e pastas/saves de jogos da série Xeno. Variantes abaixo cobrem o executor.
    "xeno.exe":         "high",
    "xeno executor":    "high",
    "xeno hub":         "high",
    "xeno.now":         "high",
    "xenoexec":         "high",
    # Cryptic
    # "cryptic" (solto) removido — FP garantido: Cryptic Studios (Star Trek
    # Online, Neverwinter, Champions Online) cria pasta "Cryptic Studios".
    # Variantes "cryptic exec/executor/hub" cobrem o executor.
    "cryptic exec":     "high",
    "cryptic executor": "high",
    "cryptic hub":      "high",
    # Empyrean
    # "empyrean" (solto) removido — aparece em nomes de mods/jogos. "empyrean exec" cobre.
    "empyrean exec":    "high",
    # Valyse
    "valyse":           "high",
    "valyse executor":  "high",
    # Bunni Hub
    "bunni hub":        "high",
    "bunni executor":   "high",
    # Cosmic
    "cosmic executor":  "high",
    "cosmic exec":      "high",
    "cosmic.exe":       "high",
    # Acrylix
    "acrylix":          "high",
    "acrylix executor": "high",
    # Marin
    "marin executor":   "high",
    "marin.exe":        "high",
    "marin hub":        "high",
    # Coral
    "coral exploit":    "high",
    "coral executor":   "high",
    # Furk Os
    "furk os":          "high",
    "furkos":           "high",
    "furk.cc":          "high",
    # Sense
    "sense executor":   "high",
    "sense exec":       "high",
    # Karambit X
    "karambit x":       "high",
    "karambit executor":"high",
    # Drumix
    "drumix":           "high",
    "drumix executor":  "high",
    # Omega X
    "omega x":          "high",
    "omegax":           "high",
    # Apex Hardware
    "apex hardware":    "high",
    "apex hw":          "high",
    # Stellar
    "stellar spoof":    "high",
    "stellar executor": "high",
    # Sploitware
    "sploitware":       "high",
    # CCDownloader
    "ccdownloader":     "high",
    # Vega X (variante Vegax)
    "vega x":           "high",
    "vega executor":    "high",
    # Cellura
    "cellura":          "high",
    "cellura exec":     "high",
    # Hexus
    "hexus executor":   "high",
    "hexus exec":       "high",
    # Verbose
    "verbose executor": "high",
    "verbose exec":     "high",
    # Ninja Hub
    "ninjahub":         "high",
    "ninja hub":        "high",
    # Outros menos comuns
    "scriptware":       "high",  # já tinha mas reforça
    "calamari executor":"high",  # já tinha
    "valex":            "high",
    "pylon executor":   "high",
    "shellsploit":      "high",
    "fenix exec":       "high",
    "ronin exec":       "high",
    "swift x":          "high",

    # ===== HWID Spoofers (burlar ban Hyperion) =====
    "hwid spoofer":     "high",
    "hwid spoof":       "high",
    "spoofer pro":      "high",
    "hardware spoofer": "high",
    "rage spoofer":     "high",
    "tbh spoofer":      "high",
    "tbhd spoofer":     "high",
    "perm spoofer":     "high",
    "permanent spoofer":"high",

    # ===== Kernel-level / driver injection =====
    "kdmapper":         "high",
    "kdumapper":        "high",
    "drvmap":           "high",
    "ezmapper":         "high",
    "manualmapper":     "high",
    "dbk64.sys":        "high",   # Cheat Engine driver
    "dbk32.sys":        "high",
    "kduapi":           "high",
    "intelmapper":      "high",
    "msrexec":          "high",

    # ===== Anti-cheat bypass =====
    "byfron tools":     "high",
    "hyperion tools":   "high",
    "ac bypass":        "high",
    "anticheat bypass": "high",
    "byfron killer":    "high",
    "vac bypass":       "high",

    # ===== Hubs / scripts famosos =====
    "owl hub":          "high",
    "dark hub":         "high",
    "infinite yield":   "high",
    "hoho hub":         "high",
    "epix hub":         "high",
    "vape v4":          "high",
    "vape lite":        "high",
    "fates admin":      "high",
    "fly hub":          "high",
    "kraken hub":       "high",
    "rip hub":          "high",
    "rocky hub":        "high",
    "fluxus hub":       "high",
    "thresh hub":       "high",
    "matrix hub":       "medium",
    "yba hub":          "medium",
    "evade hub":        "medium",
}

EXECUTOR_PROCESS_NAMES = {
    "krnl.exe":             "high",
    "fluxus.exe":           "high",
    "wave.exe":             "high",
    "solara.exe":           "high",
    "velocity.exe":         "high",
    "electron.exe":         "high",
    "sentinel.exe":         "high",
    "trigon.exe":           "high",
    "argon.exe":            "high",
    "zorara.exe":           "high",
    "vegax.exe":            "high",
    "swift.exe":            "high",
    "nezur.exe":            "high",
    "nihon.exe":            "high",
    "hydrogen.exe":         "high",
    "codex.exe":            "high",
    "jjsploit.exe":         "high",
    "synapse.exe":          "high",
    "synapsex.exe":         "high",
    "synapselauncher.exe":  "high",
    "wave-bootstrapper.exe":"high",
    "solara-bootstrapper.exe":"high",
    "krnl-bootstrapper.exe":"high",
    "fluxus-bootstrapper.exe":"high",
    "cheatengine-x86_64.exe": "medium",
    "cheatengine-i386.exe":   "medium",
    "processhacker.exe":      "medium",
    "systeminformer.exe":     "medium",
    "extremeinjector.exe":    "medium",
    "xenosinjector.exe":      "medium",

    # ===== Executores 2024-2026 =====
    "xeno.exe":                   "high",
    "xeno-bootstrapper.exe":      "high",
    "xenobootstrapper.exe":       "high",
    "xenolauncher.exe":           "high",
    "cryptic.exe":                "high",
    "cryptic-bootstrapper.exe":   "high",
    "empyrean.exe":               "high",
    "valyse.exe":                 "high",
    "bunni.exe":                  "high",
    "cosmic.exe":                 "high",
    "acrylix.exe":                "high",
    "marin.exe":                  "high",
    "coral.exe":                  "high",
    "furk.exe":                   "high",
    "furkos.exe":                 "high",
    "sense.exe":                  "high",
    "karambit.exe":               "high",
    "drumix.exe":                 "high",
    "omega.exe":                  "high",
    "omegax.exe":                 "high",
    "apex.exe":                   "high",
    "stellar.exe":                "high",
    "sploitware.exe":             "high",
    "ccdownloader.exe":           "high",
    "cellura.exe":                "high",
    "hexus.exe":                  "high",
    "verbose.exe":                "high",
    "ninja.exe":                  "high",
    "valex.exe":                  "high",
    "pylon.exe":                  "high",
    "fenix.exe":                  "high",
    "ronin.exe":                  "high",
    # Bootstrappers genéricos
    "exec-bootstrapper.exe":      "medium",
    "robloxexec.exe":             "high",
    "rbxexec.exe":                "high",

    # ===== HWID Spoofers (processos) =====
    "spoofer.exe":            "high",
    "hwidspoofer.exe":        "high",
    "ragespoofer.exe":        "high",
    "permspoofer.exe":        "high",
    "perm_spoofer.exe":       "high",

    # ===== Kernel mappers (drivers de injeção) =====
    "kdmapper.exe":           "high",
    "drvmap.exe":             "high",
    "ezmapper.exe":           "high",
    "intelmapper.exe":        "high",
    "manualmapper.exe":       "high",

    # ===== Anti-cheat bypass =====
    "byfrontools.exe":        "high",
    "hyperiontools.exe":      "high",
    "acbypass.exe":           "high",

    # ===== Outros utilitários de cheating =====
    "scylla.exe":             "medium",   # PE dumper
    "x32dbg.exe":             "medium",   # Debugger (preto se Roblox aberto)
    "x64dbg.exe":             "medium",
    "ollydbg.exe":            "medium",
    "ida.exe":                "medium",
    "ida64.exe":              "medium",
    "ghidra.exe":             "medium",
    "dnspy.exe":              "medium",
    "windbg.exe":             "medium",
    "pe-bear.exe":            "medium",
    "die.exe":                "medium",
}

SUSPICIOUS_DOMAINS = {
    "wearedevs.net":        "high",
    "krnl.cat":             "high",
    "krnl.place":           "high",
    "krnl.ca":              "high",
    "getfluxus.com":        "high",
    "fluxteam.net":         "high",
    "getsolara.dev":        "high",
    "solara.gg":            "high",
    "wave.cx":              "high",
    "getwave.gg":           "high",
    "velocityexploit.com":  "high",
    "electron.dev":         "high",
    "sentinel.gg":          "high",
    "trigonevo.com":        "high",
    "argonexec.com":        "high",
    "awp.gg":               "high",
    "zorara.cc":            "high",
    "swift.lat":            "high",
    "nezur.cc":             "high",
    "hydrogen.lat":         "high",
    "codex.lol":            "high",
    "arceusx.net":          "high",
    "arceusx.com":          "high",
    "delta-executor.com":   "high",
    "deltaexploits.gg":     "high",
    "scriptware.com":       "high",
    "evonexecutor.com":     "high",
    "v3rmillion.net":       "low",
    "rscripts.net":         "low",
    "scriptblox.com":       "low",
    "robloxscripts.com":    "low",

    # ===== Executores 2024-2026 (domínios) =====
    "xeno.now":             "high",
    "xeno.lat":             "high",
    "xeno.gg":              "high",
    "xenoexec.com":         "high",
    "crypticexec.com":      "high",
    "cryptic.gg":           "high",
    "cryptic-exec.com":     "high",
    "empyrean.gg":          "high",
    "empyreanexec.com":     "high",
    "valyse.cc":            "high",
    "valyse.gg":            "high",
    "bunnihub.com":         "high",
    "bunni.cc":             "high",
    "cosmicexec.com":       "high",
    "cosmic.gg":            "high",
    "acrylix.gg":           "high",
    "acrylix.cc":           "high",
    "marinexecutor.cc":     "high",
    "marin-executor.com":   "high",
    "coralexploit.com":     "high",
    "coral.gg":             "high",
    "furkos.cc":            "high",
    "furkos.com":           "high",
    "furk.cc":              "high",
    "ccdownloader.com":     "high",
    "omegax.gg":            "high",
    "omegax.cc":            "high",
    "drumix.cc":            "high",
    "drumix.gg":            "high",
    "karambitx.cc":         "high",
    "karambit-x.com":       "high",
    "sense-exec.com":       "high",
    "sense.gg":             "high",
    "apexhw.cc":            "high",
    "apex-hardware.com":    "high",
    "stellarspoof.com":     "high",
    "sploitware.com":       "high",
    "cellura.cc":           "high",
    "hexusexec.com":        "high",
    "verbose-exec.com":     "high",
    "ninjahub.cc":          "high",
    "ninjahub.gg":          "high",
    "valex.gg":             "high",
    "pylonexec.com":        "high",
    "fenixexec.com":        "high",

    # Hubs / repositórios de cheats
    "v3rmillion.com":       "medium",   # variantes
    "v3rm.net":             "medium",
    "robloxscripts.gg":     "low",
    "fluxusscripts.com":    "high",
    "waveexec.gg":          "high",
    "waveexecutor.com":     "high",
    "solaraexec.com":       "high",
    "solara-executor.com":  "high",
    "krnl.gg":              "high",
    "krnl.lol":             "high",
    "krnl.lat":             "high",
    "hydrogen.gg":          "high",
    "hydrogen.cc":          "high",
    "deltaexploits.gg":     "high",     # já tinha mas reforço
    "evon.cc":              "high",
    "evonexploit.com":      "high",
    "trigonevo.gg":         "high",
    "argonexec.com":        "high",     # já tinha
    "swiftexec.gg":         "high",
    "swift-exec.com":       "high",

    # HWID Spoofer sites
    "ragespoof.com":        "high",
    "permspoof.com":        "high",
    "tbhd.cc":              "high",
    "spoofer.gg":           "high",
    "hwid-spoofer.com":     "high",

    # Marketplaces / forums grayhat
    "elitepvpers.com":      "medium",
    "unknowncheats.me":     "medium",
    "guidedhacking.com":    "medium",
    "lanik.us":             "medium",
    "mpgh.net":             "medium",
}

SUSPICIOUS_FOLDER_NAMES = {
    "synapse x":            "high",
    "synapsex":             "high",
    "krnl":                 "high",
    "fluxus":               "high",
    "wave":                 "high",
    "solara":               "high",
    "velocity executor":    "high",
    "electron":             "high",
    "sentinel":             "high",
    "trigon evo":           "high",
    "argon":                "high",
    "hydrogen":             "high",
    "codex":                "high",
    "jjsploit":             "high",
    "scriptware":           "high",
    "rbxexploits":          "high",
    "robloxscripts":        "medium",
    "roblox scripts":       "medium",
    "exploits":             "low",

    # ===== Executores 2024-2026 (folder names) =====
    "xeno":                 "high",
    "xeno executor":        "high",
    "cryptic":              "high",
    "cryptic exec":         "high",
    "empyrean":             "high",
    "valyse":               "high",
    "bunni hub":            "high",
    "cosmic":               "high",
    "cosmic exec":          "high",
    "acrylix":              "high",
    "marin":                "high",
    "marin exec":           "high",
    "coral":                "medium",
    "coral exec":           "high",
    "furk os":              "high",
    "furkos":               "high",
    "sense":                "medium",
    "sense exec":           "high",
    "karambit x":           "high",
    "drumix":               "high",
    "omega x":              "high",
    "omegax":               "high",
    "apex hardware":        "high",
    "stellar":              "medium",
    "stellar spoof":        "high",
    "sploitware":           "high",
    "ccdownloader":         "high",
    "cellura":              "high",
    "hexus":                "high",
    "verbose exec":         "high",
    "ninjahub":             "high",
    "ninja hub":            "high",
    "valex":                "high",
    "pylon exec":           "high",
    "fenix exec":           "high",
    "ronin exec":           "high",

    # HWID Spoofers
    "spoofer":              "high",
    "hwid spoofer":         "high",
    "rage spoofer":         "high",
    "perm spoofer":         "high",
    "tbhd spoofer":         "high",
    "spoofer pro":          "high",

    # Kernel mappers
    "kdmapper":             "high",
    "drvmap":               "high",
    "ezmapper":             "high",

    # Pastas de scripts famosas
    "owl hub":              "high",
    "dark hub":             "high",
    "infinite yield":       "high",
    "hoho hub":             "high",
    "epix hub":             "high",
    "fates admin":          "high",
    "vape v4":              "high",
    "scripts hub":          "medium",
    "executors":            "high",
    "rbxscripts":           "high",
    "roblox exploits":      "high",
    "roblox cheats":        "high",
    "roblox hack":          "high",
    "byfron bypass":        "high",
    "hyperion bypass":      "high",
    "anticheat bypass":     "high",
}

PATHS_TO_SCAN_FOR_EXECUTORS = [
    r"%USERPROFILE%",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\AppData\Local",
    r"%USERPROFILE%\AppData\Roaming",
    r"%USERPROFILE%\AppData\LocalLow",
    r"%LOCALAPPDATA%\Programs",
    r"%PROGRAMFILES%",
    r"%PROGRAMFILES(X86)%",
]

BROWSER_HISTORY_DBS = [
    (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\History", "Chrome"),
    (r"%LOCALAPPDATA%\Google\Chrome\User Data\Profile 1\History", "Chrome P1"),
    (r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History", "Edge"),
    (r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\History", "Brave"),
    (r"%APPDATA%\Opera Software\Opera Stable\History", "Opera"),
    (r"%APPDATA%\Opera Software\Opera GX Stable\History", "Opera GX"),
]

ROBLOX_LOG_PATHS = [
    r"%LOCALAPPDATA%\Roblox\logs",
    r"%TEMP%\Roblox",
]

ROBLOX_LOG_PATTERNS = [
    "DllInjection",
    "module injected",
    "Hyperion",
    "AntiTamper",
    "ProcessUntrusted",
]

# Paths que, se excluídos do Defender, são LEGÍTIMOS (não red flag).
# IDEs/dev tools pedem exclusão por performance — JetBrains até documenta.
DEFENDER_EXCLUSION_DEV_PATHS = [
    r"\jetbrains\\", r"\pycharm", r"\rider", r"\webstorm", r"\intellij",
    r"\clion", r"\datagrip", r"\goland", r"\rubymine", r"\phpstorm",
    r"\android studio", r"\androidstudio",
    r"\visual studio\\", r"\vs code\\", r"\vscode\\", r"\cursor\\",
    r"\unity\\", r"\unrealengine", r"\unreal engine", r"\godot",
    r"\.git\\", r"\node_modules\\", r"\.venv\\", r"\__pycache__\\",
    r"\docker\\", r"\docker desktop\\",
    r"\.cargo\\", r"\.rustup\\", r"\go\\", r"\.go\\",
    r"\anaconda3", r"\miniconda", r"\python3", r"\python311", r"\python312",
    r"\onedrive\\", r"\dropbox\\", r"\google drive\\",
]

# PowerShell keywords que precisam de CONTEXTO pra subir pra HIGH.
# `ExecutionPolicy Bypass` sozinho não é cheat (admins/devs usam direto).
# Só fica HIGH se vier junto de keyword de download na MESMA linha.
PS_HIGH_REQUIRES_DOWNLOAD_CONTEXT = {
    "executionpolicy bypass",
    "set-executionpolicy unrestricted",
    "set-executionpolicy bypass",
    "-windowstyle hidden",
    "-noninteractive",
}

# Keywords de download — se aparece junto, o contexto é malicioso
PS_DOWNLOAD_KEYWORDS = (
    "iex ", "iex(", "invoke-expression",
    "irm ", "invoke-restmethod",
    "iwr ", "invoke-webrequest",
    "downloadstring", "downloadfile",
    "bitsadmin /transfer", "start-bitstransfer",
    "wget ", "curl ",
)

# ----------------------------- Anti-evasão -----------------------------

VM_PROCESS_NAMES = {
    "vmtoolsd.exe":      "VMware Tools",
    "vmwaretray.exe":    "VMware",
    "vmwareuser.exe":    "VMware",
    "vboxservice.exe":   "VirtualBox",
    "vboxtray.exe":      "VirtualBox",
    "vboxcontrol.exe":   "VirtualBox",
    "qemu-ga.exe":       "QEMU",
    "xenservice.exe":    "Xen",
    "prl_tools.exe":     "Parallels",
    "prl_cc.exe":        "Parallels",
}

SANDBOX_PROCESS_NAMES = {
    "sbiesvc.exe":       "Sandboxie",
    "sbiectrl.exe":      "Sandboxie",
    "sandboxierpcss.exe":"Sandboxie",
    "cuckoo.exe":        "Cuckoo Sandbox",
    "wireshark.exe":     "Wireshark (análise)",
    "fiddler.exe":       "Fiddler (proxy)",
    "procmon.exe":       "Process Monitor",
    "procmon64.exe":     "Process Monitor",
}

VM_REGISTRY_PROBES = [
    # (subkey, value_name, substring_que_indica_vm, label)
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "vmware",      "VMware"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "innotek",     "VirtualBox"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "qemu",        "QEMU"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemManufacturer", "parallels",   "Parallels"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "SystemProductName",  "virtual",     "VM (genérica)"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "BIOSVendor",         "vmware",      "VMware"),
    (r"HARDWARE\DESCRIPTION\System\BIOS",   "BIOSVendor",         "innotek",     "VirtualBox"),
]

VM_SERVICE_NAMES = [
    "vmci", "vmhgfs", "vmmemctl", "vmmouse", "vmrawdsk", "vmusbmouse", "vmx86",
    "vboxguest", "vboxmouse", "vboxservice", "vboxsf", "vboxvideo",
    "xenevtchn", "xennet", "xenservice", "xenvbd",
    "prl_eth5", "prl_fs", "prl_memdev", "prl_tg", "prl_time",
]

VM_MAC_PREFIXES = {
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    # Hyper-V (00:03:FF / 00:15:5D) REMOVIDO: o adaptador vEthernet do
    # WSL2, Docker Desktop, Windows Sandbox e VBS usa esses prefixos na
    # MÁQUINA FÍSICA. Em Win10/11 com WSL/Docker/Sandbox isso gerava
    # "VM Detection HIGH" em PC legítimo. FP grave e comum.
    "00:1C:42": "Parallels",
    "52:54:00": "QEMU/KVM",
}

# ----------------------------- Scripts Lua/Luau -----------------------------

SCRIPT_SEARCH_PATHS = [
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\AppData\Roaming",
    r"%USERPROFILE%\AppData\Local",
    r"%LOCALAPPDATA%\Roblox",
]

SCRIPT_SEARCH_MAX_DEPTH = 4
SCRIPT_EXTENSIONS = (".lua", ".luau", ".txt")

SCRIPT_RED_FLAGS = {
    "loadstring(":          "high",
    "getrawmetatable":      "high",
    "setreadonly":          "high",
    "sethiddenproperty":    "high",
    "gethiddenproperty":    "high",
    "hookfunction":         "high",
    "hookmetamethod":       "high",
    "getconnections":       "high",
    "remotespy":            "high",
    "infinite jump":        "medium",
    "infinitejump":         "medium",
    "fly script":           "medium",
    "aimbot":               "high",
    "esp script":           "high",
    "wallhack":             "high",
    "noclip":               "medium",
    "speed hack":           "high",
    "speedhack":            "high",
    "owl hub":              "high",
    "dark hub":             "high",
    "infinite yield":       "high",
    "infiniteyield":        "high",
    "rconsoleprint":        "medium",
    "queue_on_teleport":    "medium",
    "syn.request":          "high",
    "http_request":         "medium",
    "getgenv()":            "high",
    "getsenv":              "medium",
    "getrenv":              "medium",
    # fireserver removido — é API padrão de RemoteEvent, não exclusiva de executor
    "writefile(":           "low",

    # ===== Mais funções de executor 2024+ =====
    "newcclosure":          "high",
    "checkcaller":          "high",
    "iscclosure":           "high",
    "islclosure":           "high",
    "isexecutorclosure":    "high",
    "is_synapse_function":  "high",
    "syn_request":          "high",
    "getnamecallmethod":    "high",
    "setnamecallmethod":    "high",
    "firetouchinterest":    "high",
    "fireclickdetector":    "high",
    "fireproximityprompt":  "high",
    "decompile(":           "high",
    "getscripts(":          "high",
    "getloadedmodules":     "high",
    "getmodules":           "high",
    "getinstances":         "high",
    "getnilinstances":      "high",
    "getgc()":              "high",
    "getreg()":             "high",
    "saveinstance":         "high",
    "appendfile(":          "medium",
    "readfile(":            "medium",
    "loadfile(":            "medium",
    "isfile(":              "low",
    "listfiles(":           "medium",
    "makefolder(":          "low",
    "delfile(":             "medium",

    # ===== Hubs / scripts populares =====
    "xeno hub":             "high",
    "cryptic hub":          "high",
    "marin hub":            "high",
    "hoho hub":             "high",
    "epix hub":             "high",
    "vape v4":              "high",
    "vape lite":            "high",
    "fates admin":          "high",
    "fly hub":              "high",
    "kraken hub":           "high",
    "rip hub":              "high",
    "rocky hub":            "high",
    "fluxus hub":           "high",
    "thresh hub":           "high",
    "matrix hub":           "medium",
    "yba hub":              "medium",
    "evade hub":            "medium",
    "shadovis":             "medium",
    "blox fruits hub":      "high",
    "pet sim hub":          "high",
    "arsenal hub":          "high",
    "phantom forces hub":   "high",
    "doors hub":            "high",
    "criminality hub":      "high",
    "da hood hub":          "high",

    # ===== Funções de bypass/anticheat =====
    "byfron":               "high",
    "hyperion":             "high",
    "antitamper":           "high",
    "anticheat":            "medium",
    "spoof hwid":           "high",
    "byfron bypass":        "high",

    # ===== Padrões comuns em scripts maliciosos =====
    "_g.aimbot":            "high",
    "_g.esp":               "high",
    "_g.noclip":            "high",
    "_g.fly":               "high",
    "_g.speed":             "high",
    "shared.aimbot":        "high",
    "auto farm":            "medium",
    "autofarm":             "medium",
    "auto kill":            "medium",
    "auto rob":             "medium",
    "kill all":             "high",
    "killall":              "high",
    "teleport to player":   "medium",
    "tptoplayer":           "medium",
    "btools":               "medium",
}

# ----------------------------- Cleaners / Anti-forensics -----------------------------

CLEANER_NAMES = {
    "bleachbit":        "high",
    "privazer":         "high",
    "ccleaner":         "medium",
    "ccleaner.exe":     "medium",
    "wise disk cleaner":"medium",
    "wise registry cleaner":"medium",
    "advanced systemcare":"medium",
    "cleanmypc":        "medium",
    "kcleaner":         "medium",
    "iobit uninstaller":"medium",
    "revo uninstaller": "medium",
    "wipe":             "medium",
    "eraser":           "high",
    "sdelete":          "high",
    "shred":            "high",
    "usnjrnl delete":   "high",
    "fsutil usn deletejournal": "high",
}

# ----------------------------- PowerShell / CMD history -----------------------------

POWERSHELL_HISTORY_PATH = r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

POWERSHELL_RED_FLAGS = {
    # One-liner installers (clássico de instalação de cheat por DM)
    "iex ":                    "high",
    "iex(":                    "high",
    "invoke-expression":       "high",
    "irm ":                    "high",
    "invoke-restmethod":       "high",
    "iwr ":                    "high",
    "invoke-webrequest":       "high",
    "downloadstring":          "high",
    "downloadfile":            "high",
    "new-object net.webclient":"medium",

    # Windows Defender bypass
    "set-mppreference":              "high",
    "add-mppreference":              "high",
    "-exclusionpath":                "high",
    "-exclusionprocess":             "high",
    "-disablerealtimemonitoring":    "high",
    "-disablebehaviormonitoring":    "high",
    "-disableioavprotection":        "high",

    # Anti-forense
    "attrib +h":                "medium",
    "cipher /w":                "high",
    "fsutil usn":               "high",
    "sdelete":                  "high",
    "wevtutil cl":              "high",
    "clear-eventlog":           "high",
    "wmic shadowcopy delete":   "high",
    "vssadmin delete":          "high",
    "remove-item -recurse -force": "low",

    # AMSI bypass
    "amsiscanbuffer":           "high",
    "amsiinitfailed":           "high",
    "amsicontext":              "high",

    # Reflection / loading in-memory
    "system.reflection.assembly":"medium",
    "[reflection.assembly]":     "medium",
    "loadwithpartialname":       "medium",

    # Download alternativos
    "curl ":                    "low",
    "wget ":                    "low",
    "bitsadmin /transfer":      "high",
    "start-bitstransfer":       "high",

    # Encoded commands
    "-encodedcommand":          "high",
    "-enc ":                    "high",
    "frombase64string":         "medium",

    # Bypass execution policy
    "executionpolicy bypass":           "high",
    "set-executionpolicy unrestricted": "high",
    "set-executionpolicy bypass":       "high",

    # Hidden window / non-interactive
    "-windowstyle hidden":      "medium",
    "-noninteractive":          "low",
    "-noprofile":               "low",

    # PowerShell remoting suspeito
    "invoke-command":           "low",
}

# Win+R history no registry (clássico - cara digitou caminho de cheat)
RUNMRU_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

# Typed paths (Explorer address bar)
TYPED_PATHS_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"

# ----------------------------- Macro Mouse Software -----------------------------

# Software fabricante: detectar presença + ler scripts/configs
MOUSE_SOFTWARE = {
    "logitech_ghub": {
        "name": "Logitech G HUB",
        "paths": [
            r"%LOCALAPPDATA%\LGHUB",
            r"%PROGRAMDATA%\LGHUB",
            r"%PROGRAMFILES%\LGHUB",
        ],
        # Scripts Lua ficam aqui (motor Lua interno = pode escrever cheat-like macros)
        "script_paths": [
            r"%LOCALAPPDATA%\LGHUB\settings.db",         # SQLite com scripts
            r"%LOCALAPPDATA%\LGHUB\depot_cache",
        ],
    },
    "logitech_gaming_software": {
        "name": "Logitech Gaming Software (legacy)",
        "paths": [
            r"%PROGRAMFILES%\LGS",
            r"%PROGRAMFILES(X86)%\Logitech Gaming Software",
            r"%LOCALAPPDATA%\Logitech\Logitech Gaming Software",
        ],
        "script_paths": [],
    },
    "razer_synapse": {
        "name": "Razer Synapse",
        "paths": [
            r"%PROGRAMFILES(X86)%\Razer",
            r"%LOCALAPPDATA%\Razer",
            r"%APPDATA%\Razer",
        ],
        "script_paths": [
            r"%APPDATA%\Razer\Synapse3\Accounts",
            r"%LOCALAPPDATA%\Razer\Synapse3\Log",
        ],
    },
    "bloody": {
        "name": "Bloody (A4Tech)",
        "paths": [
            r"%PROGRAMFILES(X86)%\Bloody6",
            r"%PROGRAMFILES(X86)%\Bloody7",
            r"%PROGRAMFILES%\Bloody6",
            r"%PROGRAMFILES%\Bloody7",
            r"%LOCALAPPDATA%\Bloody",
        ],
        "script_paths": [],
    },
    "xmouse": {
        "name": "X-Mouse Button Control",
        "paths": [
            r"%PROGRAMFILES%\Highresolution Enterprises\X-Mouse Button Control",
            r"%PROGRAMFILES(X86)%\Highresolution Enterprises\X-Mouse Button Control",
            r"%APPDATA%\Highresolution Enterprises\XMouseButtonControl",
        ],
        "script_paths": [
            r"%APPDATA%\Highresolution Enterprises\XMouseButtonControl",
        ],
    },
    "steelseries_gg": {
        "name": "SteelSeries GG",
        "paths": [
            r"%PROGRAMFILES%\SteelSeries\SteelSeries GG",
            r"%PROGRAMFILES(X86)%\SteelSeries\SteelSeries GG",
            r"%APPDATA%\SteelSeries\SteelSeries Engine 3",
        ],
        "script_paths": [],
    },
    "corsair_icue": {
        "name": "Corsair iCUE",
        "paths": [
            r"%PROGRAMFILES(X86)%\Corsair\CORSAIR iCUE Software",
            r"%PROGRAMFILES%\Corsair\CORSAIR iCUE 4 Software",
            r"%PROGRAMFILES%\Corsair\CORSAIR iCUE 5 Software",
        ],
        "script_paths": [],
    },
    "hyperx_ngenuity": {
        "name": "HyperX NGENUITY",
        "paths": [
            r"%PROGRAMFILES%\HP\HyperX NGENUITY",
            r"%PROGRAMFILES(X86)%\HyperX",
        ],
        "script_paths": [],
    },
    "redragon": {
        "name": "Redragon software",
        "paths": [
            r"%PROGRAMFILES(X86)%\Redragon",
            r"%PROGRAMFILES%\Redragon",
        ],
        "script_paths": [],
    },
}

# Keywords pra procurar em scripts de macro
MACRO_RED_FLAGS = {
    "no recoil":          "high",
    "norecoil":           "high",
    "anti recoil":        "high",
    "antirecoil":         "high",
    "recoil control":     "high",
    "recoil compensation":"high",
    "rcs script":         "high",
    "auto headshot":      "high",
    "autoheadshot":       "high",
    "aim assist":         "medium",
    "aimassist":          "medium",
    "auto fire":          "medium",
    "autofire":           "medium",
    "rapid fire":         "medium",
    "rapidfire":          "medium",
    "burst fire":         "medium",
    "burstfire":          "medium",
    "auto click":         "medium",
    "autoclick":          "medium",
    "spam click":         "medium",
    "spamclick":          "medium",
    "movemouserelative":  "medium",  # Logitech API usada em macros pesadas
    "pressmousebutton":   "low",
    "releasemousebutton": "low",
    "pressandreleasemousebutton":"low",
    "getmkeystate":       "low",
    "outputlogmessage":   "low",
    "enableprimarymousebuttonevents": "medium",
    "valorant":           "low",     # macros pra outros jogos = red flag por hábito
    "cs:go":              "low",
    "csgo":               "low",
    "rust":               "low",
}

# ----------------------------- DLL injection scan -----------------------------

# Nomes de processo do Roblox client a verificar
ROBLOX_PROCESS_NAMES = [
    "RobloxPlayerBeta.exe",
    "RobloxPlayerLauncher.exe",
    "Windows10Universal.exe",
    "Roblox.exe",
    "RobloxStudioBeta.exe",
]

# Pastas onde DLLs LEGÍTIMAS do Windows residem
TRUSTED_DLL_PATHS = [
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs",
    r"c:\program files\windowsapps",
    r"c:\program files (x86)\microsoft",
    r"c:\program files\common files\microsoft shared",
    r"c:\program files (x86)\common files\microsoft shared",
    r"c:\program files\windows defender",
    r"c:\program files (x86)\nvidia corporation",
    r"c:\program files\nvidia corporation",
]

# Pastas onde DLL injetada é SUSPEITA (cheats geralmente caem aqui)
SUSPICIOUS_DLL_PATHS = [
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\temp\\",
    r"\downloads\\",
    r"\desktop\\",
    r"\documents\\",
    r"\users\public\\",
]

# ----------------------------- Bloxstrap / Bytecode -----------------------------

BLOXSTRAP_PATHS = [
    r"%LOCALAPPDATA%\Bloxstrap",
    r"%LOCALAPPDATA%\Bloxstrap\Modifications",
    r"%LOCALAPPDATA%\Bloxstrap\Versions",
]

BYTECODE_DUMP_FOLDERS = [
    r"%USERPROFILE%\Desktop\scripts",
    r"%USERPROFILE%\Desktop\roblox scripts",
    r"%USERPROFILE%\Documents\scripts",
    r"%USERPROFILE%\Documents\roblox",
    r"%USERPROFILE%\Documents\roblox scripts",
    r"%LOCALAPPDATA%\Roblox\Modules",
    r"%APPDATA%\Krnl\autoexec",
    r"%APPDATA%\Krnl\scripts",
    r"%APPDATA%\Wave\autoexec",
    r"%APPDATA%\Solara\autoexec",
    r"%APPDATA%\Fluxus\autoexec",
    r"%APPDATA%\Hydrogen\autoexec",
]

# ----------------------------- Hidden files / persistence -----------------------------

HIDDEN_FILE_PATHS = [
    r"%USERPROFILE%\Desktop",
    r"%USERPROFILE%\Downloads",
    r"%USERPROFILE%\Documents",
    r"%USERPROFILE%\AppData\Local",
    r"%USERPROFILE%\AppData\Roaming",
]

AUTOSTART_REGISTRY_KEYS_HKCU = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    (r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policies Run"),
]

AUTOSTART_REGISTRY_KEYS_HKLM = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    (r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (Wow64)"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policies Run"),
]

STARTUP_FOLDERS = [
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
]

WER_PATHS = [
    r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportArchive",
    r"%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue",
    r"%PROGRAMDATA%\Microsoft\Windows\WER\ReportArchive",
    r"%PROGRAMDATA%\Microsoft\Windows\WER\ReportQueue",
]
