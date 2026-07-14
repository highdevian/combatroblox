"""
Banco de assinaturas conhecidas — executores Roblox, ferramentas auxiliares,
sinais de VM/Sandbox e padrões em scripts Lua.

Severity:
  high   = match direto (quase certeza)
  medium = ferramenta auxiliar ou bypass
  low    = palavra-chave ambígua

As listas embutidas abaixo podem ser ESTENDIDAS sem recompilar, via um
arquivo signatures.json ao lado do executável (ver load_external_signatures
no fim do módulo). Útil pra adicionar executor novo entre releases.
"""

import os
import sys
import json

EXECUTOR_KEYWORDS = {
    # PC Executors
    # "synapse" (solto) removido — FP grave: colide com Razer Synapse
    # (software de mouse em milhões de PCs gamer). As variantes abaixo
    # cobrem o executor Synapse X sem o FP. "synapse.exe" é keyword (não só
    # process name) pra ser pego no Prefetch/Amcache, e não casa
    # "razersynapse.exe" (sem fronteira de palavra antes de synapse).
    "synapse.exe":      "high",
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
    # Process Hacker / System Informer = dual-use (sysadmin/dev/SS supervisor
    # usam tanto quanto cheater). LOW de baseline; o filtro dev-env ainda pode
    # rebaixar. Cheater que injeta com isso aparece em outras fontes (DLL não
    # assinada no Roblox, BYOVD, exclusão Defender).
    "process hacker":   "low",
    "system informer":  "low",
    "extreme injector": "medium",
    "xenos injector":   "medium",
    "manualmap":        "medium",
    "dll injector":     "medium",
    "ram-master":       "low",

    # ===== Top 5 priorizados 2024-2026 (Solara/Xeno/Wave/Velocity/Ronix) =====
    # Variantes redundantes propositais — pega o cheater independente de
    # qual fonte (Prefetch/Amcache/BAM/Browser) está mais explícita.

    # Solara — keywords adicionais (process/dom já estão nas suas seções)
    "solara hub":       "high",
    "solara.cc":        "high",
    "solara.gg":        "high",
    "solara.dev":       "high",
    "getsolara":        "high",
    "solaraexec":       "high",
    "solara-bootstrapper":"high",

    # Xeno (open-source, muito popular)
    # "xeno" (solto) removido — substring pega Xenoblade, Xenonauts, XenoBot,
    # e pastas/saves de jogos da série Xeno. Variantes abaixo cobrem o executor.
    "xeno.exe":         "high",
    "xeno executor":    "high",
    "xeno hub":         "high",
    "xeno.now":         "high",
    "xeno.lat":         "high",
    "xeno.gg":          "high",
    "xeno.cc":          "high",
    "xeno.dev":         "high",
    "xenoexec":         "high",
    "xeno-bootstrapper":"high",
    "xenobootstrapper": "high",

    # Wave — keywords adicionais
    "wave hub":         "high",
    "wave.gg":          "high",
    "wave.cc":          "high",
    "getwave":          "high",
    "waveexec":         "high",
    "waveexecutor":     "high",
    "wave-bootstrapper":"high",

    # Velocity — keywords adicionais
    "velocity exec":    "high",
    "velocity hub":     "high",
    "velocity.exe":     "high",
    "velocity.cx":      "high",
    "velocity.gg":      "high",
    "velocity.cc":      "high",
    "velocityexec":     "high",
    "velocityexploit":  "high",
    "getvelocity":      "high",

    # Ronix — AUSENTE na base anterior. Adicionado completo.
    # "ronix" (solto) removido — FP: colide com Ronix (marca de wakeboard).
    # As variantes abaixo + ronix.exe (processo) cobrem o executor.
    "ronix executor":   "high",
    "ronix exec":       "high",
    "ronix hub":        "high",
    "ronix.exe":        "high",
    "ronix.cc":         "high",
    "ronix.gg":         "high",
    "ronix.lat":        "high",
    "ronix.dev":        "high",
    "ronixexec":        "high",
    "ronix-bootstrapper":"high",

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
    # ("scriptware" e "calamari executor" já estão definidos acima — dupes removidas)
    # "valex" (solto) removido — FP: colide com Valex (marca de cabos).
    # "valex.exe" (keyword, pra Prefetch/Amcache) + "valex executor" cobrem.
    "valex.exe":        "high",
    "valex executor":   "high",
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

    # ===== External cheats (aimbot/ESP fora do cliente — não são executor Luau) =====
    # Prefetch/Amcache/BAM. Catálogo expandido em external_scanner (pesquisa
    # pública: Matcha, Severe, DX9WARE, Matrix, Celex, Bauix, …).
    # Bare words comuns (severe/matrix/photon) só em compostos.
    "matcha.exe":           "high",
    "matcha external":      "high",
    "matcha-external":      "high",
    "matcha_external":      "high",
    "matcha beta":          "high",
    "matchabeta":           "high",
    "matchaloader":         "high",
    "matcha latte":         "high",
    "vasile.exe":           "high",
    "vasile external":      "high",
    "bauix.exe":            "high",
    "bauix external":       "high",
    "sheldon external":     "high",
    "sheldonexternal":      "high",
    "timeoutwtf":           "medium",
    "timeout external":     "medium",
    "roblox external":      "high",
    "robloxexternal":       "high",
    "external aimbot":      "medium",
    "external esp":         "medium",
    "external cheat":       "medium",
    "omega-launcher":       "medium",
    # Severe / DX9 / Matrix / Celex / Mooze / Ronin-ext / Oxygen-ext / …
    "severe external":      "high",
    "severe-external":      "high",
    "severe.exe":           "high",
    "severe2":              "high",
    "severe 2.0":           "high",
    "dx9ware":              "high",
    "dx9 ware":             "high",
    "dx9 external":         "high",
    "dx9external":          "high",
    "matrix external":      "high",
    "matrixhub":            "high",
    "mtxhub":               "high",
    "matrixexternal":       "high",
    "celex":                "high",
    "celex external":       "high",
    "celex v3":             "high",
    "celexv3":              "high",
    "celex.exe":            "high",
    "mooze":                "high",
    "mooze external":       "high",
    "mooze.exe":            "high",
    "ronin external":       "high",
    "roninexternal":        "high",
    "oxygen external":      "high",
    "oxygenexternal":       "high",
    "santoware":            "high",
    "santo ware":           "high",
    "photon external":      "high",
    "photonexternal":       "high",
    "clarity external":     "high",
    "clarityexternal":      "high",
    "serotonin":            "high",
    "serotonin external":   "high",
    "serotonin.exe":        "high",
    "spxrkz":               "high",
    "spxrkz external":      "high",
    "spxrkz.exe":           "high",
    "yerba external":       "medium",
    "yerbaexternal":        "medium",
    "polter.sys":           "high",
    "polter.exe":           "high",

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

    # ===== Autoclickers / macros standalone =====
    # Ferramentas dedicadas de autoclique/macro — uso comum em farm de
    # Roblox (clicar sozinho), combo automático, etc. Severidade MEDIUM:
    # tê-las não prova cheat (clicker game legítimo existe), mas é sinal —
    # o Confidence Engine corrobora se houver atividade de Roblox junto.
    # Nomes específicos o suficiente pra não dar FP (word-boundary).
    "op autoclicker":     "medium",
    "opautoclicker":      "medium",
    "speed autoclicker":  "medium",
    "speedautoclicker":   "medium",
    "gs auto clicker":    "medium",
    "gsautoclicker":      "medium",
    "free mouse clicker": "medium",
    "free mouse auto clicker": "medium",
    "auto mouse clicker": "medium",
    "tinytask":           "medium",
    "mouse recorder":     "medium",
    "mouserecorder":      "medium",
    "macro recorder":     "medium",
    "macrorecorder":      "medium",
    "pulover":            "medium",   # Pulover's Macro Creator
    "macro creator":      "medium",
    "mini mouse macro":   "medium",
    "minimousemacro":     "medium",
    "perfect automation": "medium",
    "murgee":             "medium",   # Auto Clicker by MurGee
    "auto keyboard presser": "medium",
    "autokeyboard":       "medium",
    "fast clicker":       "medium",
    "jitter clicker":     "medium",
    "jitterclicker":      "medium",
    # Roblox-específico = mais suspeito
    "roblox auto clicker":"high",
    "roblox autoclicker": "high",
    "roblox macro":       "high",
    "auto farm macro":    "high",
    "autofarm macro":     "high",

    # ===== Evasão de ban e contas alt =====
    # Gerenciadores de alt / multi-instância: MEDIUM (rodar várias contas
    # não prova cheat, mas é sinal forte de botting/alt evasion num SS).
    # NÃO inclui "fps unlocker"/"bloxstrap"/"fishstrap" (legítimos).
    "roblox account manager": "medium",
    "rbx account manager":    "medium",
    "alt manager":            "medium",
    "multi account manager":  "medium",
    "multibloxy":             "medium",
    "multi bloxy":            "medium",
    "multiroblox":            "medium",
    "multi roblox":           "medium",
    "multirblx":              "medium",
    "roblox multi instance":  "medium",
    "roblox multiinstance":   "medium",
    "rbxmulti":               "medium",
    "roblox alt generator":   "high",
    "alt generator":          "medium",
    "account generator":      "medium",

    # HWID spoofers — burlar BAN DE HARDWARE (Hyperion/Byfron). Sem uso
    # legítimo pra jogador normal: HIGH. Expande a cobertura existente.
    "hwid changer":           "high",
    "hwid reset":             "high",
    "serial spoofer":         "high",
    "disk spoofer":           "high",
    "smbios spoofer":         "high",
    "mac spoofer":            "high",
    "byfron spoofer":         "high",
    "hyperion spoofer":       "high",
    "roblox spoofer":         "high",
    "cleaner spoofer":        "high",
    "exodus spoofer":         "high",
    "vanity spoofer":         "high",

    # ===== Winter Bypass ecosystem (IoC 07/2026) =====
    # Fishstrap: wrapper Roblox que carrega Winter Bypass (NÃO confundir com
    # Bloxstrap open-source legítimo). RobloxCrashHandler.exe: masquerade
    # usado pelo Winter Bypass p/ se esconder. WEAO-LIVE-WindowsPlayer:
    # path/GUID que aparece no Prefetch/Amcache do Winter.
    "winter bypass":          "high",
    "winter executor":        "high",
    "fishstrap":              "high",
    "fishstrap.exe":          "high",
    "weao-live-windowsplayer":"high",
    "weao live":              "high",
}

EXECUTOR_PROCESS_NAMES = {
    "krnl.exe":             "high",
    "fluxus.exe":           "high",
    "wave.exe":             "high",
    "solara.exe":           "high",
    "velocity.exe":         "high",
    # electron.exe removido — framework Electron (dev) usa esse nome em dev mode.
    # sentinel.exe removido — Thales/Gemalto Sentinel LDK/HASP (licenciamento
    #   em software corporativo/CAD/engenharia) é comuníssimo. "sentinel exploit" cobre.
    # swift.exe removido — Swift (linguagem/transfer tools). "swift executor"/"swift x" cobrem.
    "trigon.exe":           "high",
    "argon.exe":            "high",
    "zorara.exe":           "high",
    "vegax.exe":            "high",
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
    # Dual-use (ver nota em EXECUTOR_KEYWORDS): rebaixado pra LOW de baseline.
    "processhacker.exe":      "low",
    "systeminformer.exe":     "low",
    "extremeinjector.exe":    "medium",
    "xenosinjector.exe":      "medium",

    # ===== Executores 2024-2026 =====
    "xeno.exe":                   "high",
    "xeno-bootstrapper.exe":      "high",
    "xenobootstrapper.exe":       "high",
    "xenolauncher.exe":           "high",
    # Ronix (faltava completamente)
    "ronix.exe":                  "high",
    "ronix-bootstrapper.exe":     "high",
    "ronixbootstrapper.exe":      "high",
    "ronixlauncher.exe":          "high",
    "ronixexec.exe":              "high",
    # Velocity (faltavam variantes)
    "velocity-bootstrapper.exe":  "high",
    "velocitybootstrapper.exe":   "high",
    "velocitylauncher.exe":       "high",
    # Wave (faltavam variantes)
    "wavelauncher.exe":           "high",
    "waveexec.exe":               "high",
    # Solara (faltavam variantes)
    "solarabootstrapper.exe":     "high",
    "solaralauncher.exe":         "high",
    "solaraexec.exe":             "high",
    "cryptic.exe":                "high",
    "cryptic-bootstrapper.exe":   "high",
    "empyrean.exe":               "high",
    "valyse.exe":                 "high",
    "bunni.exe":                  "high",
    "acrylix.exe":                "high",
    "marin.exe":                  "high",
    "furk.exe":                   "high",
    "furkos.exe":                 "high",
    "karambit.exe":               "high",
    "drumix.exe":                 "high",
    "omegax.exe":                 "high",
    "stellar.exe":                "high",
    "sploitware.exe":             "high",
    "ccdownloader.exe":           "high",
    "cellura.exe":                "high",
    "hexus.exe":                  "high",
    "valex.exe":                  "high",
    # Removidos (nomes genéricos demais p/ exact-match HIGH — cobertos por
    # keyword "<nome> executor"): cosmic.exe, coral.exe, sense.exe (RGB/periférico),
    # omega.exe, apex.exe (Apex Legends), verbose.exe, ninja.exe (Ninja build
    # system — dev C++/CMake), pylon.exe, fenix.exe, ronin.exe.
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

    # ===== External cheats (process names) =====
    "matcha.exe":             "high",
    "matchaexternal.exe":     "high",
    "matcha_external.exe":    "high",
    "matcha-external.exe":    "high",
    "matchaloader.exe":       "high",
    "matchabeta.exe":         "high",
    "vasile.exe":             "high",
    "vasileexternal.exe":     "high",
    "bauix.exe":              "high",
    "bauixexternal.exe":      "high",
    "sheldonexternal.exe":    "high",
    "sheldon_external.exe":   "high",
    "timeoutwtf.exe":         "medium",
    "robloxexternal.exe":     "high",
    "rbxexternal.exe":        "high",
    "stomega.exe":            "medium",
    "severe.exe":             "high",
    "severeexternal.exe":     "high",
    "severe2.exe":            "high",
    "severeloader.exe":      "high",
    "dx9ware.exe":            "high",
    "dx9wareloader.exe":      "high",
    "dx9external.exe":        "high",
    "matrixhub.exe":          "high",
    "matrixexternal.exe":     "high",
    "mtxhub.exe":             "high",
    "celex.exe":              "high",
    "celexexternal.exe":      "high",
    "celexv3.exe":            "high",
    "mooze.exe":              "high",
    "moozeexternal.exe":      "high",
    "roninexternal.exe":      "high",
    "oxygenexternal.exe":     "high",
    "santoware.exe":          "high",
    "photonexternal.exe":     "high",
    "clarityexternal.exe":    "high",
    "serotonin.exe":          "high",
    "spxrkz.exe":             "high",
    "polter.exe":             "high",

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

    # ===== Autoclickers / macros standalone (processos) =====
    "opautoclicker.exe":      "medium",
    "speedautoclicker.exe":   "medium",
    "gsautoclicker.exe":      "medium",
    "autoclicker.exe":        "medium",
    "auto clicker.exe":       "medium",
    "freemouseclicker.exe":   "medium",
    "freemouseautoclicker.exe":"medium",
    "automouseclicker.exe":   "medium",
    "tinytask.exe":           "medium",
    "mouserecorder.exe":      "medium",
    "macrorecorder.exe":      "medium",
    "mouse recorder pro.exe": "medium",
    "minimousemacro.exe":     "medium",
    "perfectautomation.exe":  "medium",
    "macrocreator.exe":       "medium",   # Pulover's Macro Creator
    "fastclicker.exe":        "medium",
    "autokeyboard.exe":       "medium",
    "auto keyboard presser.exe": "medium",

    # ===== Evasão de ban e contas alt (processos) =====
    "roblox account manager.exe": "medium",
    "rbxalt.exe":             "medium",
    "altmanager.exe":         "medium",
    "multibloxy.exe":         "medium",
    "multiroblox.exe":        "medium",
    "multirblx.exe":          "medium",
    "rbxmulti.exe":           "medium",
    # HWID spoofers (processos) — expande
    "hwidchanger.exe":        "high",
    "spooferpro.exe":         "high",
    "serialspoofer.exe":      "high",
    "smbiosspoofer.exe":      "high",
    "macspoofer.exe":         "high",
    "byfronspoofer.exe":      "high",
    "robloxspoofer.exe":      "high",

    # ===== Winter Bypass ecosystem (IoC 07/2026) =====
    # Fishstrap: wrapper Roblox que carrega Winter Bypass (NÃO confundir com
    # Bloxstrap open-source legítimo).
    "fishstrap.exe":          "high",
    "winter.exe":             "high",
    "winterbypass.exe":       "high",
    "winter-bypass.exe":      "high",
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
    # External products (browser/DNS)
    "moon.sex":             "high",   # Bauix
    "celex.gg":             "high",
    "v3rmillion.net":       "low",
    "rscripts.net":         "low",
    "scriptblox.com":       "low",
    "robloxscripts.com":    "low",

    # ===== Executores 2024-2026 (domínios) =====
    "xeno.now":             "high",
    "xeno.lat":             "high",
    "xeno.gg":              "high",
    "xeno.cc":              "high",
    "xeno.dev":             "high",
    "xenoexec.com":         "high",
    "getxeno.gg":           "high",
    "getxeno.com":          "high",
    # Ronix — domínios (faltavam completamente)
    "ronix.cc":             "high",
    "ronix.gg":             "high",
    "ronix.lat":            "high",
    "ronix.dev":            "high",
    "ronix.now":            "high",
    "ronixexec.com":        "high",
    "getronix.com":         "high",
    "getronix.gg":          "high",
    # Velocity — domínios adicionais
    "velocity.cx":          "high",
    "velocity.gg":          "high",
    "velocity.cc":          "high",
    "velocity.lat":         "high",
    "velocityexec.com":     "high",
    "getvelocity.com":      "high",
    "getvelocity.gg":       "high",
    # Wave — domínios adicionais
    "wave.gg":              "high",
    "wave.cc":              "high",
    "wave.dev":             "high",
    # Solara — domínios adicionais
    "solara.cc":            "high",
    "solara.lat":           "high",
    "solara.dev":           "high",
    "getsolara.com":        "high",
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
    "evon.cc":              "high",
    "evonexploit.com":      "high",
    "trigonevo.gg":         "high",
    "swiftexec.gg":         "high",
    "swift-exec.com":       "high",

    # HWID Spoofer sites
    "ragespoof.com":        "high",
    "permspoof.com":        "high",
    "tbhd.cc":              "high",
    "spoofer.gg":           "high",
    "hwid-spoofer.com":     "high",

    # KeyAuth — SaaS de DRM/licensing usado em ~todo external pago
    # (auth handshake HTTPS aparece em DNS cache / net conns / browser cache).
    # Extraído de repos públicos (Layuh-Roblox usa keyauth). Um browser fez
    # DNS pra keyauth.win → cheat pago rodou aqui em algum momento.
    "keyauth.win":          "high",
    "keyauth.cc":           "high",
    "keyauth.pro":          "high",
    "keyauth.gg":           "high",
    "keyauth.to":           "high",
    "keyauth.us":           "high",

    # Offset feeds — sites que publicam offsets do RobloxPlayerBeta atualizados
    # pra cheaters syncarem seus builds. Ninguém legítimo visita.
    # imtheo.lol referenciado no repo autopsy (github.com/pwpo/autopsy).
    "imtheo.lol":           "high",
    "rbxoffsets.com":       "high",
    "robloxoffsets.com":    "high",
    # autopsy.lol — brand direta do external cheat pwpo/autopsy. Aparece como
    # title de MessageBox ("Open Roblox first.") + class name da window ImGui.
    # Um browser history pra este domínio ou hosts file referencia = cheater.
    "autopsy.lol":          "high",

    # Marketplaces / forums grayhat
    "elitepvpers.com":      "medium",
    "unknowncheats.me":     "medium",
    "guidedhacking.com":    "medium",
    "lanik.us":             "medium",
    "mpgh.net":             "medium",
}

# Domínios CONFIÁVEIS (allowlist). Download+execução (irm|iex) a partir destes
# NÃO é flag — software legítimo que o dono instala por one-liner.
#
# O set abaixo contém domínios UNIVERSAIS — plataformas tão comuns que um
# `Invoke-RestMethod` / `irm` para elas não é indício de cheat. O dono ainda
# pode SOMAR domínios próprios via `trusted_domains.json` (ao lado do exe, ou
# env TELADOR_TRUSTED_DOMAINS) — load_trusted_domains() mescla no import.
#
# Semântica: a allowlist só LIMPA o par download/execução (família de rede
# iex/irm/iwr/downloadstring…). Red flag INDEPENDENTE na mesma linha (bypass de
# Defender, anti-forense, encodedcommand…) ou nome de executor real continuam
# acendendo — domínio confiável não dá passe livre pro resto. Casa com fronteira
# de domínio (matching.domain_in_text): sub.x.tools casa, evilx.tools.co não.
TRUSTED_DOMAINS = {
    "discord.com",          # webhooks, bots — uso massivo na comunidade Roblox
    "discordapp.com",       # alias antigo do Discord
}

_TRUSTED_DOMAINS_FILENAME = "trusted_domains.json"


def _trusted_domains_candidates() -> list:
    """env TELADOR_TRUSTED_DOMAINS -> lado do exe/módulo -> %LOCALAPPDATA%\\Telador.

    NÃO inclui o CWD de propósito: como TRUSTED_DOMAINS SUPRIME detecção (ao
    contrário do yara_rules.json, que só adiciona), um arquivo solto na pasta de
    onde se roda o telador seria um vetor de evasão drive-by fácil demais.

    LOCALAPPDATA é OK (e idêntico ao fallback de signatures.json) porque exige
    posicionamento INTENCIONAL — não é vetor drive-by — e resolve o caso real do
    dono: baixou o exe em Downloads/Desktop, dropa o JSON em LOCALAPPDATA UMA
    vez e funciona de qualquer lugar que rode o exe."""
    cands = []
    env = os.environ.get("TELADOR_TRUSTED_DOMAINS")
    if env:
        cands.append(env)
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    cands.append(os.path.join(base, _TRUSTED_DOMAINS_FILENAME))
    # LOCALAPPDATA é o padrão; USERPROFILE\AppData\Local é fallback redundante
    # pra casos onde LOCALAPPDATA não está definido (env truncado, contexto
    # elevado anômalo etc). Os dois apontam pro mesmo lugar em uso normal —
    # dedup com set() preserva ordem só por garantia.
    seen = set(cands)
    for base in (
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("APPDATA"),
        os.path.join(os.environ["USERPROFILE"], "AppData", "Local")
            if os.environ.get("USERPROFILE") else None,
    ):
        if not base:
            continue
        p = os.path.join(base, "Telador", _TRUSTED_DOMAINS_FILENAME)
        if p not in seen:
            cands.append(p)
            seen.add(p)
    return cands


def load_trusted_domains() -> int:
    """Mescla trusted_domains.json no set TRUSTED_DOMAINS (in-place).

    Tenta TODOS os candidatos: se o primeiro está com BOM/JSON quebrado,
    segue pro próximo (antes retornava 0 e a allowlist ficava só Discord —
    FP clássico de irm|iex legítimo). utf-8-sig engole BOM do PowerShell
    Set-Content. Formato: lista JSON de strings. Retorna nº de domínios
    somados."""
    added = 0
    for path in _trusted_domains_candidates():
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8-sig") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue  # tenta o próximo caminho
        if not isinstance(data, list):
            continue
        for d in data:
            if isinstance(d, str) and d.strip():
                dom = d.strip().lower()
                if dom not in TRUSTED_DOMAINS:
                    TRUSTED_DOMAINS.add(dom)
                    added += 1
        # Achou um arquivo válido — não precisa mesclar todos (primeiro
        # intencional vence: env > lado do exe > LOCALAPPDATA).
        if added or data is not None:
            return added
    return 0


load_trusted_domains()

# Família "rede/download" dos red flags — são os únicos que um TRUSTED_DOMAINS
# limpa. Subconjunto de POWERSHELL_RED_FLAGS; o resto (Defender/anti-forense/
# AMSI/encoded) NÃO é limpo por domínio confiável.
PS_NETWORK_REDFLAGS = {
    "iex ", "iex(", "invoke-expression",
    "irm ", "invoke-restmethod",
    "iwr ", "invoke-webrequest",
    "downloadstring", "downloadfile", "new-object net.webclient",
    "curl ", "wget ", "bitsadmin /transfer", "start-bitstransfer",
}

SUSPICIOUS_FOLDER_NAMES = {
    "synapse x":            "high",
    "synapsex":             "high",
    "krnl":                 "high",
    "fluxus":               "high",
    "wave":                 "high",
    "solara":               "high",
    "velocity executor":    "high",
    # Bare words genéricos removidos — como SUSPICIOUS_FOLDER_NAMES casa o nome
    # EXATO da pasta, estes colidiam com software/ferramentas legítimas cuja
    # pasta se chama exatamente assim. Os executores seguem cobertos por
    # variantes específicas (process name / domínio / "X executor"):
    #   "codex"    → OpenAI Codex (IA dev)              · cobre codex.exe, codex.lol, "codex executor"
    #   "argon"    → Argon (sync tool de Rojo p/ Roblox) · cobre "argon executor"
    #   "electron" → Electron framework (build/cache)    · cobre "electron exploit"
    #   "hydrogen" → Hydrogen (sequencer de música)      · cobre hydrogen.exe, hydrogen-m
    #   "sentinel" → Sentinel licensing/HASP, Dell       · cobre "sentinel exploit"
    "trigon evo":           "high",
    "jjsploit":             "high",
    "scriptware":           "high",
    "rbxexploits":          "high",
    "robloxscripts":        "medium",
    "roblox scripts":       "medium",
    "exploits":             "low",

    # ===== Executores 2024-2026 (folder names) =====
    "xeno":                 "high",
    "xeno executor":        "high",
    # "cryptic" (solto) removido — Cryptic Studios (Star Trek Online, Neverwinter)
    # cria pasta "Cryptic". Cobre "cryptic exec".
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

    # ===== External cheats (folder names exact) =====
    "matcha":               "high",
    "matcha external":      "high",
    "matcha beta":          "high",
    "matchabeta":           "high",
    "vasile":               "high",
    "bauix":                "high",
    "sheldon external":     "high",
    "omega-launcher":       "medium",
    "robloxexternal":       "high",
    "severe external":      "high",
    "severe2":              "high",
    "severe 2.0":           "high",
    "dx9ware":              "high",
    "matrixhub":            "high",
    "matrix external":      "high",
    "celex":                "high",
    "celex v3":             "high",
    "celexv3":              "high",
    "mooze":                "high",
    "ronin external":       "high",
    "oxygen external":      "high",
    "santoware":            "high",
    "serotonin":            "high",
    "spxrkz":               "high",
    "polter":               "high",
    "timeoutwtf":           "medium",
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
    r"\visual studio\\", r"\vs code\\", r"\vscode\\", r"microsoft vs code", r"\cursor\\",
    r"\unity\\", r"\unrealengine", r"\unreal engine", r"\godot",
    r"\.git\\", r"\node_modules\\", r"\.venv\\", r"\__pycache__\\",
    r"\.vscode", r"\.cursor",
    r"\.idea\\",
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
    # fire* rebaixados p/ medium — são APIs NATIVAS do Roblox (Instance:Fire*)
    # usadas em jogos legítimos no Studio, não exclusivas de executor.
    "firetouchinterest":    "medium",
    "fireclickdetector":    "medium",
    "fireproximityprompt":  "medium",
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

    # ===== APIs de executor pra aimbot/ESP Luau (v3.45.3) =====
    # Extraído de github.com/dev79kz/AimbotScript e correlatos.
    # mousemoverel: função exposta APENAS por executor pra mover mouse do OS
    # a partir do script Lua (aim-assist "externo" saindo do Roblox). Roblox
    # nativo nunca expõe. Zero uso legítimo — HIGH sem hesitação.
    "mousemoverel":         "high",
    # Drawing API: exclusiva de executor. Roblox client não expõe Drawing.new.
    # "circle"/"square"/"line"/"text" são as primitivas usadas em ESP/FOV.
    "drawing.new(":         "high",
    # FOVCircle: nome de variável muito distintivo do combo aimbot+FOV
    # visualizer. Se aparece em log/cache/history, é aimbot dropado.
    "fovcircle":            "high",
    # Aim-snap padrão: Camera.CFrame = CFrame.new(Camera.CFrame.Position, alvo).
    # Match de substring case-insensitive — sobrevive a whitespace variation.
    # Zero FP conhecido (jogo dev normal NÃO faz isso).
    "camera.cframe = cframe.new(camera.cframe.position": "high",
    # WorldToViewportPoint: API pública mas ~exclusivamente usada em ESP
    # (projeção 3D → 2D pra desenhar box/tracer). MEDIUM porque tem uso raro
    # legítimo em UI custom de jogo.
    "worldtoviewportpoint": "medium",
    # GetPartsObscuringTarget: API pública mas assinatura de wallcheck
    # (checa raio entre câmera e alvo). MEDIUM pela mesma razão.
    "getpartsobscuringtarget": "medium",

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


# ----------------------------- Assinaturas externas -----------------------------

# Seções aceitas em signatures.json -> dict embutido correspondente.
_MERGE_TARGETS = {
    "executor_keywords":      EXECUTOR_KEYWORDS,
    "executor_process_names": EXECUTOR_PROCESS_NAMES,
    "suspicious_domains":     SUSPICIOUS_DOMAINS,
    "suspicious_folder_names": SUSPICIOUS_FOLDER_NAMES,
    "script_red_flags":       SCRIPT_RED_FLAGS,
}
_VALID_SEVERITIES = {"high", "medium", "low"}

# Versão da base de assinaturas externa carregada (None se só embutidas).
# Permite avisar o supervisor quando a lista local está velha.
LOADED_SIG_VERSION = None


def _signatures_path() -> str:
    """signatures.json ao lado do .exe (frozen) ou do módulo (dev)."""
    sidecar = _sidecar_signatures_path()
    if os.path.isfile(sidecar):
        return sidecar
    appdata = _appdata_signatures_path()
    return appdata or sidecar


def _sidecar_signatures_path() -> str:
    """signatures.json ao lado do exe/modulo."""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "signatures.json")


def _appdata_signatures_path() -> str | None:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    if not base:
        return None
    return os.path.join(base, "Telador", "signatures.json")


def _candidate_signature_paths() -> list[str]:
    paths = [_sidecar_signatures_path()]
    appdata = _appdata_signatures_path()
    if appdata and appdata not in paths:
        paths.append(appdata)
    return paths


def load_external_signatures(path: str = None) -> tuple[int, str | None]:
    """
    Mescla signatures.json (se existir) nas listas embutidas, IN-PLACE.

    Formato esperado (todas as seções opcionais):
        {
          "executor_keywords":      {"novoexec": "high"},
          "executor_process_names": {"novoexec.exe": "high"},
          "suspicious_domains":     {"novoexec.gg": "high"},
          "suspicious_folder_names":{"novoexec": "high"},
          "script_red_flags":       {"novafuncao": "high"},
          "external_process_names": {"novocheat.exe": "high"},
          "external_path_tokens":   {"novocheat external": "high"},
          "external_basenames":     {"novocheat": "high"}
        }

    Seções external_* alimentam external_scanner (family_id default "custom").
    Valor pode ser "high"|"medium"|"low" ou
    {"severity": "high", "family": "nome"}.

    Degrada graciosamente: arquivo ausente, JSON inválido, seção ou entrada
    malformada nunca quebram — apenas são ignorados. Retorna (n_mescladas,
    erro_ou_None). A mutação é in-place (mesmo objeto que matching.py referencia),
    e deve ocorrer ANTES do primeiro match_keyword (matching compila sob demanda).
    """
    if path is None:
        for candidate in _candidate_signature_paths():
            if os.path.isfile(candidate):
                path = candidate
                break
    if not path or not os.path.isfile(path):
        return 0, None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as e:
        return 0, f"signatures.json ignorado ({e})"
    if not isinstance(data, dict):
        return 0, "signatures.json ignorado (raiz não é objeto)"

    global LOADED_SIG_VERSION
    ver = data.get("version")
    if isinstance(ver, str) and ver.strip():
        LOADED_SIG_VERSION = ver.strip()

    added = 0
    for section_key, target in _MERGE_TARGETS.items():
        section = data.get(section_key)
        if not isinstance(section, dict):
            continue
        for raw_k, raw_v in section.items():
            if not isinstance(raw_k, str):
                continue
            k = raw_k.lower().strip()
            sev = str(raw_v).lower().strip()
            if not k or sev not in _VALID_SEVERITIES:
                continue
            target[k] = sev
            added += 1

    added += _merge_external_scanner_sigs(data)
    return added, None


def _parse_ext_sev_family(raw_v) -> tuple[str, str] | None:
    """Parse valor de seção external_* → (severity, family) ou None."""
    if isinstance(raw_v, str):
        sev = raw_v.lower().strip()
        if sev in _VALID_SEVERITIES:
            return sev, "custom"
        return None
    if isinstance(raw_v, dict):
        sev = str(raw_v.get("severity", "")).lower().strip()
        fam = str(raw_v.get("family", "custom")).lower().strip() or "custom"
        if sev in _VALID_SEVERITIES:
            return sev, fam
    return None


def _merge_external_scanner_sigs(data: dict) -> int:
    """Mescla IOCs de external no módulo external_scanner (se importável)."""
    try:
        import external_scanner as ext
    except ImportError:
        return 0

    mapping = {
        "external_process_names": ext.EXTERNAL_PROCESS_NAMES,
        "external_path_tokens":   ext.EXTERNAL_PATH_TOKENS,
        "external_basenames":     ext.EXTERNAL_BASENAME_EXACT,
    }
    added = 0
    for section_key, target in mapping.items():
        section = data.get(section_key)
        if not isinstance(section, dict):
            continue
        for raw_k, raw_v in section.items():
            if not isinstance(raw_k, str):
                continue
            k = raw_k.lower().strip()
            parsed = _parse_ext_sev_family(raw_v)
            if not k or not parsed:
                continue
            sev, fam = parsed
            target[k] = (sev, fam)
            # Mantém cluster engine alinhado (alias + label)
            ext.EXTERNAL_ALIAS_MAP[k] = fam
            ext.EXTERNAL_ALIAS_MAP.setdefault(fam, fam)
            if fam not in ext.EXTERNAL_FAMILY_LABELS:
                ext.EXTERNAL_FAMILY_LABELS[fam] = f"{fam} (external)"
            stem = k[:-4] if k.endswith(".exe") else k
            if stem != k:
                ext.EXTERNAL_ALIAS_MAP[stem] = fam
            added += 1
    return added


def signatures_path() -> str:
    """Caminho público do signatures.json (ao lado do exe/módulo)."""
    return _signatures_path()
