/*
 * Frida script - Bypass SSL Certificate Pinning pour Arc Raiders
 * Version 4: Binary patching via xref scanning
 *
 * BoringSSL est statiquement compilé dans PioneerGame.exe sans symboles.
 * On trouve les fonctions de vérification SSL par:
 * 1. Localiser les strings d'erreur BoringSSL en mémoire
 * 2. Scanner le code pour les instructions LEA qui référencent ces strings
 * 3. Remonter au début de la fonction
 * 4. Patcher pour retourner ssl_verify_ok (0)
 */

"use strict";

var hookCount = 0;
var patchCount = 0;
var foundStringAddrs = [];

// === PHASE 1: Hooks système (SChannel/WinAPI) ===
function hookSystemSSL() {
    try {
        var addr = Module.findExportByName("crypt32.dll", "CertVerifyCertificateChainPolicy");
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function(args) { this.pStatus = args[3]; },
                onLeave: function(retval) {
                    retval.replace(1);
                    if (this.pStatus && !this.pStatus.isNull()) {
                        try { this.pStatus.add(4).writeU32(0); } catch(e) {}
                    }
                }
            });
            hookCount++;
            console.log("[+] Hooked CertVerifyCertificateChainPolicy");
        }
    } catch(e) {}

    try {
        var addr2 = Module.findExportByName("crypt32.dll", "CertGetCertificateChain");
        if (addr2) {
            Interceptor.attach(addr2, {
                onLeave: function(retval) { retval.replace(1); }
            });
            hookCount++;
            console.log("[+] Hooked CertGetCertificateChain");
        }
    } catch(e) {}
}

// === PHASE 2: Monitor réseau ===
function hookNetwork() {
    try {
        var getaddrinfo = Module.findExportByName("ws2_32.dll", "getaddrinfo");
        if (getaddrinfo) {
            Interceptor.attach(getaddrinfo, {
                onEnter: function(args) {
                    var h = args[0].readUtf8String();
                    if (h && (h.indexOf("es-pio") !== -1 || h.indexOf("embark") !== -1))
                        console.log("[NET] DNS: " + h);
                }
            });
            hookCount++;
        }
    } catch(e) {}

    try {
        var connect = Module.findExportByName("ws2_32.dll", "connect");
        if (connect) {
            Interceptor.attach(connect, {
                onEnter: function(args) {
                    try {
                        var sa = args[1];
                        var family = sa.readU16();
                        if (family === 2) {
                            var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                            var ip = sa.add(4).readU8() + "." + sa.add(5).readU8() + "." +
                                     sa.add(6).readU8() + "." + sa.add(7).readU8();
                            if (port === 443) console.log("[NET] connect " + ip + ":443");
                        }
                    } catch(e) {}
                }
            });
            hookCount++;
        }
    } catch(e) {}
}

// === PHASE 3: Trouver et patcher BoringSSL ===

function findBoringSSLStrings(mod) {
    console.log("[*] Scanning " + mod.name + " (" + (mod.size/1024/1024).toFixed(1) + " MB) for BoringSSL strings...");

    var targets = [
        "CERTIFICATE_VERIFY_FAILED",
        "certificate verify failed",
        "X509_verify_cert",
        "ssl_verify_peer_cert",
        "handshake.cc",
        "ssl_x509.cc",
        "ssl_cert.cc"
    ];

    var promises = [];
    targets.forEach(function(str) {
        var pattern = "";
        for (var i = 0; i < str.length; i++) {
            pattern += str.charCodeAt(i).toString(16).padStart(2, "0") + " ";
        }
        pattern = pattern.trim();

        try {
            Memory.scan(mod.base, mod.size, pattern, {
                onMatch: function(address, size) {
                    foundStringAddrs.push({ str: str, addr: address });
                    console.log("[+] Found '" + str + "' @ " + address);
                },
                onComplete: function() {}
            });
        } catch(e) {}
    });

    // Aussi chercher "boringssl" pour confirmer
    try {
        Memory.scan(mod.base, mod.size, "62 6f 72 69 6e 67 73 73 6c", {
            onMatch: function(addr) { console.log("[+] BoringSSL confirmed @ " + addr); },
            onComplete: function() {}
        });
    } catch(e) {}
}

function scanXrefsAndPatch(mod) {
    console.log("\n[*] === XREF SCANNING ===");
    console.log("[*] Found " + foundStringAddrs.length + " target strings");

    if (foundStringAddrs.length === 0) {
        console.log("[!] No BoringSSL strings found - trying error code approach...");
        scanErrorCodeAndPatch(mod);
        return;
    }

    // Pour chaque string trouvée, chercher les instructions LEA qui la référencent
    // LEA reg, [rip+disp32] en x64:
    // [REX prefix 48/4C] [8D] [ModRM: 00_reg_101] [disp32 LE]
    // Total: 7 bytes

    var textBase = mod.base;
    var textSize = mod.size;

    // On lit toute la section .text en mémoire pour scanner plus vite
    console.log("[*] Reading " + (textSize/1024/1024).toFixed(1) + " MB of code...");

    var xrefs = [];

    foundStringAddrs.forEach(function(target) {
        if (target.str !== "CERTIFICATE_VERIFY_FAILED" &&
            target.str !== "certificate verify failed" &&
            target.str !== "ssl_verify_peer_cert" &&
            target.str !== "handshake.cc" &&
            target.str !== "ssl_x509.cc") return;

        var targetAddr = target.addr;
        console.log("[*] Scanning xrefs for '" + target.str + "' @ " + targetAddr + "...");

        // Scanner par blocs de 4MB pour éviter les timeouts
        var blockSize = 4 * 1024 * 1024;
        var offset = 0;

        while (offset < textSize) {
            var chunkSize = Math.min(blockSize, textSize - offset);
            var chunkBase = textBase.add(offset);

            try {
                var buf = chunkBase.readByteArray(chunkSize);
                if (!buf) { offset += chunkSize; continue; }

                var view = new Uint8Array(buf);

                for (var i = 0; i < view.length - 7; i++) {
                    // Check for LEA pattern: [48|4C] 8D [05|0D|15|1D|2D|35|3D] [disp32]
                    var b0 = view[i];
                    if (b0 !== 0x48 && b0 !== 0x4C) continue;
                    if (view[i+1] !== 0x8D) continue;

                    var modrm = view[i+2];
                    // mod=00, r/m=101 -> low bits: xx_xxx_101
                    if ((modrm & 0xC7) !== 0x05) continue;

                    // Read disp32 (little-endian, signed)
                    var d = view[i+3] | (view[i+4] << 8) | (view[i+5] << 16) | (view[i+6] << 24);
                    if (d > 0x7FFFFFFF) d -= 0x100000000; // sign extend

                    // LEA is at chunkBase+i, instruction length=7
                    var leaAddr = chunkBase.add(i);
                    var resolvedAddr = leaAddr.add(7).add(d);

                    if (resolvedAddr.equals(targetAddr)) {
                        console.log("[+] XREF FOUND! LEA @ " + leaAddr + " -> '" + target.str + "'");
                        xrefs.push({ leaAddr: leaAddr, targetStr: target.str });
                    }
                }
            } catch(e) {
                // Skip unreadable pages
            }

            offset += chunkSize;
        }
    });

    console.log("[*] Found " + xrefs.length + " xrefs total");

    if (xrefs.length === 0) {
        console.log("[!] No xrefs found via LEA scan - trying error code approach...");
        scanErrorCodeAndPatch(mod);
        return;
    }

    // Pour chaque xref, remonter au début de la fonction et la patcher
    xrefs.forEach(function(xref, idx) {
        patchFunctionAtXref(xref.leaAddr, xref.targetStr, idx);
    });
}

function patchFunctionAtXref(leaAddr, strName, idx) {
    console.log("[*] Patching function containing xref #" + idx + " ('" + strName + "')...");

    // Remonter depuis l'instruction LEA pour trouver le début de la fonction
    // Les fonctions MSVC x64 commencent typiquement par:
    // - 48 89 xx xx  (mov [rsp+??], reg)  - sauvegarde de registres
    // - 55           (push rbp)
    // - 41 5x        (push r12-r15)
    // - 48 83 EC xx  (sub rsp, xx)
    // - 48 8B EC     (mov rbp, rsp)
    // - CC           (int3) - padding entre fonctions
    // - 90           (nop) - padding entre fonctions
    //
    // On cherche en remontant le premier CC ou un prologue typique

    var funcStart = null;
    var searchBack = 4096; // Chercher jusqu'à 4KB en arrière

    try {
        var buf = leaAddr.sub(searchBack).readByteArray(searchBack);
        var view = new Uint8Array(buf);

        // Chercher en remontant depuis la fin du buffer
        for (var i = view.length - 1; i >= 1; i--) {
            // CC (int3) suivi d'un byte non-CC = début de fonction après le padding
            if (view[i-1] === 0xCC && view[i] !== 0xCC) {
                funcStart = leaAddr.sub(searchBack).add(i);
                break;
            }
        }

        // Si pas trouvé avec CC, chercher des prologues connus
        if (!funcStart) {
            for (var i = view.length - 1; i >= 4; i--) {
                // sub rsp, imm8: 48 83 EC xx
                if (view[i] === 0x48 && view[i+1] === 0x83 && view[i+2] === 0xEC) {
                    // Vérifier si c'est précédé par des push ou mov
                    if (i > 0 && (view[i-1] === 0xCC || view[i-1] === 0x90 ||
                        view[i-1] === 0xC3)) {
                        funcStart = leaAddr.sub(searchBack).add(i);
                        break;
                    }
                }
            }
        }
    } catch(e) {
        console.log("[-] Error scanning back: " + e);
    }

    if (!funcStart) {
        console.log("[!] Could not find function start for xref #" + idx);
        // Fallback: patcher directement autour du LEA
        // On cherche un jump conditionnel (JZ/JNZ) près du LEA
        patchNearLea(leaAddr, strName);
        return;
    }

    console.log("[*] Function starts at " + funcStart + " (offset: -" + leaAddr.sub(funcStart).toInt32() + " from LEA)");

    // Stratégie de patch selon la string
    if (strName === "CERTIFICATE_VERIFY_FAILED" || strName === "certificate verify failed") {
        // C'est la fonction qui rapporte l'erreur de vérification
        // On veut la patcher pour retourner 0 (succès) ou 1 selon le contexte

        // Approche: NOP le jump conditionnel qui mène au code d'erreur
        // Chercher le JZ/JNZ avant le LEA (dans les ~100 bytes avant)
        patchConditionalJump(leaAddr, funcStart);
    } else {
        // Pour ssl_verify_peer_cert ou handshake.cc:
        // Patcher le début de la fonction pour retourner 0
        patchFunctionReturn(funcStart, 0);
    }
}

function patchConditionalJump(leaAddr, funcStart) {
    // Chercher les jumps conditionnels dans les 200 bytes avant le LEA
    // qui mènent au bloc de code contenant le LEA (le bloc d'erreur)
    var searchRange = Math.min(200, leaAddr.sub(funcStart).toInt32());

    try {
        var buf = leaAddr.sub(searchRange).readByteArray(searchRange);
        var view = new Uint8Array(buf);

        var patches = [];

        for (var i = view.length - 1; i >= 0; i--) {
            // JZ (74 xx) ou JNZ (75 xx) - short jump
            if ((view[i] === 0x74 || view[i] === 0x75) && i + 1 < view.length) {
                var jumpDest = i + 2 + (view[i+1] > 127 ? view[i+1] - 256 : view[i+1]);
                // Si le jump mène vers ou après le LEA
                if (jumpDest >= view.length - 20 || jumpDest <= i) {
                    patches.push({
                        offset: i,
                        type: view[i] === 0x74 ? "JZ" : "JNZ",
                        addr: leaAddr.sub(searchRange).add(i)
                    });
                }
            }
            // JZ (0F 84 xx xx xx xx) ou JNZ (0F 85 xx xx xx xx) - near jump
            if (view[i] === 0x0F && i + 5 < view.length &&
                (view[i+1] === 0x84 || view[i+1] === 0x85)) {
                patches.push({
                    offset: i,
                    type: view[i+1] === 0x84 ? "JZ-near" : "JNZ-near",
                    addr: leaAddr.sub(searchRange).add(i)
                });
            }
        }

        if (patches.length > 0) {
            // Prendre le dernier jump conditionnel avant le LEA (le plus proche)
            var patch = patches[0]; // Le premier trouvé en remontant = le plus proche
            console.log("[*] Found " + patch.type + " @ " + patch.addr + " before error LEA");

            // Inverser le jump ou le NOP
            if (patch.type === "JZ" || patch.type === "JNZ") {
                // NOP le jump (2 bytes: 90 90)
                try {
                    Memory.protect(patch.addr, 2, "rwx");
                    patch.addr.writeByteArray([0x90, 0x90]);
                    patchCount++;
                    console.log("[+] PATCHED: NOP'd " + patch.type + " @ " + patch.addr);
                } catch(e) {
                    console.log("[-] Failed to patch: " + e);
                }
            } else {
                // Near jump: NOP 6 bytes
                try {
                    Memory.protect(patch.addr, 6, "rwx");
                    patch.addr.writeByteArray([0x90, 0x90, 0x90, 0x90, 0x90, 0x90]);
                    patchCount++;
                    console.log("[+] PATCHED: NOP'd " + patch.type + " @ " + patch.addr);
                } catch(e) {
                    console.log("[-] Failed to patch: " + e);
                }
            }
        } else {
            console.log("[!] No conditional jumps found before error LEA");
            // Fallback: patcher la fonction entière pour retourner 0
            patchFunctionReturn(funcStart, 0);
        }
    } catch(e) {
        console.log("[-] Error in patchConditionalJump: " + e);
    }
}

function patchNearLea(leaAddr, strName) {
    // Fallback: chercher et NOP les jumps autour du LEA
    console.log("[*] Fallback: patching near LEA @ " + leaAddr);

    // Chercher dans les 64 bytes avant le LEA
    try {
        var buf = leaAddr.sub(64).readByteArray(64);
        var view = new Uint8Array(buf);

        for (var i = view.length - 1; i >= 0; i--) {
            if ((view[i] === 0x74 || view[i] === 0x75) && i + 1 < view.length) {
                var addr = leaAddr.sub(64).add(i);
                try {
                    Memory.protect(addr, 2, "rwx");
                    // Inverser: JZ->JNZ ou JNZ->JZ pour prendre l'autre branche
                    var newOp = view[i] === 0x74 ? 0x75 : 0x74;
                    addr.writeU8(newOp);
                    patchCount++;
                    console.log("[+] PATCHED: Inverted jump @ " + addr);
                    return;
                } catch(e) {}
            }
        }
    } catch(e) {}

    console.log("[!] Fallback patch failed");
}

function patchFunctionReturn(funcAddr, retValue) {
    // Patcher le début de la fonction pour:
    // xor eax, eax  (31 C0) - retourne 0
    // ret           (C3)
    // Total: 3 bytes

    // Ou pour retourner 1:
    // mov eax, 1    (B8 01 00 00 00)
    // ret           (C3)
    // Total: 6 bytes

    try {
        if (retValue === 0) {
            Memory.protect(funcAddr, 3, "rwx");
            funcAddr.writeByteArray([0x31, 0xC0, 0xC3]); // xor eax,eax; ret
        } else {
            Memory.protect(funcAddr, 6, "rwx");
            funcAddr.writeByteArray([0xB8, retValue & 0xFF, 0, 0, 0, 0xC3]); // mov eax,N; ret
        }
        patchCount++;
        console.log("[+] PATCHED: Function @ " + funcAddr + " now returns " + retValue);
    } catch(e) {
        console.log("[-] Failed to patch function: " + e);
    }
}

// === Approche alternative: scanner le code d'erreur 0x1000007d ===

function scanErrorCodeAndPatch(mod) {
    console.log("[*] Scanning for BoringSSL error code 0x1000007d...");

    // OPENSSL_PUT_ERROR(SSL, SSL_R_CERTIFICATE_VERIFY_FAILED)
    // SSL_R_CERTIFICATE_VERIFY_FAILED = 125 (0x7D)
    // ERR_pack(ERR_LIB_SSL, 0, 125) = 0x1000007D
    // En code MSVC x64, cela apparaît comme:
    // mov ecx/edx/r8d, 0x1000007D  ->  B9/BA/41B8 7D000010
    // ou
    // mov dword [rsp+xx], 0x1000007D  ->  C7 44 24 xx 7D 00 00 10

    var patterns = [
        // mov ecx, 0x1000007D
        { name: "mov ecx, ERR", hex: "B9 7D 00 00 10", size: 5 },
        // mov edx, 0x1000007D
        { name: "mov edx, ERR", hex: "BA 7D 00 00 10", size: 5 },
        // mov r8d, 0x1000007D
        { name: "mov r8d, ERR", hex: "41 B8 7D 00 00 10", size: 6 },
        // mov [rsp+x], 0x1000007D
        { name: "mov [rsp], ERR", hex: "7D 00 00 10", size: 4 },
        // Also search for the value 125 (0x7D) used in OPENSSL_PUT_ERROR as the reason code
        // with lib=SSL(0x14=20): actually in modern BoringSSL, error packing is different
    ];

    var allRefs = [];

    patterns.forEach(function(pat) {
        try {
            Memory.scan(mod.base, mod.size, pat.hex, {
                onMatch: function(address, size) {
                    // Vérifier que c'est dans une section exécutable
                    try {
                        var info = Process.findRangeByAddress(address);
                        if (info && info.protection.indexOf("x") !== -1) {
                            allRefs.push({ addr: address, pattern: pat.name });
                            console.log("[+] " + pat.name + " @ " + address + " (executable)");
                        }
                    } catch(e) {
                        allRefs.push({ addr: address, pattern: pat.name });
                    }
                },
                onComplete: function() {}
            });
        } catch(e) {}
    });

    // Traiter les résultats après un délai pour que les scans finissent
    setTimeout(function() {
        console.log("[*] Found " + allRefs.length + " error code references in executable memory");

        allRefs.forEach(function(ref, idx) {
            if (idx >= 10) return; // Limiter
            console.log("[*] Analyzing ref #" + idx + ": " + ref.pattern + " @ " + ref.addr);

            // Remonter pour trouver le début de la fonction
            var funcStart = findFunctionStart(ref.addr);
            if (funcStart) {
                console.log("[*] Function start: " + funcStart);
                // Ne pas patcher toutes les fonctions qui utilisent ce code d'erreur
                // Seulement celles liées à la vérification de certificat
                // Vérifier si la fonction contient aussi une référence aux strings SSL
                if (functionContainsSSLStrings(funcStart, ref.addr)) {
                    patchFunctionReturn(funcStart, 0);
                }
            }
        });

        printResults();
    }, 3000);
}

function findFunctionStart(codeAddr) {
    var searchBack = 4096;
    try {
        var startAddr = codeAddr.sub(searchBack);
        var buf = startAddr.readByteArray(searchBack);
        var view = new Uint8Array(buf);

        for (var i = view.length - 1; i >= 1; i--) {
            if (view[i-1] === 0xCC && view[i] !== 0xCC) {
                return startAddr.add(i);
            }
        }
    } catch(e) {}
    return null;
}

function functionContainsSSLStrings(funcStart, errorAddr) {
    // Vérifier si dans la plage funcStart..errorAddr+512 on trouve des refs SSL
    // Pour simplifier, on accepte toujours si la fonction est assez petite
    var funcSize = errorAddr.sub(funcStart).toInt32();
    return funcSize < 2048; // Fonctions SSL typiques < 2KB
}

// === PHASE 4: Approche complémentaire - Hooker les callbacks de vérification ===

function hookSSLCallbacks(mod) {
    console.log("[*] Scanning for SSL_CTX_set_custom_verify pattern...");

    // BoringSSL appelle ssl_verify_peer_cert pendant le handshake
    // Cette fonction appelle le callback custom si défini, sinon X509_verify_cert
    // On peut hooker l'appel CALL indirect qui invoque le callback

    // Chercher SSL_CTX_set_verify / SSL_set_custom_verify comme string
    // puis trouver la fonction qui les implémente

    // Pattern pour "SSL_CTX_set_custom_verify" dans BoringSSL:
    // La fonction fait: ctx->custom_verify_callback = callback;
    // En x64 MSVC: mov [rcx+offset], rdx  (48 89 51 xx)

    // Pas assez de contexte pour scanner par pattern - on se fie aux xrefs
}

// === PHASE 5: Approche nucléaire - Patcher les vérifications TLS alert ===

function patchTLSAlerts(mod) {
    console.log("[*] Scanning for TLS bad_certificate alert send...");

    // Quand la vérification échoue, BoringSSL envoie l'alerte TLS:
    // ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_BAD_CERTIFICATE)
    // SSL3_AL_FATAL = 2, SSL_AD_BAD_CERTIFICATE = 42 (0x2A)
    //
    // En code x64, on cherche les patterns qui chargent 2 et 42:
    // mov edx/r8d, 2 puis mov ecx/r9d, 42 (ou l'inverse selon calling convention)

    var alertPatterns = [
        // mov edx, 2; ... mov r8d, 0x2A (dans ~20 bytes)
        // Trop vague, on cherche des patterns plus spécifiques

        // Pattern: mov ecx/edx, 0x2A (bad_certificate)
        { name: "mov 0x2A (bad_cert)", hex: "BA 2A 00 00 00" },
        { name: "mov r8d 0x2A", hex: "41 B8 2A 00 00 00" },
    ];

    // Ce serait trop de faux positifs, on skip cette approche
}

// === Résultats ===
function printResults() {
    console.log("\n╔═══════════════════════════════════════╗");
    console.log("║     SSL BYPASS v4 - RESULTS           ║");
    console.log("╠═══════════════════════════════════════╣");
    console.log("║ Hooks:   " + hookCount);
    console.log("║ Patches: " + patchCount);
    console.log("║ Strings: " + foundStringAddrs.length);
    console.log("╚═══════════════════════════════════════╝");

    if (patchCount > 0) {
        console.log("\n[+] SSL verification functions patched!");
        console.log("[+] Certificate pinning should be bypassed.");
        console.log("[+] mitmproxy should now intercept HTTPS traffic.");
    } else if (hookCount > 2) {
        console.log("\n[*] System SSL hooked but BoringSSL not patched.");
        console.log("[*] Some connections may still be blocked.");
    } else {
        console.log("\n[!] Could not patch BoringSSL verify functions.");
        console.log("[!] Try running with the game already at the menu.");
    }
}

// === DÉMARRAGE ===

console.log("[*] SSL Bypass v4 - Binary xref patching for static BoringSSL");
console.log("[*] Target: PioneerGame.exe (Arc Raiders)\n");

console.log("[*] Phase 1: System SSL hooks...");
hookSystemSSL();

console.log("[*] Phase 2: Network monitoring...");
hookNetwork();

console.log("[*] Phase 3: BoringSSL binary analysis (deferred 5s)...\n");

// Attendre que le binaire soit complètement chargé en mémoire
setTimeout(function() {
    var mainModule = Process.enumerateModules()[0];
    console.log("[*] Main module: " + mainModule.name + " @ " + mainModule.base);
    console.log("[*] Size: " + (mainModule.size/1024/1024).toFixed(1) + " MB");

    // Phase 3a: Trouver les strings
    findBoringSSLStrings(mainModule);

    // Phase 3b: Après que les scans de strings soient terminés, scanner les xrefs
    setTimeout(function() {
        scanXrefsAndPatch(mainModule);

        // Phase 3c: Si les xrefs n'ont rien donné, essayer error code
        setTimeout(function() {
            if (patchCount === 0) {
                console.log("[*] No patches from xref scan, trying error code approach...");
                scanErrorCodeAndPatch(mainModule);
            } else {
                printResults();
            }
        }, 5000);
    }, 3000);

}, 5000);

// Monitor des nouveaux modules
var knownMods = {};
Process.enumerateModules().forEach(function(m) { knownMods[m.name] = true; });

var poll = setInterval(function() {
    Process.enumerateModules().forEach(function(m) {
        if (!knownMods[m.name]) {
            knownMods[m.name] = true;
            var n = m.name.toLowerCase();
            if (n.indexOf("ssl") !== -1 || n.indexOf("crypto") !== -1 ||
                n.indexOf("tls") !== -1 || n.indexOf("boring") !== -1) {
                console.log("[!] NEW MODULE: " + m.name);
            }
        }
    });
}, 2000);
setTimeout(function() { clearInterval(poll); }, 60000);

console.log("[*] Script loaded - analysis will begin in 5 seconds...\n");
