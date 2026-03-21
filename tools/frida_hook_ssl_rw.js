/**
 * Frida hook pour BoringSSL SSL_write/SSL_read dans PioneerGame.exe
 *
 * Stratégie simplifiée:
 * 1. Chercher "SSL_write\0" et "SSL_read\0" (null-terminated) dans le .rdata
 * 2. Trouver les LEA qui chargent ces strings (xrefs)
 * 3. Remonter au début de la fonction
 * 4. Hooker pour dumper le plaintext
 *
 * Optimisation: scan seulement les sections code (.text) pour les xrefs
 */

'use strict';

const LOG = '[HOOK]';

const KEYWORDS_MATCH = [
    'match', 'gameserver', 'manifest', 'ticket', 'secret',
    'routing', 'squad', 'scenario', 'party', 'clan',
    'Bearer', 'Authorization', '/v1/', '/v2/',
    'POST ', 'GET ', 'HTTP/', 'PUT ', 'PATCH ',
    '"reason"', '"matchId"', '"ticketId"',
    'secretKey', 'serverAddress', 'gameSession',
    'embark', 'es-pio', 'pioneer',
    'inventory', 'profile', 'heartbeat', 'feature-flag',
    'scenarioId', 'manifestId', 'allocation',
];

function isRelevant(text) {
    if (!text || text.length < 5) return false;
    const t = text.toLowerCase();
    return KEYWORDS_MATCH.some(k => t.includes(k.toLowerCase()));
}

function dumpBuffer(buf, len, direction) {
    try {
        if (len < 5 || len > 500000) return;
        const text = buf.readUtf8String(Math.min(len, 8000));
        if (!text) return;

        if (isRelevant(text)) {
            const ts = new Date().toISOString().substr(11, 12);
            console.log(`\n${'!'.repeat(60)}`);
            console.log(`${LOG} [${ts}] ${direction} (${len} bytes)`);

            // Afficher les premières lignes
            const preview = text.substring(0, 2000);
            console.log(preview);
            console.log('!'.repeat(60));

            // Envoyer au host Python
            send({
                type: 'ssl_traffic',
                direction: direction,
                timestamp: ts,
                length: len,
                data: text.substring(0, 10000),
            });
        }
    } catch(e) {
        // Pas du texte
    }
}

function findStringInModule(mod, searchStr) {
    // Chercher la string null-terminée
    const pattern = searchStr.split('').map(c =>
        c.charCodeAt(0).toString(16).padStart(2, '0')
    ).join(' ') + ' 00';

    return Memory.scanSync(mod.base, mod.size, pattern);
}

function findXrefs(mod, targetAddr) {
    /**
     * Trouver les instructions LEA rip-relative qui pointent vers targetAddr
     * Scan par blocs de 4MB pour la perf
     */
    const xrefs = [];
    const base = mod.base;
    const size = mod.size;
    const targetVal = targetAddr;

    const BLOCK = 4 * 1024 * 1024;

    for (let off = 0; off < size - 7; off += BLOCK) {
        const blockSize = Math.min(BLOCK + 7, size - off);
        const blockBase = base.add(off);

        let block;
        try {
            block = new Uint8Array(blockBase.readByteArray(blockSize));
        } catch(e) { continue; }

        for (let i = 0; i < block.length - 6; i++) {
            // REX.W LEA reg, [rip+disp32]
            // 48 8D [05|0D|15|1D|25|2D|35|3D] xx xx xx xx
            // Also 4C 8D for r8-r15
            if ((block[i] === 0x48 || block[i] === 0x4C) && block[i+1] === 0x8D) {
                const modrm = block[i+2];
                if ((modrm & 0xC7) === 0x05) { // mod=00, r/m=101 (RIP-relative)
                    // Read signed 32-bit displacement (little-endian)
                    const d0 = block[i+3], d1 = block[i+4], d2 = block[i+5], d3 = block[i+6];
                    let disp = d0 | (d1 << 8) | (d2 << 16) | (d3 << 24);
                    if (disp > 0x7FFFFFFF) disp -= 0x100000000; // sign extend

                    const instrEnd = blockBase.add(i + 7);
                    const target = instrEnd.add(disp);

                    if (target.equals(targetVal)) {
                        xrefs.push(blockBase.add(i));
                    }
                }
            }
        }
    }

    return xrefs;
}

function findFunctionStart(addr) {
    /**
     * Remonter depuis addr pour trouver le début de la fonction.
     * Cherche le pattern: CC/90 padding suivi d'un prologue
     */
    for (let back = 1; back < 4000; back++) {
        try {
            const a = addr.sub(back);
            const prev = a.sub(1).readU8();
            const curr = a.readU8();

            // Après du padding CC/90, le premier octet non-CC/90 est le début
            if ((prev === 0xCC || prev === 0x90 || prev === 0x00) &&
                curr !== 0xCC && curr !== 0x90 && curr !== 0x00) {
                // Vérifier que c'est un prologue valide
                // Common: 48 89 (mov), 55 (push rbp), 40 55 (push rbp), 48 83 EC (sub rsp)
                // 56 (push rsi), 57 (push rdi), 41 (REX.B prefix)
                if (curr === 0x48 || curr === 0x55 || curr === 0x40 ||
                    curr === 0x56 || curr === 0x57 || curr === 0x41 ||
                    curr === 0x53 || curr === 0x44 || curr === 0x45) {
                    return a;
                }
            }
        } catch(e) { break; }
    }
    return null;
}

// === MAIN ===

function findMainModule() {
    // Essayer plusieurs noms possibles
    const names = [
        'PioneerGame-Win64-Shipping.exe',
        'PioneerGame.exe',
        'ArcRaiders-Win64-Shipping.exe',
        'ArcRaiders.exe',
    ];
    for (const name of names) {
        try {
            const m = Process.getModuleByName(name);
            if (m) return m;
        } catch(e) {}
    }
    // Fallback: le premier module (le main exe)
    return Process.enumerateModules()[0];
}

function startHooking() {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`${LOG} Arc Raiders BoringSSL Hook`);
    console.log(`${'='.repeat(60)}`);

    const mod = findMainModule();
    console.log(`${LOG} Module: ${mod.name} @ ${mod.base} size=${(mod.size/1024/1024).toFixed(0)}MB`);

    // Étape 1: Trouver les strings SSL_write et SSL_read
    console.log(`${LOG} Searching for SSL function name strings...`);

    const sslWriteMatches = findStringInModule(mod, 'SSL_write');
    const sslReadMatches = findStringInModule(mod, 'SSL_read');

    console.log(`${LOG} "SSL_write\\0" found at ${sslWriteMatches.length} locations`);
    console.log(`${LOG} "SSL_read\\0" found at ${sslReadMatches.length} locations`);

    if (sslWriteMatches.length === 0 && sslReadMatches.length === 0) {
        console.log(`${LOG} No BoringSSL strings found! Trying alternative patterns...`);

        // Alternative: chercher d'autres strings BoringSSL
        const altPatterns = [
            'ssl_lib.cc', 'ssl3_get_message', 'do_ssl3_write',
            'SSL_ERROR_', 'SSL_CTX_', 'BIO_write', 'BIO_read',
        ];
        for (const p of altPatterns) {
            const m = findStringInModule(mod, p);
            if (m.length > 0) {
                console.log(`${LOG}   "${p}" found at ${m.length} locations`);
            }
        }

        // Dernière tentative: hooker les fonctions WinSock pour au moins voir les connexions
        console.log(`${LOG} Falling back to Winsock hooks (encrypted traffic)...`);
        hookWinsock();
        return;
    }

    // Étape 2: Trouver les xrefs
    let sslWriteFunc = null;
    let sslReadFunc = null;

    for (const match of sslWriteMatches) {
        console.log(`${LOG} Scanning xrefs to SSL_write @ ${match.address}...`);
        const xrefs = findXrefs(mod, match.address);
        console.log(`${LOG}   Found ${xrefs.length} xrefs`);

        for (const xref of xrefs) {
            const funcStart = findFunctionStart(xref);
            if (funcStart) {
                console.log(`${LOG}   Function at ${funcStart} (xref at ${xref})`);

                // La vraie SSL_write a la string comme nom de fonction pour OPENSSL_PUT_ERROR
                // C'est typiquement la plus "externe" (appelée par le code utilisateur)
                // On prend la première trouvée
                if (!sslWriteFunc) {
                    sslWriteFunc = funcStart;
                }
            }
        }
    }

    for (const match of sslReadMatches) {
        console.log(`${LOG} Scanning xrefs to SSL_read @ ${match.address}...`);
        const xrefs = findXrefs(mod, match.address);
        console.log(`${LOG}   Found ${xrefs.length} xrefs`);

        for (const xref of xrefs) {
            const funcStart = findFunctionStart(xref);
            if (funcStart) {
                console.log(`${LOG}   Function at ${funcStart} (xref at ${xref})`);
                if (!sslReadFunc) {
                    sslReadFunc = funcStart;
                }
            }
        }
    }

    // Étape 3: Hooker
    if (sslWriteFunc) {
        try {
            // SSL_write(SSL *ssl, const void *buf, int num) -> int
            // Windows x64: rcx=ssl, rdx=buf, r8d=num
            Interceptor.attach(sslWriteFunc, {
                onEnter(args) {
                    const buf = args[1];
                    const num = args[2].toInt32();
                    dumpBuffer(buf, num, 'WRITE>>>');
                }
            });
            console.log(`${LOG} HOOKED SSL_write at ${sslWriteFunc}`);
        } catch(e) {
            console.log(`${LOG} Failed to hook SSL_write: ${e}`);
        }
    }

    if (sslReadFunc) {
        try {
            // SSL_read(SSL *ssl, void *buf, int num) -> int
            Interceptor.attach(sslReadFunc, {
                onEnter(args) {
                    this.buf = args[1];
                },
                onLeave(retval) {
                    const bytesRead = retval.toInt32();
                    if (bytesRead > 0) {
                        dumpBuffer(this.buf, bytesRead, 'READ<<<');
                    }
                }
            });
            console.log(`${LOG} HOOKED SSL_read at ${sslReadFunc}`);
        } catch(e) {
            console.log(`${LOG} Failed to hook SSL_read: ${e}`);
        }
    }

    if (!sslWriteFunc && !sslReadFunc) {
        console.log(`${LOG} Could not find SSL functions. Falling back to Winsock.`);
        hookWinsock();
    }

    console.log(`\n${LOG} Setup complete. Queue for a match to capture traffic.`);

}

// Attendre que le jeu charge, puis tenter les hooks
// En mode SPAWN, le script est injecté avant resume - on laisse plus de temps
setTimeout(function() {
    try {
        startHooking();
    } catch(e) {
        console.log(`${LOG} First attempt failed: ${e}`);
        console.log(`${LOG} Retrying in 10s...`);
        setTimeout(function() {
            try {
                startHooking();
            } catch(e2) {
                console.log(`${LOG} Second attempt failed: ${e2}`);
                console.log(`${LOG} Falling back to Winsock only`);
                hookWinsock();
            }
        }, 10000);
    }
}, 5000); // 5s pour laisser le jeu charger

function hookWinsock() {
    // Hooker send/recv au niveau socket pour au moins voir les tailles
    // et détecter les connexions
    const ws2 = 'ws2_32.dll';

    const send = Module.findExportByName(ws2, 'send');
    const recv = Module.findExportByName(ws2, 'recv');
    const WSASend = Module.findExportByName(ws2, 'WSASend');
    const WSARecv = Module.findExportByName(ws2, 'WSARecv');

    if (send) {
        Interceptor.attach(send, {
            onEnter(args) {
                const buf = args[1];
                const len = args[2].toInt32();
                if (len > 50 && len < 100000) {
                    // Vérifier si c'est du HTTP en clair (non chiffré)
                    try {
                        const preview = buf.readUtf8String(Math.min(len, 100));
                        if (preview && (preview.startsWith('GET ') || preview.startsWith('POST ') ||
                            preview.startsWith('PUT ') || preview.includes('HTTP/'))) {
                            console.log(`${LOG} [send] PLAINTEXT HTTP detected (${len} bytes):`);
                            dumpBuffer(buf, len, 'SEND-PLAIN');
                        }
                    } catch(e) {}
                }
            }
        });
    }

    if (recv) {
        Interceptor.attach(recv, {
            onEnter(args) {
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave(retval) {
                const bytesRead = retval.toInt32();
                if (bytesRead > 50) {
                    try {
                        const preview = this.buf.readUtf8String(Math.min(bytesRead, 100));
                        if (preview && (preview.startsWith('HTTP/') || preview.includes('"reason"'))) {
                            console.log(`${LOG} [recv] PLAINTEXT HTTP detected (${bytesRead} bytes):`);
                            dumpBuffer(this.buf, bytesRead, 'RECV-PLAIN');
                        }
                    } catch(e) {}
                }
            }
        });
    }

    console.log(`${LOG} Winsock hooks installed (plaintext HTTP detection)`);
}
