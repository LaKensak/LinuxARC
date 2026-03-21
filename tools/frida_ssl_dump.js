/**
 * Frida SSL traffic dumper pour Arc Raiders
 * Hooke SSL_write et SSL_read de BoringSSL (statiquement linké)
 * pour capturer le trafic HTTP déchiffré.
 *
 * Stratégie:
 * 1. Scanner la mémoire pour les signatures de SSL_write/SSL_read
 * 2. Hooker ces fonctions pour dumper le plaintext
 * 3. Parser le HTTP pour extraire matchId, manifestId, secretKey, etc.
 */

'use strict';

const KEYWORDS = [
    'match/start', 'match/status', 'gameserver/status',
    'manifestId', 'matchId', 'ticketId', 'secretKey',
    'routingToken', 'gameserver', 'squad/layout',
    'match/cancel', 'scenarios', 'party',
    'Authorization', 'Bearer',
];

const LOG_PREFIX = '[SSL-DUMP]';

// File output pour les données capturées
const capturedData = [];

function isInteresting(text) {
    const lower = text.toLowerCase();
    for (const kw of KEYWORDS) {
        if (lower.includes(kw.toLowerCase())) return true;
    }
    // Aussi détecter les requêtes HTTP
    if (text.startsWith('POST ') || text.startsWith('GET ') ||
        text.startsWith('HTTP/') || text.includes('"reason"')) return true;
    return false;
}

function tryParseAndLog(data, direction, ssl_ptr) {
    try {
        const text = data.readUtf8String();
        if (!text || text.length < 10) return;

        if (isInteresting(text)) {
            const ts = new Date().toISOString().substr(11, 12);
            send({
                type: 'ssl_data',
                direction: direction,
                timestamp: ts,
                ssl: ssl_ptr.toString(),
                data: text.substring(0, 5000),
                length: text.length,
            });

            // Afficher dans la console Frida
            console.log(`\n${'='.repeat(60)}`);
            console.log(`${LOG_PREFIX} [${ts}] ${direction} (${text.length} bytes)`);
            // Tronquer pour l'affichage console
            const lines = text.split('\n');
            for (let i = 0; i < Math.min(lines.length, 30); i++) {
                console.log(`  ${lines[i].substring(0, 120)}`);
            }
            if (lines.length > 30) {
                console.log(`  ... (${lines.length - 30} more lines)`);
            }
            console.log('='.repeat(60));
        }
    } catch (e) {
        // Pas du texte UTF-8, ignorer
    }
}

// === Méthode 1: Hooker les fonctions Winsock send/recv ===
// Plus fiable que trouver SSL_write dans BoringSSL statique
// Mais ne donne que le trafic chiffré...

// === Méthode 2: Pattern scanning pour BoringSSL SSL_write/SSL_read ===
// BoringSSL SSL_write signature: la fonction appelle ssl_write_buffer_flush
// On cherche des patterns connus dans le code x86_64

function findBoringSSLFunctions() {
    console.log(`${LOG_PREFIX} Scanning for BoringSSL functions...`);

    const module = Process.getModuleByName('PioneerGame.exe');
    const base = module.base;
    const size = module.size;

    console.log(`${LOG_PREFIX} Module: ${module.name} @ ${base} (${(size/1024/1024).toFixed(1)} MB)`);

    // Stratégie: chercher les strings d'erreur BoringSSL qui sont près des fonctions SSL
    // "OPENSSL_internal" est utilisé dans les assertions

    const errorStrings = [
        // Strings utilisées dans SSL_write
        'SSL_write',
        'SSL_read',
        'ssl_write_buffer_flush',
        'ssl_read_buffer',
        // Strings d'erreur
        'OPENSSL_internal',
        'ssl_lib.cc',
        'ssl_buffer.cc',
    ];

    const foundAddrs = {};

    for (const searchStr of errorStrings) {
        const results = Memory.scanSync(base, size, stringToPattern(searchStr));
        if (results.length > 0) {
            console.log(`${LOG_PREFIX} Found "${searchStr}" at ${results.length} locations`);
            foundAddrs[searchStr] = results.map(r => r.address);
        }
    }

    return foundAddrs;
}

function stringToPattern(str) {
    let pattern = '';
    for (let i = 0; i < str.length; i++) {
        if (i > 0) pattern += ' ';
        pattern += str.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return pattern;
}

// === Méthode 3: Hooker les fonctions de haut niveau ===
// HttpSendRequest, WinHTTP, etc.

function hookWinHTTP() {
    console.log(`${LOG_PREFIX} Hooking WinHTTP functions...`);

    const modules = ['winhttp.dll', 'wininet.dll'];
    let hooked = 0;

    for (const modName of modules) {
        try {
            const mod = Process.getModuleByName(modName);
            if (!mod) continue;

            // WinHttpSendRequest
            const sendReq = Module.findExportByName(modName, 'WinHttpSendRequest');
            if (sendReq) {
                Interceptor.attach(sendReq, {
                    onEnter(args) {
                        // args[1] = headers, args[3] = optional data
                        try {
                            const headers = args[1].readUtf16String();
                            if (headers && isInteresting(headers)) {
                                console.log(`${LOG_PREFIX} WinHttpSendRequest headers: ${headers.substring(0, 500)}`);
                            }
                        } catch(e) {}
                    }
                });
                hooked++;
                console.log(`${LOG_PREFIX} Hooked WinHttpSendRequest`);
            }

            // WinHttpReadData
            const readData = Module.findExportByName(modName, 'WinHttpReadData');
            if (readData) {
                Interceptor.attach(readData, {
                    onEnter(args) {
                        this.buf = args[1];
                        this.bufSize = args[2].toInt32();
                    },
                    onLeave(retval) {
                        if (this.buf && this.bufSize > 0) {
                            tryParseAndLog(this.buf, 'WinHTTP-READ', ptr(0));
                        }
                    }
                });
                hooked++;
                console.log(`${LOG_PREFIX} Hooked WinHttpReadData`);
            }

            // WinHttpWriteData
            const writeData = Module.findExportByName(modName, 'WinHttpWriteData');
            if (writeData) {
                Interceptor.attach(writeData, {
                    onEnter(args) {
                        const buf = args[1];
                        const len = args[2].toInt32();
                        if (len > 0 && len < 100000) {
                            tryParseAndLog(buf, 'WinHTTP-WRITE', ptr(0));
                        }
                    }
                });
                hooked++;
                console.log(`${LOG_PREFIX} Hooked WinHttpWriteData`);
            }
        } catch(e) {
            // Module non chargé
        }
    }

    return hooked;
}

// === Méthode 4: Hooker les fonctions crypto Windows (SChannel/SSPI) ===
function hookSchannel() {
    console.log(`${LOG_PREFIX} Hooking Schannel/SSPI...`);
    let hooked = 0;

    // EncryptMessage / DecryptMessage dans secur32.dll ou sspicli.dll
    for (const modName of ['secur32.dll', 'sspicli.dll']) {
        try {
            // EncryptMessage - capture le plaintext avant chiffrement
            const encrypt = Module.findExportByName(modName, 'EncryptMessage');
            if (encrypt) {
                Interceptor.attach(encrypt, {
                    onEnter(args) {
                        // args[1] = fQOP, args[2] = pMessage (SecBufferDesc)
                        try {
                            const pMessage = args[2];
                            if (pMessage.isNull()) return;

                            const cBuffers = pMessage.add(4).readU32();
                            const pBuffers = pMessage.add(8).readPointer();

                            for (let i = 0; i < cBuffers && i < 4; i++) {
                                const bufType = pBuffers.add(i * 16 + 4).readU32();
                                // SECBUFFER_DATA = 1
                                if (bufType === 1) {
                                    const cbBuffer = pBuffers.add(i * 16).readU32();
                                    const pvBuffer = pBuffers.add(i * 16 + 8).readPointer();
                                    if (cbBuffer > 0 && cbBuffer < 100000 && !pvBuffer.isNull()) {
                                        tryParseAndLog(pvBuffer, 'ENCRYPT(send)', ptr(0));
                                    }
                                }
                            }
                        } catch(e) {}
                    }
                });
                hooked++;
                console.log(`${LOG_PREFIX} Hooked EncryptMessage (${modName})`);
            }

            // DecryptMessage - capture le plaintext après déchiffrement
            const decrypt = Module.findExportByName(modName, 'DecryptMessage');
            if (decrypt) {
                Interceptor.attach(decrypt, {
                    onEnter(args) {
                        this.pMessage = args[1];
                    },
                    onLeave(retval) {
                        try {
                            if (!this.pMessage || this.pMessage.isNull()) return;
                            if (retval.toInt32() !== 0) return; // SEC_E_OK = 0

                            const cBuffers = this.pMessage.add(4).readU32();
                            const pBuffers = this.pMessage.add(8).readPointer();

                            for (let i = 0; i < cBuffers && i < 4; i++) {
                                const bufType = pBuffers.add(i * 16 + 4).readU32();
                                if (bufType === 1) {
                                    const cbBuffer = pBuffers.add(i * 16).readU32();
                                    const pvBuffer = pBuffers.add(i * 16 + 8).readPointer();
                                    if (cbBuffer > 0 && cbBuffer < 100000 && !pvBuffer.isNull()) {
                                        tryParseAndLog(pvBuffer, 'DECRYPT(recv)', ptr(0));
                                    }
                                }
                            }
                        } catch(e) {}
                    }
                });
                hooked++;
                console.log(`${LOG_PREFIX} Hooked DecryptMessage (${modName})`);
            }
        } catch(e) {}
    }

    return hooked;
}

// === Méthode 5: Hooker directement dans BoringSSL via pattern scan ===
function hookBoringSSLDirect() {
    console.log(`${LOG_PREFIX} Attempting direct BoringSSL hook via xrefs...`);

    const module = Process.getModuleByName('PioneerGame.exe');
    const base = module.base;
    const size = module.size;

    // Chercher la string "SSL_write" dans le binaire
    // Puis trouver les xrefs vers cette string
    // La fonction qui référence "SSL_write" EST SSL_write (pour le reporting d'erreur)

    const sslWriteStr = Memory.scanSync(base, size, stringToPattern('SSL_write'));
    const sslReadStr = Memory.scanSync(base, size, stringToPattern('SSL_read'));

    console.log(`${LOG_PREFIX} "SSL_write" found at ${sslWriteStr.length} locations`);
    console.log(`${LOG_PREFIX} "SSL_read" found at ${sslReadStr.length} locations`);

    // Pour BoringSSL, SSL_write et SSL_read ont des signatures connues:
    // SSL_write(SSL *ssl, const void *buf, int num) -> int
    // SSL_read(SSL *ssl, void *buf, int num) -> int

    // Chercher les patterns d'instructions qui forment ces fonctions
    // Pattern typique de début de fonction x64: push rbp; mov rbp, rsp ou sub rsp, XX

    // Alternative: chercher les appels à ces strings comme arguments de OPENSSL_PUT_ERROR
    // OPENSSL_PUT_ERROR(SSL, func_code, reason_code) utilise la string du nom de fonction

    for (const match of sslWriteStr) {
        const strAddr = match.address;
        console.log(`${LOG_PREFIX} SSL_write string at ${strAddr}`);

        // Chercher les LEA instructions qui chargent cette adresse
        // LEA reg, [rip + offset] = 48 8D xx xx xx xx xx
        // L'offset est relatif à RIP (fin de l'instruction)

        // Scanner les 50MB avant/après pour trouver les xrefs
        const scanStart = base;
        const scanSize = size;

        // Chercher toutes les instructions LEA qui pointent vers strAddr
        const strAddrVal = strAddr;
        let xrefs = [];

        // Scanner par blocs
        const blockSize = 1024 * 1024; // 1MB
        for (let offset = 0; offset < scanSize - 7; offset += blockSize) {
            const currentBlockSize = Math.min(blockSize + 7, scanSize - offset);
            const blockBase = base.add(offset);

            try {
                const block = blockBase.readByteArray(currentBlockSize);
                if (!block) continue;
                const bytes = new Uint8Array(block);

                for (let i = 0; i < bytes.length - 6; i++) {
                    // LEA avec 4-byte displacement: 48 8D 05/0D/15/1D/25/2D/35/3D
                    if (bytes[i] === 0x48 && bytes[i+1] === 0x8D) {
                        const modRM = bytes[i+2];
                        // modrm: mod=00, r/m=101 (RIP-relative) = XX 05
                        if ((modRM & 0xC7) === 0x05) {
                            const dispBytes = new Int32Array(new Uint8Array([
                                bytes[i+3], bytes[i+4], bytes[i+5], bytes[i+6]
                            ]).buffer);
                            const disp = dispBytes[0];
                            const instrEnd = blockBase.add(i + 7);
                            const target = instrEnd.add(disp);

                            if (target.equals(strAddr)) {
                                const instrAddr = blockBase.add(i);
                                xrefs.push(instrAddr);
                                console.log(`${LOG_PREFIX}   XREF to SSL_write string at ${instrAddr}`);
                            }
                        }
                    }
                }
            } catch(e) {}
        }

        if (xrefs.length > 0) {
            console.log(`${LOG_PREFIX} Found ${xrefs.length} xrefs to "SSL_write"`);

            // Pour chaque xref, remonter au début de la fonction
            for (const xref of xrefs) {
                // Remonter jusqu'à trouver le début de la fonction
                // Typiquement: cc cc cc ... (padding) suivi de push rbp / sub rsp
                let funcStart = null;
                for (let back = 0; back < 2000; back++) {
                    const addr = xref.sub(back);
                    try {
                        const b = addr.readU8();
                        const prev = addr.sub(1).readU8();
                        // Début de fonction: après du padding (CC ou 90)
                        if ((prev === 0xCC || prev === 0x90) && b !== 0xCC && b !== 0x90) {
                            funcStart = addr;
                            break;
                        }
                    } catch(e) { break; }
                }

                if (funcStart) {
                    console.log(`${LOG_PREFIX}   Potential SSL_write function at ${funcStart}`);

                    // Hooker la fonction
                    // SSL_write(SSL *ssl, const void *buf, int num)
                    // rcx = ssl, rdx = buf, r8 = num
                    try {
                        Interceptor.attach(funcStart, {
                            onEnter(args) {
                                const buf = args[1];
                                const num = args[2].toInt32();
                                if (num > 0 && num < 100000) {
                                    tryParseAndLog(buf, 'SSL_WRITE', args[0]);
                                }
                            }
                        });
                        console.log(`${LOG_PREFIX}   HOOKED SSL_write at ${funcStart}!`);
                    } catch(e) {
                        console.log(`${LOG_PREFIX}   Hook failed: ${e}`);
                    }
                }
            }
        }
    }

    // Même chose pour SSL_read
    for (const match of sslReadStr) {
        const strAddr = match.address;
        // Pour SSL_read, on hook onLeave pour lire le buffer après déchiffrement
        // Mais c'est plus complexe car le buffer est rempli par la fonction
        // On le fera dans une v2 si SSL_write fonctionne
        console.log(`${LOG_PREFIX} SSL_read string at ${strAddr} (hook later if SSL_write works)`);
    }
}

// === MAIN ===
setTimeout(function() {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`${LOG_PREFIX} Arc Raiders SSL Traffic Dumper`);
    console.log(`${'='.repeat(60)}\n`);

    // Méthode 1: WinHTTP (peu probable que le jeu l'utilise, mais facile)
    const winHttpHooks = hookWinHTTP();

    // Méthode 2: SChannel/SSPI (le jeu utilise BoringSSL, pas SChannel)
    // const schannelHooks = hookSchannel();
    // Ne pas hooker SChannel car BoringSSL n'utilise pas SChannel

    // Méthode 3: Hook direct BoringSSL
    hookBoringSSLDirect();

    console.log(`\n${LOG_PREFIX} Setup complete. Waiting for traffic...`);
    console.log(`${LOG_PREFIX} Play a match and this will capture the API calls.`);

}, 3000); // Attendre 3s que le jeu charge
