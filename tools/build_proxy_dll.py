"""
Build une proxy winhttp.dll pour Arc Raiders.
runtime.dll importe WINHTTP.dll -> on place notre DLL dans le dossier du jeu.

La proxy DLL:
1. Forwarde les appels WinHTTP vers la vraie DLL (system32)
2. Attend que Cerebro.dll soit chargé (contient BoringSSL)
3. Scanne les strings BoringSSL et patche la vérification SSL
4. Log le trafic HTTP via WinHttpSendRequest/WinHttpReceiveResponse

Build avec MinGW: gcc -shared -o winhttp.dll proxy_winhttp.c -lwinhttp
"""

import os
import subprocess
import shutil

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
BUILD_DIR = os.path.join(PROJECT_DIR, "build")
GAME_DIR = r"F:\SteamLibrary\steamapps\common\Arc Raiders\PioneerGame\Binaries\Win64"
os.makedirs(BUILD_DIR, exist_ok=True)

C_SOURCE = r"""
/*
 * Proxy winhttp.dll pour Arc Raiders
 * Forwarde tous les exports vers la vraie DLL.
 * Patche BoringSSL dans Cerebro.dll pour bypass cert pinning.
 * Log le trafic SSL dechiffre.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>

#pragma comment(lib, "psapi")

/* ===== Logging ===== */
static FILE* g_log = NULL;
static CRITICAL_SECTION g_cs;

static void logInit(HINSTANCE hDll) {
    char path[MAX_PATH];
    GetModuleFileNameA(hDll, path, MAX_PATH);
    char* s = strrchr(path, '\\');
    if (s) strcpy(s + 1, "ssl_proxy.log");
    else strcpy(path, "ssl_proxy.log");
    g_log = fopen(path, "a");
    InitializeCriticalSection(&g_cs);
}

static void LOG(const char* fmt, ...) {
    if (!g_log) return;
    va_list a;
    va_start(a, fmt);
    EnterCriticalSection(&g_cs);
    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d.%03d] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    vfprintf(g_log, fmt, a);
    fprintf(g_log, "\n");
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
    va_end(a);
}

/* ===== Real winhttp.dll forwarding ===== */
static HMODULE g_real = NULL;

/* Macro pour definir un pointeur de fonction et le resoudre */
#define RESOLVE(name) \
    static typeof(name)* p_##name = NULL; \
    if (!p_##name && g_real) p_##name = (typeof(name)*)GetProcAddress(g_real, #name);

/*
 * On ne peut pas utiliser typeof() avec MinGW pour les fonctions WinHTTP
 * car les prototypes sont complexes. On utilise des typedefs manuels.
 */

/* Pointeurs vers les fonctions reelles */
typedef HINTERNET (WINAPI *t_WinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *t_WinHttpConnect)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET (WINAPI *t_WinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL (WINAPI *t_WinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *t_WinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL (WINAPI *t_WinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *t_WinHttpQueryHeaders)(HINTERNET,DWORD,LPCWSTR,LPVOID,LPDWORD,LPDWORD);
typedef BOOL (WINAPI *t_WinHttpCloseHandle)(HINTERNET);
typedef BOOL (WINAPI *t_WinHttpSetOption)(HINTERNET,DWORD,LPVOID,DWORD);
typedef BOOL (WINAPI *t_WinHttpQueryOption)(HINTERNET,DWORD,LPVOID,LPDWORD);
typedef BOOL (WINAPI *t_WinHttpAddRequestHeaders)(HINTERNET,LPCWSTR,DWORD,DWORD);
typedef BOOL (WINAPI *t_WinHttpSetCredentials)(HINTERNET,DWORD,DWORD,LPCWSTR,LPCWSTR,LPVOID);
typedef BOOL (WINAPI *t_WinHttpSetTimeouts)(HINTERNET,int,int,int,int);
typedef DWORD (WINAPI *t_WinHttpSetStatusCallback)(HINTERNET,WINHTTP_STATUS_CALLBACK,DWORD,DWORD_PTR);
typedef BOOL (WINAPI *t_WinHttpWriteData)(HINTERNET,LPCVOID,DWORD,LPDWORD);
typedef BOOL (WINAPI *t_WinHttpQueryDataAvailable)(HINTERNET,LPDWORD);
typedef BOOL (WINAPI *t_WinHttpGetProxyForUrl)(HINTERNET,LPCWSTR,WINHTTP_AUTOPROXY_OPTIONS*,WINHTTP_PROXY_INFO*);
typedef BOOL (WINAPI *t_WinHttpGetDefaultProxyConfiguration)(WINHTTP_PROXY_INFO*);
typedef BOOL (WINAPI *t_WinHttpGetIEProxyConfigForCurrentUser)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG*);
typedef BOOL (WINAPI *t_WinHttpCrackUrl)(LPCWSTR,DWORD,DWORD,LPURL_COMPONENTS);
typedef BOOL (WINAPI *t_WinHttpCreateUrl)(LPURL_COMPONENTS,DWORD,LPWSTR,LPDWORD);
typedef BOOL (WINAPI *t_WinHttpCheckPlatform)(void);
typedef BOOL (WINAPI *t_WinHttpDetectAutoProxyConfigUrl)(DWORD,LPWSTR*);
typedef HINTERNET (WINAPI *t_WinHttpFreeProxyResult)(void*);

static t_WinHttpOpen                            r_WinHttpOpen;
static t_WinHttpConnect                         r_WinHttpConnect;
static t_WinHttpOpenRequest                     r_WinHttpOpenRequest;
static t_WinHttpSendRequest                     r_WinHttpSendRequest;
static t_WinHttpReceiveResponse                 r_WinHttpReceiveResponse;
static t_WinHttpReadData                        r_WinHttpReadData;
static t_WinHttpQueryHeaders                    r_WinHttpQueryHeaders;
static t_WinHttpCloseHandle                     r_WinHttpCloseHandle;
static t_WinHttpSetOption                       r_WinHttpSetOption;
static t_WinHttpQueryOption                     r_WinHttpQueryOption;
static t_WinHttpAddRequestHeaders               r_WinHttpAddRequestHeaders;
static t_WinHttpSetCredentials                  r_WinHttpSetCredentials;
static t_WinHttpSetTimeouts                     r_WinHttpSetTimeouts;
static t_WinHttpSetStatusCallback               r_WinHttpSetStatusCallback;
static t_WinHttpWriteData                       r_WinHttpWriteData;
static t_WinHttpQueryDataAvailable              r_WinHttpQueryDataAvailable;
static t_WinHttpCrackUrl                        r_WinHttpCrackUrl;
static t_WinHttpCreateUrl                       r_WinHttpCreateUrl;
static t_WinHttpCheckPlatform                   r_WinHttpCheckPlatform;

static void resolveAll(void) {
    if (!g_real) return;
    #define R(n) r_##n = (t_##n)GetProcAddress(g_real, #n)
    R(WinHttpOpen);
    R(WinHttpConnect);
    R(WinHttpOpenRequest);
    R(WinHttpSendRequest);
    R(WinHttpReceiveResponse);
    R(WinHttpReadData);
    R(WinHttpQueryHeaders);
    R(WinHttpCloseHandle);
    R(WinHttpSetOption);
    R(WinHttpQueryOption);
    R(WinHttpAddRequestHeaders);
    R(WinHttpSetCredentials);
    R(WinHttpSetTimeouts);
    R(WinHttpSetStatusCallback);
    R(WinHttpWriteData);
    R(WinHttpQueryDataAvailable);
    R(WinHttpCrackUrl);
    R(WinHttpCreateUrl);
    R(WinHttpCheckPlatform);
    #undef R
}

/* ===== Exported functions (proxy + logging) ===== */

__declspec(dllexport) HINTERNET WINAPI xWinHttpOpen(
    LPCWSTR pszAgentW, DWORD dwAccessType,
    LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags)
{
    LOG("WinHttpOpen agent=%ls", pszAgentW ? pszAgentW : L"(null)");
    return r_WinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
}

__declspec(dllexport) HINTERNET WINAPI xWinHttpConnect(
    HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved)
{
    LOG("WinHttpConnect server=%ls port=%d", pswzServerName ? pswzServerName : L"(null)", nServerPort);
    return r_WinHttpConnect(hSession, pswzServerName, nServerPort, dwReserved);
}

__declspec(dllexport) HINTERNET WINAPI xWinHttpOpenRequest(
    HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName,
    LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags)
{
    LOG("WinHttpOpenRequest %ls %ls", pwszVerb ? pwszVerb : L"GET",
        pwszObjectName ? pwszObjectName : L"/");
    return r_WinHttpOpenRequest(hConnect, pwszVerb, pwszObjectName, pwszVersion,
                                 pwszReferrer, ppwszAcceptTypes, dwFlags);
}

__declspec(dllexport) BOOL WINAPI xWinHttpSendRequest(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength,
    LPVOID lpOptional, DWORD dwOptionalLength,
    DWORD dwTotalLength, DWORD_PTR dwContext)
{
    if (lpOptional && dwOptionalLength > 0 && dwOptionalLength < 100000) {
        /* Log le body de la requete */
        char preview[2048];
        DWORD copyLen = dwOptionalLength < sizeof(preview)-1 ? dwOptionalLength : sizeof(preview)-1;
        memcpy(preview, lpOptional, copyLen);
        preview[copyLen] = 0;
        LOG("WinHttpSendRequest body(%d bytes): %.500s", dwOptionalLength, preview);
    }
    return r_WinHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength,
                                 lpOptional, dwOptionalLength, dwTotalLength, dwContext);
}

__declspec(dllexport) BOOL WINAPI xWinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved)
{
    return r_WinHttpReceiveResponse(hRequest, lpReserved);
}

__declspec(dllexport) BOOL WINAPI xWinHttpReadData(
    HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
    BOOL ret = r_WinHttpReadData(hRequest, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
    if (ret && lpdwNumberOfBytesRead && *lpdwNumberOfBytesRead > 0) {
        DWORD n = *lpdwNumberOfBytesRead;
        /* Chercher des keywords dans la reponse */
        char* buf = (char*)lpBuffer;
        if (n > 10) {
            /* Quick check pour JSON interessant */
            int dominated = 0;
            const char* keys[] = {"matchId","manifestId","ticketId","secretKey",
                                  "serverAddress","gameSession","scenarioId",NULL};
            for (int i = 0; keys[i]; i++) {
                if (memmem(buf, n, keys[i], strlen(keys[i]))) {
                    dominated = 1;
                    break;
                }
            }
            if (dominated) {
                char preview[4096];
                DWORD copyLen = n < sizeof(preview)-1 ? n : sizeof(preview)-1;
                memcpy(preview, buf, copyLen);
                preview[copyLen] = 0;
                LOG("!!! INTERESTING RESPONSE (%d bytes): %.2000s", n, preview);
            }
        }
    }
    return ret;
}

__declspec(dllexport) BOOL WINAPI xWinHttpQueryHeaders(
    HINTERNET hRequest, DWORD dwInfoLevel, LPCWSTR pwszName,
    LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)
{
    return r_WinHttpQueryHeaders(hRequest, dwInfoLevel, pwszName, lpBuffer, lpdwBufferLength, lpdwIndex);
}

__declspec(dllexport) BOOL WINAPI xWinHttpCloseHandle(HINTERNET hInternet)
{
    return r_WinHttpCloseHandle(hInternet);
}

__declspec(dllexport) BOOL WINAPI xWinHttpSetOption(
    HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength)
{
    return r_WinHttpSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
}

__declspec(dllexport) BOOL WINAPI xWinHttpQueryOption(
    HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, LPDWORD lpdwBufferLength)
{
    return r_WinHttpQueryOption(hInternet, dwOption, lpBuffer, lpdwBufferLength);
}

__declspec(dllexport) BOOL WINAPI xWinHttpAddRequestHeaders(
    HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers)
{
    return r_WinHttpAddRequestHeaders(hRequest, lpszHeaders, dwHeadersLength, dwModifiers);
}

__declspec(dllexport) BOOL WINAPI xWinHttpSetCredentials(
    HINTERNET hRequest, DWORD AuthTargets, DWORD AuthScheme,
    LPCWSTR pwszUserName, LPCWSTR pwszPassword, LPVOID pAuthParams)
{
    return r_WinHttpSetCredentials(hRequest, AuthTargets, AuthScheme,
                                    pwszUserName, pwszPassword, pAuthParams);
}

__declspec(dllexport) BOOL WINAPI xWinHttpSetTimeouts(
    HINTERNET hInternet, int nResolveTimeout, int nConnectTimeout,
    int nSendTimeout, int nReceiveTimeout)
{
    return r_WinHttpSetTimeouts(hInternet, nResolveTimeout, nConnectTimeout,
                                 nSendTimeout, nReceiveTimeout);
}

__declspec(dllexport) WINHTTP_STATUS_CALLBACK WINAPI xWinHttpSetStatusCallback(
    HINTERNET hInternet, WINHTTP_STATUS_CALLBACK lpfnInternetCallback,
    DWORD dwNotificationFlags, DWORD_PTR dwReserved)
{
    return (WINHTTP_STATUS_CALLBACK)r_WinHttpSetStatusCallback(
        hInternet, lpfnInternetCallback, dwNotificationFlags, dwReserved);
}

__declspec(dllexport) BOOL WINAPI xWinHttpWriteData(
    HINTERNET hRequest, LPCVOID lpBuffer, DWORD dwNumberOfBytesToWrite, LPDWORD lpdwNumberOfBytesWritten)
{
    if (lpBuffer && dwNumberOfBytesToWrite > 0 && dwNumberOfBytesToWrite < 100000) {
        char preview[2048];
        DWORD copyLen = dwNumberOfBytesToWrite < sizeof(preview)-1 ? dwNumberOfBytesToWrite : sizeof(preview)-1;
        memcpy(preview, lpBuffer, copyLen);
        preview[copyLen] = 0;
        LOG("WinHttpWriteData (%d bytes): %.500s", dwNumberOfBytesToWrite, preview);
    }
    return r_WinHttpWriteData(hRequest, lpBuffer, dwNumberOfBytesToWrite, lpdwNumberOfBytesWritten);
}

__declspec(dllexport) BOOL WINAPI xWinHttpQueryDataAvailable(HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable)
{
    return r_WinHttpQueryDataAvailable(hRequest, lpdwNumberOfBytesAvailable);
}

__declspec(dllexport) BOOL WINAPI xWinHttpCrackUrl(
    LPCWSTR pwszUrl, DWORD dwUrlLength, DWORD dwFlags, LPURL_COMPONENTS lpUrlComponents)
{
    return r_WinHttpCrackUrl(pwszUrl, dwUrlLength, dwFlags, lpUrlComponents);
}

__declspec(dllexport) BOOL WINAPI xWinHttpCreateUrl(
    LPURL_COMPONENTS lpUrlComponents, DWORD dwFlags, LPWSTR pwszUrl, LPDWORD pdwUrlLength)
{
    return r_WinHttpCreateUrl(lpUrlComponents, dwFlags, pwszUrl, pdwUrlLength);
}

__declspec(dllexport) BOOL WINAPI xWinHttpCheckPlatform(void)
{
    return r_WinHttpCheckPlatform();
}

/* ===== Generic forwarder for any export not explicitly handled ===== */
/* MinGW uses the .def file for forwarding the rest */

/* ===== BoringSSL Patching ===== */

static int g_patches = 0;

static unsigned char* memfind(unsigned char* haystack, size_t hLen,
                               const char* needle, size_t nLen) {
    if (nLen > hLen) return NULL;
    for (size_t i = 0; i <= hLen - nLen; i++) {
        if (memcmp(haystack + i, needle, nLen) == 0)
            return haystack + i;
    }
    return NULL;
}

static void* memmem_local(const void* h, size_t hlen, const void* n, size_t nlen) {
    if (!nlen) return (void*)h;
    if (nlen > hlen) return NULL;
    const unsigned char* hp = (const unsigned char*)h;
    const unsigned char* np = (const unsigned char*)n;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (hp[i] == np[0] && memcmp(hp + i, np, nlen) == 0)
            return (void*)(hp + i);
    }
    return NULL;
}
#define memmem memmem_local

static unsigned char* findFuncStart(unsigned char* addr, size_t maxBack) {
    for (size_t i = 1; i < maxBack; i++) {
        unsigned char prev = *(addr - i);
        unsigned char curr = *(addr - i + 1);
        if ((prev == 0xCC || prev == 0x90) &&
            curr != 0xCC && curr != 0x90 && curr != 0x00) {
            /* Verifier que c'est un prologue x64 valide */
            if (curr == 0x48 || curr == 0x55 || curr == 0x40 ||
                curr == 0x56 || curr == 0x57 || curr == 0x41 ||
                curr == 0x53 || curr == 0x44 || curr == 0x45) {
                return addr - i + 1;
            }
        }
    }
    return NULL;
}

static void patchRetZero(unsigned char* func) {
    DWORD old;
    if (VirtualProtect(func, 3, PAGE_EXECUTE_READWRITE, &old)) {
        func[0] = 0x31; /* xor eax, eax */
        func[1] = 0xC0;
        func[2] = 0xC3; /* ret */
        VirtualProtect(func, 3, old, &old);
        g_patches++;
        LOG("PATCHED %p -> xor eax,eax; ret", func);
    } else {
        LOG("VirtualProtect failed for %p: %d", func, GetLastError());
    }
}

static void patchBoringSSL(HMODULE hMod) {
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi))) {
        LOG("GetModuleInformation failed: %d", GetLastError());
        return;
    }

    unsigned char* base = (unsigned char*)mi.lpBaseOfDll;
    size_t modSize = mi.SizeOfImage;
    LOG("Scanning %p, %zu MB for BoringSSL strings...", base, modSize / (1024*1024));

    /* Strings a chercher - fonctions de verification */
    const char* targets[] = {
        "ssl_verify_peer_cert",
        "X509_verify_cert",
        "CERTIFICATE_VERIFY_FAILED",
        "certificate verify failed",
        "handshake.cc",
        "ssl_x509.cc",
        "ssl_cert.cc",
        NULL
    };

    /* Phase 1: trouver les strings dans le module */
    typedef struct { unsigned char* addr; const char* name; } StringMatch;
    StringMatch matches[64];
    int matchCount = 0;

    for (int t = 0; targets[t] && matchCount < 60; t++) {
        size_t slen = strlen(targets[t]);
        unsigned char* pos = base;
        while (pos < base + modSize - slen && matchCount < 60) {
            unsigned char* found = memfind(pos, (base + modSize) - pos, targets[t], slen);
            if (!found) break;
            matches[matchCount].addr = found;
            matches[matchCount].name = targets[t];
            matchCount++;
            LOG("Found '%s' @ %p", targets[t], found);
            pos = found + 1;
        }
    }

    LOG("Phase 1: %d strings found", matchCount);
    if (matchCount == 0) {
        LOG("No BoringSSL strings found in module!");
        return;
    }

    /* Phase 2: scanner les LEA rip-relative qui pointent vers ces strings */
    LOG("Phase 2: scanning for LEA xrefs...");

    /* On scanne par blocs de 4MB pour la perf */
    size_t BLOCK = 4 * 1024 * 1024;
    int xrefCount = 0;

    for (size_t off = 0; off < modSize - 7; off += BLOCK) {
        size_t blockSz = BLOCK + 7;
        if (off + blockSz > modSize) blockSz = modSize - off;

        unsigned char* block = base + off;

        /* Verifier que la region est lisible */
        MEMORY_BASIC_INFORMATION mbi2;
        if (VirtualQuery(block, &mbi2, sizeof(mbi2)) == 0) continue;
        if (!(mbi2.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE)))
            continue;

        for (size_t i = 0; i < blockSz - 6; i++) {
            /* REX.W LEA reg, [rip+disp32]: 48/4C 8D [modrm] [disp32] */
            if ((block[i] != 0x48 && block[i] != 0x4C) || block[i+1] != 0x8D)
                continue;
            if ((block[i+2] & 0xC7) != 0x05) continue;

            int32_t disp;
            memcpy(&disp, &block[i+3], 4);
            unsigned char* resolved = block + i + 7 + disp;

            /* Verifier si ca pointe vers une de nos strings */
            for (int m = 0; m < matchCount; m++) {
                if (resolved == matches[m].addr) {
                    unsigned char* leaAddr = block + i;
                    LOG("XREF: LEA @ %p -> '%s'", leaAddr, matches[m].name);
                    xrefCount++;

                    /* Remonter au debut de la fonction */
                    unsigned char* funcStart = findFuncStart(leaAddr, 4096);
                    if (!funcStart) {
                        LOG("  Could not find function start");
                        continue;
                    }
                    LOG("  Function @ %p", funcStart);

                    /* Patcher selon la string */
                    if (strcmp(matches[m].name, "ssl_verify_peer_cert") == 0 ||
                        strcmp(matches[m].name, "X509_verify_cert") == 0) {
                        patchRetZero(funcStart);
                    }
                    else if (strstr(matches[m].name, "VERIFY_FAILED") ||
                             strstr(matches[m].name, "verify failed")) {
                        /* NOP le jump conditionnel avant le LEA d'erreur */
                        for (int back = 1; back < 200 && leaAddr - back > funcStart; back++) {
                            unsigned char* c = leaAddr - back;
                            if (c[0] == 0x0F && (c[1] == 0x84 || c[1] == 0x85)) {
                                DWORD old;
                                if (VirtualProtect(c, 6, PAGE_EXECUTE_READWRITE, &old)) {
                                    memset(c, 0x90, 6);
                                    VirtualProtect(c, 6, old, &old);
                                    g_patches++;
                                    LOG("NOP'd near jump @ %p", c);
                                }
                                break;
                            }
                            if (c[0] == 0x74 || c[0] == 0x75) {
                                DWORD old;
                                if (VirtualProtect(c, 2, PAGE_EXECUTE_READWRITE, &old)) {
                                    c[0] = 0x90; c[1] = 0x90;
                                    VirtualProtect(c, 2, old, &old);
                                    g_patches++;
                                    LOG("NOP'd short jump @ %p", c);
                                }
                                break;
                            }
                        }
                    }
                    else {
                        /* handshake.cc, ssl_x509.cc -> patcher la fonction */
                        patchRetZero(funcStart);
                    }
                }
            }
        }
    }

    LOG("Phase 2: %d xrefs found, %d patches applied", xrefCount, g_patches);
}

static DWORD WINAPI PatchThread(LPVOID param) {
    LOG("Patch thread started");

    /* Attendre que Cerebro.dll soit charge */
    HMODULE hTarget = NULL;
    for (int i = 0; i < 120; i++) {
        hTarget = GetModuleHandleA("Cerebro.dll");
        if (hTarget) break;
        Sleep(1000);
        if (i % 10 == 9) LOG("Still waiting for Cerebro.dll... (%ds)", i+1);
    }

    if (!hTarget) {
        LOG("Cerebro.dll not found, trying main module");
        hTarget = GetModuleHandleA(NULL);
    } else {
        LOG("Cerebro.dll loaded @ %p", hTarget);
    }

    /* Laisser le module s'initialiser */
    Sleep(3000);

    patchBoringSSL(hTarget);

    /* Si Cerebro n'a pas donne de resultats, essayer le main exe */
    if (g_patches == 0) {
        HMODULE hMain = GetModuleHandleA(NULL);
        if (hMain != hTarget) {
            LOG("No patches in Cerebro.dll, trying main exe...");
            patchBoringSSL(hMain);
        }
    }

    LOG("=== Patching complete: %d total patches ===", g_patches);
    return 0;
}

/* ===== DLL Entry ===== */

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        logInit(hinstDLL);
        LOG("=== Proxy winhttp.dll loaded (PID %d) ===", GetCurrentProcessId());

        /* Charger la vraie winhttp.dll depuis System32 */
        char sysDir[MAX_PATH];
        GetSystemDirectoryA(sysDir, MAX_PATH);
        strcat(sysDir, "\\winhttp.dll");
        g_real = LoadLibraryA(sysDir);
        if (!g_real) {
            LOG("FATAL: cannot load real winhttp.dll from %s (err %d)", sysDir, GetLastError());
            return FALSE;
        }
        LOG("Real winhttp.dll: %s @ %p", sysDir, g_real);

        resolveAll();

        /* Lancer le thread de patching */
        CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
    }
    else if (fdwReason == DLL_PROCESS_DETACH) {
        LOG("=== Proxy winhttp.dll unloaded ===");
        if (g_log) fclose(g_log);
        if (g_real) FreeLibrary(g_real);
        DeleteCriticalSection(&g_cs);
    }
    return TRUE;
}
"""

# .def file pour les exports - forwarde les fonctions non-hookées vers la vraie DLL
# Les fonctions hookées sont exportées avec le préfixe x et redirigées via le .def
DEF_FILE = """LIBRARY winhttp
EXPORTS
    WinHttpOpen = xWinHttpOpen
    WinHttpConnect = xWinHttpConnect
    WinHttpOpenRequest = xWinHttpOpenRequest
    WinHttpSendRequest = xWinHttpSendRequest
    WinHttpReceiveResponse = xWinHttpReceiveResponse
    WinHttpReadData = xWinHttpReadData
    WinHttpQueryHeaders = xWinHttpQueryHeaders
    WinHttpCloseHandle = xWinHttpCloseHandle
    WinHttpSetOption = xWinHttpSetOption
    WinHttpQueryOption = xWinHttpQueryOption
    WinHttpAddRequestHeaders = xWinHttpAddRequestHeaders
    WinHttpSetCredentials = xWinHttpSetCredentials
    WinHttpSetTimeouts = xWinHttpSetTimeouts
    WinHttpSetStatusCallback = xWinHttpSetStatusCallback
    WinHttpWriteData = xWinHttpWriteData
    WinHttpQueryDataAvailable = xWinHttpQueryDataAvailable
    WinHttpCrackUrl = xWinHttpCrackUrl
    WinHttpCreateUrl = xWinHttpCreateUrl
    WinHttpCheckPlatform = xWinHttpCheckPlatform
"""


def build():
    c_file = os.path.join(BUILD_DIR, "proxy_winhttp.c")
    def_file = os.path.join(BUILD_DIR, "proxy_winhttp.def")
    dll_file = os.path.join(BUILD_DIR, "winhttp.dll")

    with open(c_file, 'w') as f:
        f.write(C_SOURCE)
    with open(def_file, 'w') as f:
        f.write(DEF_FILE)

    print(f"[+] Source: {c_file}")
    print(f"[+] DEF:    {def_file}")

    # Trouver GCC
    gcc = shutil.which("gcc") or shutil.which("x86_64-w64-mingw32-gcc")
    if not gcc:
        print("[!] GCC non trouvé!")
        print("[*] Installe MinGW-w64 ou compile manuellement")
        return None

    print(f"[*] Compilateur: {gcc}")

    cmd = [
        gcc, "-shared", "-O2", "-Wall",
        "-o", dll_file,
        c_file, def_file,
        "-lwinhttp", "-lpsapi",
        "-Wl,--enable-stdcall-fixup",
    ]

    print(f"[*] Build: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[!] Build échoué!")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        return None

    print(f"[+] DLL compilée: {dll_file}")
    size_kb = os.path.getsize(dll_file) / 1024
    print(f"[+] Taille: {size_kb:.0f} KB")
    return dll_file


def install(dll_path):
    dest = os.path.join(GAME_DIR, "winhttp.dll")
    if os.path.exists(dest):
        print(f"[!] {dest} existe déjà!")
        print("[!] Backup avant d'écraser? (o/n): ", end="")
        if input().strip().lower() == 'o':
            backup = dest + ".bak"
            shutil.copy2(dest, backup)
            print(f"[+] Backup: {backup}")

    shutil.copy2(dll_path, dest)
    print(f"[+] Installé: {dest}")
    print(f"[*] Log sera écrit dans: {os.path.join(GAME_DIR, 'ssl_proxy.log')}")


def uninstall():
    dest = os.path.join(GAME_DIR, "winhttp.dll")
    if os.path.exists(dest):
        os.remove(dest)
        print(f"[+] Supprimé: {dest}")
    else:
        print("[*] Pas de proxy DLL installée")


def main():
    print("=" * 60)
    print("  ARC RAIDERS - PROXY WINHTTP.DLL BUILDER")
    print("=" * 60)
    print()
    print("  1. build     - Compiler la DLL")
    print("  2. install   - Compiler + installer dans le dossier du jeu")
    print("  3. uninstall - Supprimer la proxy DLL")
    print()

    action = input("[?] Action (1/2/3) [défaut: 2]: ").strip() or "2"

    if action == "3":
        uninstall()
        return

    dll_path = build()
    if not dll_path:
        return

    if action == "2":
        install(dll_path)
        print(f"\n[*] Lance le jeu normalement via Steam")
        print(f"[*] La DLL se chargera automatiquement")
        print(f"[*] Vérifie {os.path.join(GAME_DIR, 'ssl_proxy.log')} pour le log")


if __name__ == "__main__":
    main()
