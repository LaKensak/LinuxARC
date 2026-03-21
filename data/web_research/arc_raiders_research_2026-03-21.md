# Arc Raiders Reverse Engineering Research
# Date: 2026-03-21
# Sources: Web search compilation

---

## 1. GAME ARCHITECTURE

### Engine & Executable
- **Engine**: Unreal Engine 5 (modified by Embark Studios)
- **Executable**: `PioneerGame.exe` (Win64)
- **Config path**: `%LOCALAPPDATA%\PioneerGame\Saved\SaveGames\` (hexadecimal encoded files)
- **Log path**: `%LOCALAPPDATA%\PioneerGame\Saved\Logs\`
- **PAK encryption**: Non-standard encryption (NOT standard UE AES pak encryption)
  - FModel does NOT work with Arc Raiders because Embark uses a modified UE5 build
  - Standard AES key extraction tools fail on Arc Raiders paks

### Anti-Cheat
- **EAC (Easy Anti-Cheat)**: Kernel-level protection against external memory hacking
- **Anybrain AI**: Behavioral analysis, processes input telemetry
  - Operates without deep kernel scanning
  - Lightweight, focuses on gameplay data
- Embark gathered player data ~60 days post-launch, then enforced bans (December 2025)
  - Bans primarily targeted aimbot usage

---

## 2. NETWORK INFRASTRUCTURE

### Quilkin UDP Proxy (Open Source - by Embark Studios + Google)
- **Repository**: https://github.com/EmbarkStudios/quilkin (also https://github.com/googleforgames/quilkin)
- **Purpose**: Non-transparent UDP proxy for game server deployments
- **Status**: Beta, used in production

#### QCMP (Quilkin Control Message Protocol)
- **Magic header**: `QLKN` (4 bytes)
- **Protocol format**:
  ```
  | Magic "QLKN" (4 bytes) | Protocol Version (u1) | Packet Type (u1) | Packet Length (u2) |
  ```
- **Packet types**:
  - `0` = ping_packet (contains nonce + client timestamp in UTC unix nanoseconds)
  - `1` = ping_reply_packet
- **Protocol spec**: Defined in Kaitai Struct format (machine-readable)
- **Documentation**: https://googleforgames.github.io/quilkin/main/book/services/proxy/qcmp.html

#### Quilkin Features
- Non-transparent proxying of UDP data (obfuscation)
- Composable processing filters for routing, access control, rate limiting
- CaptureBytes filter extracts information from packets at fixed positions
- Access tokens associated with endpoints (routing tokens)
- Can run as sidecar, DDoS protection layer, or edge proxy
- Version-based packet processing for evolving formats

### Server Infrastructure
- Uses Cloudflare for encrypted channels
- Domain `*.europe.es-pio.net` referenced in connection troubleshooting
- Uses AWS or similar cloud hosting

### UE5 Network Encryption (General)
- UE5 uses PacketHandler system with HandlerComponents
- Built-in: `AESEncryptionHandler`, `StatelessHandler`
- Encryption via `?EncryptionToken=` URL option on client connection
- Token should NOT be the actual key - used to look up real key from web service
- Encrypts all replicated items and RPCs at packet handler level
- Key documentation: https://dev.epicgames.com/community/learning/knowledge-base/6PBP/

---

## 3. SDK DUMP & OFFSETS

### Dumpspace
- **URL**: https://dumpspace.spuckwaffel.com/Games/?hash=ca4c1d0d
- Contains SDK dumps for Arc Raiders / PioneerGame
- Note: OFFSET_UWORLD renamed to OFFSET_GWORLD (as of April 22)
- Required offset names: `OFFSET_GNAMES`, `OFFSET_GOBJECTS`, `OFFSET_GWORLD`

### DMA Dumper Tool
- **Repository**: https://github.com/xmodius/ArcRaiders-DMA-Dumper
- Generates: `offsets.txt` (human-readable) and `Offsets_Dumped.h` (C++ header)
- Scans for: GWorld, GNames, structure offsets
- **Requirements**:
  - DMA hardware (ScreamerM2 or compatible FPGA)
  - MemProcFS (vmm.dll, leechcore.dll)
  - Game must be in an actual match (not menu)
  - Process name: `PioneerGame.exe`
- Initializes DMA via MemProcFS with FPGA device
- Finds process via DMA process enumeration
- Gets module base address via DMA module mapping
- Reads memory directly through DMA hardware (bypasses EAC)

### Offset Finding Tools (General UE5)
- **UEDumper**: https://github.com/Spuckwaffel/UEDumper (UE 4.19 - 5.3)
- **GSpots**: https://github.com/Do0ks/GSpots (auto-finds GWorld, GNames, GObjects)
- **UEDumperDMA**: https://github.com/dvGrab/UEDumperDMA (DMA-compatible)
- **aes-finder**: https://github.com/mmozeiko/aes-finder (finds AES keys in running processes)
- **UnrealKey**: https://github.com/devinacker/UnrealKey (AES key finder for UE4)

---

## 4. DMA RADAR CHEATS (Technical Implementation)

### How DMA Radar Works
- Operates on a **second PC** connected via DMA hardware (FPGA card)
- Reads game memory through DMA card + custom firmware
- Completely outside of game memory space on primary PC
- EAC cannot detect reads from DMA hardware

### Radar Features
- Real-time tactical radar: enemies, allies, ARC bots
- Hostable on local network with customizable IP and port
- Can be shared with friends (web radar)

### Detection Evasion
- Low-level system drivers manage communication
- Dynamic code structuring and encryption prevent static patterns
- Anybrain AI focuses on behavioral analysis (aimbot patterns)
- Read-only DMA is harder to detect than write operations

---

## 5. DISCORD SDK VULNERABILITY (March 2026)

### Technical Details
- Discord Rich Presence SDK connected using FULL user Bearer token
- Opened complete Discord gateway connection (identical to desktop app)
- Gateway pushes ALL events including private DMs
- SDK logged everything to disk in plaintext (no filtering)

### Exposed Data
- Full Discord Bearer authentication token (plaintext)
- Private Direct Message conversations (plaintext)
- All Discord gateway events

### File Location
- `C:\Users\<user>\AppData\Local\PioneerGame\Saved\Logs\`

### Impact
- Bearer token = full account access
- Log sharing (bug reports, forums, support) would expose token
- Crash report auto-upload would transmit token to Embark servers
- **Patched** via hotfix by Embark Studios (March 2026)

### Source
- Discovery: https://timothymeadows.com/arc-raiders-discord-sdk-data-exposure/

---

## 6. COMMUNITY DATA & APIs

### Official
- **No official public API** - Embark keeps all tools in-game
- Design director Virgil Watkins confirmed no current plans for external APIs

### Community APIs
- **MetaForge**: https://metaforge.app/arc-raiders/api (items, ARCs, quests)
- **ARDB**: https://ardb.app/developers/api
- **ArcRaidersAPI**: https://www.shrouded.gg/
- **arcraiders-data**: https://github.com/RaidTheory/arcraiders-data (JSON format game data)
- **arcraiders-data-api**: https://github.com/Mahcks/arcraiders-data-api (REST API)

---

## 7. GITHUB REPOSITORIES OF INTEREST

| Repository | Description |
|------------|-------------|
| https://github.com/xmodius/ArcRaiders-DMA-Dumper | DMA-based offset dumper for Arc Raiders |
| https://github.com/EmbarkStudios/quilkin | Quilkin UDP proxy (by Embark Studios) |
| https://github.com/RaidTheory/arcraiders-data | Game data in JSON format |
| https://github.com/Spuckwaffel/UEDumper | UE 4.19-5.3 dumper/editor |
| https://github.com/Do0ks/GSpots | Auto GWorld/GNames/GObjects finder |
| https://github.com/Cracko298/UE4-AES-Key-Extracting-Guide | AES key extraction guide |
| https://github.com/mmozeiko/aes-finder | AES key finder in running processes |
| https://github.com/devinacker/UnrealKey | UE4 AES decryption key finder |
| https://github.com/aj-geddes/arc-raiders-tuner | Local config file tuner |
| https://github.com/rodafux/ARC-Sight | Event overlay tool |
| https://github.com/4sval/FModel/discussions/621 | FModel discussion (doesn't work with Arc Raiders) |

---

## 8. KEY FINDINGS SUMMARY

### What IS Known
1. Arc Raiders uses Quilkin (open source UDP proxy by Embark) - packet format documented
2. QCMP protocol uses "QLKN" magic header with version/type/length fields
3. UE5 network encryption uses AES via PacketHandler with EncryptionToken URL param
4. SDK offsets available on Dumpspace (GWorld, GNames, GObjects)
5. DMA dumper exists for Arc Raiders (xmodius/ArcRaiders-DMA-Dumper)
6. PAK files use non-standard encryption (FModel/standard tools don't work)
7. Anti-cheat: EAC (kernel) + Anybrain (behavioral AI)
8. Process name is PioneerGame.exe

### What is NOT Publicly Documented
1. Specific AES key for network packet encryption
2. Game-specific packet structures beyond Quilkin QCMP
3. Exact SDK offsets (must be dumped per-version from Dumpspace or DMA tools)
4. Custom encryption scheme for PAK files
5. Specifics of how Quilkin is deployed in Arc Raiders' production setup
6. The searched AES key "047A8AC14396604CE1BAB46366C0A7FD" was not found in any public source

---

## 9. NEXT STEPS FOR RESEARCH

1. **Dumpspace**: Visit https://dumpspace.spuckwaffel.com/Games/?hash=ca4c1d0d directly to get current offsets
2. **Quilkin source**: Study filter implementations in the Quilkin repo for encryption/token handling
3. **UE5 PacketHandler**: Review AESEncryptionHandler source in UE5 for network packet format
4. **DMA Dumper**: Review xmodius/ArcRaiders-DMA-Dumper source for offset scanning patterns
5. **AES key extraction**: Try aes-finder on running PioneerGame.exe process
6. **Packet capture**: Capture UDP traffic and look for QLKN magic bytes to confirm Quilkin usage
