# CardputerZero RFID

RFID standalone app for CardputerZero — read, write, dump, emulate, sniff and crack
NFC tags across multiple hardware devices.

---

## Device Feature Matrix

| Device | Interface | Scan | Read / Dump | Write (UID) | Emulate | Sniff | UHF | NDEF | Key Mgmt |
|--------|-----------|:----:|:-----------:|:-----------:|:-------:|:-----:|:---:|:----:|:--------:|
| **PN532Killer** | USB / UART | ✅ | ✅ MFC/NTAG/15693 | ✅ Gen1A/2/3/4 | ✅ HW slot 0-7 | ✅ Both modes | ❌ | ✅ | ✅ |
| **PN532 (standard)** | USB / UART | ✅ | ✅ MFC/NTAG/15693 | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **PN532 Module** | UART | ✅ | ✅ MFC/NTAG/15693 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **M5 NFC Unit** | I²C (0x50) | ✅ | ✅ MFC/NTAG/15693 | ✅ Gen1A/3 | ✅ ISO14443A/B/15693/MFC | ❌ | ❌ | ❌ | ✅ |
| **Grove NFC** | I²C (0x48) | ✅ | ✅ MFC/NTAG/15693/FeliCa | ❌ | ✅ NTAG/MFC1K/15693 | ❌ | ❌ | ❌ | ✅ |
| **M5 NFC CAP** | SPI (spidev) | ✅ | ✅ MFC/NTAG | ✅ Gen1A | ✅ ISO14443A | ❌ | ❌ | ❌ | ✅ |
| **UHF Reader** | USB (1A86:FE1C) | ✅ | ✅ Continuous scan | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |

## Supported Protocols & Operations

| Protocol | R/W | Dump | Emulate | UID Change | Notes |
|----------|:---:|:----:|:-------:|:----------:|-------|
| **MIFARE Classic 1K / 4K** | ✅ | ✅ | ✅ | ✅ (Gen1A/2/3/4) | Full sector read with key auth, emulation, magic card UID change |
| **NTAG213 / 215 / 216** | ✅ | ✅ | ✅ | ❌ | NDEF read/write, emulation |
| **MIFARE Ultralight** | ✅ | ✅ | ❌ | ❌ | Read/write full memory pages |
| **ISO 15693** | ✅ | ✅ | ✅ | ❌ | Tag-it, I-Code SLI, ST LRI |
| **FeliCa** | ✅ (GroveNFC) | ❌ | ❌ | ❌ | Limited to Grove NFC reader |
| **DESFire** | ❌ | ❌ | ❌ | ❌ | Detected but not read |
| **UHF RFID (EPC C1G2)** | ✅ | ✅ Continuous | ❌ | ❌ | Read once or continuous, CSV export |

---

## UI — 4-Tab Workflow

### Read Tab
- **Scan tags** — detect ISO14443A (MFC/NTAG/MFU), ISO15693, UHF in field
- **Dump** — read all memory blocks (sector-level for MFC with key auth)
- **Save** — persist scanned dump to local storage
- **Hex log** — Ctrl+L toggles full TX/RX frame log overlay
- **Auto-detect** card type and display ATQA/SAK/UID

### Saved Tab
- Browse saved dumps, rename, edit raw hex
- Upload dump to emulator slot (PN532Killer HW slots 0-7)
- Export / delete records

### Emulator Tab
- **PN532Killer HW Emulation** — up to 8 slots, ISO14443A / ISO15693 / MIFARE Classic
- **Grove NFC Tag Emulation** — NTAG213/215/216, MFC1K, China2, ISO15693 via I²C register protocol
- **NFC Unit (ST25R3916B) Emulation** — ISO14443A / ISO14443B / ISO15693 / MIFARE Classic with slot profile
- **M5 NFC CAP (ST25R3916) Emulation** — ISO14443A listener (REQA → anticollision → UID response)
- **NDEF URL Emulation** — PN532-only: broadcast a custom NDEF URI/URL
- **UID Changer** — rewrite block 0 of Gen1A / Gen2 (CUID) / Gen3 / Gen4 magic cards
- **Dump from emulator** — read back emulated slot content as hex lines
- **Profile switcher** — toggle protocol/slot and auto-reprobe

### Tools Tab
| Tool | Description |
|------|-------------|
| **MIFARE Keys** | Manage key dictionary: add/edit/disable default keys, import `.dic` files, load `.mfd` keys from dumps |
| **UID Changer** | Change UID on magic cards: detect Gen1A/Gen2(CUID)/Gen3/Gen4, write block 0 with custom UID |
| **MFKey32v2** | Sniff MIFARE Classic authentication + crack keys via PN532Killer (no tag required) |
| **MFKey64** | Sniff MIFARE Classic authentication + crack keys via PN532Killer (tag required for non-UID) |

## Attack / Cracking Methods

| Method | Description | Supported On |
|--------|-------------|--------------|
| **Default Keys** | Try known default keys from key dictionary to authenticate sectors | PN532, PN532Killer, NFC Unit, Grove NFC, NFC CAP |
| **Basic Auth Read** | Least-privilege: try keys only from selected dumps | PN532, PN532Killer |
| **Darkside** | MFC authentication attack (for unknown keys) | PN532Killer |
| **Hardnested** | Brute-force nested authentication attack | PN532Killer |
| **MFKey32v2** | Offline key recovery from sniffed nonces | PN532Killer + crapto1 |
| **MFKey64** | Offline key recovery from sniffed nonces (tag present) | PN532Killer + crapto1 |
| **UHF Continuous Scan** | Poll UHF tags at interval, table view with RSSI/count/antenna | UHF Reader |

---

## Data Storage

| Path | Contents |
|------|----------|
| `~/rfid/dumps/` | Saved tag dumps (JSON, raw hex blocks) |
| `~/rfid/mifare_keys.json` | MIFARE key dictionary (A/B keys per sector) |
| `~/rfid/emulator_config.json` | Emulator slot config (data per slot) |
| `~/rfid/uart_config.json` | UART port settings (device path, baud) |
| `~/rfid/last_transport.json` | Last connected endpoint (reconnect on restart) |
| `~/rfid/nfc_data/logs/` | Daily hex TX/RX log files |
| Override via env: `M5CZ_NFC_ROOT_DIR`, `M5CZ_NFC_RECORDS_DIR` | Custom storage paths |

---

## Project Layout

```
main/
├── src/main.cpp                       # App entry, LVGL init, evdev keyboard
├── ui/components/
│   ├── nfc/
│   │   ├── nfc_models.hpp              # Enums (Protocol, Transport, DeviceKind, AttackMethod)
│   │   ├── nfc_transport.hpp           # Serial / I²C / SPI transport abstraction
│   │   ├── nfc_protocol.hpp            # PN532 frame codec, Pn532KillerClient, detect_device()
│   │   ├── nfc_i2c_device.hpp          # Grove NFC / NFC Unit I²C driver (ST25R3916B)
│   │   ├── nfc_spi_device.hpp          # M5 NFC CAP SPI driver (ST25R3916)
│   │   ├── nfc_device_service.hpp      # Main service: connect/scan/dump/emulate/crack/UHF
│   │   ├── nfc_storage.hpp             # JSON dump/key/emulator config persistence
│   │   └── nfc_hex_logger.hpp          # Ring-buffer hex TX/RX logger + daily file writer
│   ├── page_app/ui_app_nfc.hpp         # LVGL UI: 4-tab layout, modals, event handlers
│   └── ui_app_page.hpp                 # Base page class (menu integration)
├── hal/
│   ├── hal_paths.h / hal_paths_rfid.c  # APPLaunch data directory resolution
│   └── hal_settings.h / hal_settings_rfid.c  # Runtime settings persistence
├── tools/
│   ├── mfkey/                          # crapto1 + mfkey32v2 / mfkey64 source
│   └── nfc_device_service.hpp          # Standalone copy for mfkey cross-build
applications/rfid.desktop               # APPLaunch launcher entry
tools/package_deb.py                     # Debian package builder
```

## Build

```bash
cd projects/RFID
scons -j4
```

Output:

- `dist/M5CardputerZero-RFID` — main app binary
- `dist_mfkey/mfkey32v2`, `dist_mfkey/mfkey64` — helper tools

## Package as .deb

```bash
cd projects/RFID
python3 tools/package_deb.py --maintainer "yourname <you@example.com>"
```

Output: `build/rfid_0.1-m5stack1_arm64.deb`

Install:

```bash
scp build/rfid_0.1-m5stack1_arm64.deb pi@<device-ip>:/tmp/
ssh pi@<device-ip> "echo pi | sudo -S dpkg -i /tmp/rfid_0.1-m5stack1_arm64.deb"
```

## APPLaunch Integration

- Desktop entry: `applications/rfid.desktop`
- Binary: `/usr/share/APPLaunch/apps/rfid/M5CardputerZero-RFID`
- Helper tools: `/usr/share/APPLaunch/apps/rfid/bin/`

## Notes

- NFC storage and key files are persisted under `~/rfid/` (or `hal_path_data_dir()`).
- For deployment from APPLaunch, compose binary with mfkey tools via SKIP_BUILD=1.
- Hex logging auto-rotates daily under `~/rfid/nfc_data/logs/`.
