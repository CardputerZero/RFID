#pragma once

// Linux ioctl-based I2C implementation of the GroveNFC register protocol.
// Ported from /Users/wilson/Github/GroveNFC/src/GroveNFC.cpp (register protocol only).
// Does NOT depend on Arduino / M5UnitUnified.

#include "nfc_models.hpp"
#include "nfc_hex_logger.hpp"

#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <array>
#include <bitset>
#include <functional>
#include <random>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#endif
#ifndef I2C_SLAVE
#define I2C_SLAVE 0x0703
#endif
#ifndef I2C_RDWR
#define I2C_RDWR  0x0707
#endif
#ifndef I2C_M_RD
#define I2C_M_RD  0x0001
#endif
#ifndef __linux__
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
struct i2c_msg {
    __u16 addr;
    __u16 flags;
    __u16 len;
    __u8 *buf;
};
struct i2c_rdwr_ioctl_data {
    struct i2c_msg *msgs;
    __u32 nmsgs;
};
#endif

#include <chrono>
#include <thread>

namespace nfc_app {

// GroveNFC register addresses (from GroveNFC.h)
namespace i2c_reg {
    static constexpr uint16_t HW_VER      = 0x0000;
    static constexpr uint16_t FW_VER      = 0x0002;
    static constexpr uint16_t SET_MODE    = 0x0004;
    static constexpr uint16_t SET_TAGADDR = 0x0006;
    static constexpr uint16_t SET_RFCFG   = 0x0008;
    static constexpr uint16_t SET_FWI     = 0x000A;
    static constexpr uint16_t SET_TXCRCE  = 0x000C;
    static constexpr uint16_t SET_RXCRCE  = 0x000E;
    static constexpr uint16_t NFC_STATUS  = 0x0010;
    static constexpr uint16_t RX_LEN      = 0x0012;
    static constexpr uint16_t MISC_RFON   = 0x0020;
    static constexpr uint16_t MISC_TXLAST = 0x0021;
    static constexpr uint16_t MISC_THRU   = 0x0022;
    static constexpr uint16_t MISC_EGT    = 0x0023;
    static constexpr uint16_t MISC_SLOT   = 0x0024;
    static constexpr uint16_t MISC_EPWR   = 0x0029;
    static constexpr uint16_t DATA        = 0x0100;
    static constexpr uint16_t EPROM       = 0x1000;
}

// Mode register constants
namespace i2c_mode {
    static constexpr uint16_t DEFAULT    = 0x0000;
    static constexpr uint16_t READER     = 0x0100;
    static constexpr uint16_t MIFARE1_READER = 0x0300;
    static constexpr uint16_t TAG_NONE   = 0x0000;
    static constexpr uint16_t TAG_NTAG213 = 0x0001;
    static constexpr uint16_t TAG_NTAG215 = 0x0002;
    static constexpr uint16_t TAG_NTAG216 = 0x0003;
    static constexpr uint16_t TAG_MFC1K  = 0x0004;
    static constexpr uint16_t TAG_CHINA2 = 0x0020;
    static constexpr uint16_t TAG_ISO15  = 0x000C;
}

// RF config constants
namespace i2c_rfcfg {
    static constexpr uint16_t R14A = 0x0100;
    static constexpr uint16_t T14A = 0x0001;
    static constexpr uint16_t R14B = 0x0500;
    static constexpr uint16_t T14B = 0x0005;
    static constexpr uint16_t R212 = 0x0900;
    static constexpr uint16_t T212 = 0x0009;
    static constexpr uint16_t R15  = 0x0B00;
    static constexpr uint16_t T15  = 0x000B;
}

// Status bits
static constexpr uint16_t STATUS_RECV_DONE    = 0x0001;
static constexpr uint16_t STATUS_RECV_TIMEOUT = 0x4000;
static constexpr uint16_t STATUS_RECV_CRCERR  = 0x2000;
static constexpr uint16_t STATUS_RECV_BITERR  = 0x1000;
static constexpr uint16_t STATUS_MIFARE1_AUTHOK   = 0x0800;
static constexpr uint16_t STATUS_MIFARE1_AUTHERR  = 0x0400;
static constexpr uint16_t STATUS_MIFARE1_WRITEOK  = 0x0200;
static constexpr uint16_t STATUS_MIFARE1_WRITEERR = 0x0100;

// Tag address constants (slot base addresses in EEPROM)
static constexpr uint16_t TAG_ADDR_NTAG213 = 0x0000;
static constexpr uint16_t TAG_ADDR_NTAG215 = 0x1000;
static constexpr uint16_t TAG_ADDR_NTAG216 = 0x2000;
static constexpr uint16_t TAG_ADDR_MFC1K   = 0x3000;
static constexpr uint16_t TAG_ADDR_ISO15   = 0x7000;
static constexpr uint16_t TAG_ADDR_14B     = 0x0000;

// I2C addresses
static constexpr uint8_t I2C_ADDR_GROVENFC = 0x48;
static constexpr uint8_t I2C_ADDR_NFCUNIT  = 0x50;

// ─────────────────────────────────────────────────────────────────────────────
// CardInfo — simplified card read result (corresponds to grove_nfc::CardInfo)
// ─────────────────────────────────────────────────────────────────────────────
struct I2cCardInfo {
    bool        valid    = false;
    std::string protocol;   // "MFC1K","MFC4K","NTAG213","NTAG215","NTAG216",
                            // "MFUL","DESFire","ISO14443A","ISO14443B",
                            // "ISO15693","FeliCa","None"
    std::string uid;        // uppercase hex, e.g. "04:AB:CD:EF"
    std::string detail;     // human-readable card details
    std::string atqa_hex;   // uppercase hex, e.g. "0004"
    std::string sak_hex;    // uppercase hex, e.g. "08"
    std::string magic_type; // "Gen1A" / "Gen3" / "Gen4" / ""
};

// ─────────────────────────────────────────────────────────────────────────────
// I2cGroveNfcDevice
// ─────────────────────────────────────────────────────────────────────────────
class I2cGroveNfcDevice {
public:
    I2cGroveNfcDevice() = default;
    ~I2cGroveNfcDevice() { close(); }

    // Open the I2C bus at bus_path (e.g. "/dev/i2c-1") and address addr.
    bool open(const std::string &bus_path, uint8_t addr, std::string *error = nullptr)
    {
#ifdef _WIN32
        if (error) *error = "I2C not supported on Windows";
        return false;
#else
        close();
        addr_ = addr;
        bus_path_ = bus_path;

        fd_ = ::open(bus_path.c_str(), O_RDWR);
        if (fd_ < 0) {
            if (error) *error = std::string("open ") + bus_path + ": " + std::strerror(errno);
            return false;
        }
        if (::ioctl(fd_, I2C_SLAVE, (long)addr) < 0) {
            if (error) *error = std::string("ioctl I2C_SLAVE 0x") + hex8(addr) + ": " + std::strerror(errno);
            ::close(fd_);
            fd_ = -1;
            return false;
        }
        // Probe: try to read firmware version register — if it fails the device isn't there.
        uint16_t fw = readSysReg(i2c_reg::FW_VER);
        if (fw == 0 && errno != 0) {
            // Attempt a raw 1-byte read as ping (same as GroveNFC::ping)
            uint8_t dummy = 0;
            if (::read(fd_, &dummy, 1) < 0) {
                if (error) *error = std::string("probe 0x") + hex8(addr) + " on " + bus_path + ": no device";
                ::close(fd_);
                fd_ = -1;
                return false;
            }
        }
        if (error) error->clear();
        return true;
#endif
    }

    void close()
    {
        if (fd_ >= 0) {
            if (is_nfc_unit()) {
                nfcunit_stop_listener();
            }
            stopRF();
            ::close(fd_);
            fd_ = -1;
        }
    }

    bool is_open() const { return fd_ >= 0; }
    bool is_nfc_unit() const { return addr_ == I2C_ADDR_NFCUNIT; }
    uint8_t addr() const { return addr_; }
    const std::string &bus_path() const { return bus_path_; }

    DeviceKind device_kind() const {
        if (addr_ == I2C_ADDR_NFCUNIT) return DeviceKind::NFCUnit;
        if (addr_ == I2C_ADDR_GROVENFC) return DeviceKind::GroveNFC;
        return DeviceKind::Unknown;
    }

    // ── Card reading ───────────────────────────────────────────────────────────

    // Try to read any card type (ISO14443A > ISO14443B > ISO15693 > FeliCa).
    // Returns true if a card was found.
    bool readCard(I2cCardInfo &card)
    {
        card.magic_type.clear();
        card.atqa_hex.clear();
        card.sak_hex.clear();

        if (is_nfc_unit()) {
            // M5 NFC Unit (ST25R3916B at 0x50) uses a completely different I2C
            // register protocol from GroveNFC (Nuvoton MCU at 0x48).
            // Use the dedicated ST25R3916B driver path.
            return readCardNFCUnit(card);
        }

        if (readISO14B(card)) return true;
        if (readISO14A(card)) return true;
        if (readISO15(card)) return true;
        if (readFelica(card)) return true;

        card.valid = false;
        card.protocol = "None";
        card.uid = "";
        card.detail = "No card";
        return false;
    }

    // Dump card content as hex lines based on protocol + UID from last scan.
    bool dumpCard(ProtocolKind protocol,
                  const std::string &uid_hint,
                  const std::string &tag_type,
                  const std::vector<std::string> *mfc_key_hex,
                  std::string *magic_type,
                  std::vector<std::string> &out_lines,
                  const std::function<void(const std::string &)> *progress = nullptr,
                  std::string *error = nullptr)
    {
        out_lines.clear();
        if (magic_type) magic_type->clear();
        if (!is_open()) {
            if (error) *error = "I2C device not open";
            return false;
        }

        if (!is_nfc_unit()) {
            switch (protocol) {
            case ProtocolKind::Iso14443A:
            case ProtocolKind::MifareClassic:
                return dumpGroveMFC(uid_hint, tag_type, mfc_key_hex, out_lines, progress, error);
            default:
                if (error) *error = "GroveNFC dump currently supports MFC only";
                return false;
            }
        }

        switch (protocol) {
        case ProtocolKind::Iso15693:
            return dumpNFCUnitISO15693(uid_hint, out_lines, error);
        case ProtocolKind::Iso14443A: {
            std::string mfu_err;
            if (dumpNFCUnitMFU(uid_hint, out_lines, &mfu_err)) {
                if (error) error->clear();
                return true;
            }
            // Some Gen1A/Magic MFC cards may be scanned as generic ISO14443A.
            // If MFU path fails, fall back to MFC dump path automatically.
            std::string mfc_err;
            std::string detected_magic;
            if (dumpNFCUnitMFC(uid_hint, tag_type, mfc_key_hex, &detected_magic, out_lines, progress, &mfc_err)) {
                if (magic_type && !detected_magic.empty()) *magic_type = detected_magic;
                if (error) error->clear();
                return true;
            }
            if (error) {
                *error = mfu_err.empty() ? (mfc_err.empty() ? "ISO14443A dump failed" : mfc_err)
                                         : mfu_err;
            }
            return false;
        }
        case ProtocolKind::MifareClassic:
            return dumpNFCUnitMFC(uid_hint, tag_type, mfc_key_hex, magic_type, out_lines, progress, error);
        default:
            if (error) *error = "Unsupported protocol for I2C dump";
            return false;
        }
    }

    // ── Write card data (NFC Unit only) ───────────────────────────────────────
    // protocol: protocol of the dump data.
    // tag_type: e.g. "Mifare Classic 1K", "NTAG213", "ISO15693"
    // lines: dump lines in "NN: HEXHEX..." format (same as SavedRecord::raw_data).
    // mfc_key_hex: optional list of MFC sector keys (used for non-magic MFC).
    // progress: optional callback for per-line status updates.
    // Returns true on full success; partial writes return false (some blocks may
    // have been written before failure).
    bool writeCard(ProtocolKind protocol,
                   const std::string &tag_type,
                   const std::vector<std::string> &lines,
                   const std::vector<std::string> *mfc_key_hex = nullptr,
                   const std::function<void(const std::string &)> *progress = nullptr,
                   std::string *error = nullptr)
    {
        if (!is_open()) {
            if (error) *error = "I2C device not open";
            return false;
        }
        if (!is_nfc_unit()) {
            if (error) *error = "Write is only supported on NFC Unit";
            return false;
        }
        if (lines.empty()) {
            if (error) *error = "No data to write";
            return false;
        }

        switch (protocol) {
        case ProtocolKind::MifareClassic:
            return writeNFCUnitMFC(tag_type, lines, mfc_key_hex, progress, error);
        case ProtocolKind::Iso14443A:
            return writeNFCUnitMFU(tag_type, lines, progress, error);
        case ProtocolKind::Iso15693:
            return writeNFCUnitISO15693(lines, progress, error);
        default:
            if (error) *error = "Unsupported protocol for write";
            return false;
        }
    }

    // Write block 0 for Gen1A magic card on NFC Unit (ST25R3916B).
    // block0 must be exactly 16 bytes and already contain UID/BCC/SAK/ATQA bytes.
    bool writeNFCUnitGen1ABlock0(const std::vector<uint8_t> &block0,
                                 std::string *error = nullptr)
    {
        if (!is_open()) {
            if (error) *error = "I2C device not open";
            return false;
        }
        if (!is_nfc_unit()) {
            if (error) *error = "Only NFC Unit supports this operation";
            return false;
        }
        if (block0.size() != 16) {
            if (error) *error = "block0 must be 16 bytes";
            return false;
        }

        if (!st25r_init_nfca_reader()) {
            if (error) *error = "NFCA init failed";
            return false;
        }

        auto parse_ack = [](const uint8_t *rx, uint8_t rx_len) {
            if (!rx || rx_len == 0) return false;
            const uint8_t lo = static_cast<uint8_t>(rx[0] & 0x0F);
            const uint8_t hi = static_cast<uint8_t>((rx[0] >> 4) & 0x0F);
            return (lo == 0x0A) || (hi == 0x0A) || (rx[0] == 0x0A);
        };

        auto write_step = [&](const uint8_t *tx, uint8_t tx_len, const char *name) {
            uint8_t ack_len = 4;
            uint8_t ack[4] = {0};
            if (!st25r_nfca_transceive(tx, tx_len, true, ack, ack_len, 60, 0x00, true, 0)) {
                if (error) *error = std::string(name) + " timeout";
                return false;
            }
            if (!parse_ack(ack, ack_len)) {
                if (error) *error = std::string(name) + " no ACK";
                return false;
            }
            return true;
        };

        // Reuse proven unlock path; success implies card is in Gen1A unlocked mode.
        if (!st25r_is_gen1a_magic("")) {
            st25r_write_reg(0x02, 0x80);
            if (error) *error = "not Gen1A";
            return false;
        }

        const uint8_t write_cmd[2] = {0xA0, 0x00};
        if (!write_step(write_cmd, sizeof(write_cmd), "write cmd") ||
            !write_step(block0.data(), static_cast<uint8_t>(block0.size()), "write data")) {
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        std::array<uint8_t, 16> verify{};
        const bool verify_ok = st25r_mfc_read_plain_block(0, verify) &&
                               std::equal(verify.begin(), verify.end(), block0.begin());
        st25r_write_reg(0x02, 0x80);
        if (!verify_ok) {
            if (error) *error = "verify block0 failed";
            return false;
        }
        if (error) error->clear();
        return true;
    }

    // Write block 0 for Gen3 (CUID) magic card on NFC Unit (ST25R3916B).
    // uid must be 4 or 7 bytes; block0 must be exactly 16 bytes.
    // Protocol: select → plain READ block0 (Gen3 check) → UID-set cmd → block0-write cmd.
    bool writeNFCUnitGen3Block0(const std::vector<uint8_t> &uid,
                                const std::vector<uint8_t> &block0,
                                std::string *error = nullptr)
    {
        if (!is_open()) {
            if (error) *error = "I2C device not open";
            return false;
        }
        if (!is_nfc_unit()) {
            if (error) *error = "Only NFC Unit supports this operation";
            return false;
        }
        if (uid.size() != 4 && uid.size() != 7) {
            if (error) *error = "uid must be 4 or 7 bytes";
            return false;
        }
        if (block0.size() != 16) {
            if (error) *error = "block0 must be 16 bytes";
            return false;
        }

        // Full ISO14443-A select (includes RF reset inside st25r_nfca_select_uid).
        std::vector<uint8_t> sel_uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(sel_uid, sak)) {
            if (error) *error = "card select failed";
            return false;
        }

        // Match PN532 sequence for Gen3: HALT -> WUPA -> SELECT before raw cmds.
        if (!st25r_nfca_reselect_current_field(sel_uid, sak, true)) {
            st25r_write_reg(0x02, 0x80);
            if (error) *error = "reselect failed";
            return false;
        }

        // Verify Mifare Classic / Mifare Plus SL2 by SAK.
        if (!(sak == 0x08 || sak == 0x09 || sak == 0x18 || sak == 0x28 || sak == 0x38 ||
              sak == 0x1C)) {
            st25r_write_reg(0x02, 0x80);
            if (error) *error = "not Mifare Classic (SAK mismatch)";
            return false;
        }

        auto parse_sw_9000 = [](const uint8_t *rx, uint8_t rx_len) -> bool {
            if (!rx || rx_len < 2) return false;
            for (uint8_t i = 0; i + 1 < rx_len; ++i) {
                if (rx[i] == 0x90 && rx[i + 1] == 0x00) return true;
            }
            return false;
        };

        auto transceive_raw_with_crc = [&](const std::vector<uint8_t> &cmd,
                                           uint8_t *rx,
                                           uint8_t &rx_len,
                                           int timeout_ms,
                                           bool issue_stop,
                                           const char *name) -> bool {
            if (cmd.empty()) return false;
            std::array<uint8_t, 64> frame{};
            const size_t cmd_len = cmd.size();
            if (cmd_len + 2 > frame.size()) {
                if (error) *error = std::string(name) + " too long";
                return false;
            }

            std::copy(cmd.begin(), cmd.end(), frame.begin());
            const uint16_t crc = crc_a(frame.data(), cmd_len);
            frame[cmd_len] = static_cast<uint8_t>(crc & 0xFF);
            frame[cmd_len + 1] = static_cast<uint8_t>((crc >> 8) & 0xFF);

            if (!st25r_nfca_transceive(frame.data(),
                                       static_cast<uint8_t>(cmd_len + 2),
                                       false,
                                       rx,
                                       rx_len,
                                       timeout_ms,
                                       0x00,
                                       true,
                                       0,
                                       issue_stop)) {
                if (error) *error = std::string(name) + " timeout";
                return false;
            }
            return true;
        };

        // Gen3 UID-set command: {0x90, 0xFB, 0xCC, 0xCC, Lc, uid...}
        // Note: Gen3 (CUID) cards DO support unauthenticated READ (0x30) in principle.
        // However, empirical testing shows the card does not respond via ST25R3916B
        // (while it does respond via PN532 InCommunicateThru). Root cause unknown —
        // likely an RF/parity/framing difference between the two reader chips.
        // We skip the pre-check and rely on the 9000 response to 90FBCCCC instead.
        std::vector<uint8_t> uid_cmd = {0x90, 0xFB, 0xCC, 0xCC, static_cast<uint8_t>(uid.size())};
        uid_cmd.insert(uid_cmd.end(), uid.begin(), uid.end());
        {
            uint8_t rx[16] = {0};
            uint8_t rx_len = sizeof(rx);
            if (!transceive_raw_with_crc(uid_cmd,
                                         rx,
                                         rx_len,
                                         120,
                                         false,
                                         "Gen3 UID set") ||
                !parse_sw_9000(rx, rx_len)) {
                st25r_write_reg(0x02, 0x80);
                if (error && error->empty()) *error = "Gen3 UID set failed";
                return false;
            }
        }

        // Keep same RF session (no reselect), but give the card a short settle
        // window after 90FBCCCC before sending 90F0CCCC.
        // PN532 path has natural transport latency; ST25R path is faster and can
        // otherwise trigger unstable UID commit on some Gen3 cards.
        delay_ms(8);

        // NOTE: Do NOT reselect here. On ST25R3916B, 90FBCCCC and 90F0CCCC must be
        // sent back-to-back in the same session. A reselect between them causes
        // the block0 write to silently fail (card returns 9000 but data is not
        // committed). Send 90F0CCCC immediately after 90FBCCCC.

        // Gen3 block0-write command: {0x90, 0xF0, 0xCC, 0xCC, 0x10, block0...}
        std::vector<uint8_t> blk0_cmd = {0x90, 0xF0, 0xCC, 0xCC, 0x10};
        blk0_cmd.insert(blk0_cmd.end(), block0.begin(), block0.end());
        {
            uint8_t rx[16] = {0};
            uint8_t rx_len = sizeof(rx);
            if (!transceive_raw_with_crc(blk0_cmd,
                                         rx,
                                         rx_len,
                                         120,
                                         false,
                                         "Gen3 block0 write") ||
                !parse_sw_9000(rx, rx_len)) {
                st25r_write_reg(0x02, 0x80);
                if (error && error->empty()) *error = "Gen3 block0 write failed";
                return false;
            }
        }

        // Verification via plain READ (0x30) is currently unreliable on ST25R3916B
        // for Gen3 cards (card does not respond, see note above). The 9000 from
        // 90F0CCCC is sufficient write confirmation.

        // After a successful UID-changing write, the card now responds with the NEW
        // UID. Reselecting with the old sel_uid will naturally fail — this is expected
        // and is NOT an error. Just turn off RF and return success.
        st25r_nfca_reselect_current_field(sel_uid, sak, true); // best-effort, ignore failure
        st25r_write_reg(0x02, 0x80);
        if (error) error->clear();
        return true;
    }

    // ── Gen4 block0 write ────────────────────────────────────────────────────

    // Write UID + Block 0 to a Gen4 (DirectWrite) magic card via ST25R3916B.
    // Uses the CF-backdoor command set:
    //   CF <pw4> 68 <uid_mode>       → set UID length (0=4B, 1=7B)
    //   CF <pw4> CD 00 <block0_16B>  → write block 0
    // password: 8-char hex string of the 4-byte password (default 00000000).
    bool writeNFCUnitGen4Block0(const std::vector<uint8_t> &uid,
                                const std::vector<uint8_t> &block0,
                                const std::string &password,
                                std::string *error = nullptr)
    {
        if (!is_open()) {
            if (error) *error = "I2C device not open";
            return false;
        }
        if (!is_nfc_unit()) {
            if (error) *error = "Only NFC Unit supports this operation";
            return false;
        }
        if (uid.size() != 4 && uid.size() != 7) {
            if (error) *error = "uid must be 4 or 7 bytes";
            return false;
        }
        if (block0.size() != 16) {
            if (error) *error = "block0 must be 16 bytes";
            return false;
        }

        // Decode 8-char hex password (default 00 00 00 00).
        auto hexval = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        uint8_t pw[4] = {0, 0, 0, 0};
        for (int i = 0; i < 4 && (i * 2 + 1) < static_cast<int>(password.size()); ++i)
            pw[i] = static_cast<uint8_t>((hexval(password[i * 2]) << 4) | hexval(password[i * 2 + 1]));

        // Select card.
        std::vector<uint8_t> sel_uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(sel_uid, sak)) {
            if (error) *error = "card select failed";
            return false;
        }
        if (!st25r_nfca_reselect_current_field(sel_uid, sak, true)) {
            st25r_write_reg(0x02, 0x80);
            if (error) *error = "reselect failed";
            return false;
        }
        if (!(sak == 0x08 || sak == 0x09 || sak == 0x18 || sak == 0x28 || sak == 0x38 || sak == 0x1C)) {
            st25r_write_reg(0x02, 0x80);
            if (error) *error = "not Mifare Classic (SAK mismatch)";
            return false;
        }

        // Helper: append CRC-A and transceive, require rx_len >= min_rx.
        auto transceive_gen4 = [&](const std::vector<uint8_t> &cmd,
                                   uint8_t min_rx,
                                   const char *name) -> bool {
            std::array<uint8_t, 64> frame{};
            const size_t cmd_len = cmd.size();
            if (cmd_len + 2 > frame.size()) {
                if (error) *error = std::string(name) + " too long";
                return false;
            }
            std::copy(cmd.begin(), cmd.end(), frame.begin());
            const uint16_t crc = crc_a(frame.data(), cmd_len);
            frame[cmd_len] = static_cast<uint8_t>(crc & 0xFF);
            frame[cmd_len + 1] = static_cast<uint8_t>((crc >> 8) & 0xFF);
            uint8_t rx[64] = {0};
            uint8_t rx_len = sizeof(rx);
            if (!st25r_nfca_transceive(frame.data(),
                                       static_cast<uint8_t>(cmd_len + 2),
                                       false, rx, rx_len, 120, 0x00, true, 0)) {
                if (error) *error = std::string(name) + " timeout";
                return false;
            }
            if (rx_len < min_rx) {
                if (error) *error = std::string(name) + " short response";
                return false;
            }
            return true;
        };

        // Step 1: CF pw 68 uid_mode → set UID length.
        const uint8_t uid_mode = (uid.size() == 4) ? 0x00 : 0x01;
        const std::vector<uint8_t> cmd_len_set = {0xCF, pw[0], pw[1], pw[2], pw[3], 0x68, uid_mode};
        if (!transceive_gen4(cmd_len_set, 2, "Gen4 set UID mode")) {
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        // Re-select before block0 write.
        if (!st25r_nfca_reselect_current_field(sel_uid, sak, true)) {
            st25r_write_reg(0x02, 0x80);
            if (error) *error = "reselect before block0 write failed";
            return false;
        }

        // Step 2: CF pw CD 00 block0[16] → write block 0.
        std::vector<uint8_t> cmd_write = {0xCF, pw[0], pw[1], pw[2], pw[3], 0xCD, 0x00};
        cmd_write.insert(cmd_write.end(), block0.begin(), block0.end());
        if (!transceive_gen4(cmd_write, 1, "Gen4 block0 write")) {
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        // Final reselect to leave card in clean state.
        st25r_nfca_reselect_current_field(sel_uid, sak, true);
        st25r_write_reg(0x02, 0x80);
        if (error) error->clear();
        return true;
    }

    // ── Gen3 block read ──────────────────────────────────────────────────────

    // Read one block (16 bytes) from a Gen3 (CUID) card via plain READ(0x30).
    // Gen3 cards respond to READ without authentication (vendor backdoor feature).
    // Equivalent to PN532 "hf 14a raw -s -c 30 <block>".
    // The card must already be selected. Returns true on success.
    // NOTE: Empirically fails on some Gen3 cards via ST25R3916B (card gives no
    // response), while the same card responds correctly via PN532. Cause unknown.
    bool readNFCUnitGen3Block(uint8_t block,
                             std::vector<uint8_t> *block_data,
                             std::string *error = nullptr)
    {
        if (!is_open() || !is_nfc_unit()) {
            if (error) *error = "device not available";
            return false;
        }
        std::array<uint8_t, 16> data{};
        if (!st25r_mfc_read_plain_block(block, data)) {
            if (error) *error = "READ 0x30 timeout (no response from card)";
            return false;
        }
        if (block_data) block_data->assign(data.begin(), data.end());
        return true;
    }

    // Read all 64 blocks of a Gen3 card. Requires fresh select before calling.
    bool readNFCUnitGen3Full(std::vector<std::vector<uint8_t>> *blocks,
                             std::vector<std::string> *log,
                             std::string *error = nullptr)
    {
        auto emit = [&](const std::string &s) {
            if (log) log->push_back(s);
        };
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) {
            if (error) *error = "select failed";
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        emit("> Gen3 selected, reading blocks via 30 XX...");
        if (blocks) blocks->assign(64, {});
        int ok_count = 0;
        for (uint8_t blk = 0; blk < 64; ++blk) {
            std::vector<uint8_t> bdata;
            std::string berr;
            if (readNFCUnitGen3Block(blk, &bdata, &berr)) {
                if (blocks) (*blocks)[blk] = bdata;
                ++ok_count;
                char buf[40];
                int pos = std::snprintf(buf, sizeof(buf), "%02d:", blk);
                for (size_t bi = 0; bi < bdata.size() && bi < 16; ++bi)
                    pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%02X", bdata[bi]);
                emit(buf);
            } else {
                char buf[48];
                std::snprintf(buf, sizeof(buf), "ERR blk%02d: %s", blk, berr.c_str());
                emit(buf);
                // If first block fails, abort early — card likely doesn't support this.
                if (blk == 0) {
                    if (error) *error = "block 0 read failed; Gen3 READ not supported on this card";
                    st25r_write_reg(0x02, 0x80);
                    return false;
                }
            }
        }
        char buf[32];
        std::snprintf(buf, sizeof(buf), "OK %d/64 blocks read", ok_count);
        emit(buf);
        st25r_write_reg(0x02, 0x80);
        return ok_count > 0;
    }

    // ── Emulation (GroveNFC 0x48 only, NFC Unit returns false) ───────────────

    bool startEmulationNtag213()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG213);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG213);
    }

    bool startEmulationNtag215()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG215);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG215);
    }

    bool startEmulationNtag216()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_NTAG216);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NTAG216);
    }

    bool startEmulationMifare1K()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_MFC1K);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_MFC1K);
    }

    bool startEmulationISO15()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R15 | i2c_rfcfg::T15);
        delay_ms(2);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_ISO15);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_ISO15);
    }

    // Write default emulation dump to EEPROM for GroveNFC.
    // Called before activate to ensure card data is present.
    template<typename Storage>
    void writeEmulationDefaultDump(ProtocolKind protocol, const Storage &storage)
    {
        if (is_nfc_unit()) return;  // NFCUnit uses RAM not EEPROM
        std::vector<uint8_t> data = storage.load_emulator_default_dump(protocol);
        uint16_t addr = 0;
        // Use a static default if no custom dump is loaded
        if (data.empty()) return;
        // Custom dump loaded
        if (data.size() < 4) return;
        switch (protocol) {
        case ProtocolKind::MifareClassic: addr = TAG_ADDR_MFC1K; break;
        case ProtocolKind::Iso15693:      addr = TAG_ADDR_ISO15; break;
        default:                          addr = TAG_ADDR_NTAG213; break;
        }
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE); delay_ms(2);
        writeSysReg(i2c_reg::SET_TAGADDR, addr); delay_ms(2);
        writeData(i2c_reg::EPROM, data.data(), data.size()); delay_ms(2);
        writeMiscReg(i2c_reg::MISC_EPWR, 0x01); delay_ms(350);
    }

    bool nfcunit_refresh_iso15_emulation()
    {
        if (!is_open() || !is_nfc_unit()) return false;

        const uint16_t mode = readSysReg(i2c_reg::SET_MODE);
        if ((mode & 0x00FFu) != i2c_mode::TAG_ISO15) {
            return startEmulationISO15();
        }

        const uint16_t status = readSysReg(i2c_reg::NFC_STATUS);
        const uint16_t err_bits = STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR;
        if ((status & err_bits) != 0) {
            // Recover from stale receive/error state by fully re-applying ISO15 config.
            return startEmulationISO15();
        }

        return true;
    }

    bool startEmulationChinaII()
    {
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(5);
        writeSysReg(i2c_reg::SET_TAGADDR, TAG_ADDR_14B);
        delay_ms(5);
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_CHINA2);
    }

    bool stopEmulation()
    {
        return writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
    }

    // ── NFC Unit (ST25R3916) listener-mode emulation helpers ───────────────

    // Start NFC-A listener mode using ST25R3916 passive target memory.
    // uid size must be 4 or 7 bytes.
    bool nfcunit_start_listener_a(const std::vector<uint8_t> &uid,
                                  uint16_t atqa,
                                  uint8_t sak,
                                  bool keep_auto_collision = false)
    {
        if (!is_open() || !is_nfc_unit()) return false;
        if (!(uid.size() == 4 || uid.size() == 7)) return false;

        nfcunit_stop_listener();

        // NOTE: Do NOT call writeSysReg() here. writeSysReg sends a 4-byte
        // MCU-bridge frame [reg_hi, reg_lo, val_lo, val_hi]. The NFC Unit at
        // 0x50 is a raw ST25R3916B, so it interprets those 4 bytes as a
        // multi-byte auto-increment register write starting at reg 0x00:
        //   reg0(IO_CONFIG_1)=0x04, reg1(IO_CONFIG_2)=xx, reg2(OP_CONTROL)=0x00
        // Setting OP_CONTROL=0 kills the oscillator, causing the subsequent
        // PT memory write to be silently ignored by the chip.

        st25r_cmd(0xD6);  // ADJUST_REGULATORS
        delay_ms(5);

        // Upstream default passive-target definition for NFC-A emulation.
        if (!st25r_write_reg(0x08, 0x5C)) return false;

        // External field detector thresholds + auto mode (required for I_eon).
        if (!st25r_write_reg(0x2A, 0x13)) return false;
        if (!st25r_write_reg(0x2B, 0x02)) return false;
        if (!st25r_change_bits(0x02, 0x03, 0x00)) return false;
        if (!st25r_write_reg(0x29, 0x5F)) return false;       // passive target modulation
        (void)st25r_write_spaceb(0x05, 0x40);                 // EMD suppression start on first bits

        // Disable GPT trigger source and set MRT step to 512/fc.
        if (!st25r_change_bits(0x12, 0x00, 0xE0)) return false;
        if (!st25r_change_bits(0x12, 0x08, 0x00)) return false;
        if (!st25r_write_reg(0x0F, 0x04)) return false;  // ~100us mask-receive timer (ceil + clamp)

        // 14443-A parity on, NFC-F off.
        if (!st25r_change_bits(0x05, 0x00, 0xE0)) return false;

        // Match M5Unit-NFC listener defaults.
        st25r_write_reg(0x26, 0x00);
        st25r_write_reg(0x27, 0xFF);
        st25r_write_spaceb(0x30, 0x00);
        st25r_write_spaceb(0x31, 0x00);
        st25r_write_spaceb(0x32, 0x00);
        st25r_write_spaceb(0x33, 0x00);

        // PT_MEMORY_A layout (15 bytes) for ST25R3916B passive-target mode.
        // The hardware computes BCC internally — we only supply raw UID bytes.
        // Layout matches M5Unit-NFC EmulationLayerA::load_config():
        //   [0..size-1] = raw uid bytes (max 7)
        //   [7..9]      = 0 (reserved / padding)
        //   [10]        = ATQA low byte
        //   [11]        = ATQA high byte
        //   [12]        = SAK CL1 (with cascade bit for 7-byte UID)
        //   [13]        = SAK CL2 final
        //   [14]        = SAK CL3 (same as CL2)
        uint8_t pt_mem_a[15] = {0};
        if (uid.size() == 7) {
            memcpy(pt_mem_a, uid.data(), 7);              // bytes 0-6: raw uid, no BCC
            pt_mem_a[10] = static_cast<uint8_t>(atqa & 0xFF);
            pt_mem_a[11] = static_cast<uint8_t>((atqa >> 8) & 0xFF);
            pt_mem_a[12] = static_cast<uint8_t>(sak | 0x04u);   // CL1 SAK (cascade bit set)
            pt_mem_a[13] = static_cast<uint8_t>(sak & ~0x04u);  // CL2 SAK (final)
            pt_mem_a[14] = static_cast<uint8_t>(sak & ~0x04u);  // CL3 SAK (same)
        } else {
            memcpy(pt_mem_a, uid.data(), 4);              // bytes 0-3: raw uid, no BCC
            pt_mem_a[10] = static_cast<uint8_t>(atqa & 0xFF);
            pt_mem_a[11] = static_cast<uint8_t>((atqa >> 8) & 0xFF);
            pt_mem_a[12] = static_cast<uint8_t>(sak & ~0x04u);  // CL1 SAK (final, no cascade)
            pt_mem_a[13] = static_cast<uint8_t>(sak & ~0x04u);
            pt_mem_a[14] = static_cast<uint8_t>(sak & ~0x04u);
        }

        // Ensure oscillator (en=0x80) and receiver (rx_en=0x40) are on before
        // writing PT memory.  nfcunit_stop_listener() leaves en set, but be
        // explicit so a cold-start path also works.
        if (!st25r_change_bits(0x02, 0xC0u, 0x00u)) return false;
        delay_ms(5);

        // UID length bit in AUX(0x0A): uid_7=0x10, uid_4=0x00 (mask 0x30).
        const uint8_t uid_bits = (uid.size() == 7) ? 0x10 : 0x00;
        if (!st25r_change_bits(0x0A, uid_bits, static_cast<uint8_t>(0x30 & ~uid_bits))) return false;
        delay_ms(5);

        // Debug: log PT memory bytes we are about to write.
        std::fprintf(stderr, "[NFCU-PT] writing pt_mem_a:");
        for (int _i = 0; _i < 15; ++_i) std::fprintf(stderr, " %02X", pt_mem_a[_i]);
        std::fprintf(stderr, "\n");
        std::fflush(stderr);
        // Also write to /tmp for capture when stderr is suppressed.
        if (FILE *_dbgf = std::fopen("/tmp/nfcu_pt_debug.txt", "a")) {
            std::fprintf(_dbgf, "[NFCU-PT] writing:");
            for (int _i = 0; _i < 15; ++_i) std::fprintf(_dbgf, " %02X", pt_mem_a[_i]);
            std::fprintf(_dbgf, "\n");
            std::fclose(_dbgf);
        }

        const bool pt_ok = st25r_write_pt_memory_a(pt_mem_a, sizeof(pt_mem_a));
        std::fprintf(stderr, "[NFCU-PT] write result=%d\n", (int)pt_ok);
        std::fflush(stderr);
        if (FILE *_dbgf2 = std::fopen("/tmp/nfcu_pt_debug.txt", "a")) {
            std::fprintf(_dbgf2, "[NFCU-PT] write_result=%d\n", (int)pt_ok);
            std::fclose(_dbgf2);
        }
        if (!pt_ok) return false;

        // Debug: read back PT memory via OP_READ_PT_MEMORY (0xBF).
        {
            uint8_t readop = 0xBF;
            uint8_t rbuf[15] = {0};
            struct i2c_msg rmsgs[2] = {
                {addr_, 0,        1,  (__u8*)&readop},
                {addr_, I2C_M_RD, 15, (__u8*)rbuf}
            };
            struct i2c_rdwr_ioctl_data rd = {rmsgs, 2};
            int rc = ::ioctl(fd_, I2C_RDWR, &rd);
            std::fprintf(stderr, "[NFCU-PT] readback rc=%d:", rc);
            for (int _i = 0; _i < 15; ++_i) std::fprintf(stderr, " %02X", rbuf[_i]);
            std::fprintf(stderr, "\n");
            std::fflush(stderr);
            if (FILE *_dbgf3 = std::fopen("/tmp/nfcu_pt_debug.txt", "a")) {
                std::fprintf(_dbgf3, "[NFCU-PT] readback rc=%d:", rc);
                for (int _i = 0; _i < 15; ++_i) std::fprintf(_dbgf3, " %02X", rbuf[_i]);
                std::fprintf(_dbgf3, "\n");
                std::fclose(_dbgf3);
            }
        }
        delay_ms(2);

        st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
        nfcunit_listener_running_ = true;
        nfcunit_listener_target_active_ = false;
        nfcunit_listener_wakeup_ = false;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_active_idle_ticks_ = 0;
        nfcunit_listener_bitrate_ = 0xFF;
        nfcunit_listener_irq_latch_ = 0;
        nfcunit_listener_mode_f_ = false;
        nfcunit_listener_keep_auto_collision_ = keep_auto_collision;

        return nfcunit_listener_enter_off();
    }

    bool nfcunit_start_listener_f(const uint8_t idm[8], const uint8_t pmm[8], uint16_t system_code)
    {
        if (!is_open() || !is_nfc_unit() || !idm || !pmm) return false;

        nfcunit_stop_listener();

        (void)writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(3);
        (void)writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_ISO15);
        delay_ms(3);
        (void)writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(3);

        st25r_cmd(0xD6);  // ADJUST_REGULATORS
        delay_ms(5);

        uint8_t pt_mem_f[21] = {0};
        pt_mem_f[0] = static_cast<uint8_t>((system_code >> 8) & 0xFF);
        pt_mem_f[1] = static_cast<uint8_t>(system_code & 0xFF);
        pt_mem_f[2] = 0x01;  // SENSF_RES response code
        std::memcpy(pt_mem_f + 3, idm, 8);
        std::memcpy(pt_mem_f + 11, pmm, 8);
        if (!st25r_write_pt_memory_f(pt_mem_f, sizeof(pt_mem_f))) return false;

        uint8_t tsn[12] = {0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67};
        if (!st25r_write_pt_memory_tsn(tsn, sizeof(tsn))) return false;

        // Auto response only for NFC-F: set d_ac_ap2p|d_106_ac_a, clear d_212_424_1r.
        if (!st25r_change_bits(0x08, 0x09, 0x04)) return false;
        if (!st25r_change_bits(0x12, 0x00, 0xE0)) return false;
        if (!st25r_change_bits(0x12, 0x08, 0x00)) return false;
        if (!st25r_write_reg(0x0F, 0x04)) return false;
        if (!st25r_change_bits(0x05, 0x00, 0xE0)) return false;

        st25r_write_reg(0x26, 0x00);
        st25r_write_reg(0x27, 0xFF);
        st25r_write_spaceb(0x30, 0x00);
        st25r_write_spaceb(0x31, 0x00);
        st25r_write_spaceb(0x32, 0x00);
        st25r_write_spaceb(0x33, 0x00);
        st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA

        nfcunit_listener_running_ = true;
        nfcunit_listener_target_active_ = false;
        nfcunit_listener_wakeup_ = false;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_active_idle_ticks_ = 0;
        nfcunit_listener_bitrate_ = 0xFF;
        nfcunit_listener_irq_latch_ = 0;
        nfcunit_listener_mode_f_ = true;

        return nfcunit_listener_enter_off();
    }

    bool nfcunit_stop_listener()
    {
        if (!is_open() || !is_nfc_unit()) return false;
        nfcunit_listener_running_ = false;
        nfcunit_listener_target_active_ = false;
        nfcunit_listener_wakeup_ = false;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_active_idle_ticks_ = 0;
        nfcunit_listener_bitrate_ = 0xFF;
        nfcunit_listener_irq_latch_ = 0;
        nfcunit_listener_mode_f_ = false;
        nfcunit_listener_state_ = NfcUnitListenerState::Off;

        st25r_cmd(0xC2);               // STOP_ALL_ACTIVITIES
        st25r_change_bits(0x08, 0x0D, 0x00);  // restore passive-target defaults
        st25r_write_reg(0x03, 0x00);          // mode off
        st25r_write_reg(0x02, 0x80);          // oscillator on, RF off
        st25r_cmd(0xD0);               // MASK_RECEIVE_DATA
        st25r_cmd(0xDB);               // CLEAR_FIFO
        st25r_clear_irq_regs();
        return true;
    }

    bool nfcunit_listener_running() const
    {
        return nfcunit_listener_running_;
    }

    // Initialize ST25R3916B as NFC-A reader (call once after connection/power-on)
    bool nfcunit_init_reader() { return st25r_init_nfca_reader(); }

    // Poll one listener frame. Returns true when a frame is received.
    // Output frame excludes trailing CRC_A bytes when present.
    bool nfcunit_poll_listener_frame(std::vector<uint8_t> &frame, int timeout_ms = 20)
    {
        frame.clear();
        if (!is_open() || !is_nfc_unit() || !nfcunit_listener_running_) return false;

        const auto start = std::chrono::steady_clock::now();
        while (true) {
            const NfcUnitListenerState state_before = nfcunit_listener_state_;
            switch (nfcunit_listener_state_) {
            case NfcUnitListenerState::Off:
                nfcunit_listener_update_off();
                break;
            case NfcUnitListenerState::Idle:
                nfcunit_listener_update_idle(frame);
                break;
            case NfcUnitListenerState::Ready:
                nfcunit_listener_update_ready();
                break;
            case NfcUnitListenerState::Active:
                if (nfcunit_listener_update_active(frame)) return true;
                break;
            case NfcUnitListenerState::Halt:
                nfcunit_listener_update_halt();
                break;
            }

            if (!frame.empty()) return true;

            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) break;
            if (nfcunit_listener_state_ != state_before ||
                nfcunit_listener_state_ == NfcUnitListenerState::Ready ||
                nfcunit_listener_state_ == NfcUnitListenerState::Active) {
                continue;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        return false;
    }

    // Send one listener response frame with CRC auto-appended by ST25R3916.
    bool nfcunit_send_listener_frame(const uint8_t *tx, uint8_t tx_len)
    {
        if (!is_open() || !is_nfc_unit() || !nfcunit_listener_running_) return false;
        if (nfcunit_listener_state_ != NfcUnitListenerState::Active) return false;
        if (!tx || tx_len == 0) return false;

        st25r_cmd(0xDB);  // CLEAR_FIFO
        if (!st25r_fifo_write(tx, tx_len)) return false;
        st25r_set_ntx(tx_len, 0);
        {
            uint8_t dummy = 0;
            st25r_read_reg(0x1A, dummy);
        }
        if (!st25r_cmd(0xC4)) return false;  // TRANSMIT_WITH_CRC
        (void)st25r_wait_irq(0x08, 25);      // TXE best effort
        return true;
    }

    // ── Slot selection (GroveNFC / NFC Unit) ─────────────────────────────────

    bool setSlot(uint8_t slot_index)
    {
        return writeMiscReg(i2c_reg::MISC_SLOT, slot_index);
    }

    // ── Low-level register I/O (public for diagnostics) ──────────────────────

    bool writeSysReg(uint16_t reg, uint16_t value)
    {
        if (fd_ < 0) return false;
        // Address: big-endian. Value: little-endian (same as GroveNFC Arduino driver).
        uint8_t buf[4] = {
            (uint8_t)(reg >> 8),
            (uint8_t)(reg & 0xFF),
            (uint8_t)(value & 0xFF),
            (uint8_t)(value >> 8)
        };
        return ::write(fd_, buf, 4) == 4;
    }

    bool writeMiscReg(uint16_t reg, uint8_t value)
    {
        if (fd_ < 0) return false;
        uint8_t buf[3] = {
            (uint8_t)(reg >> 8),
            (uint8_t)(reg & 0xFF),
            value
        };
        return ::write(fd_, buf, 3) == 3;
    }

    uint16_t readSysReg(uint16_t reg)
    {
        if (fd_ < 0) return 0;
        // Use I2C_RDWR (repeated-start) so no STOP is issued between the
        // register address write and the data read. GroveNFC M090 clears its
        // receive buffer on a STOP, so a plain write()+read() sequence returns
        // stale / zero data for volatile registers (STATUS, RX_LEN, DATA).
        uint8_t reg_buf[2] = {(uint8_t)(reg >> 8), (uint8_t)(reg & 0xFF)};
        uint8_t rx[2] = {0, 0};
        struct i2c_msg msgs[2] = {
            {addr_, 0,        2, (__u8*)reg_buf},
            {addr_, I2C_M_RD, 2, (__u8*)rx}
        };
        struct i2c_rdwr_ioctl_data data = {msgs, 2};
        if (::ioctl(fd_, I2C_RDWR, &data) < 0) return 0;
        return (uint16_t(rx[1]) << 8) | rx[0]; // little-endian
    }

    bool writeData(uint16_t reg, const uint8_t *data, uint16_t len)
    {
        if (fd_ < 0) return false;
        std::vector<uint8_t> buf(2u + len);
        buf[0] = (uint8_t)(reg >> 8);
        buf[1] = (uint8_t)(reg & 0xFF);
        if (len > 0) std::memcpy(buf.data() + 2, data, len);
        bool ok = ::write(fd_, buf.data(), (size_t)(2 + len)) == (ssize_t)(2 + len);
        if (len > 0) {
            std::vector<uint8_t> payload(data, data + len);
            NfcHexLog::get().log_tx("I2C", payload.data(), payload.size());
        }
        return ok;
    }

    bool readData(uint16_t reg, uint8_t *data, uint16_t len)
    {
        if (fd_ < 0) return false;
        if (len == 0) return true;
        uint8_t reg_buf[2] = {(uint8_t)(reg >> 8), (uint8_t)(reg & 0xFF)};
        struct i2c_msg msgs[2] = {
            {addr_, 0,        2,   (__u8*)reg_buf},
            {addr_, I2C_M_RD, len, (__u8*)data}
        };
        struct i2c_rdwr_ioctl_data ioctl_data = {msgs, 2};
        bool ok = ::ioctl(fd_, I2C_RDWR, &ioctl_data) >= 0;
        if (ok && len > 0) {
            std::vector<uint8_t> payload(data, data + len);
            NfcHexLog::get().log_rx("I2C", payload.data(), payload.size());
        }
        return ok;
    }

private:
    enum class NfcUnitListenerState {
        Off,
        Idle,
        Ready,
        Active,
        Halt,
    };

    int      fd_   = -1;
    uint8_t  addr_ = 0;
    std::string bus_path_;
    bool nfcunit_listener_running_ = false;
    bool nfcunit_listener_target_active_ = false;
    bool nfcunit_listener_wakeup_ = false;
    bool nfcunit_listener_data_flag_ = false;
    bool nfcunit_listener_mode_f_ = false;
    bool nfcunit_listener_keep_auto_collision_ = false;
    uint16_t nfcunit_listener_active_idle_ticks_ = 0;
    uint8_t nfcunit_listener_bitrate_ = 0xFF;  // 0:106, 1:212, 2:424, 0xFF:invalid
    uint32_t nfcunit_listener_irq_latch_ = 0;
    uint32_t nfcunit_listener_irq_mask_ = 0xFFFFFFFFu;
    NfcUnitListenerState nfcunit_listener_state_ = NfcUnitListenerState::Off;

    // ── ST25R3916B I2C protocol helpers (M5 NFC Unit at 0x50) ────────────────
    //
    // The ST25R3916B I2C command-byte encoding:
    //   0x00-0x3F  Space-A register (addr in [5:0]); write = [addr][data], read
    //              via I2C_RDWR repeated-start [addr] → read [data]
    //   0x40-0x7F  Space-B register (addr in [5:0]); same R/W pattern
    //   0x80       FIFO access; write = [0x80][data…], read via repeated-start
    //   0xC0-0xFF  Direct command (single write byte, no data)
    //
    // Key registers:
    //   0x02 OP_CONTROL: bit7=en(osc), bit6=rx_en, bit3=tx_en(RF field)
    //   0x03 MODE:       bits[6:3]=0x1 → ISO14443A initiator
    //   0x04 BIT_RATE:   0x00 = 106kbps TX+RX
    //   0x05 ISO14443A_NFC: bit0=antcl (anticollision enable)
    //   0x1A IRQ_MAIN:   bit4=rxe(end-of-receive), bit3=txe, bit2=col(collision)
    //   0x1E FIFO_STATUS1: RX FIFO byte count (lower 8 bits)
    //   0x22/0x23 NUM_TX_BYTES: TX byte count + incomplete-bits

    bool st25r_write_reg(uint8_t reg, uint8_t val)
    {
        uint8_t buf[2] = {(uint8_t)(reg & 0x3F), val};
        return ::write(fd_, buf, 2) == 2;
    }

    bool st25r_read_reg(uint8_t reg, uint8_t &val)
    {
        uint8_t rb = (reg & 0x3F) | 0x40;  // bit6=1 indicates register read in ST25R3916B I2C protocol
        uint8_t data = 0;
        struct i2c_msg msgs[2] = {
            {addr_, 0,        1, (__u8*)&rb},
            {addr_, I2C_M_RD, 1, (__u8*)&data}
        };
        struct i2c_rdwr_ioctl_data d = {msgs, 2};
        if (::ioctl(fd_, I2C_RDWR, &d) < 0) return false;
        val = data;
        return true;
    }

    bool st25r_cmd(uint8_t cmd)
    {
        return ::write(fd_, &cmd, 1) == 1;
    }

    bool st25r_fifo_write(const uint8_t *data, uint8_t len)
    {
        std::vector<uint8_t> buf;
        buf.push_back(0x80);
        buf.insert(buf.end(), data, data + len);
        return ::write(fd_, buf.data(), buf.size()) == (ssize_t)buf.size();
    }

    bool st25r_fifo_read(uint8_t *data, uint8_t len)
    {
        // OP_READ_FIFO = 0x9F (NOT 0x80! 0x80 = OP_LOAD_FIFO, 0xC0 = OP_DIRECT_COMMAND)
        uint8_t op = 0x9F;
        struct i2c_msg msgs[2] = {
            {addr_, 0,        1,   (__u8*)&op},
            {addr_, I2C_M_RD, len, (__u8*)data}
        };
        struct i2c_rdwr_ioctl_data d = {msgs, 2};
        return ::ioctl(fd_, I2C_RDWR, &d) >= 0;
    }

    // Set NUM_TX_BYTES registers (0x22-0x23).
    // Format: 16-bit big-endian value = (bytes_count << 3) | last_bits
    // CMD_TRANSMIT_WITH_CRC (0xC4) appends CRC automatically; do NOT include CRC in count.
    // CMD_TRANSMIT_WITHOUT_CRC (0xC5) transmits exactly bytes_count bytes.
    void st25r_set_ntx(uint16_t bytes_count, uint8_t last_bits = 0)
    {
        uint16_t v = ((bytes_count & 0x1FF) << 3) | (last_bits & 0x07);
        st25r_write_reg(0x22, (uint8_t)((v >> 8) & 0xFF));
        st25r_write_reg(0x23, (uint8_t)(v & 0xFF));
    }

    bool st25r_write_pt_memory_a(const uint8_t *data, uint8_t len)
    {
        if (!data || len == 0 || len > 15) return false;
        std::vector<uint8_t> buf;
        buf.reserve(static_cast<size_t>(len) + 1);
        buf.push_back(0xA0);  // OP_LOAD_PT_MEMORY_A_CONFIG
        buf.insert(buf.end(), data, data + len);
        return ::write(fd_, buf.data(), buf.size()) == static_cast<ssize_t>(buf.size());
    }

    bool st25r_write_pt_memory_f(const uint8_t *data, uint8_t len)
    {
        if (!data || len == 0 || len > 21) return false;
        std::vector<uint8_t> buf;
        buf.reserve(static_cast<size_t>(len) + 1);
        buf.push_back(0xA8);  // OP_LOAD_PT_MEMORY_F_CONFIG
        buf.insert(buf.end(), data, data + len);
        return ::write(fd_, buf.data(), buf.size()) == static_cast<ssize_t>(buf.size());
    }

    bool st25r_write_pt_memory_tsn(const uint8_t *data, uint8_t len)
    {
        if (!data || len == 0 || len > 12) return false;
        std::vector<uint8_t> buf;
        buf.reserve(static_cast<size_t>(len) + 1);
        buf.push_back(0xAC);  // OP_LOAD_PT_MEMORY_TSN_DATA
        buf.insert(buf.end(), data, data + len);
        return ::write(fd_, buf.data(), buf.size()) == static_cast<ssize_t>(buf.size());
    }

    bool st25r_change_bits(uint8_t reg, uint8_t set_mask, uint8_t clear_mask)
    {
        uint8_t v = 0;
        if (!st25r_read_reg(reg, v)) return false;
        v = static_cast<uint8_t>((v | set_mask) & static_cast<uint8_t>(~clear_mask));
        return st25r_write_reg(reg, v);
    }

    uint32_t st25r_read_irq32()
    {
        uint8_t m = 0, t = 0, e = 0, p = 0;
        if (!st25r_read_reg(0x1A, m)) return 0;
        if (!st25r_read_reg(0x1B, t)) return 0;
        if (!st25r_read_reg(0x1C, e)) return 0;
        if (!st25r_read_reg(0x1D, p)) return 0;
        uint32_t irq32 = 0;
        irq32 |= static_cast<uint32_t>(m) << 24;
        irq32 |= static_cast<uint32_t>(t) << 16;
        irq32 |= static_cast<uint32_t>(e) << 8;
        irq32 |= static_cast<uint32_t>(p);
        return irq32;
    }

    static constexpr uint32_t ST25R_I_OSC32     = (0x80u << 24);
    static constexpr uint32_t ST25R_I_RXS32     = (0x20u << 24);
    static constexpr uint32_t ST25R_I_RXE32     = (0x10u << 24);
    static constexpr uint32_t ST25R_I_EON32     = (0x10u << 16);
    static constexpr uint32_t ST25R_I_EOF32     = (0x08u << 16);
    static constexpr uint32_t ST25R_I_NFCT32    = (0x01u << 16);
    static constexpr uint32_t ST25R_I_CRC32     = (0x80u << 8);
    static constexpr uint32_t ST25R_I_PAR32     = (0x40u << 8);
    static constexpr uint32_t ST25R_I_ERR232    = (0x20u << 8);
    static constexpr uint32_t ST25R_I_ERR132    = (0x10u << 8);
    static constexpr uint32_t ST25R_I_RXE_PTA32 = 0x10u;
    static constexpr uint32_t ST25R_I_WU_F32    = 0x08u;
    static constexpr uint32_t ST25R_I_WU_AX32   = 0x02u;
    static constexpr uint32_t ST25R_I_WU_A32    = 0x01u;

    static constexpr uint8_t ST25R_MODE_BITRATE_DETECTION = 0xC8;  // targ | (0x09 << 3)
    static constexpr uint8_t ST25R_MODE_LISTEN_NFCA       = 0x88;  // targ | (0x01 << 3)

    static constexpr uint32_t ST25R_LISTENER_MODE_IRQ = ST25R_I_WU_A32 | ST25R_I_WU_AX32 | ST25R_I_WU_F32 | ST25R_I_RXE_PTA32;
    static constexpr uint32_t ST25R_LISTENER_DEFAULT_IRQ =
        ST25R_I_NFCT32 | ST25R_I_RXS32 | ST25R_I_EON32 | ST25R_I_EOF32 |
        ST25R_I_CRC32 | ST25R_I_ERR132 | ST25R_I_ERR232 | ST25R_I_PAR32;

    void nfcunit_listener_trace(const char *label, uint32_t detail = 0xFFFFFFFFu)
    {
        if (detail == 0xFFFFFFFFu) {
            std::fprintf(stderr, "[NFC-EMU] %s\n", label);
        } else {
            std::fprintf(stderr, "[NFC-EMU] %s 0x%08X\n", label, detail);
        }
    }

    void nfcunit_listener_trace_bytes(const char *label, const uint8_t *data, size_t len, size_t max_show = 24)
    {
        std::fprintf(stderr, "[NFC-EMU] %s len=%zu", label, len);
        const size_t show = std::min(len, max_show);
        for (size_t i = 0; i < show; ++i) {
            std::fprintf(stderr, " %02X", data[i]);
        }
        if (len > show) {
            std::fprintf(stderr, " ...");
        }
        std::fprintf(stderr, "\n");
    }

    bool st25r_read_mask_interrupts(uint32_t &value)
    {
        uint8_t main = 0, timer = 0, err = 0, pta = 0;
        if (!st25r_read_reg(0x16, main)) return false;
        if (!st25r_read_reg(0x17, timer)) return false;
        if (!st25r_read_reg(0x18, err)) return false;
        if (!st25r_read_reg(0x19, pta)) return false;
        value = (static_cast<uint32_t>(main) << 24) |
                (static_cast<uint32_t>(timer) << 16) |
                (static_cast<uint32_t>(err) << 8) |
                static_cast<uint32_t>(pta);
        return true;
    }

    bool st25r_write_mask_interrupts(uint32_t value)
    {
        const bool ok = st25r_write_reg(0x16, static_cast<uint8_t>((value >> 24) & 0xFF)) &&
                        st25r_write_reg(0x17, static_cast<uint8_t>((value >> 16) & 0xFF)) &&
                        st25r_write_reg(0x18, static_cast<uint8_t>((value >> 8) & 0xFF)) &&
                        st25r_write_reg(0x19, static_cast<uint8_t>(value & 0xFF));
        if (ok) nfcunit_listener_irq_mask_ = value;
        return ok;
    }

    bool st25r_enable_interrupts(uint32_t mask_bits)
    {
        uint32_t current = nfcunit_listener_irq_mask_;
        if (current == 0xFFFFFFFFu) {
            (void)st25r_read_mask_interrupts(current);
        }
        return st25r_write_mask_interrupts(current & ~mask_bits);
    }

    bool st25r_disable_interrupts(uint32_t mask_bits)
    {
        uint32_t current = nfcunit_listener_irq_mask_;
        if (current == 0xFFFFFFFFu) {
            (void)st25r_read_mask_interrupts(current);
        }
        return st25r_write_mask_interrupts(current | mask_bits);
    }

    uint32_t nfcunit_listener_take_irq(uint32_t mask_bits)
    {
        const uint32_t latest = st25r_read_irq32();
        if (latest) nfcunit_listener_irq_latch_ |= latest;

        const uint32_t hit = nfcunit_listener_irq_latch_ & mask_bits;
        if (hit) {
            nfcunit_listener_irq_latch_ &= ~hit;
        }
        return hit;
    }

    bool nfcunit_listener_is_extra_field()
    {
        uint8_t v = 0;
        return st25r_read_reg(0x31, v) && ((v & 0x40u) != 0);
    }

    bool nfcunit_listener_enter_off()
    {
        if (!is_open() || !is_nfc_unit()) return false;

        nfcunit_listener_trace("state -> OFF");

        nfcunit_listener_state_ = NfcUnitListenerState::Off;
        nfcunit_listener_target_active_ = false;
        nfcunit_listener_wakeup_ = false;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_active_idle_ticks_ = 0;
        nfcunit_listener_bitrate_ = 0xFF;

        st25r_cmd(0xC2);  // CMD_STOP_ALL_ACTIVITIES
        st25r_change_bits(0x02, 0x03, 0x00);  // enable external field detector auto mode
        st25r_change_bits(0x02, 0x40, 0x00);  // set rx_en

        if (nfcunit_listener_mode_f_) {
            st25r_change_bits(0x08, 0x09, 0x04);  // Enable auto response for NFC-F only
        } else {
            st25r_change_bits(0x08, 0x00, 0x01);  // Enable auto response for NFC-A
        }
        st25r_cmd(0xCD);                      // CMD_GO_TO_SENSE
        st25r_change_bits(0x05, 0x00, 0x20);  // clear nfc_f0

        st25r_write_mask_interrupts(0xFFFFFFFFu);
        st25r_clear_irq_regs();
        st25r_enable_interrupts(ST25R_I_OSC32 | ST25R_LISTENER_DEFAULT_IRQ | ST25R_LISTENER_MODE_IRQ);

        st25r_change_bits(0x0A, 0x80, 0x00);  // set no_crc_rx
        st25r_change_bits(0x03, nfcunit_listener_mode_f_ ? 0xE0 : 0xC8,
                  nfcunit_listener_mode_f_ ? 0x18 : 0x30);

        if (nfcunit_listener_is_extra_field()) {
            return nfcunit_listener_enter_idle();
        }
        // Keep oscillator/RX on to avoid missing short reader polling bursts.
        st25r_change_bits(0x02, 0xC0, 0x00);
        return true;
    }

    bool nfcunit_listener_enter_idle()
    {
        if (!is_open() || !is_nfc_unit()) return false;

        nfcunit_listener_trace("state -> IDLE");

        uint8_t op = 0;
        uint8_t aux = 0;
        nfcunit_listener_state_ = NfcUnitListenerState::Idle;
        nfcunit_listener_target_active_ = false;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_active_idle_ticks_ = 0;

        if (st25r_read_reg(0x02, op) && ((op & 0x80u) == 0)) {
            st25r_change_bits(0x02, 0xC0, 0x00);  // set en|rx_en
            if (st25r_read_reg(0x31, aux) && ((aux & 0x10u) == 0)) {
                if ((st25r_wait_irq(0x80, 1000) & 0x80u) == 0) {
                    return nfcunit_listener_enter_off();
                }
            }
        } else {
            (void)nfcunit_listener_take_irq(ST25R_I_OSC32);
        }

        st25r_change_bits(0x0A, 0x80, 0x00);  // set no_crc_rx

        if (nfcunit_listener_mode_f_) {
            st25r_change_bits(0x08, 0x09, 0x04);  // Enable auto response for NFC-F only
        } else {
            st25r_change_bits(0x08, 0x00, 0x01);  // Enable auto response for NFC-A
        }
        st25r_cmd(0xCD);                      // GO_TO_SENSE

        st25r_cmd(0xDB);  // CLEAR_FIFO
        st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA

        nfcunit_listener_wakeup_ = false;
        return true;
    }

    bool nfcunit_listener_enter_ready()
    {
        if (!is_open() || !is_nfc_unit()) return false;

        nfcunit_listener_trace("state -> READY");

        nfcunit_listener_state_ = NfcUnitListenerState::Ready;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_target_active_ = false;

        if (nfcunit_listener_take_irq(ST25R_I_EOF32)) {
            return nfcunit_listener_enter_off();
        }

        st25r_change_bits(0x0A, 0x00, 0x80);  // clear no_crc_rx
        if (nfcunit_listener_bitrate_ <= 2) {
            const uint8_t br = nfcunit_listener_bitrate_ & 0x03u;
            st25r_write_reg(0x04, static_cast<uint8_t>((br << 4) | br));
        }
        st25r_change_bits(0x02, 0x00, 0x04);  // clear wakeup bit
        st25r_write_reg(0x03, nfcunit_listener_mode_f_ ? 0xA0 : ST25R_MODE_LISTEN_NFCA);
        return true;
    }

    bool nfcunit_listener_enter_active()
    {
        if (!is_open() || !is_nfc_unit()) return false;

        nfcunit_listener_trace("state -> ACTIVE");

        nfcunit_listener_state_ = NfcUnitListenerState::Active;
        nfcunit_listener_target_active_ = true;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_active_idle_ticks_ = 0;

        if (nfcunit_listener_mode_f_) {
            st25r_change_bits(0x08, 0x04, 0x09);  // Disable NFC-F auto response
        } else {
            st25r_change_bits(0x08, 0x01, 0x00);  // Disable auto response for NFC-A
        }
        (void)nfcunit_listener_take_irq(ST25R_I_PAR32 | ST25R_I_CRC32 | ST25R_I_ERR232 | ST25R_I_ERR132);
        st25r_enable_interrupts(ST25R_I_RXE32);
        return true;
    }

    bool nfcunit_listener_enter_halt()
    {
        if (!is_open() || !is_nfc_unit()) return false;

        nfcunit_listener_trace("state -> HALT");

        nfcunit_listener_state_ = NfcUnitListenerState::Halt;
        nfcunit_listener_target_active_ = false;
        nfcunit_listener_data_flag_ = false;
        nfcunit_listener_active_idle_ticks_ = 0;

        if (nfcunit_listener_mode_f_) {
            st25r_change_bits(0x08, 0x09, 0x04);  // Enable auto response for NFC-F only
        } else {
            st25r_change_bits(0x08, 0x00, 0x01);  // Enable auto response for NFC-A
        }
        st25r_cmd(0xCE);                      // GO_TO_SLEEP
        st25r_change_bits(0x03, nfcunit_listener_mode_f_ ? 0xE0 : 0xC8,
                          nfcunit_listener_mode_f_ ? 0x18 : 0x30);
        st25r_change_bits(0x05, 0x00, 0x20);  // clear nfc_f0
        st25r_cmd(0xD1);                      // UNMASK_RECEIVE_DATA
        st25r_write_mask_interrupts(0xFFFFFFFFu);
        st25r_enable_interrupts(ST25R_LISTENER_DEFAULT_IRQ | ST25R_LISTENER_MODE_IRQ);

        if (!nfcunit_listener_is_extra_field()) {
            return nfcunit_listener_enter_off();
        }
        return true;
    }

    bool nfcunit_listener_update_off()
    {
        if (nfcunit_listener_take_irq(ST25R_I_EON32) & ST25R_I_EON32) {
            nfcunit_listener_trace("irq EON");
            return nfcunit_listener_enter_idle();
        }
        return true;
    }

    bool nfcunit_listener_update_idle(std::vector<uint8_t> &frame)
    {
        frame.clear();
        const uint32_t mode_wake = nfcunit_listener_mode_f_ ? ST25R_I_WU_F32 : ST25R_I_RXE_PTA32;
        uint32_t irq32 = nfcunit_listener_take_irq(ST25R_I_NFCT32 | ST25R_I_RXE32 | ST25R_I_EOF32 | mode_wake);
        if (!irq32) return true;
        nfcunit_listener_trace("idle irq", irq32);

        if (irq32 & ST25R_I_NFCT32) {
            uint8_t br = 0;
            if (st25r_read_reg(0x24, br)) {
                br = static_cast<uint8_t>((br >> 4) & 0x03);
                if (br > 2) br = 2;
                nfcunit_listener_bitrate_ = br;
                nfcunit_listener_trace("irq NFCT bitrate", static_cast<uint32_t>(br));
            }
        }

        if ((irq32 & ST25R_I_EOF32) && !nfcunit_listener_data_flag_) {
            uint16_t fifo_cnt = 0;
            if (st25r_read_fifo_count(fifo_cnt) && fifo_cnt > 0) {
                uint8_t raw[16] = {0};
                const uint16_t to_read = std::min<uint16_t>(fifo_cnt, sizeof(raw));
                if (st25r_fifo_read(raw, static_cast<uint8_t>(to_read))) {
                    nfcunit_listener_trace_bytes("idle eof raw", raw, to_read);
                    if ((to_read > 0) && (raw[0] == 0x26u || raw[0] == 0x52u)) {
                        nfcunit_listener_bitrate_ = 0;
                        nfcunit_listener_trace("idle short poll", raw[0]);
                        st25r_cmd(0xDB);  // CLEAR_FIFO
                        st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
                        return nfcunit_listener_enter_ready();
                    }

                    // Some readers send anti-collision/select frames directly after short poll.
                    // Keep those frames and hand them to the upper emulation worker immediately.
                    if (to_read > 0) {
                        const uint16_t use_len = (to_read > 2) ? static_cast<uint16_t>(to_read - 2) : to_read;
                        if (use_len > 0) {
                            frame.assign(raw, raw + use_len);
                            nfcunit_listener_data_flag_ = true;
                            nfcunit_listener_trace("idle eof frame", use_len);
                            st25r_cmd(0xDB);  // CLEAR_FIFO
                            st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
                            (void)nfcunit_listener_enter_active();
                            return true;
                        }
                    }
                }
            }
            // Keep listener alive for follow-up frames (e.g. anti-collision/select)
            // instead of resetting to OFF on every EOF.
            st25r_cmd(0xDB);  // CLEAR_FIFO
            st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
            nfcunit_listener_trace("idle eof -> keep");
            return true;
        }

        if ((irq32 & ST25R_I_RXE32) && nfcunit_listener_bitrate_ != 0xFF) {
            irq32 |= nfcunit_listener_take_irq(ST25R_I_RXE32 | ST25R_I_EOF32 | ST25R_I_CRC32 | ST25R_I_PAR32 |
                                               ST25R_I_ERR232 | ST25R_I_ERR132);
            const uint32_t err_bits = irq32 & (ST25R_I_CRC32 | ST25R_I_PAR32 | ST25R_I_ERR132 | ST25R_I_ERR232);
            if (err_bits) {
                nfcunit_listener_trace("idle err bits", err_bits);
            }
            if (irq32 & (ST25R_I_CRC32 | ST25R_I_PAR32 | ST25R_I_ERR132)) {
                st25r_cmd(0xDB);  // CLEAR_FIFO
                st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
                st25r_change_bits(0x02, 0x00, 0x08);  // clear tx_en
                return true;
            }

            uint16_t fifo_cnt = 0;
            if (!st25r_read_fifo_count(fifo_cnt)) {
                nfcunit_listener_trace("idle fifo read failed");
            } else {
                nfcunit_listener_trace("idle fifo cnt", fifo_cnt);
            }
            if (fifo_cnt > 0) {
                uint8_t raw[96] = {0};
                const uint16_t to_read = std::min<uint16_t>(fifo_cnt, sizeof(raw));
                if (st25r_fifo_read(raw, static_cast<uint8_t>(to_read))) {
                    nfcunit_listener_trace_bytes("idle fifo raw", raw, to_read);
                    const uint16_t use_len = (to_read > 2) ? static_cast<uint16_t>(to_read - 2) : to_read;
                    nfcunit_listener_data_flag_ = (use_len > 0);
                } else {
                    nfcunit_listener_trace("idle fifo read op failed", to_read);
                }
            }
        }

        if (nfcunit_listener_mode_f_ && (irq32 & ST25R_I_WU_F32) && nfcunit_listener_bitrate_ != 0xFF) {
            return nfcunit_listener_enter_ready();
        }

        if (!nfcunit_listener_mode_f_ && (irq32 & ST25R_I_RXE_PTA32) && nfcunit_listener_bitrate_ == 0) {
            uint8_t pta = 0;
            if (st25r_read_reg(0x21, pta)) {
                nfcunit_listener_trace("idle pta", pta);
                if ((pta & 0x0Fu) > 0x01u) {
                    return nfcunit_listener_enter_ready();
                }
            }
        }

        return true;
    }

    bool nfcunit_listener_update_ready()
    {
        const uint32_t wake_irq = nfcunit_listener_mode_f_ ? ST25R_I_WU_F32 :
                      (nfcunit_listener_wakeup_ ? ST25R_I_WU_AX32 : ST25R_I_WU_A32);
        uint32_t irq32 = nfcunit_listener_take_irq(ST25R_I_EOF32 | wake_irq);
        if (!irq32) return true;

        if (irq32 & ST25R_I_EOF32) {
            st25r_cmd(0xDB);  // CLEAR_FIFO
            st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
            nfcunit_listener_trace("ready eof -> idle");
            return nfcunit_listener_enter_idle();
        }
        if (irq32 & (ST25R_I_WU_A32 | ST25R_I_WU_AX32 | ST25R_I_WU_F32)) {
            nfcunit_listener_trace("irq WAKE", irq32);
            if (nfcunit_listener_keep_auto_collision_) return true;
            return nfcunit_listener_enter_active();
        }
        return true;
    }

    bool nfcunit_listener_update_active(std::vector<uint8_t> &frame)
    {
        frame.clear();
        uint32_t irq32 = nfcunit_listener_take_irq(ST25R_I_EOF32 | ST25R_I_RXE32);
        if (!irq32) return false;
        nfcunit_listener_trace("active irq", irq32);

        if (irq32 & ST25R_I_RXE32) {
            irq32 |= nfcunit_listener_take_irq(ST25R_I_PAR32 | ST25R_I_CRC32 | ST25R_I_ERR232 | ST25R_I_ERR132);

            uint16_t fifo_cnt = 0;
            if (!st25r_read_fifo_count(fifo_cnt) || fifo_cnt == 0) {
                return false;
            }

            const bool bad_frame = nfcunit_listener_mode_f_
                ? (irq32 & (ST25R_I_CRC32 | ST25R_I_ERR132 | ST25R_I_ERR232))
                : ((irq32 & (ST25R_I_PAR32 | ST25R_I_CRC32 | ST25R_I_ERR132 | ST25R_I_ERR232)) || fifo_cnt <= 2);
            if (bad_frame) {
                uint8_t raw[96] = {0};
                const uint16_t to_read = std::min<uint16_t>(fifo_cnt, sizeof(raw));
                (void)st25r_fifo_read(raw, static_cast<uint8_t>(to_read));

                st25r_cmd(0xDB);  // CLEAR_FIFO
                st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
                if (nfcunit_listener_wakeup_) {
                    (void)nfcunit_listener_enter_halt();
                } else {
                    (void)nfcunit_listener_enter_idle();
                }
                return false;
            }

            const uint16_t payload_len = nfcunit_listener_mode_f_ ? fifo_cnt : static_cast<uint16_t>(fifo_cnt - 2);
            const uint16_t to_read = std::min<uint16_t>(payload_len, 96);
            uint8_t raw[96] = {0};
            if (st25r_fifo_read(raw, static_cast<uint8_t>(to_read))) {
                nfcunit_listener_data_flag_ = true;
                frame.assign(raw, raw + to_read);
                nfcunit_listener_trace("rx frame bytes", static_cast<uint32_t>(to_read));
                if (!frame.empty()) return true;
            }
        }

        if (irq32 & ST25R_I_EOF32) {
            nfcunit_listener_trace("active eof -> off");
            (void)nfcunit_listener_enter_off();
            return false;
        }

        return false;
    }

    bool nfcunit_listener_update_halt()
    {
        uint32_t irq32 = nfcunit_listener_take_irq(ST25R_I_NFCT32 | ST25R_I_RXE32 | ST25R_I_EOF32 | ST25R_I_RXE_PTA32);
        if (!irq32) return true;

        if ((irq32 & ST25R_I_NFCT32) && nfcunit_listener_bitrate_ == 0xFF) {
            uint8_t br = 0;
            if (st25r_read_reg(0x24, br)) {
                br = static_cast<uint8_t>((br >> 4) & 0x03);
                if (br > 2) br = 2;
                nfcunit_listener_bitrate_ = br;
            }
        }

        if (irq32 & ST25R_I_EOF32) {
            nfcunit_listener_trace("halt eof -> off");
            return nfcunit_listener_enter_off();
        }

        if ((irq32 & ST25R_I_RXE32) && nfcunit_listener_bitrate_ != 0xFF) {
            st25r_cmd(0xDB);  // CLEAR_FIFO
            st25r_cmd(0xD1);  // UNMASK_RECEIVE_DATA
            return true;
        }

        if ((irq32 & ST25R_I_RXE_PTA32) && nfcunit_listener_bitrate_ == 0) {
            uint8_t pta = 0;
            if (st25r_read_reg(0x21, pta) && ((pta & 0x0Fu) > 0x09u)) {
                nfcunit_listener_wakeup_ = true;
                return nfcunit_listener_enter_ready();
            }
        }

        return true;
    }

    static constexpr uint8_t ST25R_IRQ_MAIN_FWL = 0x40;
    static constexpr uint8_t ST25R_IRQ_MAIN_RXS = 0x20;
    static constexpr uint8_t ST25R_IRQ_MAIN_RXE = 0x10;
    static constexpr uint8_t ST25R_IRQ_MAIN_TXE = 0x08;
    static constexpr uint8_t ST25R_IRQ_MAIN_COL = 0x04;

    static constexpr uint8_t ST25R_IRQ_TIMER_NFC_NRE = 0x40;

    struct St25rIrqStatus {
        uint8_t main = 0;
        uint8_t timer_nfc = 0;
        uint8_t error_wup = 0;
        uint8_t target = 0;
    };

    uint32_t st25r_ms_to_64fc(int timeout_ms)
    {
        if (timeout_ms <= 0) return 1;
        const uint64_t raw = (static_cast<uint64_t>(timeout_ms) * 13560ULL + 63ULL) / 64ULL;
        return static_cast<uint32_t>(std::min<uint64_t>(raw, 0xFFFFULL));
    }

    void st25r_clear_irq_regs()
    {
        uint8_t dummy = 0;
        st25r_read_reg(0x1A, dummy);
        st25r_read_reg(0x1B, dummy);
        st25r_read_reg(0x1C, dummy);
        st25r_read_reg(0x1D, dummy);
    }

    bool st25r_config_nfca_rx_timers(int timeout_ms)
    {
        // Match the RFAL default NFCA receive path closely enough for magic-card
        // probing: 64/fc steps, NRT tied to the end of TX, tiny MRT.
        if (!st25r_write_reg(0x12, 0x00)) return false;
        if (!st25r_write_reg(0x0F, 0x01)) return false;

        const uint32_t nrt_64fc = st25r_ms_to_64fc(timeout_ms);
        if (!st25r_write_reg(0x10, static_cast<uint8_t>((nrt_64fc >> 8) & 0xFF))) return false;
        if (!st25r_write_reg(0x11, static_cast<uint8_t>(nrt_64fc & 0xFF))) return false;
        return true;
    }

    St25rIrqStatus st25r_read_irq_status(bool include_error = false)
    {
        St25rIrqStatus irq;
        st25r_read_reg(0x1A, irq.main);
        st25r_read_reg(0x1B, irq.timer_nfc);
        if (include_error) st25r_read_reg(0x1C, irq.error_wup);
        return irq;
    }

    bool st25r_wait_for_nfca_rx(St25rIrqStatus &first_irq,
                                St25rIrqStatus &last_irq,
                                int timeout_ms)
    {
        auto start = std::chrono::steady_clock::now();
        bool saw_rxs = false;

        while (true) {
            St25rIrqStatus irq = st25r_read_irq_status(false);
            if (!saw_rxs && (irq.main || irq.timer_nfc)) first_irq = irq;
            if (irq.main & ST25R_IRQ_MAIN_COL) {
                last_irq = irq;
                return false;
            }
            if (!saw_rxs) {
                if ((irq.timer_nfc & ST25R_IRQ_TIMER_NFC_NRE) && !(irq.main & ST25R_IRQ_MAIN_RXS)) {
                    last_irq = irq;
                    return false;
                }
                if (irq.main & (ST25R_IRQ_MAIN_RXS | ST25R_IRQ_MAIN_RXE)) {
                    saw_rxs = true;
                    if (irq.main & ST25R_IRQ_MAIN_RXE) {
                        last_irq = irq;
                        return true;
                    }
                }
            } else {
                if (irq.main & ST25R_IRQ_MAIN_RXE) {
                    last_irq = irq;
                    return true;
                }
                if (irq.timer_nfc & ST25R_IRQ_TIMER_NFC_NRE) {
                    last_irq = irq;
                    return false;
                }
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) {
                last_irq = irq;
                return false;
            }
        }
    }

    bool st25r_read_fifo_count(uint16_t &fifo_cnt)
    {
        uint8_t fifo_lo = 0;
        uint8_t fifo_hi = 0;
        if (!st25r_read_reg(0x1E, fifo_lo)) return false;
        if (!st25r_read_reg(0x1F, fifo_hi)) return false;
        fifo_cnt = static_cast<uint16_t>((static_cast<uint16_t>((fifo_hi >> 6) & 0x03) << 8) | fifo_lo);
        return true;
    }

    bool st25r_wait_fifo_after_missed_rxe(uint16_t &fifo_cnt, int window_us = 1800)
    {
        fifo_cnt = 0;
        auto start = std::chrono::steady_clock::now();
        while (true) {
            if (!st25r_read_fifo_count(fifo_cnt)) return false;
            if (fifo_cnt > 0) return true;

            const auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed_us >= window_us) return false;
        }
    }

    // Poll IRQ_MAIN (0x1A) until `mask` bits are set or `timeout_ms` expires.
    // Returns the IRQ_MAIN byte (0 on timeout).
    uint8_t st25r_wait_irq(uint8_t mask, int timeout_ms)
    {
        // No sleep between polls: ISO14443A card responses start within ~302µs
        // after TX ends. With delay_ms(1) the RECEIVE command would arrive after
        // the card is already done. Tight I2C polling (~200µs/read) is needed.
        auto start = std::chrono::steady_clock::now();
        while (true) {
            uint8_t irq = 0;
            st25r_read_reg(0x1A, irq);
            if (irq & mask) return irq;
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) return 0;
            // No sleep — tight polling required for NFC timing
        }
    }

    // ── ISO15693 / NFC-V helpers ──────────────────────────────────────────────

    // Write a Space-B register via the ST25R3916B I2C protocol.
    // Space-B access: [0xFB, reg&0x3F, value]
    bool st25r_write_spaceb(uint8_t reg, uint8_t val)
    {
        uint8_t buf[3] = {0xFB, (uint8_t)(reg & 0x3F), val};
        return ::write(fd_, buf, 3) == 3;
    }

    // ISO15693 CRC-16 (poly=0x8408 reflected 0x1021, init=0xFFFF, xor-out=0xFFFF)
    static uint16_t crc16_iso15693(const uint8_t *data, size_t len)
    {
        uint16_t crc = 0xFFFF;
        for (size_t i = 0; i < len; i++) {
            uint8_t b = data[i];
            for (int j = 0; j < 8; j++) {
                uint8_t mix = (uint8_t)((crc ^ b) & 1);
                crc >>= 1;
                if (mix) crc ^= 0x8408;
                b >>= 1;
            }
        }
        return crc ^ 0xFFFF;
    }

    // Encode data bytes with ISO15693 1-of-4 PPM (SubCarrierStream TX).
    // Prepends SOF (0x21), appends CRC16 + EOF (0x04).
    // out must be at least 1 + (len+2)*4 + 1 bytes.
    // Returns encoded length.
    static uint8_t encode_nfcv_1of4(uint8_t *out, const uint8_t *data, uint8_t len)
    {
        static const uint8_t SYM4[4] = {0x02, 0x08, 0x20, 0x80};
        uint16_t crc = crc16_iso15693(data, len);
        // Build frame: data + CRC
        uint8_t frame[64];
        uint8_t flen = 0;
        for (uint8_t i = 0; i < len && flen < 60; i++) frame[flen++] = data[i];
        frame[flen++] = (uint8_t)(crc & 0xFF);
        frame[flen++] = (uint8_t)(crc >> 8);
        // Encode
        uint8_t pos = 0;
        out[pos++] = 0x21;  // SOF_1OF4
        for (uint8_t i = 0; i < flen; i++) {
            uint8_t b = frame[i];
            for (int j = 0; j < 4; j++) {
                out[pos++] = SYM4[b & 3];
                b >>= 2;
            }
        }
        out[pos++] = 0x04;  // EOF
        return pos;
    }

    // Decode Manchester-encoded ISO15693 response (SubCarrierStream RX).
    // buf/len = raw FIFO bytes; out must be >= 16 bytes; out_len = payload bytes (excl CRC).
    // Returns true on success (SOF ok, no collision, CRC matches).
    static bool decode_vicc_manchester(const uint8_t *buf, uint8_t len,
                                       uint8_t *out, uint8_t &out_len)
    {
        if (!buf || len == 0) return false;
        if ((buf[0] & 0x1F) != 0x17) return false;  // SOF check

        const uint32_t manBits     = (uint32_t)len * 8;
        const uint32_t maxPayBits  = (manBits > 5) ? ((manBits - 5) / 2) : 0;
        const uint32_t outBufLen   = (maxPayBits + 7) / 8;
        if (outBufLen == 0) return false;

        std::memset(out, 0, outBufLen < 32 ? outBufLen : 32);

        uint16_t mp = 5;   // Manchester bit position (after 5-bit SOF)
        uint16_t bp = 0;   // Payload bit position

        for (; mp < (uint16_t)(manBits - 2); mp += 2) {
            bool isEOF = false;
            uint8_t man = (buf[mp / 8] >> (mp % 8)) & 1;
            man |= (uint8_t)(((buf[(mp + 1) / 8] >> ((mp + 1) % 8)) & 1) << 1);

            if (man == 1) {
                bp++;
            } else if (man == 2) {
                uint16_t bpos = bp / 8;
                if (bpos < outBufLen && bpos < 32) out[bpos] |= (uint8_t)(1 << (bp % 8));
                bp++;
            }

            if ((bp % 8) == 0) {
                uint16_t byte_pos = (uint16_t)(mp / 8);
                if (byte_pos + 1 < len) {
                    if (((buf[byte_pos] & 0xE0) == 0xA0) && (buf[byte_pos + 1] == 0x03)) {
                        isEOF = true;
                    }
                }
            }

            if ((man == 0 || man == 3) && !isEOF) return false;  // Collision
            if (bp >= (uint16_t)(outBufLen * 8) || isEOF) break;
        }

        uint8_t out_bytes = (uint8_t)(bp / 8);
        if (out_bytes < 3) return false;  // Need flags+DSFID+UID minimum
        if ((bp % 8) != 0) return false;  // Bit boundary error

        // Verify CRC (last 2 bytes of decoded output)
        uint16_t crc_calc = crc16_iso15693(out, out_bytes - 2);
        uint16_t crc_rx   = ((uint16_t)out[out_bytes - 1] << 8) | out[out_bytes - 2];
        if (crc_calc != crc_rx) return false;

        out_len = out_bytes - 2;  // Strip CRC
        return true;
    }

    // Configure ST25R3916B for ISO15693 / NFC-V SubCarrierStream mode.
    // Mirrors GroveNFC UnitST25R3916::configure_nfc_v() exactly.
    // Includes CMD_NFC_INITIAL_FIELD_ON at end (no tx_en/rx_en set — critical).
    bool configure_nfcv()
    {
        // Stop all active operations before reconfiguring
        st25r_cmd(0xC2);   // CMD_STOP
        delay_ms(5);
        st25r_write_reg(0x02, 0x80);  // OP_CONTROL: osc only, field off
        delay_ms(5);
        // Space-A: Receiver config for 424kHz subcarrier demodulation
        st25r_write_reg(0x0B, 0x13);  // ReceiverConfig1: lp0|h80|z12k
        st25r_write_reg(0x0C, 0x2D);  // ReceiverConfig2: sqm_dyn|agc_en|agc_m|agc6_3
        st25r_write_reg(0x0D, 0x00);  // ReceiverConfig3
        st25r_write_reg(0x0E, 0x00);  // ReceiverConfig4
        // TX driver 40% modulation (required for ISO15693)
        st25r_write_reg(0x28, 0x70);
        // IOConfiguration1: MCU_CLK disabled, no LF clock
        st25r_write_reg(0x00, 0x07);
        // IOConfiguration2: enable AAT D/A (aat_en=0x20) — critical for RX sensitivity
        st25r_write_reg(0x01, 0x20);
        // OP_CONTROL: set en_fd_c1|en_fd_c0=0x03 (field detector auto-enable)
        // Do NOT set tx_en|rx_en here — GroveNFC explicitly avoids this for NFC-V
        st25r_write_reg(0x02, 0x80 | 0x03);
        // StreamModeDefinition: fc/32=424kHz subcarrier, num pulses=2
        st25r_write_reg(0x09, 0x38);
        // AuxiliaryDefinition
        st25r_write_reg(0x0A, 0x02);
        // Space-B: correlator and subcarrier configuration
        st25r_write_spaceb(0x05, 0x40);  // EMD_SUPPRESSION_CONFIGURATION
        st25r_write_spaceb(0x06, 0x14);  // SUBCARRIER_START_TIMER = 20
        st25r_write_spaceb(0x0B, 0x0C);  // P2P_RECEIVER_CONFIGURATION
        st25r_write_spaceb(0x0C, 0x13);  // CORRELATOR_CONFIGURATION_1: corr_s4|corr_s1|corr_s0
        st25r_write_spaceb(0x0D, 0x01);  // CORRELATOR_CONFIGURATION_2: 424kHz subcarrier stream
        st25r_write_spaceb(0x0E, 0x00);  // SQUELCH_TIMER
        st25r_write_spaceb(0x0F, 0x00);  // NFC_FIELD_ON_GUARD_TIMER
        st25r_write_spaceb(0x10, 0x10);  // AUXILIARY_MODULATION_SETTING
        st25r_write_spaceb(0x11, 0x7C);  // TX_DRIVER_TIMING
        st25r_write_spaceb(0x12, 0x80);  // RESISTIVE_AM_MODULATION
        // ModeDefinition = SubCarrierStream (0x70) — write LAST per GroveNFC
        st25r_write_reg(0x03, 0x70);
        // nfc_initial_field_on(): CMD + 5ms delay + explicitly set tx_en|rx_en.
        // GroveNFC modify_bit_register8(OP_CONTROL, set=tx_en|rx_en, clear=0x00)
        // sets BOTH tx_en and rx_en after CMD_NFC_INITIAL_FIELD_ON.
        // rx_en is required so the chip auto-switches to RX after CMD_TRANSMIT.
        st25r_cmd(0xC8);   // CMD_NFC_INITIAL_FIELD_ON (RFCA + field on; sets tx_en)
        delay_ms(5);
        {
            uint8_t op = 0;
            st25r_read_reg(0x02, op);
            st25r_write_reg(0x02, op | 0x40);  // Set rx_en (bit6), tx_en already set by cmd
        }
        return true;
    }

    // Restore ST25R3916B to ISO14443A mode after ISO15693 scan attempt.
    // Clears all registers changed by configure_nfcv() that are NOT reset
    // by the readCardNFCUnit() init sequence on the next call.
    void restore_iso14443a()
    {
        // Stop cleanly first
        st25r_cmd(0xC2);   // CMD_STOP
        delay_ms(5);
        // Restore IOConfiguration2: clear aat_en bit (reg 0x01, was set to 0x20)
        st25r_write_reg(0x01, 0x00);
        // Restore AUX_DEF (not set by readCardNFCUnit init, was changed to 0x02)
        st25r_write_reg(0x0A, 0x00);  // AUXILIARY_DEFINITION: reset to default
        // CRITICAL: Reset Space-B correlator to ISO14443A mode.
        // configure_nfcv() set CORRELATOR_CONFIGURATION_2=0x01 (424kHz subcarrier).
        // GroveNFC configure_nfc_a() explicitly calls writeCorrelatorConfiguration2(0x00)
        // before each ISO14443A scan — without this, the demodulator stays in NFC-V mode.
        st25r_write_spaceb(0x0B, 0x00);  // P2P_RECEIVER_CONFIGURATION: reset
        st25r_write_spaceb(0x0C, 0x00);  // CORRELATOR_CONFIGURATION_1: reset
        st25r_write_spaceb(0x0D, 0x00);  // CORRELATOR_CONFIGURATION_2: 0=ISO14443A (was 0x01=NFC-V)
        // OP_CONTROL: OSC only, field off (clears en_fd bits too)
        // readCardNFCUnit init will re-enable the field on next scan
        st25r_write_reg(0x02, 0x80);
    }

    // Compute ISO14443-3 CRC-A (for SELECT frames).
    static uint16_t crc_a(const uint8_t* data, uint8_t len) {
        uint16_t crc = 0x6363;
        for (int i = 0; i < len; i++) {
            uint8_t b = data[i] ^ (uint8_t)(crc & 0xFF);
            b ^= b << 4;
            crc = (crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ ((uint16_t)b >> 4);
        }
        return crc;
    }

    static std::string normalize_uid_hex(const std::string &uid)
    {
        std::string out;
        out.reserve(uid.size());
        for (char ch : uid) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        return out;
    }

    static std::string hex_compact(const uint8_t *data, size_t len)
    {
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            char h[3];
            std::snprintf(h, sizeof(h), "%02X", data[i]);
            out += h;
        }
        return out;
    }

    static std::vector<uint8_t> parse_hex_bytes(const std::string &hex)
    {
        const std::string compact = normalize_uid_hex(hex);
        std::vector<uint8_t> out;
        if ((compact.size() & 1U) != 0) return out;
        out.reserve(compact.size() / 2);
        auto hexval = [](char ch) -> uint8_t {
            if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
            if (ch >= 'A' && ch <= 'F') return static_cast<uint8_t>(ch - 'A' + 10);
            return 0;
        };
        for (size_t i = 0; i < compact.size(); i += 2) {
            out.push_back(static_cast<uint8_t>((hexval(compact[i]) << 4) | hexval(compact[i + 1])));
        }
        return out;
    }

    class FibonacciLFSRRight32 {
    public:
        explicit FibonacciLFSRRight32(uint32_t seed) : state_(seed) {}

        bool step()
        {
            const bool out = (state_ & 0x1U) != 0;
            const bool fb = (((state_ >> 16) ^ (state_ >> 18) ^ (state_ >> 19) ^ (state_ >> 21)) & 0x1U) != 0;
            state_ = (state_ >> 1) | (static_cast<uint32_t>(fb) << 31);
            return out;
        }

        uint32_t next32()
        {
            uint32_t v = 0;
            for (uint32_t i = 0; i < 32; ++i) {
                v |= (static_cast<uint32_t>(step()) << i);
            }
            return v;
        }

    private:
        uint32_t state_ = 0;
    };

    class Crypto1Local {
    public:
        void init(uint64_t key48)
        {
            odd_ = 0U;
            even_ = 0U;

            for (int bit = 47; bit > 0; bit -= 2) {
                odd_ = (odd_ << 1) | static_cast<uint32_t>((key48 >> (((bit - 1) ^ 7))) & 0x01ULL);
                even_ = (even_ << 1) | static_cast<uint32_t>((key48 >> ((bit ^ 7))) & 0x01ULL);
            }
        }

        uint32_t inject(uint32_t uid, uint32_t nt, bool encrypted = false)
        {
            return step32(uid ^ nt, encrypted);
        }

        bool step_with(bool in, bool enc = false)
        {
            const uint8_t out_bit = filter();
            uint32_t feedback = enc ? static_cast<uint32_t>(out_bit) : 0U;

            feedback ^= in ? 1U : 0U;
            feedback ^= (odd_ & 0x0029CE5CU);
            feedback ^= (even_ & 0x00870804U);

            even_ = ((even_ << 1) & 0x00FFFFFFU) | evenparity32(feedback);

            const uint32_t previous_odd = odd_;
            odd_ = even_;
            even_ = previous_odd;

            return out_bit != 0;
        }

        uint8_t step8(uint8_t in, bool enc = false, uint8_t *last_ks_bit = nullptr)
        {
            uint8_t v = 0U;
            for (uint8_t bit = 0U; bit < 8U; ++bit) {
                v |= static_cast<uint8_t>(step_with(((in >> bit) & 0x01U) != 0U, enc)) << bit;
            }
            if (last_ks_bit) *last_ks_bit = parity_keystream_bit();
            return v;
        }

        uint8_t parity_keystream_bit() const
        {
            return filter();
        }

        uint32_t step32(uint32_t in, bool enc = false)
        {
            uint32_t out = 0U;
            for (uint8_t bit = 0U; bit < 32U; ++bit) {
                out |= static_cast<uint32_t>(step_with(crypto_big_endian_bit(in, bit) != 0U, enc)) << (bit ^ 24U);
            }
            return out;
        }

        static uint8_t oddparity8(uint8_t x)
        {
            return static_cast<uint8_t>(!__builtin_parity(static_cast<unsigned int>(x)));
        }

        uint8_t encrypt_nr_ar(uint8_t out[8], uint32_t nr, uint32_t ar)
        {
            uint8_t parity = 0;
            for (uint_fast8_t i = 0; i < 4; ++i) {
                const uint8_t v = static_cast<uint8_t>((nr >> ((i ^ 0x03U) << 3)) & 0xFFU);
                out[i] = static_cast<uint8_t>(step8(v, false) ^ v);
                parity |= static_cast<uint8_t>((parity_keystream_bit() ^ oddparity8(v)) & 0x01U) << i;
            }
            for (uint_fast8_t pos = 4; pos < 8; ++pos) {
                const uint8_t i = static_cast<uint8_t>(pos - 4);
                const uint8_t v = static_cast<uint8_t>((ar >> (i << 3)) & 0xFFU);
                out[pos] = static_cast<uint8_t>(step8(v, false) ^ v);
                parity |= static_cast<uint8_t>((parity_keystream_bit() ^ oddparity8(v)) & 0x01U) << pos;
            }
            return parity;
        }

        uint32_t encrypt_stream(uint8_t *out, const uint8_t *in, uint8_t len)
        {
            uint32_t parity = 0;
            for (uint_fast8_t i = 0; i < len; ++i) {
                out[i] = static_cast<uint8_t>(in[i] ^ step8(0x00, false));
                parity |= static_cast<uint32_t>((parity_keystream_bit() ^ oddparity8(in[i])) & 1U) << i;
            }
            return parity;
        }

    private:
        static uint8_t evenparity32(uint32_t value)
        {
            return static_cast<uint8_t>(__builtin_parity(value));
        }

        static uint8_t crypto_big_endian_bit(uint32_t value, uint8_t bit)
        {
            return static_cast<uint8_t>((value >> (bit ^ 24U)) & 0x01U);
        }

        uint8_t filter() const
        {
            uint32_t f = 0U;
            f |= (0x000F22C0U >> (odd_ & 0x0FU)) & 0x10U;
            f |= (0x0006C9C0U >> ((odd_ >> 4U) & 0x0FU)) & 0x08U;
            f |= (0x0003C8B0U >> ((odd_ >> 8U) & 0x0FU)) & 0x04U;
            f |= (0x0001E458U >> ((odd_ >> 12U) & 0x0FU)) & 0x02U;
            f |= (0x0000D938U >> ((odd_ >> 16U) & 0x0FU)) & 0x01U;
            return static_cast<uint8_t>((0xEC57E80AU >> f) & 0x01U);
        }

        uint32_t odd_ = 0U;
        uint32_t even_ = 0U;
    };

    static uint32_t bswap32_local(uint32_t v)
    {
        return ((v & 0x000000FFU) << 24) |
               ((v & 0x0000FF00U) << 8) |
               ((v & 0x00FF0000U) >> 8) |
               ((v & 0xFF000000U) >> 24);
    }

    static uint32_t prng_successor_local(uint32_t value, uint32_t steps)
    {
        uint32_t prng = bswap32_local(value);
        while (steps-- != 0U) {
            const uint32_t feedback = ((prng >> 16U) ^ (prng >> 18U) ^ (prng >> 19U) ^ (prng >> 21U)) & 0x01U;
            prng = (prng >> 1U) | (feedback << 31U);
        }
        return bswap32_local(prng);
    }

    static void suc_23(uint32_t nt, uint32_t &suc2, uint32_t &suc3)
    {
        FibonacciLFSRRight32 lfsr(nt);
        lfsr.next32();
        lfsr.next32();
        suc2 = lfsr.next32();
        suc3 = lfsr.next32();
    }

    static uint64_t key_to64(const std::array<uint8_t, 6> &k)
    {
        uint64_t v = 0;
        v |= static_cast<uint64_t>(k[0]) << 40;
        v |= static_cast<uint64_t>(k[1]) << 32;
        v |= static_cast<uint64_t>(k[2]) << 24;
        v |= static_cast<uint64_t>(k[3]) << 16;
        v |= static_cast<uint64_t>(k[4]) << 8;
        v |= static_cast<uint64_t>(k[5]);
        return v;
    }

    static uint32_t array_to32(const uint8_t a[4])
    {
        return (static_cast<uint32_t>(a[0]) << 24) |
               (static_cast<uint32_t>(a[1]) << 16) |
               (static_cast<uint32_t>(a[2]) << 8) |
               (static_cast<uint32_t>(a[3]));
    }

    static void append_parity(uint8_t *out,
                              uint32_t out_len,
                              const uint8_t *in,
                              uint32_t in_len,
                              uint32_t parity)
    {
        if (!out || !in) return;
        const uint32_t required = (in_len * 9 + 7) >> 3;
        if (out_len < required) return;
        std::memset(out, 0, out_len);

        uint32_t bitpos = 0;
        for (uint32_t i = 0; i < in_len; ++i) {
            uint8_t v = in[i];
            for (int k = 0; k < 8; ++k) {
                const uint8_t b = static_cast<uint8_t>((v >> k) & 1U);
                if (b) out[bitpos >> 3] |= static_cast<uint8_t>(1U << (bitpos & 7));
                ++bitpos;
            }
            const uint8_t pb = static_cast<uint8_t>((parity >> i) & 1U);
            if (pb) out[bitpos >> 3] |= static_cast<uint8_t>(1U << (bitpos & 7));
            ++bitpos;
        }
    }

    static bool decode_st25r3916_parity_frame(const uint8_t *encoded,
                                              uint16_t encoded_bits,
                                              uint8_t *out,
                                              uint8_t *parity,
                                              uint16_t max_out,
                                              uint16_t &out_len)
    {
        if (!encoded || !out || !parity) return false;
        const uint16_t bytes = static_cast<uint16_t>(encoded_bits / 9U);
        if (bytes == 0 || bytes > max_out) return false;
        std::memset(out, 0, max_out);
        std::memset(parity, 0, max_out);

        for (uint16_t i = 0; i < bytes; ++i) {
            for (uint16_t bit = 0; bit < 8; ++bit) {
                const uint16_t src_bit = static_cast<uint16_t>(i * 9U + bit);
                const uint8_t b = static_cast<uint8_t>((encoded[src_bit >> 3] >> (src_bit & 7U)) & 0x01U);
                out[i] = static_cast<uint8_t>(out[i] | (b << bit));
            }
            const uint16_t parity_bit = static_cast<uint16_t>(i * 9U + 8U);
            parity[i] = static_cast<uint8_t>((encoded[parity_bit >> 3] >> (parity_bit & 7U)) & 0x01U);
        }
        out_len = bytes;
        return true;
    }

    static int mfc_sector_count_from_sak_tag(uint8_t sak, const std::string &tag_type)
    {
        const uint8_t sak_norm = normalize_mifare_classic_sak(sak);
        if (sak_norm == 0x18 || tag_type.find("4K") != std::string::npos) return 40;
        if (sak == 0x09 || tag_type.find("Mini") != std::string::npos) return 5;
        return 16;
    }

    static uint8_t normalize_mifare_classic_sak(uint8_t sak)
    {
        if (sak == 0x88) return 0x08;
        if (sak == 0x98) return 0x18;
        return sak;
    }

    static bool is_mifare_classic_family_sak(uint8_t sak)
    {
        const uint8_t normalized = normalize_mifare_classic_sak(sak);
        return (normalized == 0x08 || normalized == 0x09 || normalized == 0x18 ||
                normalized == 0x28 || normalized == 0x38 || normalized == 0x1C);
    }

    static int mfc_sector_first_block(int sector)
    {
        return (sector < 32) ? (sector * 4) : (128 + (sector - 32) * 16);
    }

    static int mfc_sector_block_count(int sector)
    {
        return (sector < 32) ? 4 : 16;
    }

    static int mfc_sector_trailer_block(int sector)
    {
        return mfc_sector_first_block(sector) + mfc_sector_block_count(sector) - 1;
    }

    static bool parse_mfc_key_hex12(const std::string &raw, std::array<uint8_t, 6> &out)
    {
        std::string hex;
        hex.reserve(12);
        for (char c : raw) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (std::isspace(uc)) continue;
            if (!std::isxdigit(uc)) return false;
            hex.push_back(static_cast<char>(std::toupper(uc)));
        }
        if (hex.size() != 12) return false;

        for (size_t i = 0; i < 6; ++i) {
            const std::string pair = hex.substr(i * 2, 2);
            out[i] = static_cast<uint8_t>(std::strtoul(pair.c_str(), nullptr, 16));
        }
        return true;
    }

    static void append_external_mfc_keys(std::vector<std::array<uint8_t, 6>> &keys,
                                         const std::vector<std::string> *external_hex)
    {
        if (!external_hex) return;
        for (const auto &line : *external_hex) {
            std::array<uint8_t, 6> parsed{};
            if (!parse_mfc_key_hex12(line, parsed)) continue;
            if (std::find(keys.begin(), keys.end(), parsed) == keys.end()) {
                keys.push_back(parsed);
            }
        }
    }

    bool st25r_wait_fifo(uint16_t need_bytes, int timeout_ms)
    {
        auto start = std::chrono::steady_clock::now();
        while (true) {
            uint8_t fifo = 0;
            if (st25r_read_reg(0x1E, fifo) && fifo >= need_bytes) return true;

            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) return false;
        }
    }

    bool st25r_mfc_send_encrypted(Crypto1Local &crypto, const uint8_t *tx, uint8_t tx_len)
    {
        if (!tx || tx_len == 0 || tx_len > 32) return false;

        uint8_t plain[34] = {0};
        std::memcpy(plain, tx, tx_len);
        const uint16_t crc = crc_a(tx, tx_len);
        plain[tx_len] = static_cast<uint8_t>(crc & 0xFF);
        plain[tx_len + 1] = static_cast<uint8_t>((crc >> 8) & 0xFF);

        const uint8_t tx_with_crc = static_cast<uint8_t>(tx_len + 2);
        uint8_t enc[34] = {0};
        const uint32_t parity = crypto.encrypt_stream(enc, plain, tx_with_crc);

        const uint16_t total_bits = static_cast<uint16_t>(9U * tx_with_crc);
        const uint8_t stream_len = static_cast<uint8_t>((total_bits + 7U) >> 3);
        uint8_t bitstream[40] = {0};
        append_parity(bitstream, sizeof(bitstream), enc, tx_with_crc, parity);

        if (!st25r_write_reg(0x05, 0xC0)) return false;  // no_tx_par | no_rx_par (MFC encrypted parity framing)

        st25r_cmd(0xDB);
        if (!st25r_fifo_write(bitstream, stream_len)) return false;
        st25r_set_ntx(static_cast<uint16_t>(total_bits >> 3), static_cast<uint8_t>(total_bits & 0x07));
        st25r_clear_irq_regs();
        st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC
        return true;
    }

    bool st25r_mfc_transceive_encrypted(Crypto1Local &crypto,
                                        uint8_t *rx,
                                        uint8_t &rx_len,
                                        const uint8_t *tx,
                                        uint8_t tx_len,
                                        int timeout_ms,
                                        bool include_crc,
                                        bool decrypt)
    {
        if (!rx || rx_len == 0 || !tx || tx_len == 0) return false;

        if (!st25r_set_aux_crc_mode(include_crc)) return false;
        if (!st25r_mfc_send_encrypted(crypto, tx, tx_len)) return false;

        const uint8_t expect_plain = static_cast<uint8_t>(rx_len + (include_crc ? 2 : 0));
        const uint16_t expect_bits = static_cast<uint16_t>(expect_plain * 9U);
        const uint8_t expect_encoded = static_cast<uint8_t>((expect_bits + 7U) >> 3);

        uint8_t encoded[48] = {0};
        St25rIrqStatus first_irq;
        St25rIrqStatus last_irq;
        uint16_t fifo_cnt = 0;
        if (!st25r_wait_for_nfca_rx(first_irq, last_irq, timeout_ms)) {
            if (!st25r_wait_fifo_after_missed_rxe(fifo_cnt)) return false;
        } else {
            if (!st25r_read_fifo_count(fifo_cnt)) return false;
        }
        if (fifo_cnt < expect_encoded) return false;
        if (!st25r_fifo_read(encoded, expect_encoded)) return false;
        if (fifo_cnt > expect_encoded) {
            uint8_t sink[32] = {0};
            uint16_t rem = static_cast<uint16_t>(fifo_cnt - expect_encoded);
            while (rem > 0) {
                const uint8_t n = static_cast<uint8_t>(std::min<uint16_t>(rem, sizeof(sink)));
                st25r_fifo_read(sink, n);
                rem = static_cast<uint16_t>(rem - n);
            }
        }

        uint8_t rbuf[34] = {0};
        uint8_t rpar[34] = {0};
        uint16_t decoded_len = 0;
        if (!decode_st25r3916_parity_frame(encoded, expect_bits, rbuf, rpar, sizeof(rbuf), decoded_len) ||
            decoded_len != expect_plain) {
            return false;
        }

        if (decrypt) {
            if (expect_plain == 1) {
                const uint8_t ret = static_cast<uint8_t>(rbuf[0] & 0x0F);
                uint8_t res = 0;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 0) & 1U)) << 0;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 1) & 1U)) << 1;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 2) & 1U)) << 2;
                res |= static_cast<uint8_t>(crypto.step_with(0) ^ ((ret >> 3) & 1U)) << 3;
                if (res != 0x0A) return false;
                rx[0] = res;
                rx_len = 1;
                return true;
            }

            for (uint8_t i = 0; i < expect_plain; ++i) {
                rbuf[i] ^= crypto.step8(0, false);
                const uint8_t plain_parity = static_cast<uint8_t>(crypto.parity_keystream_bit() ^ rpar[i]);
                if (Crypto1Local::oddparity8(rbuf[i]) != plain_parity) return false;
            }
        }

        if (include_crc) {
            if (expect_plain < 3) return false;
            const uint16_t crc_calc = crc_a(rbuf, rx_len);
            const uint16_t crc_rx = static_cast<uint16_t>(rbuf[expect_plain - 2]) |
                                    (static_cast<uint16_t>(rbuf[expect_plain - 1]) << 8);
            if (crc_calc != crc_rx) return false;
        }

        std::memcpy(rx, rbuf, rx_len);
        return true;
    }

    bool st25r_mfc_authenticate(uint8_t auth_cmd,
                                uint8_t block,
                                const std::array<uint8_t, 6> &key,
                                const std::vector<uint8_t> &uid,
                                Crypto1Local &crypto)
    {
        auto &hexlog = NfcHexLog::get();
        char auth_label[32];
        std::snprintf(auth_label, sizeof(auth_label), "MFC-AUTH blk%02X cmd%02X", block, auth_cmd);

        uint8_t rb_len = 8;
        uint8_t rb[8] = {0};
        const uint8_t auth_frame[2] = {auth_cmd, block};
        hexlog.log_tx(auth_label, auth_frame, 2);
        if (!st25r_nfca_transceive(auth_frame, 2, true, rb, rb_len, 40, 0x00, false, 0) || rb_len < 4) {
            hexlog.log_event(auth_label, "FAIL: no NT response");
            return false;
        }
        hexlog.log_rx(auth_label, rb, rb_len);  // NT

        if (uid.size() < 4) return false;
        std::this_thread::sleep_for(std::chrono::microseconds(90));

        uint8_t tail4[4] = {uid[uid.size() - 4], uid[uid.size() - 3], uid[uid.size() - 2], uid[uid.size() - 1]};
        const uint32_t u32 = array_to32(tail4);
        const uint32_t nt = array_to32(rb);

        static thread_local std::mt19937 rng(static_cast<uint32_t>(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        const uint32_t nr_seed = rng();
        uint8_t nr_bytes[4] = {
            static_cast<uint8_t>((nr_seed >> 24) & 0xFFU),
            static_cast<uint8_t>((nr_seed >> 16) & 0xFFU),
            static_cast<uint8_t>((nr_seed >> 8) & 0xFFU),
            static_cast<uint8_t>(nr_seed & 0xFFU)
        };

        uint8_t ab[8] = {0};
        uint8_t parity = 0;

        crypto.init(key_to64(key));
        (void)crypto.inject(u32, nt, false);

        uint32_t reader_prng = prng_successor_local(nt, 32U);
        for (uint8_t i = 0; i < 4; ++i) {
            const uint8_t v = nr_bytes[i];
            ab[i] = static_cast<uint8_t>(crypto.step8(v, false) ^ v);
            parity |= static_cast<uint8_t>((crypto.parity_keystream_bit() ^ Crypto1Local::oddparity8(v)) & 0x01U) << i;
        }
        for (uint8_t i = 0; i < 4; ++i) {
            reader_prng = prng_successor_local(reader_prng, 8U);
            const uint8_t plain_byte = static_cast<uint8_t>(reader_prng & 0xFFU);
            // AR bytes use keystream generated with zero input, then XOR plain successor byte.
            ab[4U + i] = static_cast<uint8_t>(crypto.step8(0x00, false) ^ plain_byte);
            parity |= static_cast<uint8_t>((crypto.parity_keystream_bit() ^ Crypto1Local::oddparity8(plain_byte)) & 0x01U) << (4U + i);
        }
        const uint32_t expected_at = prng_successor_local(reader_prng, 32U);
        const uint8_t expected_at_bytes[4] = {
            static_cast<uint8_t>((expected_at >> 24) & 0xFFU),
            static_cast<uint8_t>((expected_at >> 16) & 0xFFU),
            static_cast<uint8_t>((expected_at >> 8) & 0xFFU),
            static_cast<uint8_t>(expected_at & 0xFFU)
        };

        uint8_t bitstream[9] = {0};
        append_parity(bitstream, sizeof(bitstream), ab, sizeof(ab), parity);

        st25r_cmd(0xD5);  // RESET_RX_GAIN
        if (!st25r_write_reg(0x05, 0xC0)) return false;  // no_tx_par | no_rx_par
        if (!st25r_set_aux_crc_mode(true)) return false; // no_crc_rx

        st25r_cmd(0xDB);
        hexlog.log_tx(auth_label, bitstream, sizeof(bitstream));  // {NR,AR} encrypted
        if (!st25r_fifo_write(bitstream, sizeof(bitstream))) {
            hexlog.log_event(auth_label, "FAIL: FIFO write NR/AR");
            return false;
        }
        st25r_set_ntx(sizeof(bitstream), 0);
        st25r_clear_irq_regs();
        st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC

        constexpr uint16_t at_bits = 4U * 9U;
        constexpr uint8_t at_encoded_len = static_cast<uint8_t>((at_bits + 7U) >> 3);
        St25rIrqStatus first_irq;
        St25rIrqStatus last_irq;
        uint16_t fifo_cnt = 0;
        if (!st25r_wait_for_nfca_rx(first_irq, last_irq, 50)) {
            if (!st25r_wait_fifo_after_missed_rxe(fifo_cnt)) {
                hexlog.log_event(auth_label, "FAIL: timeout waiting AT");
                return false;
            }
        } else {
            if (!st25r_read_fifo_count(fifo_cnt)) {
                hexlog.log_event(auth_label, "FAIL: timeout waiting AT");
                return false;
            }
        }
        if (fifo_cnt < at_encoded_len) {
            hexlog.log_event(auth_label, "FAIL: timeout waiting AT");
            return false;
        }

        uint8_t ba_encoded[at_encoded_len] = {0};
        if (!st25r_fifo_read(ba_encoded, sizeof(ba_encoded))) {
            hexlog.log_event(auth_label, "FAIL: FIFO read AT");
            return false;
        }
        if (fifo_cnt > at_encoded_len) {
            uint8_t sink[16] = {0};
            uint16_t rem = static_cast<uint16_t>(fifo_cnt - at_encoded_len);
            while (rem > 0) {
                const uint8_t n = static_cast<uint8_t>(std::min<uint16_t>(rem, sizeof(sink)));
                st25r_fifo_read(sink, n);
                rem = static_cast<uint16_t>(rem - n);
            }
        }
        hexlog.log_rx(auth_label, ba_encoded, sizeof(ba_encoded));  // AT encoded

        uint8_t ba[4] = {0};
        uint8_t ba_parity[4] = {0};
        uint16_t ba_len = 0;
        if (!decode_st25r3916_parity_frame(ba_encoded, at_bits, ba, ba_parity, sizeof(ba), ba_len) || ba_len != 4) {
            hexlog.log_event(auth_label, "FAIL: decode AT frame");
            return false;
        }

        uint8_t at2[4] = {0};
        for (int i = 0; i < 4; ++i) {
            at2[i] = static_cast<uint8_t>(ba[i] ^ crypto.step8(0, false));
            const uint8_t plain_parity = static_cast<uint8_t>(crypto.parity_keystream_bit() ^ ba_parity[i]);
            if (Crypto1Local::oddparity8(at2[i]) != plain_parity) {
                char pmsg[48];
                std::snprintf(pmsg, sizeof(pmsg), "FAIL: parity mismatch byte %d", i);
                hexlog.log_event(auth_label, pmsg);
                hexlog.log_rx(auth_label, at2, 4);  // partial AT decrypt for inspection
                return false;
            }
        }

        if (std::memcmp(at2, expected_at_bytes, sizeof(at2)) != 0) {
            hexlog.log_rx(auth_label, at2, 4);
            hexlog.log_event(auth_label, "FAIL: AT mismatch suc3");
            return false;
        }

        hexlog.log_event(auth_label, "OK");
        return true;
    }

    bool st25r_mfc_read_block(Crypto1Local &crypto, uint8_t block, std::array<uint8_t, 16> &out)
    {
        uint8_t rx_len = 16;
        uint8_t rx[16] = {0};
        const uint8_t cmd[2] = {0x30, block};
        if (!st25r_mfc_transceive_encrypted(crypto, rx, rx_len, cmd, sizeof(cmd), 40, true, true) || rx_len != 16) {
            return false;
        }
        std::copy(rx, rx + 16, out.begin());
        return true;
    }

    bool st25r_init_nfca_reader()
    {
        st25r_cmd(0xD6);              // ADJUST_REGULATORS
        delay_ms(5);
        st25r_write_reg(0x02, 0x80);  // OP_CONTROL: osc only
        delay_ms(10);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }

        st25r_write_reg(0x03, 0x08);  // ISO14443A initiator
        st25r_write_reg(0x04, 0x00);  // 106kbps
        st25r_write_reg(0x05, 0x00);  // standard parity
        st25r_write_reg(0x09, 0x03);  // antenna drivers
        st25r_write_reg(0x26, 0x80);  // mask osc irq
        st25r_write_reg(0x0B, 0x08);
        st25r_write_reg(0x0C, 0x2D);
        st25r_write_reg(0x0D, 0xD8);
        st25r_write_reg(0x0E, 0x22);

        st25r_cmd(0xC8);              // NFC_INITIAL_FIELD_ON
        delay_ms(10);
        {
            uint8_t op = 0x80;
            st25r_read_reg(0x02, op);
            if (!st25r_write_reg(0x02, op | 0x48)) return false;  // tx_en|rx_en
        }
        delay_ms(5);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        return true;
    }

    bool st25r_set_aux_crc_mode(bool no_crc_rx)
    {
        uint8_t aux = 0;
        if (!st25r_read_reg(0x0A, aux)) return false;
        if (no_crc_rx) aux |= 0x80;
        else aux &= static_cast<uint8_t>(~0x80);
        return st25r_write_reg(0x0A, aux);
    }

    bool st25r_nfca_transceive(const uint8_t *tx,
                               uint8_t tx_len,
                               bool with_crc,
                               uint8_t *rx,
                               uint8_t &rx_len,
                               int timeout_ms,
                               uint8_t iso14443a_settings = 0x00,
                               bool no_crc_rx = false,
                               uint8_t last_bits = 0,
                               bool issue_stop = true)
    {
        auto &hexlog = NfcHexLog::get();
        if (!tx || tx_len == 0 || !rx || rx_len == 0) return false;
        hexlog.log_tx("NFC", tx, tx_len);
        if (!st25r_write_reg(0x05, iso14443a_settings)) return false;
        if (!st25r_set_aux_crc_mode(no_crc_rx)) return false;
        if (!st25r_config_nfca_rx_timers(timeout_ms)) return false;

        if (issue_stop) st25r_cmd(0xC2);  // STOP
        st25r_cmd(0xD5);  // RESET_RXGAIN
        st25r_cmd(0xDB);  // CLEAR_FIFO
        if (!st25r_fifo_write(tx, tx_len)) return false;
        const uint16_t ntx_bytes = (last_bits == 0) ? tx_len : static_cast<uint16_t>(tx_len - 1);
        st25r_set_ntx(ntx_bytes, last_bits);
        st25r_clear_irq_regs();
        st25r_cmd(with_crc ? 0xC4 : 0xC5);

        St25rIrqStatus first_irq;
        St25rIrqStatus last_irq;
        uint16_t fifo_cnt = 0;
        if (!st25r_wait_for_nfca_rx(first_irq, last_irq, timeout_ms)) {
            // Some frames can be fully received while RXE/RXS sampling is missed
            // by tight polling windows; do a short FIFO check before failing.
            if (!st25r_wait_fifo_after_missed_rxe(fifo_cnt)) return false;
        } else {
            if (!st25r_read_fifo_count(fifo_cnt)) return false;
        }
        if (fifo_cnt == 0) return false;
        const uint8_t to_read = std::min<uint16_t>(fifo_cnt, rx_len);
        if (!st25r_fifo_read(rx, to_read)) return false;
        if (fifo_cnt > to_read) {
            uint8_t sink[32] = {0};
            uint16_t rem = static_cast<uint16_t>(fifo_cnt - to_read);
            while (rem > 0) {
                const uint8_t n = static_cast<uint8_t>(std::min<uint16_t>(rem, sizeof(sink)));
                st25r_fifo_read(sink, n);
                rem = static_cast<uint16_t>(rem - n);
            }
        }
        rx_len = to_read;
        if (rx_len > 0) hexlog.log_rx("NFC", rx, rx_len);
        return true;
    }

    bool st25r_nfca_transceive_diag(const char *log_tag,
                                    const uint8_t *tx,
                                    uint8_t tx_len,
                                    bool with_crc,
                                    uint8_t iso14443a_settings,
                                    bool no_crc_rx,
                                    int timeout_ms,
                                    bool issue_stop = true)
    {
        if (!tx || tx_len == 0) return false;
        (void)log_tag;

        uint8_t rx[48] = {0};
        uint8_t rx_len = static_cast<uint8_t>(sizeof(rx));
        const bool ok = st25r_nfca_transceive(tx,
                                              tx_len,
                                              with_crc,
                                              rx,
                                              rx_len,
                                              timeout_ms,
                                              iso14443a_settings,
                                              no_crc_rx,
                                              0,
                                              issue_stop);
        return ok;
    }

    bool st25r_nfca_transmit_only(const uint8_t *tx,
                                  uint8_t tx_len,
                                  bool with_crc,
                                  uint8_t iso14443a_settings = 0x00,
                                  uint8_t last_bits = 0,
                                  int timeout_ms = 20)
    {
        if (!tx || tx_len == 0) return false;
        if (!st25r_write_reg(0x05, iso14443a_settings)) return false;
        if (!st25r_set_aux_crc_mode(false)) return false;

        st25r_cmd(0xDB);  // CLEAR_FIFO
        if (!st25r_fifo_write(tx, tx_len)) return false;
        const uint16_t ntx_bytes = (last_bits == 0) ? tx_len : static_cast<uint16_t>(tx_len - 1);
        st25r_set_ntx(ntx_bytes, last_bits);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        st25r_cmd(with_crc ? 0xC4 : 0xC5);

        const uint8_t irq = st25r_wait_irq(0x08 | 0x04, timeout_ms);
        return (irq & 0x08) != 0;
    }

    bool st25r_mfc_read_plain_block(uint8_t block,
                                    std::array<uint8_t, 16> &out,
                                    uint8_t *observed_rx_len = nullptr,
                                    bool *exchange_ok = nullptr,
                                    const char **read_mode = nullptr)
    {
        bool any_exchange = false;
        uint8_t last_rx_len = 0;
        const char *last_mode = "none";

        auto finish_success = [&](const uint8_t *rx, uint8_t rx_len, const char *mode) {
            if (exchange_ok) *exchange_ok = true;
            if (observed_rx_len) *observed_rx_len = rx_len;
            if (read_mode) *read_mode = mode;
            std::copy(rx, rx + 16, out.begin());
            return true;
        };

        auto try_native = [&](uint8_t iso14443a_settings, bool issue_stop, const char *mode) {
            uint8_t rx_len = 18;
            uint8_t rx[18] = {0};
            const uint8_t cmd[2] = {0x30, block};
            const bool ok = st25r_nfca_transceive(cmd,
                                                  sizeof(cmd),
                                                  true,
                                                  rx,
                                                  rx_len,
                                                  80,
                                                  iso14443a_settings,
                                                  false,
                                                  0,
                                                  issue_stop);
            if (ok) {
                any_exchange = true;
                last_rx_len = rx_len;
                last_mode = mode;
            }
            if (ok && rx_len >= 16) {
                return finish_success(rx, rx_len, mode);
            }
            return false;
        };

        auto try_raw = [&](uint8_t iso14443a_settings, bool no_crc_rx, bool issue_stop, const char *mode) {
            uint8_t rx_len = 20;
            uint8_t rx[20] = {0};
            const uint8_t cmd[2] = {0x30, block};
            const uint16_t crc = crc_a(cmd, sizeof(cmd));
            const uint8_t raw_cmd[4] = {
                cmd[0],
                cmd[1],
                static_cast<uint8_t>(crc & 0xFF),
                static_cast<uint8_t>((crc >> 8) & 0xFF)
            };
            // Match pn532-python's Gen3 probe: send a raw READ frame with an
            // explicit CRC-A and keep CRC bytes in RX. Some magic cards appear
            // to need looser receive settings than standard MFC.
            const bool ok = st25r_nfca_transceive(raw_cmd,
                                                  sizeof(raw_cmd),
                                                  false,
                                                  rx,
                                                  rx_len,
                                                  80,
                                                  iso14443a_settings,
                                                  no_crc_rx,
                                                  0,
                                                  issue_stop);
            if (ok) {
                any_exchange = true;
                last_rx_len = rx_len;
                last_mode = mode;
            }
            if (ok && rx_len >= 16) {
                return finish_success(rx, rx_len, mode);
            }
            return false;
        };

        if (try_raw(0x00, false, true, "raw-crc-check")) return true;
        if (try_raw(0x00, false, false, "raw-crc-check-keep")) return true;
        if (try_raw(0x00, true, true, "raw")) return true;
        if (try_raw(0x00, true, false, "raw-keep")) return true;
        if (try_raw(0x40, true, true, "raw-no-rx-par")) return true;
        if (try_raw(0x40, true, false, "raw-no-rx-par-keep")) return true;
        if (try_native(0x00, true, "native")) return true;
        if (try_native(0x00, false, "native-keep")) return true;
        if (try_native(0x40, true, "native-no-rx-par")) return true;
        if (try_native(0x40, false, "native-no-rx-par-keep")) return true;

        if (exchange_ok) *exchange_ok = any_exchange;
        if (observed_rx_len) *observed_rx_len = last_rx_len;
        if (read_mode) *read_mode = last_mode;
        return false;
    }

    // Type 2 tags support READ(page) for 4 consecutive pages (16 bytes).
    // We probe specific high pages to distinguish NTAG203 vs NTAG21x reliably.
    bool st25r_type2_has_page(uint8_t page, int timeout_ms = 40)
    {
        uint8_t rx_len = 20;
        uint8_t rx[20] = {0};
        const uint8_t cmd[2] = {0x30, page};
        return st25r_nfca_transceive(cmd, 2, true, rx, rx_len, timeout_ms, 0x00, false, 0) &&
               rx_len >= 16;
    }

    // Generic 7-bit (or N-bit) short-frame transceive with ACK nibble check.
    // Use last_bits=7 for backdoor commands (e.g. 0x40/0x43), last_bits=0 for full-byte.
    bool st25r_nfca_7bit_cmd_ack(uint8_t cmd, uint8_t tx_last_bits)
    {
        uint8_t rx_len = 4;
        uint8_t rx[4] = {0};
        if (!st25r_nfca_transceive(&cmd, 1, false, rx, rx_len, 30, 0x00, true, tx_last_bits) || rx_len < 1) {
            return false;
        }

        const uint8_t lo = static_cast<uint8_t>(rx[0] & 0x0F);
        const uint8_t hi = static_cast<uint8_t>((rx[0] >> 4) & 0x0F);
        return lo == 0x0A || hi == 0x0A;
    }

    bool st25r_is_gen1a_magic(const std::string &selected_uid)
    {
        auto run_unlock_probe = [&](bool send_halt) -> bool {
            std::vector<uint8_t> uid;
            uint8_t sak = 0;
            if (!st25r_nfca_select_uid(uid, sak)) return false;

            const std::string uid_hex = hex_compact(uid.data(), uid.size());
            if (!selected_uid.empty() && uid_hex != selected_uid) return false;

            if (send_halt) {
                const uint8_t halt_no_crc[2] = {0x50, 0x00};
                (void)st25r_nfca_transmit_only(halt_no_crc, 2, false, 0x00, 0, 25);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            const bool ack1 = st25r_nfca_7bit_cmd_ack(0x40, 7);  // 7-bit frame
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            const bool ack2 = st25r_nfca_7bit_cmd_ack(0x43, 0);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            return ack1 && ack2;
        };

        // Try with HALT pre-step first, then without — each only once.
        if (run_unlock_probe(true)) return true;
        if (run_unlock_probe(false)) return true;
        return false;
    }

    bool st25r_gen3_apdu_transceive(uint8_t ins,
                                    const uint8_t *payload,
                                    uint8_t payload_len,
                                    uint8_t *rx,
                                    uint8_t &rx_len,
                                    const char **mode = nullptr)
    {
        if (!rx || rx_len == 0) return false;

        std::array<uint8_t, 32> cmd{};
        const size_t cmd_len = static_cast<size_t>(5U + payload_len);
        if (cmd_len > cmd.size()) return false;

        cmd[0] = 0x90;
        cmd[1] = ins;
        cmd[2] = 0xCC;
        cmd[3] = 0xCC;
        cmd[4] = payload_len;
        if (payload_len > 0 && payload) {
            std::copy(payload, payload + payload_len, cmd.begin() + 5);
        }

        auto try_raw_mode = [&](uint8_t iso14443a_settings, bool no_crc_rx, bool issue_stop, const char *mode_name) {
            std::array<uint8_t, 34> raw_cmd{};
            if (cmd_len + 2 > raw_cmd.size()) return false;
            std::copy(cmd.begin(), cmd.begin() + static_cast<ptrdiff_t>(cmd_len), raw_cmd.begin());
            const uint16_t crc = crc_a(raw_cmd.data(), cmd_len);
            raw_cmd[cmd_len] = static_cast<uint8_t>(crc & 0xFF);
            raw_cmd[cmd_len + 1] = static_cast<uint8_t>((crc >> 8) & 0xFF);

            uint8_t tmp_len = rx_len;
            if (!st25r_nfca_transceive(raw_cmd.data(),
                                       static_cast<uint8_t>(cmd_len + 2),
                                       false,
                                       rx,
                                       tmp_len,
                                       70,
                                       iso14443a_settings,
                                       no_crc_rx,
                                       0,
                                       issue_stop)) {
                return false;
            }
            rx_len = tmp_len;
            if (mode) *mode = mode_name;
            return true;
        };

        auto try_mode = [&](uint8_t iso14443a_settings, bool issue_stop, const char *mode_name) {
            uint8_t tmp_len = rx_len;
            if (!st25r_nfca_transceive(cmd.data(),
                                       static_cast<uint8_t>(cmd_len),
                                       true,
                                       rx,
                                       tmp_len,
                                       70,
                                       iso14443a_settings,
                                       false,
                                       0,
                                       issue_stop)) {
                return false;
            }
            rx_len = tmp_len;
            if (mode) *mode = mode_name;
            return true;
        };

        if (try_raw_mode(0x00, false, true, "apdu-raw-crc-check")) return true;
        if (try_mode(0x00, true, "apdu")) return true;
        if (try_raw_mode(0x40, true, false, "apdu-raw-no-rx-par-keep")) return true;
        if (mode) *mode = "none";
        return false;
    }

    // Gen3 magic detection: HALT + fresh select, then plain READ(block0) without auth.
    // A Gen3 card responds with 16+ bytes; a normal MFC card NAKs (no auth = no data).
    // Uses no_crc_rx=true (raw RX) to match PN532 InCommunicateThru raw exchange
    // behavior and avoid HW CRC stripping failures on some card variants.
    bool st25r_is_gen3_magic(const std::string &selected_uid)
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_reselect_current_field(uid, sak, true)) return false;

        // Only Mifare Classic / Mifare Plus SL2 can be Gen3 magic.
        if (!(sak == 0x08 || sak == 0x09 || sak == 0x18 || sak == 0x28 || sak == 0x38 ||
              sak == 0x1C)) {
            return false;
        }

        if (!selected_uid.empty()) {
            const std::string got = hex_compact(uid.data(), uid.size());
            if (got != selected_uid) return false;
        }

        // Gen3 probe: send "90 FB CC CC [Lc] [uid...]" with the card's own UID.
        // A Gen3 (CUID) card responds with SW 9000; normal Mifare Classic ignores it.
        // This matches the proven write-path command observed in logs:
        //   TX: 90FBCCCC07[uid7]CRC  RX: 9000CRC
        const uint8_t uid_len = static_cast<uint8_t>(uid.size());
        std::array<uint8_t, 32> cmd{};
        cmd[0] = 0x90; cmd[1] = 0xFB; cmd[2] = 0xCC; cmd[3] = 0xCC; cmd[4] = uid_len;
        std::copy(uid.begin(), uid.end(), cmd.begin() + 5);
        const size_t cmd_len = 5u + uid_len;
        const uint16_t crc = crc_a(cmd.data(), cmd_len);
        cmd[cmd_len]     = static_cast<uint8_t>(crc & 0xFF);
        cmd[cmd_len + 1] = static_cast<uint8_t>((crc >> 8) & 0xFF);

        uint8_t rx[16] = {0};
        uint8_t rx_len = sizeof(rx);
        if (!st25r_nfca_transceive(cmd.data(),
                                   static_cast<uint8_t>(cmd_len + 2),
                                   false,   // CRC already appended manually
                                   rx,
                                   rx_len,
                                   120,
                                   0x00,
                                   true,    // no_crc_rx: raw RX, no HW CRC strip
                                   0,
                                   false)) {
            return false;
        }
        // Accept response if it contains 90 00 anywhere (raw bytes, CRC not stripped).
        for (uint8_t i = 0; i + 1 < rx_len; ++i) {
            if (rx[i] == 0x90 && rx[i + 1] == 0x00) return true;
        }
        return false;
    }

    // Gen4 magic detection.
    // password: 4-byte PWD field in the CF command (default all-zero).
    bool st25r_is_gen4_magic(const std::string &selected_uid,
                             const std::array<uint8_t, 4> &password = {})
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_reselect_current_field(uid, sak, true)) return false;

        // Only Mifare Classic / Mifare Plus SL2 can be Gen4 magic.
        if (!(sak == 0x08 || sak == 0x09 || sak == 0x18 || sak == 0x28 || sak == 0x38 ||
              sak == 0x1C)) {
            return false;
        }

        const std::string uid_hex = hex_compact(uid.data(), uid.size());
        if (!selected_uid.empty() && uid_hex != selected_uid) return false;

        // CF <4-byte PWD> C6 <2-byte CRC-A>
        uint8_t cmd[8] = {0xCF,
                          password[0], password[1], password[2], password[3],
                          0xC6, 0x00, 0x00};
        const uint16_t c = crc_a(cmd, 6);
        cmd[6] = static_cast<uint8_t>(c & 0xFF);
        cmd[7] = static_cast<uint8_t>((c >> 8) & 0xFF);

        uint8_t rx[32] = {0};
        uint8_t rx_len = sizeof(rx);
        // Command already contains CRC-A, so transmit without auto-CRC and accept raw RX.
        if (!st25r_nfca_transceive(cmd, sizeof(cmd), false, rx, rx_len, 60, 0x00, true, 0)) {
            return false;
        }
        return rx_len >= 4;
    }

    // Probe order: Gen3 → Gen4 → Gen1A.
    // Gen3 must run before Gen1A: Gen1A sends 7-bit backdoor frames that leave
    // the ST25R in a state where a subsequent plain READ would fail.
    // current_sak / use_current_selection are kept for call-site compatibility
    // but are no longer used — each detector does its own fresh reselect.
    std::string st25r_detect_magic_type(const std::string &selected_uid,
                                        uint8_t current_sak = 0xFF,
                                        bool use_current_selection = false)
    {
        (void)current_sak;
        (void)use_current_selection;
        auto &hexlog = NfcHexLog::get();

        hexlog.log_event("MAGIC", "Check Magic Type: is Gen3?");
        if (st25r_is_gen3_magic(selected_uid)) { hexlog.log_event("MAGIC", "=> Gen3"); return "Gen3"; }

        hexlog.log_event("MAGIC", "Check Magic Type: is Gen1A?");
        if (st25r_is_gen1a_magic(selected_uid)) { hexlog.log_event("MAGIC", "=> Gen1A"); return "Gen1A"; }

        hexlog.log_event("MAGIC", "Check Magic Type: is Gen4?");
        if (st25r_is_gen4_magic(selected_uid)) { hexlog.log_event("MAGIC", "=> Gen4"); return "Gen4"; }

        hexlog.log_event("MAGIC", "=> not magic");
        return "";
    }

    bool st25r_nfca_select_uid_current_field(std::vector<uint8_t> &uid, uint8_t &sak)
    {
        uid.clear();
        sak = 0;

        // WUPA short frame (retry once — some cards need extra RF stabilization time)
        st25r_cmd(0xDB);
        st25r_cmd(0xC7);
        uint8_t irq = st25r_wait_irq(0x10 | 0x04, 25);
        if (!(irq & 0x10)) {
            st25r_cmd(0xDB);
            st25r_cmd(0xC7);
            irq = st25r_wait_irq(0x10 | 0x04, 40);
        }
        if (!(irq & 0x10)) return false;
        uint8_t atqa_len = 0;
        uint8_t atqa[8] = {0};
        if (!st25r_read_reg(0x1E, atqa_len) || atqa_len < 2) return false;
        const uint8_t atqa_read = std::min<uint8_t>(atqa_len, sizeof(atqa));
        if (!st25r_fifo_read(atqa, atqa_read)) return false;
        if (atqa_len > atqa_read) {
            uint8_t sink[8] = {0};
            uint8_t rem = static_cast<uint8_t>(atqa_len - atqa_read);
            while (rem > 0) {
                const uint8_t n = std::min<uint8_t>(rem, sizeof(sink));
                st25r_fifo_read(sink, n);
                rem = static_cast<uint8_t>(rem - n);
            }
        }
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }

        // CL1 anticollision
        const uint8_t anticol1[2] = {0x93, 0x20};
        uint8_t cl1_len = 8;
        uint8_t cl1[8] = {0};
        if (!st25r_nfca_transceive(anticol1, 2, false, cl1, cl1_len, 50, 0x01, false, 0)) return false;
        if (cl1_len < 5) return false;

        const uint8_t sel1[9] = {
            0x93, 0x70, cl1[0], cl1[1], cl1[2], cl1[3], cl1[4], 0x00, 0x00
        };
        const uint16_t sel1_c = crc_a(sel1, 7);
        uint8_t sel1_raw[9] = {
            sel1[0], sel1[1], sel1[2], sel1[3], sel1[4], sel1[5], sel1[6],
            static_cast<uint8_t>(sel1_c & 0xFF),
            static_cast<uint8_t>((sel1_c >> 8) & 0xFF)
        };
        uint8_t sak_len = 4;
        uint8_t sak_buf[4] = {0};
        if (!st25r_nfca_transceive(sel1_raw, sizeof(sel1_raw), false, sak_buf, sak_len, 50, 0x00, false, 0)) return false;
        if (sak_len < 1) return false;
        sak = sak_buf[0];

        // GroveNFC behavior: CT(0x88) means cascade UID.
        // Some readers/cards may not present SAK cascade bit reliably in this step.
        const bool cascade = (cl1[0] == 0x88);
        if (!cascade) {
            uid.assign(cl1, cl1 + 4);
            return true;
        }

        const uint8_t anticol2[2] = {0x95, 0x20};
        uint8_t cl2_len = 8;
        uint8_t cl2[8] = {0};
        if (!st25r_nfca_transceive(anticol2, 2, false, cl2, cl2_len, 50, 0x01, false, 0)) return false;
        if (cl2_len < 5) return false;

        const uint8_t sel2[9] = {
            0x95, 0x70, cl2[0], cl2[1], cl2[2], cl2[3], cl2[4], 0x00, 0x00
        };
        const uint16_t sel2_c = crc_a(sel2, 7);
        uint8_t sel2_raw[9] = {
            sel2[0], sel2[1], sel2[2], sel2[3], sel2[4], sel2[5], sel2[6],
            static_cast<uint8_t>(sel2_c & 0xFF),
            static_cast<uint8_t>((sel2_c >> 8) & 0xFF)
        };
        sak_len = 4;
        std::memset(sak_buf, 0, sizeof(sak_buf));
        if (!st25r_nfca_transceive(sel2_raw, sizeof(sel2_raw), false, sak_buf, sak_len, 50, 0x00, false, 0)) return false;
        if (sak_len < 1) return false;
        sak = sak_buf[0];

        uid = {cl1[1], cl1[2], cl1[3], cl2[0], cl2[1], cl2[2], cl2[3]};
        return true;
    }

    bool st25r_nfca_reselect_current_field(std::vector<uint8_t> &uid,
                                           uint8_t &sak,
                                           bool send_halt_pre_step = false)
    {
        if (send_halt_pre_step) {
            const uint8_t halt_no_crc[2] = {0x50, 0x00};
            (void)st25r_nfca_transmit_only(halt_no_crc, 2, false, 0x00, 0, 25);
            delay_ms(5);
        }
        return st25r_nfca_select_uid_current_field(uid, sak);
    }

    bool st25r_nfca_select_uid(std::vector<uint8_t> &uid,
                               uint8_t &sak,
                               bool send_halt_pre_step = false)
    {
        if (!st25r_init_nfca_reader()) return false;
        return st25r_nfca_reselect_current_field(uid, sak, send_halt_pre_step);
    }

    bool st25r_nfcv_transceive(const uint8_t *req,
                               uint8_t req_len,
                               uint8_t *decoded,
                               uint8_t &decoded_len,
                               int timeout_ms)
    {
        if (!req || req_len == 0 || !decoded) return false;

        uint8_t encoded[96] = {0};
        uint8_t enc_len = encode_nfcv_1of4(encoded, req, req_len);

        st25r_cmd(0xDB);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        if (!st25r_fifo_write(encoded, enc_len)) return false;
        st25r_set_ntx(enc_len, 0);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        st25r_cmd(0xC5);  // transmit without CRC (already in stream)

        uint8_t irq = st25r_wait_irq(0x08, 20);
        if (irq & 0x08) irq |= st25r_wait_irq(0x10 | 0x04, timeout_ms);
        if (!(irq & 0x10)) return false;

        uint8_t fifo_cnt = 0;
        if (!st25r_read_reg(0x1E, fifo_cnt) || fifo_cnt < 3) return false;
        uint8_t raw[96] = {0};
        const uint8_t to_read = std::min<uint8_t>(fifo_cnt, sizeof(raw));
        if (!st25r_fifo_read(raw, to_read)) return false;

        uint8_t out_len = 0;
        if (!decode_vicc_manchester(raw, to_read, decoded, out_len)) return false;
        decoded_len = out_len;
        return true;
    }

    bool dumpGroveMFC(const std::string &uid_hint,
                      const std::string &tag_type,
                      const std::vector<std::string> *mfc_key_hex,
                      std::vector<std::string> &out_lines,
                      const std::function<void(const std::string &)> *progress,
                      std::string *error)
    {
        I2cCardInfo card;
        if (!readISO14A(card)) {
            if (error) *error = "GroveNFC ISO14443A select failed";
            stopRF();
            return false;
        }

        const bool looks_mfc =
            (card.protocol == "MFC1K" || card.protocol == "MFC4K" || card.protocol == "MFCMini" ||
             card.protocol == "MFCPlus" || card.protocol == "MFPlus2K" || card.protocol == "MFPlus4K");
        if (!looks_mfc) {
            if (error) *error = "GroveNFC dump currently supports MFC only";
            stopRF();
            return false;
        }

        const std::string selected_uid = normalize_uid_hex(card.uid);
        const std::string expect_uid = normalize_uid_hex(uid_hint);
        if (!expect_uid.empty() && expect_uid != selected_uid) {
            if (error) *error = "Card UID changed, rescan card";
            stopRF();
            return false;
        }

        const auto uid_bytes = parse_hex_bytes(selected_uid);
        if (uid_bytes.size() != 4 && uid_bytes.size() != 7) {
            if (error) *error = "Unsupported UID length for GroveNFC MFC dump";
            stopRF();
            return false;
        }

        std::array<uint8_t, 4> auth_uid{};
        if (uid_bytes.size() == 7) {
            auth_uid[0] = uid_bytes[3];
            auth_uid[1] = uid_bytes[4];
            auth_uid[2] = uid_bytes[5];
            auth_uid[3] = uid_bytes[6];
        } else {
            auth_uid[0] = uid_bytes[0];
            auth_uid[1] = uid_bytes[1];
            auth_uid[2] = uid_bytes[2];
            auth_uid[3] = uid_bytes[3];
        }

        auto reselect_same_card = [&]() -> bool {
            I2cCardInfo fresh;
            if (!readISO14A(fresh)) return false;
            if (normalize_uid_hex(fresh.uid) != selected_uid) {
                if (error) *error = "Card UID changed, rescan card";
                return false;
            }
            return true;
        };

        int sector_count = 16;
        if (card.protocol == "MFC4K" || tag_type.find("4K") != std::string::npos) {
            sector_count = 40;
        } else if (card.protocol == "MFCMini" || tag_type.find("Mini") != std::string::npos) {
            sector_count = 5;
        }
        const int block_count = (sector_count == 40) ? 256 : ((sector_count == 5) ? 20 : 64);

        static const std::array<std::array<uint8_t, 6>, 22> common_keys = {{
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
            {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
            {{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}},
            {{0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xA0}},
            {{0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A}},
            {{0x5C, 0x8F, 0xF9, 0x99, 0x0D, 0xA2}},
            {{0x75, 0xCC, 0xB5, 0x9C, 0x9B, 0xED}},
            {{0xD0, 0x1A, 0xFE, 0xEB, 0x89, 0x0A}},
            {{0x4B, 0x79, 0x1B, 0xEA, 0x7B, 0xCC}},
            {{0x26, 0x12, 0xC6, 0xDE, 0x84, 0xCA}},
            {{0x70, 0x7B, 0x11, 0xFC, 0x14, 0x81}},
            {{0x03, 0xF9, 0x06, 0x76, 0x46, 0xAE}},
            {{0x23, 0x52, 0xC5, 0xB5, 0x6D, 0x85}},
            {{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}},
            {{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}},
            {{0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5}},
            {{0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5}},
            {{0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD}},
            {{0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A}},
            {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
            {{0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA}},
            {{0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB}},
        }};

        std::vector<std::array<uint8_t, 6>> auth_keys(common_keys.begin(), common_keys.end());
        append_external_mfc_keys(auth_keys, mfc_key_hex);

        auto emit_progress = [&](const std::string &line) {
            if (progress && *progress) (*progress)(line);
        };

        auto format_mfc_block_line = [&](int block, const uint8_t *data16) {
            char prefix[8];
            std::snprintf(prefix, sizeof(prefix), "%02d:", block);
            return std::string(prefix) + hex_compact(data16, 16);
        };

        auto wait_status = [&](uint16_t done_mask, int timeout_ms, uint16_t *final_status) {
            uint16_t status = 0;
            const auto start = std::chrono::steady_clock::now();
            while (true) {
                status = readSysReg(i2c_reg::NFC_STATUS);
                if ((status & done_mask) ||
                    (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR |
                               STATUS_MIFARE1_AUTHERR | STATUS_MIFARE1_WRITEERR))) {
                    break;
                }
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();
                if (elapsed >= timeout_ms) break;
                delay_ms(2);
            }
            if (final_status) *final_status = status;
            return (status & done_mask) != 0;
        };

        auto enter_mifare1_reader_mode = [&]() {
            if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE)) return false;
            delay_ms(12);
            if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::MIFARE1_READER | i2c_mode::TAG_NONE)) return false;
            delay_ms(12);
            return true;
        };

        out_lines.assign(static_cast<size_t>(block_count), std::string());
        bool any_auth_ok = false;
        bool any_block_ok = false;
        int first_failed_sector = -1;

        for (int sector = 0; sector < sector_count; ++sector) {
            // Re-scan the card before each sector. GroveNFC needs a fresh
            // ISO14443A selection after a failed sector auth before trying the
            // next sector, otherwise the next auth often reuses stale state.
            if (!reselect_same_card()) {
                if (first_failed_sector < 0) first_failed_sector = sector;
                continue;
            }

            const int trailer_block = mfc_sector_trailer_block(sector);
            const int first_block = mfc_sector_first_block(sector);
            const int sector_blocks = mfc_sector_block_count(sector);

            bool sector_auth_ok = false;
            uint8_t sector_auth_cmd = 0x60;
            std::array<uint8_t, 6> sector_key{};

            for (const auto &key : auth_keys) {
                for (uint8_t auth_cmd : {static_cast<uint8_t>(0x60), static_cast<uint8_t>(0x61)}) {
                    if (!enter_mifare1_reader_mode()) {
                        continue;
                    }

                    uint8_t auth_frame[12] = {
                        auth_cmd,
                        static_cast<uint8_t>(trailer_block),
                        auth_uid[0], auth_uid[1], auth_uid[2], auth_uid[3],
                        key[0], key[1], key[2], key[3], key[4], key[5]
                    };

                    writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
                    if (!writeData(i2c_reg::DATA, auth_frame, sizeof(auth_frame))) {
                        continue;
                    }

                    uint16_t auth_status = 0;
                    if (wait_status(STATUS_MIFARE1_AUTHOK, 80, &auth_status)) {
                        sector_auth_ok = true;
                        sector_auth_cmd = auth_cmd;
                        sector_key = key;
                        break;
                    }
                }
                if (sector_auth_ok) break;
            }

            emit_progress(std::string("Check Keys for Sector ") + std::to_string(sector) +
                          (sector_auth_ok ? " OK" : " FAIL"));

            if (!sector_auth_ok) {
                if (first_failed_sector < 0) first_failed_sector = sector;
                continue;
            }

            any_auth_ok = true;

            auto read_sector_blocks = [&]() {
                int ok = 0;
                for (int i = 0; i < sector_blocks; ++i) {
                    const int block = first_block + i;
                    const uint8_t read_cmd[2] = {0x30, static_cast<uint8_t>(block)};

                    writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
                    if (!writeData(i2c_reg::DATA, read_cmd, sizeof(read_cmd))) {
                        continue;
                    }

                    uint16_t read_status = 0;
                    if (!wait_status(STATUS_RECV_DONE, 60, &read_status)) {
                        continue;
                    }

                    uint16_t rx_len = readSysReg(i2c_reg::RX_LEN);
                    if (rx_len < 16) {
                        continue;
                    }

                    uint8_t rx[32] = {0};
                    const uint16_t rx_need = std::min<uint16_t>(rx_len, static_cast<uint16_t>(sizeof(rx)));
                    if (!readData(i2c_reg::DATA, rx, rx_need)) {
                        continue;
                    }

                    out_lines[static_cast<size_t>(block)] = format_mfc_block_line(block, rx);
                    any_block_ok = true;
                    ++ok;
                }
                return ok;
            };

            // At this point the successful probe auth is still active; read
            // immediately to avoid losing state in an unnecessary mode reset.
            int read_ok = read_sector_blocks();

            // Some Grove firmwares may drop auth state right after key check;
            // retry once with fresh select+auth when a whole sector read fails.
            if (read_ok == 0) {
                if (reselect_same_card() && enter_mifare1_reader_mode()) {
                    uint8_t auth_frame[12] = {
                        sector_auth_cmd,
                        static_cast<uint8_t>(trailer_block),
                        auth_uid[0], auth_uid[1], auth_uid[2], auth_uid[3],
                        sector_key[0], sector_key[1], sector_key[2], sector_key[3], sector_key[4], sector_key[5]
                    };
                    writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
                    if (writeData(i2c_reg::DATA, auth_frame, sizeof(auth_frame))) {
                        uint16_t auth_status = 0;
                        if (wait_status(STATUS_MIFARE1_AUTHOK, 80, &auth_status)) {
                            read_ok = read_sector_blocks();
                        }
                    }
                }
            }

            emit_progress("Read Sector " + std::to_string(sector) + " " +
                          std::to_string(read_ok) + "/" + std::to_string(sector_blocks));
        }

        stopRF();
        if (any_block_ok) return true;

        if (error) {
            if (!any_auth_ok) {
                if (first_failed_sector >= 0) {
                    char msg[96];
                    std::snprintf(msg, sizeof(msg),
                                  "MFC auth failed on sector %d (common keys exhausted)",
                                  first_failed_sector);
                    *error = msg;
                } else {
                    *error = "MFC auth failed (common keys exhausted)";
                }
            } else {
                *error = "MFC read failed after auth";
            }
        }
        return false;
    }

    bool dumpNFCUnitMFU(const std::string &uid_hint,
                        std::vector<std::string> &out_lines,
                        std::string *error)
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) {
            if (error) *error = "NFCA select failed";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const std::string selected_uid = hex_compact(uid.data(), uid.size());
        const std::string expect_uid = normalize_uid_hex(uid_hint);
        if (!expect_uid.empty() && expect_uid != selected_uid) {
            if (error) *error = "Card UID changed, rescan card";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        uint8_t ver_len = 24;
        uint8_t ver[24] = {0};
        uint16_t last_page = 63;
        {
            const uint8_t get_ver[1] = {0x60};
            if (st25r_nfca_transceive(get_ver, 1, true, ver, ver_len, 40, 0x00, false, 0) && ver_len >= 8) {
                const uint8_t ic_type = ver[2];
                const uint8_t storage_sz = ver[6];
                if (ic_type == 0x04) {
                    if      (storage_sz == 0x0F) last_page = 44;   // NTAG213
                    else if (storage_sz == 0x11) last_page = 134;  // NTAG215
                    else if (storage_sz == 0x13) last_page = 230;  // NTAG216
                    else if (storage_sz == 0x12) {
                        // Ambiguous reports appear on some clones/firmware paths.
                        // Probe high pages to avoid falsely truncating NTAG213 to NTAG203.
                        const bool has_page44 = st25r_type2_has_page(0x2C);
                        if (has_page44) {
                            const bool has_page134 = st25r_type2_has_page(0x86);
                            const bool has_page230 = has_page134 && st25r_type2_has_page(0xE6);
                            if (has_page230) last_page = 230;
                            else if (has_page134) last_page = 134;
                            else last_page = 44;
                        } else {
                            last_page = 41;  // NTAG203 max page
                        }
                    } else {
                        last_page = 63;
                    }
                } else if (ic_type == 0x03) {
                    if      (storage_sz == 0x0B) last_page = 19;   // Ultralight EV1 UL11
                    else if (storage_sz == 0x0E) last_page = 40;   // Ultralight EV1 UL21
                    else if (storage_sz == 0x06) last_page = 15;   // Ultralight 64B
                    else                         last_page = 63;
                } else {
                    last_page = 63;
                }
            }
        }

        out_lines.clear();
        for (uint16_t page = 0; page <= last_page; page = static_cast<uint16_t>(page + 4)) {
            uint8_t rx_len = 20;
            uint8_t rx[20] = {0};
            const uint8_t cmd[2] = {0x30, static_cast<uint8_t>(page & 0xFF)};
            if (!st25r_nfca_transceive(cmd, 2, true, rx, rx_len, 40, 0x00, false, 0) || rx_len < 16) {
                if (page == 0) {
                    if (error) *error = "MFU read failed";
                    st25r_write_reg(0x02, 0x80);
                    return false;
                }
                break;
            }

            for (uint8_t i = 0; i < 4; ++i) {
                const uint16_t p = static_cast<uint16_t>(page + i);
                if (p > last_page) break;
                char prefix[8];
                std::snprintf(prefix, sizeof(prefix), "%02u:", static_cast<unsigned>(p));
                out_lines.push_back(std::string(prefix) + hex_compact(rx + i * 4, 4));
            }
        }

        st25r_write_reg(0x02, 0x80);
        if (out_lines.empty()) {
            if (error) *error = "MFU dump empty";
            return false;
        }
        return true;
    }

    bool dumpNFCUnitMFC(const std::string &uid_hint,
                        const std::string &tag_type,
                        const std::vector<std::string> *mfc_key_hex,
                        std::string *magic_type,
                        std::vector<std::string> &out_lines,
                        const std::function<void(const std::string &)> *progress,
                        std::string *error)
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) {
            if (error) *error = "MFC select failed";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const std::string selected_uid = hex_compact(uid.data(), uid.size());
        const std::string expect_uid = normalize_uid_hex(uid_hint);
        if (!expect_uid.empty() && expect_uid != selected_uid) {
            if (error) *error = "Card UID changed, rescan card";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const int sector_count = mfc_sector_count_from_sak_tag(sak, tag_type);
        const int block_count = (sector_count == 40) ? 256 : (sector_count == 5 ? 20 : 64);
        auto format_mfc_block_line = [&](int block, const std::array<uint8_t, 16> &data) {
            char prefix[8];
            std::snprintf(prefix, sizeof(prefix), "%02d:", block);
            return std::string(prefix) + hex_compact(data.data(), data.size());
        };

        const std::string detected_magic = st25r_detect_magic_type(selected_uid, sak, true);
        if (magic_type) *magic_type = detected_magic;
        if (!detected_magic.empty()) {
            out_lines.assign(static_cast<size_t>(block_count), std::string());
            bool any_ok = false;
            for (int block = 0; block < block_count; ++block) {
                std::array<uint8_t, 16> data{};
                if (st25r_mfc_read_plain_block(static_cast<uint8_t>(block), data)) {
                    out_lines[static_cast<size_t>(block)] = format_mfc_block_line(block, data);
                    any_ok = true;
                }
            }
            if (any_ok) {
                st25r_write_reg(0x02, 0x80);
                return true;
            }
            if (detected_magic == "Gen1A") {
                st25r_write_reg(0x02, 0x80);
                if (error) *error = "Gen1A detected but read failed";
                return false;
            }
        }

        static const std::array<std::array<uint8_t, 6>, 22> common_keys = {{
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
            {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
            {{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}},
            {{0xA5, 0xA4, 0xA3, 0xA2, 0xA1, 0xA0}},
            {{0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A}},
            {{0x5C, 0x8F, 0xF9, 0x99, 0x0D, 0xA2}},
            {{0x75, 0xCC, 0xB5, 0x9C, 0x9B, 0xED}},
            {{0xD0, 0x1A, 0xFE, 0xEB, 0x89, 0x0A}},
            {{0x4B, 0x79, 0x1B, 0xEA, 0x7B, 0xCC}},
            {{0x26, 0x12, 0xC6, 0xDE, 0x84, 0xCA}},
            {{0x70, 0x7B, 0x11, 0xFC, 0x14, 0x81}},
            {{0x03, 0xF9, 0x06, 0x76, 0x46, 0xAE}},
            {{0x23, 0x52, 0xC5, 0xB5, 0x6D, 0x85}},
            {{0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7}},
            {{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}},
            {{0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5}},
            {{0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5}},
            {{0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD}},
            {{0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A}},
            {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
            {{0xFA, 0xFA, 0xFA, 0xFA, 0xFA, 0xFA}},
            {{0xFB, 0xFB, 0xFB, 0xFB, 0xFB, 0xFB}},
        }};
        std::vector<std::array<uint8_t, 6>> auth_keys(common_keys.begin(), common_keys.end());
        append_external_mfc_keys(auth_keys, mfc_key_hex);

        struct SectorAuthPlan {
            bool valid = false;
            uint8_t auth_cmd = 0x60;
            std::array<uint8_t, 6> key{};
        };
        std::vector<SectorAuthPlan> sector_auth(static_cast<size_t>(sector_count));

        bool any_auth_ok = false;
        int first_failed_sector = -1;

        auto emit_progress = [&](const std::string &line) {
            if (progress && *progress) (*progress)(line);
        };

        auto key_to_hex = [](const std::array<uint8_t, 6> &key) {
            char buf[13];
            std::snprintf(buf, sizeof(buf), "%02X%02X%02X%02X%02X%02X",
                          key[0], key[1], key[2], key[3], key[4], key[5]);
            return std::string(buf);
        };

        auto select_same_card = [&](std::vector<uint8_t> &sector_uid, uint8_t &sector_sak) {
            sector_uid.clear();
            sector_sak = 0;
            if (!st25r_nfca_select_uid(sector_uid, sector_sak)) return false;
            const std::string sector_uid_hex = hex_compact(sector_uid.data(), sector_uid.size());
            return sector_uid_hex == selected_uid;
        };

        auto authenticate_after_select = [&](uint8_t auth_cmd,
                                             int trailer_block,
                                             const std::array<uint8_t, 6> &key,
                                             Crypto1Local &crypto) {
            std::vector<uint8_t> sector_uid;
            uint8_t sector_sak = 0;
            if (!select_same_card(sector_uid, sector_sak)) return false;
            return st25r_mfc_authenticate(auth_cmd, static_cast<uint8_t>(trailer_block), key, sector_uid, crypto);
        };

        // Phase 1: probe each sector with the key list and remember usable auth mode/key.
        for (int sector = 0; sector < sector_count; ++sector) {
            const int trailer_block = mfc_sector_trailer_block(sector);
            std::string progress_line = "Check Keys for Sector " + std::to_string(sector) + " ";

            for (const auto &k : auth_keys) {
                progress_line.push_back('.');
                Crypto1Local probe_crypto;
                if (authenticate_after_select(0x60, trailer_block, k, probe_crypto)) {
                    sector_auth[static_cast<size_t>(sector)] = {true, 0x60, k};
                    any_auth_ok = true;
                    progress_line += " OK KeyA " + key_to_hex(k);
                    break;
                }
                if (authenticate_after_select(0x61, trailer_block, k, probe_crypto)) {
                    sector_auth[static_cast<size_t>(sector)] = {true, 0x61, k};
                    any_auth_ok = true;
                    progress_line += " OK KeyB " + key_to_hex(k);
                    break;
                }
            }

            if (!sector_auth[static_cast<size_t>(sector)].valid && first_failed_sector < 0) {
                first_failed_sector = sector;
            }
            if (!sector_auth[static_cast<size_t>(sector)].valid) progress_line += " FAIL";
            emit_progress(progress_line);
        }

        out_lines.assign(static_cast<size_t>(block_count), std::string());
        bool any_block_ok = false;

        // Phase 2: read each sector only after a valid key/auth mode has been found.
        for (int sector = 0; sector < sector_count; ++sector) {
            const auto &plan = sector_auth[static_cast<size_t>(sector)];
            if (!plan.valid) continue;

            const int first_block = mfc_sector_first_block(sector);
            const int sector_blocks = mfc_sector_block_count(sector);
            const int trailer_block = mfc_sector_trailer_block(sector);

            Crypto1Local crypto;
            if (!authenticate_after_select(plan.auth_cmd, trailer_block, plan.key, crypto)) {
                continue;
            }

            int read_ok = 0;
            for (int i = 0; i < sector_blocks; ++i) {
                const int block = first_block + i;
                std::array<uint8_t, 16> data{};
                if (st25r_mfc_read_block(crypto, static_cast<uint8_t>(block), data)) {
                    out_lines[static_cast<size_t>(block)] = format_mfc_block_line(block, data);
                    any_block_ok = true;
                    ++read_ok;
                }
            }
            emit_progress("Read Sector " + std::to_string(sector) + " " +
                          std::string(static_cast<size_t>(read_ok), '.') +
                          " " + std::to_string(read_ok) + "/" + std::to_string(sector_blocks));
        }

        st25r_write_reg(0x02, 0x80);
        if (!any_block_ok) {
            if (error) {
                if (!any_auth_ok) {
                    if (first_failed_sector >= 0) {
                        char msg[96];
                        std::snprintf(msg, sizeof(msg), "MFC auth failed on sector %d (common keys exhausted)", first_failed_sector);
                        *error = msg;
                    } else {
                        *error = "MFC auth failed (common keys exhausted)";
                    }
                } else {
                    *error = "MFC read failed after auth";
                }
            }
            return false;
        }

        return true;
    }

    bool dumpNFCUnitISO15693(const std::string &uid_hint,
                             std::vector<std::string> &out_lines,
                             std::string *error)
    {
        if (!configure_nfcv()) {
            if (error) *error = "ISO15693 init failed";
            return false;
        }

        uint8_t inv_req[3] = {0x26, 0x01, 0x00};
        uint8_t inv_dec[48] = {0};
        uint8_t inv_len = 0;
        if (!st25r_nfcv_transceive(inv_req, 3, inv_dec, inv_len, 80) || inv_len < 10) {
            restore_iso14443a();
            if (error) *error = "ISO15693 inventory failed";
            return false;
        }

        std::array<uint8_t, 8> uid_lsb{};
        for (size_t i = 0; i < uid_lsb.size(); ++i) uid_lsb[i] = inv_dec[2 + i];

        std::string uid_msb;
        uid_msb.reserve(16);
        for (int i = 7; i >= 0; --i) {
            char h[3];
            std::snprintf(h, sizeof(h), "%02X", uid_lsb[static_cast<size_t>(i)]);
            uid_msb += h;
        }
        const std::string expect_uid = normalize_uid_hex(uid_hint);
        if (!expect_uid.empty() && expect_uid != uid_msb) {
            restore_iso14443a();
            if (error) *error = "Card UID changed, rescan card";
            return false;
        }

        uint16_t block_count = 32;
        uint8_t sys_req[10] = {0x22, 0x2B};
        for (size_t i = 0; i < uid_lsb.size(); ++i) sys_req[2 + i] = uid_lsb[i];
        uint8_t sys_dec[64] = {0};
        uint8_t sys_len = 0;
        if (st25r_nfcv_transceive(sys_req, sizeof(sys_req), sys_dec, sys_len, 100) &&
            sys_len >= 12 && (sys_dec[0] & 0x01) == 0) {
            const uint8_t info_flags = sys_dec[1];
            size_t idx = 2 + 8;  // info_flags + UID
            if (info_flags & 0x01) idx += 1;  // DSFID
            if (info_flags & 0x02) idx += 1;  // AFI
            if ((info_flags & 0x04) && idx + 1 < sys_len) {
                block_count = static_cast<uint16_t>(sys_dec[idx] + 1);
            }
        }

        block_count = std::min<uint16_t>(block_count, 256);
        out_lines.clear();
        for (uint16_t block = 0; block < block_count; ++block) {
            uint8_t req[11] = {0x22, 0x20};
            for (size_t i = 0; i < uid_lsb.size(); ++i) req[2 + i] = uid_lsb[i];
            req[10] = static_cast<uint8_t>(block & 0xFF);

            uint8_t dec[64] = {0};
            uint8_t dec_len = 0;
            if (!st25r_nfcv_transceive(req, sizeof(req), dec, dec_len, 80) || dec_len < 2) {
                if (block == 0) {
                    restore_iso14443a();
                    if (error) *error = "ISO15693 read block failed";
                    return false;
                }
                break;
            }
            if (dec[0] & 0x01) {
                if (block == 0) {
                    restore_iso14443a();
                    if (error) {
                        char msg[48];
                        std::snprintf(msg, sizeof(msg), "ISO15693 error 0x%02X", dec_len > 1 ? dec[1] : 0xFF);
                        *error = msg;
                    }
                    return false;
                }
                break;
            }

            char prefix[8];
            std::snprintf(prefix, sizeof(prefix), "%02u:", static_cast<unsigned>(block));
            out_lines.push_back(std::string(prefix) + hex_compact(dec + 1, dec_len - 1));
        }

        restore_iso14443a();
        if (out_lines.empty()) {
            if (error) *error = "ISO15693 dump empty";
            return false;
        }
        return true;
    }

    // ── NFC Unit write helpers ────────────────────────────────────────────────

    // Write MIFARE Classic (1K/4K) data to NFC Unit.
    // Handles Gen1A magic cards (plain write), Gen3/Gen4 and standard MFC
    // (authenticated write). lines format: "NN: HEXHEX...", 16 bytes per line.
    bool writeNFCUnitMFC(const std::string &tag_type,
                         const std::vector<std::string> &lines,
                         const std::vector<std::string> *mfc_key_hex,
                         const std::function<void(const std::string &)> *progress,
                         std::string *error)
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) {
            if (error) *error = "No card detected";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const std::string selected_uid = hex_compact(uid.data(), uid.size());
        const int sector_count = mfc_sector_count_from_sak_tag(sak, tag_type);
        const int block_count = (sector_count == 40) ? 256 : (sector_count == 5 ? 20 : 64);

        // Parse dump lines into per-block (block_index -> 16 bytes)
        std::vector<std::vector<uint8_t>> blocks(static_cast<size_t>(block_count));
        for (const auto &line : lines) {
            if (line.size() < 5) continue;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            int blk = 0;
            try { blk = std::stoi(line.substr(0, colon)); } catch (...) { continue; }
            if (blk < 0 || blk >= block_count) continue;
            std::string hex = line.substr(colon + 1);
            auto &dst = blocks[static_cast<size_t>(blk)];
            for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                char *end = nullptr;
                unsigned long val = std::strtoul(hex.substr(i, 2).c_str(), &end, 16);
                if (end && *end == '\0') dst.push_back(static_cast<uint8_t>(val));
            }
            if (dst.size() > 16) dst.resize(16);
        }

        if (blocks[0].size() < 16) {
            if (error) *error = "Missing block 0 in dump data";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        auto emit = [&](const std::string &s) {
            if (progress && *progress) (*progress)(s);
        };
        emit("Found " + selected_uid);

        std::this_thread::sleep_for(std::chrono::seconds(1));

        // ── Detect magic type ─────────────────────────────────────────────
        const std::string magic = st25r_detect_magic_type(selected_uid, sak, true);
        if (!magic.empty())
            emit("Magic: " + magic);
        else
            emit("MFC standard");

        std::this_thread::sleep_for(std::chrono::seconds(1));

        if (magic == "Gen1A") {
            emit("Gen1A detected, writing blocks...");
            // Card is already unlocked by st25r_is_gen1a_magic inside detect.
            // Write block 0 directly, then plain-write blocks 1..N.
            uint8_t ack[4] = {0};
            uint8_t ack_len = 4;
            // Write block 0: A0 00 + 16 bytes
            const uint8_t w0_cmd[2] = {0xA0, 0x00};
            if (!st25r_nfca_transceive(w0_cmd, 2, true, ack, ack_len, 60, 0x00, false, 0) ||
                !st25r_nfca_transceive(blocks[0].data(), 16, true, ack, ack_len, 60, 0x00, false, 0)) {
                st25r_write_reg(0x02, 0x80);
                if (error) *error = "Gen1A write block 0 failed";
                return false;
            }
            char b0[64];
            std::snprintf(b0, sizeof(b0), "Write block 0:%02X%02X%02X%02X%02X%02X%02X%02X...",
                          blocks[0][0], blocks[0][1], blocks[0][2], blocks[0][3],
                          blocks[0][4], blocks[0][5], blocks[0][6], blocks[0][7]);
            emit(b0);
            // Write remaining blocks 1..N with plain A0+block/16B
            auto plain_write = [&](int blk) -> bool {
                if (blocks[static_cast<size_t>(blk)].size() < 16) return true;
                const uint8_t cmd[2] = {0xA0, static_cast<uint8_t>(blk)};
                uint8_t a1[4] = {0}, a1_len = 4;
                if (!st25r_nfca_transceive(cmd, 2, true, a1, a1_len, 60, 0x00, false, 0)) return false;
                uint8_t a2[4] = {0}, a2_len = 4;
                if (!st25r_nfca_transceive(blocks[static_cast<size_t>(blk)].data(), 16, true, a2, a2_len, 60, 0x00, false, 0))
                    return false;
                return (a2_len > 0 && (a2[0] & 0x0F) == 0x0A);
            };
            for (int blk = 1; blk < block_count; ++blk) {
                if (!plain_write(blk)) {
                    emit("Write block " + std::to_string(blk) + " failed");
                } else {
                    char progress[64];
                    const auto &bdata = blocks[static_cast<size_t>(blk)];
                    std::snprintf(progress, sizeof(progress), "Write block %d:%02X%02X%02X%02X%02X%02X%02X%02X...",
                                  blk, bdata[0], bdata[1], bdata[2], bdata[3],
                                  bdata[4], bdata[5], bdata[6], bdata[7]);
                    emit(progress);
                }
            }
            st25r_write_reg(0x02, 0x80);
            emit("Gen1A write complete");
            if (error) error->clear();
            return true;
        }

        // ── Standard MFC / Gen3 / Gen4: authenticate and write ───────────
        // Build key list
        static const std::array<std::array<uint8_t, 6>, 6> fallback_keys = {{
            {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
            {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
            {{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}},
            {{0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5}},
            {{0x4D, 0x3A, 0x99, 0xC3, 0x51, 0xDD}},
            {{0x1A, 0x98, 0x2C, 0x7E, 0x45, 0x9A}},
        }};
        std::vector<std::array<uint8_t, 6>> auth_keys(fallback_keys.begin(), fallback_keys.end());
        append_external_mfc_keys(auth_keys, mfc_key_hex);

        auto select_and_auth = [&](std::vector<uint8_t> &sector_uid, uint8_t &sector_sak,
                                   int trailer_block, const std::array<uint8_t, 6> &key,
                                   uint8_t auth_cmd, Crypto1Local &crypto) -> bool {
            sector_uid.clear();
            sector_sak = 0;
            if (!st25r_nfca_select_uid(sector_uid, sector_sak)) return false;
            if (hex_compact(sector_uid.data(), sector_uid.size()) != selected_uid) return false;
            return st25r_mfc_authenticate(auth_cmd, static_cast<uint8_t>(trailer_block), key, sector_uid, crypto);
        };

        auto mfc_write_block_enc = [&](Crypto1Local &crypto, uint8_t block,
                                       const std::vector<uint8_t> &data) -> bool {
            if (data.size() < 16) return false;
            const uint8_t cmd[2] = {0xA0, block};
            uint8_t rx[4] = {0};
            uint8_t rx_len = 4;
            if (!st25r_mfc_transceive_encrypted(crypto, rx, rx_len, cmd, sizeof(cmd), 40, true, true))
                return false;
            uint8_t wb[18] = {0};
            std::copy(data.begin(), data.begin() + 16, wb);
            uint8_t wb_rx[4] = {0};
            uint8_t wb_rx_len = 4;
            if (!st25r_mfc_transceive_encrypted(crypto, wb_rx, wb_rx_len, wb, 16, 40, true, true))
                return false;
            return (wb_rx_len > 0 && (wb_rx[0] & 0x0F) == 0x0A);
        };

        int written = 0;
        for (int sector = 0; sector < sector_count; ++sector) {
            const int first_block = mfc_sector_first_block(sector);
            const int sector_blocks = mfc_sector_block_count(sector);
            const int trailer_block = mfc_sector_trailer_block(sector);

            // Find a working key
            std::array<uint8_t, 6> found_key{};
            uint8_t found_cmd = 0;
            bool auth_ok = false;

            for (const auto &k : auth_keys) {
                Crypto1Local probe;
                if (select_and_auth(uid, sak, trailer_block, k, 0x60, probe)) {
                    found_key = k; found_cmd = 0x60; auth_ok = true; break;
                }
                if (select_and_auth(uid, sak, trailer_block, k, 0x61, probe)) {
                    found_key = k; found_cmd = 0x61; auth_ok = true; break;
                }
            }
            if (!auth_ok) {
                emit("Sector " + std::to_string(sector) + " auth failed, skipping");
                continue;
            }

            // Skip trailer block (block == last block in sector) to avoid locking
            for (int i = 0; i < sector_blocks; ++i) {
                const int blk = first_block + i;
                if (blk == trailer_block) continue; // don't write sector trailer
                if (blocks[static_cast<size_t>(blk)].size() < 16) continue;

                Crypto1Local crypto;
                if (!select_and_auth(uid, sak, trailer_block, found_key, found_cmd, crypto)) {
                    emit("Sector " + std::to_string(sector) + " re-auth failed");
                    break;
                }
                if (mfc_write_block_enc(crypto, static_cast<uint8_t>(blk), blocks[static_cast<size_t>(blk)])) {
                    ++written;
                    char progress[64];
                    const auto &bdata = blocks[static_cast<size_t>(blk)];
                    std::snprintf(progress, sizeof(progress), "Write block %d:%02X%02X%02X%02X%02X%02X%02X%02X...",
                                  blk, bdata[0], bdata[1], bdata[2], bdata[3],
                                  bdata[4], bdata[5], bdata[6], bdata[7]);
                    emit(progress);
                } else {
                    emit("Write block " + std::to_string(blk) + " failed");
                }
            }
        }

        st25r_write_reg(0x02, 0x80);
        if (written == 0 && !magic.empty()) {
            // Non-Gen1A magic: try Gen4-style write
            if (error) *error = "No blocks written (card may need different keys)";
            return false;
        }
        emit("MFC write done: " + std::to_string(written) + " blocks");
        if (error) error->clear();
        return written > 0;
    }

    // Write MFU/NTAG data to NFC Unit.
    // Use COMPLIANCE_WRITE (0xA2) command. pages are 4 bytes each.
    bool writeNFCUnitMFU(const std::string &tag_type,
                         const std::vector<std::string> &lines,
                         const std::function<void(const std::string &)> *progress,
                         std::string *error)
    {
        std::vector<uint8_t> uid;
        uint8_t sak = 0;
        if (!st25r_nfca_select_uid(uid, sak)) {
            if (error) *error = "No card detected";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        const std::string selected_uid = hex_compact(uid.data(), uid.size());

        auto emit = [&](const std::string &s) {
            if (progress && *progress) (*progress)(s);
        };

        // Verify card is MFU/NTAG (SAK=0x00)
        if (sak != 0x00) {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "Card SAK=0x%02X, expected NTAG/MFU (SAK=00)", sak);
            if (error) *error = msg;
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        emit("Found " + selected_uid);

        std::this_thread::sleep_for(std::chrono::seconds(1));

        // Parse pages: "NN: XXXXXXXX"
        std::map<uint8_t, std::array<uint8_t, 4>> pages;
        for (const auto &line : lines) {
            if (line.size() < 5) continue;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            int pg = 0;
            try { pg = std::stoi(line.substr(0, colon)); } catch (...) { continue; }
            if (pg < 0 || pg > 255) continue;
            std::string hex = line.substr(colon + 1);
            std::array<uint8_t, 4> data{};
            for (size_t i = 0; i < 4 && (i * 2 + 1) < hex.size(); ++i) {
                char *end = nullptr;
                unsigned long val = std::strtoul(hex.substr(i * 2, 2).c_str(), &end, 16);
                if (end && *end == '\0') data[i] = static_cast<uint8_t>(val);
            }
            pages[static_cast<uint8_t>(pg)] = data;
        }

        if (pages.empty()) {
            if (error) *error = "No pages to write";
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        int written = 0;
        // NTAG: skip first 4 pages (page 0-3) to preserve UID/manufacturer data
        for (const auto &kv : pages) {
            uint8_t pg = kv.first;
            if (pg < 4) continue;  // skip first 4 pages
            const auto &data = kv.second;
            // COMPLIANCE_WRITE: 0xA2 + page + 4 bytes
            uint8_t cmd[6] = {0xA2, pg, data[0], data[1], data[2], data[3]};
            uint8_t rx[4] = {0};
            uint8_t rx_len = 4;
            if (!st25r_nfca_transceive(cmd, 6, true, rx, rx_len, 50, 0x00, false, 0)) {
                emit("Write page " + std::to_string(pg) + " failed");
                continue;
            }
            if (rx_len > 0 && (rx[0] & 0x0F) == 0x0A) {
                ++written;
                char progress[64];
                std::snprintf(progress, sizeof(progress), "Write page %d:%02X%02X%02X%02X",
                              pg, data[0], data[1], data[2], data[3]);
                emit(progress);
            } else {
                emit("Write page " + std::to_string(pg) + " NAK");
            }
        }

        st25r_write_reg(0x02, 0x80);
        if (written == 0) {
            if (error) *error = "No pages written (wrong tag type?)";
            return false;
        }
        emit("MFU write done: " + std::to_string(written) + " pages");
        if (error) error->clear();
        return written > 0;
    }

    // Write ISO15693 data to NFC Unit.
    // Uses WRITE SINGLE BLOCK (0x21) command.
    bool writeNFCUnitISO15693(const std::vector<std::string> &lines,
                              const std::function<void(const std::string &)> *progress,
                              std::string *error)
    {
        if (!configure_nfcv()) {
            if (error) *error = "ISO15693 init failed";
            return false;
        }

        auto emit = [&](const std::string &s) {
            if (progress && *progress) (*progress)(s);
        };

        // Inventory to get UID
        uint8_t inv_req[3] = {0x26, 0x01, 0x00};
        uint8_t inv_dec[48] = {0};
        uint8_t inv_len = 0;
        if (!st25r_nfcv_transceive(inv_req, 3, inv_dec, inv_len, 80) || inv_len < 10) {
            restore_iso14443a();
            if (error) *error = "ISO15693 inventory failed";
            return false;
        }
        std::array<uint8_t, 8> uid_lsb{};
        for (size_t i = 0; i < uid_lsb.size(); ++i) uid_lsb[i] = inv_dec[2 + i];

        // Parse blocks: "NN: XXXX..." (block size varies, typically 4 bytes)
        std::map<uint16_t, std::vector<uint8_t>> blocks;
        for (const auto &line : lines) {
            if (line.size() < 5) continue;
            size_t colon = line.find(':');
            if (colon == std::string::npos) continue;
            int blk = 0;
            try { blk = std::stoi(line.substr(0, colon)); } catch (...) { continue; }
            if (blk < 0 || blk > 255) continue;
            std::string hex = line.substr(colon + 1);
            std::vector<uint8_t> data;
            for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                char *end = nullptr;
                unsigned long val = std::strtoul(hex.substr(i, 2).c_str(), &end, 16);
                if (end && *end == '\0') data.push_back(static_cast<uint8_t>(val));
            }
            blocks[static_cast<uint16_t>(blk)] = std::move(data);
        }

        if (blocks.empty()) {
            restore_iso14443a();
            if (error) *error = "No blocks to write";
            return false;
        }

        int written = 0;
        for (const auto &kv : blocks) {
            uint16_t blk = kv.first;
            const auto &data = kv.second;
            if (data.empty()) continue;

            // WRITE SINGLE BLOCK: 0x21 + UID(8) + block(2) + data(N) with CRC
            std::vector<uint8_t> req;
            req.push_back(0x22);  // Addressed mode
            req.push_back(0x21);  // Write Single Block
            for (size_t i = 0; i < uid_lsb.size(); ++i) req.push_back(uid_lsb[i]);
            req.push_back(static_cast<uint8_t>(blk & 0xFF));

            // Data (block size from the dump line)
            for (uint8_t b : data) req.push_back(b);

            uint8_t dec[64] = {0};
            uint8_t dec_len = 0;
            if (!st25r_nfcv_transceive(req.data(), static_cast<uint8_t>(req.size()),
                                       dec, dec_len, 80) || dec_len < 1) {
                emit("Write block " + std::to_string(blk) + " timeout");
                continue;
            }
            if (dec[0] & 0x01) {
                emit("Write block " + std::to_string(blk) + " error");
                continue;
            }
            ++written;
            // Show block index + first 4 hex bytes in footer
            char progress[64];
            std::snprintf(progress, sizeof(progress), "Write block %d:%02X%02X%02X%02X",
                          blk,
                          data.size() > 0 ? data[0] : 0,
                          data.size() > 1 ? data[1] : 0,
                          data.size() > 2 ? data[2] : 0,
                          data.size() > 3 ? data[3] : 0);
            emit(progress);
        }

        restore_iso14443a();
        if (written == 0) {
            if (error) *error = "No blocks written";
            return false;
        }
        emit("ISO15693 write done: " + std::to_string(written) + " blocks");
        if (error) error->clear();
        return written > 0;
    }

    // ── ST25R3916B ISO14443A card reader ─────────────────────────────────────
    // Implements WUPA → ATQA → SDD CL1/CL2 → SELECT → UID + SAK.
    // Returns true if a card was found.
    bool readCardNFCUnit(I2cCardInfo &card)
    {
        if (fd_ < 0) return false;
        card.magic_type.clear();
        card.atqa_hex.clear();
        card.sak_hex.clear();

        auto &hexlog = NfcHexLog::get();

        if (nfcunit_listener_running_) {
            nfcunit_stop_listener();
        } else {
            restore_iso14443a();
        }

        // Init sequence per M5UnitNFC library reference (confirmed via hardware testing):
        // 1. Enable oscillator only, configure mode/bitrate/receiver.
        // 2. CMD_NFC_INITIAL_FIELD_ON (0xC8) = RF Collision Avoidance + field on.
        // 3. Set tx_en | rx_en in OP_CONTROL.
        hexlog.log_event("NFC-I2C", "Init: OSC only, mode/receiver config, CMD_NFC_INITIAL_FIELD_ON");
        st25r_cmd(0xD6);              // ADJUST_REGULATORS first
        delay_ms(5);
        st25r_write_reg(0x02, 0x80);  // OP_CONTROL: en (osc only, no TX yet)
        delay_ms(20);
        // Clear any pending IRQs
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }

        // ISO14443A initiator mode at 106 kbps.
        st25r_write_reg(0x03, 0x08);  // MODE: om_iso14443a
        st25r_write_reg(0x04, 0x00);  // BIT_RATE: 106kbps
        st25r_write_reg(0x05, 0x00);  // ISO14443A_NFC: no antcl, no no_rx_par (initial)
        st25r_write_reg(0x09, 0x03);  // TX1+TX2 antenna drivers
        st25r_write_reg(0x26, 0x80);  // IRQ_MASK: only mask osc IRQ
        // Receiver configuration (per M5UnitNFC stability settings):
        st25r_write_reg(0x0B, 0x08);  // ReceiverConfig1: z_600k
        st25r_write_reg(0x0C, 0x2D);  // ReceiverConfig2: agc settings
        st25r_write_reg(0x0D, 0xD8);  // ReceiverConfig3: stability
        st25r_write_reg(0x0E, 0x22);  // ReceiverConfig4: stability
        delay_ms(10);

        // CMD_NFC_INITIAL_FIELD_ON (0xC8): RFCA + enable RF field.
        st25r_cmd(0xC8);
        delay_ms(10);
        // Now set tx_en (bit3) | rx_en (bit6) in OP_CONTROL.
        {
            uint8_t op = 0x80;
            st25r_read_reg(0x02, op);
            if (!st25r_write_reg(0x02, op | 0x48)) {
                hexlog.log_event("NFC-I2C", "ERR: OP_CONTROL write failed");
                return false;
            }
        }
        delay_ms(20);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }  // clear IRQs

        // Clear FIFO + IRQ status, then send WUPA (wakes IDLE and HALT cards).
        hexlog.log_event("NFC-I2C", "CMD CLEAR_FIFO (0xDB) then TRANSMIT_WUPA (0xC7)");
        st25r_cmd(0xDB);  // CLEAR_FIFO
        st25r_cmd(0xC7);  // TRANSMIT_WUPA (7-bit short frame, no CRC)

        // Wait for ATQA (end-of-receive IRQ_MAIN bit4=rxe).
        uint8_t irq = st25r_wait_irq(0x10 | 0x04, 25);
        {
            char irq_msg[40];
            std::snprintf(irq_msg, sizeof(irq_msg), "WUPA irq=0x%02X (rxe=%d col=%d)",
                          irq, !!(irq & 0x10), !!(irq & 0x04));
            hexlog.log_event("NFC-I2C", irq_msg);
        }
        if (!(irq & 0x10)) {
            // Some Mifare Classic cards need a second short-frame wakeup after
            // RF field stabilization. Retry once before falling back to ISO15693.
            st25r_cmd(0xDB);
            st25r_cmd(0xC7);
            irq = st25r_wait_irq(0x10 | 0x04, 40);
            {
                char irq_retry_msg[48];
                std::snprintf(irq_retry_msg, sizeof(irq_retry_msg),
                              "WUPA retry irq=0x%02X (rxe=%d col=%d)",
                              irq, !!(irq & 0x10), !!(irq & 0x04));
                hexlog.log_event("NFC-I2C", irq_retry_msg);
            }
        }
        if (!(irq & (0x10 | 0x04))) {
            hexlog.log_event("NFC-I2C", "WUPA: no rxe → try ISO15693 SubCarrierStream");
            // ── ISO15693 INVENTORY (SubCarrierStream mode) ────────────────
            // ST25R3916B has no native ISO15693 mode.  It uses SubCarrierStream
            // (MODE=0x70) with software 1-of-4 PPM TX and Manchester decode RX.
            // Reference: M5UnitNFC configure_nfc_v() + encode_VCD() + decode_VICC().

            configure_nfcv();  // includes CMD_NFC_INITIAL_FIELD_ON + 5ms delay

            // Encode INVENTORY frame: {0x26, 0x01, 0x00} + CRC16 → 1-of-4 PPM
            const uint8_t inv_raw[3] = {0x26, 0x01, 0x00};
            uint8_t encoded[32];
            uint8_t enc_len = encode_nfcv_1of4(encoded, inv_raw, 3);

            st25r_cmd(0xDB);  // CLEAR_FIFO
            { uint8_t dummy15 = 0; st25r_read_reg(0x1A, dummy15); }

            if (!st25r_fifo_write(encoded, enc_len)) {
                hexlog.log_event("NFC-I2C", "ISO15693: FIFO write failed");
                restore_iso14443a();
                return false;
            }
            // NUM_TX_BYTES: total encoded bytes (CRC already inside encoded stream)
            st25r_set_ntx(enc_len, 0);
            { uint8_t dummy15 = 0; st25r_read_reg(0x1A, dummy15); }
            st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC (CRC is inside PPM stream)

            // Wait for txe then rxe
            uint8_t irq15 = st25r_wait_irq(0x08, 20);
            if (irq15 & 0x08) {
                irq15 |= st25r_wait_irq(0x10 | 0x04, 50);
            }
            {
                char msg15[64];
                std::snprintf(msg15, sizeof(msg15), "ISO15693 irq=0x%02X (rxe=%d txe=%d)",
                              irq15, !!(irq15 & 0x10), !!(irq15 & 0x08));
                hexlog.log_event("NFC-I2C", msg15);
            }
            if (!(irq15 & 0x10)) {
                hexlog.log_event("NFC-I2C", "ISO15693: no response → no card");
                restore_iso14443a();
                return false;
            }

            // Read raw Manchester-encoded response from FIFO
            uint8_t fc15 = 0;
            st25r_read_reg(0x1E, fc15);
            {
                char msg15[48];
                std::snprintf(msg15, sizeof(msg15), "ISO15693 FIFO=%d bytes", fc15);
                hexlog.log_event("NFC-I2C", msg15);
            }
            if (fc15 < 8) {
                hexlog.log_event("NFC-I2C", "ISO15693: response too short");
                restore_iso14443a();
                return false;
            }
            uint8_t raw15[64] = {0};
            uint8_t to_read15 = (fc15 < 64) ? fc15 : 64;
            if (!st25r_fifo_read(raw15, to_read15)) {
                hexlog.log_event("NFC-I2C", "ISO15693: FIFO read failed");
                restore_iso14443a();
                return false;
            }

            // Decode Manchester stream → flags + DSFID + UID (8 bytes) [+ CRC stripped]
            uint8_t decoded[32] = {0};
            uint8_t dec_len = 0;
            if (!decode_vicc_manchester(raw15, to_read15, decoded, dec_len) || dec_len < 10) {
                char msg15[64];
                std::snprintf(msg15, sizeof(msg15),
                              "ISO15693: decode failed (fc=%d dec=%d sof=0x%02X)",
                              fc15, dec_len, raw15[0]);
                hexlog.log_event("NFC-I2C", msg15);
                restore_iso14443a();
                return false;
            }

            // decoded[0] = response flags, decoded[1] = DSFID, decoded[2..9] = UID LSB-first
            std::string uid15;
            uid15.reserve(16);
            for (int i = 9; i >= 2; --i) {
                char h[3];
                std::snprintf(h, sizeof(h), "%02X", decoded[i]);
                uid15 += h;
            }
            {
                char msg15[72];
                std::snprintf(msg15, sizeof(msg15),
                              "ISO15693 flags=0x%02X DSFID=0x%02X UID=%s",
                              decoded[0], decoded[1], uid15.c_str());
                hexlog.log_event("NFC-I2C", msg15);
            }
            std::string dsfid_hex = "00";
            std::string afi_hex = "00";
            std::string ic_ref_hex;
            uint16_t block_count = 0;
            uint8_t block_bytes = 0;
            bool has_block_layout = false;

            uint8_t sys_req[10] = {0x22, 0x2B};
            for (size_t i = 0; i < 8; ++i) sys_req[2 + i] = decoded[2 + i];
            uint8_t sys_dec[64] = {0};
            uint8_t sys_len = 0;
            if (st25r_nfcv_transceive(sys_req, sizeof(sys_req), sys_dec, sys_len, 100) &&
                sys_len >= 10 && (sys_dec[0] & 0x01) == 0) {
                const uint8_t info_flags = sys_dec[1];
                size_t idx = 2 + 8;  // response_flags + info_flags + UID(LSB)

                auto hex2 = [](uint8_t v) {
                    char buf[3];
                    std::snprintf(buf, sizeof(buf), "%02X", v);
                    return std::string(buf);
                };

                if ((info_flags & 0x01) && idx < sys_len) dsfid_hex = hex2(sys_dec[idx++]);
                if ((info_flags & 0x02) && idx < sys_len) afi_hex = hex2(sys_dec[idx++]);
                if ((info_flags & 0x04) && idx + 1 < sys_len) {
                    const uint8_t blocks_minus_one = sys_dec[idx++];
                    const uint8_t block_size_raw = sys_dec[idx++];
                    block_count = static_cast<uint16_t>(blocks_minus_one) + 1;
                    block_bytes = static_cast<uint8_t>(block_size_raw & 0x1F) + 1;
                    has_block_layout = true;
                }
                if ((info_flags & 0x08) && idx < sys_len) ic_ref_hex = hex2(sys_dec[idx++]);
            }

            card.uid      = uid15;
            card.protocol = "ISO15693";
            {
                std::string detail = "ISO15693 Tag DSFID:" + dsfid_hex + ", AFI:" + afi_hex;
                if (!ic_ref_hex.empty()) detail += ", IC Reference:" + ic_ref_hex;
                if (has_block_layout) {
                    detail += ", Block size:" + std::to_string(block_count);
                    detail += ", Block bytes:" + std::to_string(block_bytes);
                }
                card.detail = detail;
            }
            card.valid    = true;
            card.atqa_hex.clear();
            card.sak_hex.clear();
            restore_iso14443a();
            return true;
        }

        // Read ATQA when rxe is present. If collision-only IRQ happened, still
        // continue anticollision with ATQA unknown to avoid false "no card".
        uint8_t fifo_cnt = 0;
        uint8_t atqa[2] = {0, 0};
        if (irq & 0x10) {
            st25r_read_reg(0x1E, fifo_cnt);
            if (fifo_cnt < 2) {
                hexlog.log_event("NFC-I2C", "ATQA: FIFO too short (<2 bytes)");
                st25r_write_reg(0x02, 0x80);
                return false;
            }
            if (!st25r_fifo_read(atqa, 2)) {
                hexlog.log_event("NFC-I2C", "ATQA: FIFO read failed");
                st25r_write_reg(0x02, 0x80);
                return false;
            }
            // Drain any extra FIFO bytes beyond the 2 ATQA bytes.
            if (fifo_cnt > 2) {
                uint8_t drain[8];
                st25r_fifo_read(drain, (uint8_t)(fifo_cnt - 2));
            }
        } else {
            hexlog.log_event("NFC-I2C", "WUPA collision-only IRQ, continue with anticollision");
        }
        // Clear IRQ before next step.
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
        {
            char atqa_msg[40];
            std::snprintf(atqa_msg, sizeof(atqa_msg), "ATQA=%02X%02X", atqa[0], atqa[1]);
            hexlog.log_event("NFC-I2C", atqa_msg);
        }
        {
            char atqa_hex[5];
            std::snprintf(atqa_hex, sizeof(atqa_hex), "%02X%02X", atqa[0], atqa[1]);
            card.atqa_hex = atqa_hex;
        }

        // ── Anticollision CL1 ────────────────────────────────────────────────
        // Set antcl (bit0) in ISO14443A_NFC reg for anticollision bit-framing.
        // no_rx_par (bit6=0x40) is intentionally NOT set here (parity checked).
        hexlog.log_event("NFC-I2C", "Anticol CL1: ISO14443A_NFC=0x01, sending 93 20");
        st25r_write_reg(0x05, 0x01);  // antcl only (NOT 0x81 - bit7 is not no_rx_par!)
        st25r_cmd(0xDB);
        const uint8_t anticol1[2] = {0x93, 0x20};
        if (!st25r_fifo_write(anticol1, 2)) {
            hexlog.log_event("NFC-I2C", "CL1: FIFO write failed");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        // NUM_TX_BYTES: 16-bit big-endian at 0x22-0x23, value = (bytes<<3)|last_bits
        // For 2 complete bytes: (2<<3)|0 = 0x0010 → 0x22=0x00, 0x23=0x10
        st25r_set_ntx(2);
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }  // clear IRQ
        st25r_cmd(0xC5);  // TRANSMIT_WITHOUT_CRC (transceive: auto-enables RX after TX)

        // CMD_TRANSMIT_WITHOUT_CRC is a transceive: no separate RECEIVE command needed.
        // Wait directly for rxe (bit4) or col (bit2). No txe-then-RECEIVE sequence!
        irq = st25r_wait_irq(0x10 | 0x04, 50);
        {
            char irq_msg[48];
            std::snprintf(irq_msg, sizeof(irq_msg), "CL1 irq=0x%02X (rxe=%d col=%d)",
                          irq, !!(irq & 0x10), !!(irq & 0x04));
            hexlog.log_event("NFC-I2C", irq_msg);
        }
        if (!(irq & (0x10 | 0x04))) {
            hexlog.log_event("NFC-I2C", "CL1: timeout, no rxe/col");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        st25r_read_reg(0x1E, fifo_cnt);
        {
            char fcnt_msg[40];
            std::snprintf(fcnt_msg, sizeof(fcnt_msg), "CL1 FIFO=%d bytes", fifo_cnt);
            hexlog.log_event("NFC-I2C", fcnt_msg);
        }
        if (fifo_cnt < 5) {
            hexlog.log_event("NFC-I2C", "CL1: FIFO too short (<5 bytes)");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        uint8_t cl1[5] = {0};
        if (!st25r_fifo_read(cl1, 5)) {
            hexlog.log_event("NFC-I2C", "CL1: FIFO read failed");
            st25r_write_reg(0x02, 0x80);
            return false;
        }
        {
            char cl1_msg[64];
            std::snprintf(cl1_msg, sizeof(cl1_msg), "CL1=%02X%02X%02X%02X%02X",
                          cl1[0], cl1[1], cl1[2], cl1[3], cl1[4]);
            hexlog.log_event("NFC-I2C", cl1_msg);
        }

        // ── SELECT CL1 ───────────────────────────────────────────────────────
        // CMD_TRANSMIT_WITH_CRC (0xC4) automatically appends 2-byte CRC-A.
        // Write only 7 data bytes to FIFO (NOT 9); chip adds CRC to make 9 bytes on air.
        hexlog.log_event("NFC-I2C", "SELECT CL1: ISO14443A_NFC=0x00, 7 bytes, cmd 0xC4 (auto-CRC)");
        st25r_write_reg(0x05, 0x00);  // clear antcl for SELECT (normal framing + parity)
        st25r_set_aux_crc_mode(false); // ensure CRC stripped so FIFO has only SAK (1 byte)
        st25r_cmd(0xDB);
        {
            const uint8_t sel1[7] = {0x93, 0x70, cl1[0], cl1[1], cl1[2], cl1[3], cl1[4]};
            st25r_fifo_write(sel1, 7);
        }
        st25r_set_ntx(7);   // 7 data bytes; chip appends 2 CRC bytes automatically
        { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }  // clear IRQ
        st25r_cmd(0xC4);  // TRANSMIT_WITH_CRC: TX the 7 bytes + auto CRC, then RX

        // Wait for rxe (0x10) or col (0x04) — NOT txe (0x08).
        // 0xC4 is transceive: txe fires before card responds (~300µs later).
        // Using 0x08 in mask causes early return before rxe → sak stays 0 → misclassified as Ultralight.
        irq = st25r_wait_irq(0x10 | 0x04, 50);
        uint8_t sak = 0;
        {
            char irq_msg[40];
            std::snprintf(irq_msg, sizeof(irq_msg), "SELECT CL1 irq=0x%02X (rxe=%d col=%d)", irq, !!(irq & 0x10), !!(irq & 0x04));
            hexlog.log_event("NFC-I2C", irq_msg);
        }
        if (irq & 0x10) {
            st25r_read_reg(0x1E, fifo_cnt);
            if (fifo_cnt >= 1) {
                uint8_t sak_buf[3] = {0};
                // Read up to 3 bytes (SAK + optional CRC if no_crc_rx=1)
                uint8_t to_read = fifo_cnt < 3 ? fifo_cnt : 3;
                st25r_fifo_read(sak_buf, to_read);
                sak = sak_buf[0];
            }
        }
        {
            char sak_msg[32];
            std::snprintf(sak_msg, sizeof(sak_msg), "SAK CL1=0x%02X cascade=%d", sak, !!(sak & 0x04) && cl1[0] == 0x88);
            hexlog.log_event("NFC-I2C", sak_msg);
        }

        // UID cascade: if uid[0]==CT(0x88) AND SAK bit2 set → more levels.
        // Keep consistent with GroveNFC: rely on CT byte for cascade decision.
        const bool cascade = (cl1[0] == 0x88);

        uint8_t uid_buf[10] = {0};
        size_t uid_len = 0;

        if (!cascade) {
            // 4-byte UID: cl1[0..3]
            std::memcpy(uid_buf, cl1, 4);
            uid_len = 4;
        } else {
            // 7-byte UID: CL1 part = cl1[1..3], CL2 part = cl2[0..3]
            uid_buf[0] = cl1[1];
            uid_buf[1] = cl1[2];
            uid_buf[2] = cl1[3];

            // Anticollision CL2
            st25r_write_reg(0x05, 0x01);  // antcl for CL2
            st25r_cmd(0xDB);
            const uint8_t anticol2[2] = {0x95, 0x20};
            if (st25r_fifo_write(anticol2, 2)) {
                st25r_set_ntx(2);
                { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
                st25r_cmd(0xC5);  // transceive

                irq = st25r_wait_irq(0x10 | 0x04, 50);
                if (irq & (0x10 | 0x04)) {
                    st25r_read_reg(0x1E, fifo_cnt);
                    if (fifo_cnt >= 5) {
                        uint8_t cl2[5] = {0};
                        if (st25r_fifo_read(cl2, 5)) {
                            // SELECT CL2 - use CMD_TRANSMIT_WITH_CRC (0xC4), 7 bytes only
                            st25r_write_reg(0x05, 0x00);  // clear antcl
                            st25r_cmd(0xDB);
                            {
                                const uint8_t sel2[7] = {0x95, 0x70,
                                    cl2[0], cl2[1], cl2[2], cl2[3], cl2[4]};
                                st25r_fifo_write(sel2, 7);
                            }
                            st25r_set_ntx(7);
                            { uint8_t dummy = 0; st25r_read_reg(0x1A, dummy); }
                            st25r_cmd(0xC4);  // TRANSMIT_WITH_CRC (auto-CRC)
                            // Same fix: wait for rxe/col, not txe
                            irq = st25r_wait_irq(0x10 | 0x04, 50);
                            {
                                char cl2_irq_msg[48];
                                std::snprintf(cl2_irq_msg, sizeof(cl2_irq_msg),
                                             "SELECT CL2 irq=0x%02X (rxe=%d col=%d)",
                                             irq, !!(irq & 0x10), !!(irq & 0x04));
                                hexlog.log_event("NFC-I2C", cl2_irq_msg);
                            }
                            if (irq & 0x10) {
                                st25r_read_reg(0x1E, fifo_cnt);
                                if (fifo_cnt >= 1) {
                                    uint8_t s2[3] = {0};
                                    uint8_t to_read = fifo_cnt < 3 ? fifo_cnt : 3;
                                    st25r_fifo_read(s2, to_read);
                                    sak = s2[0];
                                }
                            }
                            uid_buf[3] = cl2[0];
                            uid_buf[4] = cl2[1];
                            uid_buf[5] = cl2[2];
                            uid_buf[6] = cl2[3];
                            uid_len = 7;
                        }
                    }
                }
            }
            if (uid_len == 0) {
                // Partial: return the 3 CL1 bytes we already have.
                uid_len = 3;
            }
        }

        if (uid_len == 0) {
            st25r_write_reg(0x02, 0x80);
            return false;
        }

        {
            char sak_msg[24];
            std::snprintf(sak_msg, sizeof(sak_msg), "Final SAK=0x%02X", sak);
            hexlog.log_event("NFC-I2C", sak_msg);
        }
        {
            char sak_hex[3];
            std::snprintf(sak_hex, sizeof(sak_hex), "%02X", sak);
            card.sak_hex = sak_hex;
        }

        // Format UID (no colon separators, consistent with GroveNFC path).
        std::string uid_str;
        uid_str.reserve(uid_len * 2);
        for (size_t i = 0; i < uid_len; ++i) {
            char h[3];
            std::snprintf(h, sizeof(h), "%02X", uid_buf[i]);
            uid_str += h;
        }
        card.uid = uid_str;
        card.valid = true;
        {
            char done_msg[80];
            std::snprintf(done_msg, sizeof(done_msg), "Card found: UID=%s SAK=%02X proto=%s",
                          uid_str.c_str(), sak, card.protocol.c_str());
            hexlog.log_event("NFC-I2C", done_msg);
        }

        // Classify by SAK (same mapping as readISO14A).
        if (sak == 0x08) {
            card.protocol = "MFC1K";
            card.detail = "MIFARE Classic 1K (SAK:08)";
        } else if (sak == 0x18) {
            card.protocol = "MFC4K";
            card.detail = "MIFARE Classic 4K (SAK:18)";
        } else if (sak == 0x09) {
            card.protocol = "MFCMini";
            card.detail = "MIFARE Classic Mini (SAK:09)";
        } else if (sak == 0x10 || sak == 0x11) {
            card.protocol = "MFPlus";
            char buf[32]; std::snprintf(buf, sizeof(buf), "MIFARE Plus (SAK:%02X)", sak);
            card.detail = buf;
        } else if (sak == 0x20) {
            card.protocol = "DESFire";
            char buf[32]; std::snprintf(buf, sizeof(buf), "DESFire/JCOP (SAK:%02X)", sak);
            card.detail = buf;
        } else if (sak == 0x28) {
            card.protocol = "MFC1K";
            card.detail = "MIFARE Classic 1K (7-byte UID, SAK:28)";
        } else if (sak == 0x38) {
            card.protocol = "MFC4K";
            card.detail = "MIFARE Classic 4K (7-byte UID, SAK:38)";
        } else if (sak == 0x1C) {
            card.protocol = "MFCPlus";
            card.detail = "MIFARE Plus SL2 (SAK:1C, MFC-compatible)";
        } else if (sak == 0x00) {
            // NTAG / Ultralight: follow GroveNFC flow, classify with GET_VERSION.
            card.protocol = "NTAG";
            card.detail = "NTAG/Ultralight (SAK:00)";

            uint8_t ver_len = 24;
            uint8_t ver[24] = {0};
            const uint8_t get_ver[1] = {0x60};
            if (st25r_nfca_transceive(get_ver, 1, true, ver, ver_len, 40, 0x00, false, 0) && ver_len >= 8) {
                const uint8_t ic_type = ver[2];     // 0x03=UL, 0x04=NTAG
                const uint8_t storage = ver[6];     // storage size marker
                if (ic_type == 0x04) {
                    if      (storage == 0x0F) { card.protocol = "NTAG213"; card.detail = "NTAG213 144B (SAK:00)"; }
                    else if (storage == 0x11) { card.protocol = "NTAG215"; card.detail = "NTAG215 504B (SAK:00)"; }
                    else if (storage == 0x13) { card.protocol = "NTAG216"; card.detail = "NTAG216 888B (SAK:00)"; }
                    else if (storage == 0x12) {
                        // NTAG203 vs NTAG21x disambiguation:
                        // NTAG213+ can read page 44 (0x2C), while NTAG203 cannot.
                        const bool has_page44 = st25r_type2_has_page(0x2C);
                        if (has_page44) {
                            const bool has_page134 = st25r_type2_has_page(0x86);
                            const bool has_page230 = has_page134 && st25r_type2_has_page(0xE6);
                            if (has_page230) {
                                card.protocol = "NTAG216";
                                card.detail = "NTAG216 888B (probe, SAK:00)";
                            } else if (has_page134) {
                                card.protocol = "NTAG215";
                                card.detail = "NTAG215 504B (probe, SAK:00)";
                            } else {
                                card.protocol = "NTAG213";
                                card.detail = "NTAG213 144B (probe, SAK:00)";
                            }
                        } else {
                            card.protocol = "NTAG203";
                            card.detail = "NTAG203 (SAK:00)";
                        }
                    }
                    else {
                        card.protocol = "NTAG";
                        char buf[40];
                        std::snprintf(buf, sizeof(buf), "NTAG stor=0x%02X (SAK:00)", storage);
                        card.detail = buf;
                    }
                } else if (ic_type == 0x03) {
                    if      (storage == 0x0B) { card.protocol = "MFUL11"; card.detail = "MIFARE Ultralight EV1 (48B, SAK:00)"; }
                    else if (storage == 0x0E) { card.protocol = "MFUL21"; card.detail = "MIFARE Ultralight EV1 (128B, SAK:00)"; }
                    else if (storage == 0x06) { card.protocol = "MFUL";   card.detail = "MIFARE Ultralight (64B, SAK:00)"; }
                    else {
                        card.protocol = "MFUL";
                        char buf[44];
                        std::snprintf(buf, sizeof(buf), "Ultralight stor=0x%02X (SAK:00)", storage);
                        card.detail = buf;
                    }
                }
            } else {
                // GET_VERSION failed: keep conservative and avoid forcing NTAG203.
                uint8_t probe_len = 20;
                uint8_t probe[20] = {0};
                const uint8_t rd29[2] = {0x30, 0x29};
                if (st25r_nfca_transceive(rd29, 2, true, probe, probe_len, 40, 0x00, false, 0) && probe_len >= 16) {
                    card.protocol = "MFUL-C";
                    card.detail = "MIFARE Ultralight C (SAK:00)";
                } else {
                    if (st25r_type2_has_page(0x2C)) {
                        card.protocol = "NTAG";
                        card.detail = "NTAG21x (GET_VERSION fail, SAK:00)";
                    } else {
                        card.protocol = "MFUL";
                        card.detail = "MIFARE Ultralight/NTAG (SAK:00)";
                    }
                }
            }
        } else {
            card.protocol = "ISO14443A";
            char buf[32]; std::snprintf(buf, sizeof(buf), "ISO14443A (SAK:%02X)", sak);
            card.detail = buf;
        }

        const bool magic_probe_candidate =
            (is_mifare_classic_family_sak(sak) ||
             card.protocol == "MFC1K" || card.protocol == "MFC4K" ||
             card.protocol == "MFCMini" || card.protocol == "MFCPlus");

        if (magic_probe_candidate) {
            card.magic_type = st25r_detect_magic_type(uid_str, sak, true);
        }

        // Turn off RF field (keep oscillator on for fast next poll).
        // Leave RF active through magic probing so the probe can reuse the
        // just-selected card state for Bruce-style HALT/reselect flows.
        st25r_write_reg(0x02, 0x80);

        return true;
    }

    // Arduino delay() → usleep
    static void delay_ms(int ms)
    {
        if (ms > 0)
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    // Hex helpers
    static std::string hex8(uint8_t v) {
        char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", v); return buf;
    }
    static std::string bytes_to_hex(const uint8_t *data, size_t len, bool reverse = false) {
        std::string out;
        out.reserve(len * 3);
        for (size_t i = 0; i < len; ++i) {
            if (i) out += ':';
            const uint8_t b = reverse ? data[len - 1 - i] : data[i];
            char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", b); out += buf;
        }
        return out;
    }

    void stopRF()
    {
        if (fd_ < 0) return;
        writeMiscReg(i2c_reg::MISC_RFON, 0x00);
    }

    bool recover()
    {
        if (fd_ < 0) return false;
        stopRF();
        delay_ms(2);
        writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE);
        delay_ms(3);
        writeSysReg(i2c_reg::SET_FWI, 0x0000);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
        writeMiscReg(i2c_reg::MISC_THRU, 0x00);
        writeMiscReg(i2c_reg::MISC_EGT, 0x06);
        writeMiscReg(i2c_reg::MISC_SLOT, 0x00);
        return true;
    }

    // txrx: send NFC command, wait for response via status polling.
    // Mirrors GroveNFC::txrx() exactly (no millis() / delay() needed here).
    bool txrx(const uint8_t *cmd, uint8_t cmd_len,
              uint8_t *out, uint16_t &out_len, uint16_t wait_ms)
    {
        if (!writeData(i2c_reg::DATA, cmd, cmd_len)) return false;

        const auto start = std::chrono::steady_clock::now();
        uint16_t status = 0;
        while (true) {
            status = readSysReg(i2c_reg::NFC_STATUS);
            if ((status & STATUS_RECV_DONE) ||
                (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)))
                break;
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed_ms >= wait_ms) break;
            delay_ms(2);
        }

        if (!(status & STATUS_RECV_DONE)) {
            stopRF();
            delay_ms(2);
            return false;
        }

        const uint16_t rx_len = readSysReg(i2c_reg::RX_LEN);
        if (rx_len == 0 || rx_len > out_len) {
            stopRF();
            delay_ms(2);
            return false;
        }
        if (!readData(i2c_reg::DATA, out, rx_len)) {
            stopRF();
            delay_ms(2);
            return false;
        }
        out_len = rx_len;
        return true;
    }

    bool selectReaderCommon()
    {
        stopRF();
        if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE)) return false;
        delay_ms(5);
        if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::READER | i2c_mode::TAG_NONE)) return false;
        writeMiscReg(i2c_reg::MISC_THRU, 0x00);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
        return true;
    }

    // ── ISO14443A ─────────────────────────────────────────────────────────────
    bool readISO14A(I2cCardInfo &card)
    {
        if (!selectReaderCommon()) return false;
        writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R14A | i2c_rfcfg::T14A);
        writeSysReg(i2c_reg::SET_FWI, 0x0009);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x07); // 7-bit last byte for REQA
        writeMiscReg(i2c_reg::MISC_RFON, 0x01);
        delay_ms(5);

        auto rf_rearm = [&]() {
            writeMiscReg(i2c_reg::MISC_RFON, 0x00);
            delay_ms(10);
            writeMiscReg(i2c_reg::MISC_RFON, 0x01);
            delay_ms(5);
        };

        uint8_t rx[64] = {0};
        uint16_t rx_len = sizeof(rx);
        const uint8_t reqa[] = {0x52};
        if (!txrx(reqa, 1, rx, rx_len, 10)) {
            rf_rearm();
            if (!txrx(reqa, 1, rx, rx_len, 10)) return false;
        }

        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);

        // Anticollision CL1
        const uint8_t anticol1[] = {0x93, 0x20};
        rx_len = sizeof(rx);
        if (!txrx(anticol1, 2, rx, rx_len, 10) || rx_len < 5) {
            rf_rearm();
            rx_len = sizeof(rx);
            if (!txrx(anticol1, 2, rx, rx_len, 10) || rx_len < 5) return false;
        }
        uint8_t uid1[4] = {rx[0], rx[1], rx[2], rx[3]};
        uint8_t bcc1 = rx[4];

        writeSysReg(i2c_reg::SET_TXCRCE, 0x0001);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0001);

        // SELECT CL1
        uint8_t sel1[] = {0x93, 0x70, uid1[0], uid1[1], uid1[2], uid1[3], bcc1};
        rx_len = sizeof(rx);
        if (!txrx(sel1, 7, rx, rx_len, 10)) {
            rf_rearm();
            rx_len = sizeof(rx);
            if (!txrx(sel1, 7, rx, rx_len, 10)) return false;
        }
        uint8_t sak = rx[0];

        uint8_t uid_buf[7];
        size_t uid_len;
        const bool cascade = (uid1[0] == 0x88);

        if (!cascade) {
            std::memcpy(uid_buf, uid1, 4);
            uid_len = 4;
        } else {
            writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
            const uint8_t anticol2[] = {0x95, 0x20};
            rx_len = sizeof(rx);
            if (!txrx(anticol2, 2, rx, rx_len, 10) || rx_len < 5) {
                rf_rearm();
                rx_len = sizeof(rx);
                if (!txrx(anticol2, 2, rx, rx_len, 10) || rx_len < 5) return false;
            }
            uint8_t uid2[4] = {rx[0], rx[1], rx[2], rx[3]};
            uint8_t bcc2 = rx[4];

            writeSysReg(i2c_reg::SET_TXCRCE, 0x0001);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0001);
            uint8_t sel2[] = {0x95, 0x70, uid2[0], uid2[1], uid2[2], uid2[3], bcc2};
            rx_len = sizeof(rx);
            if (!txrx(sel2, 7, rx, rx_len, 10)) {
                rf_rearm();
                rx_len = sizeof(rx);
                if (!txrx(sel2, 7, rx, rx_len, 10)) return false;
            }
            sak = rx[0];

            uid_buf[0] = uid1[1]; uid_buf[1] = uid1[2]; uid_buf[2] = uid1[3];
            uid_buf[3] = uid2[0]; uid_buf[4] = uid2[1]; uid_buf[5] = uid2[2]; uid_buf[6] = uid2[3];
            uid_len = 7;
        }

        card.uid = bytes_to_hex(uid_buf, uid_len);
        card.valid = true;

        // Identify by SAK
        const uint8_t mfc_sak = normalize_mifare_classic_sak(sak);
        if (mfc_sak == 0x08) {
            card.protocol = "MFC1K";
            card.detail = (sak == 0x88) ? "MIFARE Classic 1K (SAK:88)" : "MIFARE Classic 1K (SAK:08)";
        } else if (mfc_sak == 0x18) {
            card.protocol = "MFC4K";
            card.detail = (sak == 0x98) ? "MIFARE Classic 4K (SAK:98)" : "MIFARE Classic 4K (SAK:18)";
        } else if (mfc_sak == 0x09) {
            card.protocol = "MFCMini";
            card.detail = "MIFARE Classic Mini (SAK:09)";
        } else if (mfc_sak == 0x10) {
            card.protocol = "MFPlus2K";
            card.detail = "MIFARE Plus 2K (SAK:10)";
        } else if (mfc_sak == 0x11) {
            card.protocol = "MFPlus4K";
            card.detail = "MIFARE Plus 4K (SAK:11)";
        } else if (mfc_sak == 0x20) {
            card.protocol = "DESFire";
            char buf[32]; std::snprintf(buf, sizeof(buf), "DESFire/JCOP (SAK:%02X)", sak);
            card.detail = buf;
        } else if (sak == 0x00) {
            // NTAG / Ultralight: use GET_VERSION to distinguish
            writeSysReg(i2c_reg::SET_TXCRCE, 0x0000);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0000);
            uint8_t get_ver[] = {0x60};
            rx_len = sizeof(rx);
            if (txrx(get_ver, 1, rx, rx_len, 15) && rx_len >= 8) {
                const uint8_t ic_type    = rx[2]; // 0x03=UL, 0x04=NTAG
                const uint8_t storage_sz = rx[6];
                if (ic_type == 0x04) {
                    if      (storage_sz == 0x0F) { card.protocol = "NTAG213"; card.detail = "NTAG213 144B (SAK:00)"; }
                    else if (storage_sz == 0x11) { card.protocol = "NTAG215"; card.detail = "NTAG215 504B (SAK:00)"; }
                    else if (storage_sz == 0x13) { card.protocol = "NTAG216"; card.detail = "NTAG216 888B (SAK:00)"; }
                    else                         { card.protocol = "NTAG";    card.detail = "NTAG (SAK:00)"; }
                } else {
                    card.protocol = "MFUL";
                    card.detail = "MIFARE Ultralight (SAK:00)";
                }
            } else {
                card.protocol = "MFUL";
                card.detail = "MIFARE Ultralight/NTAG (SAK:00)";
            }
        } else {
            card.protocol = "ISO14443A";
            char buf[32]; std::snprintf(buf, sizeof(buf), "ISO14443A (SAK:%02X)", sak);
            card.detail = buf;
        }
        return true;
    }

    // ── ISO14443B ─────────────────────────────────────────────────────────────
    bool readISO14B(I2cCardInfo &card)
    {
        auto runOnce = [&]() -> bool {
            stopRF();
            if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::DEFAULT | i2c_mode::TAG_NONE)) return false;
            delay_ms(10);
            if (!writeSysReg(i2c_reg::SET_MODE, i2c_mode::READER | i2c_mode::TAG_NONE)) return false;
            writeSysReg(i2c_reg::SET_TAGADDR, 0x0000);
            writeMiscReg(i2c_reg::MISC_THRU, 0x00);
            writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
            writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R14B | i2c_rfcfg::T14B);
            writeSysReg(i2c_reg::SET_FWI, 0x0000);
            writeSysReg(i2c_reg::SET_TXCRCE, 0x0002);
            writeSysReg(i2c_reg::SET_RXCRCE, 0x0002);
            writeMiscReg(i2c_reg::MISC_EGT, 0x06);
            writeMiscReg(i2c_reg::MISC_RFON, 0x01);
            delay_ms(10);

            uint8_t rx[128] = {0};
            uint16_t rx_len = 0;

            // Clear status, then send REQB
            writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
            const uint8_t reqb[] = {0x05, 0x00, 0x00};
            if (!writeData(i2c_reg::DATA, reqb, 3)) return false;
            delay_ms(10);

            // Poll for RECV_DONE
            uint16_t status = 0;
            for (int i = 0; i < 20; ++i) {
                status = readSysReg(i2c_reg::NFC_STATUS);
                if (status & STATUS_RECV_DONE) break;
                if (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)) break;
                delay_ms(2);
            }
            if (!(status & STATUS_RECV_DONE)) { stopRF(); return false; }

            rx_len = readSysReg(i2c_reg::RX_LEN);
            if (rx_len == 0 || rx_len > sizeof(rx)) { stopRF(); return false; }
            if (!readData(i2c_reg::DATA, rx, rx_len)) { stopRF(); return false; }

            // ATTRIB
            writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
            const uint8_t attrib[] = {0x1D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x08};
            if (!writeData(i2c_reg::DATA, attrib, 9)) return false;
            delay_ms(10);
            for (int i = 0; i < 20; ++i) {
                status = readSysReg(i2c_reg::NFC_STATUS);
                if (status & STATUS_RECV_DONE) break;
                if (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)) break;
                delay_ms(2);
            }
            if (!(status & STATUS_RECV_DONE)) { stopRF(); return false; }
            rx_len = readSysReg(i2c_reg::RX_LEN);
            if (rx_len == 0 || rx_len > sizeof(rx)) { stopRF(); return false; }
            if (!readData(i2c_reg::DATA, rx, rx_len)) { stopRF(); return false; }

            uint8_t uid_buf[16] = {0};
            size_t uid_len = (rx_len > sizeof(uid_buf)) ? sizeof(uid_buf) : rx_len;
            std::memcpy(uid_buf, rx, uid_len);

            // GET UID
            writeSysReg(i2c_reg::NFC_STATUS, 0x0000);
            const uint8_t getuid[] = {0x00, 0x36, 0x00, 0x00, 0x08};
            if (writeData(i2c_reg::DATA, getuid, 5)) {
                delay_ms(10);
                for (int i = 0; i < 20; ++i) {
                    status = readSysReg(i2c_reg::NFC_STATUS);
                    if (status & STATUS_RECV_DONE) break;
                    if (status & (STATUS_RECV_TIMEOUT | STATUS_RECV_CRCERR | STATUS_RECV_BITERR)) break;
                    delay_ms(2);
                }
                if ((status & STATUS_RECV_DONE)) {
                    uint16_t rlen2 = readSysReg(i2c_reg::RX_LEN);
                    if (rlen2 > 0 && rlen2 <= sizeof(uid_buf)) {
                        if (readData(i2c_reg::DATA, uid_buf, rlen2))
                            uid_len = rlen2;
                    }
                }
            }

            stopRF();
            if (uid_len == 0) return false;

            card.protocol = "ISO14443B";
            card.uid = bytes_to_hex(uid_buf, uid_len);
            card.detail = "ISO14443B";
            card.valid = true;
            return true;
        };

        if (runOnce()) return true;
        recover();
        delay_ms(20);
        return runOnce();
    }

    // ── ISO15693 ──────────────────────────────────────────────────────────────
    bool readISO15(I2cCardInfo &card)
    {
        if (!selectReaderCommon()) return false;
        writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R15 | i2c_rfcfg::T15);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0008);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0008);
        writeMiscReg(i2c_reg::MISC_TXLAST, 0x00);
        writeMiscReg(i2c_reg::MISC_RFON, 0x01);
        delay_ms(5);

        uint8_t rx[64] = {0};
        uint16_t rx_len = sizeof(rx);
        const uint8_t inv[] = {0x26, 0x01, 0x00};
        if (!txrx(inv, 3, rx, rx_len, 15) || rx_len < 10) {
            writeMiscReg(i2c_reg::MISC_RFON, 0x01);
            delay_ms(4);
            rx_len = sizeof(rx);
            if (!txrx(inv, 3, rx, rx_len, 100) || rx_len < 10) return false;
        }

        card.protocol = "ISO15693";
        card.uid = bytes_to_hex(&rx[2], 8, /*reverse=*/true);
        card.valid = true;
        card.detail = "ISO15693 Inventory";
        return true;
    }

    // ── FeliCa ────────────────────────────────────────────────────────────────
    bool readFelica(I2cCardInfo &card)
    {
        if (!selectReaderCommon()) return false;
        writeSysReg(i2c_reg::SET_RFCFG, i2c_rfcfg::R212 | i2c_rfcfg::T212);
        writeMiscReg(i2c_reg::MISC_SLOT, 0x00);
        writeSysReg(i2c_reg::SET_TXCRCE, 0x0004);
        writeSysReg(i2c_reg::SET_RXCRCE, 0x0004);
        writeMiscReg(i2c_reg::MISC_RFON, 0x01);
        delay_ms(5);

        uint8_t rx[64] = {0};
        uint16_t rx_len = sizeof(rx);
        const uint8_t polling[] = {0x06, 0x00, 0xFF, 0xFF, 0x00, 0x00};
        if (!txrx(polling, 6, rx, rx_len, 15) || rx_len < 10) return false;

        card.protocol = "FeliCa";
        card.uid = bytes_to_hex(&rx[2], 8);
        card.valid = true;
        char buf[48];
        std::snprintf(buf, sizeof(buf), "FeliCa IDm:%s", card.uid.c_str());
        card.detail = buf;
        return true;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper: translate I2cCardInfo.protocol → ProtocolKind + tag_type string
// ─────────────────────────────────────────────────────────────────────────────
inline ProtocolKind i2c_protocol_to_kind(const std::string &proto)
{
    if (proto == "MFC1K" || proto == "MFC4K" || proto == "MFCMini") return ProtocolKind::MifareClassic;
    if (proto == "ISO14443B") return ProtocolKind::Iso14443B;
    if (proto == "ISO15693")  return ProtocolKind::Iso15693;
    return ProtocolKind::Iso14443A;
}

inline std::string i2c_protocol_to_tag_type(const std::string &proto)
{
    if (proto == "MFC1K")    return "MIFARE Classic 1K";
    if (proto == "MFC4K")    return "MIFARE Classic 4K";
    if (proto == "MFCMini")  return "MIFARE Classic Mini";
    if (proto == "MFPlus2K") return "MIFARE Plus 2K";
    if (proto == "MFPlus4K") return "MIFARE Plus 4K";
    if (proto == "DESFire")  return "MIFARE DESFire";
    if (proto == "NTAG213")  return "NTAG213";
    if (proto == "NTAG215")  return "NTAG215";
    if (proto == "NTAG216")  return "NTAG216";
    if (proto == "NTAG203")  return "NTAG203";
    if (proto == "NTAG")     return "NTAG";
    if (proto == "MFUL11")   return "MIFARE Ultralight EV1 (UL11)";
    if (proto == "MFUL21")   return "MIFARE Ultralight EV1 (UL21)";
    if (proto == "MFUL")     return "MIFARE Ultralight";
    if (proto == "MFUL-C")   return "MIFARE Ultralight C";
    if (proto == "ISO14443A") return "ISO14443A";
    if (proto == "ISO14443B") return "ISO14443B";
    if (proto == "ISO15693")  return "ISO15693";
    if (proto == "FeliCa")    return "FeliCa";
    return proto;
}

} // namespace nfc_app
