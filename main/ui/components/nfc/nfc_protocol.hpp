#pragma once

#include "nfc_transport.hpp"

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <chrono>
#include <functional>
#include <optional>
#include <sstream>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace nfc_app {

struct Pn532FirmwareInfo {
    std::string chip = "";
    std::string version = "";  // "vVER.REV" (plain PN532) or "vYEAR.MONTH" (PN532Killer)
    uint8_t     day   = 0;    // PN532Killer: day byte from GetFirmwareVersion response
};

class Pn532FrameCodec {
public:
    static std::vector<uint8_t> build_command(uint8_t command, const std::vector<uint8_t> &payload = {})
    {
        std::vector<uint8_t> data;
        data.push_back(0xD4);
        data.push_back(command);
        data.insert(data.end(), payload.begin(), payload.end());

        const uint8_t len = static_cast<uint8_t>(data.size());
        const uint8_t lcs = static_cast<uint8_t>(0x100 - len);
        uint8_t sum = 0;
        for (uint8_t byte : data) sum = static_cast<uint8_t>(sum + byte);
        const uint8_t dcs = static_cast<uint8_t>(0x100 - sum);

        std::vector<uint8_t> frame = {0x00, 0x00, 0xFF, len, lcs};
        frame.insert(frame.end(), data.begin(), data.end());
        frame.push_back(dcs);
        frame.push_back(0x00);
        return frame;
    }

    static bool is_ack(const std::vector<uint8_t> &bytes)
    {
        static const uint8_t ack[] = {0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00};
        if (bytes.size() < sizeof(ack)) return false;
        for (size_t i = 0; i < bytes.size() - sizeof(ack) + 1; ++i) {
            bool same = true;
            for (size_t j = 0; j < sizeof(ack); ++j) {
                if (bytes[i + j] != ack[j]) {
                    same = false;
                    break;
                }
            }
            if (same) return true;
        }
        return false;
    }

    static bool parse_first_frame(const std::vector<uint8_t> &bytes, std::vector<uint8_t> *data_out)
    {
        for (size_t i = 0; i + 7 < bytes.size(); ++i) {
            if (bytes[i] != 0x00 || bytes[i + 1] != 0x00 || bytes[i + 2] != 0xFF) continue;

            const uint8_t len = bytes[i + 3];
            const uint8_t lcs = bytes[i + 4];
            if (static_cast<uint8_t>(len + lcs) != 0x00) continue;
            if (len == 0) continue;
            if (i + 5 + len + 2 > bytes.size()) continue;

            const size_t data_start = i + 5;
            const size_t data_end = data_start + len;
            uint8_t sum = 0;
            for (size_t cursor = data_start; cursor < data_end; ++cursor) {
                sum = static_cast<uint8_t>(sum + bytes[cursor]);
            }
            const uint8_t dcs = bytes[data_end];
            if (static_cast<uint8_t>(sum + dcs) != 0x00) continue;

            if (data_out) {
                data_out->assign(bytes.begin() + static_cast<long>(data_start), bytes.begin() + static_cast<long>(data_end));
            }
            return true;
        }
        return false;
    }
};

class Pn532KillerClient {
public:
    explicit Pn532KillerClient(INfcTransport *transport) : transport_(transport) {}

    // Send HSU wakeup preamble.
    // MUST be immediately followed by sam_configuration() — no sleep between them.
    // Mirrors Python pn532_com.py set_normal_mode():
    //   communication.write(wakeup_bytes)  ← no delay
    //   send_cmd_sync(SAMConfiguration)    ← waits for response
    // The PN532 processes the preamble as bytes arrive and is ready for the
    // SAMConfig frame that follows in the same OS write burst.
    void send_wakeup()
    {
        static const uint8_t wake[] = {
            0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        transport_->write_bytes(wake, sizeof(wake), nullptr);
        // No sleep here.  Call sam_configuration() immediately after.
    }

    // SAMConfiguration – put PN532 into Normal mode (required before NFC ops).
    // Returns true if the PN532 responded (D5 15), false if timed out.
    // Callers that do not need the return value may ignore it safely.
    bool sam_configuration(std::string *error)
    {
        // Mode 0x01 = Normal only (matches Python set_normal_mode payload=[0x01])
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x14, {0x01});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        return collect_response(&rx, nullptr); // true = D5 15 received; false = timeout
    }

    // SetWorkMode for PN532Killer (0xAC): mode=1 READER, type=1 MFC, index=0.
    bool set_work_mode(uint8_t mode, uint8_t type, uint8_t index, std::string *error)
    {
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0xAC, {mode, type, index});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd) || fd.size() < 3 ||
            fd[0] != 0xD5 || fd[1] != 0xAD) {
            if (error) *error = "unexpected SetWorkMode response";
            return false;
        }
        if (fd[2] != 0x00) {
            if (error) {
                char msg[64] = {};
                std::snprintf(msg, sizeof(msg), "SetWorkMode failed: status=0x%02X", fd[2]);
                *error = msg;
            }
            return false;
        }
        return true;
    }

    // Compute actual slot byte sent to PN532Killer (ISO15693 adds +0x1A, EM4100 adds +0x12).
    static uint8_t emu_actual_slot(uint8_t type, uint8_t slot)
    {
        switch (type) {
        case 0x03: return static_cast<uint8_t>(slot + 0x1A);  // ISO15693
        case 0x04: return static_cast<uint8_t>(slot + 0x12);  // EM4100
        default:   return slot;                                // MFC, NTAG/MFU
        }
    }

    // getEmulatorData (0x1C) — "prepare" call with index 0x00FF to init read session.
    // type: 1=MFC, 2=MFU/NTAG, 3=ISO15693, 4=EM4100  slot: 0-7
    bool emu_prepare_read(uint8_t type, uint8_t slot)
    {
        const uint8_t actual = emu_actual_slot(type, slot);
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x1C, {type, actual, 0x00, 0xFF});
        if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr);
        return true;
    }

    // getEmulatorData (0x1C) — read one block/page at given 16-bit index from emulator slot.
    // Response frame: [D5, 1D, type, actual_slot, idx_hi, idx_lo, data...]
    // Populates out with raw data bytes (16 for MFC block, 4 for NTAG page, 8 for ISO15693 UID).
    bool emu_download_block(uint8_t type, uint8_t slot, uint16_t index, std::vector<uint8_t> *out)
    {
        const uint8_t actual = emu_actual_slot(type, slot);
        const uint8_t idx_hi = static_cast<uint8_t>((index >> 8) & 0xFF);
        const uint8_t idx_lo = static_cast<uint8_t>(index & 0xFF);
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x1C, {type, actual, idx_hi, idx_lo});
        if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr);
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd)) return false;
        // fd: [D5, 1D, type, actual_slot, idx_hi, idx_lo, data...]
        if (fd.size() < 7 || fd[0] != 0xD5 || fd[1] != 0x1D) return false;
        if (out) out->assign(fd.begin() + 6, fd.end());
        return out && !out->empty();
    }

    // setEmulatorData (0x1E) — upload one block to emulator slot.
    // type: 1=MFC, 2=MFU/NTAG, 3=ISO15693  slot: 0-7  index: block number
    // data must be exactly 16 bytes (MFC block).  Returns true on success (response last byte 0x00).
    bool emu_upload_block(uint8_t type, uint8_t slot, uint16_t index, const std::vector<uint8_t> &data)
    {
        const uint8_t actual  = emu_actual_slot(type, slot);
        const uint8_t idx_hi  = static_cast<uint8_t>((index >> 8) & 0xFF);
        const uint8_t idx_lo  = static_cast<uint8_t>(index & 0xFF);
        std::vector<uint8_t> payload = {type, actual, idx_hi, idx_lo};
        payload.insert(payload.end(), data.begin(), data.end());
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x1E, payload);
        if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr);
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd)) return false;
        return !fd.empty() && fd.back() == 0x00;
    }

    // setEmulatorData (0x1E) — signal end of upload (index=0xFFFF, 16 zero bytes).
    bool emu_upload_done(uint8_t type, uint8_t slot)
    {
        const uint8_t actual = emu_actual_slot(type, slot);
        std::vector<uint8_t> payload = {type, actual, 0xFF, 0xFF};
        payload.insert(payload.end(), 16, 0x00);
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x1E, payload);
        if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr);
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd)) return false;
        return !fd.empty() && fd.back() == 0x00;
    }

    // ── PN532Killer sniffer commands ─────────────────────────────────────────

    struct MfkeyEntry {
        uint32_t uid;
        uint32_t nt;
        uint32_t nr;
        uint32_t ar;
        uint32_t at;   // only valid when with_card=true
        uint8_t  sector;
        uint8_t  key_type; // 0=A, 1=B
        bool     has_at;
    };

    // sniff_set_uid: configure the sniffer slot UID (slot 0x11) before entering
    // no-card sniffer mode.  block0_16 must be 16 bytes:
    //   uid[4] | BCC[1] | SAK[1] | ATQA[2] | pad[8 zeros]
    bool sniff_set_uid(const uint8_t *block0_16)
    {
        if (!transport_ || !transport_->is_open()) return false;
        // upload_data_block: type=1, slot=0x11, index=0x0000, data=block0_16[16]
        {
            std::vector<uint8_t> payload = {0x01, 0x11, 0x00, 0x00};
            payload.insert(payload.end(), block0_16, block0_16 + 16);
            const auto frame = Pn532FrameCodec::build_command(0x1E, payload);
            if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return false;
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr);
        }
        // upload_data_block_done: type=1, slot=0x11, index=0xFFFF, 16 zero bytes
        {
            std::vector<uint8_t> payload = {0x01, 0x11, 0xFF, 0xFF};
            payload.insert(payload.end(), 16, 0x00);
            const auto frame = Pn532FrameCodec::build_command(0x1E, payload);
            if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return false;
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr);
            std::vector<uint8_t> fd;
            if (!Pn532FrameCodec::parse_first_frame(rx, &fd)) return false;
            return !fd.empty() && fd.back() == 0x00;
        }
    }

    // sniff_enter_mode: switch PN532Killer to SNIFFER mode (mode=3, MFC=1).
    // with_card=false → no-card capture (mfkey32v2)
    // with_card=true  → card-present capture (mfkey64)
    bool sniff_enter_mode(bool with_card)
    {
        return set_work_mode(0x03, 0x01, with_card ? 0x01 : 0x00, nullptr);
    }

    // ClearSnifferLog (0x22): clears captured sniffer frames on device.
    bool sniff_clear()
    {
        if (!transport_ || !transport_->is_open()) return false;
        const std::vector<uint8_t> payload = {0x01, 0x00};
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x22, payload);
        if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr);
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd)) return false;
        return !fd.empty() && fd.back() == 0x00;
    }

    // GetSnifferLog (0x20): retrieve mfkey-ready nonce tuples from device.
    // with_card=true  → card-present entries (24 bytes each, up to 4)
    // with_card=false → no-card entries      (20 bytes each, up to 8)
    std::vector<MfkeyEntry> sniff_get_mfkey_entries(bool with_card)
    {
        std::vector<MfkeyEntry> result;
        if (!transport_ || !transport_->is_open()) return result;

        const uint8_t tag_flag = with_card ? 0x01 : 0x00;
        const std::vector<uint8_t> payload = {0x01, tag_flag};
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x20, payload);
        if (transport_->write_bytes(frame.data(), frame.size(), nullptr) < 0) return result;

        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr);
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd)) return result;
        // fd layout: D5 21 [mode_flag] [pad] [entries...]
        // parse_first_frame returns the full data payload including TFI(D5) + CMD(21).
        // Skip 4 bytes (D5 21 XX XX) before the entry array.
        if (fd.size() < 4 || fd[0] != 0xD5 || fd[1] != 0x21) return result;

        const uint8_t *raw  = fd.data() + 4;
        const size_t   raw_len = fd.size() - 4;
        const int entry_size   = with_card ? 24 : 20;
        const int max_entries  = with_card ? 4  : 8;

        for (int idx = 0; idx < max_entries; ++idx) {
            size_t start = static_cast<size_t>(idx * entry_size);
            if (start + static_cast<size_t>(entry_size) > raw_len) break;
            const uint8_t *c = raw + start;
            // Skip all-zero entries
            bool nonzero = false;
            for (int b = 0; b < entry_size; ++b) if (c[b]) { nonzero = true; break; }
            if (!nonzero) continue;

            MfkeyEntry e{};
            e.uid     = static_cast<uint32_t>(c[0]) | (static_cast<uint32_t>(c[1]) << 8) |
                        (static_cast<uint32_t>(c[2]) << 16) | (static_cast<uint32_t>(c[3]) << 24);
            e.nt      = static_cast<uint32_t>(c[4]) | (static_cast<uint32_t>(c[5]) << 8) |
                        (static_cast<uint32_t>(c[6]) << 16) | (static_cast<uint32_t>(c[7]) << 24);
            e.nr      = static_cast<uint32_t>(c[8]) | (static_cast<uint32_t>(c[9]) << 8) |
                        (static_cast<uint32_t>(c[10]) << 16) | (static_cast<uint32_t>(c[11]) << 24);
            e.ar      = static_cast<uint32_t>(c[12]) | (static_cast<uint32_t>(c[13]) << 8) |
                        (static_cast<uint32_t>(c[14]) << 16) | (static_cast<uint32_t>(c[15]) << 24);
            if (with_card) {
                e.at      = static_cast<uint32_t>(c[16]) | (static_cast<uint32_t>(c[17]) << 8) |
                            (static_cast<uint32_t>(c[18]) << 16) | (static_cast<uint32_t>(c[19]) << 24);
                e.sector   = c[20];
                e.key_type = (c[21] == 0x61) ? 1 : 0;  // 0x60=KEYA, 0x61=KEYB
                e.has_at   = true;
            } else {
                e.at       = 0;
                e.sector   = c[16];
                e.key_type = (c[17] == 0x61) ? 1 : 0;  // 0x60=KEYA, 0x61=KEYB
                e.has_at   = false;
            }
            result.push_back(e);
        }
        return result;
    }

    // ── PN532 target emulation commands (Type 4 Tag style) ─────────────────

    // TgInitAsTarget (0x8C): enter target mode with caller-provided config.
    // Returns true once PN532 accepts target init (D5 8D ...).
    bool tg_init_as_target(const std::vector<uint8_t> &config,
                           std::vector<uint8_t> *resp_data,
                           std::string *error)
    {
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x8C, config);
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd) ||
            fd.size() < 2 || fd[0] != 0xD5 || fd[1] != 0x8D) {
            if (error) *error = "unexpected TgInitAsTarget response";
            return false;
        }
        if (resp_data) resp_data->assign(fd.begin() + 2, fd.end());
        return true;
    }

    // TgGetData (0x86): receive one APDU/data packet from initiator.
    // Output includes the PN532 target status byte at out[0].
    bool tg_get_data(std::vector<uint8_t> *out, std::string *error)
    {
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x86, {});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd) ||
            fd.size() < 3 || fd[0] != 0xD5 || fd[1] != 0x87) {
            if (error) *error = "unexpected TgGetData response";
            return false;
        }
        if (out) out->assign(fd.begin() + 2, fd.end());
        return true;
    }

    // TgSetData (0x8E): send response APDU/data packet to initiator.
    bool tg_set_data(const std::vector<uint8_t> &data, std::string *error)
    {
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x8E, data);
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd) ||
            fd.size() < 3 || fd[0] != 0xD5 || fd[1] != 0x8F) {
            if (error) *error = "unexpected TgSetData response";
            return false;
        }
        if (fd[2] != 0x00) {
            if (error) {
                char b[32];
                std::snprintf(b, sizeof(b), "tg status 0x%02X", fd[2]);
                *error = b;
            }
            return false;
        }
        return true;
    }

    std::optional<Pn532FirmwareInfo> query_firmware(std::string *error)
    {
        if (!transport_ || !transport_->is_open()) {
            if (error) *error = "transport not connected";
            return std::nullopt;
        }

        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x02);
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) {
            return std::nullopt;
        }

        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) {
            return std::nullopt;
        }

        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) {
            if (error) *error = "no valid PN532 frame";
            return std::nullopt;
        }

        if (data.size() < 6 || data[0] != 0xD5 || data[1] != 0x03) {
            if (error) *error = "unexpected firmware response";
            return std::nullopt;
        }

        Pn532FirmwareInfo info;
        info.chip = (data[2] == 0x32) ? "PN532" : "PN53x";
        char version[32];
        std::snprintf(version, sizeof(version), "v%d.%02d", data[3], data[4]);
        info.version = version;
        // data[5] is the "Support" byte for plain PN532 and the "day" byte for PN532Killer.
        // Store it so detect_device() can build the full killer version string.
        if (data.size() >= 6) info.day = data[5];
        if (error) error->clear();
        return info;
    }

    // Detect PN532Killer using checkPn532Killer vendor command (0xAA).
    // PN532Killer responds with TFI=0xD5, cmd=0xAB, status 0x00.
    // Plain PN532 returns an error frame (cmd=0x7F) or times out.
    bool probe_pn532killer(std::string *error)
    {
        if (!transport_ || !transport_->is_open()) {
            if (error) *error = "transport not connected";
            return false;
        }

        // Drain any stale bytes (e.g. postamble from the preceding GetFirmwareVersion).
        // UART kernel buffers are slower to drain than USB-CDC; use 5×50ms (250ms total)
        // to ensure any late-arriving bytes from GetFirmwareVersion are fully flushed.
        {
            uint8_t flush[128];
            for (int i = 0; i < 5; ++i)
                transport_->read_bytes(flush, sizeof(flush), 50, nullptr);
        }
        // Pn532KillerCommand.checkPn532Killer = 0xAA
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0xAA, {});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) {
            return false;
        }

        // Read up to 8×200ms = 1600ms total.  UART PN532Killer can be slower than
        // USB-CDC to process the vendor command, especially right after GetFirmwareVersion.
        // We skip any D4-TFI frames (command echoes) and ACK frames (len=0, already
        // skipped by parse_first_frame) and keep accumulating until we see a D5 response.
        std::vector<uint8_t> rx;
        uint8_t buf[128];
        for (int i = 0; i < 8; ++i) {
            ssize_t got = transport_->read_bytes(buf, sizeof(buf), 200, error);
            if (got > 0) rx.insert(rx.end(), buf, buf + got);
            std::vector<uint8_t> tmp;
            if (Pn532FrameCodec::parse_first_frame(rx, &tmp)) {
                // Skip command-echo frames (TFI=0xD4); keep reading for the response.
                if (tmp.size() >= 1 && tmp[0] == 0xD5) break;
            }
        }
        if (rx.empty()) return false;

        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) return false;
        if (data.size() < 2) return false;
        // If we still landed on an echo frame, try finding the next D5 frame.
        if (data[0] == 0xD4) {
            // Brute-force: scan for the D5 AB response anywhere in rx.
            for (size_t off = 1; off + 9 < rx.size(); ++off) {
                std::vector<uint8_t> sub(rx.begin() + static_cast<long>(off), rx.end());
                std::vector<uint8_t> d2;
                if (Pn532FrameCodec::parse_first_frame(sub, &d2) &&
                    d2.size() >= 2 && d2[0] == 0xD5) {
                    data = d2;
                    break;
                }
            }
        }
        if (data.size() < 2 || data[0] != 0xD5) return false;
        // Error frame from plain PN532: cmd byte 0x7F
        if (data[1] == 0x7F) return false;
        // PN532Killer responds with cmd = 0xAB (0xAA + 1)
        return (data[1] == 0xAB);
    }

    // Convenience: probe device kind in one call.
    // Returns DeviceKind and fills firmware string.
    // Flow (mirrors Python pn532_com.py open()):
    //   wakeup → SAMConfig (wait for response) → GetFirmwareVersion → checkPN532Killer(0xAA)
    //   → for PN532Killer: wakeup → SAMConfig → SetWorkMode(READER) → SetRFRetries
    //   → for plain PN532: SetRFRetries
    DeviceKind detect_device(std::string *firmware_out, std::string *error)
    {
        if (firmware_out) firmware_out->clear();

        // Step 0: Flush stale bytes from kernel RX buffer.
        {
            uint8_t flush[256];
            for (int i = 0; i < 3; ++i)
                transport_->read_bytes(flush, sizeof(flush), 30, nullptr);
        }

        // Step 1: Wakeup preamble → SAMConfiguration (like Python set_normal_mode).
        // send_wakeup() writes the preamble bytes with NO delay so that sam_configuration()
        // writes the SAMConfig frame immediately after — this is exactly what Python does:
        //   communication.write(wakeup_bytes)   ← no sleep
        //   send_cmd_sync(SAMConfiguration)     ← waits for D5 15 response
        // On a cold USB connect the PN532 may need multiple attempts; retry up to 2×.
        bool sam_ok = false;
        for (int sam_try = 0; sam_try < 2 && !sam_ok; ++sam_try) {
            if (sam_try > 0) {
                // Drain any late bytes from the previous timed-out SAMConfig attempt.
                uint8_t drain[256];
                for (int i = 0; i < 5; ++i)
                    transport_->read_bytes(drain, sizeof(drain), 50, nullptr);
            }
            send_wakeup();                        // write preamble – NO sleep after
            sam_ok = sam_configuration(nullptr);  // write SAMConfig + wait ≤2500 ms
        }

        // Drain any residual bytes (echo, extra ACK, or late SAMConfig when sam_ok=false).
        {
            uint8_t drain[128];
            for (int i = 0; i < 2; ++i)
                transport_->read_bytes(drain, sizeof(drain), 30, nullptr);
        }

        // Step 2: GetFirmwareVersion.
        // When sam_ok=true the SAMConfig response was already consumed by collect_response,
        // so there are no stale bytes to poison this command.
        // When sam_ok=false (all SAMConfig retries timed out) we still try once; the chip
        // may have woken up during the retries even if the response was never seen.
        std::optional<Pn532FirmwareInfo> fw = query_firmware(error);
        if (!fw) {
            // Last-resort extra cycle: drain late bytes, fresh wakeup+SAMConfig, retry firmware.
            {
                uint8_t drain[256];
                for (int i = 0; i < 5; ++i)
                    transport_->read_bytes(drain, sizeof(drain), 50, nullptr);
            }
            send_wakeup();
            sam_configuration(nullptr);
            {
                uint8_t drain[64];
                for (int i = 0; i < 2; ++i)
                    transport_->read_bytes(drain, sizeof(drain), 30, nullptr);
            }
            fw = query_firmware(error);
            if (!fw) return DeviceKind::Unknown;
        }

        // Build a preliminary firmware label (overridden below for PN532Killer).
        if (firmware_out) *firmware_out = fw->chip + " " + fw->version;

        // Step 3: checkPn532Killer (0xAA) to distinguish PN532Killer from plain PN532.
        // Must be done AFTER GetFirmwareVersion so the PN532 is in a known good state.
        // Fallback: PN532Killer encodes the build date as vYEAR.MONTH (e.g. v26.03), while
        // plain PN532 always reports v1.xx (NXP silicon revision). If the 0xAA vendor probe
        // fails (e.g. UART timing differences), use the version major number as a heuristic.
        bool version_looks_like_killer = false;
        if (!fw->version.empty() && fw->version[0] == 'v') {
            int ver = std::atoi(fw->version.c_str() + 1);
            version_looks_like_killer = (ver >= 10);
        }
        const bool is_killer = probe_pn532killer(nullptr) || version_looks_like_killer;

        // Step 4: drain any bytes left over from the 0xAA probe before next commands.
        {
            uint8_t drain[128];
            for (int i = 0; i < 4; ++i)
                transport_->read_bytes(drain, sizeof(drain), 50, nullptr);
        }

        if (is_killer) {
            // Override firmware label: PN532Killer reports date as vYEAR.MONTH.DAY.
            if (firmware_out) {
                char killer_ver[48];
                std::snprintf(killer_ver, sizeof(killer_ver), "PN532Killer %s.%02d",
                              fw->version.c_str(), static_cast<int>(fw->day));
                *firmware_out = killer_ver;
            }
            // Step 5a: re-wakeup so PN532Killer responds cleanly to SetWorkMode.
            send_wakeup();
            sam_configuration(nullptr);
            set_work_mode(0x01, 0x01, 0x00, nullptr);
            set_rf_passive_retries(0x20, nullptr);
            return DeviceKind::PN532Killer;
        }

        // Step 5b: plain PN532 – set finite retry count so InListPassiveTarget
        // returns within ~820 ms when no card is present (0x20 = 32 retries × 25.6 ms).
        set_rf_passive_retries(0x20, nullptr);
        return DeviceKind::PN532;
    }

    // RFConfiguration (0x32) CfgItem=0x05: set MaxRetries.
    // mx_rty_passive: max retries for InListPassiveTarget (0xFF = infinite, default).
    // Keep MxRtyATR and MxRtyCOM at 0xFF (default) to not affect other operations.
    bool set_rf_passive_retries(uint8_t mx_rty_passive, std::string *error)
    {
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x32, {0x05, 0xFF, 0xFF, mx_rty_passive});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr); // expect D5 33
        return true;
    }

    // Release currently listed target (if any) to keep subsequent scans responsive.
    void release_target_if_listed()
    {
        in_release_all();
    }

    // InRelease (0x52): release all listed targets from the PN532.
    // Only called when target_listed_ is true (a target IS in the PN532's list).
    // Calling InRelease when no target is listed causes PN532 v1.6 to respond
    // with a delayed D5 53 frame that arrives AFTER the subsequent InListPassiveTarget
    // command is sent, poisoning collect_response() with D5 53 ≠ D5 4B.
    void in_release_all()
    {
        if (!target_listed_) return;  // Nothing to release; avoid spurious InRelease
        target_listed_ = false;

        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x52, {0x00});
        transport_->write_bytes(frame.data(), frame.size(), nullptr);
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr); // expect D5 53 00

        // Drain any additional stale bytes (safety net: e.g. delayed InCommunicateThru
        // responses or extra PN532 data that arrived after the InRelease response).
        uint8_t drain[64];
        for (int i = 0; i < 3; ++i) {
            if (transport_->read_bytes(drain, sizeof(drain), 8, nullptr) <= 0) break;
        }
    }

    // ── Gen1a magic card support ─────────────────────────────────────────────

    // Write a PN532 internal register via WriteRegister (0x08) command.
    // addr: 16-bit register address (e.g. 0x633D for CIU_BitFraming)
    bool write_register(uint16_t addr, uint8_t val, std::string *error)
    {
        const uint8_t ah = (addr >> 8) & 0xFF;
        const uint8_t al = addr & 0xFF;
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x08, {ah, al, val});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        collect_response(&rx, nullptr); // expect D5 09
        return true;
    }

    // Read a PN532 internal register via ReadRegister (0x06) command.
    // Returns the register value, or 0xFF on failure.
    uint8_t read_register(uint16_t addr)
    {
        const uint8_t ah = (addr >> 8) & 0xFF;
        const uint8_t al = addr & 0xFF;
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x06, {ah, al});
        transport_->write_bytes(frame.data(), frame.size(), nullptr);
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, nullptr)) return 0xFF;
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd) ||
            fd.size() < 3 || fd[0] != 0xD5 || fd[1] != 0x07) return 0xFE;
        return fd[2]; // first register value
    }

    // InCommunicateThru (0x42): send raw bytes through NFC RF link, return tag response.
    // resp_data receives [status, data...] bytes from the PN532 response frame.
    bool in_communicate_thru_raw(const uint8_t *data, size_t len,
                                 std::vector<uint8_t> *resp_data, std::string *error)
    {
        std::vector<uint8_t> payload(data, data + len);
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x42, payload);
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> frame_data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &frame_data)) {
            if (error) *error = "no InCommunicateThru response";
            return false;
        }
        if (frame_data.size() < 3 || frame_data[0] != 0xD5 || frame_data[1] != 0x43) {
            if (error) *error = "unexpected InCommunicateThru response";
            return false;
        }
        if (resp_data) resp_data->assign(frame_data.begin() + 2, frame_data.end());
        return true;
    }

    // Detect Gen1A magic card using Bruce-compatible handshake only:
    // send7bit(0x40) ACK(0x0A) + send(0x43) ACK(0x0A).
    // Do not use unauthenticated READ(0x30) as confirmation because Gen3/Gen4
    // may also respond and cause false Gen1A positives.
    bool is_gen1a(std::string *error)
    {
        auto has_ack_0a = [](const std::vector<uint8_t> &resp) {
            // in_communicate_thru_raw returns [status, data...].
            return resp.size() >= 2 && resp[1] == 0x0A;
        };

        // Session pre-step: clear register state and HALT the tag once.
        // Avoid repeating HALT on every retry; only retry unlock handshakes.
        {
            const std::vector<uint8_t> frame =
                Pn532FrameCodec::build_command(0x08, {0x63, 0x02, 0x00, 0x63, 0x03, 0x00});
            transport_->write_bytes(frame.data(), frame.size(), nullptr);
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr);
        }
        {
            const std::vector<uint8_t> frame =
                Pn532FrameCodec::build_command(0x42, {0x50, 0x00});
            transport_->write_bytes(frame.data(), frame.size(), nullptr);
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr); // timeout is normal
        }
#ifndef _WIN32
        usleep(10000);
#endif

        for (int attempt = 0; attempt < 3; ++attempt) {

            // ── Step 3 & 4: send7bit(0x40) via WriteReg(0x633D,7) + ICT + WriteReg(0x633D,0) ─
            write_register(0x633D, 0x07, nullptr); // CIU TxLastBits=7 (Bruce uses 0x633D)
#ifndef _WIN32
            usleep(5000);
#endif
            const uint8_t u1 = 0x40;
            std::vector<uint8_t> resp1;
            in_communicate_thru_raw(&u1, 1, &resp1, nullptr);
            write_register(0x633D, 0x00, nullptr);
#ifndef _WIN32
            usleep(5000);
#endif
            // ── Step 5: ICT({0x43}) — unlock2 ─────────────────────────────
            const uint8_t u2 = 0x43;
            std::vector<uint8_t> resp2;
            in_communicate_thru_raw(&u2, 1, &resp2, nullptr);
#ifndef _WIN32
            usleep(5000);
#endif

            if (has_ack_0a(resp1) && has_ack_0a(resp2)) {
                target_listed_ = true;
                return true;
            }
#ifndef _WIN32
            usleep(10000);
#endif
        }
        if (error) *error = "Gen1A unlock ACK not observed";
        return false;
    }

    // Read one block (16 bytes) via InCommunicateThru + MfReadBlock (0x30).
    // Use ICT (not InDataExchange) so it works in Gen1A mode after CIU unlock.
    bool read_gen1a_block(uint8_t block, std::vector<uint8_t> *block_data, std::string *error)
    {
        // ICT payload: {0x30, block, CRC_H, CRC_L}
        uint8_t rd[4] = {0x30, block, 0, 0};
        compute_crc_a(rd, 2, &rd[2], &rd[3]);
        std::vector<uint8_t> resp;
        if (!in_communicate_thru_raw(rd, 4, &resp, error)) return false;
        // resp[0] = PN532 status (0x00=ok), resp[1..16] = block data
        if (resp.size() < 17 || resp[0] != 0x00) {
            if (error) {
                char b[32];
                std::snprintf(b, sizeof(b), "block %02d err %02X", block,
                              resp.empty() ? 0xFF : resp[0]);
                *error = b;
            }
            return false;
        }
        if (block_data) block_data->assign(resp.begin() + 1, resp.begin() + 17);
        return true;
    }

    // Read all 64 blocks of a Gen1a card.
    // blocks: output vector of 64 entries (empty vector for failed blocks).
    // log: optional per-step progress strings.
    // on_line: optional callback invoked immediately for each output line (real-time streaming).
    bool read_gen1a_full(std::vector<std::vector<uint8_t>> *blocks,
                         std::vector<std::string> *log, std::string *error,
                         std::function<void(const std::string &)> on_line = nullptr,
                         int inter_block_delay_ms = 0)
    {
        auto emit = [&](const std::string &s) {
            if (log) log->push_back(s);
            if (on_line) on_line(s);
        };
        emit("> Gen1A unlock...");
        if (!is_gen1a(error)) {
            emit(std::string("ERR ") + (error && !error->empty() ? *error : "not Gen1A"));
            return false;
        }
        emit("OK Gen1A unlocked");
        if (blocks) blocks->assign(64, {});
        int ok_count = 0;
        for (uint8_t blk = 0; blk < 64; ++blk) {
            if (inter_block_delay_ms > 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(inter_block_delay_ms));
            std::vector<uint8_t> bdata;
            std::string berr;
            if (read_gen1a_block(blk, &bdata, &berr)) {
                if (blocks) (*blocks)[blk] = bdata;
                ++ok_count;
                // format: "00:0102030405060708090A0B0C0D0E0F"
                char buf[40];
                int pos = std::snprintf(buf, sizeof(buf), "%02d:", blk);
                for (size_t bi = 0; bi < bdata.size() && bi < 16; ++bi)
                    pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%02X", bdata[bi]);
                emit(buf);
            } else {
                char buf[40];
                std::snprintf(buf, sizeof(buf), "ERR blk%02d: %s", blk, berr.c_str());
                emit(buf);
            }
        }
        {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "OK %d/64 blocks read", ok_count);
            emit(buf);
        }
        return ok_count > 0;
    }

    // ── Gen3 / Gen4 magic card detection ────────────────────────────────────

    // ISO 14443A CRC-A: initial=0x6363, poly=x^16+x^12+x^5+1
    static void compute_crc_a(const uint8_t *data, size_t len, uint8_t *out_lo, uint8_t *out_hi)
    {
        uint16_t crc = 0x6363;
        for (size_t i = 0; i < len; ++i) {
            uint8_t b = data[i];
            b = (uint8_t)(b ^ (crc & 0xFF));
            b = (uint8_t)(b ^ (b << 4));
            crc = (uint16_t)((crc >> 8) ^ ((uint16_t)b << 8) ^ ((uint16_t)b << 3) ^ ((uint16_t)b >> 4));
        }
        *out_lo = (uint8_t)(crc & 0xFF);
        *out_hi = (uint8_t)((crc >> 8) & 0xFF);
    }

    // Detect Gen3 magic card via manual ISO14443-A anticollision+select+READ.
    // Reference: pn532-python isGen3() sequence.
    // Key insight: InListPassiveTarget leaves the card in a PN532-managed state
    // where raw ICT READ fails (status 0x01). Must use the full manual RF path:
    // HALT -> 7-bit WUPA -> anticollision -> select -> ICT READ block0.
    bool is_gen3(std::string *error, const TagInfo *detected_tag = nullptr)
    {
        TagInfo tag;
        if (detected_tag) {
            tag = *detected_tag;
        } else {
            if (!in_list_passive_target_iso14443a(&tag, error)) return false;
        }

        auto is_mfc_like = [&]() {
            if (tag.protocol == ProtocolKind::MifareClassic) return true;

            std::string type_upper = tag.tag_type;
            for (char &ch : type_upper) {
                if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - ('a' - 'A'));
            }
            if (type_upper.find("MIFARE CLASSIC") != std::string::npos) return true;

            auto it = tag.identity_fields.find("SAK");
            if (it == tag.identity_fields.end()) return false;

            std::string sak_hex;
            sak_hex.reserve(it->second.size());
            for (char ch : it->second) {
                const bool digit = (ch >= '0' && ch <= '9');
                const bool lower_hex = (ch >= 'a' && ch <= 'f');
                const bool upper_hex = (ch >= 'A' && ch <= 'F');
                if (!digit && !lower_hex && !upper_hex) continue;
                if (lower_hex) ch = static_cast<char>(ch - ('a' - 'A'));
                sak_hex.push_back(ch);
            }
            if (sak_hex.size() < 2) return false;

            const std::string sak = sak_hex.substr(sak_hex.size() - 2);
            return sak == "08" || sak == "09" || sak == "18" || sak == "1C" ||
                   sak == "28" || sak == "38";
        };

        if (!is_mfc_like()) return false;

        // ── Manual RF probe (pn532-python path) ─────────────────────────────
        // 1. Reset registers (clear CommIEn/DivIEn)
        {
            const std::vector<uint8_t> frame =
                Pn532FrameCodec::build_command(0x08, {0x63, 0x02, 0x00, 0x63, 0x03, 0x00});
            transport_->write_bytes(frame.data(), frame.size(), nullptr);
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr);
        }
        // 2. HALT (no CRC, per pn532-python / Bruce)
        {
            const std::vector<uint8_t> frame =
                Pn532FrameCodec::build_command(0x42, {0x50, 0x00});
            transport_->write_bytes(frame.data(), frame.size(), nullptr);
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr); // timeout expected
        }
#ifndef _WIN32
        usleep(10000);
#endif
        // 3. 7-bit WUPA (0x52): wake card from HALT
        write_register(0x633D, 0x07, nullptr);
#ifndef _WIN32
        usleep(5000);
#endif
        const uint8_t wupa = 0x52;
        std::vector<uint8_t> atqa_resp;
        in_communicate_thru_raw(&wupa, 1, &atqa_resp, nullptr);
        write_register(0x633D, 0x00, nullptr);
#ifndef _WIN32
        usleep(5000);
#endif
        if (atqa_resp.empty() || atqa_resp[0] != 0x00) {
            if (error && error->empty()) *error = "Gen3 WUPA no ATQA";
            return false;
        }

        // 4. Anticollision cascade 1: ICT(0x93, 0x20) -> [status, uid0..3, bcc]
        const uint8_t ac1_cmd[] = {0x93, 0x20};
        std::vector<uint8_t> ac1;
        in_communicate_thru_raw(ac1_cmd, sizeof(ac1_cmd), &ac1, nullptr);
        if (ac1.size() < 6 || ac1[0] != 0x00) {
            if (error && error->empty()) *error = "Gen3 anticol1 failed";
            return false;
        }

        // 5. Select cascade 1: ICT(0x93, 0x70, uid0..3, bcc, crc_a, crc_b)
        {
            uint8_t sel1[9] = {0x93, 0x70, ac1[1], ac1[2], ac1[3], ac1[4], ac1[5], 0, 0};
            compute_crc_a(sel1, 7, &sel1[7], &sel1[8]);
            std::vector<uint8_t> sak1;
            in_communicate_thru_raw(sel1, sizeof(sel1), &sak1, nullptr);
            if (sak1.size() < 2 || sak1[0] != 0x00) {
                if (error && error->empty()) *error = "Gen3 sel1 failed";
                return false;
            }

            // 6. Cascade 2 for 7-byte UIDs (uid0 == 0x88 cascade tag)
            if (ac1[1] == 0x88) {
                const uint8_t ac2_cmd[] = {0x95, 0x20};
                std::vector<uint8_t> ac2;
                in_communicate_thru_raw(ac2_cmd, sizeof(ac2_cmd), &ac2, nullptr);
                if (ac2.size() < 6 || ac2[0] != 0x00) {
                    if (error && error->empty()) *error = "Gen3 anticol2 failed";
                    return false;
                }
                uint8_t sel2[9] = {0x95, 0x70, ac2[1], ac2[2], ac2[3], ac2[4], ac2[5], 0, 0};
                compute_crc_a(sel2, 7, &sel2[7], &sel2[8]);
                std::vector<uint8_t> sak2;
                in_communicate_thru_raw(sel2, sizeof(sel2), &sak2, nullptr);
                if (sak2.size() < 2 || sak2[0] != 0x00) {
                    if (error && error->empty()) *error = "Gen3 sel2 failed";
                    return false;
                }
            }
        }

        // 7. ICT READ block0 without auth -- Gen3 responds, normal MFC cards refuse
        uint8_t rd[4] = {0x30, 0x00, 0, 0};
        compute_crc_a(rd, 2, &rd[2], &rd[3]);
        std::vector<uint8_t> rd_resp;
        in_communicate_thru_raw(rd, sizeof(rd), &rd_resp, nullptr);

        // Success: [status=0x00] + 16 data bytes (+ optional CRC)
        if ((rd_resp.size() >= 17 && rd_resp[0] == 0x00) || rd_resp.size() >= 16) {
            target_listed_ = false; // selected via raw ICT, not InListPassiveTarget
            return true;
        }

        if (error && error->empty()) {
            char b[72];
            std::snprintf(b, sizeof(b), "Gen3 READ short: %zu bytes (status 0x%02X)",
                          rd_resp.size(), rd_resp.empty() ? 0xFFu : (unsigned)rd_resp[0]);
            *error = b;
        }
        return false;
    }

    // Detect Gen4 (GDM) magic card: re-select then send Gen4 GetVersion command.
    // password: 8-char hex string, default "00000000"
    // Reference: Bruce pn532external.cpp isGen4()
    bool is_gen4(const std::string &password, std::string *error)
    {
        // Parse 4-byte password from hex string
        uint8_t pw[4] = {0, 0, 0, 0};
        auto hexval = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
            if (c >= 'a' && c <= 'f') return (uint8_t)(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
            return 0;
        };
        for (int i = 0; i < 4 && (size_t)(i * 2 + 1) < password.size(); ++i) {
            pw[i] = (uint8_t)((hexval(password[i * 2]) << 4) | hexval(password[i * 2 + 1]));
        }
        TagInfo tag;
        if (!in_list_passive_target_iso14443a(&tag, error)) return false;
        // Gen4 command: CF [pw 4B] C6 [CRC 2B]
        uint8_t cmd[8];
        cmd[0] = 0xCF;
        cmd[1] = pw[0]; cmd[2] = pw[1]; cmd[3] = pw[2]; cmd[4] = pw[3];
        cmd[5] = 0xC6;
        compute_crc_a(cmd, 6, &cmd[6], &cmd[7]);
        std::vector<uint8_t> resp;
        if (!in_communicate_thru_raw(cmd, 8, &resp, error)) return false;
        return resp.size() >= 15;
    }

    // Write Mifare Classic block 0 on a Gen1A magic card.
    // Requires unlocked Gen1A state and a full 16-byte block payload.
    bool write_gen1a_block0(const std::vector<uint8_t> &block0, std::string *error)
    {
        if (block0.size() != 16) {
            if (error) *error = "block0 must be 16 bytes";
            return false;
        }

        TagInfo tag;
        if (!in_list_passive_target_iso14443a(&tag, error)) return false;
        if (!is_gen1a(error)) {
            if (error && error->empty()) *error = "not Gen1A";
            return false;
        }

        // Gen1A write ACK is a 4-bit frame (0x0A). The PN532 firmware often
        // reports framing-error status 0x05 for these, even when the write
        // succeeded. Accept both 0x00 (clean) and 0x05 (framing error) as long
        // as the ACK byte 0x0A is present in the response data.
        auto gen1a_ict_write = [&](const std::vector<uint8_t> &payload, bool append_crc,
                                   const char *step_name) -> bool {
            std::vector<uint8_t> tx = payload;
            if (append_crc) {
                uint8_t lo = 0, hi = 0;
                compute_crc_a(tx.data(), tx.size(), &lo, &hi);
                tx.push_back(lo);
                tx.push_back(hi);
            }
            std::vector<uint8_t> resp;
            in_communicate_thru_raw(tx.data(), tx.size(), &resp, nullptr);
            // Accept: status 0x00 or 0x05 (framing error from 4-bit ACK), ACK byte 0x0A
            const bool status_ok = !resp.empty() && (resp[0] == 0x00 || resp[0] == 0x05);
            if (status_ok && resp.size() >= 2 && resp[1] == 0x0A) return true;
            if (status_ok && resp.size() == 1 && resp[0] == 0x05) return true; // ACK squeezed into status
            if (error) {
                char b[48];
                if (resp.empty()) std::snprintf(b, sizeof(b), "%s: no response", step_name);
                else std::snprintf(b, sizeof(b), "%s: status 0x%02X ack 0x%02X",
                                   step_name, resp[0], resp.size() >= 2 ? resp[1] : 0xFF);
                *error = b;
            }
            return false;
        };

        if (!gen1a_ict_write({0xA0, 0x00}, true, "write cmd")) return false;
        if (!gen1a_ict_write(block0, true, "write data")) return false;
        return true;
    }

    // Write Mifare Classic block 0 using authenticated write (CUID/Gen2 style).
    // key_a must be 6 bytes (Sector0 KeyA).
    bool write_gen2_block0(const std::vector<uint8_t> &block0,
                           const std::vector<uint8_t> &key_a,
                           std::string *error)
    {
        if (block0.size() != 16) {
            if (error) *error = "block0 must be 16 bytes";
            return false;
        }
        if (key_a.size() != 6) {
            if (error) *error = "Sector0 KeyA must be 6 bytes";
            return false;
        }

        TagInfo tag;
        if (!in_list_passive_target_iso14443a(&tag, error)) return false;

        std::vector<uint8_t> uid_bytes;
        for (size_t i = 0; i + 1 < tag.uid.size(); i += 2) {
            uid_bytes.push_back(static_cast<uint8_t>(std::strtoul(tag.uid.substr(i, 2).c_str(), nullptr, 16)));
        }
        if (uid_bytes.size() < 4) {
            if (error) *error = "invalid card UID";
            return false;
        }
        uint8_t uid4[4] = {
            uid_bytes[uid_bytes.size() - 4],
            uid_bytes[uid_bytes.size() - 3],
            uid_bytes[uid_bytes.size() - 2],
            uid_bytes[uid_bytes.size() - 1],
        };
        uint8_t key_arr[6] = {
            key_a[0], key_a[1], key_a[2], key_a[3], key_a[4], key_a[5]
        };

        std::string auth_err;
        bool authed = mf_authenticate(0, false, key_arr, uid4, &auth_err);
        if (!authed) {
            reselect_card_lightweight(nullptr);
            authed = mf_authenticate(0, true, key_arr, uid4, &auth_err);
        }
        if (!authed) {
            if (error) *error = auth_err.empty() ? "auth sector0 failed" : auth_err;
            return false;
        }

        return mf_write_block_auth(0, block0, error);
    }

    // Re-select a Gen3 card via raw ICT anticollision without going through
    // InListPassiveTarget. Does: HALT → WUPA → 9320(→9520) → 9370(→9570).
    // Must be called while in raw ICT mode (target_listed_ == false).
    // Returns false on any RF error; does NOT set target_listed_.
    bool gen3_select_raw(std::string *error)
    {
        // HALT (no CRC, timeout expected)
        {
            const std::vector<uint8_t> frame =
                Pn532FrameCodec::build_command(0x42, {0x50, 0x00});
            transport_->write_bytes(frame.data(), frame.size(), nullptr);
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr);
        }
#ifndef _WIN32
        usleep(10000);
#endif
        // WUPA (7-bit)
        write_register(0x633D, 0x07, nullptr);
#ifndef _WIN32
        usleep(5000);
#endif
        const uint8_t wupa = 0x52;
        std::vector<uint8_t> atqa_resp;
        in_communicate_thru_raw(&wupa, 1, &atqa_resp, nullptr);
        write_register(0x633D, 0x00, nullptr);
#ifndef _WIN32
        usleep(5000);
#endif
        if (atqa_resp.empty() || atqa_resp[0] != 0x00) {
            if (error) *error = "Gen3 reselect: WUPA no ATQA";
            return false;
        }

        // Anticollision cascade 1 (9320)
        const uint8_t ac1_cmd[] = {0x93, 0x20};
        std::vector<uint8_t> ac1;
        in_communicate_thru_raw(ac1_cmd, sizeof(ac1_cmd), &ac1, nullptr);
        if (ac1.size() < 6 || ac1[0] != 0x00) {
            if (error) *error = "Gen3 reselect: anticol1 failed";
            return false;
        }

        // Select cascade 1 (9370)
        uint8_t sel1[9] = {0x93, 0x70, ac1[1], ac1[2], ac1[3], ac1[4], ac1[5], 0, 0};
        compute_crc_a(sel1, 7, &sel1[7], &sel1[8]);
        std::vector<uint8_t> sak1;
        in_communicate_thru_raw(sel1, sizeof(sel1), &sak1, nullptr);
        if (sak1.size() < 2 || sak1[0] != 0x00) {
            if (error) *error = "Gen3 reselect: sel1 failed";
            return false;
        }

        // Cascade 2 for 7-byte UIDs
        if (ac1[1] == 0x88) {
            const uint8_t ac2_cmd[] = {0x95, 0x20};
            std::vector<uint8_t> ac2;
            in_communicate_thru_raw(ac2_cmd, sizeof(ac2_cmd), &ac2, nullptr);
            if (ac2.size() < 6 || ac2[0] != 0x00) {
                if (error) *error = "Gen3 reselect: anticol2 failed";
                return false;
            }
            uint8_t sel2[9] = {0x95, 0x70, ac2[1], ac2[2], ac2[3], ac2[4], ac2[5], 0, 0};
            compute_crc_a(sel2, 7, &sel2[7], &sel2[8]);
            std::vector<uint8_t> sak2;
            in_communicate_thru_raw(sel2, sizeof(sel2), &sak2, nullptr);
            if (sak2.size() < 2 || sak2[0] != 0x00) {
                if (error) *error = "Gen3 reselect: sel2 failed";
                return false;
            }
        }
        return true;
    }

    // Set UID for Gen3 Mifare Classic magic cards.
    // Sequence: is_gen3 (confirm + initial select) →
    //           gen3_select_raw (fresh select before 90FBCCCC) →
    //           90FBCCCC →
    //           gen3_select_raw (fresh select before 90F0CCCC) →
    //           90F0CCCC.
    bool set_classic_gen3_uid(const std::vector<uint8_t> &uid,
                              const std::vector<uint8_t> &block0,
                              std::string *error)
    {
        if (uid.size() != 4 && uid.size() != 7) {
            if (error) *error = "UID must be 4 or 7 bytes";
            return false;
        }
        if (block0.size() != 16) {
            if (error) *error = "block0 must be 16 bytes";
            return false;
        }

        // Confirm Gen3 via HALT→WUPA→9320→9370→READ. Card ends up selected.
        if (!is_gen3(error)) {
            if (error && error->empty()) *error = "not Gen3";
            return false;
        }

        // After is_gen3's READ, card needs a fresh anticollision cycle before
        // it will accept the backdoor 90FBCCCC command.
        if (!gen3_select_raw(error)) return false;

        // 90FBCCCC: set UID.
        // NOTE: Do NOT reselect between 90FBCCCC and 90F0CCCC. The two commands
        // must be sent back-to-back in the same RF session; a reselect in between
        // causes 90F0CCCC to fail silently (returns 9000 but data not committed).
        std::vector<uint8_t> cmd_uid = {0x90, 0xFB, 0xCC, 0xCC,
                                        static_cast<uint8_t>(uid.size())};
        cmd_uid.insert(cmd_uid.end(), uid.begin(), uid.end());
        if (!in_communicate_thru_checked(cmd_uid, true, nullptr, error)) return false;

        // 90F0CCCC: write block0 immediately (no reselect)
        std::vector<uint8_t> cmd_blk0 = {0x90, 0xF0, 0xCC, 0xCC, 0x10};
        cmd_blk0.insert(cmd_blk0.end(), block0.begin(), block0.end());
        return in_communicate_thru_checked(cmd_blk0, true, nullptr, error);
    }

    // Set UID for Gen4 magic cards (GDM family).
    // password: 8-char hex string, defaults to "00000000" in caller.
    bool set_gen4_uid(const std::vector<uint8_t> &uid,
                      const std::vector<uint8_t> &block0,
                      const std::string &password,
                      std::string *error)
    {
        if (uid.size() != 4 && uid.size() != 7) {
            if (error) *error = "UID must be 4 or 7 bytes";
            return false;
        }
        if (block0.size() != 16) {
            if (error) *error = "block0 must be 16 bytes";
            return false;
        }

        uint8_t pw[4] = {0, 0, 0, 0};
        auto hexval = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            return 0;
        };
        for (int i = 0; i < 4 && (i * 2 + 1) < static_cast<int>(password.size()); ++i) {
            pw[i] = static_cast<uint8_t>((hexval(password[i * 2]) << 4) | hexval(password[i * 2 + 1]));
        }

        if (!is_gen4(password, error)) {
            if (error && error->empty()) *error = "not Gen4";
            return false;
        }

        const uint8_t uid_mode = (uid.size() == 4) ? 0x00 : 0x01;
        std::vector<uint8_t> cmd_len = {0xCF, pw[0], pw[1], pw[2], pw[3], 0x68, uid_mode};
        if (!in_communicate_thru_checked(cmd_len, true, nullptr, error)) return false;

        std::vector<uint8_t> cmd_write = {0xCF, pw[0], pw[1], pw[2], pw[3], 0xCD, 0x00};
        cmd_write.insert(cmd_write.end(), block0.begin(), block0.end());
        return in_communicate_thru_checked(cmd_write, true, nullptr, error);
    }

    bool in_list_passive_target_iso14443a(TagInfo *tag, std::string *error)
    {
        if (!tag) {
            if (error) *error = "missing tag output";
            return false;
        }

        // Python pn532_cmd.py hf_14a_scan() calls set_normal_mode() (= wakeup +
        // SAMConfiguration) before every InListPassiveTarget.  Do the same here
        // to ensure the chip is in a clean reader state each attempt.
        send_wakeup();
        sam_configuration(nullptr);

        // Release the current target (if any) before a new scan.
        // in_release_all() is a no-op when target_listed_=false, so safe to call
        // unconditionally; on first scan it simply skips, avoiding the spurious
        // delayed-D5-53 issue seen with PN532 v1.6 firmware.
        in_release_all();

        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x4A, {0x01, 0x00});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) {
            return false;
        }

        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) {
            return false;
        }

        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) {
            if (error) *error = "no card response frame";
            return false;
        }

        // Minimum: TFI(D5) + cmd(4B) + NbTg(1) = 3 bytes
        if (data.size() < 3 || data[0] != 0xD5 || data[1] != 0x4B) {
            if (error) *error = "unexpected card response";
            return false;
        }
        if (data[2] == 0x00) {
            if (error) *error = "no passive target found";
            return false;
        }
        // Target present: need at least 9 bytes for ATQA(2)+SAK(1)+UIDLen(1)+UID(>=4)
        if (data.size() < 9) {
            if (error) *error = "truncated card response";
            return false;
        }

        const uint8_t atqa1 = data[4];
        const uint8_t atqa2 = data[5];
        const uint8_t sak = data[6];
        const uint8_t uid_len = data[7];
        if (data.size() < static_cast<size_t>(8 + uid_len)) {
            if (error) *error = "truncated UID data";
            return false;
        }

        tag->protocol = ProtocolKind::Iso14443A;
        tag->uid = to_hex(data.data() + 8, uid_len);
        tag->tag_type = detect_mifare_classic(sak, uid_len);

        if (sak == 0x00) {
            tag->tag_type = classify_type2_tag();
        }

        if (tag->tag_type.find("Mifare Classic") != std::string::npos) {
            tag->protocol = ProtocolKind::MifareClassic;
        }
        tag->identity_fields["ATQA"] = byte_hex(atqa1) + byte_hex(atqa2);
        tag->identity_fields["SAK"] = byte_hex(sak);
        tag->identity_fields["UID_LEN"] = std::to_string(uid_len);
        tag->raw_data.push_back(bytes_to_hex(data));
        if (error) error->clear();
        target_listed_ = true;  // Tg=1 is now listed in the PN532
        return true;
    }

    // Re-select the current target with a bare InListPassiveTarget,
    // WITHOUT classify_type2_tag() probes. Used before write so the
    // card is in a clean selected state.
    bool iso14443a_reselect_for_write(std::string *error = nullptr)
    {
        // Release current target, then re-list
        in_release_all();
        target_listed_ = false;

        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x4A, {0x01, 0x00});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) {
            if (error) *error = "no card response";
            return false;
        }
        if (data.size() < 3 || data[0] != 0xD5 || data[1] != 0x4B || data[2] == 0x00) {
            if (error) *error = "card not found";
            return false;
        }
        target_listed_ = true;
        return true;
    }

    // InDataExchange (0x40): send data to selected target, receive response.
    // tg: target number (0x01 for first target).
    // data: command bytes for the target (e.g. auth or read).
    // resp_data: output — response bytes AFTER the status byte (empty on error).
    bool in_data_exchange(uint8_t tg, const std::vector<uint8_t> &data,
                          std::vector<uint8_t> *resp_data, std::string *error)
    {
        std::vector<uint8_t> payload = {tg};
        payload.insert(payload.end(), data.begin(), data.end());
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x40, payload);
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd) ||
            fd.size() < 3 || fd[0] != 0xD5 || fd[1] != 0x41) {
            if (error) *error = "unexpected InDataExchange response";
            return false;
        }
        const uint8_t status = fd[2];
        if (status != 0x00) {
            if (error) {
                char b[32];
                std::snprintf(b, sizeof(b), "status 0x%02X", status);
                *error = b;
            }
            return false;
        }
        if (resp_data) resp_data->assign(fd.begin() + 3, fd.end());
        return true;
    }

    // Mifare Classic auth via InDataExchange (0x60=Key A, 0x61=Key B).
    // block: block number to authenticate (use first block of sector).
    // uid4: first 4 bytes of tag UID.
    bool mf_authenticate(uint8_t block, bool key_b,
                         const uint8_t key[6], const uint8_t uid4[4],
                         std::string *error)
    {
        const uint8_t cmd = key_b ? 0x61 : 0x60;
        std::vector<uint8_t> data = {cmd, block};
        data.insert(data.end(), key, key + 6);
        data.insert(data.end(), uid4, uid4 + 4);
        std::vector<uint8_t> resp;
        return in_data_exchange(0x01, data, &resp, error);
    }

    // Mifare Classic read block (0x30) via InDataExchange.
    // Target sector must be authenticated before calling this.
    bool mf_read_block_auth(uint8_t block, std::vector<uint8_t> *block_data, std::string *error)
    {
        std::vector<uint8_t> resp;
        if (!in_data_exchange(0x01, {0x30, block}, &resp, error)) return false;
        if (resp.size() < 16) {
            if (error) *error = "short block response";
            return false;
        }
        if (block_data) block_data->assign(resp.begin(), resp.begin() + 16);
        return true;
    }

    // Mifare Classic write block (0xA0) via InDataExchange.
    // Target sector must be authenticated before calling this.
    bool mf_write_block_auth(uint8_t block, const std::vector<uint8_t> &block_data, std::string *error)
    {
        if (block_data.size() != 16) {
            if (error) *error = "write data must be 16 bytes";
            return false;
        }

        std::vector<uint8_t> ack;
        if (!in_data_exchange(0x01, {0xA0, block}, &ack, error)) return false;
        if (!ack.empty() && ack[0] != 0x0A) {
            if (error) *error = "write command not acknowledged";
            return false;
        }

        std::vector<uint8_t> resp;
        if (!in_data_exchange(0x01, block_data, &resp, error)) return false;
        if (!resp.empty() && resp[0] != 0x0A) {
            if (error) *error = "write data not acknowledged";
            return false;
        }
        return true;
    }

    bool in_communicate_thru_checked(const std::vector<uint8_t> &command,
                                     bool append_crc,
                                     std::vector<uint8_t> *resp_data,
                                     std::string *error)
    {
        std::vector<uint8_t> tx = command;
        if (append_crc) {
            uint8_t crc_lo = 0, crc_hi = 0;
            compute_crc_a(tx.data(), tx.size(), &crc_lo, &crc_hi);
            tx.push_back(crc_lo);
            tx.push_back(crc_hi);
        }

        std::vector<uint8_t> resp;
        if (!in_communicate_thru_raw(tx.data(), tx.size(), &resp, error)) return false;
        if (resp.empty()) {
            if (error) *error = "empty response";
            return false;
        }
        if (resp[0] != 0x00) {
            if (error) {
                char b[32];
                std::snprintf(b, sizeof(b), "status 0x%02X", resp[0]);
                *error = b;
            }
            return false;
        }
        if (resp_data) *resp_data = resp;
        return true;
    }

    // Lightweight re-select: release current target then InListPassiveTarget,
    // WITHOUT wakeup+SAMConfig overhead.  Used after a failed auth attempt
    // to restore the card to a selectable state quickly.
    bool reselect_card_lightweight(std::string *error)
    {
        // Release current target (if any)
        if (target_listed_) {
            target_listed_ = false;
            const std::vector<uint8_t> rel = Pn532FrameCodec::build_command(0x52, {0x00});
            transport_->write_bytes(rel.data(), rel.size(), nullptr);
            std::vector<uint8_t> rx;
            collect_response(&rx, nullptr);
            uint8_t drain[64];
            for (int i = 0; i < 3; ++i)
                if (transport_->read_bytes(drain, sizeof(drain), 8, nullptr) <= 0) break;
        }
        // Re-select
        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x4A, {0x01, 0x00});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> fd;
        if (!Pn532FrameCodec::parse_first_frame(rx, &fd) ||
            fd.size() < 3 || fd[0] != 0xD5 || fd[1] != 0x4B || fd[2] == 0x00) return false;
        target_listed_ = true;
        return true;
    }

    // Read all sectors of a standard (non-magic) Mifare Classic card
    // using a set of well-known default keys.
    // uid4: first 4 bytes of UID as raw bytes.
    // sector_count: 16 for 1K, 40 for 4K (sectors 32-39 each have 16 blocks).
    // blocks_hex: output vector (one hex string per block, empty string for failed reads).
    // on_line: optional progress callback.
    // Returns true if at least one block was read successfully.
    bool read_mifare_standard(const std::vector<uint8_t> &uid4,
                              int sector_count,
                              std::vector<std::string> *blocks_hex,
                              std::string *error,
                              std::function<void(const std::string &)> on_line = nullptr)
    {
        // Common default keys to try (Key A then Key B)
        static const uint8_t DEFAULT_KEYS[][6] = {
            {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
            {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5},
            {0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7},
            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        };
        static const int NUM_KEYS = 4;

        uint8_t uid4_arr[4] = {0};
        for (int i = 0; i < 4 && i < static_cast<int>(uid4.size()); ++i)
            uid4_arr[i] = uid4[i];

        // Mifare Classic 4K: sectors 0-31 have 4 blocks, sectors 32-39 have 16 blocks.
        // For 1K: 16 sectors × 4 blocks = 64 total.
        const int total_blocks = (sector_count <= 32) ? sector_count * 4
                                                       : 32 * 4 + (sector_count - 32) * 16;
        if (blocks_hex) blocks_hex->assign(total_blocks, "");

        auto emit = [&](const std::string &s) { if (on_line) on_line(s); };
        int ok_count = 0;

        for (int s = 0; s < sector_count; ++s) {
            const uint8_t first_block = (s < 32) ? static_cast<uint8_t>(s * 4)
                                                  : static_cast<uint8_t>(32 * 4 + (s - 32) * 16);
            const int blocks_in_sector = (s < 32) ? 4 : 16;
            bool auth_ok = false;
            std::string auth_err;

            // Try Key A then Key B for each default key
            for (int kb = 0; kb < 2 && !auth_ok; ++kb) {
                for (int ki = 0; ki < NUM_KEYS && !auth_ok; ++ki) {
                    if (mf_authenticate(first_block, kb != 0,
                                        DEFAULT_KEYS[ki], uid4_arr, &auth_err)) {
                        auth_ok = true;
                    } else {
                        // Failed auth: re-select the card before trying next key
                        if (!reselect_card_lightweight(nullptr)) break;
                    }
                }
            }

            if (!auth_ok) {
                char buf[40];
                std::snprintf(buf, sizeof(buf), "ERR sec%02d: no key", s);
                emit(buf);
                continue;
            }

            // Read all blocks of this sector
            for (int b = 0; b < blocks_in_sector; ++b) {
                const uint8_t blk = static_cast<uint8_t>(first_block + b);
                std::vector<uint8_t> bdata;
                std::string berr;
                if (mf_read_block_auth(blk, &bdata, &berr)) {
                    std::string hex;
                    hex.reserve(32);
                    for (uint8_t byte : bdata) {
                        char hb[3];
                        std::snprintf(hb, sizeof(hb), "%02X", byte);
                        hex += hb;
                    }
                    if (blocks_hex && blk < static_cast<uint8_t>(blocks_hex->size()))
                        (*blocks_hex)[blk] = hex;
                    ++ok_count;
                    char buf[48];
                    std::snprintf(buf, sizeof(buf), "%02d:%s", blk, hex.c_str());
                    emit(buf);
                } else {
                    char buf[40];
                    std::snprintf(buf, sizeof(buf), "ERR blk%02d: %s", blk, berr.c_str());
                    emit(buf);
                    // Re-authenticate for next block attempt
                    reselect_card_lightweight(nullptr);
                    for (int kb = 0; kb < 2 && !mf_authenticate(first_block, kb != 0,
                             DEFAULT_KEYS[0], uid4_arr, nullptr); ++kb) {}
                }
            }
        }

        char result[48];
        std::snprintf(result, sizeof(result), "OK %d/%d blocks", ok_count, total_blocks);
        emit(result);
        if (error && ok_count == 0) *error = "all sectors locked";
        return ok_count > 0;
    }

    // InListPassiveTarget for ISO15693 (brTy=0x05): scan for ISO 15693 tags.
    // On success, populates tag->uid (reversed display, E0... format), protocol = Iso15693.
    bool in_list_passive_target_iso15693(TagInfo *tag, std::string *error)
    {
        if (!tag) return false;
        send_wakeup();
        sam_configuration(nullptr);
        in_release_all();

        const std::vector<uint8_t> frame = Pn532FrameCodec::build_command(0x4A, {0x01, 0x05});
        if (transport_->write_bytes(frame.data(), frame.size(), error) < 0) return false;
        std::vector<uint8_t> rx;
        if (!collect_response(&rx, error)) return false;
        std::vector<uint8_t> data;
        if (!Pn532FrameCodec::parse_first_frame(rx, &data)) {
            if (error) *error = "no 15693 response frame";
            return false;
        }
        // Expected: D5 4B NbTg [Tg UID[8]]
        if (data.size() < 3 || data[0] != 0xD5 || data[1] != 0x4B) {
            if (error) *error = "unexpected 15693 response";
            return false;
        }
        if (data[2] == 0x00) {
            if (error) *error = "no ISO15693 tag found";
            return false;
        }
        // Minimum: D5(1) 4B(1) NbTg(1) Tg(1) UID[8] = 12 bytes
        if (data.size() < 12) {
            if (error) *error = "truncated 15693 response";
            return false;
        }
        // data[3] = Tg (target number), data[4..11] = UID (8 bytes, device sends MSB first)
        // pn532-python reverses byte order for display (so E0 prefix appears last):
        const uint8_t *uid = data.data() + 4;
        char uid_buf[17] = {};
        for (int i = 7; i >= 0; --i)
            std::snprintf(uid_buf + (7 - i) * 2, 3, "%02X", uid[i]);
        tag->protocol = ProtocolKind::Iso15693;
        tag->tag_type = "ISO 15693";
        tag->uid = uid_buf;
        tag->raw_data.clear();
        tag->raw_data.push_back("UID: " + tag->uid);
        tag->identity_fields.clear();
        tag->identity_fields["DSFID"] = "00";
        tag->identity_fields["AFI"]   = "00";
        tag->identity_fields.erase("ATQA");
        tag->identity_fields.erase("SAK");

        // Tg=1 is now listed, so InDataExchange can query ISO15693 system info.
        target_listed_ = true;

        auto enrich_iso15693_system_info = [&]() {
            std::vector<uint8_t> info;
            if (!in_data_exchange(0x01, {0x2B}, &info, nullptr) &&
                !in_data_exchange(0x01, {0x02, 0x2B}, &info, nullptr) &&
                !in_data_exchange(0x01, {0x00, 0x2B}, &info, nullptr)) {
                return;
            }
            if (info.empty()) return;

            size_t pos = 0;
            const uint8_t info_flags = info[pos++];
            if (pos + 8 > info.size()) return;
            pos += 8;  // UID in system-info payload, scan path already has UID.

            if ((info_flags & 0x01) && pos < info.size()) {
                tag->identity_fields["DSFID"] = byte_hex(info[pos++]);
            }
            if ((info_flags & 0x02) && pos < info.size()) {
                tag->identity_fields["AFI"] = byte_hex(info[pos++]);
            }
            if ((info_flags & 0x04) && pos + 1 < info.size()) {
                const uint8_t blocks_minus_one = info[pos++];
                const uint8_t block_size_raw = info[pos++];
                const int block_count = static_cast<int>(blocks_minus_one) + 1;
                const int block_bytes = static_cast<int>(block_size_raw & 0x1F) + 1;
                tag->identity_fields["BLOCK_SIZE"] = std::to_string(block_count);
                tag->identity_fields["BLOCK_BYTES"] = std::to_string(block_bytes);
            }
            if ((info_flags & 0x08) && pos < info.size()) {
                tag->identity_fields["IC_REF"] = byte_hex(info[pos++]);
            }
        };
        enrich_iso15693_system_info();

        tag->raw_data.push_back("AFI: " + tag->identity_fields["AFI"]);
        tag->raw_data.push_back("DSFID: " + tag->identity_fields["DSFID"]);
        if (tag->identity_fields.count("IC_REF")) {
            tag->raw_data.push_back("IC Reference: " + tag->identity_fields["IC_REF"]);
        }
        if (tag->identity_fields.count("BLOCK_SIZE")) {
            tag->raw_data.push_back("Block size: " + tag->identity_fields["BLOCK_SIZE"]);
        }
        if (error) error->clear();
        return true;
    }

    // ── NTAG / Mifare Ultralight dump ────────────────────────────────────────

    // Read 4 Type2 pages (16 bytes) using READ (0x30), with PN532Killer raw fallback.
    bool type2_read_four_pages(uint8_t start_page, std::vector<uint8_t> *out16)
    {
        if (!out16) return false;

        std::vector<uint8_t> resp;
        if (in_data_exchange(0x01, {0x30, start_page}, &resp, nullptr) && resp.size() >= 16) {
            out16->assign(resp.begin(), resp.begin() + 16);
            return true;
        }

        // Compatibility fallback for firmware variants that reject InDataExchange
        // for Type2 READ but accept raw 14A transceive.
        uint8_t raw_cmd[4] = {0x30, start_page, 0x00, 0x00};
        compute_crc_a(raw_cmd, 2, &raw_cmd[2], &raw_cmd[3]);
        std::vector<uint8_t> raw_resp;
        if (!in_communicate_thru_raw(raw_cmd, sizeof(raw_cmd), &raw_resp, nullptr)) return false;
        if (raw_resp.size() < 17 || raw_resp[0] != 0x00) return false;

        out16->assign(raw_resp.begin() + 1, raw_resp.begin() + 17);
        return true;
    }

    // Probe whether a Type2 page exists by issuing READ on that page address.
    bool type2_has_page(uint8_t page)
    {
        std::vector<uint8_t> chunk;
        return type2_read_four_pages(page, &chunk);
    }

    // GET_VERSION (0x60) for NTAG/Ultralight chips (NXP-specific command).
    // Returns the version payload bytes on success, empty vector on failure.
    // Mifare Ultralight (original / C) will NAK → empty returned.
    std::vector<uint8_t> ntag_get_version()
    {
        std::vector<uint8_t> resp;
        if (in_data_exchange(0x01, {0x60}, &resp, nullptr)) {
            return resp;
        }

        // pn532-python falls back to raw 14A transceive on some PN532Killer firmware.
        // InCommunicateThru expects a full 14A frame (with CRC-A appended).
        uint8_t cmd[3] = {0x60, 0x00, 0x00};
        compute_crc_a(cmd, 1, &cmd[1], &cmd[2]);
        std::vector<uint8_t> raw;
        if (in_communicate_thru_raw(cmd, sizeof(cmd), &raw, nullptr) &&
            raw.size() >= 2 && raw[0] == 0x00) {
            return std::vector<uint8_t>(raw.begin() + 1, raw.end());
        }
        return {};
    }

    // GroveNFC-style Type2 classification flow:
    // 1) GET_VERSION (0x60) first
    // 2) If unknown/fail, probe high pages to differentiate NTAG213/215/216
    // 3) Finally use page 0x29 heuristic for MFUL-C vs NTAG203-like cards
    std::string classify_type2_tag()
    {
        const std::vector<uint8_t> ver = ntag_get_version();
        const std::string known = ntag_type_from_version(ver);
        if (!known.empty()) return known;

        // High-page probe avoids collapsing NTAG213/216 into generic Ultralight.
        if (type2_has_page(0x2C)) {
            if (type2_has_page(0x86)) {
                if (type2_has_page(0xE6)) return "NTAG216";
                return "NTAG215";
            }
            return "NTAG213";
        }

        // GroveNFC fallback: page 0x29 readable usually indicates UL-C path.
        if (type2_has_page(0x29)) {
            return "MIFARE Ultralight C";
        }

        // If GET_VERSION responded but unknown, keep family-level hint.
        if (ver.size() >= 8) {
            const uint8_t ic_type = ver[2];
            const uint8_t storage = ver[6];
            if (ic_type == 0x04) {
                if (storage == 0x12) return "NTAG203";
                return "NTAG";
            }
            if (ic_type == 0x03) return "MIFARE Ultralight";
            return "ISO14443A Type2";
        }
        return "NTAG/Ultralight";
    }

    // Identify NTAG variant from GET_VERSION response bytes (NXP AN10609).
    // ver[6] = storage size indicator:
    //   0x0F → NTAG213 (45 pages), 0x11 → NTAG215 (135 pages), 0x13 → NTAG216 (231 pages)
    static std::string ntag_type_from_version(const std::vector<uint8_t> &ver)
    {
        if (ver.size() < 8) return "";
        switch (ver[6]) {
        case 0x0B: return "MIFARE Ultralight EV1 (UL11)";
        case 0x0E: return "MIFARE Ultralight EV1 (UL21)";
        case 0x0F: return "NTAG213";
        case 0x11: return "NTAG215";
        case 0x12: return "NTAG203";
        case 0x13: return "NTAG216";
        default:   return "";
        }
    }

    // Total page count for known NTAG types (4 bytes per page).
    static int ntag_page_count_for_type(const std::string &type)
    {
        if (type == "MIFARE Ultralight EV1 (UL11)") return 20;
        if (type == "MIFARE Ultralight EV1 (UL21)") return 41;
        if (type == "MIFARE Ultralight C") return 48;
        if (type == "NTAG203") return 42;
        if (type == "NTAG213") return 45;
        if (type == "NTAG215") return 135;
        if (type == "NTAG216") return 231;
        return 16; // Mifare Ultralight: 16 pages minimum
    }

    // Read all pages of a NTAG/Mifare Ultralight card via InDataExchange.
    // Target must already be selected (in_list_passive_target_iso14443a returned true).
    // pages_out: optional per-page 4-byte vectors (may be nullptr).
    // type_out:  optional chip type string ("NTAG213", "Ultralight", etc.).
    bool ntag_read_all_pages(std::vector<std::vector<uint8_t>> *pages_out,
                             std::string *type_out,
                             std::string *error,
                             std::function<void(const std::string &)> on_line = nullptr)
    {
        auto emit = [&](const std::string &s) { if (on_line) on_line(s); };

        // Identify chip via GET_VERSION + GroveNFC-style page probes.
        std::string type = classify_type2_tag();
        if (type == "NTAG") type = "NTAG213"; // conservative Type2 default size
        if (type == "NTAG/Ultralight") type = "MIFARE Ultralight";
        if (type_out) *type_out = type;

        const int total_pages = ntag_page_count_for_type(type);
        {
            char buf[48];
            std::snprintf(buf, sizeof(buf), "> %s (%d pages)", type.c_str(), total_pages);
            emit(buf);
        }

        if (pages_out) pages_out->assign(total_pages, {});
        int ok = 0;

        for (int p = 0; p < total_pages; p += 4) {
            std::vector<uint8_t> chunk16;
            if (!type2_read_four_pages(static_cast<uint8_t>(p), &chunk16)) {
                char buf[24];
                std::snprintf(buf, sizeof(buf), "ERR page%02d", p);
                emit(buf);
                break;
            }
            for (int i = 0; i < 4 && p + i < total_pages; ++i) {
                std::vector<uint8_t> pg(chunk16.begin() + i * 4, chunk16.begin() + i * 4 + 4);
                if (pages_out && p + i < static_cast<int>(pages_out->size()))
                    (*pages_out)[p + i] = pg;
                ++ok;
                char buf[24];
                std::snprintf(buf, sizeof(buf), "%02d:%02X%02X%02X%02X",
                    p + i, pg[0], pg[1], pg[2], pg[3]);
                emit(buf);
            }
        }

        char result[40];
        std::snprintf(result, sizeof(result), "OK %d/%d pages read", ok, total_pages);
        emit(result);
        if (error && ok == 0) *error = "no pages readable";
        return ok > 0;
    }

    // ── ISO15693 data dump ───────────────────────────────────────────────────

    // Read all ISO15693 blocks via InDataExchange.
    // Target must already be selected (in_list_passive_target_iso15693 returned true).
    // Reads single blocks until failure (end of memory or command error).
    // blocks_out: optional per-block byte vectors (may be nullptr).
    bool iso15693_read_all_blocks(std::vector<std::vector<uint8_t>> *blocks_out,
                                  std::string *error,
                                  std::function<void(const std::string &)> on_line = nullptr)
    {
        auto emit = [&](const std::string &s) { if (on_line) on_line(s); };
        auto read_block = [&](uint8_t block, std::vector<uint8_t> *out) -> bool {
            // Match pn532-python: InDataExchange payload starts with cmd=0x20 (no explicit flags byte).
            // Some firmware variants still expect explicit flags=0x02, so keep it as fallback.
            if (in_data_exchange(0x01, {0x20, block}, out, nullptr) && !out->empty()) return true;
            if (in_data_exchange(0x01, {0x02, 0x20, block}, out, nullptr) && !out->empty()) return true;
            return false;
        };

        if (blocks_out) blocks_out->clear();
        int ok = 0;

        for (int b = 0; b < 256; ++b) {
            std::vector<uint8_t> resp;
            if (!read_block(static_cast<uint8_t>(b), &resp)) {
                break;
            }
            if (blocks_out) blocks_out->push_back(resp);
            ++ok;
            char buf[40];
            int pos = std::snprintf(buf, sizeof(buf), "%02d:", b);
            for (uint8_t byte : resp) {
                if (pos < static_cast<int>(sizeof(buf)) - 3)
                    pos += std::snprintf(buf + pos, sizeof(buf) - pos, "%02X", byte);
            }
            emit(buf);
        }

        char result[32];
        std::snprintf(result, sizeof(result), "OK %d blocks", ok);
        emit(result);
        if (error && ok == 0) *error = "no blocks readable";
        return ok > 0;
    }

private:
    static std::string byte_hex(uint8_t value)
    {
        char buffer[4];
        std::snprintf(buffer, sizeof(buffer), "%02X", value);
        return buffer;
    }

    static std::string to_hex(const uint8_t *data, size_t size)
    {
        std::string out;
        for (size_t i = 0; i < size; ++i) out += byte_hex(data[i]);
        return out;
    }

    static std::string bytes_to_hex(const std::vector<uint8_t> &data)
    {
        return to_hex(data.data(), data.size());
    }

    static std::string detect_mifare_classic(uint8_t sak, uint8_t uid_len)
    {
        switch (sak) {
        case 0x09: return "Mifare Classic Mini";
        case 0x08: return "Mifare Classic 1K";
        case 0x18: return "Mifare Classic 4K";
        case 0x28: return "Mifare Classic 1K (7-byte UID)";
        case 0x38: return "Mifare Classic 4K (7-byte UID)";
        case 0x00: return (uid_len == 7) ? "NTAG/Ultralight (7B)" : "ISO14443A Tag (SAK=00)";
        case 0x20: return "ISO14443-4 (DESFire)";
        default:   return "ISO14443A Tag";
        }
    }

    bool collect_response(std::vector<uint8_t> *rx, std::string *error)
    {
        rx->clear();
        uint8_t buffer[128];
        // 25 attempts × 100ms = 2500ms maximum, matching Python's read_until(max_sec=2.0).
        // macOS WCH CH340 driver needs continuous select() polling to deliver USB IN data.
        for (int attempt = 0; attempt < 25; ++attempt) {
            ssize_t got = transport_->read_bytes(buffer, sizeof(buffer), 100, error);
            if (got < 0) return false;
            if (got == 0) continue;
            rx->insert(rx->end(), buffer, buffer + got);
            if (Pn532FrameCodec::parse_first_frame(*rx, nullptr)) {
                return true;
            }
        }
        if (error) *error = "timeout waiting for PN532 response";
        return false;
    }

    INfcTransport *transport_ = nullptr;
    // Tracks whether Tg=1 is currently listed in the PN532.
    // InRelease is only sent when this is true; avoids a PN532 v1.6 firmware bug
    // where InRelease(Tg=0) with no targets causes a delayed D5 53 response
    // that poisons the next InListPassiveTarget's collect_response().
    bool target_listed_ = false;
};

} // namespace nfc_app