#pragma once

#include "nfc_models.hpp"
#include "hal/hal_paths.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fstream>
#include <set>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace nfc_app {

class NfcStorage {
public:
    static std::string env_path(const char *name)
    {
        if (!name || !name[0]) return "";
        const char *v = std::getenv(name);
        if (!v || !v[0]) return "";
        return std::string(v);
    }

    std::string root_dir() const
    {
        const std::string overridden = env_path("M5CZ_NFC_ROOT_DIR");
        if (!overridden.empty()) return overridden;
        const char *home = std::getenv("HOME");
        if (home && home[0]) return std::string(home) + "/rfid";
        return std::string(hal_path_data_dir()) + "/nfc_data";
    }

    std::string records_dir() const
    {
        const std::string overridden = env_path("M5CZ_NFC_RECORDS_DIR");
        if (!overridden.empty()) return overridden;
        return root_dir() + "/dumps";
    }

    std::string emulator_config_path() const
    {
        return emulator_json_dir() + "/emulator_config.json";
    }

    std::string emulator_config_legacy_path() const
    {
        return root_dir() + "/emulator_config.json";
    }

    std::string mifare_keys_path() const
    {
        return root_dir() + "/mifare_keys.json";
    }

    std::string uart_config_path() const
    {
        return root_dir() + "/uart_config.json";
    }

    std::string last_transport_kind_path() const
    {
        return root_dir() + "/last_transport.json";
    }

    // Save both kind and endpoint path so SPI/I2C paths survive restarts.
    bool save_last_endpoint(TransportKind kind, const std::string &path) const
    {
        if (!ensure_layout()) return false;
        std::ofstream out(last_transport_kind_path().c_str(), std::ios::out | std::ios::trunc);
        if (!out.is_open()) return false;
        nlohmann::json j;
        j["kind"] = to_string(kind);
        j["path"] = path;
        out << j.dump(2);
        return out.good();
    }

    bool save_last_transport_kind(TransportKind kind) const
    {
        return save_last_endpoint(kind, "");
    }

    TransportKind load_last_transport_kind() const
    {
        std::ifstream in(last_transport_kind_path().c_str());
        if (!in.is_open()) return TransportKind::UsbSerial; // default
        try {
            nlohmann::json j;
            in >> j;
            if (j.contains("kind") && j["kind"].is_string())
                return transport_from_string(j["kind"].get<std::string>());
        } catch (...) {}
        return TransportKind::UsbSerial;
    }

    std::string load_last_endpoint_path() const
    {
        std::ifstream in(last_transport_kind_path().c_str());
        if (!in.is_open()) return "";
        try {
            nlohmann::json j;
            in >> j;
            if (j.contains("path") && j["path"].is_string())
                return j["path"].get<std::string>();
        } catch (...) {}
        return "";
    }

    bool save_uart_config(const UartConfig &cfg) const
    {
        if (!ensure_layout()) return false;
        const std::string path = uart_config_path();
        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
        if (!out.is_open()) return false;
        nlohmann::json j;
        j["device_path"] = cfg.device_path;
        j["baud_rate"]   = cfg.baud_rate;
        j["tx_pin"]      = cfg.tx_pin;
        j["rx_pin"]      = cfg.rx_pin;
        out << j.dump(2);
        return out.good();
    }

    UartConfig load_uart_config() const
    {
        UartConfig cfg;
        const std::string path = uart_config_path();
        std::ifstream in(path.c_str());
        if (!in.is_open()) return cfg;
        try {
            nlohmann::json j;
            in >> j;
            if (j.contains("device_path") && j["device_path"].is_string())
                cfg.device_path = j["device_path"].get<std::string>();
            if (j.contains("baud_rate") && j["baud_rate"].is_number())
                cfg.baud_rate = j["baud_rate"].get<int>();
            if (j.contains("tx_pin") && j["tx_pin"].is_number())
                cfg.tx_pin = j["tx_pin"].get<int>();
            if (j.contains("rx_pin") && j["rx_pin"].is_number())
                cfg.rx_pin = j["rx_pin"].get<int>();
        } catch (...) {}
        return cfg;
    }

    bool ensure_layout() const
    {
        return ensure_dir(root_dir()) &&
               ensure_dir_recursive(records_dir()) &&
               ensure_dir_recursive(emulator_json_dir());
    }

    bool save_record(const SavedRecord &record, std::string *error = nullptr) const
    {
        if (!ensure_layout()) {
            if (error) *error = "Failed to create RFID storage directory";
            return false;
        }

        const std::string path = records_dir() + "/" + sanitize_filename(record.meta.record_id) + ".json";
        std::ofstream output(path.c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) {
            if (error) *error = "Failed to open record for write";
            return false;
        }

        nlohmann::json document = record;
        output << document.dump(2);
        return true;
    }

    bool delete_record(const std::string &record_id, std::string *error = nullptr) const
    {
        const std::string path = records_dir() + "/" + sanitize_filename(record_id) + ".json";
        if (::remove(path.c_str()) != 0) {
            if (error) *error = "Delete failed: " + std::string(strerror(errno));
            return false;
        }
        return true;
    }

    std::vector<SavedRecord> list_records() const
    {
        std::vector<SavedRecord> result;
        if (!ensure_layout()) return result;

        DIR *dir = opendir(records_dir().c_str());
        if (!dir) return result;

        struct dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            const char *name = entry->d_name;
            if (name[0] == '.') continue;
            const std::string filename(name);
            if (filename.size() < 6 || filename.substr(filename.size() - 5) != ".json") continue;
            SavedRecord record;
            if (load_record(records_dir() + "/" + filename, &record)) {
                result.push_back(record);
            }
        }
        closedir(dir);

        std::sort(result.begin(), result.end(), [](const SavedRecord &lhs, const SavedRecord &rhs) {
            return lhs.meta.created_at > rhs.meta.created_at;
        });
        return result;
    }

    bool load_record_by_id(const std::string &record_id, SavedRecord *record) const
    {
        return load_record(records_dir() + "/" + sanitize_filename(record_id) + ".json", record);
    }

    bool save_emulator_slots(const std::vector<EmulatorSlotRecord> &slots) const
    {
        if (!ensure_layout()) return false;
        std::ofstream output(emulator_config_path().c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) return false;
        nlohmann::json document;
        document["schema_version"] = 1;
        document["schema_name"] = "m5cz.nfc.emulator_config";
        document["slots"] = slots;
        output << document.dump(2);
        return true;
    }

    bool save_emulator_slots_by_protocol(const std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> &slots_by_protocol) const
    {
        if (!ensure_layout()) return false;
        std::ofstream output(emulator_config_path().c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) return false;
        nlohmann::json document;
        document["schema_version"] = 2;
        document["schema_name"] = "m5cz.nfc.emulator_config";
        nlohmann::json groups = nlohmann::json::object();
        for (const auto &protocol : supported_emulator_protocols()) {
            const auto it = slots_by_protocol.find(protocol);
            groups[protocol_storage_key(protocol)] = (it == slots_by_protocol.end())
                ? std::vector<EmulatorSlotRecord>{}
                : it->second;
        }
        document["slots_by_protocol"] = groups;
        output << document.dump(2);
        return true;
    }

    bool save_mifare_keys(const std::vector<MifareKeyRecord> &keys) const
    {
        if (!ensure_layout()) return false;
        std::ofstream output(mifare_keys_path().c_str(), std::ios::out | std::ios::trunc);
        if (!output.is_open()) return false;
        nlohmann::json document;
        document["schema_version"] = 1;
        document["schema_name"] = "m5cz.nfc.mifare_keys";
        document["keys"] = keys;
        output << document.dump(2);
        return true;
    }

    std::vector<EmulatorSlotRecord> load_emulator_slots() const
    {
        std::vector<EmulatorSlotRecord> slots;
        if (!ensure_layout()) return slots;

        migrate_legacy_emulator_config();

        std::ifstream input(emulator_config_path().c_str());
        if (!input.is_open()) {
            return default_slots();
        }

        try {
            nlohmann::json document;
            input >> document;
            slots = document.value("slots", default_slots());
        } catch (...) {
            slots = default_slots();
        }

        if (slots.empty()) slots = default_slots();
        return slots;
    }

    std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> load_emulator_slots_by_protocol() const
    {
        auto groups = default_slots_by_protocol();
        if (!ensure_layout()) return groups;

        migrate_legacy_emulator_config();

        std::ifstream input(emulator_config_path().c_str());
        if (!input.is_open()) {
            return groups;
        }

        try {
            nlohmann::json document;
            input >> document;
            if (document.contains("slots_by_protocol") && document["slots_by_protocol"].is_object()) {
                const auto &node = document["slots_by_protocol"];
                for (const auto &protocol : supported_emulator_protocols()) {
                    const auto key = protocol_storage_key(protocol);
                    if (node.contains(key) && node[key].is_array()) {
                        groups[protocol] = node[key].get<std::vector<EmulatorSlotRecord>>();
                    }
                }
            } else {
                const auto flat = document.value("slots", default_slots());
                groups.clear();
                for (const auto &protocol : supported_emulator_protocols()) groups[protocol] = {};
                for (auto slot : flat) {
                    if (groups.find(slot.protocol) == groups.end()) slot.protocol = ProtocolKind::Iso14443A;
                    groups[slot.protocol].push_back(slot);
                }
            }
        } catch (...) {
            groups = default_slots_by_protocol();
        }

        for (const auto &protocol : supported_emulator_protocols()) {
            auto &slots = groups[protocol];
            for (size_t i = 0; i < slots.size(); ++i) {
                slots[i].slot_index = static_cast<int>(i);
                slots[i].protocol = protocol;
            }
        }
        return groups;
    }

    std::vector<MifareKeyRecord> load_mifare_keys() const
    {
        std::vector<MifareKeyRecord> keys;
        if (!ensure_layout()) return keys;

        std::ifstream input(mifare_keys_path().c_str());
        if (!input.is_open()) {
            return keys;
        }

        try {
            nlohmann::json document;
            input >> document;
            keys = document.value("keys", std::vector<MifareKeyRecord>{});
        } catch (...) {
            keys.clear();
        }
        return keys;
    }

    static std::vector<EmulatorSlotRecord> default_slots()
    {
        EmulatorSlotRecord s0;
        s0.slot_index    = 0;
        s0.protocol      = ProtocolKind::MifareClassic;
        s0.default_slot  = true;
        s0.default_protocol = true;
        s0.payload_record_id = "DEADBEEF";
        s0.raw_data = { "04: DEAD BEEF 11 22 33 44",
                        "Sector0: 00 00 00 00 00 00 FF 07 80 69 FF FF FF FF FF FF",
                        "KeyA:FFFFFFFFFFFF  KeyB:FFFFFFFFFFFF" };

        EmulatorSlotRecord s1;
        s1.slot_index    = 1;
        s1.protocol      = ProtocolKind::Iso14443A;
        s1.default_slot  = false;
        s1.default_protocol = false;
        s1.payload_record_id = "04A1B2C3";
        s1.raw_data = { "UID: 04 A1 B2 C3", "ATQA:0344  SAK:20  NFC-A T4T",
                        "AID:D2760000850101  App:NDEF" };

        EmulatorSlotRecord s2;
        s2.slot_index    = 2;
        s2.protocol      = ProtocolKind::Iso15693;
        s2.default_slot  = false;
        s2.default_protocol = false;
        s2.payload_record_id = "E0040100112233AA";
        s2.raw_data = { "UID(rev): E0 04 01 00 11 22 33 AA",
                        "DSFID:00  AFI:00  Blocks:32x4B",
                        "IC:TI Tag-it HF-I Plus" };

        return { s0, s1, s2 };
    }

    static std::vector<MifareKeyRecord> default_mifare_keys()
    {
        return {
            {"Factory A", "FFFFFFFFFFFF", MifareKeyType::KeyA, true, "default", "2026-05-01T00:00:00"},
            {"Factory B", "FFFFFFFFFFFF", MifareKeyType::KeyB, true, "default", "2026-05-01T00:00:00"},
            {"MAD Key", "A0A1A2A3A4A5", MifareKeyType::KeyA, true, "default", "2026-05-01T00:00:00"},
            {"NFC Forum", "D3F7D3F7D3F7", MifareKeyType::KeyA, true, "default", "2026-05-01T00:00:00"},
        };
    }

private:
    static std::vector<ProtocolKind> supported_emulator_protocols()
    {
        return {
            ProtocolKind::Iso14443A,
            ProtocolKind::Iso14443B,
            ProtocolKind::Iso15693,
            ProtocolKind::MifareClassic,
        };
    }

    static std::string protocol_storage_key(ProtocolKind protocol)
    {
        switch (protocol) {
        case ProtocolKind::Iso14443A: return "iso14443a";
        case ProtocolKind::Iso14443B: return "iso14443b";
        case ProtocolKind::Iso15693: return "iso15693";
        case ProtocolKind::MifareClassic: return "mifare_classic";
        default: return "unknown";
        }
    }

    static std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> default_slots_by_protocol()
    {
        std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> groups;
        const auto base = default_slots();
        for (const auto &protocol : supported_emulator_protocols()) {
            groups[protocol] = {};
            for (auto slot : base) {
                if (slot.protocol == protocol) groups[protocol].push_back(slot);
            }
            for (size_t i = 0; i < groups[protocol].size(); ++i) {
                groups[protocol][i].slot_index = static_cast<int>(i);
                groups[protocol][i].protocol = protocol;
            }
        }
        return groups;
    }

    // ── Key dictionary file support ──────────────────────────────────────────

public:
    std::string keys_dict_dir() const
    {
        const std::string overridden = env_path("M5CZ_NFC_KEYS_DIR");
        if (!overridden.empty()) return overridden;
        return std::string(hal_path_nfc_keys_dir());
    }

    bool ensure_keys_dir() const
    {
        return ensure_dir_recursive(keys_dict_dir());
    }

    static std::string trim_copy(const std::string &value)
    {
        size_t start = 0;
        size_t end = value.size();
        while (start < end && std::isspace(static_cast<unsigned char>(value[start]))) ++start;
        while (end > start && std::isspace(static_cast<unsigned char>(value[end - 1]))) --end;
        return value.substr(start, end - start);
    }

    static bool parse_12hex_line(const std::string &line, std::string *normalized)
    {
        const std::string trimmed = trim_copy(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') return false;
        if (trimmed.size() != 12) return false;
        std::string key;
        key.reserve(12);
        for (char c : trimmed) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
            key.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
        if (normalized) *normalized = key;
        return true;
    }

    static std::vector<std::string> default_key_dict_lines()
    {
        return {
            "FFFFFFFFFFFF",
            "000000000000",
            "A0A1A2A3A4A5",
            "A5A4A3A2A1A0",
            "89ECA97F8C2A",
            "5C8FF9990DA2",
            "75CCB59C9BED",
            "D01AFEEB890A",
            "4B791BEA7BCC",
            "2612C6DE84CA",
            "707B11FC1481",
            "03F9067646AE",
            "2352C5B56D85",
            "B0B1B2B3B4B5",
            "C0C1C2C3C4C5",
            "D0D1D2D3D4D5",
            "AABBCCDDEEFF",
            "4D3A99C351DD",
            "1A982C7E459A",
            "FAFAFAFAFAFA",
            "FBFBFBFBFBFB",
            "D3F7D3F7D3F7",
        };
    }

    bool ensure_default_key_file() const
    {
        if (!ensure_keys_dir()) return false;
        const std::string path = keys_dict_dir() + "/mfc_default.dic";
        {
            std::ifstream in(path.c_str());
            if (in.is_open()) return true;
        }
        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
        if (!out.is_open()) return false;
        out << "# Auto-generated default MIFARE keys\n";
        for (const auto &line : default_key_dict_lines()) {
            std::string key;
            if (parse_12hex_line(line, &key)) out << key << "\n";
        }
        return out.good();
    }

    // List key files in ~/rfid/keys, preferring mfc*.dic files.
    std::vector<std::string> list_key_files() const
    {
        std::vector<std::string> all_dic;
        std::vector<std::string> mfc_dic;
        ensure_keys_dir();
        DIR *dir = opendir(keys_dict_dir().c_str());
        if (!dir) return all_dic;
        struct dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            const char *name = entry->d_name;
            if (name[0] == '.') continue;
            const std::string fn(name);
            if (fn.size() <= 4) continue;

            std::string lower = fn;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                           [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            if (lower.substr(lower.size() - 4) != ".dic") continue;

            all_dic.push_back(fn);
            if (lower.find("mfc") != std::string::npos) {
                mfc_dic.push_back(fn);
            }
        }
        closedir(dir);
        if (all_dic.empty() && ensure_default_key_file()) {
            all_dic.push_back("mfc_default.dic");
            mfc_dic.push_back("mfc_default.dic");
        }

        std::vector<std::string> result = mfc_dic.empty() ? all_dic : mfc_dic;
        std::sort(result.begin(), result.end());
        return result;
    }

    // Load hex keys (one 12-char key per line) from a .dic/.txt file.
    std::vector<std::string> load_key_file(const std::string &filename) const
    {
        std::vector<std::string> keys;
        const std::string path = keys_dict_dir() + "/" + filename;
        std::ifstream f(path.c_str());
        if (!f.is_open()) return keys;
        std::string line;
        while (std::getline(f, line)) {
            std::string key;
            if (parse_12hex_line(line, &key)) keys.push_back(key);
        }
        return keys;
    }

    // Save hex keys (one 12-char key per line) to a .dic/.txt file.
    bool save_key_file(const std::string &filename,
                       const std::vector<std::string> &keys,
                       std::string *error = nullptr) const
    {
        ensure_keys_dir();
        if (filename.empty()) {
            if (error) *error = "Missing filename";
            return false;
        }
        const std::string path = keys_dict_dir() + "/" + filename;
        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
        if (!out.is_open()) {
            if (error) *error = "Cannot write key file: " + path;
            return false;
        }
        for (const auto &raw : keys) {
            std::string key;
            if (parse_12hex_line(raw, &key)) out << key << "\n";
        }
        return true;
    }

    // Extract MIFARE Classic sector-trailer keys from raw dump blocks and save to
    // <keys_dict_dir>/<uid>.dic.  raw_lines: hex strings, one per block (64 blocks for 1K).
    bool save_uid_key_file(const std::string &uid, const std::vector<std::string> &raw_lines,
                           std::string *error = nullptr) const
    {
        ensure_keys_dir();
        std::set<std::string> seen;
        std::vector<std::string> keys;
        const int num_sectors = static_cast<int>(raw_lines.size()) / 4;
        for (int sec = 0; sec < num_sectors; ++sec) {
            const int trailer_idx = sec * 4 + 3;
            if (trailer_idx >= static_cast<int>(raw_lines.size())) break;
            // raw_lines[trailer_idx] should be 32 hex chars = 16 bytes
            std::string hex;
            for (char c : raw_lines[static_cast<size_t>(trailer_idx)])
                if (std::isxdigit(static_cast<unsigned char>(c))) hex += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (hex.size() < 32) continue;
            // key A: bytes 0-5 (chars 0-11), key B: bytes 10-15 (chars 20-31)
            const std::string keyA = hex.substr(0, 12);
            const std::string keyB = hex.substr(20, 12);
            for (const auto &k : {keyA, keyB}) {
                if (k == "FFFFFFFFFFFF" || k == "000000000000") continue; // skip common placeholders
                if (seen.insert(k).second) keys.push_back(k);
            }
        }
        if (keys.empty()) {
            if (error) *error = "No usable keys found in dump";
            return false;
        }
        const std::string uid_clean = sanitize_filename(uid);
        const std::string path = keys_dict_dir() + "/" + uid_clean + ".dic";
        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
        if (!out.is_open()) {
            if (error) *error = "Cannot write key file: " + path;
            return false;
        }
        out << "# MIFARE Classic keys extracted from UID " << uid << "\n";
        for (const auto &k : keys) out << k << "\n";
        return true;
    }

    static bool ensure_dir(const std::string &path)
    {
        if (path.empty()) return false;
        if (::mkdir(path.c_str(), 0755) == 0) return true;
        return errno == EEXIST;
    }

    static bool ensure_dir_recursive(const std::string &path)
    {
        if (path.empty()) return false;
        if (::mkdir(path.c_str(), 0755) == 0 || errno == EEXIST) return true;
        const auto sep = path.rfind('/');
        if (sep == std::string::npos || sep == 0) return false;
        if (!ensure_dir_recursive(path.substr(0, sep))) return false;
        return ::mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
    }

    static std::string sanitize_filename(const std::string &value)
    {
        std::string result = value;
        for (char &ch : result) {
            if (!(std::isalnum(static_cast<unsigned char>(ch)) || ch == '_' || ch == '-')) {
                ch = '_';
            }
        }
        return result;
    }

    static bool load_record(const std::string &path, SavedRecord *record)
    {
        if (!record) return false;
        std::ifstream input(path.c_str());
        if (!input.is_open()) return false;

        try {
            nlohmann::json document;
            input >> document;
            *record = document.get<SavedRecord>();
            return true;
        } catch (...) {
            return false;
        }
    }

    // Emulator file stem: user-facing short names matching the filesystem.
    // MFC: mfc1k, NTAG: ntag213, ISO15693: iso15693
    static std::string emulator_file_stem(ProtocolKind protocol)
    {
        switch (protocol) {
        case ProtocolKind::Iso14443A: return "ntag213";
        case ProtocolKind::MifareClassic: return "mfc1k";
        case ProtocolKind::Iso15693: return "iso15693";
        default: return "unknown";
        }
    }

    // Write record hex data as structured JSON to emulator file.
    // Used by the "Emulate" flow: Saved record → write to {p}_0.json.
    void save_emulator_json_from_record(ProtocolKind protocol, const SavedRecord &record) const
    {
        const std::string path = emulator_json_path(protocol);
        ensure_dir(emulator_json_dir());

        nlohmann::json j;
        if (protocol == ProtocolKind::MifareClassic) {
            j["filetype"] = "mfc";
            std::string uid;
            for (char c : record.tag.uid)
                if (std::isxdigit((unsigned char)c)) uid += (char)std::toupper((unsigned char)c);
            j["card"]["uid"] = uid;
            j["card"]["atqa"] = "0400";
            j["card"]["sak"] = "08";
            j["card"]["protocol"] = "mifareclassic";
        } else if (protocol == ProtocolKind::Iso14443A) {
            j["filetype"] = "ntag";
            std::string uid;
            for (char c : record.tag.uid)
                if (std::isxdigit((unsigned char)c)) uid += (char)std::toupper((unsigned char)c);
            j["card"]["uid"] = uid;
            j["card"]["version"] = "";
            j["card"]["protocol"] = "iso14443a";
        } else if (protocol == ProtocolKind::Iso15693) {
            j["filetype"] = "iso15";
            std::string uid;
            for (char c : record.tag.uid)
                if (std::isxdigit((unsigned char)c)) uid += (char)std::toupper((unsigned char)c);
            j["card"]["uid"] = uid;
            j["card"]["dsfid"] = "00";
            j["card"]["afi"] = "00";
            j["card"]["protocol"] = "iso15693";
        }

        for (size_t i = 0; i < record.tag.raw_data.size(); ++i) {
            std::string pure;
            const std::string &line = record.tag.raw_data[i];
            size_t colon = line.find(':');
            std::string hex = (colon != std::string::npos && colon + 1 < line.size())
                ? line.substr(colon + 1) : line;
            for (char c : hex) if (std::isxdigit((unsigned char)c)) pure += (char)std::toupper((unsigned char)c);
            if (!pure.empty()) j["blocks"][std::to_string(i)] = pure;
        }

        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
        if (out.is_open()) out << j.dump(2);
    }

    // Reset user JSON to default by copying from default/ directory.
    // Falls back to config/defaults/ if default/ file doesn't exist yet.
    bool reset_emulator_json(ProtocolKind protocol) const
    {
        const std::string user_path = emulator_json_path(protocol);
        const std::string default_path = emulator_json_default_path(protocol);
        ensure_dir(emulator_json_dir());
        ensure_dir(emulator_json_default_dir());

        // If default doesn't exist, populate from app-bundled config/defaults first
        if (::access(default_path.c_str(), F_OK) != 0) {
            std::string app_default_dir = std::string(hal_path_data_dir()) + "/config/defaults";
            std::string app_path = app_default_dir + "/" + emulator_file_stem(protocol) + ".json";
            if (::access(app_path.c_str(), F_OK) == 0) {
                if (!copy_file(app_path, default_path)) return false;
            } else {
                return false;  // no default source available
            }
        }

        return copy_file(default_path, user_path);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Emulator JSON directory — structured per-protocol dump files used by the UI.
    // Runtime path: $HOME/rfid/emulator/{protocol_key}_0.json
    // Defaults path: $HOME/rfid/emulator/default/{protocol_key}_0.json
    //                  (populated by deploy script from config/defaults/)
    // ═══════════════════════════════════════════════════════════════════════════
    std::string emulator_json_dir() const
    {
        const std::string overridden = env_path("M5CZ_NFC_EMULATOR_DIR");
        if (!overridden.empty()) return overridden;
        const char *home = std::getenv("HOME");
        return (home ? std::string(home) : "/home/pi") + "/rfid/emulator";
    }

    std::string emulator_json_default_dir() const
    {
        return emulator_json_dir() + "/default";
    }

    std::string emulator_json_path(ProtocolKind protocol) const
    {
        ensure_dir(emulator_json_dir());
        return emulator_json_dir() + "/" + emulator_file_stem(protocol) + "_0.json";
    }

    std::string emulator_json_default_path(ProtocolKind protocol) const
    {
        ensure_dir(emulator_json_default_dir());
        // Note: default files are named without _0 suffix (e.g. mfc1k.json)
        return emulator_json_default_dir() + "/" + emulator_file_stem(protocol) + ".json";
    }

    // Ensure user JSONs exist: if {p}_0.json missing, copy from default/
    void ensure_emulator_jsons() const
    {
        ensure_dir(emulator_json_dir());
        ensure_dir(emulator_json_default_dir());

        for (auto protocol : {ProtocolKind::Iso14443A, ProtocolKind::MifareClassic, ProtocolKind::Iso15693}) {
            const std::string user_path = emulator_json_path(protocol);
            if (::access(user_path.c_str(), F_OK) == 0) continue;  // already exists

            // Try default/ first, then app-bundled config/defaults/
            const std::string default_path = emulator_json_default_path(protocol);
            if (::access(default_path.c_str(), F_OK) == 0) {
                // Copy default → user
                copy_file(default_path, user_path);
                continue;
            }

            // Fallback: try app-bundled config/defaults/ directory
            std::string app_default_dir = std::string(hal_path_data_dir()) + "/config/defaults";
            std::string app_path = app_default_dir + "/" + emulator_file_stem(protocol) + ".json";
            if (::access(app_path.c_str(), F_OK) == 0) {
                // Copy from app bundle to user emulator dir
                copy_file(app_path, user_path);
                // Also populate default/ for future
                copy_file(app_path, default_path);
            }
        }
    }

private:
    static bool copy_file(const std::string &src, const std::string &dst)
    {
        std::ifstream in(src.c_str(), std::ios::binary);
        if (!in.is_open()) return false;
        std::ofstream out(dst.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
        if (!out.is_open()) return false;
        out << in.rdbuf();
        return out.good();
    }

    // ── Persistent operation log (debugging / audit trail) ────────────────────
public:
    std::string op_log_path() const
    {
        return root_dir() + "/oplog.txt";
    }

    void append_op_log(const std::string &line) const
    {
        ensure_layout();
        std::ofstream out(op_log_path().c_str(), std::ios::out | std::ios::app);
        if (!out.is_open()) return;
        auto now = std::chrono::system_clock::now();
        auto tt = std::chrono::system_clock::to_time_t(now);
        char ts[32];
        std::strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));
        out << ts << " " << line << "\n";
    }

    std::string emulator_defaults_dir() const
    {
        return emulator_json_default_dir();
    }

    std::string emulator_defaults_legacy_dir() const
    {
        return root_dir() + "/emulator_defaults";
    }

    // Create directory and write default dump files for all supported protocols
    // if they don't exist yet.  Called once on I2C device connect.
    void ensure_emulator_defaults() const
    {
        migrate_legacy_emulator_defaults();
        ensure_dir(emulator_defaults_dir());
        // NTAG213 default (already written if file doesn't exist)
        write_default_if_missing(ProtocolKind::Iso14443A, {
            0x04,0x31,0x1D,0xA0,0x01,0x17,0x45,0x03,0x50,0x48,0x00,0x00,
            0xE1,0x10,0x12,0x00,0x01,0x03,0xA0,0x0C,0x34,0x03,0x00,0xFE,
        });
        // MFC1K default
        write_default_if_missing(ProtocolKind::MifareClassic, {
            0x11,0x22,0x33,0x44,0x04,0x08,0x00,0x04,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x07,0x80,0x69,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x07,0x80,0x69,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        });
        // ISO15693 default
        write_default_if_missing(ProtocolKind::Iso15693, {
            0xC1,0xC6,0x02,0xB9,0x50,0x00,0x07,0xE0,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        });
    }

    void write_default_if_missing(ProtocolKind protocol, const std::vector<uint8_t> &data) const
    {
        const std::string path = emulator_default_path(protocol);
        if (::access(path.c_str(), F_OK) == 0) return; // already exists
        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
        if (!out.is_open()) return;
        nlohmann::json j;
        j["protocol"] = to_string(protocol);
        j["data_hex"] = bytes_to_hex_string(data);
        out << j.dump(2);
    }

    std::string emulator_default_path(ProtocolKind protocol) const
    {
        return emulator_json_default_path(protocol);
    }

    std::string emulator_default_legacy_path(ProtocolKind protocol) const
    {
        return emulator_defaults_legacy_dir() + "/" + protocol_storage_key(protocol) + ".json";
    }

public:
    bool save_emulator_default_dump(ProtocolKind protocol, const std::vector<uint8_t> &data) const
    {
        const std::string path = emulator_default_path(protocol);
        nlohmann::json j;
        std::ifstream in(path.c_str());
        if (in.is_open()) {
            try {
                in >> j;
            } catch (...) {
                j = nlohmann::json::object();
            }
        }
        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
        if (!out.is_open()) return false;
        j["protocol"] = to_string(protocol);
        j["data_hex"] = bytes_to_hex_string(data);
        out << j.dump(2);
        return out.good();
    }

    std::vector<uint8_t> load_emulator_default_dump(ProtocolKind protocol) const
    {
        // Backward compatibility: move legacy root/emulator_defaults/*.json on demand.
        const std::string current_path = emulator_default_path(protocol);
        if (::access(current_path.c_str(), F_OK) != 0) {
            const std::string legacy_path = emulator_default_legacy_path(protocol);
            if (::access(legacy_path.c_str(), F_OK) == 0) {
                ensure_dir_recursive(emulator_json_default_dir());
                copy_file(legacy_path, current_path);
            }
        }

        std::ifstream in(current_path.c_str());
        if (!in.is_open()) return {};
        try {
            nlohmann::json j;
            in >> j;
            if (j.contains("data_hex") && j["data_hex"].is_string())
                return hex_string_to_bytes(j["data_hex"].get<std::string>());

            if (j.contains("blocks") && j["blocks"].is_object()) {
                std::vector<std::pair<int, std::string>> blocks;
                for (auto it = j["blocks"].begin(); it != j["blocks"].end(); ++it) {
                    if (!it.value().is_string()) continue;
                    char *end = nullptr;
                    long idx = std::strtol(it.key().c_str(), &end, 10);
                    if (!end || *end != '\0' || idx < 0) continue;
                    std::string hex;
                    for (char c : it.value().get<std::string>()) {
                        if (std::isxdigit(static_cast<unsigned char>(c))) {
                            hex.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
                        }
                    }
                    if ((hex.size() % 2) != 0) hex.pop_back();
                    if (!hex.empty()) blocks.emplace_back(static_cast<int>(idx), std::move(hex));
                }
                std::sort(blocks.begin(), blocks.end(),
                          [](const std::pair<int, std::string> &a, const std::pair<int, std::string> &b) {
                              return a.first < b.first;
                          });
                std::vector<uint8_t> out;
                for (const auto &entry : blocks) {
                    auto chunk = hex_string_to_bytes(entry.second);
                    out.insert(out.end(), chunk.begin(), chunk.end());
                }
                return out;
            }
        } catch (...) {}
        return {};
    }

    void migrate_legacy_emulator_config() const
    {
        const std::string current = emulator_config_path();
        if (::access(current.c_str(), F_OK) == 0) return;

        const std::string legacy = emulator_config_legacy_path();
        if (::access(legacy.c_str(), F_OK) != 0) return;

        ensure_dir_recursive(emulator_json_dir());
        copy_file(legacy, current);
    }

    void migrate_legacy_emulator_defaults() const
    {
        for (auto protocol : {ProtocolKind::Iso14443A, ProtocolKind::MifareClassic, ProtocolKind::Iso15693}) {
            const std::string target = emulator_default_path(protocol);
            if (::access(target.c_str(), F_OK) == 0) continue;
            const std::string legacy = emulator_default_legacy_path(protocol);
            if (::access(legacy.c_str(), F_OK) != 0) continue;
            ensure_dir_recursive(emulator_json_default_dir());
            copy_file(legacy, target);
        }
    }

    static std::string bytes_to_hex_string(const std::vector<uint8_t> &data)
    {
        std::string out;
        out.reserve(data.size() * 2);
        for (uint8_t b : data) {
            char h[3];
            std::snprintf(h, sizeof(h), "%02X", b);
            out += h;
        }
        return out;
    }

    static std::vector<uint8_t> hex_string_to_bytes(const std::string &hex)
    {
        std::vector<uint8_t> out;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            char *end = nullptr;
            unsigned long val = std::strtoul(hex.substr(i, 2).c_str(), &end, 16);
            if (end && *end == '\0')
                out.push_back(static_cast<uint8_t>(val));
        }
        return out;
    }
};

} // namespace nfc_app