#pragma once

#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace nfc_app {

enum class ProtocolKind {
    Unknown,
    Iso14443A,
    Iso14443B,
    Iso15693,
    Felica,
    MifareClassic,
};

enum class TransportKind {
    Mock,
    UsbSerial,
    UartSerial,
    I2cBus,
    SpiBus,   // SPI NFC device (M5 NFC CAP)
};

// What kind of device was identified on a port
enum class DeviceKind {
    Unknown,       // port opened but no PN532 frame response
    NotConnected,  // port couldn't be opened
    PN532,         // standard NXP PN532 chip confirmed
    PN532Killer,   // PN532Killer firmware detected (vendor command responded)
    UHFReader,     // UHF RFID reader over serial protocol
    OtherSerial,   // port opened, non-PN532 data received
    GroveNFC,      // Grove NFC 2 at I2C 0x48 (register-based, emulation supported)
    NFCUnit,       // M5Stack NFC Unit at I2C 0x50 (read-only on Linux)
    ST25RNFC,      // M5 NFC CAP (ST25R3916 over SPI)
};

inline const char *to_string(DeviceKind value)
{
    switch (value) {
    case DeviceKind::PN532:       return "PN532";
    case DeviceKind::PN532Killer: return "PN532Killer";
    case DeviceKind::UHFReader:   return "UHFReader";
    case DeviceKind::Unknown:     return "No Response";
    case DeviceKind::NotConnected: return "Not Connected";
    case DeviceKind::OtherSerial: return "Unknown Device";
    case DeviceKind::GroveNFC:    return "GroveNFC";
    case DeviceKind::NFCUnit:     return "NFC Unit";
    case DeviceKind::ST25RNFC:    return "M5 NFC CAP";
    default:                      return "?";
    }
}

// UART port configuration (saved per port)
struct UartConfig {
    std::string device_path;      // e.g. /dev/ttyTHS1
    int         baud_rate = 115200;
    int         tx_pin    = -1;   // informational; -1 = unknown
    int         rx_pin    = -1;   // informational; -1 = unknown
};

// Result of probing one transport endpoint
struct DeviceProbeResult {
    std::string   path;
    TransportKind transport   = TransportKind::Mock;
    DeviceKind    device_kind = DeviceKind::Unknown;
    std::string   firmware;        // "PN532 v1.6"  or ""
    std::string   error;
    bool          probing    = false;
};

enum class AttackMethod {
    None,
    DefaultKeys,
    BasicAuthRead,
    Darkside,
    Hardnested,
};

enum class AttackStatus {
    Idle,
    Pending,
    Running,
    Success,
    Failed,
};

enum class MifareKeyType {
    KeyA,
    KeyB,
};

inline const char *to_string(ProtocolKind value)
{
    switch (value) {
    case ProtocolKind::Iso14443A: return "ISO14443A";
    case ProtocolKind::Iso14443B: return "ISO14443B";
    case ProtocolKind::Iso15693: return "ISO15693";
    case ProtocolKind::Felica: return "FELICA";
    case ProtocolKind::MifareClassic: return "MIFARE_CLASSIC";
    default: return "UNKNOWN";
    }
}

inline const char *to_string(TransportKind value)
{
    switch (value) {
    case TransportKind::UsbSerial:  return "USB";
    case TransportKind::UartSerial: return "UART";
    case TransportKind::I2cBus:     return "I2C";
    case TransportKind::SpiBus:     return "SPI";
    default: return "MOCK";
    }
}

inline const char *to_string(AttackMethod value)
{
    switch (value) {
    case AttackMethod::DefaultKeys: return "default_keys";
    case AttackMethod::BasicAuthRead: return "basic_auth_read";
    case AttackMethod::Darkside: return "darkside";
    case AttackMethod::Hardnested: return "hardnested";
    default: return "none";
    }
}

inline const char *to_string(AttackStatus value)
{
    switch (value) {
    case AttackStatus::Pending: return "pending";
    case AttackStatus::Running: return "running";
    case AttackStatus::Success: return "success";
    case AttackStatus::Failed: return "failed";
    default: return "idle";
    }
}

inline const char *to_string(MifareKeyType value)
{
    switch (value) {
    case MifareKeyType::KeyB: return "B";
    default: return "A";
    }
}

inline ProtocolKind protocol_from_string(const std::string &value)
{
    if (value == "ISO14443A") return ProtocolKind::Iso14443A;
    if (value == "ISO14443B") return ProtocolKind::Iso14443B;
    if (value == "ISO15693") return ProtocolKind::Iso15693;
    if (value == "FELICA") return ProtocolKind::Felica;
    if (value == "MIFARE_CLASSIC") return ProtocolKind::MifareClassic;
    return ProtocolKind::Unknown;
}

// PM3-compatible lowercase protocol keys
inline std::string protocol_to_pm3_key(ProtocolKind p)
{
    switch (p) {
    case ProtocolKind::Iso14443A:    return "iso14443a";
    case ProtocolKind::MifareClassic:return "mifareclassic";
    case ProtocolKind::Iso15693:     return "iso15693";
    default:                         return "unknown";
    }
}

inline ProtocolKind protocol_from_pm3_key(const std::string &value)
{
    if (value == "iso14443a")     return ProtocolKind::Iso14443A;
    if (value == "mifareclassic") return ProtocolKind::MifareClassic;
    if (value == "iso15693")      return ProtocolKind::Iso15693;
    return protocol_from_string(value);
}

inline TransportKind transport_from_string(const std::string &value)
{
    if (value == "USB")  return TransportKind::UsbSerial;
    if (value == "UART") return TransportKind::UartSerial;
    if (value == "I2C")  return TransportKind::I2cBus;
    if (value == "SPI")  return TransportKind::SpiBus;
    return TransportKind::Mock;
}

inline AttackMethod attack_method_from_string(const std::string &value)
{
    if (value == "default_keys") return AttackMethod::DefaultKeys;
    if (value == "basic_auth_read") return AttackMethod::BasicAuthRead;
    if (value == "darkside") return AttackMethod::Darkside;
    if (value == "hardnested") return AttackMethod::Hardnested;
    return AttackMethod::None;
}

inline AttackStatus attack_status_from_string(const std::string &value)
{
    if (value == "pending") return AttackStatus::Pending;
    if (value == "running") return AttackStatus::Running;
    if (value == "success") return AttackStatus::Success;
    if (value == "failed") return AttackStatus::Failed;
    return AttackStatus::Idle;
}

inline MifareKeyType mifare_key_type_from_string(const std::string &value)
{
    if (value == "B") return MifareKeyType::KeyB;
    return MifareKeyType::KeyA;
}

inline std::string iso8601_now()
{
    std::time_t now = std::time(nullptr);
    struct tm local_tm;
#if defined(_WIN32)
    localtime_s(&local_tm, &now);
#else
    localtime_r(&now, &local_tm);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &local_tm);
    return std::string(buffer);
}

struct AttackSummary {
    AttackMethod method = AttackMethod::None;
    AttackStatus status = AttackStatus::Idle;
    bool dump_obtained = false;
    std::string reason;
};

struct MifareClassicDump {
    int sector_count = 0;
    int block_count = 0;
    std::vector<std::string> blocks_hex;
    AttackSummary attack;
};

struct TagInfo {
    ProtocolKind protocol = ProtocolKind::Unknown;
    std::string tag_type = "Unknown";
    std::string uid;
    std::string magic_type;              // "Gen1A", "Gen3", "Gen4", or "" (Normal)
    std::map<std::string, std::string> identity_fields;
    std::vector<std::string> raw_data;
    std::vector<std::string> block_log;  // Gen1A block dump lines
};

struct EmulatorSlotRecord {
    int slot_index = 0;
    ProtocolKind protocol = ProtocolKind::Iso14443A;
    bool default_slot = false;
    bool default_protocol = false;
    std::string payload_record_id;
    std::vector<std::string> raw_data;
};

struct MifareKeyRecord {
    std::string label;
    std::string key_hex;
    MifareKeyType type = MifareKeyType::KeyA;
    bool enabled = true;
    std::string source = "manual";
    std::string created_at;
};

struct RecordMeta {
    int schema_version = 1;
    std::string schema_name = "m5cz.nfc.record";
    std::string record_id;
    std::string display_name;
    std::string created_at;
    std::string source;
    std::string notes;
    TransportKind transport = TransportKind::Mock;
    std::string transport_path;
    bool mock = false;
};

struct SavedRecord {
    RecordMeta meta;
    TagInfo tag;
    std::optional<MifareClassicDump> mifare_dump;
    std::optional<EmulatorSlotRecord> emulator_slot;
};

inline void to_json(nlohmann::json &j, const AttackSummary &value)
{
    j = nlohmann::json{
        {"method", to_string(value.method)},
        {"status", to_string(value.status)},
        {"dump_obtained", value.dump_obtained},
        {"reason", value.reason},
    };
}

inline void from_json(const nlohmann::json &j, AttackSummary &value)
{
    value.method = attack_method_from_string(j.value("method", "none"));
    value.status = attack_status_from_string(j.value("status", "idle"));
    value.dump_obtained = j.value("dump_obtained", false);
    value.reason = j.value("reason", "");
}

inline void to_json(nlohmann::json &j, const MifareClassicDump &value)
{
    j = nlohmann::json{
        {"sector_count", value.sector_count},
        {"block_count", value.block_count},
        {"blocks_hex", value.blocks_hex},
        {"attack_summary", value.attack},
    };
}

inline void from_json(const nlohmann::json &j, MifareClassicDump &value)
{
    value.sector_count = j.value("sector_count", 0);
    value.block_count = j.value("block_count", 0);
    value.blocks_hex = j.value("blocks_hex", std::vector<std::string>{});
    value.attack = j.value("attack_summary", AttackSummary{});
}

inline void to_json(nlohmann::json &j, const TagInfo &value)
{
    // Serialize as PM3-compatible blocks + card format.
    // Build card info from tag fields.
    j["card"]["protocol"] = protocol_to_pm3_key(value.protocol);
    j["card"]["uid"] = value.uid;
    if (!value.tag_type.empty())
        j["card"]["type"] = value.tag_type;
    for (const auto &kv : value.identity_fields) {
        if (!kv.second.empty())
            j["card"][kv.first] = kv.second;
    }

    // Serialize raw_data as blocks map with zero-padded keys for correct
    // numeric sort order (00,01,...09,10,11... instead of 0,1,10,11,2,3...).
    for (size_t i = 0; i < value.raw_data.size(); ++i) {
        const std::string &line = value.raw_data[i];
        std::string key;
        std::string hex;
        size_t colon = line.find(':');
        if (colon != std::string::npos && colon + 1 < line.size()) {
            key = line.substr(0, colon);
            // Strip leading zeros but ensure at least "0" for key lookup
            while (key.size() > 1 && key[0] == '0') key.erase(0, 1);
            hex = line.substr(colon + 1);
        } else {
            key = std::to_string(i);
            hex = line;
        }
        // Pad to 2-digit key for correct alphabetical=numerical sort
        if (key.size() < 2) key = "0" + key;
        std::string pure;
        for (char c : hex)
            if (std::isxdigit(static_cast<unsigned char>(c)))
                pure += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        if (!pure.empty())
            j["blocks"][key] = pure;
    }
    if (!j.contains("blocks")) j["blocks"] = nlohmann::json::object();
}

inline void from_json(const nlohmann::json &j, TagInfo &value)
{
    // Read card info
    if (j.contains("card")) {
        const auto &card = j["card"];
        value.protocol = protocol_from_pm3_key(card.value("protocol", "UNKNOWN"));
        value.uid = card.value("uid", "");
        value.tag_type = card.value("type", card.value("tag_type", ""));
        for (auto it = card.begin(); it != card.end(); ++it) {
            if (it.key() == "protocol" || it.key() == "uid" || it.key() == "type" || it.key() == "tag_type")
                continue;
            if (it.value().is_string())
                value.identity_fields[it.key()] = it.value().get<std::string>();
        }
    } else {
        // Legacy backward compat
        value.protocol = protocol_from_string(j.value("protocol", "UNKNOWN"));
        value.tag_type = j.value("tag_type", "Unknown");
        value.uid = j.value("uid", "");
        value.identity_fields = j.value("identity_fields", std::map<std::string, std::string>{});
    }

    // Read blocks → convert to "NN: HEX..." lines for raw_data
    value.raw_data.clear();
    if (j.contains("blocks") && j["blocks"].is_object()) {
        for (auto it = j["blocks"].begin(); it != j["blocks"].end(); ++it) {
            std::string pure;
            if (it.value().is_string()) {
                for (char c : it.value().get<std::string>())
                    if (std::isxdigit(static_cast<unsigned char>(c)))
                        pure += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            }
            if (!pure.empty()) {
                // Strip leading zeros from key (e.g. "00" → "0", "01" → "1")
                std::string key = it.key();
                while (key.size() > 1 && key[0] == '0') key.erase(0, 1);
                value.raw_data.push_back(key + ":" + pure);
            }
        }
    }

    // Legacy fallback: if no blocks, try old raw_data array
    if (value.raw_data.empty() && j.contains("raw_data") && j["raw_data"].is_array()) {
        value.raw_data = j.value("raw_data", std::vector<std::string>{});
    }
}

inline void to_json(nlohmann::json &j, const EmulatorSlotRecord &value)
{
    j = nlohmann::json{
        {"slot_index", value.slot_index},
        {"protocol", to_string(value.protocol)},
        {"default_slot", value.default_slot},
        {"default_protocol", value.default_protocol},
        {"payload_record_id", value.payload_record_id},
        {"raw_data", value.raw_data},
    };
}

inline void from_json(const nlohmann::json &j, EmulatorSlotRecord &value)
{
    value.slot_index = j.value("slot_index", 0);
    value.protocol = protocol_from_string(j.value("protocol", "ISO14443A"));
    value.default_slot = j.value("default_slot", false);
    value.default_protocol = j.value("default_protocol", false);
    value.payload_record_id = j.value("payload_record_id", "");
    value.raw_data = j.value("raw_data", std::vector<std::string>{});
}

inline void to_json(nlohmann::json &j, const MifareKeyRecord &value)
{
    j = nlohmann::json{
        {"label", value.label},
        {"key_hex", value.key_hex},
        {"type", to_string(value.type)},
        {"enabled", value.enabled},
        {"source", value.source},
        {"created_at", value.created_at},
    };
}

inline void from_json(const nlohmann::json &j, MifareKeyRecord &value)
{
    value.label = j.value("label", "");
    value.key_hex = j.value("key_hex", "");
    value.type = mifare_key_type_from_string(j.value("type", "A"));
    value.enabled = j.value("enabled", true);
    value.source = j.value("source", "manual");
    value.created_at = j.value("created_at", "");
}

inline void to_json(nlohmann::json &j, const RecordMeta &value)
{
    j = nlohmann::json{
        {"schema_version", value.schema_version},
        {"schema_name", value.schema_name},
        {"record_id", value.record_id},
        {"display_name", value.display_name},
        {"created_at", value.created_at},
        {"source", value.source},
        {"notes", value.notes},
        {"transport", to_string(value.transport)},
        {"transport_path", value.transport_path},
        {"mock", value.mock},
    };
}

inline void from_json(const nlohmann::json &j, RecordMeta &value)
{
    value.schema_version = j.value("schema_version", 1);
    value.schema_name = j.value("schema_name", "m5cz.nfc.record");
    value.record_id = j.value("record_id", "");
    value.display_name = j.value("display_name", "");
    value.created_at = j.value("created_at", "");
    value.source = j.value("source", "");
    value.notes = j.value("notes", "");
    value.transport = transport_from_string(j.value("transport", "MOCK"));
    value.transport_path = j.value("transport_path", "");
    value.mock = j.value("mock", false);
}

inline void to_json(nlohmann::json &j, const SavedRecord &value)
{
    j = nlohmann::json{
        {"meta", value.meta},
        {"tag", value.tag},
        {"emulator_slot", value.emulator_slot ? nlohmann::json(*value.emulator_slot) : nlohmann::json()},
    };
}

inline void from_json(const nlohmann::json &j, SavedRecord &value)
{
    value.meta = j.value("meta", RecordMeta{});
    value.tag = j.value("tag", TagInfo{});

    if (j.contains("mifare_classic_dump") && !j["mifare_classic_dump"].is_null()) {
        value.mifare_dump = j["mifare_classic_dump"].get<MifareClassicDump>();
    } else {
        value.mifare_dump.reset();
    }

    if (j.contains("emulator_slot") && !j["emulator_slot"].is_null()) {
        value.emulator_slot = j["emulator_slot"].get<EmulatorSlotRecord>();
    } else {
        value.emulator_slot.reset();
    }
}

inline std::string make_record_id(const TagInfo &tag)
{
    const std::string uid = tag.uid.empty() ? "unknown" : tag.uid;
    return std::string(to_string(tag.protocol)) + "_" + uid + "_" + iso8601_now();
}

inline std::string make_record_name(const TagInfo &tag)
{
    std::string prefix;
    switch (tag.protocol) {
    case ProtocolKind::MifareClassic: prefix = "MFC_"; break;
    case ProtocolKind::Iso14443A:     prefix = "N213_"; break;
    case ProtocolKind::Iso15693:      prefix = "ISO15_"; break;
    default:                          prefix = "Tag_"; break;
    }
    if (!tag.uid.empty()) {
        return prefix + tag.uid;
    }
    return prefix + "unknown";
}

} // namespace nfc_app