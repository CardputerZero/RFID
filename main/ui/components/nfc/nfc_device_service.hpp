#pragma once

#include "nfc_hex_logger.hpp"
#include "nfc_i2c_device.hpp"
#include "nfc_spi_device.hpp"
#include "nfc_protocol.hpp"
#include "nfc_storage.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <sstream>
#include <set>
#include <thread>
#include <tuple>
#include <unordered_map>

namespace nfc_app {

// Declared here to keep nfc_device_service.hpp independent of helper definition order.
ProtocolKind i2c_protocol_to_kind(const std::string &proto);
std::string i2c_protocol_to_tag_type(const std::string &proto);

struct ConnectionState {
    bool connected = false;
    TransportEndpoint endpoint;
    std::string status = "Disconnected";
    std::string detail = "Select endpoint";
    bool pn532_ready = false;
    DeviceKind device_kind = DeviceKind::Unknown;
};

struct ScanState {
    bool running = false;
    bool has_result = false;
    SavedRecord last_record;
    std::string status = "Idle";
    std::string error;
};

struct Pn532NdefState {
    bool running = false;
    std::string uri = "https://m5stack.com";
    std::string status = "Idle";
    std::string error;
};

enum class UidMagicGeneration {
    Gen1A = 0,
    Gen2,
    Gen3,
    Gen4,
};

class NfcDeviceService {
    struct UhfTagSnapshot;
public:
    struct UhfTableRow {
        std::string epc;
        std::string rssi;
        std::string antenna;
        int read_count = 0;
        std::string first_seen;
        std::string last_seen;
    };

    struct NfcUnitEmuStartState {
        bool running = false;
        bool has_result = false;
        bool ok = false;
        std::string status;
        std::string error;
        std::string profile;
    };

    NfcDeviceService()
    {
        refresh_endpoints();
        emulator_slots_by_protocol_ = storage_.load_emulator_slots_by_protocol();
        uart_config_ = storage_.load_uart_config();
        // Apply saved baud rate to any already-enumerated UART endpoint
        for (auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial &&
                ep.path == uart_config_.device_path) {
                ep.baud_rate = uart_config_.baud_rate;
            }
        }
        // Restore last-used transport kind + path so the UI starts on the right mode
        const TransportKind saved_kind = storage_.load_last_transport_kind();
        const std::string saved_path   = storage_.load_last_endpoint_path();
        if (saved_kind != TransportKind::Mock) {
            intended_kind_ = saved_kind;
            bool restored = false;

            // First priority: restore exact endpoint path for all transport kinds.
            if (!saved_path.empty()) {
                for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                    if (endpoints_[i].kind == saved_kind && endpoints_[i].path == saved_path) {
                        selected_endpoint_ = i;
                        restored = true;
                        break;
                    }
                }
            }

            // SPI/I2C endpoints are often on-demand; synthesize when not enumerated.
            if (!restored &&
                (saved_kind == TransportKind::SpiBus || saved_kind == TransportKind::I2cBus) &&
                !saved_path.empty()) {
                TransportEndpoint ep;
                ep.kind  = saved_kind;
                ep.path  = saved_path;
                ep.label = (saved_kind == TransportKind::SpiBus ? "SPI " : "I2C ") + saved_path;
                endpoints_.push_back(ep);
                selected_endpoint_ = static_cast<int>(endpoints_.size()) - 1;
                restored = true;
            }

            // Fallback: first endpoint by kind (UART prefers configured path).
            if (!restored) {
                const std::string uart_prefer_path = !saved_path.empty() ? saved_path : uart_config_.device_path;
                for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                    if (endpoints_[i].kind != saved_kind) continue;
                    if (saved_kind == TransportKind::UartSerial &&
                        !uart_prefer_path.empty() &&
                        endpoints_[i].path != uart_prefer_path) {
                        continue;
                    }
                    selected_endpoint_ = i;
                    restored = true;
                    break;
                }
            }
        }
    }

    ~NfcDeviceService()
    {
        stop_uhf_continuous_scan();
        cancel_hw_upload_.store(true);
        cancel_hw_mfkey_.store(true);
        if (nfc_unit_emu_start_thread_.joinable()) nfc_unit_emu_start_thread_.join();
        stop_nfcunit_emulation_worker(false);
        stop_spi_emulation_worker(false);
        stop_pn532_ndef_emulation();
        if (uart_test_thread_.joinable()) uart_test_thread_.join();
        if (hw_upload_thread_.joinable()) hw_upload_thread_.join();
        if (scan_thread_.joinable()) scan_thread_.join();
        if (probe_thread_.joinable()) probe_thread_.join();
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        disconnect();
    }

    // ── Hardware EMU slot probe (PN532Killer) ────────────────────────────────
    struct EmuSlotInfo {
        bool probed      = false;
        std::string uid;           // empty if not available
        std::string block0_hex;    // hex string of first block/page, empty if n/a
        // Full dump — populated only when user triggers "Download Data"
        std::vector<std::string> dump_lines;  // formatted hex lines (e.g. "00: 34 5D 80 C4 ...")
        bool dump_loaded = false;
    };

    EmuSlotInfo emu_slot_info(ProtocolKind protocol, int slot) const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        auto it = emu_slot_cache_.find({protocol, slot});
        return (it != emu_slot_cache_.end()) ? it->second : EmuSlotInfo{};
    }

    bool emu_probe_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_probe_running_;
    }

    std::string emu_probe_error() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_probe_error_;
    }

    // Switch hardware emulator slot + probe block0 in background thread.
    // Cancels any in-progress probe so the new switch is never silently dropped.
    bool hw_switch_emu_slot_and_probe(ProtocolKind protocol, int slot)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
        }
        // Signal any running probe to stop, then join it.
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);

        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_probe_running_ = true;
            emu_probe_error_.clear();
        }
        emu_probe_thread_ = std::thread([this, protocol, slot]() {
            perform_emu_slot_probe(protocol, slot);
        });
        return true;
    }

    static uint8_t emu_type_byte(ProtocolKind p)
    {
        switch (p) {
        case ProtocolKind::MifareClassic: return 0x01;
        case ProtocolKind::Iso15693:      return 0x03;
        default:                          return 0x02;  // NTAG / Iso14443A
        }
    }

    // Cycle HW EMU protocol: MFC → NTAG(Iso14443A) → ISO15693 → MFC
    void cycle_hw_emu_protocol()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (selected_emulator_protocol_ == ProtocolKind::MifareClassic)
            selected_emulator_protocol_ = ProtocolKind::Iso14443A;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso14443A)
            selected_emulator_protocol_ = ProtocolKind::Iso15693;
        else
            selected_emulator_protocol_ = ProtocolKind::MifareClassic;
    }

    // Start async full dump download from HW EMU slot. Results stored in EmuSlotInfo::dump_lines.
    bool hw_start_emu_dump_async(ProtocolKind protocol, int slot)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
        }
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_dump_running_ = true;
        }
        emu_dump_thread_ = std::thread([this, protocol, slot]() {
            perform_emu_slot_dump(protocol, slot);
        });
        return true;
    }

    bool emu_dump_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return emu_dump_running_;
    }

    // Start asynchronous upload of a saved MFC record to the given HW EMU slot (0-based).
    // Returns false if already running or scan is running.
    bool hw_start_upload_async(int slot, const SavedRecord &record)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) return false;
            if (record.tag.raw_data.size() != 64) return false;
        }
        cancel_hw_upload_.store(true);
        if (hw_upload_thread_.joinable()) hw_upload_thread_.join();
        cancel_hw_upload_.store(false);
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            hw_upload_running_  = true;
            hw_upload_progress_ = 0;
            hw_upload_ok_       = false;
        }
        hw_upload_thread_ = std::thread([this, slot, record]() {
            perform_hw_upload(slot, record);
        });
        return true;
    }

    bool hw_upload_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_running_;
    }

    int hw_upload_progress() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_progress_;
    }

    bool hw_upload_ok() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_upload_ok_;
    }

    void refresh_endpoints()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::string previous_path;
        TransportKind previous_kind = intended_kind_;
        if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
            previous_path = endpoints_[selected_endpoint_].path;
            previous_kind = endpoints_[selected_endpoint_].kind;
        }

        endpoints_ = NfcTransportFactory::enumerate_endpoints();
        if (selected_endpoint_ >= static_cast<int>(endpoints_.size())) selected_endpoint_ = 0;
        if (endpoints_.empty()) return;

        // Keep previous concrete endpoint selection whenever possible.
        if (!previous_path.empty()) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == previous_kind && endpoints_[i].path == previous_path) {
                    selected_endpoint_ = i;
                    return;
                }
            }
        }

        // Auto-select the first USB endpoint when the intended mode is USB (default at startup).
        if (intended_kind_ == TransportKind::UsbSerial) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == TransportKind::UsbSerial) {
                    selected_endpoint_ = i;
                    break;
                }
            }
        }
    }

    // ── Device probe ─────────────────────────────────────────────────────────

    // Start background probe of all non-mock endpoints.
    // Results become available via probe_results().
    void start_probe_all()
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (probe_running_) return;
            probe_running_ = true;
            // Initialise result list with "probing" placeholders
            probe_results_.clear();
            for (const auto &ep : endpoints_) {
                if (ep.kind == TransportKind::I2cBus) continue;
                DeviceProbeResult r;
                r.path      = ep.path;
                r.transport = ep.kind;
                r.probing   = true;
                probe_results_.push_back(r);
            }
            if (probe_results_.empty()) {
                probe_running_ = false;
                return;
            }
        }
        if (probe_thread_.joinable()) probe_thread_.join();
        probe_thread_ = std::thread([this]() { perform_probe_all(); });
    }

    bool probe_running() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return probe_running_;
    }

    std::vector<DeviceProbeResult> probe_results() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return probe_results_;
    }

    // ── UART configuration ───────────────────────────────────────────────────

    UartConfig uart_config() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return uart_config_;
    }

    void set_uart_config(const UartConfig &cfg)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        uart_config_ = cfg;
        // Update any matching UART endpoint's baud rate
        for (auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial && ep.path == cfg.device_path) {
                ep.baud_rate = cfg.baud_rate;
            }
        }
        storage_.save_uart_config(cfg);

        // Apply TX/RX GPIO pinmux via pinctrl if pins are specified.
        // This allows dynamic switching e.g. between different GPIO pairs.
        apply_uart_pins(cfg.tx_pin, cfg.rx_pin);
    }

    static void apply_uart_pins(int tx_pin, int rx_pin)
    {
        // Only act if at least one pin is explicitly configured.
        if (tx_pin < 0 && rx_pin < 0) return;

        // Use pinctrl (RPi utility) to set ALT5 for UART1 TXD1/RXD1.
        auto set_pin = [](int pin) {
            if (pin < 0) return std::string{};
            char buf[128];
            std::snprintf(buf, sizeof(buf), "pinctrl set %d a5", pin);  // ALT5 = TXD1/RXD1
            return std::string{buf};
        };
        std::string tx_cmd = set_pin(tx_pin);
        std::string rx_cmd = set_pin(rx_pin);

        if (!tx_cmd.empty() || !rx_cmd.empty()) {
            std::string combined;
            combined += "( ";
            if (!tx_cmd.empty()) combined += tx_cmd + " ; ";
            if (!rx_cmd.empty()) combined += rx_cmd + " ; ";
            combined += ") 2>/dev/null &";  // fire-and-forget in background
            std::system(combined.c_str());
        }
    }

    // Returns UART endpoints only (no mock, no USB)
    std::vector<TransportEndpoint> uart_endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TransportEndpoint> out;
        for (const auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UartSerial) out.push_back(ep);
        }
        return out;
    }

    // ── Async UART connection test ───────────────────────────────────────────
    // Launches a background thread that:
    //   1. Opens the UART port and sends wakeup + SAMConfig + FWVersion frames
    //   2. Logs every TX/RX byte (hex) to both a file and uart_test_log_lines_
    //   3. Sets uart_test_result_ when done.
    // Call uart_test_running() to poll; drain_uart_test_logs() to collect lines.
    void start_uart_test()
    {
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            if (uart_test_running_) return; // already running
            uart_test_running_ = true;
            uart_test_log_lines_.clear();
            uart_test_result_.clear();
        }
        if (uart_test_thread_.joinable()) uart_test_thread_.join();
        uart_test_thread_ = std::thread([this]() {
            // Resolve config
            UartConfig cfg;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                cfg = uart_config_;
                if (cfg.device_path.empty()) {
                    for (const auto &ep : endpoints_) {
                        if (ep.kind == TransportKind::UartSerial) {
                            cfg.device_path = ep.path;
                            if (cfg.baud_rate <= 0) cfg.baud_rate = ep.baud_rate;
                            break;
                        }
                    }
                }
            }
            if (cfg.device_path.empty()) {
                finish_uart_test("No UART port found (/dev/ttyAMA*)");
                return;
            }
            const int baud = 115200; // fixed baud rate

            // Open log file
            const std::string log_dir = storage_.root_dir() + "/logs";
            ::mkdir(log_dir.c_str(), 0755);
            const std::string log_path = log_dir + "/uart_test_latest.log";
            FILE *fp = fopen(log_path.c_str(), "w");
            auto log_line = [&](const std::string &s) {
                {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    uart_test_log_lines_.push_back(s);
                }
                if (fp) { fputs(s.c_str(), fp); fputc('\n', fp); fflush(fp); }
            };

            log_line("=== UART test " + cfg.device_path + " @" + std::to_string(baud) + " baud ===");

            // Build endpoint and open transport
            TransportEndpoint ep;
            ep.kind      = TransportKind::UartSerial;
            ep.path      = cfg.device_path;
            ep.baud_rate = baud;

            SerialTransport raw_transport;
            std::string open_error;
            if (!raw_transport.open(ep, &open_error)) {
                log_line("Open failed: " + open_error);
                if (fp) fclose(fp);
                finish_uart_test("Open failed: " + open_error);
                return;
            }

            // Wrap with a logging shim
            class LogTransport : public INfcTransport {
            public:
                INfcTransport *inner;
                std::function<void(const std::string&)> log;
                ssize_t write_bytes(const uint8_t *b, size_t n, std::string *err) override {
                    std::string hex = "TX[" + std::to_string(n) + "] ";
                    for (size_t i = 0; i < n && i < 64; ++i) {
                        char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", b[i]);
                        hex += buf;
                    }
                    if (n > 64) hex += "...";
                    log(hex);
                    return inner->write_bytes(b, n, err);
                }
                ssize_t read_bytes(uint8_t *b, size_t n, int timeout_ms, std::string *err) override {
                    ssize_t got = inner->read_bytes(b, n, timeout_ms, err);
                    if (got <= 0) return got;
                    // After the first bytes arrive, drain any immediately available
                    // continuation bytes (0 ms timeout) so the whole response frame
                    // lands in a single log line instead of one-byte-per-line.
                    while ((size_t)got < n) {
                        ssize_t more = inner->read_bytes(b + got, n - (size_t)got, 0, nullptr);
                        if (more <= 0) break;
                        got += more;
                    }
                    std::string hex = "RX[" + std::to_string(got) + "] ";
                    constexpr ssize_t MAX_LOG = 64;
                    for (ssize_t i = 0; i < got && i < MAX_LOG; ++i) {
                        char buf[3]; std::snprintf(buf, sizeof(buf), "%02X", b[i]);
                        hex += buf;
                    }
                    if (got > MAX_LOG) hex += "...";
                    log(hex);
                    return got;
                }
                bool is_open() const override { return inner->is_open(); }
                void close() override { inner->close(); }
                bool open(const TransportEndpoint &ep, std::string *err) override { return inner->open(ep, err); }
                TransportEndpoint endpoint() const override { return inner->endpoint(); }
            };
            LogTransport logging_transport;
            logging_transport.inner = &raw_transport;
            logging_transport.log   = log_line;

            Pn532KillerClient client(&logging_transport);
            std::string probe_error, firmware;
            const DeviceKind kind = client.detect_device(&firmware, &probe_error);
            raw_transport.close();

            std::string result;
            if (kind == DeviceKind::PN532Killer || kind == DeviceKind::PN532) {
                result = std::string("OK: ");
                result += firmware.empty() ? to_string(kind) : firmware;
            } else {
                result = "No device: " + probe_error;
            }
            log_line("=== Result: " + result + " ===");
            if (fp) fclose(fp);
            finish_uart_test(result);
        });
    }

    bool uart_test_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return uart_test_running_;
    }

    // Drain pending log lines into out (appends). Returns true if test finished.
    bool drain_uart_test_logs(std::vector<std::string> &out, std::string &result_out)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        out.insert(out.end(), uart_test_log_lines_.begin(), uart_test_log_lines_.end());
        uart_test_log_lines_.clear();
        if (!uart_test_running_ && !uart_test_result_.empty()) {
            result_out = uart_test_result_;
            return true; // finished
        }
        return false;
    }

    // Returns USB serial endpoints only (no mock, no UART)
    std::vector<TransportEndpoint> usb_endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<TransportEndpoint> out;
        for (const auto &ep : endpoints_) {
            if (ep.kind == TransportKind::UsbSerial) out.push_back(ep);
        }
        return out;
    }

    // Select a USB endpoint by path and reset connection state.
    // Returns true if found and selected.
    bool select_usb_endpoint_by_path(const std::string &path)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
            if (endpoints_[i].path == path) {
                if (transport_) { transport_->close(); transport_.reset(); }
                connection_ = ConnectionState{};
                intended_kind_ = endpoints_[i].kind;
                selected_endpoint_ = i;
                storage_.save_last_endpoint(intended_kind_, endpoints_[i].path);
                return true;
            }
        }
        return false;
    }

    // Probe I2C buses on-demand. Returns only devices that responded to the probe.
    std::vector<TransportEndpoint> scan_i2c_devices()
    {
        return NfcTransportFactory::probe_i2c_devices();
    }

    // Enumerate SPI spidev* devices for the SpiSelect modal.
    std::vector<TransportEndpoint> enumerate_spi_devices()
    {
        return NfcTransportFactory::enumerate_spi_devices();
    }

    // Select a specific SPI endpoint for connection.
    void select_spi_endpoint(const TransportEndpoint &ep)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (transport_) { transport_->close(); transport_.reset(); }
        connection_ = ConnectionState{};
        intended_kind_ = TransportKind::SpiBus;
        storage_.save_last_endpoint(intended_kind_, ep.path);
        for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
            if (endpoints_[i].kind == TransportKind::SpiBus &&
                endpoints_[i].path == ep.path) {
                selected_endpoint_ = i;
                return;
            }
        }
        endpoints_.push_back(ep);
        selected_endpoint_ = static_cast<int>(endpoints_.size()) - 1;
    }

    // Select a specific I2C endpoint for connection. If the endpoint is not
    // already in the cached list (e.g. from an on-demand scan), it is appended.
    void select_i2c_endpoint(const TransportEndpoint &ep)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Disconnect current transport first
        if (transport_) { transport_->close(); transport_.reset(); }
        connection_ = ConnectionState{};
        intended_kind_ = TransportKind::I2cBus;
        storage_.save_last_endpoint(intended_kind_, ep.path);
        // Reuse existing slot if the path is already known
        for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
            if (endpoints_[i].kind == TransportKind::I2cBus &&
                endpoints_[i].path == ep.path) {
                selected_endpoint_ = i;
                return;
            }
        }
        // Not yet in list — append it
        endpoints_.push_back(ep);
        selected_endpoint_ = static_cast<int>(endpoints_.size()) - 1;
    }

    // Pin reference table for common M5CardputerZero UART ports
    // Returns {tx_pin, rx_pin} or {-1,-1} if unknown
    static std::pair<int,int> uart_pin_hint(const std::string &dev_path)
    {
        // AX620Q / CardputerZero UART mappings (from device tree reference)
        if (dev_path.find("ttyTHS0") != std::string::npos) return {14, 15};
        if (dev_path.find("ttyTHS1") != std::string::npos) return {16, 17};
        if (dev_path.find("ttyTHS2") != std::string::npos) return {18, 19};
        if (dev_path.find("ttyS0") != std::string::npos)   return {14, 15};
        if (dev_path.find("ttyAMA0") != std::string::npos) return {8, 9};   // RPi-style
        if (dev_path.find("ttyAMA1") != std::string::npos) return {0, 1};
        return {-1, -1};
    }

    std::vector<TransportEndpoint> endpoints() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return endpoints_;
    }

    TransportEndpoint current_endpoint() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
            if (endpoints_[selected_endpoint_].kind == intended_kind_)
                return endpoints_[selected_endpoint_];
        }
        // No real endpoint for intended kind: return a synthetic one so UI can display the mode
        TransportEndpoint syn;
        syn.kind = intended_kind_;
        syn.path = "";
        syn.label = std::string(to_string(intended_kind_)) + " (no device)";
        syn.baud_rate = 0;
        return syn;
    }

    void cycle_endpoint(int delta)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return;
        const int count = static_cast<int>(endpoints_.size());
        selected_endpoint_ = (selected_endpoint_ + delta + count) % count;
    }

    // Cycle through MOCK → USB → UART → MOCK, always including all three kinds.
    // Does NOT auto-connect; just selects the endpoint and returns.
    bool cycle_device_mode(std::string *status = nullptr)
    {
        // Save current path so we can restore stable selection after re-enumeration
        std::string current_path;
        TransportKind current_kind = TransportKind::UsbSerial;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            // Use intended_kind_ as the authoritative "current" so that if the
            // last cycle landed on an empty slot we still advance from there.
            current_kind = intended_kind_;
            if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
                current_path = endpoints_[selected_endpoint_].path;
            }
        }

        refresh_endpoints();
        std::lock_guard<std::mutex> lock(mutex_);

        // Restore selected_endpoint_ by path after re-enumeration to avoid stale index
        if (!current_path.empty()) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].path == current_path) {
                    selected_endpoint_ = i;
                    break;
                }
            }
        }

        // Build cycle: USB → UART → I2C → SPI (always; Mock removed).
        std::vector<TransportKind> cycle;
        cycle.push_back(TransportKind::UsbSerial);
        cycle.push_back(TransportKind::UartSerial);
        cycle.push_back(TransportKind::I2cBus);
        cycle.push_back(TransportKind::SpiBus);

        // current_kind already determined above (stable after refresh)

        // Find next kind in cycle
        TransportKind target_kind = cycle[0];
        for (size_t i = 0; i < cycle.size(); ++i) {
            if (cycle[i] == current_kind) {
                target_kind = cycle[(i + 1) % cycle.size()];
                break;
            }
        }

        // Select first endpoint matching target kind (prefer configured UART path)
        int target_index = -1;
        if (target_kind == TransportKind::UartSerial && !uart_config_.device_path.empty()) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == target_kind && endpoints_[i].path == uart_config_.device_path) {
                    target_index = i;
                    break;
                }
            }
        }
        if (target_index < 0) {
            for (int i = 0; i < static_cast<int>(endpoints_.size()); ++i) {
                if (endpoints_[i].kind == target_kind) {
                    target_index = i;
                    break;
                }
            }
        }
        // Disconnect old transport regardless of whether we found an endpoint
        if (transport_) { transport_->close(); transport_.reset(); }
        connection_ = ConnectionState{};
        intended_kind_ = target_kind;
        if (target_index >= 0 && target_index < static_cast<int>(endpoints_.size())) {
            storage_.save_last_endpoint(target_kind, endpoints_[target_index].path);
        } else {
            storage_.save_last_endpoint(target_kind, "");
        }

        if (target_index < 0) {
            // No physical device for this kind – stay in the slot, report it
            if (status) *status = std::string(to_string(target_kind)) + ": no device";
            return false;
        }

        selected_endpoint_ = target_index;
        if (status) *status = std::string("Mode: ") + to_string(target_kind);
        return true;
    }

    // Toggle between USB and UART endpoint groups, prefer configured UART path,
    // then auto-connect and probe the selected device.
    bool cycle_transport_mode(std::string *status = nullptr)
    {
        refresh_endpoints();

        TransportEndpoint selected;
        bool selected_ok = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            std::vector<TransportKind> available;
            bool has_usb = false;
            bool has_uart = false;
            for (const auto &ep : endpoints_) {
                if (ep.kind == TransportKind::UsbSerial) has_usb = true;
                if (ep.kind == TransportKind::UartSerial) has_uart = true;
            }
            if (has_usb) available.push_back(TransportKind::UsbSerial);
            if (has_uart) available.push_back(TransportKind::UartSerial);
            if (available.empty()) {
                if (status) *status = "No USB/UART device found";
                return false;
            }

            TransportKind current_kind = TransportKind::UsbSerial;
            if (!endpoints_.empty() && selected_endpoint_ < static_cast<int>(endpoints_.size())) {
                current_kind = endpoints_[selected_endpoint_].kind;
            }

            size_t next_kind_idx = 0;
            for (size_t i = 0; i < available.size(); ++i) {
                if (available[i] == current_kind) {
                    next_kind_idx = (i + 1) % available.size();
                    break;
                }
            }
            const TransportKind target_kind = available[next_kind_idx];

            int target_index = -1;
            if (target_kind == TransportKind::UartSerial && !uart_config_.device_path.empty()) {
                for (size_t i = 0; i < endpoints_.size(); ++i) {
                    if (endpoints_[i].kind == target_kind && endpoints_[i].path == uart_config_.device_path) {
                        target_index = static_cast<int>(i);
                        break;
                    }
                }
            }
            if (target_index < 0) {
                for (size_t i = 0; i < endpoints_.size(); ++i) {
                    if (endpoints_[i].kind == target_kind) {
                        target_index = static_cast<int>(i);
                        break;
                    }
                }
            }
            if (target_index < 0) {
                if (status) *status = "No endpoint for selected transport";
                return false;
            }

            if (transport_) transport_->close();
            transport_.reset();
            connection_ = ConnectionState{};
            selected_endpoint_ = target_index;
            selected = endpoints_[selected_endpoint_];
            selected_ok = true;
        }

        if (!selected_ok) return false;

        if (!connect_current()) {
            if (status) *status = std::string(to_string(selected.kind)) + " selected, connect failed";
            return false;
        }

        const auto state = connection_state();
        if (status) {
            *status = std::string(to_string(selected.kind)) + " -> " +
                      (state.pn532_ready ? state.detail : state.status);
        }
        return true;
    }

    bool connect_current()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (endpoints_.empty()) return false;

        TransportEndpoint open_endpoint = endpoints_[selected_endpoint_];
        std::string error;
        if (!open_transport_locked(open_endpoint, &error)) {
            connection_.connected = false;
            connection_.endpoint = open_endpoint;
            connection_.status = "Connect failed";
            connection_.detail = error;
            connection_.pn532_ready = false;
            connection_.device_kind = DeviceKind::NotConnected;
            transport_.reset();
            return false;
        }

        connection_.connected = true;
        connection_.endpoint = endpoints_[selected_endpoint_];
        connection_.status = std::string("Connected ") + to_string(connection_.endpoint.kind);
        connection_.detail = connection_.endpoint.path;
        connection_.pn532_ready = false;
        connection_.device_kind = DeviceKind::Unknown;
        storage_.save_last_endpoint(connection_.endpoint.kind, connection_.endpoint.path);

        // Set log file mode prefix based on transport type.
        if (connection_.endpoint.kind == TransportKind::I2cBus) {
            NfcHexLog::get().set_mode("iic");
        } else if (connection_.endpoint.kind == TransportKind::SpiBus) {
            NfcHexLog::get().set_mode("spi");
        } else {
            NfcHexLog::get().set_mode("uart");
        }

        // ====================================================================
        // UartSerial: only PN532 / PN532Killer probe @115200, no UHF.
        // ====================================================================
        if (connection_.endpoint.kind == TransportKind::UartSerial) {
            push_log(std::string("[Detect] UART endpoint: ") + connection_.endpoint.path);
            push_log("[Detect] Probe PN532/PN532Killer @115200");

            if (connection_.endpoint.baud_rate != 115200) {
                TransportEndpoint ep = connection_.endpoint;
                ep.baud_rate = 115200;
                std::string reopen_err;
                if (!open_transport_locked(ep, &reopen_err)) {
                    connection_.connected = false;
                    connection_.status = "Connect failed";
                    connection_.detail = std::string("UART open@115200 failed: ") + reopen_err;
                    connection_.device_kind = DeviceKind::NotConnected;
                    push_log(std::string("[Detect] UART open@115200 failed: ") + reopen_err);
                    return false;
                }
                connection_.endpoint = ep;
            }

            Pn532KillerClient client(transport_.get());
            std::string probe_error;
            std::string firmware;
            const auto kind = client.detect_device(&firmware, &probe_error);
            connection_.device_kind = kind;
            if (kind == DeviceKind::PN532Killer || kind == DeviceKind::PN532) {
                connection_.pn532_ready = true;
                connection_.status = std::string("Connected ") + to_string(kind);
                const std::string fw_label = firmware.empty() ? to_string(kind) : firmware;
                connection_.detail = fw_label + " @ " + connection_.endpoint.path + " @115200";
                push_log(std::string("[Detect] UART PN532 detected: ") + fw_label);
            } else {
                connection_.pn532_ready = false;
                connection_.device_kind = DeviceKind::OtherSerial;
                connection_.status = "Connected Serial";
                connection_.detail = "UART: " +
                    (probe_error.empty() ? "PN532 not detected" : probe_error);
                if (!probe_error.empty()) {
                    push_log(std::string("[Detect] UART PN532 not found: ") + probe_error);
                } else {
                    push_log("[Detect] UART PN532 not found (no response)");
                }
            }
            return true;
        }

        // ====================================================================
        // UsbSerial: full logic with UHF detection + PN532 fallback.
        // ====================================================================
        if (connection_.endpoint.kind == TransportKind::UsbSerial) {
            const int primary_baud = 115200;
            const int uhf_preferred_baud = 9600;
            auto is_known_uhf_vid_pid = [](int vid, int pid) -> bool {
                return vid == 0x1A86 && pid == 0xFE1C;
            };
            auto endpoint_has_usb20_hint = [](const TransportEndpoint &ep) -> bool {
                const std::string up = to_upper_ascii(ep.label + " " + ep.path);
                return up.find("USB2.0") != std::string::npos ||
                       up.find("USB 2.0") != std::string::npos;
            };
            auto endpoint_has_usb_serial_hint = [](const TransportEndpoint &ep) -> bool {
                const std::string up = to_upper_ascii(ep.label + " " + ep.path);
                return up.find("USB SERIAL") != std::string::npos;
            };
            push_log(std::string("[Detect] USB endpoint: ") + connection_.endpoint.path);
            if (connection_.endpoint.usb_vid >= 0 && connection_.endpoint.usb_pid >= 0) {
                char vp[48];
                std::snprintf(vp, sizeof(vp), "[Detect] USB VID:PID = %04X:%04X",
                              connection_.endpoint.usb_vid, connection_.endpoint.usb_pid);
                push_log(vp);
            }

            const bool force_uhf_by_name = endpoint_has_usb20_hint(connection_.endpoint);
            const bool force_pn_by_name  = endpoint_has_usb_serial_hint(connection_.endpoint);

            if (force_pn_by_name) {
                push_log("[Detect] Name hint USB Serial -> PN532 route only");
            }

            if (force_uhf_by_name) {
                push_log("[Detect] USB2.0 hint found -> direct UHF probe @9600");
                std::string uhf_detail;
                bool uhf_found = false;
                int used_baud = uhf_preferred_baud;

                if (connection_.endpoint.baud_rate != uhf_preferred_baud) {
                    TransportEndpoint ep = connection_.endpoint;
                    ep.baud_rate = uhf_preferred_baud;
                    std::string reopen_err;
                    if (!open_transport_locked(ep, &reopen_err)) {
                        push_log(std::string("[Detect] open@9600 failed: ") + reopen_err);
                    } else {
                        connection_.endpoint = ep;
                    }
                }

                if (uhf_detect_on_open_transport_locked(transport_.get(), &uhf_detail)) {
                    uhf_found = true;
                    used_baud = uhf_preferred_baud;
                } else {
                    push_log("[Detect] UHF not found @9600, retry @115200");
                    TransportEndpoint ep = connection_.endpoint;
                    ep.baud_rate = primary_baud;
                    std::string reopen_err;
                    if (open_transport_locked(ep, &reopen_err)) {
                        connection_.endpoint = ep;
                        if (uhf_detect_on_open_transport_locked(transport_.get(), &uhf_detail)) {
                            uhf_found = true;
                            used_baud = primary_baud;
                        }
                    } else {
                        push_log(std::string("[Detect] open@115200 failed: ") + reopen_err);
                    }
                }

                if (uhf_found) {
                    connection_.device_kind = DeviceKind::UHFReader;
                    connection_.pn532_ready = false;
                    connection_.status = "Connected UHF Reader";
                    connection_.detail = (uhf_detail.empty()
                        ? (std::string("UHFReader @ ") + connection_.endpoint.path)
                        : uhf_detail) + " @" + std::to_string(used_baud);
                    push_log(std::string("[Detect] UHF confirmed @") + std::to_string(used_baud));
                    return true;
                }

                push_log("[Detect] USB2.0 direct UHF probe failed, fallback to PN532 probe");
            }

            if (!force_pn_by_name &&
                is_known_uhf_vid_pid(connection_.endpoint.usb_vid, connection_.endpoint.usb_pid)) {
                push_log("[Detect] VID/PID matched known UHF reader (1A86:FE1C)");

                std::string uhf_detail;
                bool uhf_found = false;
                int uhf_baud = primary_baud;

                push_log("[Detect] Probe UHF reader @115200");
                if (uhf_detect_on_open_transport_locked(transport_.get(), &uhf_detail)) {
                    uhf_found = true;
                    uhf_baud = 115200;
                } else {
                    push_log("[Detect] UHF not found @115200, retry @9600");
                    TransportEndpoint ep9600 = connection_.endpoint;
                    ep9600.baud_rate = 9600;
                    std::string reopen_err;
                    if (open_transport_locked(ep9600, &reopen_err)) {
                        connection_.endpoint = ep9600;
                        if (uhf_detect_on_open_transport_locked(transport_.get(), &uhf_detail)) {
                            uhf_found = true;
                            uhf_baud = 9600;
                        } else {
                            push_log("[Detect] UHF not found @9600");
                        }
                    } else {
                        push_log(std::string("[Detect] open@9600 failed: ") + reopen_err);
                    }
                }

                connection_.device_kind = DeviceKind::UHFReader;
                connection_.pn532_ready = false;
                connection_.status = "Connected UHF Reader";
                if (uhf_found) {
                    connection_.detail = (uhf_detail.empty()
                        ? (std::string("UHFReader @ ") + connection_.endpoint.path)
                        : uhf_detail) + " @" + std::to_string(uhf_baud);
                    push_log(std::string("[Detect] UHF confirmed @") + std::to_string(uhf_baud));
                } else {
                    connection_.detail = std::string("UHFReader VID/PID 1A86:FE1C @ ") +
                                         connection_.endpoint.path +
                                         " (version query timeout)";
                    push_log("[Detect] UHF VID/PID matched, but version query timeout");
                }
                return true;
            }

            push_log("[Detect] Probe PN532/PN532Killer @115200");

            if (connection_.endpoint.baud_rate != primary_baud) {
                TransportEndpoint ep = connection_.endpoint;
                ep.baud_rate = primary_baud;
                std::string reopen_err;
                if (!open_transport_locked(ep, &reopen_err)) {
                    connection_.connected = false;
                    connection_.status = "Connect failed";
                    connection_.detail = std::string("open@115200 failed: ") + reopen_err;
                    connection_.device_kind = DeviceKind::NotConnected;
                    push_log(std::string("[Detect] open@115200 failed: ") + reopen_err);
                    return false;
                }
                connection_.endpoint = ep;
            }

            Pn532KillerClient client(transport_.get());
            std::string probe_error;
            std::string firmware;
            const auto kind = client.detect_device(&firmware, &probe_error);
            connection_.device_kind = kind;
            if (kind == DeviceKind::PN532Killer || kind == DeviceKind::PN532) {
                connection_.pn532_ready = true;
                connection_.status = std::string("Connected ") + to_string(kind);
                const std::string fw_label = firmware.empty() ? to_string(kind) : firmware;
                connection_.detail = fw_label + std::string(" @ ") + connection_.endpoint.path + " @115200";
                push_log(std::string("[Detect] PN532 detected: ") + fw_label);

                // Some USB ACM UHF adapters may occasionally look like a PN532 response.
                // Cross-check once with UHF version query and prefer UHF when signature is clear.
                if (!force_pn_by_name &&
                    connection_.endpoint.path.find("ttyACM") != std::string::npos) {
                    std::string cross_detail;
                    push_log("[Detect] Cross-check UHF signature @115200");
                    if (uhf_detect_on_open_transport_locked(transport_.get(), &cross_detail)) {
                        connection_.device_kind = DeviceKind::UHFReader;
                        connection_.pn532_ready = false;
                        connection_.status = "Connected UHF Reader";
                        connection_.detail = (cross_detail.empty()
                            ? (std::string("UHFReader @ ") + connection_.endpoint.path)
                            : cross_detail) + " @115200";
                        push_log("[Detect] UHF signature confirmed, override PN532 result");
                    }
                }
            } else {
                if (!probe_error.empty()) {
                    push_log(std::string("[Detect] PN532 not found: ") + probe_error);
                } else {
                    push_log("[Detect] PN532 not found");
                }

                if (force_pn_by_name) {
                    connection_.device_kind = DeviceKind::OtherSerial;
                    connection_.pn532_ready = false;
                    connection_.status = "Connected Serial";
                    connection_.detail = std::string("USB Serial route: ") +
                                         (probe_error.empty() ? "PN532 not detected" : probe_error);
                    push_log("[Detect] Skip UHF probe due to USB Serial name route");
                    return true;
                }

                std::string uhf_detail;
                push_log("[Detect] Probe UHF reader @115200");
                if (uhf_detect_on_open_transport_locked(transport_.get(), &uhf_detail)) {
                    connection_.device_kind = DeviceKind::UHFReader;
                    connection_.pn532_ready = false;
                    connection_.status = "Connected UHF Reader";
                    connection_.detail = (uhf_detail.empty()
                        ? (std::string("UHFReader @ ") + connection_.endpoint.path)
                        : uhf_detail) + " @115200";
                    push_log(std::string("[Detect] UHF detected @115200: ") +
                             (uhf_detail.empty() ? "OK" : uhf_detail));
                } else {
                    push_log("[Detect] UHF not found @115200, retry @9600");

                    bool uhf_found_9600 = false;
                    std::string open9600_error;
                    TransportEndpoint ep9600 = connection_.endpoint;
                    ep9600.baud_rate = 9600;
                    if (open_transport_locked(ep9600, &open9600_error)) {
                        connection_.endpoint = ep9600;
                        if (uhf_detect_on_open_transport_locked(transport_.get(), &uhf_detail)) {
                            connection_.device_kind = DeviceKind::UHFReader;
                            connection_.pn532_ready = false;
                            connection_.status = "Connected UHF Reader";
                            connection_.detail = (uhf_detail.empty()
                                ? (std::string("UHFReader @ ") + connection_.endpoint.path)
                                : uhf_detail) + " @9600";
                            push_log(std::string("[Detect] UHF detected @9600: ") +
                                     (uhf_detail.empty() ? "OK" : uhf_detail));
                            uhf_found_9600 = true;
                        } else {
                            push_log("[Detect] UHF not found @9600");
                        }
                    } else {
                        push_log(std::string("[Detect] open@9600 failed: ") + open9600_error);
                    }

                    if (!uhf_found_9600) {
                        TransportEndpoint ep115200 = connection_.endpoint;
                        ep115200.baud_rate = primary_baud;
                        std::string restore_err;
                        if (open_transport_locked(ep115200, &restore_err)) {
                            connection_.endpoint = ep115200;
                        }
                        connection_.device_kind = DeviceKind::OtherSerial;
                        connection_.pn532_ready = false;
                        connection_.status = "Connected Serial";
                        connection_.detail = std::string("Raw serial only: ") +
                                             (probe_error.empty() ? "unknown device" : probe_error);
                    }
                }
            }
        } else if (connection_.endpoint.kind == TransportKind::I2cBus) {
            // Parse "/dev/i2c-1:0x48" → bus + addr
            const std::string &path = connection_.endpoint.path;
            const auto colon_pos = path.rfind(':');
            if (colon_pos == std::string::npos) {
                connection_.detail = "I2C: invalid endpoint path (missing ':' separator)";
            } else {
                const std::string bus = path.substr(0, colon_pos);
                uint8_t addr = 0;
                try {
                    addr = static_cast<uint8_t>(std::stoul(path.substr(colon_pos + 1), nullptr, 16));
                } catch (...) {
                    connection_.connected = false;
                    connection_.device_kind = DeviceKind::NotConnected;
                    connection_.detail = "I2C: invalid address in endpoint";
                    return false;
                }

                // First I2C connect: force a short Grove power-cycle to recover
                // from stale peripheral state after previous EMU/reader mode.
                NfcTransportFactory::grove_gpio_enable_bcm(17, false);
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                NfcTransportFactory::grove_gpio_enable_bcm(4, true);
                NfcTransportFactory::grove_gpio_enable_bcm(17, true);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));

                i2c_device_ = std::make_unique<I2cGroveNfcDevice>();
                std::string i2c_error;
                if (!i2c_device_->open(bus, addr, &i2c_error)) {
                    connection_.connected = false;
                    connection_.device_kind = DeviceKind::NotConnected;
                    connection_.detail = "I2C open failed: " + i2c_error;
                    i2c_device_.reset();
                } else {
                    connection_.device_kind = i2c_device_->device_kind();
                    connection_.pn532_ready = true;
                    connection_.status = std::string("Connected ") + to_string(connection_.device_kind);
                    char ver[128];
                    std::snprintf(ver, sizeof(ver), "%s @%s",
                        to_string(connection_.device_kind), path.c_str());
                    connection_.detail = ver;
                    if (connection_.device_kind == DeviceKind::NFCUnit) {
                        nfc_unit_emu_profile_ = 0;
                        selected_emulator_protocol_ = ProtocolKind::Iso14443A;
                    }
                    if (connection_.device_kind == DeviceKind::GroveNFC ||
                        connection_.device_kind == DeviceKind::NFCUnit) {
                        // Ensure emulator defaults directory and dump files exist on first connect
                        storage_.ensure_emulator_defaults();
                        storage_.ensure_emulator_jsons();
                    }
                }
            }
        } else if (connection_.endpoint.kind == TransportKind::SpiBus) {
            spi_device_ = std::make_unique<NfcSpiDevice>();
            std::string spi_error;
            if (!spi_device_->open(connection_.endpoint.path, &spi_error)) {
                connection_.connected = false;
                connection_.device_kind = DeviceKind::NotConnected;
                connection_.detail = "SPI open failed: " + spi_error;
                std::fprintf(stderr,
                    "[NFC][ST25R3916] SPI open failed on %s: %s\n",
                    connection_.endpoint.path.c_str(),
                    spi_error.c_str());
                spi_device_.reset();
            } else {
                connection_.device_kind = spi_device_->device_kind();
                connection_.pn532_ready = true;
                connection_.status = std::string("Connected ") + to_string(connection_.device_kind);
                char ver[128];
                std::snprintf(ver, sizeof(ver), "%s @%s",
                    to_string(connection_.device_kind),
                    connection_.endpoint.path.c_str());
                connection_.detail = ver;
                if (spi_device_->accepted_nonstandard_ic()) {
                    std::fprintf(stderr,
                        "[NFC][ST25R3916] SPI connected via debug fallback (non-standard IC_ID): %s",
                        connection_.detail.c_str());
                } else {
                    std::fprintf(stderr,
                        "[NFC][ST25R3916] SPI connected: %s",
                        connection_.detail.c_str());
                }
                if (spi_device_->has_probe_7f00()) {
                    std::fprintf(stderr,
                        " probe7f00=[%02X %02X] probe_ok=%u\n",
                        static_cast<unsigned>(spi_device_->probe_7f00_rx0()),
                        static_cast<unsigned>(spi_device_->probe_7f00_rx1()),
                        spi_device_->probe_7f00_ok() ? 1u : 0u);
                } else {
                    std::fprintf(stderr, " probe7f00=[NA] probe_ok=0\n");
                }
            }
        }
        return true;
    }

    void disconnect()
    {
        stop_nfcunit_emulation_worker(false);
        stop_spi_emulation_worker(true);
        stop_nfcunit_mfkey_sniffer(false);
        std::lock_guard<std::mutex> lock(mutex_);
        if (transport_) transport_->close();
        transport_.reset();
        i2c_device_.reset();
        spi_device_.reset();
        connection_ = ConnectionState{};
    }

    ConnectionState connection_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return connection_;
    }

    ScanState scan_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return scan_;
    }

    Pn532NdefState pn532_ndef_state() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return pn532_ndef_;
    }

    bool nfcunit_emulation_running() const
    {
        return nfc_unit_emu_running_.load();
    }

    bool is_current_device_uhf() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return connection_.connected && connection_.device_kind == DeviceKind::UHFReader;
    }

    bool uhf_continuous_scan_running() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return scan_.running && uhf_continuous_mode_;
    }

    std::vector<UhfTableRow> uhf_table_rows() const
    {
        std::vector<UhfTableRow> rows;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            rows.reserve(uhf_tags_.size());
            for (const auto &kv : uhf_tags_) {
                UhfTableRow row;
                row.epc = kv.second.epc;
                row.rssi = kv.second.rssi;
                row.antenna = kv.second.antenna;
                row.read_count = kv.second.read_count;
                row.first_seen = kv.second.first_seen;
                row.last_seen = kv.second.last_seen;
                rows.push_back(std::move(row));
            }
        }

        std::sort(rows.begin(), rows.end(), [](const UhfTableRow &a, const UhfTableRow &b) {
            if (a.read_count != b.read_count) return a.read_count > b.read_count;
            return a.epc < b.epc;
        });
        return rows;
    }

    bool start_uhf_scan_once(std::string *error = nullptr)
    {
        stop_pn532_ndef_emulation();
        if (scan_thread_.joinable()) scan_thread_.join();
        cancel_uhf_scan_.store(false);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!transport_ || !transport_->is_open()) {
                if (error) *error = "Connect UHF reader first";
                return false;
            }
            if (connection_.device_kind != DeviceKind::UHFReader) {
                if (error) *error = "Connected device is not UHF reader";
                return false;
            }
            if (scan_.running) {
                if (error) *error = "Operation already running";
                return false;
            }
            scan_.running = true;
            scan_.has_result = false;
            scan_.status = "UHF scan";
            scan_.error.clear();
            uhf_continuous_mode_ = false;
        }
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }
        scan_thread_ = std::thread([this]() { perform_uhf_scan_worker(false); });
        if (error) error->clear();
        return true;
    }

    bool start_uhf_continuous_scan(std::string *error = nullptr)
    {
        stop_pn532_ndef_emulation();
        if (scan_thread_.joinable()) scan_thread_.join();
        cancel_uhf_scan_.store(false);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!transport_ || !transport_->is_open()) {
                if (error) *error = "Connect UHF reader first";
                return false;
            }
            if (connection_.device_kind != DeviceKind::UHFReader) {
                if (error) *error = "Connected device is not UHF reader";
                return false;
            }
            if (scan_.running) {
                if (error) *error = "Operation already running";
                return false;
            }
            scan_.running = true;
            scan_.has_result = false;
            scan_.status = "UHF continuous";
            scan_.error.clear();
            uhf_continuous_mode_ = true;
        }
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }
        scan_thread_ = std::thread([this]() { perform_uhf_scan_worker(true); });
        if (error) error->clear();
        return true;
    }

    bool stop_uhf_continuous_scan(std::string *error = nullptr)
    {
        bool running = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running = scan_.running && uhf_continuous_mode_;
        }
        if (!running) {
            if (error) *error = "UHF continuous scan not running";
            return false;
        }

        cancel_uhf_scan_.store(true);
        {
            std::lock_guard<std::mutex> op_lock(transport_op_mutex_);
            INfcTransport *transport_raw = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                transport_raw = transport_.get();
            }
            if (transport_raw && transport_raw->is_open()) {
                std::string ignore;
                uhf_exchange_command_locked(transport_raw, 0x8C, {}, 80, nullptr, &ignore);
            }
        }
        if (scan_thread_.joinable()) scan_thread_.join();
        if (error) error->clear();
        return true;
    }

    bool export_uhf_csv(std::string *csv_path = nullptr, std::string *error = nullptr)
    {
        std::vector<UhfTagSnapshot> tags;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &kv : uhf_tags_) tags.push_back(kv.second);
        }
        if (tags.empty()) {
            if (error) *error = "No UHF tag data to export";
            return false;
        }

        const std::string csv_dir = "/home/pi/rfid/uhf";
        ::mkdir("/home/pi/rfid", 0755);
        ::mkdir(csv_dir.c_str(), 0755);

        std::time_t now = std::time(nullptr);
        struct tm local_tm;
#if defined(_WIN32)
        localtime_s(&local_tm, &now);
#else
        localtime_r(&now, &local_tm);
#endif
        char date_buf[16];
        std::strftime(date_buf, sizeof(date_buf), "%Y%m%d", &local_tm);

        auto file_exists = [](const std::string &path) {
            std::ifstream f(path.c_str(), std::ios::in);
            return f.good();
        };

        std::string path = csv_dir + "/" + date_buf + ".csv";
        if (file_exists(path)) {
            bool found = false;
            for (int i = 1; i <= 999; ++i) {
                char suffix[16];
                std::snprintf(suffix, sizeof(suffix), "-%03d.csv", i);
                const std::string candidate = csv_dir + "/" + date_buf + suffix;
                if (!file_exists(candidate)) {
                    path = candidate;
                    found = true;
                    break;
                }
            }
            if (!found) {
                if (error) *error = "CSV name exhausted for today";
                return false;
            }
        }

        std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
        if (!out.is_open()) {
            if (error) *error = "Open CSV failed";
            return false;
        }

        out << "first_seen,last_seen,epc,tid,pc,crc,rssi,frequency,antenna,read_count,raw_hex\n";
        for (const auto &tag : tags) {
            out << csv_escape(tag.first_seen) << ','
                << csv_escape(tag.last_seen) << ','
                << csv_escape(tag.epc) << ','
                << csv_escape(tag.tid) << ','
                << csv_escape(tag.pc) << ','
                << csv_escape(tag.crc) << ','
                << csv_escape(tag.rssi) << ','
                << csv_escape(tag.frequency) << ','
                << csv_escape(tag.antenna) << ','
                << tag.read_count << ','
                << csv_escape(tag.raw_hex)
                << '\n';
        }
        if (!out.good()) {
            if (error) *error = "Write CSV failed";
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            uhf_last_csv_path_ = path;
        }
        push_log(std::string("Inventory CSV saved: ") + path);
        if (csv_path) *csv_path = path;
        if (error) error->clear();
        return true;
    }

    bool start_pn532_ndef_emulation(const std::string &uri, std::string *error = nullptr)
    {
        std::string target_uri = uri.empty() ? "https://m5stack.com" : uri;
        stop_pn532_ndef_emulation();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!connection_.connected || connection_.device_kind != DeviceKind::PN532) {
                if (error) *error = "PN532 required for NDEF emulation";
                return false;
            }
            pn532_ndef_.running = true;
            pn532_ndef_.uri = target_uri;
            pn532_ndef_.status = "Starting";
            pn532_ndef_.error.clear();
        }

        cancel_pn532_ndef_.store(false);
        pn532_ndef_thread_ = std::thread([this, target_uri]() {
            perform_pn532_ndef_emulation(target_uri);
        });
        if (error) error->clear();
        return true;
    }

    void stop_pn532_ndef_emulation()
    {
        cancel_pn532_ndef_.store(true);
        if (pn532_ndef_thread_.joinable()) pn532_ndef_thread_.join();

        std::lock_guard<std::mutex> lock(mutex_);
        if (pn532_ndef_.running) {
            pn532_ndef_.running = false;
            pn532_ndef_.status = "Stopped";
        }
    }

    bool clear_last_scan_result(std::string *error = nullptr)
    {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (scan_.running) {
                if (error) *error = "Operation already running";
                return false;
            }
            scan_.has_result = false;
            scan_.last_record = SavedRecord{};
            scan_.status = connection_.connected ? "Ready" : "Idle";
            scan_.error.clear();
            last_dump_success_ = false;
            uhf_continuous_mode_ = false;
            uhf_tags_.clear();
            uhf_last_csv_path_.clear();
        }
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }
        if (error) error->clear();
        return true;
    }

    std::vector<ProtocolKind> supported_protocols_for_current_device() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const bool connected = connection_.connected;
        const DeviceKind kind = connection_.device_kind;
        const TransportKind transport = connected ? connection_.endpoint.kind : intended_kind_;

        if (kind == DeviceKind::PN532) {
            return {ProtocolKind::Iso14443A};
        }
        if (kind == DeviceKind::PN532Killer) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B, ProtocolKind::Iso15693};
        }
        if (kind == DeviceKind::GroveNFC) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B,
                    ProtocolKind::Iso15693, ProtocolKind::Felica};
        }
        if (kind == DeviceKind::NFCUnit) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso15693};
        }
        if (kind == DeviceKind::UHFReader) {
            return {ProtocolKind::Unknown};
        }

        if (transport == TransportKind::I2cBus) {
            return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B,
                    ProtocolKind::Iso15693, ProtocolKind::Felica};
        }
        return {ProtocolKind::Iso14443A, ProtocolKind::Iso14443B, ProtocolKind::Iso15693};
    }

    // Drain lines pushed in real-time during a Gen1A dump (called by UI each frame).
    std::vector<std::string> drain_pending_log()
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        std::vector<std::string> out;
        out.swap(pending_log_lines_);
        return out;
    }

    // Switch PN532Killer back to reader mode. Cancel any running EMU probe/dump first.
    void hw_switch_to_reader_mode()
    {
        NfcHexLog::get().log_event("reader", "switching to reader mode");
        stop_nfcunit_emulation_worker(false);
        stop_nfcunit_mfkey_sniffer(true);
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_probe_running_ = false;
            emu_dump_running_  = false;
        }
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
        }
        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            client.set_work_mode(0x01, 0x01, 0x00, nullptr);
        }
    }

    // Write UID/block0 to classic magic cards (Gen1A/Gen2/Gen3/Gen4).
    // uid_hex must be 8 or 14 hex chars, block0_hex must be 32 hex chars.
    bool write_magic_uid(UidMagicGeneration generation,
                         const std::string &uid_hex,
                         const std::string &block0_hex,
                         const std::string &gen4_password,
                         const std::string &gen2_sector0_key_a,
                         std::string *error = nullptr)
    {
        INfcTransport *transport_raw = nullptr;
        I2cGroveNfcDevice *i2c_dev = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            busy = scan_.running;
            transport_raw = transport_.get();
            i2c_dev = i2c_device_.get();
            kind = connection_.device_kind;
        }

        if (busy) {
            if (error) *error = "Scan/dump running";
            return false;
        }
        std::vector<uint8_t> uid;
        std::vector<uint8_t> block0;
        if (!parse_hex_bytes(uid_hex, &uid)) {
            if (error) *error = "Invalid UID hex";
            return false;
        }
        if (!parse_hex_bytes(block0_hex, &block0) || block0.size() != 16) {
            if (error) *error = "Invalid block0 hex";
            return false;
        }
        if (uid.size() != 4 && uid.size() != 7) {
            if (error) *error = "UID must be 4B or 7B";
            return false;
        }

        std::vector<uint8_t> gen2_key_a;
        if (generation == UidMagicGeneration::Gen2) {
            if (!parse_hex_bytes(gen2_sector0_key_a, &gen2_key_a) || gen2_key_a.size() != 6) {
                if (error) *error = "Sector0 KeyA must be 12 hex";
                return false;
            }
        }

        std::string gen4_pw;
        if (generation == UidMagicGeneration::Gen4) {
            for (char c : gen4_password) {
                if (!std::isspace(static_cast<unsigned char>(c))) {
                    gen4_pw.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
                }
            }
            if (gen4_pw.size() != 8 ||
                !std::all_of(gen4_pw.begin(), gen4_pw.end(),
                             [](char c) { return std::isxdigit(static_cast<unsigned char>(c)); })) {
                if (error) *error = "Gen4 password must be 8 hex";
                return false;
            }
        }

        if (kind == DeviceKind::NFCUnit) {
            if (!i2c_dev || !i2c_dev->is_open()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            if (generation == UidMagicGeneration::Gen1A) {
                return i2c_dev->writeNFCUnitGen1ABlock0(block0, error);
            }
            if (generation == UidMagicGeneration::Gen3) {
                if (error) *error = "NFC Unit Gen3 write is disabled (unsafe). Use PN532/PM3 for Gen3 UID changes.";
                return false;
            }
            if (generation == UidMagicGeneration::Gen4) {
                return i2c_dev->writeNFCUnitGen4Block0(uid, block0, gen4_password, error);
            }
            if (error) *error = "NFC Unit supports Gen1A and Gen4 only";
            return false;
        }

        if (!transport_raw || !transport_raw->is_open()) {
            if (error) *error = "Device not connected";
            return false;
        }
        if (kind != DeviceKind::PN532 && kind != DeviceKind::PN532Killer) {
            if (error) *error = "PN532/PN532Killer/NFC Unit required";
            return false;
        }

        Pn532KillerClient client(transport_raw);
        client.send_wakeup();
        client.sam_configuration(nullptr);

        std::string op_err;
        bool ok = false;
        switch (generation) {
        case UidMagicGeneration::Gen1A:
            ok = client.write_gen1a_block0(block0, &op_err);
            break;
        case UidMagicGeneration::Gen2:
            ok = client.write_gen2_block0(block0, gen2_key_a, &op_err);
            break;
        case UidMagicGeneration::Gen3:
            ok = client.set_classic_gen3_uid(uid, block0, &op_err);
            break;
        case UidMagicGeneration::Gen4:
            ok = client.set_gen4_uid(uid, block0, gen4_pw, &op_err);
            break;
        }

        if (!ok) {
            if (error) *error = op_err.empty() ? "UID write failed" : op_err;
            return false;
        }
        if (error) error->clear();
        return true;
    }

    // ── NFC Unit write tag (MFC/MFU/ISO15693) ────────────────────────────────
    // Writes dump data (from SavedRecord) back to a physical tag via NFC Unit.
    // Automatically detects Gen1A magic cards and uses backdoor write path.
    // progress: optional callback for per-step status lines.
    bool nfcunit_write_tag(const SavedRecord &record,
                           const std::function<void(const std::string &)> *progress = nullptr,
                           std::string *error = nullptr)
    {
        I2cGroveNfcDevice *i2c_dev = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            busy = scan_.running;
            i2c_dev = i2c_device_.get();
            kind = connection_.device_kind;
        }

        if (busy) {
            if (error) *error = "Scan/dump running";
            return false;
        }
        if (kind != DeviceKind::NFCUnit) {
            if (error) *error = "Only NFC Unit supports tag write";
            return false;
        }
        if (!i2c_dev || !i2c_dev->is_open()) {
            if (error) *error = "NFC Unit not connected";
            return false;
        }

        return i2c_dev->writeCard(record.tag.protocol, record.tag.tag_type,
                                  record.tag.raw_data, &mifare_keys_hex_list_,
                                  progress, error);
    }

    // Set MIFARE key list for authentication (used by both dump and write).
    void set_mifare_key_list(const std::vector<std::string> &keys)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        mifare_keys_hex_list_ = keys;
    }

    bool scan_uid_once(std::string *uid_hex, std::string *error,
                       std::string *tag_type = nullptr)
    {
        INfcTransport *transport_raw = nullptr;
        I2cGroveNfcDevice *i2c_dev = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            busy = scan_.running;
            transport_raw = transport_.get();
            i2c_dev = i2c_device_.get();
            kind = connection_.device_kind;
        }

        if (busy) {
            if (error) *error = "Scan/dump running";
            return false;
        }
        if (kind == DeviceKind::NFCUnit || kind == DeviceKind::GroveNFC) {
            if (!i2c_dev || !i2c_dev->is_open()) {
                if (error) *error = "I2C device not connected";
                return false;
            }
            I2cCardInfo card;
            if (!i2c_dev->readCard(card) || !card.valid) {
                if (error) *error = "no card";
                return false;
            }
            std::string normalized;
            normalized.reserve(card.uid.size());
            for (char ch : card.uid) {
                if (std::isxdigit(static_cast<unsigned char>(ch))) {
                    normalized.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
                }
            }
            if (normalized.empty()) {
                if (error) *error = "invalid UID";
                return false;
            }
            if (uid_hex) *uid_hex = normalized;
            if (tag_type) *tag_type = card.protocol; // e.g. "MFC1K","MFC4K","NTAG213","MFUL",...
            if (error) error->clear();
            return true;
        }

        if (!transport_raw || !transport_raw->is_open()) {
            if (error) *error = "Device not connected";
            return false;
        }
        if (kind != DeviceKind::PN532 && kind != DeviceKind::PN532Killer) {
            if (error) *error = "PN532/PN532Killer/NFC Unit required";
            return false;
        }

        Pn532KillerClient client(transport_raw);
        client.send_wakeup();
        client.sam_configuration(nullptr);
        TagInfo tag;
        if (!client.in_list_passive_target_iso14443a(&tag, error)) {
            return false;
        }
        if (uid_hex) *uid_hex = tag.uid;
        if (tag_type) *tag_type = tag.tag_type; // e.g. "Mifare Classic 1K", "NTAG213", ...
        return true;
    }

    bool start_scan()
    {
        stop_pn532_ndef_emulation();
        stop_nfcunit_emulation_worker(false);
        stop_nfcunit_mfkey_sniffer(true);
        if (scan_thread_.joinable()) scan_thread_.join();
        cancel_uhf_scan_.store(false);
        // Cancel any running EMU probe/dump threads to avoid racing set_work_mode calls
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        std::lock_guard<std::mutex> lock(mutex_);
        const bool i2c_connected = (i2c_device_ && i2c_device_->is_open() &&
                                    (connection_.endpoint.kind == TransportKind::I2cBus ||
                                     connection_.device_kind == DeviceKind::NFCUnit ||
                                     connection_.device_kind == DeviceKind::GroveNFC));
        const bool spi_connected = (spi_device_ && spi_device_->is_open() &&
                                    connection_.endpoint.kind == TransportKind::SpiBus);
        const bool transport_connected = (transport_ && transport_->is_open());
        if (!i2c_connected && !spi_connected && !transport_connected) {
            scan_.running = false;
            scan_.status = "No device";
            const bool i2c_expected = (connection_.endpoint.kind == TransportKind::I2cBus ||
                                       connection_.device_kind == DeviceKind::NFCUnit ||
                                       connection_.device_kind == DeviceKind::GroveNFC);
            const bool spi_expected = (connection_.endpoint.kind == TransportKind::SpiBus);
            scan_.error = spi_expected  ? "Connect SPI device first"
                        : i2c_expected  ? "Connect I2C device first"
                                        : "Connect USB/UART first";
            return false;
        }
        if (scan_.running) return false;

        scan_.running = true;
        scan_.has_result = false;
        scan_.status = "Scanning";
        scan_.error.clear();
        last_dump_success_ = false;
        uhf_continuous_mode_ = false;
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }

        if (connection_.device_kind == DeviceKind::UHFReader) {
            scan_.status = "UHF scan";
            scan_thread_ = std::thread([this]() { perform_uhf_scan_worker(false); });
        } else {
            scan_thread_ = std::thread([this]() { perform_scan(); });
        }
        return true;
    }

    bool connect_and_scan(std::string *status = nullptr)
    {
        const auto state = connection_state();
        if (!state.connected) {
            if (!connect_current()) {
                if (status) *status = "Connect failed";
                return false;
            }
        }

        if (!start_scan()) {
            const auto scan = scan_state();
            if (status) *status = scan.error.empty() ? scan.status : scan.error;
            return false;
        }

        if (status) *status = "Scanning card...";
        return true;
    }

    // ── SPI Gen1A detection + dump (blocking, call on automation thread) ──────
    // Requires SPI to already be connected via select_spi_endpoint + connect_current.
    // Scans card, checks Gen1A backdoor, optionally dumps all 64 blocks.
    // Returns false on any failure; out_blocks may be nullptr for detect-only.
    bool spi_scan_gen1a(std::vector<std::vector<uint8_t>> *out_blocks,
                        I2cCardInfo *out_info,
                        std::string *error)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!spi_device_ || !spi_device_->is_open()) {
            if (error) *error = "SPI not connected";
            return false;
        }
        return spi_device_->scan_and_dump_gen1a(out_info, out_blocks, error);
    }

    // ── SPI passive-target (EMU) control ─────────────────────────────────────
    // All methods require SPI to be connected.

    bool spi_start_current_profile(std::string *error = nullptr)
    {
        int profile = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!spi_device_ || !spi_device_->is_open()) {
                if (error) *error = "SPI not connected";
                return false;
            }
            profile = spi_emu_profile_;
            selected_emulator_protocol_ = spi_profile_protocol_for_index(profile);
        }

        std::vector<uint8_t> uid;
        uint16_t atqa = 0;
        uint8_t sak = 0;
        if (!spi_profile_params_for_index(profile, &uid, &atqa, &sak)) {
            if (error) *error = "Unknown SPI profile";
            return false;
        }
        return spi_start_listener_a(uid, atqa, sak, error);
    }

    bool spi_start_iso15693_emulation(std::string *error = nullptr)
    {
        stop_spi_emulation_worker(true);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!spi_device_ || !spi_device_->is_open()) {
                if (error) *error = "SPI not connected";
                return false;
            }
        }

        push_log("[SPI] ISO15693 emulation unsupported: transparent listener requires MCU GPIO timing");
        if (error) *error = "SPI ISO15693 emulation requires transparent GPIO timing";
        return false;
    }

    bool spi_supports_iso15693_emulation() const
    {
        return false;
    }

    static std::string spi_iso15693_emulation_reason()
    {
        return "transparent_gpio_timing_required";
    }

    std::string spi_caps_status_line() const
    {
        std::ostringstream oss;
        oss << "spi_caps"
            << " nfca_emu=1"
            << " mfc1k=1"
            << " ntag215=1"
            << " ntag216=1"
            << " iso15693_emu=" << (spi_supports_iso15693_emulation() ? 1 : 0)
            << " iso15693_reason=" << spi_iso15693_emulation_reason();
        return oss.str();
    }

    bool spi_start_listener_a(const std::vector<uint8_t> &uid, uint16_t atqa, uint8_t sak,
                              std::string *error = nullptr)
    {
        stop_spi_emulation_worker(true);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!spi_device_ || !spi_device_->is_open()) {
                if (error) *error = "SPI not connected";
                return false;
            }
            if (!spi_device_->start_listener_a(uid, atqa, sak, error)) {
                return false;
            }
            spi_emu_uid_ = uid;
            spi_emu_atqa_ = atqa;
            spi_emu_sak_ = sak;
        }

        spi_emu_cancel_.store(false);
        spi_emu_thread_ = std::thread([this]() { spi_listener_worker(); });
        return true;
    }

    void spi_stop_listener()
    {
        stop_spi_emulation_worker(true);
    }

    bool spi_listener_active() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return spi_device_ && spi_device_->listener_active();
    }

    bool can_dump_last_scan(std::string *error = nullptr) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (scan_.running) {
            if (error) *error = "Operation already running";
            return false;
        }
        if (connection_.device_kind == DeviceKind::UHFReader) {
            if (error) *error = "UHF reader does not support NFC dump";
            return false;
        }
        if (!scan_.has_result) {
            if (error) *error = "Scan card first";
            return false;
        }
        if (connection_.endpoint.kind == TransportKind::I2cBus) {
            if (!i2c_device_ || !i2c_device_->is_open()) {
                if (error) *error = "I2C device not open";
                return false;
            }
            const auto p = scan_.last_record.tag.protocol;
            if (p != ProtocolKind::MifareClassic &&
                p != ProtocolKind::Iso14443A &&
                p != ProtocolKind::Iso15693) {
                if (error) *error = "I2C dump supports MFC/MFU/ISO15693 only";
                return false;
            }
            return true;
        }
        if (connection_.endpoint.kind == TransportKind::SpiBus) {
            if (!spi_device_ || !spi_device_->is_open()) {
                if (error) *error = "SPI device not open";
                return false;
            }
            const auto p = scan_.last_record.tag.protocol;
            if (p != ProtocolKind::MifareClassic && p != ProtocolKind::Iso14443A) {
                if (error) *error = "SPI dump supports MFC/MFU only";
                return false;
            }
            return true;
        }
        if (!transport_ || !transport_->is_open()) {
            if (error) *error = "Connect device first";
            return false;
        }
        if (connection_.device_kind == DeviceKind::PN532 &&
            scan_.last_record.tag.protocol == ProtocolKind::Iso15693) {
            if (error) *error = "PN532 ISO15693 read not supported";
            return false;
        }
        return true;
    }

    bool start_dump_last_scan()
    {
        stop_pn532_ndef_emulation();
        if (scan_thread_.joinable()) scan_thread_.join();
        // Cancel any running EMU probe/dump threads to avoid racing set_work_mode calls
        cancel_emu_probe_.store(true);
        if (emu_probe_thread_.joinable()) emu_probe_thread_.join();
        cancel_emu_probe_.store(false);
        cancel_emu_dump_.store(true);
        if (emu_dump_thread_.joinable()) emu_dump_thread_.join();
        cancel_emu_dump_.store(false);

        std::string precheck_error;
        if (!can_dump_last_scan(&precheck_error)) {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.status = "Dump unavailable";
            scan_.error = precheck_error;
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = true;
            scan_.status = "Dumping";
            scan_.error.clear();
            last_dump_success_ = false;
        }
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            pending_log_lines_.clear();
        }

        scan_thread_ = std::thread([this]() { perform_dump_from_last_scan(); });
        return true;
    }

    bool can_save_last_dump(std::string *error = nullptr) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!scan_.has_result) {
            if (error) *error = "No scan result to save";
            return false;
        }
        if (!last_dump_success_) {
            if (error) *error = "Dump card first";
            return false;
        }
        if (scan_.last_record.tag.raw_data.empty()) {
            if (error) *error = "No dump data to save";
            return false;
        }
        return true;
    }

    bool save_last_scan(std::string *error = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!scan_.has_result) {
            if (error) *error = "No scan result to save";
            return false;
        }
        if (!last_dump_success_) {
            if (error) *error = "Dump card first";
            return false;
        }
        if (scan_.last_record.tag.raw_data.empty()) {
            if (error) *error = "No dump data to save";
            return false;
        }
        return storage_.save_record(scan_.last_record, error);
    }

    bool delete_saved_record(const std::string &record_id, std::string *error = nullptr)
    {
        return storage_.delete_record(record_id, error);
    }

    std::vector<MifareKeyRecord> list_mifare_keys() const
    {
        return storage_.load_mifare_keys();
    }

    bool upsert_mifare_key(int index, const MifareKeyRecord &record, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        MifareKeyRecord normalized = record;
        normalized.key_hex = normalize_mifare_key_hex(record.key_hex);
        if (normalized.key_hex.size() != 12) {
            if (err) *err = "Key must be 12 hex chars";
            return false;
        }
        if (normalized.label.empty()) {
            normalized.label = std::string("Key ") + normalized.key_hex.substr(8, 4);
        }
        if (normalized.created_at.empty()) normalized.created_at = iso8601_now();
        if (normalized.source.empty()) normalized.source = "manual";

        if (index < 0 || index >= static_cast<int>(keys.size())) keys.push_back(normalized);
        else keys[index] = normalized;

        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    bool delete_mifare_key(int index, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        if (index < 0 || index >= static_cast<int>(keys.size())) {
            if (err) *err = "Key not found";
            return false;
        }
        keys.erase(keys.begin() + index);
        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    bool toggle_mifare_key_enabled(int index, std::string *err = nullptr)
    {
        auto keys = storage_.load_mifare_keys();
        if (index < 0 || index >= static_cast<int>(keys.size())) {
            if (err) *err = "Key not found";
            return false;
        }
        keys[index].enabled = !keys[index].enabled;
        if (!storage_.save_mifare_keys(keys)) {
            if (err) *err = "Failed to save keys";
            return false;
        }
        return true;
    }

    // ── Key dictionary file service ──────────────────────────────────────────

    std::vector<std::string> list_key_files() const
    {
        return storage_.list_key_files();
    }

    std::vector<std::string> load_key_file(const std::string &filename) const
    {
        return storage_.load_key_file(filename);
    }

    bool save_key_file(const std::string &filename,
                       const std::vector<std::string> &keys,
                       std::string *err = nullptr) const
    {
        return storage_.save_key_file(filename, keys, err);
    }

    // Save keys from a SavedRecord's raw_data (MFC sector trailers) to <uid>.dic.
    bool save_keys_from_record(const SavedRecord &rec, std::string *err = nullptr) const
    {
        const std::string uid = rec.tag.uid.empty() ? rec.meta.record_id : rec.tag.uid;
        return storage_.save_uid_key_file(uid, rec.tag.raw_data, err);
    }

    // ── MFKey async crack ────────────────────────────────────────────────────

    struct MfkeyResult {
        uint32_t uid;
        uint8_t  sector;
        uint8_t  key_type; // 0=A, 1=B
        std::string key_hex; // empty if not found
    };

    struct NfcUnitMfkeyEntry {
        uint32_t uid = 0;
        uint32_t nt = 0;
        uint32_t nr = 0;
        uint32_t ar = 0;
        uint8_t sector = 0;
        uint8_t key_type = 0; // 0=A, 1=B
    };

    static uint32_t read_le_u32(const uint8_t *p)
    {
        if (!p) return 0;
        return static_cast<uint32_t>(p[0]) |
               (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    }

    static uint16_t bswap16_u16(uint16_t value)
    {
        return static_cast<uint16_t>((value >> 8) | (value << 8));
    }

    static uint16_t mfclassic_weak_prng_step16(uint16_t value)
    {
        return static_cast<uint16_t>(
            (value >> 1) |
            (((value ^ (value >> 2) ^ (value >> 3) ^ (value >> 5)) & 0x01u) << 15));
    }

    // Match Flipper's weak-PRNG nonce shape used by MIFARE Classic.
    static bool mfclassic_is_weak_prng_nonce(uint32_t nonce)
    {
        if (nonce == 0) return false;
        uint16_t x = static_cast<uint16_t>(nonce >> 16);
        x = bswap16_u16(x);
        for (uint8_t i = 0; i < 16; ++i) {
            x = mfclassic_weak_prng_step16(x);
        }
        x = bswap16_u16(x);
        return x == static_cast<uint16_t>(nonce & 0xFFFFu);
    }

    static uint32_t mfclassic_make_weak_nonce(uint16_t *state)
    {
        if (!state) return 0;
        const uint16_t upper_raw = *state;
        uint16_t lower_raw = upper_raw;
        for (uint8_t i = 0; i < 16; ++i) {
            lower_raw = mfclassic_weak_prng_step16(lower_raw);
        }
        *state = mfclassic_weak_prng_step16(upper_raw);
        return (static_cast<uint32_t>(bswap16_u16(upper_raw)) << 16) |
               static_cast<uint32_t>(bswap16_u16(lower_raw));
    }

    static uint8_t mfc_block_to_sector(uint8_t block)
    {
        if (block < 128) return static_cast<uint8_t>(block / 4);
        return static_cast<uint8_t>(32 + ((block - 128) / 16));
    }

    void stop_nfcunit_mfkey_sniffer(bool reset_reader_mode)
    {
        nfc_unit_mfkey_sniff_cancel_.store(true);
        if (nfc_unit_mfkey_sniff_thread_.joinable()) {
            nfc_unit_mfkey_sniff_thread_.join();
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (reset_reader_mode && i2c_device_ && i2c_device_->is_open()) {
            if (i2c_device_->is_nfc_unit()) {
                i2c_device_->nfcunit_stop_listener();
            } else {
                i2c_device_->writeMiscReg(i2c_reg::MISC_THRU, 0x00);
                i2c_device_->stopEmulation();
            }
        }
        nfc_unit_mfkey_sniff_running_.store(false);
    }

    void nfcunit_mfkey_sniff_worker(uint32_t uid)
    {
        NfcHexLog::get().log_event("mfkey32v2", "NFCUnit sniff worker started");

        uint16_t weak_nonce_state = static_cast<uint16_t>(std::random_device{}());
        uint32_t last_nt = 0;
        bool pending_auth = false;
        uint8_t pending_sector = 0;
        uint8_t pending_key_type = 0;
        uint32_t pending_nt = 0;

        while (!nfc_unit_mfkey_sniff_cancel_.load()) {
            I2cGroveNfcDevice *dev = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dev = i2c_device_.get();
            }

            if (!dev || !dev->is_open() || !dev->is_nfc_unit()) break;

            std::vector<uint8_t> frame;
            if (!dev->nfcunit_poll_listener_frame(frame, 25)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }

            NfcHexLog::get().log_rx("MFKEY-I2C", frame.data(), frame.size());

            if (frame.size() >= 2 && (frame[0] == 0x60 || frame[0] == 0x61)) {
                pending_auth = true;
                pending_sector = mfc_block_to_sector(frame[1]);
                pending_key_type = (frame[0] == 0x61) ? 1 : 0;
                pending_nt = mfclassic_make_weak_nonce(&weak_nonce_state);
                if (pending_nt == 0 || pending_nt == last_nt || !mfclassic_is_weak_prng_nonce(pending_nt)) {
                    pending_nt = mfclassic_make_weak_nonce(&weak_nonce_state);
                }
                if (pending_nt == 0) {
                    // Keep a valid weak nonce fallback for atypical RNG edge cases.
                    pending_nt = 0x1AD31AD3;
                }
                last_nt = pending_nt;

                uint8_t nt_resp[4] = {
                    static_cast<uint8_t>(pending_nt & 0xFF),
                    static_cast<uint8_t>((pending_nt >> 8) & 0xFF),
                    static_cast<uint8_t>((pending_nt >> 16) & 0xFF),
                    static_cast<uint8_t>((pending_nt >> 24) & 0xFF),
                };
                dev->nfcunit_send_listener_frame(nt_resp, sizeof(nt_resp));
                NfcHexLog::get().log_tx("MFKEY-I2C", nt_resp, sizeof(nt_resp));
                continue;
            }

            if (pending_auth && frame.size() >= 8) {
                NfcUnitMfkeyEntry e;
                e.uid = uid;
                e.nt = pending_nt;
                e.nr = read_le_u32(frame.data());
                e.ar = read_le_u32(frame.data() + 4);
                e.sector = pending_sector;
                e.key_type = pending_key_type;

                {
                    std::lock_guard<std::mutex> lk(nfc_unit_mfkey_mutex_);
                    nfc_unit_mfkey_entries_.push_back(e);
                }

                char line[96];
                std::snprintf(line, sizeof(line), "NFCUnit nonce s%u%c nt=%08X nr=%08X ar=%08X",
                              static_cast<unsigned>(e.sector), e.key_type ? 'B' : 'A',
                              e.nt, e.nr, e.ar);
                NfcHexLog::get().log_event("mfkey32v2", line);

                uint8_t at_resp[4] = {0, 0, 0, 0};
                dev->nfcunit_send_listener_frame(at_resp, sizeof(at_resp));
                NfcHexLog::get().log_tx("MFKEY-I2C", at_resp, sizeof(at_resp));

                pending_auth = false;
            }
        }

        nfc_unit_mfkey_sniff_running_.store(false);
        NfcHexLog::get().log_event("mfkey32v2", "NFCUnit sniff worker stopped");
    }

    bool start_nfcunit_mfkey_sniffer(std::string *error = nullptr)
    {
        // Best-effort stop stale worker before a new sniff session.
        nfc_unit_mfkey_sniff_cancel_.store(true);
        if (nfc_unit_mfkey_sniff_thread_.joinable()) {
            nfc_unit_mfkey_sniff_thread_.join();
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
            if (error) *error = "NFC Unit not connected";
            return false;
        }

        std::string uid_hex = mfkey_sniff_uid_hex_;
        if (uid_hex.size() < 8) uid_hex = "11223344";
        uid_hex = keep_hex_chars_upper(uid_hex);
        if (uid_hex.size() < 8) uid_hex = "11223344";
        uid_hex = uid_hex.substr(0, 8);

        uint8_t uid[4] = {};
        for (int i = 0; i < 4; ++i) {
            uid[i] = static_cast<uint8_t>(std::stoul(uid_hex.substr(i * 2, 2), nullptr, 16));
        }
        const uint32_t uid_u32 = static_cast<uint32_t>(std::stoul(uid_hex, nullptr, 16));

        const std::vector<uint8_t> uid_vec = {uid[0], uid[1], uid[2], uid[3]};
        const bool emu_ok = i2c_device_->nfcunit_start_listener_a(uid_vec, kNfcUnitMfc1kAtqa, kNfcUnitMfc1kSak);
        if (!emu_ok) {
            if (error) *error = "NFC Unit listener init failed";
            return false;
        }

        {
            std::lock_guard<std::mutex> lk(nfc_unit_mfkey_mutex_);
            nfc_unit_mfkey_entries_.clear();
        }
        nfc_unit_mfkey_uid_ = uid_u32;
        nfc_unit_mfkey_sniff_cancel_.store(false);
        nfc_unit_mfkey_sniff_running_.store(true);
        nfc_unit_mfkey_sniff_thread_ = std::thread([this, uid_u32]() {
            nfcunit_mfkey_sniff_worker(uid_u32);
        });

        if (error) error->clear();
        return true;
    }

    // Synchronously set sniffer slot UID from 8-char hex string (e.g. "DEADBEEF").
    // Builds block0: uid[4] + BCC[1] + SAK(0x08)[1] + ATQA(0x04,0x00)[2] + pad[8]
    bool hw_sniff_set_uid(const std::string &uid_hex)
    {
        if (uid_hex.size() < 8) return false;
        {
            char msg[32];
            std::snprintf(msg, sizeof(msg), "set sniffer UID: %s", uid_hex.substr(0, 8).c_str());
            NfcHexLog::get().log_event("mfkey32v2", msg);
        }
        uint8_t uid[4];
        for (int i = 0; i < 4; ++i) {
            uid[i] = static_cast<uint8_t>(std::stoul(uid_hex.substr(i * 2, 2), nullptr, 16));
        }
        uint8_t block0[16] = {};
        block0[0] = uid[0]; block0[1] = uid[1]; block0[2] = uid[2]; block0[3] = uid[3];
        block0[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]; // BCC
        block0[5] = 0x08; // SAK MFC 1K
        block0[6] = 0x04; block0[7] = 0x00; // ATQA
        // bytes 8-15 remain 0

        INfcTransport *transport_raw = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            kind = connection_.device_kind;
            mfkey_sniff_uid_hex_ = keep_hex_chars_upper(uid_hex.substr(0, 8));
        }

        if (kind == DeviceKind::NFCUnit) {
            return true;
        }

        if (!transport_raw || !transport_raw->is_open()) return false;
        Pn532KillerClient client(transport_raw);
        return client.sniff_set_uid(block0);
    }

    // Synchronously enter sniffer mode on the device.
    // with_card=false → mfkey32v2 (no-card), with_card=true → mfkey64 (card-present)
    bool hw_sniff_enter_mode(bool with_card)
    {
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2",
                                   with_card ? "enter card-present sniffer mode" : "enter no-card sniffer mode");
        INfcTransport *transport_raw = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            kind = connection_.device_kind;
        }

        if (kind == DeviceKind::NFCUnit) {
            if (with_card) {
                NfcHexLog::get().log_event("mfkey64", "NFCUnit does not support card-present mfkey64 flow");
                return false;
            }
            std::string err;
            const bool ok = start_nfcunit_mfkey_sniffer(&err);
            if (!ok && !err.empty()) NfcHexLog::get().log_event("mfkey32v2", err.c_str());
            return ok;
        }

        if (!transport_raw || !transport_raw->is_open()) return false;
        Pn532KillerClient client(transport_raw);
        return client.sniff_enter_mode(with_card);
    }

    bool hw_start_mfkey_async(bool with_card)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        if (hw_mfkey_running_) return false;
        cancel_hw_mfkey_.store(false);
        hw_mfkey_running_  = true;
        hw_mfkey_progress_ = 0;
        hw_mfkey_results_.clear();
        hw_mfkey_thread_ = std::thread([this, with_card]() {
            perform_hw_mfkey(with_card);
        });
        hw_mfkey_thread_.detach();
        return true;
    }

    bool hw_mfkey_running() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_running_;
    }

    int hw_mfkey_progress() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_progress_;
    }

    std::vector<MfkeyResult> hw_mfkey_results() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        return hw_mfkey_results_;
    }

    // Import a cracked MFKey result into the internal MIFARE keys JSON.
    bool import_mfkey_result(const MfkeyResult &res, std::string *err = nullptr)
    {
        if (res.key_hex.size() != 12) { if (err) *err = "No key"; return false; }
        MifareKeyRecord rec;
        char buf[64];
        std::snprintf(buf, sizeof(buf), "MFKey s%02u%c",
                      static_cast<unsigned>(res.sector), res.key_type == 0 ? 'A' : 'B');
        rec.label    = buf;
        rec.key_hex  = res.key_hex;
        rec.type     = (res.key_type == 0) ? MifareKeyType::KeyA : MifareKeyType::KeyB;
        rec.enabled  = true;
        rec.source   = "mfkey";
        return upsert_mifare_key(-1, rec, err);
    }

    std::vector<SavedRecord> list_saved_records() const
    {
        return storage_.list_records();
    }

    std::vector<EmulatorSlotRecord> emulator_slots() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(selected_emulator_protocol_);
    }

    std::vector<EmulatorSlotRecord> emulator_slots_padded(ProtocolKind protocol) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(protocol);
    }

    void cycle_slot(int delta)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &selected_slot = selected_slot_by_protocol_[selected_emulator_protocol_];
        selected_slot = (selected_slot + delta + 8) % 8;
    }

    int selected_slot_index() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = selected_slot_by_protocol_.find(selected_emulator_protocol_);
        return it == selected_slot_by_protocol_.end() ? 0 : it->second;
    }

    int selected_slot_index_for_protocol(ProtocolKind protocol) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = selected_slot_by_protocol_.find(protocol);
        return it == selected_slot_by_protocol_.end() ? 0 : it->second;
    }

    ProtocolKind current_emulator_protocol() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return selected_emulator_protocol_;
    }

    static ProtocolKind nfcunit_profile_protocol_for_index(int profile)
    {
        switch (profile) {
        case 1: return ProtocolKind::Iso15693;
        case 0:
        default:
            return ProtocolKind::Iso14443A;
        }
    }

    static ProtocolKind spi_profile_protocol_for_index(int profile)
    {
        switch (profile) {
        case 0: return ProtocolKind::MifareClassic;
        case 1:
        case 2:
            return ProtocolKind::Iso14443A;
        default:
            return ProtocolKind::MifareClassic;
        }
    }

    static bool spi_profile_params_for_index(int profile,
                                             std::vector<uint8_t> *uid,
                                             uint16_t *atqa,
                                             uint8_t *sak)
    {
        if (!uid || !atqa || !sak) return false;
        switch (profile) {
        case 0: // MFC1K
            *uid = {0x04, 0xA1, 0xB2, 0xC3};
            *atqa = 0x0004;
            *sak = 0x08;
            return true;
        case 1: // NTAG215
            *uid = {0x04, 0x51, 0x22, 0x33, 0x44, 0x55, 0x66};
            *atqa = 0x0044;
            *sak = 0x00;
            return true;
        case 2: // NTAG216
            *uid = {0x04, 0x52, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5};
            *atqa = 0x0044;
            *sak = 0x00;
            return true;
        default:
            return false;
        }
    }

    bool set_spi_profile_index(int profile)
    {
        if (profile < 0 || profile > 2) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        spi_emu_profile_ = profile;
        selected_emulator_protocol_ = spi_profile_protocol_for_index(spi_emu_profile_);
        return true;
    }

    int spi_profile_index() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return spi_emu_profile_;
    }

    void toggle_spi_profile()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        spi_emu_profile_ = (spi_emu_profile_ + 1) % 3;
        selected_emulator_protocol_ = spi_profile_protocol_for_index(spi_emu_profile_);
    }

    std::string spi_profile_label() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return spi_profile_label_for_index(spi_emu_profile_);
    }

    static std::string spi_profile_label_for_index(int profile)
    {
        switch (profile) {
        case 0: return "MFC 1K";
        case 1: return "NTAG215";
        case 2: return "NTAG216";
        default: return "MFC 1K";
        }
    }

    bool set_nfcunit_profile_index(int profile)
    {
        if (profile < 0 || profile > 1) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        nfc_unit_emu_profile_ = profile;
        selected_emulator_protocol_ = nfcunit_profile_protocol_for_index(nfc_unit_emu_profile_);
        return true;
    }

    int nfcunit_profile_index() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return nfc_unit_emu_profile_;
    }

    void toggle_slot_protocol()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (selected_emulator_protocol_ == ProtocolKind::Iso14443A) selected_emulator_protocol_ = ProtocolKind::Iso14443B;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso14443B) selected_emulator_protocol_ = ProtocolKind::Iso15693;
        else if (selected_emulator_protocol_ == ProtocolKind::Iso15693) selected_emulator_protocol_ = ProtocolKind::MifareClassic;
        else selected_emulator_protocol_ = ProtocolKind::Iso14443A;
    }

    void toggle_nfcunit_profile_protocol()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        nfc_unit_emu_profile_ = (nfc_unit_emu_profile_ + 1) % 2;
        selected_emulator_protocol_ = nfcunit_profile_protocol_for_index(nfc_unit_emu_profile_);
    }

    bool start_nfcunit_current_profile_emulation(std::string *error = nullptr)
    {
        stop_nfcunit_emulation_worker(false);

        ProtocolKind protocol = ProtocolKind::Iso14443A;
        int profile = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            profile = nfc_unit_emu_profile_;
            protocol = nfcunit_profile_protocol_for_index(profile);
            selected_emulator_protocol_ = protocol;

            std::string reset_err;
            if (!nfcunit_power_cycle_and_reopen_locked(&reset_err)) {
                if (error) *error = reset_err.empty() ? "NFC Unit power-cycle failed" : reset_err;
                return false;
            }
            nfc_unit_emu_profile_ = profile;
            selected_emulator_protocol_ = protocol;
        }
        if (protocol == ProtocolKind::Iso14443A || protocol == ProtocolKind::Iso15693) {
            (void)i2c_emulator_dump_lines(protocol);
            reload_i2c_profile_from_cache(protocol);
        }
        return grovenfc_activate(protocol, 0, error);
    }

    bool start_nfcunit_current_profile_emulation_no_reopen(std::string *error = nullptr)
    {
        stop_nfcunit_emulation_worker(false);

        ProtocolKind protocol = ProtocolKind::Iso14443A;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            protocol = nfcunit_profile_protocol_for_index(nfc_unit_emu_profile_);
            selected_emulator_protocol_ = protocol;
        }

        if (protocol == ProtocolKind::Iso14443A || protocol == ProtocolKind::Iso15693) {
            (void)i2c_emulator_dump_lines(protocol);
            reload_i2c_profile_from_cache(protocol);
        }

        if (protocol == ProtocolKind::Iso14443A) {
            return start_nfcunit_ntag_emulation_unlocked(error);
        }
        if (protocol == ProtocolKind::Iso15693) {
            return start_nfcunit_iso15693_emulation_unlocked(error);
        }
        if (error) *error = "NFC Unit does not support this protocol for emulation";
        return false;
    }

    bool start_nfcunit_current_profile_emulation_async()
    {
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            if (nfc_unit_emu_start_running_) return false;
        }
        if (nfc_unit_emu_start_thread_.joinable()) nfc_unit_emu_start_thread_.join();
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            nfc_unit_emu_start_running_ = true;
            nfc_unit_emu_start_has_result_ = false;
            nfc_unit_emu_start_ok_ = false;
            nfc_unit_emu_start_status_ = "starting";
            nfc_unit_emu_start_error_.clear();
            nfc_unit_emu_start_profile_ = nfcunit_profile_label();
        }
        std::fprintf(stderr, "[NFC-EMU-START] queued profile=%s\n", nfcunit_profile_label().c_str());
        nfc_unit_emu_start_thread_ = std::thread([this]() {
            perform_nfcunit_emu_start_worker();
        });
        return true;
    }

    NfcUnitEmuStartState nfcunit_emu_start_state() const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        NfcUnitEmuStartState state;
        state.running = nfc_unit_emu_start_running_;
        state.has_result = nfc_unit_emu_start_has_result_;
        state.ok = nfc_unit_emu_start_ok_;
        state.status = nfc_unit_emu_start_status_;
        state.error = nfc_unit_emu_start_error_;
        state.profile = nfc_unit_emu_start_profile_;
        return state;
    }

    std::string nfcunit_profile_label() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return nfcunit_profile_label_for_index(nfc_unit_emu_profile_);
    }

    static std::string nfcunit_profile_label_for_index(int profile)
    {
        switch (profile) {
        case 0: return "NTAG213";
        case 1: return "ISO15693";
        default: return "NTAG213";
        }
    }

    std::string nfcunit_ndef_uri() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return nfc_unit_ndef_uri_;
    }

    void set_nfcunit_ndef_uri(const std::string &uri)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        nfc_unit_ndef_uri_ = uri.empty() ? "https://m5stack.com" : uri;
    }

    // Generate NTAG213 NDEF pages from a URI and save to the GroveNFC emulator JSON.
    bool set_grove_ntag_ndef_uri(const std::string &uri)
    {
        const std::string safe_uri = uri.empty() ? "https://m5stack.com" : uri;
        const size_t pages = 45; // NTAG213
        auto mem = default_nfcunit_ntag_memory(pages, safe_uri);
        // Write to both the display JSON (ntag213_0.json) and the binary default dump
        // that grovenfc_activate→writeEmulationDefaultDump reads.
        bool ok = storage_.save_emulator_json_from_ntag_pages(mem);
        storage_.save_emulator_default_dump(ProtocolKind::Iso14443A, mem);
        // Invalidate the in-memory cache so the EMU tab reloads from JSON
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_slot_cache_.erase({ProtocolKind::Iso14443A, 0});
        }
        return ok;
    }

    bool emulation_allowed(std::string *reason = nullptr) const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (connection_.connected && (connection_.device_kind == DeviceKind::PN532Killer ||
                                      connection_.device_kind == DeviceKind::PN532 ||
                                      connection_.device_kind == DeviceKind::GroveNFC ||
                                      connection_.device_kind == DeviceKind::NFCUnit ||
                                      connection_.device_kind == DeviceKind::ST25RNFC)) {
            return true;
        }
        if (reason) {
            *reason = "PN532/PN532Killer/GroveNFC/NFCUnit/ST25R\nrequired for EMU";
        }
        return false;
    }

    // Reload the I2C device's profile buffer from the in-memory JSON cache,
    // so that "S" key always activates the same data shown on screen.
    void reload_i2c_profile_from_cache(ProtocolKind protocol)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        auto it = emu_slot_cache_.find({protocol, 0});
        if (it == emu_slot_cache_.end() || !it->second.dump_loaded) return;

        // Build flat byte vector from the formatted dump lines ("00:HEXHEX...")
        std::vector<uint8_t> bytes;
        for (const auto &line : it->second.dump_lines) {
            size_t colon = line.find(':');
            std::string hex = (colon != std::string::npos) ? line.substr(colon + 1) : line;
            std::string pure;
            for (char c : hex) if (std::isxdigit((unsigned char)c)) pure += (char)std::toupper((unsigned char)c);
            for (size_t i = 0; i + 1 < pure.size(); i += 2) {
                char *end = nullptr;
                unsigned long val = std::strtoul(pure.substr(i, 2).c_str(), &end, 16);
                if (end && *end == '\0') bytes.push_back(static_cast<uint8_t>(val));
            }
        }

        // Save to emulator_defaults so the existing writeEmulationDefaultDump()
        // (called by grovenfc_activate) picks up the JSON-sourced data instead
        // of the old hardcoded defaults.
        if (!bytes.empty()) {
            storage_.save_emulator_default_dump(protocol, bytes);
        }

        // Also update profile slot for consistency
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (emulator_slots_by_protocol_.count(protocol)) {
                auto &vec = emulator_slots_by_protocol_[protocol];
                if (!vec.empty()) vec[0].raw_data = it->second.dump_lines;
                storage_.save_emulator_slots_by_protocol(emulator_slots_by_protocol_);
            }
        }

        // Also persist to _0.json so consistency is maintained
        SavedRecord sr;
        sr.tag.protocol = protocol;
        sr.tag.uid = it->second.uid;
        sr.tag.raw_data = it->second.dump_lines;
        storage_.save_emulator_json_from_record(protocol, sr);
    }

    // Reset the active JSON file by copying from default/ directory.
    bool reset_emulator_json_from_default(ProtocolKind protocol)
    {
        // Invalidate cache so next render reloads
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_slot_cache_.erase({protocol, 0});
        }
        bool ok = storage_.reset_emulator_json(protocol);
        push_log(std::string("[Reset] protocol=") + nfc_app::to_string(protocol) + " result=" + (ok ? "OK" : "FAIL"));
        // Also write to persistent operation log
        storage_.append_op_log(std::string("[Reset] ") + (ok ? "OK" : "FAIL") + " protocol=" + nfc_app::to_string(protocol));
        return ok;
    }

    // Activate GroveNFC emulation for the given protocol/slot (GroveNFC 0x48 only).
    bool grovenfc_activate(ProtocolKind protocol, int slot_index, std::string *error = nullptr)
    {
        stop_nfcunit_emulation_worker(false);
        std::lock_guard<std::mutex> lock(mutex_);
        if (!i2c_device_ || !i2c_device_->is_open() ||
            (i2c_device_->device_kind() != DeviceKind::GroveNFC &&
             i2c_device_->device_kind() != DeviceKind::NFCUnit)) {
            if (error) *error = "I2C emulation device not connected";
            return false;
        }
        const int clamped_slot = (slot_index < 0 ? 0 : slot_index > 7 ? 7 : slot_index);

        if (i2c_device_->is_nfc_unit()) {
            if (protocol == ProtocolKind::Iso14443A) {
                return start_nfcunit_ntag_emulation_locked(clamped_slot, error);
            }
            if (protocol == ProtocolKind::Iso15693) {
                return start_nfcunit_iso15693_emulation_locked(error);
            }
            if (error) *error = "NFC Unit does not support this protocol for emulation";
            return false;
        }

        stop_nfcunit_emulation_worker(false);
        i2c_device_->setSlot((uint8_t)clamped_slot);
        i2c_device_->writeMiscReg(0x0020, 0x00);  // MISC_RFON = 0 → stop RF
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        // Write default dump to EEPROM — now sources from emulator_defaults
        // which was refreshed by reload_i2c_profile_from_cache() before this call.
        i2c_device_->writeEmulationDefaultDump(protocol, storage_);

        bool ok = false;
        const char *emu_type = "NTAG";
        switch (protocol) {
        case ProtocolKind::MifareClassic:
            emu_type = "MFC1K";
            ok = i2c_device_->startEmulationMifare1K(); break;
        case ProtocolKind::Iso14443B:
            emu_type = "ISO14B";
            ok = i2c_device_->startEmulationChinaII(); break;
        case ProtocolKind::Iso15693:
            emu_type = "ISO15";
            ok = i2c_device_->startEmulationISO15();   break;
        default:
            ok = i2c_device_->startEmulationNtag213(); break;
        }
        if (!ok) {
            if (error) *error = (std::string("GroveNFC activate failed: ") + emu_type).c_str();
            push_log(std::string("ERR GroveNFC EMU fail: ") + emu_type);
            NfcHexLog::get().log_event("emu", (std::string("FAIL ") + emu_type).c_str());
        } else {
            push_log(std::string("OK GroveNFC EMU: ") + emu_type);
            NfcHexLog::get().log_event("emu", (std::string("OK ") + emu_type).c_str());
        }
        return ok;
    }

    bool grovenfc_deactivate()
    {
        stop_nfcunit_emulation_worker(false);
        std::lock_guard<std::mutex> lock(mutex_);
        if (!i2c_device_ || !i2c_device_->is_open()) return false;
        if (i2c_device_->is_nfc_unit()) {
            const bool ok_listener = i2c_device_->nfcunit_stop_listener();
            const bool ok_mode = i2c_device_->stopEmulation();
            nfc_unit_emu_running_.store(false);
            return ok_listener || ok_mode;
        }
        return i2c_device_->stopEmulation();
    }

    void set_default_slot()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slots = emulator_slots_by_protocol_[selected_emulator_protocol_];
        ensure_protocol_slots_locked(selected_emulator_protocol_);
        const int selected_slot = selected_slot_by_protocol_[selected_emulator_protocol_];
        for (size_t i = 0; i < slots.size(); ++i) {
            slots[i].default_slot = (static_cast<int>(i) == selected_slot);
        }
        save_emulator_slots_locked();
    }

    bool upload_record_to_slot(const SavedRecord &record)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slot = current_slot_for_protocol_locked(record.tag.protocol, selected_slot_by_protocol_[record.tag.protocol]);
        slot.payload_record_id = record.meta.record_id;
        slot.protocol = record.tag.protocol;
        slot.raw_data = record.tag.raw_data;
        return save_emulator_slots_locked();
    }

    // Upload a record to a specific slot index (0-7); auto-expands slots as needed
    bool upload_record_to_slot_n(const SavedRecord &record, int slot_n)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slot = current_slot_for_protocol_locked(record.tag.protocol, slot_n);
        selected_slot_by_protocol_[record.tag.protocol] = slot_n;
        slot.payload_record_id = record.meta.record_id;
        slot.protocol = record.tag.protocol;
        slot.raw_data = record.tag.raw_data;
        return save_emulator_slots_locked();
    }

    bool upload_record_to_profile(ProtocolKind protocol, const SavedRecord &record)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto &slot = current_slot_for_protocol_locked(protocol, 0);
        selected_slot_by_protocol_[protocol] = 0;
        slot.payload_record_id = record.meta.record_id;
        slot.protocol = protocol;
        slot.raw_data = record.tag.raw_data;
        return save_emulator_slots_locked();
    }

    // GrooveNFC / NFCUnit emulation: upload dump to device EEPROM and start emulation.
    // For GroveNFC: writes dump to EEPROM, then calls grovenfc_activate.
    // For NFCUnit: saves dump to RAM buffer, then starts NFCUnit emulation.
    // No slot concept — data is loaded dynamically per protocol.
    bool i2c_emulate(ProtocolKind protocol, const SavedRecord &record, std::string *error = nullptr)
    {
        // Save the record as default dump for this protocol (no lock needed)
        if (!record.tag.raw_data.empty()) {
            std::vector<uint8_t> bytes;
            for (const auto &line : record.tag.raw_data) {
                std::string hex = line;
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    char *end = nullptr;
                    unsigned long val = std::strtoul(hex.substr(i, 2).c_str(), &end, 16);
                    if (end && *end == '\0') bytes.push_back(static_cast<uint8_t>(val));
                }
            }
            storage_.save_emulator_default_dump(protocol, bytes);
        }

        // Also write to rfid/emulator/{protocol}_0.json so EMU tab sees updated data
        storage_.save_emulator_json_from_record(protocol, record);

        // Invalidate EMU cache so next render reloads from the updated JSON
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            emu_slot_cache_.erase({protocol, 0});
        }

        // Also save to emulator slot
        upload_record_to_profile(protocol, record);

        // Check device availability (quick check, no long lock)
        if (!i2c_device_ || !i2c_device_->is_open()) {
            if (error) *error = "I2C device not connected";
            return false;
        }

        // Verify protocol support
        if (i2c_device_->is_nfc_unit()) {
            if (protocol != ProtocolKind::Iso14443A &&
                protocol != ProtocolKind::MifareClassic &&
                protocol != ProtocolKind::Iso15693) {
                if (error) *error = "NFC Unit does not support this protocol for emulation";
                return false;
            }
        } else {
            // GroveNFC 0x48 supports: MFC1K, NTAG21x, ISO14B, ISO15
            if (protocol != ProtocolKind::MifareClassic &&
                protocol != ProtocolKind::Iso14443A &&
                protocol != ProtocolKind::Iso14443B &&
                protocol != ProtocolKind::Iso15693) {
                if (error) *error = "GroveNFC does not support this protocol for emulation";
                return false;
            }
        }

        // Switch protocol and delegate to existing activation (which handles lock)
        selected_emulator_protocol_ = protocol;
        return grovenfc_activate(protocol, 0, error);
    }

    // Returns exactly 8 slots (padded with empty ones if fewer exist)
    std::vector<EmulatorSlotRecord> emulator_slots_padded() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return protocol_slots_padded_locked(selected_emulator_protocol_);
    }

    bool rename_saved_record(const std::string &record_id, const std::string &new_name, std::string *err = nullptr)
    {
        SavedRecord r;
        if (!storage_.load_record_by_id(record_id, &r)) {
            if (err) *err = "Record not found";
            return false;
        }
        r.meta.display_name = new_name;
        return storage_.save_record(r, err);
    }

    bool update_record_hex(const std::string &record_id, const std::vector<std::string> &raw_data, std::string *err = nullptr)
    {
        SavedRecord r;
        if (!storage_.load_record_by_id(record_id, &r)) {
            if (err) *err = "Record not found";
            return false;
        }
        r.tag.raw_data = raw_data;
        return storage_.save_record(r, err);
    }

    bool download_slot_to_saved()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto &slot = current_slot_locked();
        SavedRecord record;
        record.meta.created_at = iso8601_now();
        record.meta.record_id = "emu_slot_" + std::to_string(slot.slot_index) + "_" + record.meta.created_at;
        record.meta.display_name = "Slot " + std::to_string(slot.slot_index) + " Snapshot";
        record.meta.source = "emulator_slot";
        record.meta.transport = TransportKind::Mock;
        record.meta.transport_path = "slot://" + std::to_string(slot.slot_index);
        record.tag.protocol = slot.protocol;
        record.tag.tag_type = "Emulator Slot";
        record.tag.uid = slot.payload_record_id;
        record.tag.raw_data = slot.raw_data;
        record.emulator_slot = slot;
        return storage_.save_record(record, nullptr);
    }

    // Returns true when a full dump for the given (protocol, slot) is cached in memory.
    bool emu_dump_loaded(ProtocolKind protocol, int slot) const
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        auto it = emu_slot_cache_.find({protocol, slot});
        return it != emu_slot_cache_.end() && it->second.dump_loaded;
    }

    // Save the most recently downloaded EMU dump (from memory cache) to permanent storage.
    // Called explicitly by the user via "Save Dump" in the EMU modal.
    bool save_emu_dump_cached(ProtocolKind protocol, int slot, std::string *err = nullptr)
    {
        std::vector<std::string> dump_lines;
        std::string uid;
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            auto it = emu_slot_cache_.find({protocol, slot});
            if (it == emu_slot_cache_.end() || !it->second.dump_loaded) {
                if (err) *err = "No cached dump for this slot";
                return false;
            }
            dump_lines = it->second.dump_lines;
            uid = it->second.uid;
        }
        TagInfo tag;
        tag.protocol = protocol;
        tag.uid = uid;
        for (const auto &line : dump_lines) {
            if (line.size() > 4)
                tag.raw_data.push_back(line.substr(4));
            else
                tag.raw_data.push_back(line);
        }
        TransportEndpoint ep;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ep = connection_.endpoint;
        }
        SavedRecord record;
        record.meta.created_at     = iso8601_now();
        record.meta.record_id      = std::string("emu_dump_") + to_string(protocol)
                                     + "_" + std::to_string(slot)
                                     + "_" + record.meta.created_at;
        record.meta.display_name   = std::string("EMU ") + to_string(protocol)
                                     + " Slot" + std::to_string(slot);
        record.meta.source         = "emu_download";
        record.meta.transport      = ep.kind;
        record.meta.transport_path = ep.path;
        record.tag = tag;
        return storage_.save_record(record, err);
    }

    // For I2C emulation devices (GroveNFC / NFC Unit):
    // build an on-screen dump cache from the selected local slot payload,
    // so UI can keep the same Download -> Save Dump flow as PN532Killer.
    bool cache_i2c_slot_dump(ProtocolKind protocol, int slot, std::string *err = nullptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!connection_.connected) {
            if (err) *err = "EMU device not connected";
            return false;
        }

        const bool i2c_mode = (connection_.endpoint.kind == TransportKind::I2cBus);
        const bool spi_st25r_mode = (connection_.endpoint.kind == TransportKind::SpiBus &&
                                     connection_.device_kind == DeviceKind::ST25RNFC);
        if (!i2c_mode && !spi_st25r_mode) {
            if (err) *err = "I2C/SPI EMU device not connected";
            return false;
        }
        const auto slots = protocol_slots_padded_locked(protocol);
        if (slot < 0 || slot >= static_cast<int>(slots.size())) {
            if (err) *err = "Invalid slot";
            return false;
        }
        const auto &slot_data = slots[slot].raw_data;
        if (slot_data.empty()) {
            if (err) *err = "Selected slot has no payload";
            return false;
        }

        std::vector<std::string> dump_lines;
        dump_lines.reserve(slot_data.size());

        for (size_t i = 0; i < slot_data.size(); ++i) {
            const std::string &line = slot_data[i];
            if (line.size() >= 3 && line[2] == ':') {
                dump_lines.push_back(line);
                continue;
            }
            char prefix[8];
            std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
            dump_lines.push_back(std::string(prefix) + line);
        }

        auto &cache = emu_slot_cache_[{protocol, slot}];
        cache.probed = true;
        cache.dump_lines = std::move(dump_lines);
        cache.dump_loaded = true;

        if (cache.uid.empty() && !cache.dump_lines.empty()) {
            const std::string first = cache.dump_lines.front();
            if (first.size() > 3) cache.uid = first.substr(3, std::min<size_t>(14, first.size() - 3));
        }
        if (err) err->clear();
        return true;
    }

    // Return cached dump lines for the given protocol (I2C/GroveNFC/NFCUnit).
    // Loads from rfid/emulator/{protocol}_0.json; falls back to defaults.
    std::vector<std::string> i2c_emulator_dump_lines(ProtocolKind protocol)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        auto it = emu_slot_cache_.find({protocol, 0});
        if (it != emu_slot_cache_.end() && it->second.dump_loaded)
            return it->second.dump_lines;

        // Try loading structured JSON from rfid/emulator/{protocol}_0.json
        std::string json_path = storage_.emulator_json_path(protocol);
        std::string uid_from_json;
        std::vector<std::string> lines;

        {
            std::ifstream in(json_path.c_str());
            if (in.is_open()) {
                try {
                    nlohmann::json j;
                    in >> j;
                    // Parse UID from card.uid field
                    if (j.contains("card") && j["card"].contains("uid") && j["card"]["uid"].is_string()) {
                        uid_from_json = j["card"]["uid"].get<std::string>();
                    }
                    // Parse blocks: { "0": "04311DA0", "1": "EA1B4503", ... }
                    if (j.contains("blocks") && j["blocks"].is_object()) {
                        const auto &blocks = j["blocks"];
                        // Sort by numeric key
                        std::vector<int> keys;
                        for (auto itb = blocks.begin(); itb != blocks.end(); ++itb) {
                            try { keys.push_back(std::stoi(itb.key())); } catch (...) {}
                        }
                        std::sort(keys.begin(), keys.end());
                        for (int k : keys) {
                            std::string key_str = std::to_string(k);
                            if (blocks.contains(key_str) && blocks[key_str].is_string()) {
                                std::string hex = blocks[key_str].get<std::string>();
                                // Convert to uppercase pure hex
                                std::string pure;
                                for (char c : hex) if (std::isxdigit((unsigned char)c)) pure += (char)std::toupper((unsigned char)c);
                                if (pure.empty()) continue;
                                char prefix[16];
                                std::snprintf(prefix, sizeof(prefix), "%02d:", k);
                                lines.push_back(std::string(prefix) + pure);
                            }
                        }
                    }
                    // Fallback: if no blocks field but data_hex present, chunk it
                    if (lines.empty() && j.contains("data_hex") && j["data_hex"].is_string()) {
                        std::string raw = j["data_hex"].get<std::string>();
                        std::string pure;
                        for (char c : raw) if (std::isxdigit((unsigned char)c)) pure += (char)std::toupper((unsigned char)c);
                        int bytes_per_line = (protocol == ProtocolKind::MifareClassic) ? 16 : 4;
                        for (size_t pos = 0; pos < pure.size(); ) {
                            int n = (int)(pos / 2);
                            char prefix[16];
                            std::snprintf(prefix, sizeof(prefix), "%02d:", n);
                            std::string chunk = pure.substr(pos, bytes_per_line * 2);
                            pos += chunk.size();
                            lines.push_back(std::string(prefix) + chunk);
                        }
                    }
                } catch (...) {
                    push_log("[EMU] Failed to parse emulator JSON, using slot defaults");
                }
            }
        }

        // If JSON loading failed or file doesn't exist, fall back to default slot data
        if (lines.empty()) {
            const auto slots = protocol_slots_padded_locked(protocol);
            if (!slots.empty() && !slots[0].raw_data.empty()) {
                lines.reserve(slots[0].raw_data.size());
                for (size_t i = 0; i < slots[0].raw_data.size(); ++i) {
                    const std::string &line = slots[0].raw_data[i];
                    if (line.size() >= 3 && line[2] == ':') {
                        lines.push_back(line);
                        continue;
                    }
                    char prefix[8];
                    std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
                    lines.push_back(std::string(prefix) + line);
                }
            }
        }

        auto &cache = emu_slot_cache_[{protocol, 0}];
        cache.probed = true;
        cache.dump_lines = std::move(lines);
        cache.dump_loaded = true;
        // Use JSON UID if available, otherwise extract from first dump line
        if (!uid_from_json.empty()) {
            cache.uid = uid_from_json;
        } else if (!cache.dump_lines.empty()) {
            const std::string first = cache.dump_lines.front();
            if (first.size() > 3) cache.uid = first.substr(3, std::min<size_t>(14, first.size() - 3));
        }
        return cache.dump_lines;
    }

private:
    static constexpr size_t kNfcUnitNtag213Pages = 45;

    static bool parse_i2c_endpoint_path(const std::string &path, std::string *bus, uint8_t *addr)
    {
        const auto colon_pos = path.rfind(':');
        if (colon_pos == std::string::npos || colon_pos + 1 >= path.size()) return false;
        std::string bus_path = path.substr(0, colon_pos);
        std::string addr_text = path.substr(colon_pos + 1);
        if (bus_path.empty() || addr_text.empty()) return false;
        try {
            const unsigned long v = std::stoul(addr_text, nullptr, 16);
            if (v > 0x7F) return false;
            if (bus) *bus = bus_path;
            if (addr) *addr = static_cast<uint8_t>(v);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool nfcunit_reopen_i2c_for_worker(std::string *error)
    {
        TransportEndpoint endpoint;
        std::unique_ptr<I2cGroveNfcDevice> old_device;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (connection_.endpoint.kind == TransportKind::I2cBus) {
                endpoint = connection_.endpoint;
            } else if (!endpoints_.empty() && selected_endpoint_ >= 0 && selected_endpoint_ < static_cast<int>(endpoints_.size()) &&
                       endpoints_[selected_endpoint_].kind == TransportKind::I2cBus) {
                endpoint = endpoints_[selected_endpoint_];
            } else {
                if (error) *error = "No I2C endpoint selected";
                return false;
            }
            old_device = std::move(i2c_device_);
            connection_.connected = false;
            connection_.endpoint = endpoint;
            connection_.status = "Connecting NFC Unit";
            connection_.detail = endpoint.path;
            connection_.device_kind = DeviceKind::Unknown;
        }

        if (old_device) old_device->close();

        std::string bus;
        uint8_t addr = 0;
        if (!parse_i2c_endpoint_path(endpoint.path, &bus, &addr)) {
            std::lock_guard<std::mutex> lock(mutex_);
            connection_.connected = false;
            connection_.device_kind = DeviceKind::NotConnected;
            connection_.status = "Connect failed";
            connection_.detail = "Invalid I2C endpoint";
            if (error) *error = connection_.detail;
            return false;
        }

        NfcTransportFactory::grove_gpio_enable_bcm(17, false);
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
        NfcTransportFactory::grove_gpio_enable_bcm(4, true);
        NfcTransportFactory::grove_gpio_enable_bcm(17, true);
        std::this_thread::sleep_for(std::chrono::milliseconds(260));

        auto new_device = std::make_unique<I2cGroveNfcDevice>();
        std::string i2c_error;
        if (!new_device->open(bus, addr, &i2c_error) || !new_device->is_nfc_unit()) {
            std::lock_guard<std::mutex> lock(mutex_);
            connection_.connected = false;
            connection_.device_kind = DeviceKind::NotConnected;
            connection_.status = "Connect failed";
            connection_.detail = i2c_error.empty() ? "NFC Unit not found" : ("I2C open failed: " + i2c_error);
            if (error) *error = connection_.detail;
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            i2c_device_ = std::move(new_device);
            connection_.connected = true;
            connection_.endpoint = endpoint;
            connection_.device_kind = DeviceKind::NFCUnit;
            connection_.pn532_ready = true;
            connection_.status = "Connected NFCUnit";
            connection_.detail = std::string("NFCUnit @") + endpoint.path;
            selected_emulator_protocol_ = nfcunit_profile_protocol_for_index(nfc_unit_emu_profile_);
        }

        if (error) error->clear();
        return true;
    }

    bool nfcunit_power_cycle_and_reopen_locked(std::string *error)
    {
        if (connection_.endpoint.kind != TransportKind::I2cBus ||
            connection_.device_kind != DeviceKind::NFCUnit) {
            if (error) error->clear();
            return true;
        }

        std::string bus;
        uint8_t addr = 0;
        if (!parse_i2c_endpoint_path(connection_.endpoint.path, &bus, &addr)) {
            if (error) *error = "Invalid I2C endpoint";
            return false;
        }

        if (i2c_device_) {
            i2c_device_->close();
            i2c_device_.reset();
        }

        // Equivalent to unplug/replug: power-cycle Grove 5V and keep mux in I2C mode.
        NfcTransportFactory::grove_gpio_enable_bcm(17, false);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        NfcTransportFactory::grove_gpio_enable_bcm(4, true);
        NfcTransportFactory::grove_gpio_enable_bcm(17, true);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        i2c_device_ = std::make_unique<I2cGroveNfcDevice>();
        std::string i2c_error;
        if (!i2c_device_->open(bus, addr, &i2c_error)) {
            connection_.connected = false;
            connection_.device_kind = DeviceKind::NotConnected;
            if (error) *error = std::string("I2C reopen failed: ") + i2c_error;
            return false;
        }

        connection_.connected = true;
        connection_.device_kind = i2c_device_->device_kind();
        connection_.status = std::string("Connected ") + to_string(connection_.device_kind);
        char ver[128];
        std::snprintf(ver, sizeof(ver), "%s @%s",
                  to_string(connection_.device_kind), connection_.endpoint.path.c_str());
        connection_.detail = ver;

        if (error) error->clear();
        return true;
    }

    static std::vector<uint8_t> parse_emulator_line_payload(const std::string &line)
    {
        std::string payload = line;
        const auto colon = payload.find(':');
        if (colon != std::string::npos && colon + 1 < payload.size()) {
            payload = payload.substr(colon + 1);
        }
        std::vector<uint8_t> out;
        if (!parse_hex_bytes(payload, &out)) out.clear();
        return out;
    }

    static size_t nfcunit_ntag_pages_for_profile(int profile)
    {
        (void)profile;
        return kNfcUnitNtag213Pages;
    }

    static uint8_t nfcunit_ntag_cc_size_for_pages(size_t pages)
    {
        (void)pages;
        return 0x12;
    }

    static uint8_t nfcunit_ntag_version_storage_for_pages(size_t pages)
    {
        (void)pages;
        return 0x0F;
    }

    static std::vector<uint8_t> build_ndef_uri_tlv(const std::string &uri_in)
    {
        std::string uri = uri_in.empty() ? "https://m5stack.com" : uri_in;
        uint8_t uri_id = 0x00;
        std::string body = uri;
        if (uri.rfind("https://", 0) == 0) {
            uri_id = 0x04;
            body = uri.substr(8);
        } else if (uri.rfind("http://", 0) == 0) {
            uri_id = 0x03;
            body = uri.substr(7);
        }
        if (body.size() > 120) body.resize(120);

        std::vector<uint8_t> msg;
        msg.reserve(5 + body.size());
        msg.push_back(0xD1);
        msg.push_back(0x01);
        msg.push_back(static_cast<uint8_t>(1 + body.size()));
        msg.push_back(0x55);
        msg.push_back(uri_id);
        msg.insert(msg.end(), body.begin(), body.end());

        std::vector<uint8_t> tlv;
        tlv.reserve(3 + msg.size());
        tlv.push_back(0x03);
        tlv.push_back(static_cast<uint8_t>(msg.size()));
        tlv.insert(tlv.end(), msg.begin(), msg.end());
        tlv.push_back(0xFE);
        return tlv;
    }

    static std::vector<uint8_t> build_ntag213_nfc_forum_area(const std::string &uri)
    {
        std::vector<uint8_t> out = {0x01, 0x03, 0xA0, 0x0C, 0x34};
        const auto ndef = build_ndef_uri_tlv(uri);
        out.insert(out.end(), ndef.begin(), ndef.end());
        return out;
    }

    static std::vector<uint8_t> default_nfcunit_ntag_memory(size_t pages, const std::string &uri)
    {
        std::vector<uint8_t> mem(pages * 4, 0x00);
        const uint8_t uid7[7] = {0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
        const uint8_t bcc0 = static_cast<uint8_t>(0x88 ^ uid7[0] ^ uid7[1] ^ uid7[2]);
        const uint8_t bcc1 = static_cast<uint8_t>(uid7[3] ^ uid7[4] ^ uid7[5] ^ uid7[6]);
        mem[0] = uid7[0]; mem[1] = uid7[1]; mem[2] = uid7[2]; mem[3] = bcc0;
        mem[4] = uid7[3]; mem[5] = uid7[4]; mem[6] = uid7[5]; mem[7] = uid7[6];
        mem[8] = bcc1; mem[9] = 0x48; mem[10] = 0x00; mem[11] = 0x00;
        mem[12] = 0xE1; mem[13] = 0x10; mem[14] = nfcunit_ntag_cc_size_for_pages(pages); mem[15] = 0x00;
        const size_t cfg = (pages - 5) * 4;
        mem[cfg + 0] = 0x00; mem[cfg + 1] = 0x00; mem[cfg + 2] = 0x00; mem[cfg + 3] = 0xBD;
        mem[cfg + 4] = 0x04; mem[cfg + 5] = 0x00; mem[cfg + 6] = 0x00; mem[cfg + 7] = 0xFF;
        mem[cfg + 8] = 0x00; mem[cfg + 9] = 0x05; mem[cfg + 10] = 0x00; mem[cfg + 11] = 0x00;
        mem[cfg + 12] = 0x00; mem[cfg + 13] = 0x00; mem[cfg + 14] = 0x00; mem[cfg + 15] = 0x00;
        mem[cfg + 16] = 0x00; mem[cfg + 17] = 0x00; mem[cfg + 18] = 0x00; mem[cfg + 19] = 0x00;

        const auto tlv = build_ntag213_nfc_forum_area(uri);
        const size_t ndef_start = 16;
        const size_t ndef_end = cfg;
        if (ndef_end > ndef_start) {
            std::fill(mem.begin() + static_cast<ptrdiff_t>(ndef_start),
                      mem.begin() + static_cast<ptrdiff_t>(ndef_end),
                      0x00);
            const size_t copy_len = std::min(tlv.size(), ndef_end - ndef_start);
            std::memcpy(mem.data() + ndef_start, tlv.data(), copy_len);
        }
        return mem;
    }

    static void apply_nfcunit_ntag213_url_layout(std::vector<uint8_t> &mem, size_t pages, const std::string &uri)
    {
        if (pages <= 5 || mem.size() < pages * 4) return;
        const size_t ndef_start = 16;
        const size_t ndef_end = (pages - 5) * 4;
        if (ndef_end <= ndef_start) return;
        const auto area = build_ntag213_nfc_forum_area(uri.empty() ? "https://m5stack.com" : uri);
        std::fill(mem.begin() + static_cast<ptrdiff_t>(ndef_start),
                  mem.begin() + static_cast<ptrdiff_t>(ndef_end),
                  0x00);
        const size_t copy_len = std::min(area.size(), ndef_end - ndef_start);
        std::memcpy(mem.data() + ndef_start, area.data(), copy_len);
    }

    static void apply_slot_dump_to_ntag_memory(const EmulatorSlotRecord &slot, std::vector<uint8_t> &mem)
    {
        const size_t max_pages = mem.size() / 4;
        for (size_t i = 0; i < slot.raw_data.size() && i < max_pages; ++i) {
            std::vector<uint8_t> page = parse_emulator_line_payload(slot.raw_data[i]);
            if (page.size() >= 4) {
                std::memcpy(mem.data() + (i * 4), page.data(), 4);
            }
        }
    }

    static void normalize_nfcunit_ntag213_identity(std::vector<uint8_t> &mem)
    {
        if (mem.size() < 16) return;
        uint8_t uid7[7] = {mem[0], mem[1], mem[2], mem[4], mem[5], mem[6], mem[7]};
        bool all_zero = true;
        for (uint8_t b : uid7) {
            if (b != 0x00) {
                all_zero = false;
                break;
            }
        }
        if (all_zero || uid7[0] != 0x04) {
            const uint8_t def_uid[7] = {0x04, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
            std::memcpy(uid7, def_uid, sizeof(uid7));
            mem[0] = uid7[0]; mem[1] = uid7[1]; mem[2] = uid7[2];
            mem[4] = uid7[3]; mem[5] = uid7[4]; mem[6] = uid7[5]; mem[7] = uid7[6];
        }
        mem[3] = static_cast<uint8_t>(0x88 ^ uid7[0] ^ uid7[1] ^ uid7[2]);
        mem[8] = static_cast<uint8_t>(uid7[3] ^ uid7[4] ^ uid7[5] ^ uid7[6]);
        // Keep page2 byte1 from the loaded dump (do not force 0x48),
        // so NFC Unit profile data matches GroveNFC JSON payload exactly.
    }

    bool start_nfcunit_ntag_emulation_unlocked(std::string *error)
    {
        EmulatorSlotRecord slot_copy;
        size_t pages = kNfcUnitNtag213Pages;
        std::string uri;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            ensure_protocol_slots_locked(ProtocolKind::Iso14443A);
            slot_copy = current_slot_for_protocol_locked(ProtocolKind::Iso14443A, 0);
            pages = nfcunit_ntag_pages_for_profile(nfc_unit_emu_profile_);
            uri = nfc_unit_ndef_uri_;
        }

        auto mem = default_nfcunit_ntag_memory(pages, uri);
        apply_slot_dump_to_ntag_memory(slot_copy, mem);
        apply_nfcunit_ntag213_url_layout(mem, pages, uri);

        normalize_nfcunit_ntag213_identity(mem);
        mem[12] = 0xE1;
        mem[13] = 0x10;
        mem[14] = nfcunit_ntag_cc_size_for_pages(pages);
        mem[15] = 0x00;

        log_i2c_load_payload("NTAG213", mem);

        std::vector<uint8_t> uid = {mem[0], mem[1], mem[2], mem[4], mem[5], mem[6], mem[7]};

        I2cGroveNfcDevice *dev = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            dev = i2c_device_.get();
        }

        if (!dev->nfcunit_start_listener_a(uid, 0x0044, 0x00)) {
            if (error) *error = "NFC Unit NFC-A listener activation failed";
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            nfc_unit_ntag_pages_ = pages;
            nfc_unit_ntag_mem_ = std::move(mem);
            nfc_unit_emu_cancel_.store(false);
            nfc_unit_emu_running_.store(true);
            nfc_unit_emu_protocol_ = ProtocolKind::Iso14443A;
            nfc_unit_emu_thread_ = std::thread([this]() { nfcunit_ntag213_worker(); });
        }

        push_log("[NFCUnit] " + nfcunit_profile_label_for_index(nfc_unit_emu_profile_) + " emulation started");
        if (error) error->clear();
        return true;
    }

    bool start_nfcunit_iso15693_emulation_unlocked(std::string *error)
    {
        I2cGroveNfcDevice *dev = nullptr;
        std::vector<uint8_t> iso15_dump;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            dev = i2c_device_.get();
            iso15_dump = storage_.load_emulator_default_dump(ProtocolKind::Iso15693);
        }

        dev->nfcunit_stop_listener();
        (void)dev->stopEmulation();
        if (!iso15_dump.empty()) {
            log_i2c_load_payload("ISO15693", iso15_dump);
        }
        const bool ok = dev->startEmulationISO15();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            nfc_unit_emu_cancel_.store(false);
            nfc_unit_emu_running_.store(ok);
            nfc_unit_emu_protocol_ = ProtocolKind::Iso15693;
            if (ok) {
                nfc_unit_emu_thread_ = std::thread([this]() { nfcunit_iso15693_keepalive_worker(); });
            }
        }
        if (ok) {
            push_log("[NFCUnit] ISO15693 emulation started");
            if (error) error->clear();
            return true;
        }
        push_log("[NFCUnit] ISO15693 emulation start failed");
        if (error) *error = "NFC Unit ISO15693 emulation start failed";
        return false;
    }

    bool start_nfcunit_mifare_emulation_unlocked(std::string *error)
    {
        I2cGroveNfcDevice *dev = nullptr;
        uint32_t uid_value = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
                if (error) *error = "NFC Unit not connected";
                return false;
            }
            dev = i2c_device_.get();
            uid_value = nfc_unit_mfkey_uid_;
        }

        dev->nfcunit_stop_listener();
        const std::vector<uint8_t> uid = {
            static_cast<uint8_t>((uid_value >> 24) & 0xFF),
            static_cast<uint8_t>((uid_value >> 16) & 0xFF),
            static_cast<uint8_t>((uid_value >> 8) & 0xFF),
            static_cast<uint8_t>(uid_value & 0xFF)
        };
        const bool ok = dev->nfcunit_start_listener_a(uid, kNfcUnitMfc1kAtqa, kNfcUnitMfc1kSak, true);

        {
            std::lock_guard<std::mutex> lock(mutex_);
            nfc_unit_emu_running_.store(ok);
            nfc_unit_emu_protocol_ = ProtocolKind::MifareClassic;
            if (ok) {
                nfc_unit_emu_cancel_.store(false);
                nfc_unit_emu_thread_ = std::thread([this]() { nfcunit_mifare_listener_worker(); });
            }
        }
        if (ok) {
            push_log("[NFCUnit] MFC 1K ID emulation started (UID/SAK/ATQA only)");
            if (error) error->clear();
        } else if (error) {
            *error = "NFC Unit MFC 1K emulation start failed";
        }
        return ok;
    }

    bool start_nfcunit_ntag_emulation_locked(int slot_index, std::string *error)
    {
        ensure_protocol_slots_locked(ProtocolKind::Iso14443A);
        const auto &slot = current_slot_for_protocol_locked(ProtocolKind::Iso14443A, slot_index);
        nfc_unit_ntag_pages_ = nfcunit_ntag_pages_for_profile(nfc_unit_emu_profile_);
        nfc_unit_ntag_mem_ = default_nfcunit_ntag_memory(nfc_unit_ntag_pages_, nfc_unit_ndef_uri_);
        apply_slot_dump_to_ntag_memory(slot, nfc_unit_ntag_mem_);
        apply_nfcunit_ntag213_url_layout(nfc_unit_ntag_mem_, nfc_unit_ntag_pages_, nfc_unit_ndef_uri_);

        normalize_nfcunit_ntag213_identity(nfc_unit_ntag_mem_);
        nfc_unit_ntag_mem_[12] = 0xE1;
        nfc_unit_ntag_mem_[13] = 0x10;
        nfc_unit_ntag_mem_[14] = nfcunit_ntag_cc_size_for_pages(nfc_unit_ntag_pages_);
        nfc_unit_ntag_mem_[15] = 0x00;

        log_i2c_load_payload("NTAG213", nfc_unit_ntag_mem_);

        std::vector<uint8_t> uid = {
            nfc_unit_ntag_mem_[0], nfc_unit_ntag_mem_[1], nfc_unit_ntag_mem_[2],
            nfc_unit_ntag_mem_[4], nfc_unit_ntag_mem_[5], nfc_unit_ntag_mem_[6], nfc_unit_ntag_mem_[7]
        };
        if (!i2c_device_->nfcunit_start_listener_a(uid, 0x0044, 0x00)) {
            if (error) *error = "NFC Unit NFC-A listener activation failed";
            return false;
        }

        nfc_unit_emu_cancel_.store(false);
        nfc_unit_emu_running_.store(true);
        nfc_unit_emu_protocol_ = ProtocolKind::Iso14443A;
        nfc_unit_emu_thread_ = std::thread([this]() { nfcunit_ntag213_worker(); });
        push_log("[NFCUnit] " + nfcunit_profile_label_for_index(nfc_unit_emu_profile_) + " emulation started");
        if (error) error->clear();
        return true;
    }

    bool start_nfcunit_iso15693_emulation_locked(std::string *error)
    {
        if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
            if (error) *error = "NFC Unit not connected";
            return false;
        }
        i2c_device_->nfcunit_stop_listener();
        (void)i2c_device_->stopEmulation();
        const std::vector<uint8_t> iso15_dump = storage_.load_emulator_default_dump(ProtocolKind::Iso15693);
        if (!iso15_dump.empty()) {
            log_i2c_load_payload("ISO15693", iso15_dump);
        }
        const bool ok = i2c_device_->startEmulationISO15();
        nfc_unit_emu_cancel_.store(false);
        nfc_unit_emu_running_.store(ok);
        nfc_unit_emu_protocol_ = ProtocolKind::Iso15693;
        if (ok) {
            nfc_unit_emu_thread_ = std::thread([this]() { nfcunit_iso15693_keepalive_worker(); });
            push_log("[NFCUnit] ISO15693 emulation started");
            if (error) error->clear();
            return true;
        }
        push_log("[NFCUnit] ISO15693 emulation start failed");
        if (error) *error = "NFC Unit ISO15693 emulation start failed";
        return false;
    }

    bool start_nfcunit_mifare_emulation_locked(std::string *error)
    {
        if (!i2c_device_ || !i2c_device_->is_open() || !i2c_device_->is_nfc_unit()) {
            if (error) *error = "NFC Unit not connected";
            return false;
        }
        i2c_device_->nfcunit_stop_listener();
        const std::vector<uint8_t> uid = {
            static_cast<uint8_t>((nfc_unit_mfkey_uid_ >> 24) & 0xFF),
            static_cast<uint8_t>((nfc_unit_mfkey_uid_ >> 16) & 0xFF),
            static_cast<uint8_t>((nfc_unit_mfkey_uid_ >> 8) & 0xFF),
            static_cast<uint8_t>(nfc_unit_mfkey_uid_ & 0xFF)
        };
        const bool ok = i2c_device_->nfcunit_start_listener_a(uid, kNfcUnitMfc1kAtqa, kNfcUnitMfc1kSak, true);
        nfc_unit_emu_running_.store(ok);
        nfc_unit_emu_protocol_ = ProtocolKind::MifareClassic;
        if (ok) {
            nfc_unit_emu_cancel_.store(false);
            nfc_unit_emu_thread_ = std::thread([this]() { nfcunit_mifare_listener_worker(); });
        }
        if (ok) {
            push_log("[NFCUnit] MFC 1K ID emulation started (UID/SAK/ATQA only)");
            if (error) error->clear();
        } else if (error) {
            *error = "NFC Unit MFC 1K emulation start failed";
        }
        return ok;
    }

    bool start_nfcunit_felica_emulation_locked(std::string *error)
    {
        const uint8_t idm[8] = {0x01, 0x2E, 0x50, 0xE5, 0x3C, 0x4B, 0x4F, 0x29};
        const uint8_t pmm[8] = {0x00, 0xF1, 0x00, 0x00, 0x00, 0x01, 0x43, 0x00};
        if (!i2c_device_->nfcunit_start_listener_f(idm, pmm, 0xFFFF)) {
            if (error) *error = "NFC Unit NFC-F listener activation failed";
            return false;
        }
        nfc_unit_emu_cancel_.store(false);
        nfc_unit_emu_running_.store(true);
        nfc_unit_emu_protocol_ = ProtocolKind::Felica;
        nfc_unit_emu_thread_ = std::thread([this]() { nfcunit_felica_worker(); });
        push_log("[NFCUnit] NFC-F emulation started");
        if (error) error->clear();
        return true;
    }

    void perform_nfcunit_emu_start_worker()
    {
        auto set_status = [this](const std::string &status) {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            nfc_unit_emu_start_status_ = status;
        };

        set_status("connecting");
        std::fprintf(stderr, "[NFC-EMU-START] worker connecting\n");
        bool ok = false;
        std::string err;
        if (!nfcunit_reopen_i2c_for_worker(&err)) {
            std::fprintf(stderr, "[NFC-EMU-START] reopen failed err=%s\n", err.c_str());
        } else {
            set_status("starting");
            std::fprintf(stderr, "[NFC-EMU-START] starting listener\n");
            for (int attempt = 0; attempt < 2 && !ok; ++attempt) {
                err.clear();
                ok = start_nfcunit_current_profile_emulation_no_reopen(&err);
                std::fprintf(stderr, "[NFC-EMU-START] attempt=%d ok=%d err=%s\n",
                             attempt + 1, ok ? 1 : 0, err.c_str());
                if (!ok) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(160));
                    std::string reopen_err;
                    (void)nfcunit_reopen_i2c_for_worker(&reopen_err);
                }
            }
        }

        const std::string profile = nfcunit_profile_label();
        {
            std::lock_guard<std::mutex> lk(pending_log_mutex_);
            nfc_unit_emu_start_running_ = false;
            nfc_unit_emu_start_has_result_ = true;
            nfc_unit_emu_start_ok_ = ok;
            nfc_unit_emu_start_status_ = ok ? "running" : "failed";
            nfc_unit_emu_start_error_ = err;
            nfc_unit_emu_start_profile_ = profile;
        }
        std::fprintf(stderr, "[NFC-EMU-START] done ok=%d profile=%s err=%s\n",
                     ok ? 1 : 0, profile.c_str(), err.c_str());
    }

    void stop_nfcunit_emulation_worker(bool stop_listener)
    {
        nfc_unit_emu_cancel_.store(true);
        if (nfc_unit_emu_thread_.joinable()) nfc_unit_emu_thread_.join();
        nfc_unit_emu_running_.store(false);
        nfc_unit_emu_protocol_ = ProtocolKind::Unknown;
        if (stop_listener) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (i2c_device_ && i2c_device_->is_open() && i2c_device_->is_nfc_unit()) {
                i2c_device_->nfcunit_stop_listener();
                i2c_device_->stopEmulation();
            }
        }
    }

    void stop_spi_emulation_worker(bool stop_listener)
    {
        spi_emu_cancel_.store(true);
        if (spi_emu_thread_.joinable()) spi_emu_thread_.join();
        if (stop_listener) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (spi_device_) {
                spi_device_->stop_listener();
            }
        }
    }

    void nfcunit_ntag213_worker()
    {
        static constexpr uint8_t kAck = 0x0A;
        static constexpr uint8_t kNak = 0x00;
        static constexpr uint8_t kTearing = 0xBD;
        uint32_t counter0 = 0;
        uint8_t version[8] = {0x00, 0x04, 0x04, 0x02, 0x01, 0x00,
                              nfcunit_ntag_version_storage_for_pages(nfc_unit_ntag_pages_), 0x03};
        const std::vector<uint8_t> uid = {
            nfc_unit_ntag_mem_[0], nfc_unit_ntag_mem_[1], nfc_unit_ntag_mem_[2],
            nfc_unit_ntag_mem_[4], nfc_unit_ntag_mem_[5], nfc_unit_ntag_mem_[6], nfc_unit_ntag_mem_[7]
        };

        while (!nfc_unit_emu_cancel_.load()) {
            std::vector<uint8_t> frame;
            bool got = false;
            I2cGroveNfcDevice *dev = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dev = i2c_device_.get();
            }
            if (dev && dev->is_open() && dev->is_nfc_unit()) {
                got = dev->nfcunit_poll_listener_frame(frame, 20);
            }
            if (!got || frame.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }

            std::vector<uint8_t> response;
            const uint8_t cmd = frame[0];
            if (cmd == 0x30 && frame.size() >= 2) {
                const size_t pages = nfc_unit_ntag_mem_.size() / 4;
                const size_t start = frame[1];
                if (start < pages) {
                    response.reserve(16);
                    for (size_t p = start; p < start + 4; ++p) {
                        if (p < pages) {
                            response.insert(response.end(), nfc_unit_ntag_mem_.begin() + static_cast<ptrdiff_t>(p * 4),
                                            nfc_unit_ntag_mem_.begin() + static_cast<ptrdiff_t>(p * 4 + 4));
                        } else {
                            response.insert(response.end(), 4, 0x00);
                        }
                    }
                }
            } else if (cmd == 0x3A && frame.size() >= 3 && frame[1] <= frame[2]) {
                const size_t pages = nfc_unit_ntag_mem_.size() / 4;
                const size_t start = frame[1];
                const size_t end = std::min(static_cast<size_t>(frame[2]), pages > 0 ? pages - 1 : 0);
                if (start < pages && start <= end) {
                    const size_t len = (end - start + 1) * 4;
                    if (len <= 0xFF) {
                        response.assign(nfc_unit_ntag_mem_.begin() + static_cast<ptrdiff_t>(start * 4),
                                        nfc_unit_ntag_mem_.begin() + static_cast<ptrdiff_t>(start * 4 + len));
                    }
                }
            } else if (cmd == 0x60 && frame.size() == 1) {
                response.assign(version, version + sizeof(version));
            } else if (cmd == 0x3C && frame.size() >= 2 && frame[1] == 0x00) {
                response.assign(32, 0x00);
            } else if (cmd == 0x39 && frame.size() >= 2 && frame[1] == 0x02) {
                response = {static_cast<uint8_t>(counter0 & 0xFF), static_cast<uint8_t>((counter0 >> 8) & 0xFF), static_cast<uint8_t>((counter0 >> 16) & 0xFF)};
            } else if (cmd == 0x3E && frame.size() >= 2 && frame[1] == 0x02) {
                response = {kTearing};
            } else if (cmd == 0xA2 && frame.size() == 6) {
                const uint8_t page = frame[1];
                const size_t off = static_cast<size_t>(page) * 4;
                if (page >= 4 && page <= 39 && off + 4 <= nfc_unit_ntag_mem_.size()) {
                    std::memcpy(nfc_unit_ntag_mem_.data() + off, frame.data() + 2, 4);
                    response = {kAck};
                }
            } else if (cmd == 0x1B && frame.size() >= 5) {
                response = {nfc_unit_ntag_mem_[176], nfc_unit_ntag_mem_[177]};
            }

            // Let ST25R passive-target auto response handle anti-collision/select/halt.
            // Replying with NAK here can break reader-side activation flow.
            if (response.empty() &&
                (cmd == 0x26 || cmd == 0x52 || cmd == 0x93 || cmd == 0x95 || cmd == 0x50)) {
                continue;
            }

            if (response.empty()) response = {kNak};

            {
                bool tx_ok = false;
                I2cGroveNfcDevice *tx_dev = nullptr;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    tx_dev = i2c_device_.get();
                }
                if (tx_dev && tx_dev->is_open() && tx_dev->is_nfc_unit()) {
                    tx_ok = tx_dev->nfcunit_send_listener_frame(response.data(), static_cast<uint8_t>(response.size()));
                    if (!tx_ok && !nfc_unit_emu_cancel_.load()) {
                        NfcHexLog::get().log_event("NFC-I2C", "NTAG tx failed, auto-restart listener");
                        tx_dev->nfcunit_stop_listener();
                        if (tx_dev->nfcunit_start_listener_a(uid, 0x0044, 0x00)) {
                            NfcHexLog::get().log_event("NFC-I2C", "NTAG listener restarted");
                        } else {
                            NfcHexLog::get().log_event("NFC-I2C", "NTAG listener restart failed");
                        }
                    }
                }
            }
        }
    }

    void nfcunit_felica_worker()
    {
        while (!nfc_unit_emu_cancel_.load()) {
            std::vector<uint8_t> frame;
            bool got = false;
            I2cGroveNfcDevice *dev = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dev = i2c_device_.get();
            }
            if (dev && dev->is_open() && dev->is_nfc_unit()) {
                got = dev->nfcunit_poll_listener_frame(frame, 20);
            }
            if (!got || frame.size() < 2) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }
            const uint8_t cmd = frame[1];
            if (cmd != 0x06 && cmd != 0x08) {
                continue;
            }
            push_log(cmd == 0x06 ? "[NFCUnit] NFC-F read request received" : "[NFCUnit] NFC-F write request received");
        }
    }

    void nfcunit_mifare_listener_worker()
    {
        while (!nfc_unit_emu_cancel_.load()) {
            std::vector<uint8_t> frame;
            bool got = false;
            I2cGroveNfcDevice *dev = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dev = i2c_device_.get();
            }
            if (dev && dev->is_open() && dev->is_nfc_unit()) {
                // MIFARE emulation relies on the same listener state machine.
                // Keep polling even when payload frames are ignored.
                got = dev->nfcunit_poll_listener_frame(frame, 20);
            }
            if (!got) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    }

    void spi_listener_worker()
    {
        auto calc_bcc = [](uint8_t a, uint8_t b, uint8_t c, uint8_t d) -> uint8_t {
            return static_cast<uint8_t>(a ^ b ^ c ^ d);
        };

        bool anticollision_started = false;

        while (!spi_emu_cancel_.load()) {
            std::vector<uint8_t> frame;
            bool got = false;
            NfcSpiDevice *dev = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dev = spi_device_.get();
            }
            if (dev && dev->is_open() && dev->listener_active()) {
                // Keep polling to drive listener state transitions even when
                // payload frames are ignored.
                got = dev->poll_listener_frame(frame, 20);
            }

            if (got && !frame.empty()) {
                std::vector<uint8_t> uid;
                uint16_t atqa = 0;
                uint8_t sak = 0;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    uid = spi_emu_uid_;
                    atqa = spi_emu_atqa_;
                    sak = spi_emu_sak_;
                }

                const uint8_t cmd0 = frame[0];
                const uint8_t cmd1 = frame.size() > 1 ? frame[1] : 0x00;

                const bool is_short_poll = (cmd0 == 0x26 || cmd0 == 0x52);
                const bool is_shifted_short_poll = (cmd0 == 0x13 || cmd0 == 0x29);
                if (anticollision_started && (is_short_poll || is_shifted_short_poll)) {
                    std::fprintf(stderr, "[SPI-EMU] reset anticollision on short poll cmd=%02X\n", cmd0);
                    std::fflush(stderr);
                    anticollision_started = false;
                }

                if ((cmd0 == 0x93 && (cmd1 == 0x20 || cmd1 == 0x70)) ||
                    (cmd0 == 0x95 && (cmd1 == 0x20 || cmd1 == 0x70))) {
                    anticollision_started = true;
                }
                if (cmd0 == 0x50 && cmd1 == 0x00) {
                    anticollision_started = false;
                }

                // Some readers can expose a right-shifted echo of short frames
                // (e.g. 0x52 -> 0x29). Do not answer those artifacts.
                if (is_shifted_short_poll) {
                    std::fprintf(stderr, "[SPI-EMU] ignore shifted short poll cmd=%02X\n", cmd0);
                    std::fflush(stderr);
                    continue;
                }

                std::vector<uint8_t> response;
                bool with_crc = false;
                bool handled = false;

                // REQA / WUPA short frame: ATQA (2 bytes, no CRC).
                if (is_short_poll) {
                    response = {
                        static_cast<uint8_t>((atqa >> 8) & 0xFF),
                        static_cast<uint8_t>(atqa & 0xFF)
                    };
                    handled = true;
                }
                // ANTICOLLISION CL1 -> UID CL1/BCC (no CRC)
                else if (cmd0 == 0x93 && cmd1 == 0x20) {
                    if (uid.size() == 4) {
                        response = {uid[0], uid[1], uid[2], uid[3],
                                    calc_bcc(uid[0], uid[1], uid[2], uid[3])};
                    } else if (uid.size() == 7) {
                        response = {0x88, uid[0], uid[1], uid[2],
                                    calc_bcc(0x88, uid[0], uid[1], uid[2])};
                    }
                    with_crc = false;
                    handled = !response.empty();
                }
                // SELECT CL1 -> SAK (with CRC)
                else if (cmd0 == 0x93 && cmd1 == 0x70) {
                    const uint8_t sak_cl1 = (uid.size() == 7)
                        ? static_cast<uint8_t>(sak | 0x04)
                        : static_cast<uint8_t>(sak & static_cast<uint8_t>(~0x04));
                    response = {sak_cl1};
                    with_crc = true;
                    handled = true;
                    // 4-byte UID selection completes at CL1; allow fresh REQA/WUPA.
                    if (uid.size() == 4) {
                        anticollision_started = false;
                    }
                }
                // ANTICOLLISION CL2 (for 7-byte UID)
                else if (uid.size() == 7 && cmd0 == 0x95 && cmd1 == 0x20) {
                    response = {uid[3], uid[4], uid[5], uid[6],
                                calc_bcc(uid[3], uid[4], uid[5], uid[6])};
                    handled = true;
                }
                // SELECT CL2 -> final SAK (with CRC)
                else if (uid.size() == 7 && cmd0 == 0x95 && cmd1 == 0x70) {
                    response = {static_cast<uint8_t>(sak & static_cast<uint8_t>(~0x04))};
                    with_crc = true;
                    handled = true;
                    anticollision_started = false;
                }

                if (handled && !response.empty()) {
                    bool tx_ok = false;
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        NfcSpiDevice *tx_dev = spi_device_.get();
                        if (tx_dev && tx_dev->is_open() && tx_dev->listener_active()) {
                            tx_ok = tx_dev->send_listener_frame(
                                response.data(),
                                static_cast<uint8_t>(response.size()),
                                with_crc);
                        }
                    }
                    std::fprintf(stderr, "[SPI-EMU] tx len=%zu crc=%u ok=%u cmd=%02X/%02X data=%s\n",
                                 response.size(),
                                 with_crc ? 1u : 0u,
                                 tx_ok ? 1u : 0u,
                                 cmd0,
                                 cmd1,
                                 bytes_to_hex_string(response.data(), response.size()).c_str());
                    std::fflush(stderr);
                } else {
                    std::fprintf(stderr, "[SPI-EMU] unhandled cmd=%02X/%02X len=%zu data=%s\n",
                                 cmd0,
                                 cmd1,
                                 frame.size(),
                                 bytes_to_hex_string(frame.data(), frame.size()).c_str());
                    std::fflush(stderr);
                }
            }

            if (!got) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }
    }

    void nfcunit_iso15693_keepalive_worker()
    {
        int fail_streak = 0;
        while (!nfc_unit_emu_cancel_.load()) {
            bool ok = false;
            I2cGroveNfcDevice *dev = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                dev = i2c_device_.get();
            }
            if (dev && dev->is_open() && dev->is_nfc_unit()) {
                ok = dev->nfcunit_refresh_iso15_emulation();
            }

            if (!ok) {
                ++fail_streak;
                if (fail_streak == 1 || (fail_streak % 100) == 0) {
                    NfcHexLog::get().log_event("NFC-I2C", "ISO15693 keepalive refresh failed");
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(40));
                continue;
            }

            fail_streak = 0;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }

    bool open_transport_locked(const TransportEndpoint &endpoint, std::string *error)
    {
        if (transport_) {
            transport_->close();
            transport_.reset();
        }

        std::unique_ptr<INfcTransport> inner = NfcTransportFactory::create(endpoint);
        if (!inner) {
            if (error) *error = "create transport failed";
            return false;
        }

        std::unique_ptr<INfcTransport> wrapped(new LoggingTransport(std::move(inner), "NFC"));
        if (!wrapped->open(endpoint, error)) {
            return false;
        }
        transport_ = std::move(wrapped);
        if (error) error->clear();
        return true;
    }

    struct UhfTagSnapshot {
        std::string first_seen;
        std::string last_seen;
        std::string epc;
        std::string tid;
        std::string pc;
        std::string crc;
        std::string rssi;
        std::string frequency;
        std::string antenna;
        int read_count = 0;
        std::string raw_hex;
    };

    static std::string csv_escape(const std::string &value)
    {
        bool need_quote = false;
        for (char ch : value) {
            if (ch == ',' || ch == '"' || ch == '\n' || ch == '\r') {
                need_quote = true;
                break;
            }
        }
        if (!need_quote) return value;
        std::string out;
        out.reserve(value.size() + 4);
        out.push_back('"');
        for (char ch : value) {
            if (ch == '"') out += "\"\"";
            else out.push_back(ch);
        }
        out.push_back('"');
        return out;
    }

    static std::string to_upper_ascii(std::string value)
    {
        for (char &ch : value) {
            ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        }
        return value;
    }

    static std::string keep_hex_chars_upper(const std::string &value)
    {
        std::string out;
        out.reserve(value.size());
        for (char ch : value) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        return out;
    }

    static std::string bytes_to_hex_string(const uint8_t *data, size_t len, size_t max_len = 0)
    {
        if (!data || len == 0) return {};
        const size_t use_len = (max_len == 0 || max_len > len) ? len : max_len;
        std::ostringstream oss;
        oss << std::uppercase << std::hex << std::setfill('0');
        for (size_t i = 0; i < use_len; ++i) {
            oss << std::setw(2) << static_cast<int>(data[i]);
        }
        if (use_len < len) oss << "...";
        return oss.str();
    }

    static void log_i2c_load_payload(const char *label, const std::vector<uint8_t> &data)
    {
        if (!label || !label[0]) label = "EMU";
        if (data.empty()) {
            NfcHexLog::get().log_event("NFC-I2C", (std::string(label) + " load: empty").c_str());
            return;
        }

        char msg[160];
        std::snprintf(msg, sizeof(msg), "%s load bytes=%zu head=%s",
                      label,
                      data.size(),
                      bytes_to_hex_string(data.data(), data.size(), 32).c_str());
        NfcHexLog::get().log_event("NFC-I2C", msg);

        // Write payload in chunks so the iic log captures exactly what was loaded.
        size_t offset = 0;
        while (offset < data.size()) {
            const size_t chunk = std::min<size_t>(64, data.size() - offset);
            NfcHexLog::get().log_tx("I2C", data.data() + offset, chunk);
            offset += chunk;
        }
    }

    static std::string bytes_to_readable_ascii(const std::vector<uint8_t> &bytes)
    {
        std::string out;
        out.reserve(bytes.size());
        for (uint8_t b : bytes) {
            const unsigned char ch = static_cast<unsigned char>(b);
            if (ch >= 32 && ch <= 126) out.push_back(static_cast<char>(ch));
            else out.push_back(' ');
        }
        return out;
    }

    static std::string extract_label_token(const std::string &text_up, const std::string &label)
    {
        const std::string token = label + ":";
        const size_t pos = text_up.find(token);
        if (pos == std::string::npos) return {};

        size_t index = pos + token.size();
        while (index < text_up.size() &&
               (text_up[index] == ' ' || text_up[index] == '=' || text_up[index] == '\t')) {
            ++index;
        }

        std::string out;
        while (index < text_up.size()) {
            const char ch = text_up[index];
            const bool ok = std::isalnum(static_cast<unsigned char>(ch)) ||
                            ch == '-' || ch == '.' || ch == '/' || ch == ':';
            if (!ok) break;
            out.push_back(ch);
            ++index;
        }
        return out;
    }

    static std::vector<std::string> extract_hex_tokens(const std::string &text_up)
    {
        std::vector<std::string> tokens;
        std::string cur;
        for (char ch : text_up) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                cur.push_back(ch);
            } else {
                if (cur.size() >= 8 && (cur.size() % 2) == 0) tokens.push_back(cur);
                cur.clear();
            }
        }
        if (cur.size() >= 8 && (cur.size() % 2) == 0) tokens.push_back(cur);
        return tokens;
    }

    static bool looks_like_epc(const std::string &epc)
    {
        if (epc.size() < 8 || (epc.size() % 2) != 0) return false;
        bool all_zero = true;
        for (char ch : epc) {
            if (!std::isxdigit(static_cast<unsigned char>(ch))) return false;
            if (ch != '0') all_zero = false;
        }
        return !all_zero;
    }

    static bool is_accepted_uhf_inventory_epc(const std::string &epc)
    {
        if (!looks_like_epc(epc)) return false;
        const std::string up = to_upper_ascii(epc);
        // Keep mtools baseline acceptance (E2*) while dropping known ghost EPC prefix.
        if (up.rfind("E2", 0) != 0) return false;
        if (up.rfind("E280690000", 0) == 0) return false;
        return true;
    }

    static std::vector<uint8_t> build_uhf_bb_frame(uint8_t cmd, const std::vector<uint8_t> &payload)
    {
        const uint16_t len = static_cast<uint16_t>(payload.size());
        std::vector<uint8_t> frame;
        frame.reserve(payload.size() + 8);
        frame.push_back(0xBB);
        frame.push_back(0x00);
        frame.push_back(cmd);
        frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        frame.push_back(static_cast<uint8_t>(len & 0xFF));
        frame.insert(frame.end(), payload.begin(), payload.end());
        uint8_t sum = 0;
        for (size_t i = 1; i < frame.size(); ++i) sum = static_cast<uint8_t>(sum + frame[i]);
        frame.push_back(sum);
        frame.push_back(0x7E);
        return frame;
    }

    static std::vector<uint8_t> build_uhf_a0_frame(uint8_t cmd, const std::vector<uint8_t> &payload)
    {
        // Android reference (UhfUsbReader.kt):
        // frame = A0 | len(payload+3) | addr(0x00) | cmd | payload | checksum(two's complement)
        std::vector<uint8_t> frame;
        frame.reserve(payload.size() + 5);
        frame.push_back(0xA0);
        frame.push_back(static_cast<uint8_t>(payload.size() + 3));
        frame.push_back(0x00);
        frame.push_back(cmd);
        frame.insert(frame.end(), payload.begin(), payload.end());

        int checksum_source = 0;
        for (uint8_t b : frame) checksum_source = (checksum_source + (b & 0xFF)) & 0xFF;
        const uint8_t checksum = static_cast<uint8_t>(((~checksum_source) + 1) & 0xFF);
        frame.push_back(checksum);
        return frame;
    }

    static bool extract_a0_frames(const std::vector<uint8_t> &raw,
                                  std::vector<std::vector<uint8_t>> *frames)
    {
        if (frames) frames->clear();
        if (raw.empty() || !frames) return false;

        size_t index = 0;
        while (index < raw.size()) {
            while (index < raw.size() && raw[index] != 0xA0) ++index;
            if (index + 2 > raw.size()) break;

            const size_t frame_len = static_cast<size_t>(raw[index + 1]) + 2;
            if (frame_len < 5 || index + frame_len > raw.size()) break;

            frames->push_back(std::vector<uint8_t>(raw.begin() + index,
                                                   raw.begin() + index + frame_len));
            index += frame_len;
        }
        return !frames->empty();
    }

    static bool parse_a0_frame(const std::vector<uint8_t> &frame,
                               uint8_t *cmd,
                               std::vector<uint8_t> *data)
    {
        if (frame.size() < 5) return false;
        if (frame[0] != 0xA0) return false;

        const int len = frame[1] & 0xFF;
        if (len < 3) return false;
        if (frame.size() != static_cast<size_t>(len + 2)) return false;

        // Android mtools parity: full frame checksum must fold to 0x00.
        int checksum_total = 0;
        for (uint8_t b : frame) {
            checksum_total = (checksum_total + (b & 0xFF)) & 0xFF;
        }
        if (checksum_total != 0) return false;

        if (cmd) *cmd = frame[3];
        if (data) {
            const int data_len = len - 3;
            if (data_len <= 0) {
                data->clear();
            } else {
                data->assign(frame.begin() + 4, frame.begin() + 4 + data_len);
            }
        }
        return true;
    }

    static bool write_all(INfcTransport *transport,
                          const std::vector<uint8_t> &frame,
                          std::string *error)
    {
        if (!transport || !transport->is_open()) {
            if (error) *error = "transport not open";
            return false;
        }
        const ssize_t sent = transport->write_bytes(frame.data(), frame.size(), error);
        if (sent < 0 || static_cast<size_t>(sent) != frame.size()) {
            if (error && error->empty()) *error = "short write";
            return false;
        }
        return true;
    }

    bool uhf_exchange_command_locked(INfcTransport *transport,
                                     uint8_t cmd,
                                     const std::vector<uint8_t> &payload,
                                     int listen_ms,
                                     std::vector<uint8_t> *raw_response,
                                     std::string *error)
    {
        if (raw_response) raw_response->clear();
        std::string io_error;

        auto read_window = [&](std::vector<uint8_t> *out) {
            if (!out) return;
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(listen_ms);
            while (std::chrono::steady_clock::now() < deadline) {
                uint8_t buf[256] = {};
                std::string read_err;
                const ssize_t got = transport->read_bytes(buf, sizeof(buf), 40, &read_err);
                if (got > 0) {
                    out->insert(out->end(), buf, buf + got);
                    continue;
                }
                if (got < 0) {
                    io_error = read_err;
                    break;
                }
            }
        };

        std::vector<uint8_t> merged;
        // Prefer Android-compatible A0 framing first (UhfUsbReader.kt), then keep BB as fallback.
        const std::vector<uint8_t> a0_frame = build_uhf_a0_frame(cmd, payload);
        if (write_all(transport, a0_frame, &io_error)) {
            read_window(&merged);
        }
        if (merged.empty()) {
            const std::vector<uint8_t> bb_frame = build_uhf_bb_frame(cmd, payload);
            if (write_all(transport, bb_frame, &io_error)) {
                read_window(&merged);
            }
        }

        if (raw_response) *raw_response = merged;
        if (!merged.empty()) {
            if (error) error->clear();
            return true;
        }
        if (error) *error = io_error.empty() ? "no response" : io_error;
        return false;
    }

    bool uhf_detect_on_open_transport_locked(INfcTransport *transport, std::string *detail)
    {
        if (!transport || !transport->is_open()) return false;

        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);
        std::vector<uint8_t> raw;
        std::string err;
        if (!uhf_exchange_command_locked(transport, 0x72, {}, 160, &raw, &err)) {
            return false;
        }

        bool signature = false;
        std::string version_text;

        std::vector<std::vector<uint8_t>> a0_frames;
        if (extract_a0_frames(raw, &a0_frames)) {
            for (const auto &frame : a0_frames) {
                uint8_t frame_cmd = 0;
                std::vector<uint8_t> data;
                if (!parse_a0_frame(frame, &frame_cmd, &data)) continue;
                if (frame_cmd != 0x72) continue;
                signature = true;

                if (data.size() >= 3) {
                    version_text = std::to_string(static_cast<int>(data[0])) + "." +
                                   std::to_string(static_cast<int>(data[1])) + "." +
                                   std::to_string(static_cast<int>(data[2]));
                }
                break;
            }
        }

        if (!signature) {
            const std::string ascii_raw = bytes_to_readable_ascii(raw);
            const std::string ascii = to_upper_ascii(ascii_raw);
            if (ascii.find("UHF") != std::string::npos ||
                ascii.find("EPC") != std::string::npos ||
                ascii.find("RSSI") != std::string::npos ||
                ascii.find("TID") != std::string::npos) {
                signature = true;
            }
        }

        if (!signature) {
            for (size_t i = 0; i + 6 < raw.size(); ++i) {
                if (raw[i] == 0xBB && raw[i + 1] <= 0x02) {
                    signature = true;
                    break;
                }
            }
        }
        if (!signature) return false;

        if (detail) {
            if (!version_text.empty()) {
                *detail = std::string("UHFReader FW ") + version_text;
            } else {
                *detail = std::string("UHFReader response: ") +
                          bytes_to_hex_string(raw.data(), raw.size(), 32);
            }
        }
        return true;
    }

    std::vector<UhfTagSnapshot> parse_uhf_tags_from_raw(const std::vector<uint8_t> &raw) const
    {
        std::vector<UhfTagSnapshot> out;
        if (raw.empty()) return out;

        auto parse_a0_realtime_data = [&](const std::vector<uint8_t> &data) {
            if (data.size() < 5) return;

            auto try_layout = [&](size_t pc_offset, size_t epc_offset, bool has_antenna, size_t antenna_offset) -> bool {
                if (data.size() < pc_offset + 2) return false;

                const int pc = ((data[pc_offset] & 0xFF) << 8) | (data[pc_offset + 1] & 0xFF);
                const int epc_words = (pc >> 11) & 0x1F;
                const int epc_len = epc_words * 2;
                if (epc_len <= 0 || epc_len > 62) return false;

                const size_t epc_end = epc_offset + static_cast<size_t>(epc_len);
                if (epc_end > data.size()) return false;

                UhfTagSnapshot row;
                row.epc = keep_hex_chars_upper(
                    bytes_to_hex_string(data.data() + epc_offset, static_cast<size_t>(epc_len)));

                if (!is_accepted_uhf_inventory_epc(row.epc)) return false;

                char pc_buf[8];
                std::snprintf(pc_buf, sizeof(pc_buf), "%04X", pc & 0xFFFF);
                row.pc = pc_buf;

                if (has_antenna && antenna_offset < data.size()) {
                    row.antenna = std::to_string(static_cast<int>(data[antenna_offset] & 0xFF));
                }

                const size_t meta_offset = epc_end;
                if (data.size() >= meta_offset + 7) {
                    const int32_t rssi =
                        (static_cast<int32_t>(data[meta_offset + 0]) << 24) |
                        (static_cast<int32_t>(data[meta_offset + 1]) << 16) |
                        (static_cast<int32_t>(data[meta_offset + 2]) << 8) |
                        (static_cast<int32_t>(data[meta_offset + 3]));
                    row.rssi = std::to_string(rssi);

                    const int freq_hz =
                        ((data[meta_offset + 4] & 0xFF) << 16) |
                        ((data[meta_offset + 5] & 0xFF) << 8) |
                        (data[meta_offset + 6] & 0xFF);
                    row.frequency = std::to_string(freq_hz);
                }

                row.raw_hex = bytes_to_hex_string(data.data(), data.size(), 64);
                row.read_count = 1;
                out.push_back(row);
                return true;
            };

            // Layout A (Android reference): [ant][pc_hi][pc_lo][epc...][rssi(4)][freq(3)]
            if (try_layout(1, 3, true, 0)) return;
            // Layout B (some modules): [pc_hi][pc_lo][epc...][rssi(4)][freq(3)]
            if (try_layout(0, 2, false, 0)) return;
            // Layout C (status + antenna prefix): [status][ant][pc_hi][pc_lo][epc...]
            (void)try_layout(2, 4, true, 1);
        };

        auto parse_a0_inventory_buffer_data = [&](const std::vector<uint8_t> &data) {
            if (data.size() < 11) return;

            const int inv_data_len = data[0] & 0xFF;
            if (inv_data_len < 4) return;

            const size_t required_len = 1u + static_cast<size_t>(inv_data_len) + 4u + 3u + 1u + 1u;
            if (data.size() < required_len) return;

            const size_t inv_start = 1;
            const size_t inv_end = inv_start + static_cast<size_t>(inv_data_len);
            const size_t meta_offset = inv_end;

            UhfTagSnapshot row;
            row.pc = keep_hex_chars_upper(
                bytes_to_hex_string(data.data() + inv_start, 2));
            row.crc = keep_hex_chars_upper(
                bytes_to_hex_string(data.data() + inv_end - 2, 2));
            row.epc = keep_hex_chars_upper(
                bytes_to_hex_string(data.data() + inv_start + 2, static_cast<size_t>(inv_data_len - 4)));

            if (!is_accepted_uhf_inventory_epc(row.epc)) return;

            const uint32_t rssi =
                ((data[meta_offset + 0] & 0xFFu) << 24) |
                ((data[meta_offset + 1] & 0xFFu) << 16) |
                ((data[meta_offset + 2] & 0xFFu) << 8) |
                (data[meta_offset + 3] & 0xFFu);
            row.rssi = std::to_string(static_cast<unsigned long long>(rssi));

            const uint32_t freq_hz =
                ((data[meta_offset + 4] & 0xFFu) << 16) |
                ((data[meta_offset + 5] & 0xFFu) << 8) |
                (data[meta_offset + 6] & 0xFFu);
            row.frequency = std::to_string(static_cast<unsigned long long>(freq_hz));

            row.antenna = std::to_string(static_cast<int>(data[meta_offset + 7] & 0xFF));
            row.read_count = static_cast<int>(data[meta_offset + 8] & 0xFF);
            if (row.read_count <= 0) row.read_count = 1;
            row.raw_hex = bytes_to_hex_string(data.data(), data.size(), 64);
            out.push_back(row);
        };

        std::vector<std::vector<uint8_t>> a0_frames;
        if (extract_a0_frames(raw, &a0_frames)) {
            for (const auto &frame : a0_frames) {
                uint8_t cmd = 0;
                std::vector<uint8_t> data;
                if (!parse_a0_frame(frame, &cmd, &data)) continue;
                if (cmd == 0x72) continue; // firmware response, not EPC payload
                if (cmd == 0x89) {
                    parse_a0_realtime_data(data);
                } else if (cmd == 0x8A) {
                    parse_a0_inventory_buffer_data(data);
                }
            }
            if (!out.empty()) return out;
        }

        auto parse_one = [&](const std::vector<uint8_t> &chunk) {
            if (chunk.empty()) return;
            const std::string chunk_ascii_up = to_upper_ascii(bytes_to_readable_ascii(chunk));
            UhfTagSnapshot row;
            row.epc       = keep_hex_chars_upper(extract_label_token(chunk_ascii_up, "EPC"));
            row.tid       = keep_hex_chars_upper(extract_label_token(chunk_ascii_up, "TID"));
            row.pc        = keep_hex_chars_upper(extract_label_token(chunk_ascii_up, "PC"));
            row.crc       = keep_hex_chars_upper(extract_label_token(chunk_ascii_up, "CRC"));
            row.rssi      = extract_label_token(chunk_ascii_up, "RSSI");
            row.frequency = extract_label_token(chunk_ascii_up, "FREQ");
            row.antenna   = extract_label_token(chunk_ascii_up, "ANT");

            if (row.epc.empty()) {
                auto tokens = extract_hex_tokens(chunk_ascii_up);
                std::sort(tokens.begin(), tokens.end(),
                          [](const std::string &a, const std::string &b) { return a.size() > b.size(); });
                for (const auto &token : tokens) {
                    if (is_accepted_uhf_inventory_epc(token) && token.size() <= 96) {
                        row.epc = token;
                        break;
                    }
                }
            }

            if (!is_accepted_uhf_inventory_epc(row.epc)) return;
            row.raw_hex = bytes_to_hex_string(chunk.data(), chunk.size(), 64);
            row.read_count = 1;
            out.push_back(row);
        };

        parse_one(raw);

        // Parse BB frames to avoid missing tags from binary payload reports.
        for (size_t i = 0; i + 6 < raw.size();) {
            if (raw[i] != 0xBB) {
                ++i;
                continue;
            }
            const uint16_t len = static_cast<uint16_t>((raw[i + 3] << 8) | raw[i + 4]);
            const size_t frame_len = static_cast<size_t>(len) + 7;
            if (i + frame_len > raw.size()) break;
            if (raw[i + frame_len - 1] == 0x7E && len > 0) {
                const size_t payload_start = i + 5;
                parse_one(std::vector<uint8_t>(raw.begin() + payload_start,
                                               raw.begin() + payload_start + len));
            }
            i += frame_len;
        }

        return out;
    }

    static void merge_if_empty(std::string *target, const std::string &value)
    {
        if (target && target->empty() && !value.empty()) *target = value;
    }

    TagInfo uhf_snapshot_to_tag_info(const UhfTagSnapshot &tag) const
    {
        TagInfo info;
        info.protocol = ProtocolKind::Unknown;
        info.tag_type = "UHF EPC Gen2";
        info.uid = tag.epc;
        if (!tag.tid.empty()) info.identity_fields["TID"] = tag.tid;
        if (!tag.pc.empty()) info.identity_fields["PC"] = tag.pc;
        if (!tag.crc.empty()) info.identity_fields["CRC"] = tag.crc;
        if (!tag.rssi.empty()) info.identity_fields["RSSI"] = tag.rssi;
        if (!tag.frequency.empty()) info.identity_fields["FREQ"] = tag.frequency;
        if (!tag.antenna.empty()) info.identity_fields["ANT"] = tag.antenna;
        info.identity_fields["READ_COUNT"] = std::to_string(tag.read_count);
        if (!tag.raw_hex.empty()) info.raw_data.push_back(tag.raw_hex);
        return info;
    }

    void merge_uhf_tags(const std::vector<UhfTagSnapshot> &detected, const TransportEndpoint &endpoint)
    {
        for (const auto &row : detected) {
            if (!is_accepted_uhf_inventory_epc(row.epc)) continue;

            UhfTagSnapshot snapshot;
            bool first_seen = false;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                UhfTagSnapshot &slot = uhf_tags_[row.epc];
                first_seen = slot.read_count == 0;
                if (first_seen) {
                    slot.first_seen = iso8601_now();
                    slot.epc = row.epc;
                    slot.read_count = 0;
                }
                slot.last_seen = iso8601_now();
                slot.read_count += 1;
                merge_if_empty(&slot.tid, row.tid);
                merge_if_empty(&slot.pc, row.pc);
                merge_if_empty(&slot.crc, row.crc);
                merge_if_empty(&slot.rssi, row.rssi);
                merge_if_empty(&slot.frequency, row.frequency);
                merge_if_empty(&slot.antenna, row.antenna);
                if (!row.raw_hex.empty()) slot.raw_hex = row.raw_hex;
                snapshot = slot;

                scan_.has_result = true;
                scan_.status = uhf_continuous_mode_ ? "UHF continuous" : "UHF scan ready";
                scan_.error.clear();
                scan_.last_record = make_record_from_tag(
                    uhf_snapshot_to_tag_info(snapshot), endpoint, false, "uhf_scan");
            }

            if (first_seen) {
                std::string line = "EPC " + snapshot.epc;
                if (!snapshot.rssi.empty()) line += " RSSI:" + snapshot.rssi;
                if (!snapshot.antenna.empty()) line += " ANT:" + snapshot.antenna;
                line += " CNT:" + std::to_string(snapshot.read_count);
                push_log(line);
            }
        }
    }

    void perform_uhf_scan_worker(bool continuous)
    {
        NfcHexLog::get().log_event("uhf", continuous ? "start continuous scan" : "start single scan");

        TransportEndpoint endpoint;
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            endpoint = connection_.endpoint;
            transport_raw = transport_.get();
        }

        if (!transport_raw || !transport_raw->is_open()) {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.status = "No UHF device";
            scan_.error = "UHF reader disconnected";
            uhf_continuous_mode_ = false;
            return;
        }

        push_log(continuous ? "> UHF continuous scan..." : "> UHF scan once...");

        bool found_any = false;
        int idle_rounds = 0;
        const auto once_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1800);

        while (true) {
            if (cancel_uhf_scan_.load()) break;

            std::vector<uint8_t> raw;
            std::string io_err;
            {
                std::lock_guard<std::mutex> op_lock(transport_op_mutex_);
                uhf_exchange_command_locked(transport_raw, 0x89, {0x01}, 220, &raw, &io_err);
            }

            const auto tags = parse_uhf_tags_from_raw(raw);
            if (!tags.empty()) {
                merge_uhf_tags(tags, endpoint);
                found_any = true;
                idle_rounds = 0;
            } else {
                ++idle_rounds;
            }

            if (!continuous) {
                if (found_any) break;
                if (std::chrono::steady_clock::now() >= once_deadline) break;
                if (idle_rounds > 8) break;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(continuous ? 120 : 80));
        }

        {
            std::lock_guard<std::mutex> op_lock(transport_op_mutex_);
            std::string ignore;
            uhf_exchange_command_locked(transport_raw, 0x8C, {}, 60, nullptr, &ignore);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            if (continuous) {
                scan_.status = "UHF stopped";
                scan_.error.clear();
            } else if (found_any) {
                scan_.status = "UHF scan ready";
                scan_.error.clear();
            } else {
                scan_.status = "No UHF tag";
                scan_.error = "no tag detected";
            }
            uhf_continuous_mode_ = false;
        }

        if (continuous && cancel_uhf_scan_.load()) {
            push_log("UHF scan stopped");
        } else if (!found_any && !continuous) {
            push_log("No UHF tag detected");
        }
    }

    static bool parse_hex_bytes(const std::string &value, std::vector<uint8_t> *out)
    {
        if (!out) return false;
        std::string hex;
        hex.reserve(value.size());
        for (char ch : value) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                hex.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        if (hex.empty() || (hex.size() % 2) != 0) return false;

        out->clear();
        out->reserve(hex.size() / 2);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            const std::string byte_str = hex.substr(i, 2);
            out->push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }
        return true;
    }

    static std::string normalize_mifare_key_hex(const std::string &value)
    {
        std::string out;
        out.reserve(value.size());
        for (char ch : value) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) {
                out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            }
        }
        return out;
    }

    void perform_scan()
    {
        NfcHexLog::get().log_event("scan", "start scan");
        auto equals_ci = [](const std::string &a, const char *b) {
            if (!b || a.size() != std::strlen(b)) return false;
            for (size_t i = 0; i < a.size(); ++i) {
                const char ca = static_cast<char>(std::toupper(static_cast<unsigned char>(a[i])));
                const char cb = static_cast<char>(std::toupper(static_cast<unsigned char>(b[i])));
                if (ca != cb) return false;
            }
            return true;
        };

        auto to_upper = [](std::string s) {
            for (char &ch : s) {
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            }
            return s;
        };

        auto normalize_identity_hex = [&](std::string value) {
            value = to_upper(std::move(value));
            std::string out;
            out.reserve(value.size());
            for (char ch : value) {
                if (std::isxdigit(static_cast<unsigned char>(ch))) out.push_back(ch);
            }
            return out;
        };

        auto find_identity = [&](const TagInfo &tag, const char *key) -> std::string {
            for (const auto &kv : tag.identity_fields) {
                if (equals_ci(kv.first, key)) return kv.second;
            }
            return {};
        };

        auto extract_detail_field_hex = [&](const std::string &detail, const char *key) -> std::string {
            if (!key || !*key || detail.empty()) return {};
            const std::string key_token = std::string(key) + ":";
            const std::string detail_up = to_upper(detail);
            const size_t pos = detail_up.find(to_upper(key_token));
            if (pos == std::string::npos) return {};
            size_t start = pos + key_token.size();
            while (start < detail_up.size() && std::isspace(static_cast<unsigned char>(detail_up[start]))) ++start;
            std::string out;
            while (start < detail_up.size()) {
                const char ch = detail_up[start];
                if (!std::isxdigit(static_cast<unsigned char>(ch))) break;
                out.push_back(ch);
                ++start;
            }
            return out;
        };

        auto extract_detail_field_text = [&](const std::string &detail, const char *key) -> std::string {
            if (!key || !*key || detail.empty()) return {};
            const std::string key_token = to_upper(std::string(key) + ":");
            const std::string detail_up = to_upper(detail);
            const size_t pos = detail_up.find(key_token);
            if (pos == std::string::npos) return {};

            size_t start = pos + key_token.size();
            while (start < detail.size() && std::isspace(static_cast<unsigned char>(detail[start]))) ++start;
            size_t end = start;
            while (end < detail.size()) {
                const char ch = detail[end];
                if (ch == ',' || ch == ';' || ch == '|' || ch == '\r' || ch == '\n') break;
                ++end;
            }

            while (end > start && std::isspace(static_cast<unsigned char>(detail[end - 1]))) --end;
            if (end <= start) return {};
            return detail.substr(start, end - start);
        };

        auto emit_scan_summary = [&](const TagInfo &tag) {
            const std::string protocol = to_string(tag.protocol);
            const std::string uid = tag.uid;
            const std::string type = tag.tag_type;
            push_log("Result: Tag Found");
            push_log(std::string("Protocol: ") + protocol);
            push_log("UID: " + uid);
            if (!type.empty()) push_log("Type: " + type);

            if (tag.protocol == ProtocolKind::Iso15693) {
                const std::string afi = normalize_identity_hex(find_identity(tag, "AFI"));
                const std::string dsfid = normalize_identity_hex(find_identity(tag, "DSFID"));
                std::string ic_ref = normalize_identity_hex(find_identity(tag, "IC_REF"));
                if (ic_ref.empty()) ic_ref = normalize_identity_hex(find_identity(tag, "IC Reference"));

                std::string block_size = find_identity(tag, "BLOCK_SIZE");
                if (block_size.empty()) block_size = find_identity(tag, "BLOCK_COUNT");
                const std::string block_bytes = find_identity(tag, "BLOCK_BYTES");

                push_log(std::string("AFI: ") + (afi.empty() ? "-" : ("0x" + afi)));
                push_log(std::string("DSFID: ") + (dsfid.empty() ? "-" : ("0x" + dsfid)));
                push_log(std::string("IC Reference: ") + (ic_ref.empty() ? "-" : ("0x" + ic_ref)));
                push_log(std::string("Block size: ") + (block_size.empty() ? "-" : block_size));
                if (!block_bytes.empty()) {
                    push_log(std::string("Block bytes: ") + block_bytes);
                }
                return;
            }

            const std::string atqa_norm = normalize_identity_hex(find_identity(tag, "ATQA"));
            const std::string sak_norm = normalize_identity_hex(find_identity(tag, "SAK"));
            push_log(std::string("ATQA: ") + (atqa_norm.empty() ? "-" : atqa_norm));
            push_log(std::string("SAK: ") + (sak_norm.empty() ? "-" : sak_norm));

            std::string type_up = to_upper(type);
            std::string proto_up = to_upper(protocol);
            const bool is_mfc_family =
                (type_up.find("MIFARE CLASSIC") != std::string::npos) ||
                (type_up.find("MFC1K") != std::string::npos) ||
                (type_up.find("MFC4K") != std::string::npos) ||
                (type_up.find("MFCMINI") != std::string::npos) ||
                (sak_norm == "08" || sak_norm == "09" || sak_norm == "18" ||
                 sak_norm == "28" || sak_norm == "38" ||
                 sak_norm == "88" || sak_norm == "98") ||
                ((proto_up.find("MIFARE") != std::string::npos || proto_up.find("MFC") != std::string::npos) &&
                 (type_up.find("1K") != std::string::npos ||
                  type_up.find("4K") != std::string::npos ||
                  type_up.find("MINI") != std::string::npos));
            if (is_mfc_family) {
                push_log(std::string("MAGIC: ") + (tag.magic_type.empty() ? "Normal" : tag.magic_type));
            }
        };

        auto emit_scan_tail = [&]() {
            push_log("=====================");
        };

        // Snapshot connection under lock, then release so UI can call scan_state() freely.
        TransportEndpoint endpoint;
        DeviceKind device_kind = DeviceKind::Unknown;
        INfcTransport *transport_raw = nullptr;
        I2cGroveNfcDevice *i2c_dev = nullptr;
        NfcSpiDevice *spi_dev = nullptr;
        bool use_i2c_path = false;
        bool use_spi_path = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            endpoint    = connection_.endpoint;
            device_kind = connection_.device_kind;
            transport_raw = transport_.get();
            i2c_dev = i2c_device_.get();
            spi_dev = spi_device_.get();
            use_i2c_path = (i2c_dev && i2c_dev->is_open() &&
                            (endpoint.kind == TransportKind::I2cBus ||
                             device_kind == DeviceKind::NFCUnit ||
                             device_kind == DeviceKind::GroveNFC));
            use_spi_path = (spi_dev && spi_dev->is_open() &&
                            endpoint.kind == TransportKind::SpiBus);
        }

        SavedRecord record;
        std::string error;
        bool success = false;

        if (use_i2c_path) {
            NfcHexLog::get().log_event("scan", "path i2c");
            I2cGroveNfcDevice *dev = i2c_dev;
            if (!dev || !dev->is_open()) {
                std::lock_guard<std::mutex> lock(mutex_);
                scan_.running = false;
                scan_.status = "I2C device not open";
                scan_.error = "No I2C device";
                return;
            }
            if (dev->is_nfc_unit()) {
                push_log("> Reset NFC Unit reader...");
                std::string reset_err;
                if (!nfcunit_reopen_i2c_for_worker(&reset_err)) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    scan_.running = false;
                    scan_.status = "I2C reset failed";
                    scan_.error = reset_err.empty() ? "NFC Unit reset failed" : reset_err;
                    return;
                }
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    endpoint = connection_.endpoint;
                    device_kind = connection_.device_kind;
                    dev = i2c_device_.get();
                }
                if (!dev || !dev->is_open()) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    scan_.running = false;
                    scan_.status = "I2C device not open";
                    scan_.error = "No I2C device after reset";
                    return;
                }
            }
            push_log("> Scanning I2C NFC...");
            I2cCardInfo card;
            if (dev->is_nfc_unit()) {
                dev->nfcunit_stop_listener();
            }
            const bool card_ok = dev->readCard(card);
            if (card_ok && card.valid) {
                TagInfo tag;
                std::string uid_norm;
                uid_norm.reserve(card.uid.size());
                for (char ch : card.uid) {
                    if (std::isxdigit(static_cast<unsigned char>(ch))) {
                        uid_norm.push_back(static_cast<char>(
                            std::toupper(static_cast<unsigned char>(ch))));
                    }
                }
                tag.uid = uid_norm.empty() ? card.uid : uid_norm;
                tag.protocol = i2c_protocol_to_kind(card.protocol);
                tag.tag_type = i2c_protocol_to_tag_type(card.protocol);
                tag.magic_type = card.magic_type;
                tag.raw_data.clear();

                if (tag.protocol == ProtocolKind::Iso15693) {
                    tag.identity_fields.erase("ATQA");
                    tag.identity_fields.erase("SAK");

                    const std::string dsfid = extract_detail_field_hex(card.detail, "DSFID");
                    const std::string afi = extract_detail_field_hex(card.detail, "AFI");
                    const std::string ic_ref = extract_detail_field_hex(card.detail, "IC Reference");
                    const std::string block_size = extract_detail_field_text(card.detail, "Block size");
                    const std::string block_bytes = extract_detail_field_text(card.detail, "Block bytes");
                    if (!dsfid.empty()) tag.identity_fields["DSFID"] = dsfid;
                    if (!afi.empty()) tag.identity_fields["AFI"] = afi;
                    if (!ic_ref.empty()) tag.identity_fields["IC_REF"] = ic_ref;
                    if (!block_size.empty()) tag.identity_fields["BLOCK_SIZE"] = block_size;
                    if (!block_bytes.empty()) tag.identity_fields["BLOCK_BYTES"] = block_bytes;
                    if (tag.identity_fields.find("DSFID") == tag.identity_fields.end()) tag.identity_fields["DSFID"] = "00";
                    if (tag.identity_fields.find("AFI") == tag.identity_fields.end()) tag.identity_fields["AFI"] = "00";
                } else {
                    const std::string detail_atqa = !card.atqa_hex.empty()
                        ? card.atqa_hex : extract_detail_field_hex(card.detail, "ATQA");
                    const std::string detail_sak = !card.sak_hex.empty()
                        ? card.sak_hex : extract_detail_field_hex(card.detail, "SAK");
                    if (!detail_atqa.empty()) tag.identity_fields["ATQA"] = detail_atqa;
                    if (!detail_sak.empty()) tag.identity_fields["SAK"] = detail_sak;
                }

                emit_scan_summary(tag);
                emit_scan_tail();

                const std::string src = dev->is_nfc_unit() ? "nfc_unit" : "grovenfc";
                record = make_record_from_tag(tag, endpoint, false, src);
                success = true;
            } else {
                push_log("No card detected");
                emit_scan_tail();
                error = card_ok ? "no card present" : card.detail;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.last_record = record;
            scan_.has_result = success;
            scan_.status = success ? "Card found" : "No card";
            scan_.error = error;
            return;
        } else if (endpoint.kind == TransportKind::I2cBus) {
            NfcHexLog::get().log_event("scan", "path i2c-missing-device");
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.status = "I2C device not open";
            scan_.error = "No I2C device";
            return;
        } else if (use_spi_path) {
            NfcHexLog::get().log_event("scan", "path spi");
            push_log("> Scanning M5 NFC CAP (SPI)...");
            I2cCardInfo card;
            const bool card_ok = spi_dev->readCard(&card);
            if (card_ok && card.valid) {
                TagInfo tag;
                std::string uid_norm;
                uid_norm.reserve(card.uid.size());
                for (char ch : card.uid) {
                    if (std::isxdigit(static_cast<unsigned char>(ch))) {
                        uid_norm.push_back(static_cast<char>(
                            std::toupper(static_cast<unsigned char>(ch))));
                    }
                }
                tag.uid = uid_norm.empty() ? card.uid : uid_norm;
                tag.protocol = i2c_protocol_to_kind(card.protocol);
                tag.tag_type = i2c_protocol_to_tag_type(card.protocol);
                tag.magic_type = card.magic_type;
                tag.raw_data.clear();

                // SPI ST25R does not expose magic type in readCard(); probe it here
                // so READ page can show Gen1A/Normal like PN532/I2C paths.
                const bool mfc_like = (tag.protocol == ProtocolKind::MifareClassic) ||
                                      (to_upper(tag.tag_type).find("MIFARE CLASSIC") != std::string::npos);
                if (mfc_like) {
                    std::string magic_err;
                    if (spi_dev->scan_and_dump_gen1a(nullptr, nullptr, &magic_err)) {
                        tag.magic_type = "Gen1A";
                    } else if (tag.magic_type.empty()) {
                        tag.magic_type = "Normal";
                    }
                }

                if (tag.protocol == ProtocolKind::Iso15693) {
                    tag.identity_fields.erase("ATQA");
                    tag.identity_fields.erase("SAK");
                    if (tag.identity_fields.find("DSFID") == tag.identity_fields.end()) tag.identity_fields["DSFID"] = "00";
                    if (tag.identity_fields.find("AFI") == tag.identity_fields.end()) tag.identity_fields["AFI"] = "00";
                } else {
                    if (!card.atqa_hex.empty()) tag.identity_fields["ATQA"] = card.atqa_hex;
                    if (!card.sak_hex.empty()) tag.identity_fields["SAK"] = card.sak_hex;
                }
                emit_scan_summary(tag);
                emit_scan_tail();
                record = make_record_from_tag(tag, endpoint, false, "st25r");
                success = true;
            } else {
                push_log("No card detected");
                emit_scan_tail();
                error = card_ok ? "no card present" : card.detail;
            }
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.last_record = record;
            scan_.has_result = success;
            scan_.status = success ? "Card found" : "No card";
            scan_.error = error;
            return;
        } else if (endpoint.kind == TransportKind::SpiBus) {
            NfcHexLog::get().log_event("scan", "path spi-missing-device");
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.status = "SPI device not open";
            scan_.error = "No SPI device";
            return;
        }

        NfcHexLog::get().log_event("scan", "path transport");

        if (endpoint.kind == TransportKind::Mock) {
            record = build_mock_record(endpoint);
            emit_scan_summary(record.tag);
            emit_scan_tail();
            success = true;
        } else {
            if (!transport_raw) {
                std::lock_guard<std::mutex> lock(mutex_);
                scan_.running = false;
                scan_.status = "No transport";
                scan_.error = "Transport lost during scan";
                return;
            }

            // All I/O done WITHOUT holding mutex_ so UI thread can call scan_state() freely.
            Pn532KillerClient client(transport_raw);

            // For PN532Killer, InListPassiveTarget may return instantly (~50ms) with
            // "no passive target found" because the firmware ignores MxRtyPassiveActivation.
            // Poll for up to 4 seconds (matching nfc-usb-test behaviour) so the user
            // has time to place the card after pressing the scan button.
            // For plain PN532, set_rf_passive_retries(0x20) is configured during
            // detect_device, so each call already waits ~820ms – one call is enough.
            TagInfo tag;
            bool real_ok = false;
            {
                auto deadline = std::chrono::steady_clock::now()
                                + std::chrono::seconds(4);
                while (!real_ok && std::chrono::steady_clock::now() < deadline) {
                    tag = TagInfo{};
                    real_ok = client.in_list_passive_target_iso14443a(&tag, &error);
                    if (!real_ok)
                        std::this_thread::sleep_for(std::chrono::milliseconds(150));
                }
            }
            // For PN532Killer: also try ISO15693 if 14A found nothing.
            if (!real_ok) {
                push_log("No ISO14443A tag found");
                if (device_kind == DeviceKind::PN532Killer) {
                    std::string err15;
                    tag = TagInfo{};
                    real_ok = client.in_list_passive_target_iso15693(&tag, &err15);
                    if (!real_ok) {
                        push_log("No ISO15693 tag found");
                        error = err15.empty() ? "No tag found" : err15;
                    }
                } else {
                    error = error.empty() ? "No tag found" : error;
                }
            }
            if (real_ok) {
                if (tag.protocol == ProtocolKind::Iso15693) {
                    tag.identity_fields.erase("ATQA");
                    tag.identity_fields.erase("SAK");
                    tag.magic_type.clear();
                    if (find_identity(tag, "DSFID").empty()) tag.identity_fields["DSFID"] = "00";
                    if (find_identity(tag, "AFI").empty()) tag.identity_fields["AFI"] = "00";
                }

                auto is_mfc_like = [&]() {
                    if (tag.protocol == ProtocolKind::MifareClassic) return true;
                    const std::string type_up = to_upper(tag.tag_type);
                    if (type_up.find("MIFARE CLASSIC") != std::string::npos) return true;
                    std::string sak = normalize_identity_hex(find_identity(tag, "SAK"));
                    if (sak.size() >= 2) {
                        if (sak == "08" || sak == "09" || sak == "18" ||
                            sak == "28" || sak == "38" ||
                            sak == "88" || sak == "98") return true;
                    }
                    return false;
                };

                const bool can_magic_probe = is_mfc_like();

                if (can_magic_probe) {
                    std::string magic_err;
                    // Probe Gen3 first to avoid redundant HALT(0x50 0x00) on Gen3 cards.
                    if (client.is_gen3(&magic_err, &tag)) {
                        tag.magic_type = "Gen3";
                    } else if (client.is_gen1a(&magic_err)) {
                        tag.magic_type = "Gen1A";
                    } else if (client.is_gen4("00000000", &magic_err)) {
                        tag.magic_type = "Gen4";
                    } else {
                        // Explicitly mark MFC cards as Normal when all magic probes fail,
                        // so UI always shows a MAGIC line under SAK.
                        tag.magic_type = "Normal";
                    }
                }

                emit_scan_summary(tag);

                for (const auto &kv : tag.identity_fields) {
                    if (equals_ci(kv.first, "ATQA") || equals_ci(kv.first, "SAK") ||
                        equals_ci(kv.first, "UID_LEN") || equals_ci(kv.first, "UIDLEN")) continue;
                    push_log("  " + kv.first + ": " + kv.second);
                }
                emit_scan_tail();
                client.release_target_if_listed();
            } else {
                emit_scan_tail();
            }

            if (real_ok) {
                const std::string scan_source =
                    (device_kind == DeviceKind::PN532Killer) ? "pn532killer" :
                    (device_kind == DeviceKind::PN532)       ? "pn532"       : "nfc";
                record = make_record_from_tag(tag, endpoint, false, scan_source);
                success = true;
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        scan_.running = false;
        scan_.has_result = success;
        scan_.last_record = record;
        scan_.status = success ? "Scan ready" : "Scan failed";
        scan_.error = success ? record.meta.notes : "No tag found";
    }

    void perform_dump_from_last_scan()
    {
        NfcHexLog::get().log_event("dump", "start dump from last scan");

        TransportEndpoint endpoint;
        DeviceKind device_kind = DeviceKind::Unknown;
        INfcTransport *transport_raw = nullptr;
        I2cGroveNfcDevice *i2c_dev = nullptr;
        NfcSpiDevice *spi_dev = nullptr;
        SavedRecord base_record;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            endpoint = connection_.endpoint;
            device_kind = connection_.device_kind;
            transport_raw = transport_.get();
            i2c_dev = i2c_device_.get();
            spi_dev = spi_device_.get();
            base_record = scan_.last_record;
        }

        SavedRecord record = base_record;
        record.tag.raw_data.clear();
        record.tag.block_log.clear();
        record.mifare_dump.reset();

        std::string error;
        bool success = false;

        auto emit_dump_lines = [this](const std::vector<std::string> &lines) {
            for (const auto &line : lines) push_log(line);
        };

        auto bytes_to_hex = [](const std::vector<uint8_t> &bytes) {
            std::string out;
            out.reserve(bytes.size() * 2);
            char hb[3];
            for (uint8_t byte : bytes) {
                std::snprintf(hb, sizeof(hb), "%02X", byte);
                out += hb;
            }
            return out;
        };

        auto to_upper_copy = [](std::string s) {
            for (char &ch : s) {
                ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
            }
            return s;
        };

        auto normalize_hex = [&](std::string value) {
            value = to_upper_copy(std::move(value));
            std::string out;
            out.reserve(value.size());
            for (char ch : value) {
                if (std::isxdigit(static_cast<unsigned char>(ch))) out.push_back(ch);
            }
            return out;
        };

        auto find_identity_field = [&](const TagInfo &tag, const char *key) -> std::string {
            if (!key || !*key) return {};
            const std::string key_up = to_upper_copy(key);
            for (const auto &kv : tag.identity_fields) {
                if (to_upper_copy(kv.first) == key_up) return kv.second;
            }
            return {};
        };

        auto is_mfc_family = [&](const TagInfo &tag) {
            if (tag.protocol == ProtocolKind::MifareClassic) return true;
            const std::string type_up = to_upper_copy(tag.tag_type);
            if (type_up.find("MIFARE CLASSIC") != std::string::npos) return true;
            if (type_up.find(" S20") != std::string::npos || type_up.find(" S50") != std::string::npos ||
                type_up.find(" S70") != std::string::npos) return true;
            const std::string sak = normalize_hex(find_identity_field(tag, "SAK"));
                return (sak == "08" || sak == "09" || sak == "18" ||
                    sak == "28" || sak == "38" || sak == "88" || sak == "98");
        };

        auto is_desfire_family = [&](const TagInfo &tag) {
            const std::string type_up = to_upper_copy(tag.tag_type);
            if (type_up.find("DESFIRE") != std::string::npos) return true;
            const std::string sak = normalize_hex(find_identity_field(tag, "SAK"));
            return sak == "20";
        };

        auto emit_desfire_info_only = [&](SavedRecord &target_record) {
            push_log("> MIFARE DESFire detected");
            push_log("> Info-only mode (dump not supported)");
            const std::string uid = target_record.tag.uid.empty() ? "-" : target_record.tag.uid;
            const std::string atqa = normalize_hex(find_identity_field(target_record.tag, "ATQA"));
            const std::string sak = normalize_hex(find_identity_field(target_record.tag, "SAK"));

            std::vector<std::string> info_lines;
            info_lines.push_back(std::string("Type:") +
                                 (target_record.tag.tag_type.empty() ? "MIFARE DESFire"
                                                                     : target_record.tag.tag_type));
            info_lines.push_back(std::string("UID:") + uid);
            info_lines.push_back(std::string("ATQA:") + (atqa.empty() ? "-" : atqa));
            info_lines.push_back(std::string("SAK:") + (sak.empty() ? "-" : sak));
            info_lines.push_back("DESFire dump is not supported yet.");

            emit_dump_lines(info_lines);
            target_record.tag.raw_data = info_lines;
        };

        if (endpoint.kind == TransportKind::I2cBus) {
            if (!i2c_dev || !i2c_dev->is_open()) {
                error = "I2C device not open";
                push_log(std::string("ERR ") + error);
            } else {
                ProtocolKind dump_protocol = record.tag.protocol;
                if (dump_protocol == ProtocolKind::Iso14443A) {
                    if (is_desfire_family(record.tag)) {
                        emit_desfire_info_only(record);
                        success = true;
                    } else if (is_mfc_family(record.tag)) {
                        dump_protocol = ProtocolKind::MifareClassic;
                        record.tag.protocol = ProtocolKind::MifareClassic;
                        if (record.tag.tag_type.empty()) record.tag.tag_type = "MIFARE Classic";
                    }
                }

                const bool is_mfc = (dump_protocol == ProtocolKind::MifareClassic);
                if (!success) {
                    push_log(std::string("> Dumping I2C ") + (is_mfc ? "MFC" :
                        (dump_protocol == ProtocolKind::Iso15693 ? "ISO15693" : "MFU/NTAG")) + "...");
                }

                std::vector<std::string> mfc_default_keys;
                if (!success && is_mfc && record.tag.magic_type != "Gen1A") {
                    std::set<std::string> uniq;
                    auto append_key = [&](const std::string &raw_hex) {
                        std::string key;
                        key.reserve(12);
                        for (char c : raw_hex) {
                            if (std::isxdigit(static_cast<unsigned char>(c))) {
                                key.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
                                if (key.size() == 12) break;
                            }
                        }
                        if (key.size() != 12) return;
                        if (uniq.insert(key).second) mfc_default_keys.push_back(key);
                    };

                    const auto json_keys = storage_.load_mifare_keys();
                    for (const auto &k : json_keys) {
                        if (!k.enabled) continue;
                        append_key(k.key_hex);
                    }

                    const auto key_files = storage_.list_key_files();
                    for (const auto &fn : key_files) {
                        const auto file_keys = storage_.load_key_file(fn);
                        for (const auto &k : file_keys) append_key(k);
                    }

                    char key_msg[48];
                    std::snprintf(key_msg, sizeof(key_msg), "MFC Key loaded: %d", static_cast<int>(mfc_default_keys.size()));
                    push_log(key_msg);
                }

                std::vector<std::string> dump_lines;
                std::string i2c_magic_type;
                std::string dump_err;
                const std::function<void(const std::string &)> dump_progress = [this](const std::string &line) {
                    push_log(line);
                };
                if (!success && i2c_dev->dumpCard(dump_protocol,
                                                  record.tag.uid,
                                                  record.tag.tag_type,
                                                  is_mfc ? &mfc_default_keys : nullptr,
                                                  &i2c_magic_type,
                                                  dump_lines,
                                                  is_mfc ? &dump_progress : nullptr,
                                                  &dump_err)) {
                    record.tag.protocol = dump_protocol;
                    record.tag.raw_data = dump_lines;
                    if (!i2c_magic_type.empty()) {
                        record.tag.magic_type = i2c_magic_type;
                        push_log(std::string("MAGIC: ") + i2c_magic_type);
                    }

                    if (dump_protocol == ProtocolKind::MifareClassic) {
                        record.mifare_dump = MifareClassicDump{};
                        const int block_count = static_cast<int>(dump_lines.size());
                        record.mifare_dump->block_count = block_count;
                        record.mifare_dump->sector_count = (block_count >= 256) ? 40 :
                                                           (block_count >= 64)  ? 16 :
                                                           (block_count >= 20)  ? 5 : 0;
                        record.mifare_dump->blocks_hex = dump_lines;
                        record.mifare_dump->attack.method = AttackMethod::DefaultKeys;
                        record.mifare_dump->attack.status = AttackStatus::Success;
                        record.mifare_dump->attack.dump_obtained = !dump_lines.empty();
                        emit_dump_lines(dump_lines);
                    } else {
                        emit_dump_lines(dump_lines);
                    }

                    push_log("Tip: Press Ctrl+S to save dump.");
                    success = !record.tag.raw_data.empty();
                } else if (!success) {
                    error = dump_err.empty() ? "I2C dump failed" : dump_err;
                    push_log(std::string("ERR ") + error);
                }
            }
        } else if (endpoint.kind == TransportKind::SpiBus) {
            if (!spi_dev || !spi_dev->is_open()) {
                error = "SPI device not open";
                push_log(std::string("ERR ") + error);
            } else {
                // Current SPI ST25R dump path is Gen1A-focused.
                push_log("> Dumping SPI ST25R (Gen1A)...");
                I2cCardInfo card_info;
                std::vector<std::vector<uint8_t>> blocks;
                std::string dump_err;
                if (spi_dev->scan_and_dump_gen1a(&card_info, &blocks, &dump_err)) {
                    record.tag.uid = card_info.uid;
                    const auto proto = i2c_protocol_to_kind(card_info.protocol);
                    if (proto != ProtocolKind::Unknown) record.tag.protocol = proto;
                    const std::string type = i2c_protocol_to_tag_type(card_info.protocol);
                    if (!type.empty()) record.tag.tag_type = type;
                    record.tag.magic_type = "Gen1A";
                    if (!card_info.atqa_hex.empty()) record.tag.identity_fields["ATQA"] = card_info.atqa_hex;
                    if (!card_info.sak_hex.empty()) record.tag.identity_fields["SAK"] = card_info.sak_hex;

                    std::vector<std::string> dump_lines;
                    dump_lines.reserve(blocks.size());
                    for (size_t i = 0; i < blocks.size(); ++i) {
                        char prefix[8];
                        std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
                        const std::string line = std::string(prefix) + bytes_to_hex(blocks[i]);
                        dump_lines.push_back(line);
                        record.tag.raw_data.push_back(line);
                    }

                    record.mifare_dump = MifareClassicDump{};
                    record.mifare_dump->sector_count = 16;
                    record.mifare_dump->block_count = static_cast<int>(dump_lines.size());
                    record.mifare_dump->blocks_hex = dump_lines;
                    record.mifare_dump->attack.method = AttackMethod::None;
                    record.mifare_dump->attack.status = AttackStatus::Success;
                    record.mifare_dump->attack.dump_obtained = !dump_lines.empty();

                    emit_dump_lines(dump_lines);
                    if (!dump_err.empty()) push_log(std::string("WARN ") + dump_err);
                    push_log("Tip: Press Ctrl+S to save dump.");
                    success = !record.tag.raw_data.empty();
                } else {
                    error = dump_err.empty() ? "SPI dump failed (not Gen1A?)" : dump_err;
                    push_log(std::string("ERR ") + error);
                }
            }
        } else if (endpoint.kind == TransportKind::Mock) {
            record = build_mock_record(endpoint);
            success = true;
        } else {
            if (!transport_raw) {
                error = "Transport lost during dump";
                push_log(std::string("ERR ") + error);
            } else {
                Pn532KillerClient client(transport_raw);
                TagInfo live_tag;
                bool card_ok = false;

                push_log("> Detecting card for dump...");
                if (base_record.tag.protocol == ProtocolKind::Iso15693) {
                    card_ok = client.in_list_passive_target_iso15693(&live_tag, &error);
                } else {
                    card_ok = client.in_list_passive_target_iso14443a(&live_tag, &error);
                }

                if (!card_ok) {
                    push_log(std::string("ERR ") + (error.empty() ? "no card" : error));
                } else {
                    const bool same_or_compatible_protocol =
                        (live_tag.protocol == base_record.tag.protocol) ||
                        ((live_tag.protocol == ProtocolKind::Iso14443A || live_tag.protocol == ProtocolKind::MifareClassic) &&
                         (base_record.tag.protocol == ProtocolKind::Iso14443A || base_record.tag.protocol == ProtocolKind::MifareClassic));
                    if (!same_or_compatible_protocol) {
                        error = "Card type mismatch, rescan card";
                        push_log(std::string("ERR ") + error);
                    } else {
                        record.tag.uid = live_tag.uid;
                        if (live_tag.protocol != ProtocolKind::Unknown)
                            record.tag.protocol = live_tag.protocol;
                        if (!live_tag.tag_type.empty()) record.tag.tag_type = live_tag.tag_type;
                        if (!live_tag.identity_fields.empty())
                            record.tag.identity_fields = live_tag.identity_fields;

                        bool handled = false;
                        if (record.tag.protocol == ProtocolKind::Iso14443A &&
                            is_desfire_family(record.tag)) {
                            emit_desfire_info_only(record);
                            success = true;
                            handled = true;
                        }

                        if (!handled && record.tag.protocol == ProtocolKind::Iso14443A &&
                            (base_record.tag.protocol == ProtocolKind::MifareClassic || is_mfc_family(record.tag))) {
                            record.tag.protocol = ProtocolKind::MifareClassic;
                            if (to_upper_copy(record.tag.tag_type).find("MIFARE CLASSIC") == std::string::npos &&
                                !base_record.tag.tag_type.empty()) {
                                record.tag.tag_type = base_record.tag.tag_type;
                            }
                            handled = false;
                        }

                        if (!handled && record.tag.protocol == ProtocolKind::Iso15693) {
                            if (device_kind == DeviceKind::PN532) {
                                error = "PN532 ISO15693 read not supported";
                                push_log(std::string("ERR ") + error);
                            } else {
                            push_log("> Dumping ISO15693 blocks...");
                            std::vector<std::vector<uint8_t>> blocks;
                            std::string dump_err;
                            if (client.iso15693_read_all_blocks(&blocks, &dump_err, nullptr)) {
                                std::vector<std::string> dump_lines;
                                dump_lines.reserve(blocks.size());
                                for (size_t i = 0; i < blocks.size(); ++i) {
                                    char prefix[8];
                                    std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
                                    const std::string line = std::string(prefix) + bytes_to_hex(blocks[i]);
                                    dump_lines.push_back(line);
                                    record.tag.raw_data.push_back(line);
                                }
                                emit_dump_lines(dump_lines);
                                push_log("Tip: Press Ctrl+S to save dump.");
                                success = !record.tag.raw_data.empty();
                            } else {
                                error = dump_err.empty() ? "ISO15693 dump failed" : dump_err;
                                push_log(std::string("ERR ") + error);
                            }
                            }
                        } else if (!handled && record.tag.protocol == ProtocolKind::Iso14443A) {
                            push_log("> Dumping NTAG/Ultralight pages...");
                            std::vector<std::vector<uint8_t>> pages;
                            std::string ntag_type;
                            std::string dump_err;
                            if (client.ntag_read_all_pages(&pages, &ntag_type, &dump_err, nullptr)) {
                                if (!ntag_type.empty()) record.tag.tag_type = ntag_type;
                                std::vector<std::string> dump_lines;
                                dump_lines.reserve(pages.size());
                                for (size_t i = 0; i < pages.size(); ++i) {
                                    char prefix[8];
                                    std::snprintf(prefix, sizeof(prefix), "%02d:", static_cast<int>(i));
                                    const std::string line = std::string(prefix) + bytes_to_hex(pages[i]);
                                    dump_lines.push_back(line);
                                    record.tag.raw_data.push_back(line);
                                }
                                emit_dump_lines(dump_lines);
                                if (static_cast<int>(dump_lines.size()) > 24)
                                    push_log("Tip: Press Ctrl+S to save dump.");
                                success = !record.tag.raw_data.empty();
                            } else {
                                error = dump_err.empty() ? "NTAG dump failed" : dump_err;
                                push_log(std::string("ERR ") + error);
                            }
                        } else if (!handled && record.tag.protocol == ProtocolKind::MifareClassic) {
                            std::vector<std::string> mfc_blocks;
                            bool mfc_read_ok = false;
                            const int sc = (record.tag.tag_type.find("4K") != std::string::npos) ? 40 : 16;

                            if (device_kind == DeviceKind::PN532 ||
                                device_kind == DeviceKind::PN532Killer) {
                                std::string magic_err;
                                // Keep the same probe order as scan path to reduce duplicate HALT logs.
                                if (client.is_gen3(&magic_err, &live_tag)) {
                                    record.tag.magic_type = "Gen3";
                                    push_log("MAGIC: Gen3");
                                } else if (client.is_gen1a(&magic_err)) {
                                    record.tag.magic_type = "Gen1A";
                                    push_log("MAGIC: Gen1A");
                                    push_log("> Reading Gen1A blocks...");
                                    client.read_gen1a_full(nullptr, &record.tag.block_log, &magic_err,
                                        [this](const std::string &line) { push_log(line); },
                                        (device_kind == DeviceKind::PN532Killer) ? 5 : 0);
                                } else if (client.is_gen4("00000000", &magic_err)) {
                                    record.tag.magic_type = "Gen4";
                                    push_log("MAGIC: Gen4");
                                }
                            }

                            if (record.tag.magic_type.empty() || record.tag.magic_type == "Gen3" ||
                                record.tag.magic_type == "Gen4") {
                                push_log("> Reading MFC blocks (default keys)...");
                                std::vector<uint8_t> uid_bytes;
                                for (size_t i = 0; i + 1 < live_tag.uid.size(); i += 2) {
                                    uid_bytes.push_back(static_cast<uint8_t>(
                                        std::stoi(live_tag.uid.substr(i, 2), nullptr, 16)));
                                }
                                std::string mfc_err;
                                mfc_read_ok = client.read_mifare_standard(uid_bytes, sc, &mfc_blocks, &mfc_err,
                                    [this](const std::string &line) { push_log(line); });
                                if (!mfc_read_ok && !mfc_err.empty()) error = mfc_err;
                            }

                            record.mifare_dump = MifareClassicDump{};
                            record.mifare_dump->sector_count = sc;
                            record.mifare_dump->block_count = (sc <= 32) ? sc * 4 : 32 * 4 + (sc - 32) * 16;

                            if (mfc_read_ok) {
                                record.mifare_dump->blocks_hex = mfc_blocks;
                                record.mifare_dump->attack.method = AttackMethod::DefaultKeys;
                                record.mifare_dump->attack.status = AttackStatus::Success;
                                record.mifare_dump->attack.dump_obtained = true;
                                record.tag.raw_data = mfc_blocks;
                                success = true;
                            } else if (!record.tag.block_log.empty()) {
                                record.mifare_dump->blocks_hex.assign(record.mifare_dump->block_count, "");
                                for (const auto &line : record.tag.block_log) {
                                    if (line.size() >= 4 && line[2] == ':') {
                                        const int blk = std::stoi(line.substr(0, 2), nullptr, 10);
                                        if (blk >= 0 && blk < record.mifare_dump->block_count)
                                            record.mifare_dump->blocks_hex[blk] = line.substr(3);
                                    }
                                }
                                record.mifare_dump->attack.method = AttackMethod::None;
                                record.mifare_dump->attack.status = AttackStatus::Success;
                                record.mifare_dump->attack.dump_obtained = true;
                                record.tag.raw_data = record.mifare_dump->blocks_hex;
                                success = true;
                            } else {
                                if (error.empty()) error = "Mifare dump failed";
                                record.mifare_dump->attack.status = AttackStatus::Failed;
                                record.mifare_dump->attack.reason = error;
                                push_log(std::string("ERR ") + error);
                            }
                        } else if (!handled) {
                            error = "Unsupported protocol for dump";
                            push_log(std::string("ERR ") + error);
                        }
                    }
                }

                client.release_target_if_listed();
            }
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            scan_.running = false;
            scan_.has_result = true;
            if (success) {
                scan_.last_record = record;
                scan_.status = "Dump ready";
                scan_.error.clear();
                last_dump_success_ = true;
            } else {
                scan_.last_record = base_record;
                scan_.status = "Dump failed";
                scan_.error = error.empty() ? "dump failed" : error;
                last_dump_success_ = false;
            }
        }
    }

    static std::vector<uint8_t> build_ndef_message_from_uri(const std::string &uri)
    {
        auto starts_with = [](const std::string &s, const char *prefix) {
            return s.rfind(prefix, 0) == 0;
        };

        std::vector<uint8_t> record;
        if (starts_with(uri, "https://") || starts_with(uri, "http://") ||
            starts_with(uri, "tel:") || starts_with(uri, "mailto:")) {
            uint8_t prefix = 0x00;
            std::string rest = uri;
            if (starts_with(uri, "http://www.")) {
                prefix = 0x01;
                rest = uri.substr(11);
            } else if (starts_with(uri, "https://www.")) {
                prefix = 0x02;
                rest = uri.substr(12);
            } else if (starts_with(uri, "http://")) {
                prefix = 0x03;
                rest = uri.substr(7);
            } else if (starts_with(uri, "https://")) {
                prefix = 0x04;
                rest = uri.substr(8);
            } else if (starts_with(uri, "tel:")) {
                prefix = 0x05;
                rest = uri.substr(4);
            } else if (starts_with(uri, "mailto:")) {
                prefix = 0x06;
                rest = uri.substr(7);
            }

            std::vector<uint8_t> payload;
            payload.reserve(rest.size() + 1);
            payload.push_back(prefix);
            payload.insert(payload.end(), rest.begin(), rest.end());

            record = {0xD1, 0x01, static_cast<uint8_t>(payload.size()), 0x55};
            record.insert(record.end(), payload.begin(), payload.end());
        } else {
            std::vector<uint8_t> payload = {0x02, 0x65, 0x6E};
            payload.insert(payload.end(), uri.begin(), uri.end());
            record = {0xD1, 0x01, static_cast<uint8_t>(payload.size()), 0x54};
            record.insert(record.end(), payload.begin(), payload.end());
        }

        std::vector<uint8_t> out;
        const uint16_t ndef_len = static_cast<uint16_t>(record.size());
        out.push_back(static_cast<uint8_t>((ndef_len >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(ndef_len & 0xFF));
        out.insert(out.end(), record.begin(), record.end());
        return out;
    }

    void perform_pn532_ndef_emulation(const std::string &uri)
    {
        INfcTransport *transport_raw = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            pn532_ndef_.status = "Initializing";
            pn532_ndef_.error.clear();
        }
        if (!transport_raw || !transport_raw->is_open()) {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.running = false;
            pn532_ndef_.status = "Init failed";
            pn532_ndef_.error = "Transport not available";
            return;
        }

        // Target mode exchanges must be exclusive on the transport.
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        Pn532KillerClient client(transport_raw);
        const std::vector<uint8_t> tg_init_cfg = {
            0x04, 0x08, 0x00, 0x11, 0x22, 0x33, 0x60, 0x01, 0xFE, 0xA2,
            0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4,
            0xC5, 0xC6, 0xC7, 0xFF, 0xFF, 0xAA, 0x99, 0x88, 0x77, 0x66,
            0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00
        };

        bool init_ok = false;
        std::string init_err;
        for (int attempt = 0; attempt < 8 && !cancel_pn532_ndef_.load(); ++attempt) {
            client.send_wakeup();
            client.sam_configuration(nullptr);
            std::vector<uint8_t> init_resp;
            if (client.tg_init_as_target(tg_init_cfg, &init_resp, &init_err)) {
                init_ok = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(120));
        }

        if (!init_ok) {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.running = false;
            pn532_ndef_.status = "Init failed";
            pn532_ndef_.error = init_err.empty() ? "TgInitAsTarget failed" : init_err;
            return;
        }

        const std::vector<uint8_t> cc = {
            0x00, 0x0F, 0x20, 0x00, 0x54, 0x00, 0xFF, 0x04,
            0x06, 0xE1, 0x04, 0x00, 0xFF, 0x00, 0x00
        };
        const std::vector<uint8_t> ndef = build_ndef_message_from_uri(uri);

        enum class TagFile { None, CC, Ndef };
        TagFile current_file = TagFile::None;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.status = "Emulating";
            pn532_ndef_.error.clear();
        }

        while (!cancel_pn532_ndef_.load()) {
            std::vector<uint8_t> req;
            std::string req_err;
            if (!client.tg_get_data(&req, &req_err)) {
                if (!req_err.empty()) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    pn532_ndef_.error = req_err;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
                continue;
            }
            if (req.empty()) continue;

            const uint8_t tg_status = req[0];
            if (tg_status == 0x29 || tg_status == 0x25) {
                std::vector<uint8_t> init_resp;
                client.tg_init_as_target(tg_init_cfg, &init_resp, nullptr);
                current_file = TagFile::None;
                continue;
            }

            if (req.size() < 6) continue;
            std::vector<uint8_t> apdu(req.begin() + 1, req.end());
            if (apdu.size() < 5) continue;

            const uint8_t ins = apdu[1];
            const uint8_t p1 = apdu[2];
            const uint8_t p2 = apdu[3];
            const uint8_t lc = apdu[4];
            std::vector<uint8_t> rsp;

            // ISO7816 constants used by Bruce's PN532 NDEF emulation flow.
            constexpr uint8_t INS_SELECT_FILE = 0xA4;
            constexpr uint8_t INS_READ_BINARY = 0xB0;
            constexpr uint8_t INS_UPDATE_BINARY = 0xD6;
            constexpr uint8_t SW1_OK = 0x90;
            constexpr uint8_t SW2_OK = 0x00;
            constexpr uint8_t SW1_NF = 0x6A;
            constexpr uint8_t SW2_NF = 0x82;

            if (ins == INS_SELECT_FILE) {
                if (p1 == 0x00) { // select by id
                    if (p2 != 0x0C) {
                        rsp = {SW1_OK, SW2_OK};
                    } else if (lc == 0x02 && apdu.size() >= 7 && apdu[5] == 0xE1 &&
                               (apdu[6] == 0x03 || apdu[6] == 0x04)) {
                        current_file = (apdu[6] == 0x03) ? TagFile::CC : TagFile::Ndef;
                        rsp = {SW1_OK, SW2_OK};
                    } else {
                        rsp = {SW1_NF, SW2_NF};
                    }
                } else if (p1 == 0x04) { // select by AID
                    rsp = {SW1_OK, SW2_OK};
                } else {
                    rsp = {SW1_NF, SW2_NF};
                }
            } else if (ins == INS_READ_BINARY) {
                const uint16_t offset = static_cast<uint16_t>((p1 << 8) | p2);
                const uint8_t le = lc;
                if (current_file == TagFile::CC) {
                    if (offset + le <= cc.size()) {
                        rsp.insert(rsp.end(), cc.begin() + offset, cc.begin() + offset + le);
                    }
                    rsp.push_back(SW1_OK);
                    rsp.push_back(SW2_OK);
                } else if (current_file == TagFile::Ndef) {
                    if (offset + le <= ndef.size()) {
                        rsp.insert(rsp.end(), ndef.begin() + offset, ndef.begin() + offset + le);
                    }
                    rsp.push_back(SW1_OK);
                    rsp.push_back(SW2_OK);
                } else {
                    rsp = {SW1_NF, SW2_NF};
                }
            } else if (ins == INS_UPDATE_BINARY) {
                rsp = {SW1_OK, SW2_OK};
            } else {
                rsp = {SW1_NF, SW2_NF};
            }

            if (!rsp.empty()) {
                std::string set_err;
                client.tg_set_data(rsp, &set_err);
                if (!set_err.empty()) {
                    std::lock_guard<std::mutex> lock(mutex_);
                    pn532_ndef_.error = set_err;
                }
            }
        }

        client.in_release_all();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            pn532_ndef_.running = false;
            if (pn532_ndef_.status != "Init failed") pn532_ndef_.status = "Stopped";
        }
    }

    SavedRecord build_mock_record(const TransportEndpoint &endpoint) const
    {
        // Rotate through card types so mock scanner appears dynamic
        const int kind = scan_mock_counter_++ % 3;

        TagInfo tag;
        if (kind == 0) {
            tag.protocol = ProtocolKind::MifareClassic;
            tag.tag_type = "Mifare Classic 1K";
            tag.uid = "DE AD BE EF";
            tag.identity_fields["ATQA"] = "0004";
            tag.identity_fields["SAK"]  = "08";
            tag.identity_fields["capacity"] = "1K";
            tag.raw_data = {
                "Block0:  DE AD BE EF 21 08 04 00 46 49 4C 4C 45 44 4B 45",
                "Block1:  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "Block3:  FF FF FF FF FF FF FF 07 80 69 FF FF FF FF FF FF",
            };
        } else if (kind == 1) {
            tag.protocol = ProtocolKind::Iso14443A;
            tag.tag_type = "NFC-A Type 4 (NTAG213)";
            tag.uid = "04 B3 7C 2A";
            tag.identity_fields["ATQA"] = "0044";
            tag.identity_fields["SAK"]  = "00";
            tag.identity_fields["type"] = "NTAG213 144B";
            tag.raw_data = {
                "UID: 04 B3 7C 2A",
                "CC: E1 10 12 00  (NDEF 144B)",
                "NDEF: https://m5stack.com/products/cardputer",
            };
        } else {
            tag.protocol = ProtocolKind::Iso15693;
            tag.tag_type = "ISO 15693 (iCODE SLI)";
            tag.uid = "E0 04 01 00 5A 4B 3C 2D";
            tag.identity_fields["dsfid"] = "00";
            tag.identity_fields["afi"]   = "00";
            tag.identity_fields["blocks"] = "32 x 4B";
            tag.raw_data = {
                "UID(rev): E0 04 01 00 5A 4B 3C 2D",
                "DSFID:00  AFI:00  Blocks:32x4B",
                "Block0: 48 65 6C 6C  ('Hell')",
            };
        }

        SavedRecord record = make_record_from_tag(tag, endpoint, true, "mock_scan");
        if (kind == 0) {
            MifareClassicDump dump;
            dump.sector_count = 16;
            dump.block_count  = 64;
            dump.attack.method = AttackMethod::DefaultKeys;
            dump.attack.status = AttackStatus::Success;
            dump.attack.dump_obtained = true;
            // Generate 64 mock blocks of 16 bytes each.
            // Sector trailers (blocks 3,7,11,...,63) use FF..FF key pattern.
            for (int blk = 0; blk < 64; ++blk) {
                char hex[33];
                const bool trailer = ((blk + 1) % 4 == 0);
                if (blk == 0) {
                    // Block 0: UID + manufacturer data
                    std::snprintf(hex, sizeof(hex), "DEADBEEF2108040046494C4C45444B45");
                } else if (trailer) {
                    std::snprintf(hex, sizeof(hex), "FFFFFFFFFFFF078069FFFFFFFFFFFF%02X", blk);
                } else {
                    std::snprintf(hex, sizeof(hex), "000000000000000000000000000000%02X", blk);
                }
                dump.blocks_hex.push_back(hex);
            }
            // Populate raw_data so the Hex Editor shows all 64 blocks.
            record.tag.raw_data = dump.blocks_hex;
            record.mifare_dump = dump;
        }
        record.meta.notes = "Mock data — PN532Killer command set pending";
        return record;
    }

    SavedRecord make_record_from_tag(const TagInfo &tag, const TransportEndpoint &endpoint, bool mock, const std::string &source) const
    {
        SavedRecord record;
        record.meta.created_at = iso8601_now();
        record.meta.record_id = make_record_id(tag);
        record.meta.display_name = make_record_name(tag);
        record.meta.source = source;
        record.meta.transport = endpoint.kind;
        record.meta.transport_path = endpoint.path;
        record.meta.mock = mock;
        record.tag = tag;
        return record;
    }

    EmulatorSlotRecord &current_slot_locked()
    {
        return current_slot_for_protocol_locked(selected_emulator_protocol_, selected_slot_by_protocol_[selected_emulator_protocol_]);
    }

    EmulatorSlotRecord &current_slot_for_protocol_locked(ProtocolKind protocol, int slot_index)
    {
        ensure_protocol_slots_locked(protocol);
        auto &slots = emulator_slots_by_protocol_[protocol];
        if (slot_index < 0) slot_index = 0;
        if (slot_index > 7) slot_index = 7;
        return slots[slot_index];
    }

    void ensure_protocol_slots_locked(ProtocolKind protocol)
    {
        auto &slots = emulator_slots_by_protocol_[protocol];
        while (static_cast<int>(slots.size()) < 8) {
            EmulatorSlotRecord empty;
            empty.slot_index = static_cast<int>(slots.size());
            empty.protocol = protocol;
            slots.push_back(empty);
        }
        for (size_t i = 0; i < slots.size(); ++i) {
            slots[i].slot_index = static_cast<int>(i);
            slots[i].protocol = protocol;
        }
    }

    // Extract raw bytes from profile slot for EEPROM write.
    std::vector<uint8_t> slot_data_bytes_for_emulation_locked(ProtocolKind protocol, int slot)
    {
        const auto slots = protocol_slots_padded_locked(protocol);
        if (slot < 0 || slot >= static_cast<int>(slots.size())) return {};
        const auto &raw = slots[slot].raw_data;
        if (raw.empty()) return {};
        std::vector<uint8_t> bytes;
        for (const auto &line : raw) {
            std::string pure;
            size_t c = line.find(':');
            std::string hex = (c != std::string::npos && c + 1 < line.size()) ? line.substr(c + 1) : line;
            for (char ch : hex) if (std::isxdigit((unsigned char)ch)) pure += (char)std::toupper((unsigned char)ch);
            for (size_t i = 0; i + 1 < pure.size(); i += 2) {
                char *end = nullptr;
                unsigned long val = std::strtoul(pure.substr(i, 2).c_str(), &end, 16);
                if (end && *end == '\0') bytes.push_back(static_cast<uint8_t>(val));
            }
        }
        return bytes;
    }

    std::vector<EmulatorSlotRecord> protocol_slots_padded_locked(ProtocolKind protocol) const
    {
        auto it = emulator_slots_by_protocol_.find(protocol);
        std::vector<EmulatorSlotRecord> slots = (it == emulator_slots_by_protocol_.end()) ? std::vector<EmulatorSlotRecord>{} : it->second;
        while (static_cast<int>(slots.size()) < 8) {
            EmulatorSlotRecord empty;
            empty.slot_index = static_cast<int>(slots.size());
            empty.protocol = protocol;
            slots.push_back(empty);
        }
        return slots;
    }

    bool save_emulator_slots_locked()
    {
        ensure_protocol_slots_locked(ProtocolKind::Iso14443A);
        ensure_protocol_slots_locked(ProtocolKind::Iso14443B);
        ensure_protocol_slots_locked(ProtocolKind::Iso15693);
        ensure_protocol_slots_locked(ProtocolKind::MifareClassic);
        return storage_.save_emulator_slots_by_protocol(emulator_slots_by_protocol_);
    }

    // Push a log line from ANY thread without holding mutex_.
    void push_log(const std::string &line)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        pending_log_lines_.push_back(line);
    }

    mutable std::mutex mutex_;
    mutable std::mutex pending_log_mutex_;          // separate — safe to lock inside scan thread
    std::mutex transport_op_mutex_;                 // serialize all transport write/read cycles
    std::vector<std::string> pending_log_lines_;    // real-time per-block lines, drained by UI
    NfcStorage storage_;
    std::vector<TransportEndpoint> endpoints_;
    int selected_endpoint_ = 0;
    TransportKind intended_kind_ = TransportKind::UsbSerial; // tracks user intent even when no device
    std::unique_ptr<INfcTransport> transport_;
    std::unique_ptr<I2cGroveNfcDevice> i2c_device_;
    std::unique_ptr<NfcSpiDevice> spi_device_;
    ConnectionState connection_;
    ScanState scan_;
    std::unordered_map<std::string, UhfTagSnapshot> uhf_tags_;
    bool uhf_continuous_mode_ = false;
    std::string uhf_last_csv_path_;
    std::atomic<bool> cancel_uhf_scan_{false};
    bool last_dump_success_ = false;
    ProtocolKind selected_emulator_protocol_ = ProtocolKind::MifareClassic;
    std::map<ProtocolKind, int> selected_slot_by_protocol_;
    std::map<ProtocolKind, std::vector<EmulatorSlotRecord>> emulator_slots_by_protocol_;
    std::thread scan_thread_;
    std::thread probe_thread_;
    std::thread emu_probe_thread_;
    std::atomic<bool> cancel_emu_probe_{false};
    std::thread emu_dump_thread_;
    std::atomic<bool> cancel_emu_dump_{false};
    std::thread pn532_ndef_thread_;
    std::atomic<bool> cancel_pn532_ndef_{false};
    std::thread hw_upload_thread_;
    std::atomic<bool> cancel_hw_upload_{false};
    std::thread hw_mfkey_thread_;
    std::atomic<bool> cancel_hw_mfkey_{false};
    std::thread nfc_unit_mfkey_sniff_thread_;
    std::atomic<bool> nfc_unit_mfkey_sniff_cancel_{false};
    std::atomic<bool> nfc_unit_mfkey_sniff_running_{false};
    std::thread nfc_unit_emu_start_thread_;
    std::thread nfc_unit_emu_thread_;
    std::atomic<bool> nfc_unit_emu_cancel_{false};
    std::thread spi_emu_thread_;
    std::atomic<bool> spi_emu_cancel_{false};
    int spi_emu_profile_ = 0;  // 0=MFC 1K, 1=NTAG215, 2=NTAG216
    std::vector<uint8_t> spi_emu_uid_;
    uint16_t spi_emu_atqa_ = 0;
    uint8_t spi_emu_sak_ = 0;
    std::atomic<bool> nfc_unit_emu_running_{false};
    ProtocolKind nfc_unit_emu_protocol_ = ProtocolKind::Iso14443A;
    int nfc_unit_emu_profile_ = 0;  // 0=NTAG213, 1=ISO15693
    std::string nfc_unit_ndef_uri_ = "https://m5stack.com";
    size_t nfc_unit_ntag_pages_ = kNfcUnitNtag213Pages;
    std::vector<uint8_t> nfc_unit_ntag_mem_;
    mutable std::mutex nfc_unit_mfkey_mutex_;
    std::vector<NfcUnitMfkeyEntry> nfc_unit_mfkey_entries_;
    std::vector<std::string> mifare_keys_hex_list_;  // MFC key list for auth (dump + write)
    std::string mfkey_sniff_uid_hex_ = "11223344";
    static constexpr uint32_t kNfcUnitMfc1kUid = 0x11223344;
    static constexpr uint16_t kNfcUnitMfc1kAtqa = 0x0004;
    static constexpr uint8_t kNfcUnitMfc1kSak = 0x08;
    uint32_t nfc_unit_mfkey_uid_ = kNfcUnitMfc1kUid;
    std::map<std::pair<ProtocolKind,int>, EmuSlotInfo> emu_slot_cache_;
    bool emu_probe_running_ = false;
    bool emu_dump_running_  = false;
    bool hw_upload_running_ = false;
    int  hw_upload_progress_ = 0;   // 0-64 (blocks uploaded so far)
    bool hw_upload_ok_       = false;
    bool hw_mfkey_running_   = false;
    int  hw_mfkey_progress_  = 0;
    bool nfc_unit_emu_start_running_ = false;
    bool nfc_unit_emu_start_has_result_ = false;
    bool nfc_unit_emu_start_ok_ = false;
    std::string nfc_unit_emu_start_status_;
    std::string nfc_unit_emu_start_error_;
    std::string nfc_unit_emu_start_profile_;
    std::vector<MfkeyResult> hw_mfkey_results_;
    std::string emu_probe_error_;
    mutable int scan_mock_counter_ = 0;
    std::vector<DeviceProbeResult> probe_results_;
    bool probe_running_ = false;
    UartConfig uart_config_;
    // Async UART test
    std::thread uart_test_thread_;
    bool uart_test_running_ = false;          // guarded by pending_log_mutex_
    std::string uart_test_result_;            // guarded by pending_log_mutex_
    std::vector<std::string> uart_test_log_lines_; // guarded by pending_log_mutex_
    Pn532NdefState pn532_ndef_;

    void finish_uart_test(const std::string &result)
    {
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        uart_test_result_ = result;
        uart_test_running_ = false;
    }

    void perform_emu_slot_probe(ProtocolKind protocol, int slot)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "probe EMU slot %d", slot + 1);
            NfcHexLog::get().log_event("emu-probe", msg);
        }
        INfcTransport *transport_raw = nullptr;
        TransportKind ep_kind = TransportKind::UsbSerial;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            ep_kind = connection_.endpoint.kind;
        }
        // Serialize all UART/USB operations — prevents interleaving with dump/upload threads
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        EmuSlotInfo info;
        info.probed = true;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const uint8_t type_byte = emu_type_byte(protocol);

            // Switch hardware to this emulator slot and stay in EMU mode.
            std::string sw_err;
            client.set_work_mode(0x02, type_byte, static_cast<uint8_t>(slot), &sw_err);

            // Breakable wait for hardware to stabilize.
            // UART needs more time than USB-CDC for the device to settle after SetWorkMode.
            const int stabilize_ticks = (ep_kind == TransportKind::UartSerial) ? 30 : 15;
            for (int i = 0; i < stabilize_ticks; ++i) {
                if (cancel_emu_probe_.load()) {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    emu_probe_running_ = false;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            // Prepare read session; UART requires longer flush before reading.
            client.emu_prepare_read(type_byte, static_cast<uint8_t>(slot));
            std::this_thread::sleep_for(std::chrono::milliseconds(
                (ep_kind == TransportKind::UartSerial) ? 60 : 20));

            if (protocol == ProtocolKind::MifareClassic) {
                // MFC: block0 bytes[0..3] = 4-byte UID; retry up to 3 times on failure
                std::vector<uint8_t> block0;
                for (int retry = 0; retry < 3; ++retry) {
                    if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &block0)
                        && block0.size() >= 4) break;
                    block0.clear();
                    std::this_thread::sleep_for(std::chrono::milliseconds(
                        (ep_kind == TransportKind::UartSerial) ? 40 : 10));
                }
                if (block0.size() >= 4) {
                    const size_t n = std::min(block0.size(), size_t{16});
                    char buf[33] = {};
                    for (size_t i = 0; i < n; ++i)
                        snprintf(buf + i * 2, 3, "%02X", block0[i]);
                    info.block0_hex = buf;
                    snprintf(buf, 9, "%02X%02X%02X%02X",
                             block0[0], block0[1], block0[2], block0[3]);
                    info.uid = buf;
                }
            } else if (protocol == ProtocolKind::Iso15693) {
                // ISO15693: UID at special index 0xFE00, 8 bytes reversed
                std::vector<uint8_t> uid_bytes;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0xFE00, &uid_bytes)
                    && uid_bytes.size() >= 8) {
                    char buf[17] = {};
                    // Reversed display: uid_bytes[7..0]
                    for (int i = 7; i >= 0; --i)
                        snprintf(buf + (7 - i) * 2, 3, "%02X", uid_bytes[i]);
                    info.uid = buf;
                }
                // Also read block0 so the right panel can show data before full download.
                std::vector<uint8_t> blk0;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &blk0)
                    && !blk0.empty()) {
                    const size_t n = std::min(blk0.size(), size_t{16});
                    char buf[33] = {};
                    for (size_t i = 0; i < n; ++i)
                        snprintf(buf + i * 2, 3, "%02X", blk0[i]);
                    info.block0_hex = buf;
                }
            } else {
                // NTAG/MFU: page0[0..2] + page1[0..3] = 7-byte UID
                std::vector<uint8_t> page0, page1;
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 0, &page0)
                    && page0.size() >= 4) {
                    char buf[9] = {};
                    for (size_t i = 0; i < 4; ++i)
                        snprintf(buf + i * 2, 3, "%02X", page0[i]);
                    info.block0_hex = buf;  // page0 hex
                }
                if (client.emu_download_block(type_byte, static_cast<uint8_t>(slot), 1, &page1)
                    && page0.size() >= 3 && page1.size() >= 4) {
                    char buf[15] = {};
                    snprintf(buf, 15, "%02X%02X%02X%02X%02X%02X%02X",
                             page0[0], page0[1], page0[2],
                             page1[0], page1[1], page1[2], page1[3]);
                    info.uid = buf;
                }
            }
        }

        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        emu_slot_cache_[{protocol, slot}] = info;
        emu_probe_running_ = false;
    }

    // ── HW Upload (hfmfeload-based): upload a MFC SavedRecord to a HW EMU slot ─
    // Uses setEmulatorData (0x1E): one frame per block + done frame (index=0xFFFF).
    void perform_hw_upload(int slot, SavedRecord record)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "upload to HW slot %d", slot + 1);
            NfcHexLog::get().log_event("upload", msg);
        }
        INfcTransport *transport_raw = nullptr;
        TransportEndpoint endpoint;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            endpoint      = connection_.endpoint;
        }
        // Serialize all transport operations
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        bool ok = false;
        if (transport_raw && transport_raw->is_open() && record.tag.raw_data.size() == 64) {
            Pn532KillerClient client(transport_raw);
            constexpr uint8_t type_mfc = 1;
            const uint8_t actual_slot = static_cast<uint8_t>(slot);
            const bool is_uart = (endpoint.kind == TransportKind::UartSerial);

            auto parse_mfc_block_hex = [](const std::string &raw, std::vector<uint8_t> *out) -> bool {
                if (!out) return false;
                std::string line = raw;
                // Accept optional "NN:" prefix used by dump views.
                if (line.size() >= 3 && std::isxdigit(static_cast<unsigned char>(line[0])) &&
                    std::isxdigit(static_cast<unsigned char>(line[1])) && line[2] == ':') {
                    line = line.substr(3);
                }

                std::string compact;
                compact.reserve(32);
                for (unsigned char ch : line) {
                    if (std::isxdigit(ch)) compact.push_back(static_cast<char>(std::toupper(ch)));
                }
                if (compact.size() != 32) return false;

                out->clear();
                out->reserve(16);
                auto from_hex = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return -1;
                };
                for (int i = 0; i < 16; ++i) {
                    const int hi = from_hex(compact[static_cast<size_t>(i * 2)]);
                    const int lo = from_hex(compact[static_cast<size_t>(i * 2 + 1)]);
                    if (hi < 0 || lo < 0) return false;
                    out->push_back(static_cast<uint8_t>((hi << 4) | lo));
                }
                return true;
            };

            // Do NOT call set_work_mode before uploading.
            // pn532-python hf_mf_load uploads all blocks first, then calls set_work_mode(EMULATOR)
            // after upload_done.  Calling set_work_mode before may cause the device to reject
            // subsequent setEmulatorData frames.

            bool any_fail = false;
            std::vector<std::vector<uint8_t>> uploaded_blocks(64);
            for (int blk = 0; blk < 64; ++blk) {
                if (cancel_hw_upload_.load()) break;
                // Parse hex string to 16 bytes
                const std::string &hex = record.tag.raw_data[static_cast<size_t>(blk)];
                std::vector<uint8_t> data;
                if (!parse_mfc_block_hex(hex, &data)) {
                    char msg[96] = {};
                    std::snprintf(msg, sizeof(msg), "upload failed: invalid block format at %02d", blk);
                    NfcHexLog::get().log_event("upload", msg);
                    any_fail = true;
                    break;
                }
                // Retry each block up to 3 times to handle UART noise
                bool blk_ok = false;
                for (int retry = 0; retry < 3 && !cancel_hw_upload_.load(); ++retry) {
                    if (client.emu_upload_block(type_mfc, actual_slot,
                                               static_cast<uint16_t>(blk), data)) {
                        blk_ok = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(is_uart ? 20 : 5));
                }
                if (!blk_ok) { any_fail = true; break; }
                uploaded_blocks[static_cast<size_t>(blk)] = data;
                {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_upload_progress_ = blk + 1;
                }
                // UART needs more inter-block gap than USB
                std::this_thread::sleep_for(std::chrono::milliseconds(is_uart ? 20 : 5));
            }
            if (!any_fail && !cancel_hw_upload_.load()) {
                if (!client.emu_upload_done(type_mfc, actual_slot)) {
                    NfcHexLog::get().log_event("upload", "upload_done failed");
                    any_fail = true;
                }
                // Switch to emulator mode AFTER uploading (pn532-python hf_mf_load flow:
                // upload_data_block * N -> upload_data_block_done -> set_work_mode EMULATOR).
                std::string sw_err;
                if (!any_fail && !client.set_work_mode(0x02, type_mfc, actual_slot, &sw_err)) {
                    NfcHexLog::get().log_event("upload", ("set_work_mode failed: " + sw_err).c_str());
                    any_fail = true;
                }

                if (!any_fail) {
                    client.emu_prepare_read(type_mfc, actual_slot);
                    std::this_thread::sleep_for(std::chrono::milliseconds(is_uart ? 40 : 15));
                    const int verify_blocks[] = {0, 1, 2, 3, 63};
                    for (int vblk : verify_blocks) {
                        std::vector<uint8_t> readback;
                        if (!client.emu_download_block(type_mfc, actual_slot,
                                                       static_cast<uint16_t>(vblk), &readback) ||
                            readback.size() < 16) {
                            char msg[96] = {};
                            std::snprintf(msg, sizeof(msg), "verify failed: read block %02d", vblk);
                            NfcHexLog::get().log_event("upload", msg);
                            any_fail = true;
                            break;
                        }
                        if (!std::equal(uploaded_blocks[static_cast<size_t>(vblk)].begin(),
                                        uploaded_blocks[static_cast<size_t>(vblk)].end(),
                                        readback.begin())) {
                            char msg[96] = {};
                            std::snprintf(msg, sizeof(msg), "verify failed: mismatch block %02d", vblk);
                            NfcHexLog::get().log_event("upload", msg);
                            any_fail = true;
                            break;
                        }
                    }
                }

                ok = !any_fail;
            }
        }

        NfcHexLog::get().log_event("upload", ok ? "upload done OK" : "upload failed");
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        hw_upload_running_  = false;
        hw_upload_ok_       = ok;
    }

    // ── MFKey crack worker ────────────────────────────────────────────────────
    // Fetches sniff nonces from PN532Killer and calls mfkey64/mfkey32v2 binaries.
    void perform_hw_mfkey(bool with_card)
    {
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2",
                                   with_card ? "start mfkey64" : "start mfkey32v2");
        // Wait for device to finish saving sniffer log after reader-mode switch.
        // Without this delay, GetSnifferLog arrives while device is still committing.
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", "waiting for device to save sniff log");
        std::this_thread::sleep_for(std::chrono::milliseconds(600));
        NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", "fetching nonce entries");
        INfcTransport *transport_raw = nullptr;
        DeviceKind kind = DeviceKind::Unknown;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            kind = connection_.device_kind;
        }
        std::vector<MfkeyResult> results;

        std::vector<Pn532KillerClient::MfkeyEntry> entries;
        if (kind == DeviceKind::NFCUnit) {
            if (with_card) {
                NfcHexLog::get().log_event("mfkey64", "NFCUnit path supports mfkey32v2 only");
            } else {
                std::vector<NfcUnitMfkeyEntry> local_entries;
                {
                    std::lock_guard<std::mutex> lk(nfc_unit_mfkey_mutex_);
                    local_entries = nfc_unit_mfkey_entries_;
                }
                for (const auto &e : local_entries) {
                    Pn532KillerClient::MfkeyEntry pe{};
                    pe.uid = e.uid;
                    pe.nt = e.nt;
                    pe.nr = e.nr;
                    pe.ar = e.ar;
                    pe.at = 0;
                    pe.sector = e.sector;
                    pe.key_type = e.key_type;
                    pe.has_at = false;
                    entries.push_back(pe);
                }
            }
        } else {
            // Serialize transport access against probe/dump/upload threads
            std::lock_guard<std::mutex> op_lock(transport_op_mutex_);
            if (transport_raw && transport_raw->is_open()) {
                Pn532KillerClient client(transport_raw);
                entries = client.sniff_get_mfkey_entries(with_card);
            }
        }

        if (!entries.empty()) {
            const int total = static_cast<int>(entries.size());
            {
                char msg[64];
                std::snprintf(msg, sizeof(msg), "got %d nonce entries", total);
                NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", msg);
            }
            const std::string bin_dir = hal_path_mfkey_bin_dir();

            if (with_card) {
                // mfkey64: card-present — one auth session per entry
                // De-duplicate by (uid, nt, nr, ar, at)
                std::set<std::tuple<uint32_t,uint32_t,uint32_t,uint32_t,uint32_t>> seen;
                int done = 0;
                for (const auto &e : entries) {
                    if (cancel_hw_mfkey_.load()) break;
                    auto key = std::make_tuple(e.uid, e.nt, e.nr, e.ar, e.at);
                    if (!seen.insert(key).second) continue;
                    char cmd[512];
                    std::snprintf(cmd, sizeof(cmd),
                        "\"%s/mfkey64\" %08x %08x %08x %08x %08x 2>/dev/null",
                        bin_dir.c_str(), e.uid, e.nt, e.nr, e.ar, e.at);
                    NfcHexLog::get().log_event("mfkey64", cmd);
                    std::string out = run_cmd_capture(cmd);
                    MfkeyResult res{e.uid, e.sector, e.key_type, {}};
                    res.key_hex = parse_mfkey_result(out);
                    if (!out.empty()) NfcHexLog::get().log_event("mfkey64", out.substr(0, out.find('\n')).c_str());
                    results.push_back(res);
                    ++done;
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_mfkey_progress_ = done * 100 / std::max(1, total);
                }
            } else {
                // mfkey32v2: no-card — needs 2 nonce pairs per (uid, sector, key_type)
                using GroupKey = std::tuple<uint32_t, uint8_t, uint8_t>;
                std::map<GroupKey, std::vector<Pn532KillerClient::MfkeyEntry>> groups;
                std::set<std::tuple<uint32_t, uint8_t, uint8_t, uint32_t, uint32_t, uint32_t>> seen_caps;
                for (const auto &e : entries) {
                    auto cap = std::make_tuple(e.uid, e.sector, e.key_type, e.nt, e.nr, e.ar);
                    if (!seen_caps.insert(cap).second) continue;
                    groups[{e.uid, e.sector, e.key_type}].push_back(e);
                }
                const int group_count = static_cast<int>(groups.size());
                int done = 0;
                for (auto &[gk, caps] : groups) {
                    if (cancel_hw_mfkey_.load()) break;
                    const auto [uid, sector, key_type] = gk;
                    MfkeyResult res{uid, sector, key_type, {}};
                    // Try all pairs until a key is found
                    for (size_t i = 0; i < caps.size() && res.key_hex.empty(); ++i) {
                        for (size_t j = i + 1; j < caps.size() && res.key_hex.empty(); ++j) {
                            if (caps[i].nt == caps[j].nt) continue;
                            char cmd[512];
                            std::snprintf(cmd, sizeof(cmd),
                                "\"%s/mfkey32v2\" %08x %08x %08x %08x %08x %08x %08x 2>/dev/null",
                                bin_dir.c_str(), uid,
                                caps[i].nt, caps[i].nr, caps[i].ar,
                                caps[j].nt, caps[j].nr, caps[j].ar);
                            NfcHexLog::get().log_event("mfkey32v2", cmd);
                            std::string out = run_cmd_capture(cmd);
                            if (!out.empty()) NfcHexLog::get().log_event("mfkey32v2", out.substr(0, out.find('\n')).c_str());
                            res.key_hex = parse_mfkey_result(out);
                        }
                    }
                    results.push_back(res);
                    ++done;
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    hw_mfkey_progress_ = done * 100 / std::max(1, group_count);
                }
            }
        } else {
            NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", "no nonce entries captured");
        }

        {
            int found_count = 0;
            for (const auto &r : results) if (!r.key_hex.empty()) ++found_count;
            char msg[64];
            std::snprintf(msg, sizeof(msg), "done, %d/%d keys found", found_count, static_cast<int>(results.size()));
            NfcHexLog::get().log_event(with_card ? "mfkey64" : "mfkey32v2", msg);
        }
        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        hw_mfkey_running_  = false;
        hw_mfkey_progress_ = 100;
        hw_mfkey_results_  = results;
    }

    // Run a shell command and capture stdout (max 4KB).
    static std::string run_cmd_capture(const char *cmd)
    {
        FILE *f = popen(cmd, "r");
        if (!f) return {};
        std::string out;
        char buf[256];
        while (fgets(buf, sizeof(buf), f)) out += buf;
        pclose(f);
        return out;
    }

    // Parse "Found Key: [XXXXXXXXXXXX]" from mfkey output.
    static std::string parse_mfkey_result(const std::string &output)
    {
        static const char *PREFIX = "Found Key: [";
        const size_t pos = output.find(PREFIX);
        if (pos == std::string::npos) return {};
        const size_t start = pos + strlen(PREFIX);
        const size_t end   = output.find(']', start);
        if (end == std::string::npos || end <= start) return {};
        std::string key = output.substr(start, end - start);
        // Normalize to uppercase 12 chars
        if (key.size() < 12) key = std::string(12 - key.size(), '0') + key;
        for (char &c : key) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        return key.size() == 12 ? key : std::string{};
    }

    // ── Full dump download (triggered by user action "Download Data") ─────────
    // Downloads all blocks/pages from the current HW EMU slot and stores formatted
    // hex lines in EmuSlotInfo::dump_lines.  Runs in a background thread.
    void perform_emu_slot_dump(ProtocolKind protocol, int slot)
    {
        {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "fetch dump slot %d", slot + 1);
            NfcHexLog::get().log_event("emu-dump", msg);
        }
        INfcTransport *transport_raw = nullptr;
        TransportEndpoint endpoint;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_raw = transport_.get();
            endpoint      = connection_.endpoint;
        }
        // Serialize all transport operations
        std::lock_guard<std::mutex> op_lock(transport_op_mutex_);

        std::vector<std::string> lines;
        bool ok = false;

        if (transport_raw && transport_raw->is_open()) {
            Pn532KillerClient client(transport_raw);
            const uint8_t type_byte = emu_type_byte(protocol);

            // Determine block count and bytes per block
            int block_count  = 64;
            int bytes_per_block = 16;
            if (protocol == ProtocolKind::Iso14443A) {          // NTAG
                block_count  = 45;  // NTAG213 default
                bytes_per_block = 4;
            } else if (protocol == ProtocolKind::Iso15693) {
                block_count  = 40;
                bytes_per_block = 4;
            }

            // Switch hardware to the correct slot before dumping.
            // Without this, switching slots then downloading reads stale data.
            std::string sw_err;
            client.set_work_mode(0x02, type_byte, static_cast<uint8_t>(slot), &sw_err);
            const int stabilize_ticks = (endpoint.kind == TransportKind::UartSerial) ? 30 : 15;
            for (int i = 0; i < stabilize_ticks; ++i) {
                if (cancel_emu_dump_.load()) {
                    std::lock_guard<std::mutex> lk(pending_log_mutex_);
                    emu_dump_running_ = false;
                    return;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }

            client.emu_prepare_read(type_byte, static_cast<uint8_t>(slot));
            std::this_thread::sleep_for(std::chrono::milliseconds(
                (endpoint.kind == TransportKind::UartSerial) ? 60 : 20));

            for (int blk = 0; blk < block_count; ++blk) {
                if (cancel_emu_dump_.load()) break;

                std::vector<uint8_t> data;
                if (!client.emu_download_block(type_byte, static_cast<uint8_t>(slot),
                                               static_cast<uint16_t>(blk), &data)) break;

                // Format line: "00: XXYYZZ..." (no spaces between bytes)
                char linebuf[80] = {};
                int pos = snprintf(linebuf, sizeof(linebuf), "%02X: ", blk);
                const int max_bytes = std::min((int)data.size(), bytes_per_block);
                for (int b = 0; b < max_bytes; ++b)
                    pos += snprintf(linebuf + pos, sizeof(linebuf) - pos, "%02X", data[b]);
                lines.push_back(linebuf);
                ok = true;

                std::this_thread::sleep_for(std::chrono::milliseconds(
                    (endpoint.kind == TransportKind::UartSerial) ? 20 : 5));
            }
        }

        // Dump data is stored in cache only — NOT auto-saved to storage.
        // User must explicitly call save_emu_dump_cached() (e.g. via "Save Dump" in UI).

        std::lock_guard<std::mutex> lk(pending_log_mutex_);
        if (ok) {
            auto &info = emu_slot_cache_[{protocol, slot}];
            info.dump_lines  = std::move(lines);
            info.dump_loaded = true;
        }
        emu_dump_running_ = false;
    }

    void perform_probe_all()
    {
        // Take a snapshot of endpoints to probe (without holding the lock)
        std::vector<TransportEndpoint> to_probe;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto &ep : endpoints_) {
                if (ep.kind != TransportKind::I2cBus) to_probe.push_back(ep);
            }
        }

        for (size_t i = 0; i < to_probe.size(); ++i) {
            const auto &ep = to_probe[i];
            DeviceProbeResult result;
            result.path      = ep.path;
            result.transport = ep.kind;
            result.probing   = false;

            // Open a temporary transport
            auto transport = NfcTransportFactory::create(ep);
            std::string open_error;
            if (!transport->open(ep, &open_error)) {
                result.device_kind = DeviceKind::NotConnected;
                result.error = open_error;
            } else {
                Pn532KillerClient client(transport.get());
                std::string fw;
                std::string err;
                result.device_kind = client.detect_device(&fw, &err);
                result.firmware    = fw;
                result.error       = err;
                transport->close();
            }

            // Update probe_results_ entry in place
            std::lock_guard<std::mutex> lock(mutex_);
            if (i < probe_results_.size()) {
                probe_results_[i] = result;
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        probe_running_ = false;
    }

};

} // namespace nfc_app