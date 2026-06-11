#pragma once

// Thread-safe NFC hex logger + LoggingTransport wrapper.
// Usage:
//   NfcHexLog::get().log_event("scan", "start scan");
//   NfcHexLog::get().log_tx("NFC", data, len);
//   NfcHexLog::get().log_rx("NFC", buf, got);
//
// LoggingTransport wraps any INfcTransport and auto-logs TX/RX hex.

#include "nfc_transport.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif
#include "hal/hal_paths.h"
#ifdef __cplusplus
}
#endif

namespace nfc_app {

// ── NfcHexLog ────────────────────────────────────────────────────────────────
// Singleton ring-buffer logger (2000 lines) + daily file writer.

class NfcHexLog {
public:
    static NfcHexLog &get()
    {
        static NfcHexLog inst;
        return inst;
    }

    // Log outgoing bytes (host → device)
    void log_tx(const char *tag, const uint8_t *data, size_t len)
    {
        if (!data || len == 0) return;
        const std::string line = format_hex_line(tag, "=>", data, len);
        if (!line.empty()) push(line);
    }

    // Log incoming bytes (device → host)
    void log_rx(const char *tag, const uint8_t *data, size_t len)
    {
        if (!data || len == 0) return;
        const std::string line = format_hex_line(tag, "<=", data, len);
        if (!line.empty()) push(line);
    }

    // Log a plain text event (timestamp + optional tag + message)
    void log_event(const char *tag, const char *msg)
    {
        if (should_suppress_event(tag, msg)) return;

        char buf[256];
        if (tag && tag[0])
            std::snprintf(buf, sizeof(buf), "[%s] %s: %s", timestamp().c_str(), tag, msg ? msg : "");
        else
            std::snprintf(buf, sizeof(buf), "[%s] %s", timestamp().c_str(), msg ? msg : "");
        push(std::string(buf));
    }

    // Read lines for UI display. offset 0 = first (oldest) line in buffer.
    std::vector<std::string> get_lines(int offset, int count) const
    {
        std::lock_guard<std::mutex> lk(mutex_);
        std::vector<std::string> out;
        const int total = static_cast<int>(lines_.size());
        int start = offset;
        if (start < 0) start = 0;
        for (int i = start; i < start + count && i < total; ++i)
            out.push_back(lines_[static_cast<size_t>(i)]);
        return out;
    }

    int total_lines() const
    {
        std::lock_guard<std::mutex> lk(mutex_);
        return static_cast<int>(lines_.size());
    }

    // Discard all in-memory log lines (does NOT delete the file).
    void clear()
    {
        std::lock_guard<std::mutex> lk(mutex_);
        lines_.clear();
    }

    // Set the transport mode prefix used in log file names.
    // E.g. set_mode("uart") → "uart-2025-01-01.txt"
    //      set_mode("iic")  → "iic-2025-01-01.txt"
    //      set_mode("spi")  → "spi-2025-01-01.txt"
    //      set_mode("")     → "2025-01-01.txt" (no prefix)
    void set_mode(const char *mode)
    {
        std::lock_guard<std::mutex> lk(mutex_);
        mode_prefix_ = mode ? mode : "";
    }

    // Write all current in-memory lines to a timestamped file under save_dir.
    // Returns the file path on success, empty string on failure.
    std::string save_snapshot(const char *save_dir)
    {
        if (!save_dir || !save_dir[0]) return {};
#ifndef _WIN32
        // Ensure directory exists (mkdir -p equivalent)
        {
            std::string p(save_dir);
            for (size_t i = 1; i <= p.size(); ++i) {
                if (i == p.size() || p[i] == '/') {
                    mkdir(p.substr(0, i).c_str(), 0755);
                }
            }
        }
#endif
        time_t t = time(nullptr);
        struct tm tm_info;
#ifndef _WIN32
        localtime_r(&t, &tm_info);
#else
        localtime_s(&tm_info, &t);
#endif
        char fname[40];
        std::snprintf(fname, sizeof(fname), "%04d-%02d-%02d_%02d-%02d-%02d.txt",
                      tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
                      tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec);
        std::string path = std::string(save_dir) + "/" + fname;

        std::lock_guard<std::mutex> lk(mutex_);
        FILE *f = std::fopen(path.c_str(), "w");
        if (!f) return {};
        for (const auto &line : lines_)
            std::fprintf(f, "%s\n", line.c_str());
        std::fclose(f);
        return path;
    }

private:
    NfcHexLog() = default;
    NfcHexLog(const NfcHexLog &) = delete;
    NfcHexLog &operator=(const NfcHexLog &) = delete;

    static constexpr int MAX_LINES = 2000;

    mutable std::mutex mutex_;
    std::deque<std::string> lines_;
    std::string mode_prefix_;  // "uart", "iic", "usb", or "" (no prefix)

    static std::string timestamp()
    {
#ifndef _WIN32
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        const time_t t = ts.tv_sec;
        struct tm tm_info;
        localtime_r(&t, &tm_info);
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%03d",
                      tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
                      static_cast<int>(ts.tv_nsec / 1000000));
        return buf;
#else
        return "00:00:00.000";
#endif
    }

    static bool should_suppress_event(const char *tag, const char *msg)
    {
        (void)tag;
        (void)msg;
        // Keep all event logs so READ path debugging can see each NFC-I2C step.
        return false;
    }

    // Build the log file path for today, optionally prefixed by mode.
    // E.g. prefix="uart" → "<log_dir>/uart-2025-01-01.txt"
    static std::string today_file_with_prefix(const std::string &prefix)
    {
        time_t t = time(nullptr);
        struct tm tm_info;
#ifndef _WIN32
        localtime_r(&t, &tm_info);
#else
        localtime_s(&tm_info, &t);
#endif
        char date[20];
        std::snprintf(date, sizeof(date), "%04d-%02d-%02d.txt",
                      tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday);
        const char *log_dir = hal_path_nfc_log_dir();
#ifndef _WIN32
        // Ensure parent dirs exist (equivalent to mkdir -p)
        {
            std::string path(log_dir);
            for (size_t i = 1; i <= path.size(); ++i) {
                if (i == path.size() || path[i] == '/') {
                    mkdir(path.substr(0, i).c_str(), 0755);
                }
            }
        }
#endif
        std::string fname = prefix.empty() ? date : (prefix + "-" + date);
        return std::string(log_dir) + "/" + fname;
    }

    static bool extract_pn532_payload_after_tfi(const uint8_t *data,
                                                size_t len,
                                                uint8_t expected_tfi,
                                                std::vector<uint8_t> &payload)
    {
        payload.clear();
        for (size_t i = 0; i + 7 < len; ++i) {
            if (data[i] != 0x00 || data[i + 1] != 0x00 || data[i + 2] != 0xFF) continue;

            const uint8_t frame_len = data[i + 3];
            const uint8_t lcs = data[i + 4];
            if (static_cast<uint8_t>(frame_len + lcs) != 0x00) continue;

            if (frame_len == 0) {
                // ACK frame: 00 00 FF 00 FF 00
                if (i + 6 <= len) {
                    i += 5;
                    continue;
                }
                continue;
            }

            if (i + 5 + frame_len + 2 > len) continue;

            const size_t data_start = i + 5;
            const size_t data_end = data_start + frame_len;
            uint8_t sum = 0;
            for (size_t cursor = data_start; cursor < data_end; ++cursor) {
                sum = static_cast<uint8_t>(sum + data[cursor]);
            }
            const uint8_t dcs = data[data_end];
            if (static_cast<uint8_t>(sum + dcs) != 0x00) continue;
            if (data_start >= data_end) continue;

            if (data[data_start] == expected_tfi) {
                payload.assign(data + data_start + 1, data + data_end);
                return true;
            }
            i = data_end + 1;
        }
        return false;
    }

    static std::string format_hex_line(const char *tag, const char *arrow,
                                       const uint8_t *data, size_t len)
    {
        // [HH:MM:SS.mmm] tag => xxyyzz...
        std::string out;
        out.reserve(32 + len * 2);
        char hdr[48];
        if (tag && tag[0])
            std::snprintf(hdr, sizeof(hdr), "[%s] %s %s ", timestamp().c_str(), tag, arrow);
        else
            std::snprintf(hdr, sizeof(hdr), "[%s] %s ", timestamp().c_str(), arrow);
        out = hdr;
        std::vector<uint8_t> display;
        display.reserve(len);
        if (std::strcmp(arrow, "=>") == 0) {
            if (!extract_pn532_payload_after_tfi(data, len, 0xD4, display)) {
                display.assign(data, data + len);
            }
        } else if (std::strcmp(arrow, "<=") == 0) {
            if (!extract_pn532_payload_after_tfi(data, len, 0xD5, display)) {
                // For PN532 ACK-only replies (00 00 FF 00 FF 00), hide noisy line.
                std::vector<uint8_t> ack_filtered;
                if (extract_pn532_payload_after_tfi(data, len, 0xD4, ack_filtered)) {
                    display.assign(data, data + len);
                } else {
                    bool looks_like_ack_only = false;
                    for (size_t i = 0; i + 5 < len; ++i) {
                        if (data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0xFF &&
                            data[i + 3] == 0x00 && data[i + 4] == 0xFF && data[i + 5] == 0x00) {
                            looks_like_ack_only = true;
                            break;
                        }
                    }
                    if (looks_like_ack_only) return {};
                    display.assign(data, data + len);
                }
            }
        } else {
            display.assign(data, data + len);
        }

        char h[3];
        constexpr size_t MAX_BYTES = 64; // cap per line to keep it readable
        const size_t show = display.size() > MAX_BYTES ? MAX_BYTES : display.size();
        for (size_t i = 0; i < show; ++i) {
            std::snprintf(h, sizeof(h), "%02X", display[i]);
            out += h;
        }
        if (display.size() > MAX_BYTES) out += "...";
        return out;
    }

    void push(const std::string &line)
    {
        // Capture mode prefix and update ring buffer under lock.
        std::string prefix;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            prefix = mode_prefix_;
            lines_.push_back(line);
            while (static_cast<int>(lines_.size()) > MAX_LINES)
                lines_.pop_front();
        }
        // Write to file outside lock to avoid blocking callers.
        const std::string path = today_file_with_prefix(prefix);
        FILE *f = std::fopen(path.c_str(), "a");
        if (f) {
            std::fprintf(f, "%s\n", line.c_str());
            std::fclose(f);
        }
    }
};

// ── LoggingTransport ─────────────────────────────────────────────────────────
// Wraps any INfcTransport; every write_bytes / read_bytes call is automatically
// logged to NfcHexLog with the given tag string.

class LoggingTransport : public INfcTransport {
public:
    LoggingTransport(std::unique_ptr<INfcTransport> inner, std::string tag)
        : inner_(std::move(inner)), tag_(std::move(tag)) {}

    bool open(const TransportEndpoint &endpoint, std::string *error) override
    {
        return inner_->open(endpoint, error);
    }

    void close() override { inner_->close(); }

    bool is_open() const override { return inner_->is_open(); }

    TransportEndpoint endpoint() const override { return inner_->endpoint(); }

    void flush_rx()
    {
        if (rx_buf_.empty()) return;
        NfcHexLog::get().log_rx(tag_.c_str(), rx_buf_.data(), rx_buf_.size());
        rx_buf_.clear();
    }

    ssize_t write_bytes(const uint8_t *data, size_t size, std::string *error) override
    {
        // Flush buffered RX before TX so the previous response is visible.
        flush_rx();
        const ssize_t ret = inner_->write_bytes(data, size, error);
        if (ret > 0)
            NfcHexLog::get().log_tx(tag_.c_str(), data, static_cast<size_t>(ret));
        return ret;
    }

    ssize_t read_bytes(uint8_t *buffer, size_t size, int timeout_ms, std::string *error) override
    {
        const ssize_t ret = inner_->read_bytes(buffer, size, timeout_ms, error);
        if (ret <= 0) {
            if (!rx_buf_.empty()) flush_rx();
            return ret;
        }

        // Accumulate RX bytes. PN532 protocol reads byte-by-byte via
        // collect_response(); accumulating here merges multi-byte frames
        // into single log lines instead of one line per byte read.
        if (rx_buf_.empty() && has_complete_pn532_frame({buffer, buffer + ret})) {
            // First chunk is already a complete PN532 frame -> log directly.
            NfcHexLog::get().log_rx(tag_.c_str(), buffer, static_cast<size_t>(ret));
        } else {
            rx_buf_.insert(rx_buf_.end(), buffer, buffer + ret);
            if (has_complete_pn532_frame(rx_buf_)) flush_rx();
        }
        return ret;
    }

    ~LoggingTransport() { flush_rx(); }

private:
    // Heuristic: return true when buf contains at least one complete PN532
    // response frame (preamble 00 00 FF + LEN + LCS + data + DCS + postamble).
    static bool has_complete_pn532_frame(const std::vector<uint8_t> &buf)
    {
        for (size_t i = 0; i + 7 < buf.size(); ++i) {
            if (buf[i] != 0x00 || buf[i + 1] != 0x00 || buf[i + 2] != 0xFF) continue;
            const uint8_t len = buf[i + 3];
            const uint8_t lcs = buf[i + 4];
            if (static_cast<uint8_t>(len + lcs) != 0x00) continue;
            const size_t frame_end = i + 5 + static_cast<size_t>(len) + 2;
            if (frame_end > buf.size()) return false;
            if (buf[frame_end - 1] == 0x00) return true;
        }
        return false;
    }

    std::unique_ptr<INfcTransport> inner_;
    std::string tag_;
    std::vector<uint8_t> rx_buf_;
};

} // namespace nfc_app
