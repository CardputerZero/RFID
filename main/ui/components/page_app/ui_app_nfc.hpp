#pragma once

#include "nfc/nfc_device_service.hpp"
#include "../ui_app_page.hpp"
#include "compat/input_keys.h"
#include "keyboard_input.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

class UINfcPage : public app_base
{
    enum class Tab {
        Read = 0,
        Saved,
        Emulator,
        Tools,
    };

    enum class Modal {
        None,
        Action,       // Upload to Slot / Edit Name / Edit Hex
        SlotSelect,   // Choose target slot 0-7
        EditName,     // Rename the record
        EditHex,      // Edit raw hex data lines
        DeviceProbe,  // Probe all ports for PN532/PN532Killer
        UartConfig,   // Configure UART device path + baud rate
        ToolPage,      // Tool detail page
        EmulatorAction,// Upload / download / default menu
        HexExitConfirm,// Save/discard/cancel prompt
        ToolInfo,      // 'i' key tool detail popup (Tools tab only)
        AppInfo,       // 'i' key global RFID app introduction
        PostScan,      // After scan result: Read Again / Save Tag menu
        ReadMenu,      // Read-mode OK menu (device-aware actions)
        PortSettings,  // TX / RX / BAUD config popup
        UsbSelect,     // Multiple USB ports: choose which to connect
        I2cSelect,     // I2C bus scan: choose which device to connect
        SpiSelect,     // SPI bus scan: choose which device to connect
        HexLog,        // Ctrl+L full-screen hex TX/RX log overlay
        Pn532NdefInput,// PN532 NDEF URI input popup
    };

    enum class ReadMenuAction {
        ConnectDevice,
        PortSettings,
        Scan,
        ScanOnceUHF,
        StartUHFContinuous,
        StopUHFContinuous,
        ExportUHFCsv,
        Dump,
        Save,
        Clear,
    };

public:
    UINfcPage() : app_base()
    {
        set_page_title("RFID");
        refresh_saved_records();
        refresh_mifare_keys();
        creat_UI();
        event_handler_init();
        ui_timer_ = lv_timer_create(UINfcPage::ui_timer_cb, 200, this);
        render_all();
    }

    ~UINfcPage()
    {
        (void)service_.grovenfc_deactivate();
        (void)service_.stop_pn532_ndef_emulation();
        (void)service_.spi_stop_listener();
        if (ui_timer_) lv_timer_delete(ui_timer_);
    }

private:
    nfc_app::NfcDeviceService service_;
    std::unordered_map<std::string, lv_obj_t *> ui_obj_;
    std::vector<nfc_app::SavedRecord> saved_records_;
    Tab current_tab_ = Tab::Read;
    int read_action_idx_ = 0;
    int saved_idx_ = 0;
    int tools_idx_ = 0;
    lv_timer_t *ui_timer_ = nullptr;
    std::string ui_message_ = "Ready";
    Modal modal_          = Modal::None;
    int   modal_idx_      = 0;
    int   slot_select_idx_= 0;
    std::string edit_buf_;
    int   edit_hex_line_  = 0;
    bool  edit_hex_dirty_ = false;
    std::vector<nfc_app::MifareKeyRecord> mifare_keys_;
    int mifare_key_idx_ = 0;
    int mifare_key_field_idx_ = 0;
    bool mifare_key_editing_ = false;
    bool mifare_key_creating_ = false;
    nfc_app::MifareKeyRecord mifare_key_edit_;
    // UART config edit state
    int   uart_field_idx_ = 0;  // 0=device 1=baud 2=Test
    nfc_app::UartConfig uart_edit_buf_;
    std::string uart_test_result_;  // result from last Test Connection
    bool last_uart_test_running_ = false;  // for detecting async completion
    int active_tool_idx_ = 0;
    // Read tab scan log
    std::vector<std::string> scan_log_lines_;
    int log_scroll_offset_ = 0;
    std::vector<nfc_app::NfcDeviceService::UhfTableRow> uhf_table_rows_;
    int uhf_table_scroll_offset_ = 0;
    bool last_scan_running_ = false;
    int  app_info_scroll_ = 0;  // AppInfo modal scroll offset (line index)
    // Long-press scroll tracking
    uint32_t held_scroll_key_      = 0;
    uint32_t held_scroll_start_ms_ = 0;
    uint32_t held_scroll_last_ms_  = 0;
    // Hardware EMU slot (PN532Killer)
    int hw_emu_slot_ = 0;
    // Dump panel scroll offset (line index within dump_lines)
    int emu_dump_scroll_ = 0;
    // Toast notification (auto-dismiss 1s popup)
    std::string toast_msg_;
    uint32_t    toast_expire_tick_ = 0;  // 0 = no active toast
    // EMU dump completion tracking (to show toast when async dump finishes)
    bool last_emu_dump_running_   = false;
    bool last_emu_probe_running_  = false;
    // HW upload completion tracking
    bool last_hw_upload_running_  = false;
    int pending_hw_upload_slot_   = -1;
    // MFKey tool state
    bool last_hw_mfkey_running_  = false;
    std::vector<nfc_app::NfcDeviceService::MfkeyResult> mfkey_results_;
    int  mfkey_result_idx_ = 0;
    // MFKey step-by-step wizard state
    // mfkey32v2: 0=uid_input 1=sniffing 2=cracking 3=results
    // mfkey64:   0=ready     1=sniffing 2=cracking 3=results
    int  mfkey_step_ = 0;
    std::string mfkey_uid_input_; // hex UID typed by user (mfkey32v2 only)
    bool mfkey_save_mode_      = false; // save-all-to-file filename input overlay
    std::string mfkey_save_filename_;   // filename being typed in save overlay
    // MIFARE Keys file-browser sub-mode
    bool mifare_keys_file_mode_ = false;      // false=internal, true=file list
    std::vector<std::string> key_files_;      // .dic/.txt file names
    std::vector<int> key_file_counts_;        // cached key count per file
    int  key_file_idx_ = 0;                   // selected file
    std::vector<std::string> key_file_keys_;  // keys loaded from selected file
    int  key_file_key_idx_ = 0;               // scroll in loaded key list
    bool key_file_editing_ = false;
    bool key_file_dirty_ = false;
    // Port Settings field selection (0=TX 1=RX 2=BAUD)
    int port_settings_field_ = 0;
    // USB port selection (index into usb_endpoints() list)
    int usb_select_idx_ = 0;
    // Cached USB endpoint list for UsbSelect modal
    std::vector<nfc_app::TransportEndpoint> usb_select_list_;
    bool pending_usb_connect_ = false;
    std::string pending_usb_connect_path_;
    uint32_t nfc_automation_last_tick_ = 0;
    static constexpr const char *kNfcAutomationCmdPath = "/tmp/applaunch_nfc_automation.cmd";
    static constexpr const char *kNfcAutomationStatusPath = "/tmp/applaunch_nfc_automation.status";
    bool pending_nfcunit_emu_autostart_result_ = false;
    bool nfcunit_emu_autostart_running_ = false;
    bool nfcunit_emu_autostart_ok_ = false;
    bool nfcunit_emu_autostart_result_consumed_ = true;
    std::string nfcunit_emu_autostart_error_;
    std::string nfcunit_emu_autostart_profile_;
    std::mutex nfcunit_emu_autostart_mutex_;
    // Deferred GroveNFC emulation start (avoid blocking tab switch)
    bool grovenfc_emu_pending_ = false;
    // Async GroveNFC emulation result
    std::atomic<bool> grovenfc_emu_result_ready_{false};
    bool grovenfc_emu_result_ok_ = false;
    std::string grovenfc_emu_result_msg_;
    // I2C device selection (index into i2c_select_list_)
    int i2c_select_idx_ = 0;
    // Cached I2C endpoint list for I2cSelect modal
    std::vector<nfc_app::TransportEndpoint> i2c_select_list_;
    // SPI device selection (index into spi_select_list_)
    int spi_select_idx_ = 0;
    // Cached SPI endpoint list for SpiSelect modal
    std::vector<nfc_app::TransportEndpoint> spi_select_list_;
    // Read-tab transport pill scroll offset (0=USB+UART, 1=UART+I2C, 2=I2C+SPI)
    int read_transport_offset_ = 0;
    // PN532 NDEF URI input buffer
    std::string pn532_ndef_uri_      = "https://m5stack.com";
    int         pn532_ndef_type_idx_ = 0; // 0=https 1=http 2=tel 3=mailto 4=custom
    std::string pn532_ndef_body_     = "m5stack.com";
    bool        uri_edit_for_nfcunit_ = false;
    bool        uri_edit_for_grove_   = false;
    uint32_t    last_key_codepoint_  = 0; // Unicode codepoint of last key event
    nfc_app::DeviceKind last_serial_device_kind_ = nfc_app::DeviceKind::Unknown;
    // NFC Unit async write state
    bool nfcunit_write_running_ = false;
    bool nfcunit_write_result_ok_ = false;
    std::string nfcunit_write_result_msg_;
    std::thread nfcunit_write_thread_;
    // Hex log overlay scroll offset (line index from top)
    int hex_log_scroll_ = 0;
    // UID Changer state
    int uid_changer_step_ = 0;          // 0=UID 1=Magic type 2=Confirm write
    int uid_changer_field_idx_ = 0;
    int uid_changer_generation_idx_ = 0; // 0=Gen1A 1=Gen2 2=Gen3 3=Gen4
    int uid_changer_uid_len_idx_ = 0;   // 0=4B 1=7B
    int uid_changer_source_idx_ = 0;    // 0=input 1=scan
    bool uid_changer_write_block0_ = false;
    bool uid_changer_block0_manual_ = false; // true = user manually edited Block 0
    std::string uid_changer_uid_input_;
    std::string uid_changer_block0_input_;
    std::string uid_changer_gen2_keya_input_ = "FFFFFFFFFFFF";
    std::string uid_changer_gen4_pwd_input_ = "00000000";

    static constexpr int TAB_H = 24;
    static constexpr int CONTENT_Y = 26;
    static constexpr int CONTENT_H = 120;
    static constexpr int LOG_VISIBLE_LINES = 9;
    // HexLog overlay: 320×140 content area, 11px per line => ~12 lines
    static constexpr int LOG_VISIBLE_HEX_LINES = 11;

    void creat_UI()
    {
        lv_obj_t *bg = lv_obj_create(ui_APP_Container);
        lv_obj_set_size(bg, 320, 150);
        lv_obj_set_pos(bg, 0, 0);
        lv_obj_set_style_radius(bg, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(bg, lv_color_hex(0x0B0B0B), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(bg, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(bg, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(bg, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(bg, LV_OBJ_FLAG_SCROLLABLE);
        ui_obj_["bg"] = bg;

        lv_obj_t *tab_bar = lv_obj_create(bg);
        lv_obj_set_size(tab_bar, 320, TAB_H);
        lv_obj_set_pos(tab_bar, 0, 0);
        lv_obj_set_style_radius(tab_bar, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(tab_bar, lv_color_hex(0x111111), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(tab_bar, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(tab_bar, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(tab_bar, LV_OBJ_FLAG_SCROLLABLE);
        ui_obj_["tab_bar"] = tab_bar;

        const char *titles[4] = {"READ", "SAVED", "EMU", "TOOLS"};
        for (int index = 0; index < 4; ++index) {
            const std::string key = std::string("tab_") + std::to_string(index);
            lv_obj_t *item = lv_obj_create(tab_bar);
            lv_obj_set_size(item, 78, TAB_H - 2);
            lv_obj_set_pos(item, 1 + index * 80, 1);
            lv_obj_set_style_radius(item, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_border_width(item, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_pad_all(item, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(item, LV_OBJ_FLAG_SCROLLABLE);
            lv_obj_t *label = lv_label_create(item);
            lv_label_set_text(label, titles[index]);
            lv_obj_center(label);
            ui_obj_[key] = item;
        }

        lv_obj_t *content = lv_obj_create(bg);
        lv_obj_set_size(content, 320, CONTENT_H);
        lv_obj_set_pos(content, 0, CONTENT_Y);
        lv_obj_set_style_radius(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(content, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(content, LV_OBJ_FLAG_SCROLLABLE);
        ui_obj_["content"] = content;
    }

    void event_handler_init()
    {
        lv_obj_add_event_cb(ui_root, UINfcPage::static_lvgl_handler, LV_EVENT_ALL, this);
    }
    int read_log_visible_lines() const
    {
        const auto scan = service_.scan_state();
        if (!scan.has_result) return 10;
        const auto endpoint = service_.current_endpoint();
        return (endpoint.kind == nfc_app::TransportKind::I2cBus) ? 7 : 8;
    }

    int read_uhf_visible_rows() const
    {
        return 8;
    }

    bool read_uses_uhf_table() const
    {
        const auto conn = service_.connection_state();
        return (conn.connected && conn.device_kind == nfc_app::DeviceKind::UHFReader) ||
               !uhf_table_rows_.empty();
    }

    nfc_app::TransportEndpoint active_endpoint_for_ui(const nfc_app::ConnectionState &conn) const
    {
        return conn.connected ? conn.endpoint : service_.current_endpoint();
    }

    void cache_serial_device_kind(const nfc_app::ConnectionState &conn)
    {
        if (!conn.connected) return;
        if (conn.endpoint.kind != nfc_app::TransportKind::UsbSerial &&
            conn.endpoint.kind != nfc_app::TransportKind::UartSerial) {
            return;
        }
        if (conn.device_kind == nfc_app::DeviceKind::PN532Killer ||
            conn.device_kind == nfc_app::DeviceKind::PN532) {
            last_serial_device_kind_ = conn.device_kind;
        }
    }

    nfc_app::DeviceKind effective_emu_device_kind(const nfc_app::ConnectionState &conn) const
    {
        if (conn.device_kind != nfc_app::DeviceKind::Unknown &&
            conn.device_kind != nfc_app::DeviceKind::NotConnected) {
            return conn.device_kind;
        }
        if (conn.connected && conn.endpoint.kind == nfc_app::TransportKind::SpiBus) {
            // SPI NFC path in this app is ST25R-based EMU.
            return nfc_app::DeviceKind::ST25RNFC;
        }
        if (conn.connected &&
            (conn.endpoint.kind == nfc_app::TransportKind::UsbSerial ||
             conn.endpoint.kind == nfc_app::TransportKind::UartSerial) &&
            (last_serial_device_kind_ == nfc_app::DeviceKind::PN532Killer ||
             last_serial_device_kind_ == nfc_app::DeviceKind::PN532)) {
            return last_serial_device_kind_;
        }
        return conn.device_kind;
    }

    static std::string emulator_source_filename(nfc_app::ProtocolKind protocol)
    {
        if (protocol == nfc_app::ProtocolKind::MifareClassic) return "emulator/mfc1k_0.json";
        if (protocol == nfc_app::ProtocolKind::Iso15693) return "emulator/iso15693_0.json";
        return "emulator/ntag213_0.json";
    }

    static bool is_identified_device_kind(nfc_app::DeviceKind kind)
    {
        return kind == nfc_app::DeviceKind::PN532 ||
               kind == nfc_app::DeviceKind::PN532Killer ||
               kind == nfc_app::DeviceKind::UHFReader ||
               kind == nfc_app::DeviceKind::GroveNFC ||
               kind == nfc_app::DeviceKind::NFCUnit ||
               kind == nfc_app::DeviceKind::ST25RNFC;
    }

    int read_scroll_max_offset() const
    {
        if (read_uses_uhf_table()) {
            return std::max(0, static_cast<int>(uhf_table_rows_.size()) - read_uhf_visible_rows());
        }
        return std::max(0, static_cast<int>(scan_log_lines_.size()) - read_log_visible_lines());
    }

    static void static_lvgl_handler(lv_event_t *e)
    {
        UINfcPage *self = static_cast<UINfcPage *>(lv_event_get_user_data(e));
        if (self) self->event_handler(e);
    }

    static void ui_timer_cb(lv_timer_t *timer)
    {
        UINfcPage *self = static_cast<UINfcPage *>(lv_timer_get_user_data(timer));
        if (!self) return;
        if (self->pending_usb_connect_) {
            self->perform_pending_usb_connect();
        }
        self->consume_nfcunit_emu_autostart_result();
        self->poll_nfcunit_write_result();
        self->process_nfc_automation_command();
        const bool emu_probe_running_now = self->service_.emu_probe_running();
        if (self->last_emu_probe_running_ && !emu_probe_running_now) {
            // Probe finished: refresh once so slot block0/UID appears immediately.
            if (self->current_tab_ == Tab::Emulator) {
                self->render_all();
            }
        }
        self->last_emu_probe_running_ = emu_probe_running_now;
        // Long-press scroll: hold 400ms→scroll, hold 1500ms→fast scroll, hold 2000ms→jump to top/bottom
        // Works for Read tab scan log AND for HexLog modal
        if (self->held_scroll_key_ != 0) {
            const bool is_read_scroll = self->modal_ == Modal::None && self->current_tab_ == Tab::Read;
            const bool is_hexlog_scroll = self->modal_ == Modal::HexLog;
            if (is_read_scroll || is_hexlog_scroll) {
                const uint32_t now = lv_tick_get();
                const uint32_t held_ms = now - self->held_scroll_start_ms_;
                if (held_ms > 2000 && now - self->held_scroll_last_ms_ > 200) {
                    // Jump directly to top or bottom
                    const bool to_bottom = (self->held_scroll_key_ == KEY_DOWN);
                    if (is_read_scroll) {
                        const int max_scroll = self->read_scroll_max_offset();
                        self->log_scroll_offset_ = to_bottom ? max_scroll : 0;
                        self->uhf_table_scroll_offset_ = to_bottom ? max_scroll : 0;
                    } else {
                        const int total = nfc_app::NfcHexLog::get().total_lines();
                        const int max_scroll = std::max(0, total - LOG_VISIBLE_HEX_LINES);
                        self->hex_log_scroll_ = to_bottom ? max_scroll : 0;
                        self->render_all();
                    }
                    self->held_scroll_last_ms_ = now;
                } else {
                    const uint32_t interval = (held_ms > 1500) ? 50 : 150;
                    if (held_ms > 400 && now - self->held_scroll_last_ms_ > interval) {
                        const int dir   = (self->held_scroll_key_ == KEY_DOWN) ? 1 : -1;
                        const int step  = (held_ms > 1500) ? 3 : 1;
                        const int delta = dir * step;
                        if (is_read_scroll) {
                            const int max_scroll = self->read_scroll_max_offset();
                            if (self->read_uses_uhf_table()) {
                                self->uhf_table_scroll_offset_ = std::max(0, std::min(max_scroll, self->uhf_table_scroll_offset_ + delta));
                            } else {
                                self->log_scroll_offset_ = std::max(0, std::min(max_scroll, self->log_scroll_offset_ + delta));
                            }
                        } else {
                            const int total = nfc_app::NfcHexLog::get().total_lines();
                            const int max_scroll = std::max(0, total - LOG_VISIBLE_HEX_LINES);
                            self->hex_log_scroll_ = std::max(0, std::min(max_scroll, self->hex_log_scroll_ + delta));
                            self->render_all();
                        }
                        self->held_scroll_last_ms_ = now;
                    }
                }
            }
        }
        // Auto-clear expired toast
        if (!self->toast_msg_.empty() && self->toast_expire_tick_ != 0) {
            if (lv_tick_get() >= self->toast_expire_tick_) {
                self->toast_msg_.clear();
                self->toast_expire_tick_ = 0;
            }
        }
        // Detect EMU dump completion → show toast once
        const bool emu_running_now = self->service_.emu_dump_running();
        if (self->last_emu_dump_running_ && !emu_running_now) {
            // Dump just finished; refresh records and clear transient status text.
            self->refresh_saved_records();
            if (self->ui_message_.find("Downloading") != std::string::npos) {
                self->ui_message_ = "Download complete  Ctrl+S: save";
            }
        }
        self->last_emu_dump_running_ = emu_running_now;
        const bool upload_running_now = self->service_.hw_upload_running();
        // Keep footer status in sync while HW upload is running.
        if (upload_running_now) {
            int prog = self->service_.hw_upload_progress();
            if (prog < 0) prog = 0;
            if (prog > 64) prog = 64;
            const int pct = (prog * 100) / 64;
            if (self->pending_hw_upload_slot_ >= 0) {
                self->ui_message_ = "Uploading to HW slot "
                    + std::to_string(self->pending_hw_upload_slot_ + 1)
                    + " " + std::to_string(pct) + "%";
            } else {
                self->ui_message_ = "Uploading " + std::to_string(pct) + "%";
            }
        }
        // Detect HW upload completion → show toast
        if (self->last_hw_upload_running_ && !upload_running_now) {
            const bool ok = self->service_.hw_upload_ok();
            self->show_toast(ok ? "Upload OK" : "Upload failed");
            if (self->pending_hw_upload_slot_ >= 0) {
                self->ui_message_ = ok
                    ? ("Uploaded -> Slot " + std::to_string(self->pending_hw_upload_slot_ + 1))
                    : "Upload failed";
            }
            self->pending_hw_upload_slot_ = -1;
        }
        self->last_hw_upload_running_ = upload_running_now;
        // Detect MFKey crack completion → cache results and advance wizard to step 3
        const bool mfkey_running_now = self->service_.hw_mfkey_running();
        if (self->last_hw_mfkey_running_ && !mfkey_running_now) {
            // Normal path: saw running=true, now running=false
            self->mfkey_results_ = self->service_.hw_mfkey_results();
            self->mfkey_result_idx_ = 0;
            if (self->mfkey_step_ == 2) self->mfkey_step_ = 3;
            self->show_toast(self->mfkey_results_.empty() ? "No results" : "Cracking done");
        } else if (self->mfkey_step_ == 2 && !mfkey_running_now) {
            // Race-condition path: task finished before timer ever saw running=true
            // (e.g. no captured nonces → returns instantly; binary missing → returns instantly)
            self->mfkey_results_ = self->service_.hw_mfkey_results();
            self->mfkey_result_idx_ = 0;
            self->mfkey_step_ = 3;
            self->show_toast(self->mfkey_results_.empty() ? "No results" : "Cracking done");
        }
        self->last_hw_mfkey_running_ = mfkey_running_now;
        // Detect UART test completion → drain logs to scan_log_lines_ and update result
        {
            const bool test_running_now = self->service_.uart_test_running();
            if (self->last_uart_test_running_ || test_running_now) {
                std::string result;
                std::vector<std::string> new_lines;
                const bool done = self->service_.drain_uart_test_logs(new_lines, result);
                // Split lines that are too wide for the display (~52 chars)
                // TX[]/RX[] byte-dump lines go to the log file only, not the on-screen log
                constexpr size_t WRAP_COLS = 52;
                for (auto &l : new_lines) {
                    if (l.size() >= 2 && ((l[0] == 'T' && l[1] == 'X') || (l[0] == 'R' && l[1] == 'X')))
                        continue;
                    if (l.size() <= WRAP_COLS) {
                        self->scan_log_lines_.push_back(std::move(l));
                    } else {
                        self->scan_log_lines_.push_back(l.substr(0, WRAP_COLS));
                        size_t pos = WRAP_COLS;
                        while (pos < l.size()) {
                            self->scan_log_lines_.push_back("  " + l.substr(pos, WRAP_COLS - 2));
                            pos += WRAP_COLS - 2;
                        }
                    }
                }
                if (self->scan_log_lines_.size() > 2000)
                    self->scan_log_lines_.erase(self->scan_log_lines_.begin(),
                        self->scan_log_lines_.begin() + (int)self->scan_log_lines_.size() - 2000);
                self->log_scroll_offset_ = std::max(0, (int)self->scan_log_lines_.size() - self->read_log_visible_lines());
                if (done) self->uart_test_result_ = result;
            }
            self->last_uart_test_running_ = test_running_now;
        }
        self->render_all();
    }

    void event_handler(lv_event_t *e)
    {
        // Must guard first: handler is registered for LV_EVENT_ALL.
        // LV_EVENT_KEYBOARD_GET_KEY dereferences lv_event_get_param() directly,
        // which is null/garbage for non-keyboard events → crash without this guard.
        if (lv_event_get_code(e) != LV_EVENT_KEYBOARD) return;
        if (!lv_event_get_param(e)) return;

        const uint32_t raw_key = LV_EVENT_KEYBOARD_GET_KEY(e);
        const auto *key_item = static_cast<struct key_item *>(lv_event_get_param(e));
        const uint32_t mods = key_item ? key_item->mods : 0;

        // Track key press for long-press scroll (Read tab or HexLog modal)
        if (IS_KEY_PRESSED(e)) {
            const uint32_t nk = normalize_main_key(raw_key);
            const bool want_scroll_read = (nk == KEY_UP || nk == KEY_DOWN)
                                          && modal_ == Modal::None
                                          && current_tab_ == Tab::Read;
            const bool want_scroll_hexlog = (nk == KEY_UP || nk == KEY_DOWN)
                                             && modal_ == Modal::HexLog;
            if (want_scroll_read || want_scroll_hexlog) {
                if (held_scroll_key_ != nk) {
                    held_scroll_key_      = nk;
                    held_scroll_start_ms_ = lv_tick_get();
                    held_scroll_last_ms_  = held_scroll_start_ms_;
                }
            }
            return;
        }

        if (!IS_KEY_RELEASED(e)) return;

        // On release, clear held scroll key
        {
            const uint32_t nk = normalize_main_key(raw_key);
            if (nk == KEY_UP || nk == KEY_DOWN) {
                held_scroll_key_ = 0;
            }
        }

        // Global Ctrl+S: save EMU dump from any state when on Emulator tab.
        // Skip when URI input modal is active so symbol-key combos are not hijacked.
        if (modal_ == Modal::None && (mods & KBD_MOD_CTRL) && raw_key == KEY_S &&
            (current_tab_ == Tab::Emulator || modal_ == Modal::EmulatorAction)) {
            const auto conn2 = service_.connection_state();
            cache_serial_device_kind(conn2);
            const auto dev_kind2 = effective_emu_device_kind(conn2);
            const auto ep2 = active_endpoint_for_ui(conn2);
            const bool profile_emu2 =
                (dev_kind2 == nfc_app::DeviceKind::NFCUnit ||
                 dev_kind2 == nfc_app::DeviceKind::ST25RNFC ||
                 ep2.kind == nfc_app::TransportKind::I2cBus ||
                 (ep2.kind == nfc_app::TransportKind::SpiBus && conn2.connected));
            const bool pn532_ndef2 = (dev_kind2 == nfc_app::DeviceKind::PN532);
            const int slot2 = profile_emu2 ? 0 : hw_emu_slot_;
            if (!pn532_ndef2 &&
                service_.emu_dump_loaded(service_.current_emulator_protocol(), slot2)) {
                std::string save_err;
                if (service_.save_emu_dump_cached(
                        service_.current_emulator_protocol(), slot2, &save_err)) {
                    refresh_saved_records();
                    show_toast("Saved");
                    ui_message_ = "Dump saved to records";
                } else {
                    ui_message_ = "Save failed: " + save_err;
                }
                modal_ = Modal::None;
                modal_idx_ = 0;
            }
            render_all();
            return;
        }

        // Global Ctrl+S: save current Read dump result into Saved records.
        // This must run before the generic KEY_S shortcut (which triggers Scan on Read tab).
        if (modal_ == Modal::None && (mods & KBD_MOD_CTRL) && raw_key == KEY_S && current_tab_ == Tab::Read) {
            std::string save_error;
            if (service_.save_last_scan(&save_error)) {
                refresh_saved_records();
                show_toast("Saved");
                ui_message_ = "Record saved to JSON";
                if (modal_ == Modal::ReadMenu || modal_ == Modal::PostScan) {
                    modal_ = Modal::None;
                    modal_idx_ = 0;
                }
            } else {
                ui_message_ = save_error.empty() ? "Save failed" : save_error;
            }
            render_all();
            return;
        }

        // Global Ctrl+L: toggle HexLog overlay (works from any tab/state)
        if (modal_ == Modal::None && (mods & KBD_MOD_CTRL) && raw_key == KEY_L) {
            if (modal_ == Modal::HexLog) {
                modal_ = Modal::None;
            } else {
                modal_ = Modal::HexLog;
                // Scroll to bottom so latest entries are visible
                const int total = nfc_app::NfcHexLog::get().total_lines();
                hex_log_scroll_ = std::max(0, total - LOG_VISIBLE_HEX_LINES);
            }
            render_all();
            return;
        }

        if (modal_ != Modal::None) {
            // Capture Unicode codepoint for character-input modals (more
            // reliable than keycode_to_char which assumes a fixed layout).
            uint32_t cp = key_item ? key_item->codepoint : 0;
            if (cp == 0 && key_item && key_item->utf8[0] != '\0' && key_item->utf8[1] == '\0') {
                cp = static_cast<uint32_t>(static_cast<unsigned char>(key_item->utf8[0]));
            }
            last_key_codepoint_ = cp;
            handle_modal_key(raw_key, mods);
            return;
        }

        // In EMU tab: F/X scroll dump for GroveNFC, cycle slot for PN532Killer
        if (current_tab_ == Tab::Emulator && modal_ == Modal::None &&
            (raw_key == KEY_F || raw_key == KEY_X)) {
            const auto conn = service_.connection_state();
            cache_serial_device_kind(conn);
            const auto kind = effective_emu_device_kind(conn);
            if (kind == nfc_app::DeviceKind::PN532Killer) {
                const int delta = (raw_key == KEY_F) ? -1 : 1;
                hw_emu_slot_ = (hw_emu_slot_ + delta + 8) % 8;
                emu_dump_scroll_ = 0;
                const auto proto = service_.current_emulator_protocol();
                service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
                ui_message_ = "HW Slot " + std::to_string(hw_emu_slot_ + 1);
                render_all();
            } else if (kind == nfc_app::DeviceKind::GroveNFC ||
                       kind == nfc_app::DeviceKind::NFCUnit) {
                // Scroll entire right panel content (header + dump) as one block
                const int delta = (raw_key == KEY_X) ? 1 : -1;
                auto dump_lines = service_.i2c_emulator_dump_lines(service_.current_emulator_protocol());
                const auto proto = service_.current_emulator_protocol();
                const bool is_mfc = (proto == nfc_app::ProtocolKind::MifareClassic);
                int header_lines = is_mfc ? 5 : 3;
                int data_rows = (int)dump_lines.size();
                int total = header_lines + std::max(1, data_rows);
                const int MAX_VISIBLE = 11;
                emu_dump_scroll_ = std::max(0, std::min(emu_dump_scroll_ + delta, std::max(0, total - MAX_VISIBLE)));
                render_all();
            }
            return;
        }

        const uint32_t key = normalize_main_key(raw_key);

        if (current_tab_ == Tab::Emulator && service_.nfcunit_emu_start_state().running) {
            if (key == KEY_LEFT || key == KEY_RIGHT || key == KEY_TAB) {
                ui_message_ = "NFC Unit starting...";
                render_all();
                return;
            }
        }

        switch (key) {
        case KEY_LEFT:
            switch_tab(-1);
            break;
        case KEY_RIGHT:
            switch_tab(1);
            break;
        case KEY_TAB:
            if (current_tab_ == Tab::Read) {
                service_.cycle_device_mode(&ui_message_);
                // Auto-scroll pill bar so the newly active transport is visible
                {
                    const nfc_app::TransportKind new_kind = service_.current_endpoint().kind;
                    static const nfc_app::TransportKind kKindOrder[] = {
                        nfc_app::TransportKind::UsbSerial,
                        nfc_app::TransportKind::UartSerial,
                        nfc_app::TransportKind::I2cBus,
                        nfc_app::TransportKind::SpiBus,
                    };
                    int active_idx = 0;
                    for (int i = 0; i < 4; ++i)
                        if (kKindOrder[i] == new_kind) { active_idx = i; break; }
                    if (active_idx < read_transport_offset_)
                        read_transport_offset_ = active_idx;
                    else if (active_idx >= read_transport_offset_ + 2)
                        read_transport_offset_ = active_idx - 1;
                    if (read_transport_offset_ < 0) read_transport_offset_ = 0;
                    if (read_transport_offset_ > 2) read_transport_offset_ = 2;
                }
                render_all();
            } else if (current_tab_ == Tab::Emulator) {
                const auto conn = service_.connection_state();
                cache_serial_device_kind(conn);
                const auto emu_device_kind = effective_emu_device_kind(conn);
                if (emu_device_kind == nfc_app::DeviceKind::PN532Killer) {
                    service_.cycle_hw_emu_protocol();
                    emu_dump_scroll_ = 0;
                    const auto proto = service_.current_emulator_protocol();
                    service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
                } else if (emu_device_kind == nfc_app::DeviceKind::NFCUnit ||
                           emu_device_kind == nfc_app::DeviceKind::ST25RNFC ||
                           emu_device_kind == nfc_app::DeviceKind::GroveNFC) {
                    if (emu_device_kind == nfc_app::DeviceKind::ST25RNFC) {
                        service_.toggle_spi_profile();
                        ui_message_ = std::string("Profile -> ") + service_.spi_profile_label();
                    } else if (emu_device_kind == nfc_app::DeviceKind::GroveNFC) {
                        service_.cycle_hw_emu_protocol();
                        emu_dump_scroll_ = 0;
                        const auto proto2 = service_.current_emulator_protocol();
                        const std::string src_file = emulator_source_filename(proto2);
                        std::string emu_err;
                        if (service_.grovenfc_activate(proto2, 0, &emu_err)) {
                            ui_message_ = std::string("Protocol -> ") + nfc_app::to_string(proto2) + "  Load from " + src_file;
                        } else {
                            ui_message_ = emu_err.empty() ? "GroveNFC emulation failed" : ("GroveNFC emulation failed: " + emu_err);
                        }
                    } else {
                        service_.toggle_nfcunit_profile_protocol();
                        emu_dump_scroll_ = 0;
                        const auto proto2 = service_.current_emulator_protocol();
                        const std::string src_file = emulator_source_filename(proto2);
                        if (nfcunit_emu_autostart_running_) {
                            ui_message_ = "Load from " + src_file;
                        } else {
                            start_nfcunit_emu_autostart_async();
                            ui_message_ = "Load from " + src_file;
                        }
                    }
                } else {
                    service_.toggle_slot_protocol();
                }
                if (emu_device_kind != nfc_app::DeviceKind::NFCUnit &&
                    emu_device_kind != nfc_app::DeviceKind::ST25RNFC) {
                    ui_message_ = std::string("Protocol -> ") + nfc_app::to_string(service_.current_emulator_protocol());
                }
                render_all();
            }
            break;
        case KEY_UP:
            navigate(-1);
            break;
        case KEY_DOWN:
            navigate(1);
            break;
        case KEY_ENTER:
            activate();
            break;
        case KEY_DELETE:
            // DEL key on READ tab: clear the scan log area
            if (current_tab_ == Tab::Read) {
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                ui_message_ = "Log cleared";
                render_all();
            }
            break;
        case KEY_I:
            if (modal_ == Modal::None) {
                modal_ = Modal::AppInfo;
                render_all();
            }
            break;
        case KEY_S:
            if (current_tab_ == Tab::Emulator) {
                const auto conn = service_.connection_state();
                cache_serial_device_kind(conn);
                const auto endpoint = active_endpoint_for_ui(conn);
                const auto emu_device_kind = effective_emu_device_kind(conn);
                const bool st25r_mode =
                    (emu_device_kind == nfc_app::DeviceKind::ST25RNFC) ||
                    (endpoint.kind == nfc_app::TransportKind::SpiBus && conn.connected);
                if (emu_device_kind == nfc_app::DeviceKind::PN532) {
                    std::string err;
                    if (service_.pn532_ndef_state().running) {
                        ui_message_ = "PN532 NDEF already running";
                    } else if (service_.start_pn532_ndef_emulation(pn532_ndef_uri_, &err)) {
                        ui_message_ = "PN532 NDEF emulation running";
                    } else {
                        ui_message_ = err.empty() ? "NDEF start failed" : err;
                    }
                    render_all();
                } else if (emu_device_kind == nfc_app::DeviceKind::GroveNFC) {
                    const auto protocol = service_.current_emulator_protocol();
                    // Before activating, reload I2C emulator dump from JSON so
                    // the hardware emulates the data actually shown on screen.
                    service_.i2c_emulator_dump_lines(protocol);  // triggers JSON→cache load
                    service_.reload_i2c_profile_from_cache(protocol);

                    std::string emuErr;
                    if (service_.grovenfc_activate(protocol, 0, &emuErr)) {
                        scan_log_lines_.push_back(std::string("> GroveNFC EMU: ") + nfc_app::to_string(protocol) + " started");
                        ui_message_ = "GroveNFC emulation started";
                    } else {
                        scan_log_lines_.push_back(std::string("ERR GroveNFC EMU: ") + (emuErr.empty() ? "activate failed" : emuErr));
                        scan_log_lines_.push_back(std::string("  proto=") + nfc_app::to_string(protocol));
                        ui_message_ = emuErr.empty() ? "GroveNFC start failed" : emuErr;
                    }
                    render_all();
                } else if (endpoint.kind == nfc_app::TransportKind::I2cBus || emu_device_kind == nfc_app::DeviceKind::NFCUnit) {
                    if (service_.nfcunit_emulation_running()) {
                        ui_message_ = "NFC Unit already running";
                    } else if (nfcunit_emu_autostart_running_) {
                        ui_message_ = "NFC Unit starting...";
                    } else {
                        start_nfcunit_emu_autostart_async();
                        ui_message_ = "NFC Unit starting...";
                    }
                    render_all();
                } else if (st25r_mode) {
                    if (service_.spi_listener_active()) {
                        ui_message_ = "SPI ST25R already running";
                    } else {
                        std::string emu_err;
                        const bool ok = service_.spi_start_current_profile(&emu_err);
                        ui_message_ = ok
                            ? ("SPI ST25R " + service_.spi_profile_label() + " emulating...")
                            : ("SPI start failed: " + emu_err);
                    }
                    render_all();
                }
            } else if (current_tab_ == Tab::Read) {
                trigger_read_scan_shortcut();
                render_all();
            }
            break;
        case KEY_R:
            // Keep R as an alias for scan.
            if (current_tab_ == Tab::Read) {
                trigger_read_scan_shortcut();
                render_all();
            }
            break;
        case KEY_P:
            if (current_tab_ == Tab::Emulator) {
                const auto conn = service_.connection_state();
                cache_serial_device_kind(conn);
                const auto endpoint = active_endpoint_for_ui(conn);
                const auto emu_device_kind = effective_emu_device_kind(conn);
                const bool st25r_mode =
                    (emu_device_kind == nfc_app::DeviceKind::ST25RNFC) ||
                    (endpoint.kind == nfc_app::TransportKind::SpiBus && conn.connected);
                if (emu_device_kind == nfc_app::DeviceKind::PN532) {
                    service_.stop_pn532_ndef_emulation();
                    ui_message_ = "PN532 NDEF emulation stopped";
                    render_all();
                } else if (endpoint.kind == nfc_app::TransportKind::I2cBus || emu_device_kind == nfc_app::DeviceKind::NFCUnit) {
                    service_.grovenfc_deactivate();
                    ui_message_ = "NFC Unit emulation stopped";
                    render_all();
                } else if (st25r_mode) {
                    service_.spi_stop_listener();
                    ui_message_ = "SPI ST25R emulation stopped";
                    render_all();
                }
            } else if (current_tab_ == Tab::Read) {
                const auto conn_state = service_.connection_state();
                if (conn_state.connected && conn_state.device_kind == nfc_app::DeviceKind::UHFReader) {
                    std::string error;
                    if (service_.stop_uhf_continuous_scan(&error)) {
                        scan_log_lines_.push_back("> Inventory stopped");
                        ui_message_ = "Inventory stopped";
                    } else {
                        ui_message_ = error.empty() ? "UHF stop failed" : error;
                    }
                } else {
                    ui_message_ = "P: stop inventory";
                }
                render_all();
            }
            break;
        case KEY_ESC:
            break;
        default:
            break;
        }
    }

    uint32_t normalize_main_key(uint32_t key) const
    {
        switch (key) {
        case KEY_F: return KEY_UP;
        case KEY_Z: return KEY_LEFT;
        case KEY_X: return KEY_DOWN;
        case KEY_C: return KEY_RIGHT;
        default: return key;
        }
    }

    void trigger_read_scan_shortcut()
    {
        const auto scan = service_.scan_state();
        if (scan.running) {
            ui_message_ = service_.is_current_device_uhf() ? "Inventory running" : "Scanning...";
            return;
        }

        const auto endpoint = service_.current_endpoint();
        const auto conn = service_.connection_state();
        if (!conn.connected) {
            if (endpoint.kind == nfc_app::TransportKind::UsbSerial) {
                service_.refresh_endpoints();
                usb_select_list_ = service_.usb_endpoints();
                if (usb_select_list_.empty()) {
                    ui_message_ = "No USB device";
                    return;
                }
                usb_select_idx_ = 0;
                modal_ = Modal::UsbSelect;
                modal_idx_ = 0;
                return;
            }
            if (endpoint.kind == nfc_app::TransportKind::I2cBus) {
                i2c_select_list_ = service_.scan_i2c_devices();
                if (i2c_select_list_.empty()) {
                    ui_message_ = "No I2C device";
                    return;
                }
                if (i2c_select_list_.size() > 1) {
                    i2c_select_idx_ = 0;
                    modal_ = Modal::I2cSelect;
                    modal_idx_ = 0;
                    return;
                }
                service_.select_i2c_endpoint(i2c_select_list_[0]);
            }

            if (endpoint.kind == nfc_app::TransportKind::SpiBus) {
                spi_select_list_ = service_.enumerate_spi_devices();
                if (spi_select_list_.empty()) {
                    ui_message_ = "No SPI device";
                    return;
                }
                if (spi_select_list_.size() > 1) {
                    spi_select_idx_ = 0;
                    modal_ = Modal::SpiSelect;
                    modal_idx_ = 0;
                    return;
                }
                service_.select_spi_endpoint(spi_select_list_[0]);
            }

            const auto connect_ep = service_.current_endpoint();
            scan_log_lines_.push_back("> Connect " + connect_ep.label.substr(0, 22) + "...");
            const bool ok = service_.connect_current();
            const auto conn2 = service_.connection_state();
            if (!ok) {
                scan_log_lines_.push_back("ERR " + compact_read_connection_detail(conn2));
                ui_message_ = "Connect failed";
                return;
            }
            scan_log_lines_.push_back("OK  " + compact_read_connection_detail(conn2));
            scan_log_lines_.push_back(supported_protocols_text());
        }

        const bool is_uhf = service_.is_current_device_uhf();
        scan_log_lines_.push_back(is_uhf ? "> Start inventory..." : "> Scan card...");
        if (is_uhf) {
            std::string error;
            if (service_.start_uhf_continuous_scan(&error)) {
                ui_message_ = "Inventory running";
            } else {
                ui_message_ = error.empty() ? "Inventory start failed" : error;
            }
        } else {
            if (service_.start_scan()) {
                ui_message_ = "Scanning...";
            } else {
                const auto state = service_.scan_state();
                ui_message_ = state.error.empty() ? "Scan failed" : state.error;
            }
        }
    }

    void switch_tab(int delta)
    {
        const Tab prev_tab = current_tab_;
        int tab_index = static_cast<int>(current_tab_);
        tab_index = (tab_index + delta + 4) % 4;
        current_tab_ = static_cast<Tab>(tab_index);
        // When leaving Emulator tab, stop NDEF emulation only.
        if (prev_tab == Tab::Emulator && current_tab_ != Tab::Emulator) {
            if (service_.pn532_ndef_state().running) {
                service_.stop_pn532_ndef_emulation();
                ui_message_ = "NDEF emulation stopped";
            }
            if (service_.nfcunit_emulation_running() || service_.nfcunit_emu_start_state().running) {
                service_.grovenfc_deactivate();
                ui_message_ = "NFC Unit emulation stopped";
            } else {
                const auto leaving_conn = service_.connection_state();
                cache_serial_device_kind(leaving_conn);
                if (effective_emu_device_kind(leaving_conn) == nfc_app::DeviceKind::GroveNFC) {
                    service_.grovenfc_deactivate();
                    ui_message_ = "GroveNFC emulation stopped";
                }
            }
            if (service_.spi_listener_active()) {
                service_.spi_stop_listener();
                ui_message_ = "SPI ST25R emulation stopped";
            }
        }
        if (current_tab_ == Tab::Emulator) {
            const auto proto = service_.current_emulator_protocol();
            const std::string src_filename = emulator_source_filename(proto);
            ui_message_ = "Load from " + src_filename;
            const auto conn = service_.connection_state();
            cache_serial_device_kind(conn);
            const auto kind = effective_emu_device_kind(conn);
            if (conn.connected && kind == nfc_app::DeviceKind::PN532Killer) {
                emu_dump_scroll_ = 0;
                const auto proto = service_.current_emulator_protocol();
                service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
            } else if (conn.connected && kind == nfc_app::DeviceKind::GroveNFC) {
                std::string emu_err;
                if (service_.grovenfc_activate(service_.current_emulator_protocol(), 0, &emu_err)) {
                    ui_message_ = std::string("GroveNFC emulating: ") + nfc_app::to_string(service_.current_emulator_protocol());
                } else {
                    ui_message_ = emu_err.empty() ? "GroveNFC emulation failed" : ("GroveNFC emulation failed: " + emu_err);
                }
            } else if (conn.connected && kind == nfc_app::DeviceKind::NFCUnit) {
                if (nfcunit_emu_autostart_running_) {
                    ui_message_ = "Load from " + src_filename;
                } else {
                    start_nfcunit_emu_autostart_async();
                    ui_message_ = "Load from " + src_filename;
                }
            }
        } else if (current_tab_ == Tab::Read) {
            // When entering READ tab with PN532Killer: always switch back to reader mode
            // regardless of which tab we came from (e.g. from Tools or Emulator).
            const auto conn = service_.connection_state();
            if (conn.device_kind == nfc_app::DeviceKind::PN532Killer) {
                service_.hw_switch_to_reader_mode();
            }
        }
        render_all();
    }

    void start_nfcunit_emu_autostart_async()
    {
        {
            std::lock_guard<std::mutex> lock(nfcunit_emu_autostart_mutex_);
            pending_nfcunit_emu_autostart_result_ = false;
            nfcunit_emu_autostart_running_ = true;
            nfcunit_emu_autostart_ok_ = false;
            nfcunit_emu_autostart_result_consumed_ = false;
            nfcunit_emu_autostart_error_.clear();
            nfcunit_emu_autostart_profile_.clear();
        }

        const bool queued = service_.start_nfcunit_current_profile_emulation_async();
        const auto state = service_.nfcunit_emu_start_state();
        if (queued || state.running) {
            ui_message_ = "NFC Unit starting...";
        } else if (state.has_result && !state.ok) {
            ui_message_ = state.error.empty() ? "NFC Unit start failed" : ("NFC Unit start failed: " + state.error);
        } else {
            ui_message_ = "NFC Unit start requested";
        }
    }

    void consume_nfcunit_emu_autostart_result()
    {
        // Handle deferred GroveNFC / NFCUnit emulation start (threaded)
        if (grovenfc_emu_pending_) {
            grovenfc_emu_pending_ = false;
            const auto conn = service_.connection_state();
            const auto kind = effective_emu_device_kind(conn);
            if (conn.connected && (kind == nfc_app::DeviceKind::GroveNFC ||
                                   kind == nfc_app::DeviceKind::NFCUnit)) {
                const auto proto = service_.current_emulator_protocol();
                std::thread([this, proto]() {
                    std::string emuErr;
                    bool ok = service_.grovenfc_activate(proto, 0, &emuErr);
                    grovenfc_emu_result_ok_ = ok;
                    grovenfc_emu_result_msg_ = ok
                        ? (std::string("> EMU auto: ") + nfc_app::to_string(proto))
                        : (std::string("ERR EMU auto: ") + (emuErr.empty() ? "failed" : emuErr));
                    grovenfc_emu_result_ready_ = true;
                }).detach();
            }
        }
        if (grovenfc_emu_result_ready_) {
            if (current_tab_ == Tab::Emulator) {
                ui_message_ = grovenfc_emu_result_msg_;
                render_all();
            }
            grovenfc_emu_result_ready_ = false;
        }

        const auto state = service_.nfcunit_emu_start_state();
        if (state.running) {
            std::lock_guard<std::mutex> lock(nfcunit_emu_autostart_mutex_);
            nfcunit_emu_autostart_running_ = true;
            return;
        }

        bool consumed = true;
        {
            std::lock_guard<std::mutex> lock(nfcunit_emu_autostart_mutex_);
            nfcunit_emu_autostart_running_ = false;
            consumed = nfcunit_emu_autostart_result_consumed_;
        }

        if (!state.has_result || consumed) return;
        if (state.ok) {
            ui_message_ = std::string("NFC Unit ") + (state.profile.empty() ? service_.nfcunit_profile_label() : state.profile) + " emulating";
        } else if (!state.error.empty()) {
            ui_message_ = std::string("NFC Unit start failed: ") + state.error;
        } else {
            ui_message_ = "NFC Unit start failed";
        }
        {
            std::lock_guard<std::mutex> lock(nfcunit_emu_autostart_mutex_);
            nfcunit_emu_autostart_result_consumed_ = true;
        }
    }

    void start_nfcunit_write_async(int saved_index)
    {
        if (nfcunit_write_running_) return;
        const auto rec = saved_records_[saved_index];
        nfcunit_write_running_ = true;
        nfcunit_write_result_ok_ = false;
        nfcunit_write_result_msg_ = "Writing...";
        ui_message_ = "Write started, place tag...";

        nfcunit_write_thread_ = std::thread([this, rec]() {
            std::string err;
            auto progress_cb = [this](const std::string &line) {
                nfcunit_write_result_msg_ = line;
            };
            bool ok = service_.nfcunit_write_tag(rec, &progress_cb, &err);
            nfcunit_write_result_ok_ = ok;
            nfcunit_write_result_msg_ = ok ? "Write complete" : ("Write failed: " + err);
        });
        nfcunit_write_thread_.detach();
    }

    void poll_nfcunit_write_result()
    {
        if (!nfcunit_write_running_) return;
        // Check if still running by trying to join — but it's detached.
        // We use the message as a simple completion signal:
        // When the thread writes to result_msg_ (atomic-like), we consume it.
        // Since we can't join a detached thread, we use a dirty flag check:
        // The thread sets msg to "Write complete" or "Write failed:*" on finish.
        const auto &msg = nfcunit_write_result_msg_;
        if (msg == "Write complete" || msg.find("Write failed:") == 0) {
            ui_message_ = msg;
            nfcunit_write_running_ = false;
        }
    }

    static std::string trim_ascii(const std::string &in)
    {
        size_t begin = 0;
        while (begin < in.size() && std::isspace(static_cast<unsigned char>(in[begin]))) ++begin;
        size_t end = in.size();
        while (end > begin && std::isspace(static_cast<unsigned char>(in[end - 1]))) --end;
        return in.substr(begin, end - begin);
    }

    static std::string upper_ascii(std::string text)
    {
        for (char &ch : text) ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
        return text;
    }

    static std::string normalize_profile_token(const std::string &token)
    {
        std::string out;
        out.reserve(token.size());
        for (unsigned char ch : token) {
            if (std::isalnum(ch)) out.push_back(static_cast<char>(std::toupper(ch)));
        }
        return out;
    }

    static int nfcunit_profile_index_from_token(const std::string &token)
    {
        const std::string n = normalize_profile_token(token);
        if (n == "NTAG" || n == "NTAG213" || n == "ISO14443A" || n == "NFCA") return 0;
        if (n == "MIFARE" || n == "MIFARE1K" || n == "MIFARECLASSIC" || n == "MIFARECLASSIC1K" || n == "MFC") return 1;
        if (n == "ISO15693" || n == "NFCV") return 2;
        return -1;
    }

    static int spi_profile_index_from_token(const std::string &token)
    {
        const std::string n = normalize_profile_token(token);
        if (n == "MIFARE" || n == "MIFARE1K" || n == "MIFARECLASSIC" || n == "MIFARECLASSIC1K" || n == "MFC" || n == "MFC1K") return 0;
        if (n == "NTAG" || n == "NTAG215" || n == "ISO14443A" || n == "NFCA") return 1;
        if (n == "NTAG216") return 2;
        return -1;
    }

    static bool is_iso15693_token(const std::string &token)
    {
        const std::string n = normalize_profile_token(token);
        return (n == "ISO15693" || n == "NFCV");
    }

    void write_nfc_automation_status(const std::string &line) const
    {
        std::ofstream out(kNfcAutomationStatusPath, std::ios::trunc);
        if (!out.good()) return;
        out << line << '\n';
    }

    bool pop_nfc_automation_command(std::string *command)
    {
        if (!command) return false;
        std::ifstream in(kNfcAutomationCmdPath);
        if (!in.good()) return false;
        std::string line;
        std::getline(in, line);
        in.close();
        std::remove(kNfcAutomationCmdPath);
        line = trim_ascii(line);
        if (line.empty()) return false;
        *command = line;
        return true;
    }

    bool ensure_nfcunit_connected_for_automation(std::string *error)
    {
        auto conn = service_.connection_state();
        if (conn.connected && conn.device_kind == nfc_app::DeviceKind::NFCUnit) return true;

        auto i2c_endpoints = service_.scan_i2c_devices();
        if (i2c_endpoints.empty()) {
            if (error) *error = "No NFC Unit I2C endpoint";
            return false;
        }

        size_t pick = 0;
        for (size_t i = 0; i < i2c_endpoints.size(); ++i) {
            if (i2c_endpoints[i].path.find(":0x50") != std::string::npos ||
                i2c_endpoints[i].path.find(":28") != std::string::npos) {
                pick = i;
                break;
            }
        }

        service_.select_i2c_endpoint(i2c_endpoints[pick]);
        if (!service_.connect_current()) {
            conn = service_.connection_state();
            if (error) *error = conn.detail.empty() ? "NFC Unit connect failed" : conn.detail;
            return false;
        }

        conn = service_.connection_state();
        if (!conn.connected || conn.device_kind != nfc_app::DeviceKind::NFCUnit) {
            if (error) *error = "Connected device is not NFC Unit";
            return false;
        }
        return true;
    }

    bool ensure_spi_connected_for_automation(const std::string &path, std::string *error)
    {
        const std::string spi_path = path.empty() ? "/dev/spidev0.2" : path;
        auto conn = service_.connection_state();
        if (conn.connected &&
            conn.endpoint.kind == nfc_app::TransportKind::SpiBus &&
            conn.endpoint.path == spi_path) {
            return true;
        }

        nfc_app::TransportEndpoint ep;
        ep.kind = nfc_app::TransportKind::SpiBus;
        ep.path = spi_path;
        ep.label = "SPI " + spi_path;
        service_.select_spi_endpoint(ep);

        if (!service_.connect_current()) {
            conn = service_.connection_state();
            if (error) *error = conn.detail.empty() ? "SPI connect failed" : conn.detail;
            return false;
        }
        if (error) error->clear();
        return true;
    }

    void process_nfc_automation_command()
    {
        const uint32_t now = lv_tick_get();
        if (now - nfc_automation_last_tick_ < 150) return;
        nfc_automation_last_tick_ = now;

        std::string command;
        if (!pop_nfc_automation_command(&command)) return;

        std::istringstream iss(command);
        std::string verb;
        iss >> verb;
        const std::string verb_upper = upper_ascii(verb);

        auto emit_ok = [this](const std::string &line) {
            write_nfc_automation_status("OK " + line);
        };
        auto emit_err = [this](const std::string &line) {
            write_nfc_automation_status("ERR " + line);
        };

        if (verb_upper == "STATUS") {
            const auto conn = service_.connection_state();
            std::ostringstream oss;
            oss << "status connected=" << (conn.connected ? 1 : 0)
                << " device=" << nfc_app::to_string(conn.device_kind)
                << " profile=" << service_.nfcunit_profile_label()
                << " running=" << (service_.nfcunit_emulation_running() ? 1 : 0)
                << " nfc_profile=" << service_.nfcunit_profile_label()
                << " nfc_running=" << (service_.nfcunit_emulation_running() ? 1 : 0)
                << " spi_profile=" << service_.spi_profile_label()
                << " spi_running=" << (service_.spi_listener_active() ? 1 : 0)
                << " spi_iso15693_emu=" << (service_.spi_supports_iso15693_emulation() ? 1 : 0);
            emit_ok(oss.str());
            ui_message_ = "Automation status exported";
            return;
        }

        if (verb_upper == "SPI_CAPS") {
            emit_ok(service_.spi_caps_status_line());
            ui_message_ = "Automation SPI caps exported";
            return;
        }

        if (verb_upper == "STOP") {
            service_.spi_stop_listener();
            const bool ok = service_.grovenfc_deactivate();
            if (ok) {
                emit_ok("stop emulation");
                ui_message_ = "Automation: emulation stopped";
            } else {
                emit_err("stop failed");
                ui_message_ = "Automation: stop failed";
            }
            return;
        }

        std::string arg;
        std::getline(iss, arg);
        arg = trim_ascii(arg);

        if (verb_upper == "PROFILE") {
            const int profile = nfcunit_profile_index_from_token(arg);
            if (profile < 0) {
                emit_err("unknown profile: " + arg);
                ui_message_ = "Automation: bad profile";
                return;
            }
            service_.set_nfcunit_profile_index(profile);
            emit_ok("profile=" + service_.nfcunit_profile_label());
            ui_message_ = "Automation profile: " + service_.nfcunit_profile_label();
            return;
        }

        if (verb_upper == "SPI_PROFILE") {
            if (is_iso15693_token(arg)) {
                emit_err("SPI ISO15693 emulation requires transparent GPIO timing");
                ui_message_ = "Automation: SPI ISO15693 unsupported";
                return;
            }
            const int profile = spi_profile_index_from_token(arg);
            if (profile < 0) {
                emit_err("unknown spi profile: " + arg);
                ui_message_ = "Automation: bad SPI profile";
                return;
            }
            service_.set_spi_profile_index(profile);
            emit_ok("spi_profile=" + service_.spi_profile_label());
            ui_message_ = "Automation SPI profile: " + service_.spi_profile_label();
            return;
        }

        if (verb_upper == "START" || verb_upper == "RUN") {
            int run_profile = -1;
            if (verb_upper == "RUN") {
                run_profile = nfcunit_profile_index_from_token(arg);
                if (run_profile < 0) {
                    emit_err("unknown profile: " + arg);
                    ui_message_ = "Automation: bad profile";
                    return;
                }
                if (run_profile != service_.nfcunit_profile_index()) {
                    (void)service_.grovenfc_deactivate();
                    service_.disconnect();
                }
            }

            std::string err;
            if (!ensure_nfcunit_connected_for_automation(&err)) {
                emit_err(err.empty() ? "connect failed" : err);
                ui_message_ = "Automation connect failed";
                return;
            }
            if (run_profile >= 0) service_.set_nfcunit_profile_index(run_profile);

            if (service_.start_nfcunit_current_profile_emulation(&err)) {
                std::ostringstream oss;
                oss << "run profile=" << service_.nfcunit_profile_label()
                    << " running=" << (service_.nfcunit_emulation_running() ? 1 : 0);
                emit_ok(oss.str());
                current_tab_ = Tab::Emulator;
                ui_message_ = "Automation: " + service_.nfcunit_profile_label() + " emulating";
            } else {
                emit_err(err.empty() ? "start failed" : err);
                ui_message_ = "Automation start failed";
            }
            return;
        }

        if (verb_upper == "SCAN") {
            std::string status;
            if (service_.connect_and_scan(&status)) {
                emit_ok(status.empty() ? "scan started" : status);
                ui_message_ = "Automation: scan started";
            } else {
                emit_err(status.empty() ? "scan failed" : status);
                ui_message_ = "Automation: scan failed";
            }
            return;
        }

        if (verb_upper == "SPI_RUN") {
            std::istringstream args_ss(arg);
            std::string token1;
            std::string token2;
            args_ss >> token1 >> token2;

            int run_profile = -1;
            bool run_iso15693 = false;
            std::string spi_path = "/dev/spidev0.2";
            if (!token1.empty()) {
                const int p = spi_profile_index_from_token(token1);
                if (p >= 0) {
                    run_profile = p;
                    if (!token2.empty()) spi_path = token2;
                } else if (is_iso15693_token(token1)) {
                    run_iso15693 = true;
                    if (!token2.empty()) spi_path = token2;
                } else {
                    spi_path = token1;
                }
            }

            std::string err;
            if (!ensure_spi_connected_for_automation(spi_path, &err)) {
                emit_err(err.empty() ? "SPI connect failed" : err);
                ui_message_ = "Automation SPI connect failed";
                return;
            }
            if (run_profile >= 0) {
                service_.set_spi_profile_index(run_profile);
            }
            if (run_iso15693) {
                if (!service_.spi_start_iso15693_emulation(&err)) {
                    emit_err(err.empty() ? "SPI ISO15693 emulation unsupported" : err);
                    ui_message_ = "Automation SPI ISO15693 unsupported";
                    return;
                }
                emit_ok("spi run profile=ISO15693 running=1");
                ui_message_ = "Automation SPI: ISO15693 emulating";
                return;
            }
            if (!service_.spi_start_current_profile(&err)) {
                emit_err(err.empty() ? "spi emu start failed" : err);
                ui_message_ = "Automation SPI start failed";
                return;
            }

            std::ostringstream oss;
            oss << "spi run profile=" << service_.spi_profile_label()
                << " running=" << (service_.spi_listener_active() ? 1 : 0);
            emit_ok(oss.str());
            ui_message_ = "Automation SPI: " + service_.spi_profile_label() + " emulating";
            return;
        }

        if (verb_upper == "SPI_EMU_START") {
            std::istringstream args_ss(arg);
            std::string token1;
            std::string token2;
            args_ss >> token1 >> token2;

            std::string err;
            if (is_iso15693_token(token1)) {
                const std::string spi_path = token2.empty() ? "/dev/spidev0.2" : token2;
                if (!ensure_spi_connected_for_automation(spi_path, &err)) {
                    emit_err(err.empty() ? "SPI connect failed" : err);
                    ui_message_ = "Automation SPI connect failed";
                    return;
                }
                if (!service_.spi_start_iso15693_emulation(&err)) {
                    emit_err(err.empty() ? "SPI ISO15693 emulation unsupported" : err);
                    ui_message_ = "Automation SPI ISO15693 unsupported";
                    return;
                }
                emit_ok("spi emu started profile=ISO15693");
                ui_message_ = "Automation SPI: ISO15693 emulating";
                return;
            }
            const int profile = spi_profile_index_from_token(token1);
            if (profile >= 0) {
                const std::string spi_path = token2.empty() ? "/dev/spidev0.2" : token2;
                if (!ensure_spi_connected_for_automation(spi_path, &err)) {
                    emit_err(err.empty() ? "SPI connect failed" : err);
                    ui_message_ = "Automation SPI connect failed";
                    return;
                }
                service_.set_spi_profile_index(profile);
                if (!service_.spi_start_current_profile(&err)) {
                    emit_err(err.empty() ? "spi emu start failed" : err);
                    ui_message_ = "Automation SPI start failed";
                    return;
                }
                emit_ok("spi emu started profile=" + service_.spi_profile_label());
                ui_message_ = "Automation SPI: " + service_.spi_profile_label() + " emulating";
                return;
            }

            // Legacy raw mode: SPI_EMU_START uid atqa sak [spi_path]
            std::string uid_hex = token1;
            std::string atqa_hex = token2;
            std::string sak_hex;
            std::string emu_path;
            args_ss >> sak_hex >> emu_path;
            if (emu_path.empty()) emu_path = "/dev/spidev0.2";

            auto hex_to_bytes = [](const std::string &hex) -> std::vector<uint8_t> {
                std::vector<uint8_t> out;
                for (size_t i = 0; i + 1 < hex.size(); i += 2) {
                    char buf[3] = {hex[i], hex[i + 1], '\0'};
                    out.push_back(static_cast<uint8_t>(std::strtoul(buf, nullptr, 16)));
                }
                return out;
            };

            const auto uid_bytes = hex_to_bytes(uid_hex);
            if (uid_bytes.size() != 4 && uid_bytes.size() != 7) {
                emit_err("SPI_EMU_START: uid must be 4 or 7 bytes (8 or 14 hex digits)");
                ui_message_ = "Automation SPI param error";
                return;
            }
            if (atqa_hex.size() < 4 || sak_hex.size() < 2) {
                emit_err("SPI_EMU_START: invalid atqa/sak");
                ui_message_ = "Automation SPI param error";
                return;
            }
            char *atqa_end = nullptr;
            const unsigned long atqa_ul = std::strtoul(atqa_hex.c_str(), &atqa_end, 16);
            if (atqa_end == nullptr || *atqa_end != '\0' || atqa_ul > 0xFFFFul) {
                emit_err("SPI_EMU_START: invalid atqa value");
                ui_message_ = "Automation SPI param error";
                return;
            }
            const uint16_t atqa = static_cast<uint16_t>(atqa_ul);
            const uint8_t sak = hex_to_bytes(sak_hex)[0];

            if (!ensure_spi_connected_for_automation(emu_path, &err)) {
                emit_err(err.empty() ? "SPI connect failed" : err);
                ui_message_ = "Automation SPI connect failed";
                return;
            }
            if (!service_.spi_start_listener_a(uid_bytes, atqa, sak, &err)) {
                emit_err(err.empty() ? "spi emu start failed" : err);
                ui_message_ = "Automation SPI start failed";
                return;
            }
            emit_ok("spi emu started");
            ui_message_ = "Automation SPI emulating";
            return;
        }

        if (verb_upper == "SPI_EMU_STOP") {
            service_.spi_stop_listener();
            emit_ok("spi emu stopped");
            ui_message_ = "Automation SPI stopped";
            return;
        }

        emit_err("unknown command: " + command);
        ui_message_ = "Automation: unknown command";
    }

    void navigate(int delta)
    {
        switch (current_tab_) {
        case Tab::Read:
            {
                const int max_scroll = read_scroll_max_offset();
                if (read_uses_uhf_table()) {
                    uhf_table_scroll_offset_ = std::max(0, std::min(max_scroll, uhf_table_scroll_offset_ + delta));
                } else {
                    log_scroll_offset_ = std::max(0, std::min(max_scroll, log_scroll_offset_ + delta));
                }
            }
            break;
        case Tab::Saved:
            if (!saved_records_.empty()) {
                saved_idx_ = (saved_idx_ + delta + static_cast<int>(saved_records_.size())) % static_cast<int>(saved_records_.size());
            }
            break;
        case Tab::Emulator: {
            const auto conn = service_.connection_state();
            cache_serial_device_kind(conn);
            if (effective_emu_device_kind(conn) == nfc_app::DeviceKind::PN532Killer) {
                const auto info = service_.emu_slot_info(
                    service_.current_emulator_protocol(), hw_emu_slot_);
                if (info.dump_loaded && !info.dump_lines.empty()) {
                    const int total = static_cast<int>(info.dump_lines.size());
                    const int max_scroll = std::max(0, total - 7);
                    emu_dump_scroll_ = std::max(0, std::min(max_scroll, emu_dump_scroll_ + delta));
                } else {
                    hw_emu_slot_ = (hw_emu_slot_ + delta + 8) % 8;
                    emu_dump_scroll_ = 0;
                    const auto proto = service_.current_emulator_protocol();
                    service_.hw_switch_emu_slot_and_probe(proto, hw_emu_slot_);
                    ui_message_ = "HW Slot " + std::to_string(hw_emu_slot_ + 1);
                }
            } else {
                const auto emu_kind = effective_emu_device_kind(conn);
                if (emu_kind == nfc_app::DeviceKind::NFCUnit ||
                    emu_kind == nfc_app::DeviceKind::ST25RNFC ||
                    emu_kind == nfc_app::DeviceKind::GroveNFC) {
                    // No slot — scroll entire right panel content (header + dump)
                    auto dump_lines = service_.i2c_emulator_dump_lines(service_.current_emulator_protocol());
                    const auto proto2 = service_.current_emulator_protocol();
                    const bool is_mfc2 = (proto2 == nfc_app::ProtocolKind::MifareClassic);
                    int header_lines = is_mfc2 ? 5 : 3;
                    int data_rows = (int)dump_lines.size();
                    int total = header_lines + std::max(1, data_rows);
                    const int MAX_VISIBLE = 11;
                    emu_dump_scroll_ = std::max(0, std::min(emu_dump_scroll_ + delta, std::max(0, total - MAX_VISIBLE)));
                } else {
                    service_.cycle_slot(delta);
                    ui_message_ = "Slot changed";
                }
            }
            break;
        }
        case Tab::Tools:
            tools_idx_ = (tools_idx_ + delta + 4) % 4;
            break;
        }
        render_all();
    }

    void activate()
    {
        switch (current_tab_) {
        case Tab::Read:
            {
                const auto scan = service_.scan_state();
                if (!scan.running) {
                    const auto ep = service_.current_endpoint();
                    if (ep.kind == nfc_app::TransportKind::UartSerial) {
                        uart_edit_buf_ = service_.uart_config();
                        port_settings_field_ = 0;
                        modal_ = Modal::ReadMenu;
                        modal_idx_ = 0;
                    } else if (ep.kind == nfc_app::TransportKind::UsbSerial) {
                        const auto conn = service_.connection_state();
                        if (conn.connected) {
                            modal_ = Modal::ReadMenu;
                            modal_idx_ = 0;
                        } else {
                            service_.refresh_endpoints();
                            usb_select_list_ = service_.usb_endpoints();
                            if (usb_select_list_.empty()) {
                                ui_message_ = "No USB device connected";
                            } else {
                                usb_select_idx_ = 0;
                                modal_ = Modal::UsbSelect;
                                modal_idx_ = 0;
                            }
                        }
                    } else if (ep.kind == nfc_app::TransportKind::I2cBus) {
                        const auto conn = service_.connection_state();
                        if (conn.connected) {
                            modal_ = Modal::ReadMenu;
                            modal_idx_ = 0;
                        } else {
                            i2c_select_list_ = service_.scan_i2c_devices();
                            if (i2c_select_list_.empty()) {
                                ui_message_ = "No I2C device connected";
                            } else {
                                i2c_select_idx_ = 0;
                                modal_ = Modal::I2cSelect;
                                modal_idx_ = 0;
                            }
                        }
                    } else if (ep.kind == nfc_app::TransportKind::SpiBus) {
                        const auto conn = service_.connection_state();
                        if (conn.connected) {
                            modal_ = Modal::ReadMenu;
                            modal_idx_ = 0;
                        } else {
                            spi_select_list_ = service_.enumerate_spi_devices();
                            if (spi_select_list_.empty()) {
                                ui_message_ = "No SPI device connected";
                            } else {
                                spi_select_idx_ = 0;
                                modal_ = Modal::SpiSelect;
                                modal_idx_ = 0;
                            }
                        }
                    }
                }
            }
            break;
        case Tab::Saved:
            activate_saved_action();
            break;
        case Tab::Emulator:
            {
                const auto conn0 = service_.connection_state();
                cache_serial_device_kind(conn0);
                const auto endpoint = active_endpoint_for_ui(conn0);
                if (endpoint.kind == nfc_app::TransportKind::I2cBus ||
                    (endpoint.kind == nfc_app::TransportKind::SpiBus && conn0.connected)) {
                    modal_ = Modal::EmulatorAction;
                    modal_idx_ = 0;
                    break;
                }

                const bool ep0_unidentified =
                    (effective_emu_device_kind(conn0) == nfc_app::DeviceKind::Unknown ||
                     effective_emu_device_kind(conn0) == nfc_app::DeviceKind::NotConnected);
                if ((!conn0.connected || ep0_unidentified) && endpoint.kind == nfc_app::TransportKind::I2cBus) {
                    start_nfcunit_emu_autostart_async();
                    ui_message_ = "NFC Unit connecting...";
                    break;
                }
                if (nfcunit_emu_autostart_running_) {
                    ui_message_ = "NFC Unit starting...";
                    break;
                }
                if (service_.emulation_allowed(&ui_message_)) {
                    modal_ = Modal::EmulatorAction;
                    modal_idx_ = 0;
                }
            }
            break;
        case Tab::Tools:
            activate_tool_action();
            break;
        }
        render_all();
    }

    void activate_read_action()
    {
        switch (read_action_idx_) {
        case 0:
            service_.refresh_endpoints();
            service_.cycle_endpoint(1);
            ui_message_ = "Endpoint cycled";
            break;
        case 1: {
            const auto state = service_.connection_state();
            if (state.connected) {
                service_.disconnect();
                ui_message_ = "Device disconnected";
            } else if (service_.connect_current()) {
                ui_message_ = "Device connected";
            } else {
                ui_message_ = "Connect failed";
            }
            break;
        }
        case 2:
            service_.start_scan();
            ui_message_ = "Scan requested";
            break;
        case 3: {
            std::string error;
            if (service_.save_last_scan(&error)) {
                refresh_saved_records();
                show_toast("Saved");
                ui_message_ = "Record saved to JSON";
            } else {
                ui_message_ = error;
            }
            break;
        }
        default:
            break;
        }
    }

    void activate_saved_action()
    {
        if (saved_records_.empty()) {
            refresh_saved_records();
            ui_message_ = "Reloaded saved list";
            return;
        }
        modal_     = Modal::Action;
        modal_idx_ = 0;
    }

    void activate_tool_action()
    {
        active_tool_idx_ = tools_idx_;
        if (active_tool_idx_ == 0) {
            refresh_mifare_keys();
            mifare_keys_file_mode_ = true;  // default: show file list
            refresh_key_files_with_counts();
            key_file_idx_ = 0;
            key_file_keys_.clear();
            key_file_key_idx_ = 0;
            key_file_editing_ = false;
            key_file_dirty_ = false;
        }
        if (active_tool_idx_ == 1) {
            uid_changer_step_ = 0;
            uid_changer_field_idx_ = 0;
            uid_changer_generation_idx_ = 0;
            uid_changer_uid_len_idx_ = 0;
            uid_changer_source_idx_ = 0;
            uid_changer_write_block0_ = false;
            uid_changer_block0_manual_ = false;
            uid_changer_uid_input_.clear();
            uid_changer_block0_input_.clear();
            uid_changer_gen2_keya_input_ = "FFFFFFFFFFFF";
            uid_changer_gen4_pwd_input_ = "00000000";
        }
        // Reset MFKey wizard state when (re-)entering the tool
        if (active_tool_idx_ == 2 || active_tool_idx_ == 3) {
            mfkey_step_           = 0;
            mfkey_uid_input_      = "";
            mfkey_results_.clear();
            mfkey_result_idx_     = 0;
            mfkey_save_mode_      = false;
            mfkey_save_filename_  = "";
        }
        modal_ = Modal::ToolPage;
        ui_message_ = std::string(tool_name(active_tool_idx_)) + " opened";
    }

    void show_toast(const std::string &msg)
    {
        toast_msg_          = msg;
        toast_expire_tick_  = lv_tick_get() + 1000;
    }

    void refresh_saved_records()
    {
        saved_records_ = service_.list_saved_records();
        if (saved_idx_ >= static_cast<int>(saved_records_.size())) saved_idx_ = 0;
    }

    void refresh_mifare_keys()
    {
        mifare_keys_ = service_.list_mifare_keys();
        if (mifare_key_idx_ > static_cast<int>(mifare_keys_.size())) {
            mifare_key_idx_ = static_cast<int>(mifare_keys_.size());
        }
    }

    bool tools_focus_mode() const
    {
        return current_tab_ == Tab::Tools && modal_ == Modal::ToolPage;
    }

    void refresh_key_files_with_counts()
    {
        key_files_ = service_.list_key_files();
        key_file_counts_.clear();
        key_file_counts_.reserve(key_files_.size());
        for (const auto &name : key_files_) {
            key_file_counts_.push_back(static_cast<int>(service_.load_key_file(name).size()));
        }
        if (key_file_idx_ >= static_cast<int>(key_files_.size())) key_file_idx_ = 0;
    }

    void render_all()
    {
        update_scan_log();
        cache_serial_device_kind(service_.connection_state());
        if (current_tab_ == Tab::Tools) {
            if (modal_ == Modal::DeviceProbe) set_page_title("RFID > Device Probe");
            else if (modal_ == Modal::UartConfig) set_page_title("RFID > UART Config");
            else if (modal_ == Modal::ToolPage) set_page_title((std::string("RFID > ") + tool_name(active_tool_idx_)).c_str());
            else set_page_title("RFID > Tools");
        } else {
            set_page_title("RFID");
        }
        render_tabs();
        render_content();
    }

    void render_tabs()
    {
        lv_obj_t *tab_bar = ui_obj_["tab_bar"];
        lv_obj_clear_flag(tab_bar, LV_OBJ_FLAG_HIDDEN);

        for (int index = 0; index < 4; ++index) {
            lv_obj_t *item = ui_obj_[std::string("tab_") + std::to_string(index)];
            lv_obj_clear_flag(item, LV_OBJ_FLAG_HIDDEN);
            const bool active = (index == static_cast<int>(current_tab_));
            lv_obj_set_style_bg_color(item, lv_color_hex(active ? 0xF7A600 : 0x1E1E1E), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(item, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_text_color(item, lv_color_hex(active ? 0x000000 : 0xD0D0D0), LV_PART_MAIN | LV_STATE_DEFAULT);
        }
    }

    void render_content()
    {
        lv_obj_t *content = ui_obj_["content"];
        lv_obj_set_pos(content, 0, CONTENT_Y);
        lv_obj_set_size(content, 320, CONTENT_H);
        lv_obj_clean(content);

        switch (current_tab_) {
        case Tab::Read:
            render_read_tab(content);
            if (modal_ == Modal::PostScan) render_post_scan_modal(content);
            else if (modal_ == Modal::ReadMenu) render_read_menu_modal(content);
            else if (modal_ == Modal::PortSettings) render_port_settings_modal(content);
            else if (modal_ == Modal::UsbSelect) render_usb_select_modal(content);
            else if (modal_ == Modal::I2cSelect) render_i2c_select_modal(content);
            else if (modal_ == Modal::SpiSelect) render_spi_select_modal(content);
            break;
        case Tab::Saved:
            render_saved_tab(content);
            if (modal_ != Modal::None && modal_ != Modal::AppInfo) render_saved_modal(content);
            break;
        case Tab::Emulator:
            render_emulator_tab(content);
            if (modal_ == Modal::EmulatorAction) render_emulator_modal(content);
            else if (modal_ == Modal::Pn532NdefInput) render_pn532_ndef_input_modal(content);
            break;
        case Tab::Tools:
            render_tools_tab(content);
            break;
        }
        // Global overlay: AppInfo modal shown on any tab
        if (modal_ == Modal::AppInfo) {
            render_app_info_modal(content);
        }
        // HexLog overlay: full-screen Ctrl+L log overlay (above everything, including AppInfo)
        if (modal_ == Modal::HexLog) {
            render_hex_log_overlay(content);
        }
        // Toast overlay: 1-second auto-dismiss popup on top of everything
        if (!toast_msg_.empty()) {
            render_toast_overlay(content);
        }
    }

    void update_scan_log()
    {
        uhf_table_rows_ = service_.uhf_table_rows();
        {
            const int max_scroll = std::max(0, static_cast<int>(uhf_table_rows_.size()) - read_uhf_visible_rows());
            uhf_table_scroll_offset_ = std::max(0, std::min(max_scroll, uhf_table_scroll_offset_));
        }

        // Always drain real-time block lines pushed during Gen1A dump
        {
            auto lines = service_.drain_pending_log();
            const auto conn = service_.connection_state();
            const bool suppress_detect_trace = conn.connected && is_identified_device_kind(conn.device_kind);
            for (auto &l : lines) {
                // UHF scan hits can be very frequent; the table view already shows live counts.
                if (l.size() >= 4 && l[0] == 'E' && l[1] == 'P' && l[2] == 'C' && l[3] == ' ') {
                    continue;
                }
                if (suppress_detect_trace && l.rfind("[Detect]", 0) == 0) {
                    continue;
                }
                scan_log_lines_.push_back(std::move(l));
                log_scroll_offset_ = std::max(0, static_cast<int>(scan_log_lines_.size()) - read_log_visible_lines());
            }
        }

        const auto scan = service_.scan_state();
        const bool now_running = scan.running;
        if (!now_running && last_scan_running_) {
            if (!scan.has_result) {
                scan_log_lines_.push_back(std::string("ERR ") + (scan.error.empty() ? "no tag" : to_compact(scan.error, 52)));
            }
            log_scroll_offset_ = std::max(0, static_cast<int>(scan_log_lines_.size()) - read_log_visible_lines());
        }
        last_scan_running_ = now_running;
        // Keep a larger history so long dumps can still be reviewed with scrolling.
        if (scan_log_lines_.size() > 600) {
            const int trim = static_cast<int>(scan_log_lines_.size() - 600);
            scan_log_lines_.erase(scan_log_lines_.begin(), scan_log_lines_.begin() + trim);
            log_scroll_offset_ = std::max(0, log_scroll_offset_ - trim);
        }
    }

    // ── MFC dump helpers ─────────────────────────────────────────────────────

    static bool has_dump_lines(const std::vector<std::string> &lines)
    {
        for (const auto &l : lines) {
            if (l.size() >= 3 && std::isdigit((unsigned char)l[0]) &&
                std::isdigit((unsigned char)l[1]) && l[2] == ':')
                return true;
        }
        return false;
    }

    static bool is_default_mfc_key(const std::string &hex12)
    {
        static const char *defaults[] = {
            "FFFFFFFFFFFF", "A0A1A2A3A4A5", "D3F7D3F7D3F7",
            "000000000000", "B0B1B2B3B4B5", "4D3A99C351DD", nullptr
        };
        std::string up(hex12);
        for (auto &c : up) c = (char)std::toupper((unsigned char)c);
        for (int i = 0; defaults[i]; ++i)
            if (up == defaults[i]) return true;
        return false;
    }

    std::vector<ReadMenuAction> read_menu_actions() const
    {
        const auto ep = service_.current_endpoint();
        const auto conn = service_.connection_state();
        const bool uhf_running = service_.uhf_continuous_scan_running();
        const bool has_uhf_data = !service_.uhf_table_rows().empty();

        auto make_uhf_actions = [&](bool include_port_settings) {
            std::vector<ReadMenuAction> actions;
            actions.push_back(uhf_running ? ReadMenuAction::StopUHFContinuous
                                          : ReadMenuAction::StartUHFContinuous);
            if (has_uhf_data) actions.push_back(ReadMenuAction::ExportUHFCsv);
            if (include_port_settings) actions.push_back(ReadMenuAction::PortSettings);
            actions.push_back(ReadMenuAction::Clear);
            return actions;
        };

        if (ep.kind == nfc_app::TransportKind::UsbSerial) {
            if (!conn.connected) {
                return {
                    ReadMenuAction::ConnectDevice,
                };
            }
            if (conn.device_kind == nfc_app::DeviceKind::UHFReader) {
                return make_uhf_actions(false);
            }
            return {
                ReadMenuAction::Scan,
                ReadMenuAction::Dump,
                ReadMenuAction::Clear,
            };
        }

        if (ep.kind == nfc_app::TransportKind::UartSerial) {
            if (!conn.connected) {
                return {
                    ReadMenuAction::ConnectDevice,
                    ReadMenuAction::PortSettings,
                };
            }
            if (conn.device_kind == nfc_app::DeviceKind::UHFReader) {
                return make_uhf_actions(true);
            }
            return {
                ReadMenuAction::Scan,
                ReadMenuAction::Dump,
                ReadMenuAction::Clear,
            };
        }

        if (ep.kind == nfc_app::TransportKind::I2cBus) {
            if (!conn.connected) {
                return {
                    ReadMenuAction::ConnectDevice,
                };
            }
            return {
                ReadMenuAction::Scan,
                ReadMenuAction::Dump,
                ReadMenuAction::Clear,
            };
        }

        if (ep.kind == nfc_app::TransportKind::SpiBus) {
            if (!conn.connected) {
                return {
                    ReadMenuAction::ConnectDevice,
                };
            }
            return {
                ReadMenuAction::Scan,
                ReadMenuAction::Dump,
                ReadMenuAction::Clear,
            };
        }

        if (conn.connected && conn.device_kind == nfc_app::DeviceKind::UHFReader) {
            return make_uhf_actions(false);
        }

        return {
            ReadMenuAction::Scan,
            ReadMenuAction::Dump,
            ReadMenuAction::Clear,
        };
    }

    static const char *protocol_short_name(nfc_app::ProtocolKind protocol)
    {
        switch (protocol) {
        case nfc_app::ProtocolKind::Iso14443A: return "ISO14443A";
        case nfc_app::ProtocolKind::Iso14443B: return "ISO14443B";
        case nfc_app::ProtocolKind::Iso15693: return "ISO15693";
        case nfc_app::ProtocolKind::Felica: return "Felica";
        case nfc_app::ProtocolKind::MifareClassic: return "MFC";
        default: return "UNKNOWN";
        }
    }

    std::string supported_protocols_text() const
    {
        const auto conn = service_.connection_state();
        if (conn.connected && conn.device_kind == nfc_app::DeviceKind::UHFReader) {
            return "Protocols: UHF EPC Gen2";
        }

        const auto supported = service_.supported_protocols_for_current_device();
        if (supported.empty()) return "Protocols: (none)";

        std::string text = "Protocols: ";
        for (size_t i = 0; i < supported.size(); ++i) {
            if (i > 0) text += '/';
            text += protocol_short_name(supported[i]);
        }
        return text;
    }

    static const char *transport_supported_devices_text(nfc_app::TransportKind kind)
    {
        switch (kind) {
        case nfc_app::TransportKind::UsbSerial:
            return "PN532, PN532Killer, UHFReader";
        case nfc_app::TransportKind::UartSerial:
            return "PN532, PN532Killer, UHFReader";
        case nfc_app::TransportKind::I2cBus:
            return "NFC Unit, GroveNFC";
        case nfc_app::TransportKind::SpiBus:
            return "M5 NFC CAP";
        default:
            return "Demo/Unknown";
        }
    }

    const char *read_menu_action_label(ReadMenuAction action) const
    {
        switch (action) {
        case ReadMenuAction::ConnectDevice: {
            const auto conn = service_.connection_state();
            return conn.connected ? "Reconnect Device" : "Connect Device";
        }
        case ReadMenuAction::PortSettings: return "Port Settings";
        case ReadMenuAction::Scan:         return "Scan";
        case ReadMenuAction::ScanOnceUHF:  return "Scan Once (UHF)";
        case ReadMenuAction::StartUHFContinuous: return "Start Inventory";
        case ReadMenuAction::StopUHFContinuous:  return "Stop Inventory";
        case ReadMenuAction::ExportUHFCsv: return "Export CSV";
        case ReadMenuAction::Dump:         return "Dump";
        case ReadMenuAction::Save:         return "Save";
        case ReadMenuAction::Clear:        return "Clear";
        default:                           return "Unknown";
        }
    }

    // Render one dump line with fixed-width font.
    // For MFC payloads ("BB:HHHH...32hex"), apply trailer key coloring and
    // block0 field coloring based on UID length (4-byte / 7-byte UID).
    void render_dump_line_colored(lv_obj_t *parent, int x_base, int y, const std::string &line, int uid_len)
    {
        constexpr int CW = 8;  // unscii_8 char width in px
        constexpr int DUMP_FONT = 7;

        const size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0 || colon > 3) {
            create_text(parent, x_base, y, to_compact(line, 37).c_str(), 0xD8D8D8, 10);
            return;
        }
        for (size_t i = 0; i < colon; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(line[i]))) {
                create_text(parent, x_base, y, to_compact(line, 37).c_str(), 0xD8D8D8, 10);
                return;
            }
        }

        const int block_num = std::stoi(line.substr(0, colon), nullptr, 10);
        const bool is_trailer = (block_num % 4 == 3);

        // "BB:" prefix in dark gray — use unscii_8 (font_size<8) for fixed 8px/char
        const std::string prefix = line.substr(0, colon + 1);
        create_text(parent, x_base, y, prefix.c_str(), 0x606060, DUMP_FONT);

        const int hx = x_base + static_cast<int>((colon + 1) * CW);  // hex data starts after "BB:"
        const std::string hex = line.substr(colon + 1);

        auto is_all_hex = [](const std::string &s) {
            if (s.empty()) return false;
            for (char ch : s) {
                if (!std::isxdigit(static_cast<unsigned char>(ch))) return false;
            }
            return true;
        };

        auto ascii_from_hex = [](const std::string &s) {
            std::string out;
            if ((s.size() % 2) != 0) return out;
            out.reserve(s.size() / 2);
            for (size_t i = 0; i + 1 < s.size(); i += 2) {
                const std::string pair = s.substr(i, 2);
                const unsigned long v = std::strtoul(pair.c_str(), nullptr, 16);
                const unsigned char ch = static_cast<unsigned char>(v & 0xFF);
                out.push_back((ch >= 32 && ch <= 126) ? static_cast<char>(ch) : '.');
            }
            return out;
        };

        // Non-MFC payloads (e.g. MFU/ISO15693) keep index + fixed-width body.
        if (hex.size() == 8 && is_all_hex(hex)) {
            // MFU/NTAG page highlighting:
            //   page0 last byte  = BCC0
            //   page2 first byte = BCC1
            if (block_num == 0) {
                create_text(parent, hx,          y, hex.substr(0, 6).c_str(), 0x00D2FF, DUMP_FONT); // UID[0..2]
                create_text(parent, hx + 6 * CW, y, hex.substr(6, 2).c_str(), 0xFF66CC, DUMP_FONT); // BCC0
            } else if (block_num == 1) {
                create_text(parent, hx, y, hex.c_str(), 0x00D2FF, DUMP_FONT); // UID[3..6]
            } else if (block_num == 2) {
                create_text(parent, hx,          y, hex.substr(0, 2).c_str(), 0xFF66CC, DUMP_FONT); // BCC1
                create_text(parent, hx + 2 * CW, y, hex.substr(2, 6).c_str(), 0xB0B0B0, DUMP_FONT);
            } else {
                create_text(parent, hx, y, hex.c_str(), 0xC0C0C0, DUMP_FONT);
            }

            const std::string ascii = ascii_from_hex(hex);
            create_text(parent, hx + 10 * CW, y, "|", 0x606060, DUMP_FONT);
            create_text(parent, hx + 12 * CW, y, ascii.c_str(), 0x8FD0FF, DUMP_FONT);
            return;
        }

        if (hex.size() != 32) {
            create_text(parent, hx, y, to_compact(hex, 34).c_str(), 0xC0C0C0, DUMP_FONT);
            return;
        }

        if (is_trailer) {
            // Key A (bytes 0-5): hex chars [0..11]
            const std::string keyA = hex.substr(0, 12);
            create_text(parent, hx,               y, keyA.c_str(),
                        (block_num == 3) ? 0x00CC66u : (is_default_mfc_key(keyA) ? 0x00CC66u : 0xFF8800u), DUMP_FONT);
            // Access Conditions + GPB (bytes 6-9): hex chars [12..19]
            const std::string ac = hex.substr(12, 8);
            create_text(parent, hx + 12 * CW,    y, ac.c_str(),   0xF7A600, DUMP_FONT);
            // Key B (bytes 10-15): hex chars [20..31]
            const std::string keyB = hex.substr(20, 12);
            create_text(parent, hx + 20 * CW,    y, keyB.c_str(),
                        is_default_mfc_key(keyB) ? 0x00CC66u : 0xFF8800u, DUMP_FONT);
        } else if (block_num == 0) {
            if (uid_len >= 7) {
                // 7-byte UID block0: UID[0..6] | SAK | ATQA[2] | manufacturer data
                create_text(parent, hx,          y, hex.substr(0, 14).c_str(), 0x00D2FF, DUMP_FONT);
                create_text(parent, hx + 14 * CW,y, hex.substr(14, 2).c_str(), 0xFFD166, DUMP_FONT);
                create_text(parent, hx + 16 * CW,y, hex.substr(16, 4).c_str(), 0x7CFF6B, DUMP_FONT);
                create_text(parent, hx + 20 * CW,y, hex.substr(20, 12).c_str(), 0xB0B0B0, DUMP_FONT);
            } else {
                // 4-byte UID block0: UID[0..3] | BCC | SAK | ATQA[2] | manufacturer data
                create_text(parent, hx,          y, hex.substr(0, 8).c_str(),  0x00D2FF, DUMP_FONT);
                create_text(parent, hx + 8 * CW, y, hex.substr(8, 2).c_str(),  0xFF66CC, DUMP_FONT);
                create_text(parent, hx + 10 * CW,y, hex.substr(10, 2).c_str(), 0xFFD166, DUMP_FONT);
                create_text(parent, hx + 12 * CW,y, hex.substr(12, 4).c_str(), 0x7CFF6B, DUMP_FONT);
                create_text(parent, hx + 16 * CW,y, hex.substr(16, 16).c_str(),0xB0B0B0, DUMP_FONT);
            }
        } else {
            create_text(parent, hx, y, hex.c_str(), 0xC0C0C0, DUMP_FONT);
        }
    }

    void render_read_tab(lv_obj_t *parent)
    {
        const auto scan = service_.scan_state();
        const auto endpoint = service_.current_endpoint();
        const auto conn = service_.connection_state();
        const nfc_app::SavedRecord &record = scan.last_record;
        const bool use_uhf_table = read_uses_uhf_table();

        // ── Top summary bar: transport mode pills + device label ──────────
        lv_obj_t *summary = create_panel(parent, 0, 0, 320, 18, 0x161616);
        {
            const nfc_app::TransportKind cur = endpoint.kind;
            // 4 transport kinds in fixed order; show 2 at a time with arrows
            struct TransportEntry { const char *label; nfc_app::TransportKind kind; };
            static const TransportEntry kModes[] = {
                {"USB",  nfc_app::TransportKind::UsbSerial},
                {"UART", nfc_app::TransportKind::UartSerial},
                {"I2C",  nfc_app::TransportKind::I2cBus},
                {"SPI",  nfc_app::TransportKind::SpiBus},
            };
            static constexpr int kModeCount = 4;

            // Clamp offset so the active kind is always visible
            {
                int active_idx = 0;
                for (int i = 0; i < kModeCount; ++i)
                    if (kModes[i].kind == cur) { active_idx = i; break; }
                if (active_idx < read_transport_offset_)
                    read_transport_offset_ = active_idx;
                else if (active_idx >= read_transport_offset_ + 2)
                    read_transport_offset_ = active_idx - 1;
                if (read_transport_offset_ > kModeCount - 2) read_transport_offset_ = kModeCount - 2;
                if (read_transport_offset_ < 0) read_transport_offset_ = 0;
            }

            // Left arrow (shown when offset > 0)
            if (read_transport_offset_ > 0) {
                lv_obj_t *arr = lv_label_create(summary);
                lv_label_set_text(arr, "<");
                lv_obj_set_pos(arr, 2, 4);
                lv_obj_set_style_text_color(arr, lv_color_hex(0x707070), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_text_font(arr, &lv_font_montserrat_10, LV_PART_MAIN | LV_STATE_DEFAULT);
            }

            // Two visible pills
            const int pill_x[2] = {16, 62};
            for (int vi = 0; vi < 2; ++vi) {
                const int mi = read_transport_offset_ + vi;
                if (mi >= kModeCount) break;
                const bool active = (kModes[mi].kind == cur);
                lv_obj_t *pill = lv_obj_create(summary);
                lv_obj_set_size(pill, 44, 14);
                lv_obj_set_pos(pill, pill_x[vi], 2);
                lv_obj_set_style_radius(pill, 3, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_color(pill, lv_color_hex(active ? 0xF7A600 : 0x303030), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_opa(pill, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_border_width(pill, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_pad_all(pill, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_clear_flag(pill, LV_OBJ_FLAG_SCROLLABLE);
                lv_obj_t *lbl = lv_label_create(pill);
                lv_label_set_text(lbl, kModes[mi].label);
                lv_obj_set_style_text_color(lbl, lv_color_hex(active ? 0x000000 : 0x909090), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_center(lbl);
            }

            // Right arrow (shown when there are more pills to the right)
            if (read_transport_offset_ + 2 < kModeCount) {
                lv_obj_t *arr = lv_label_create(summary);
                lv_label_set_text(arr, ">");
                lv_obj_set_pos(arr, 110, 4);
                lv_obj_set_style_text_color(arr, lv_color_hex(0x707070), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_text_font(arr, &lv_font_montserrat_10, LV_PART_MAIN | LV_STATE_DEFAULT);
            }
        }
        {
            std::string disp_label = endpoint.label;
            if (endpoint.kind == nfc_app::TransportKind::UsbSerial) {
                const std::string prefix = std::string(nfc_app::to_string(endpoint.kind)) + " ";
                if (disp_label.size() > prefix.size() && disp_label.substr(0, prefix.size()) == prefix)
                    disp_label = disp_label.substr(prefix.size());
            }
            create_text(summary, 152, 3, to_compact(disp_label, 26).c_str(), 0x00D2FF, 11);
        }

        // ── Card info header (shown when a result exists) ─────────────────
        int log_y = 20;
        int log_h = 100;
        if (scan.has_result && !use_uhf_table) {
            const auto &tag = record.tag;
            auto find_identity_ci = [&](const char *key) -> std::string {
                std::string key_up;
                for (const char *p = key; p && *p; ++p)
                    key_up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(*p))));
                for (const auto &kv : tag.identity_fields) {
                    std::string field_up;
                    for (char ch : kv.first)
                        field_up.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
                    if (field_up == key_up) return kv.second;
                }
                return "-";
            };

            std::string uid_clean;
            uid_clean.reserve(tag.uid.size());
            for (char c : tag.uid) if (c != ':') uid_clean.push_back(c);

            const std::string type_text = tag.tag_type.empty() ? nfc_app::to_string(tag.protocol) : tag.tag_type;
            const std::string atqa_str = find_identity_ci("ATQA");
            const std::string sak_str  = find_identity_ci("SAK");

            lv_obj_t *info = create_panel(parent, 0, 20, 320, 13, 0x0C1810);
            std::string card_line = type_text + " " + uid_clean;
            if (tag.protocol != nfc_app::ProtocolKind::Iso15693) {
                card_line += " SAK:" + sak_str + " ATQA:" + atqa_str;
            }
            create_text(info, 4, 2, to_compact(card_line, 52).c_str(), 0x00FF88, 10);
            log_y = 34;
            log_h = 86;
        }

        // ── Log area: always full-width ────────────────────────────────────
        constexpr int LOG_LINE_H = 10;
        const int visible_lines  = log_h / LOG_LINE_H;
        const int total_lines    = static_cast<int>(scan_log_lines_.size());

        lv_obj_t *detail = create_panel(parent, 0, log_y, 320, log_h, 0x0A0A0A);

        if (use_uhf_table) {
            const int idx_x = 4;
            const int epc_x = 34;
            const int cnt_x = 276; // right-aligned 5-char count column near panel edge
            create_text(detail, idx_x, 2, "#", 0x7FBFFF, 7);
            create_text(detail, epc_x, 2, "EPC", 0x7FBFFF, 7);
            char cnt_hdr[8];
            std::snprintf(cnt_hdr, sizeof(cnt_hdr), "%5s", "CNT");
            create_text(detail, cnt_x, 2, cnt_hdr, 0x7FBFFF, 7);

            const int row_y = 14;
            const int row_h = 10;
            const int visible_rows = std::max(1, (log_h - row_y - 2) / row_h);
            const int total_rows = static_cast<int>(uhf_table_rows_.size());
            const int scroll = std::max(0, std::min(uhf_table_scroll_offset_,
                                                    std::max(0, total_rows - visible_rows)));

            if (total_rows == 0) {
                create_text(detail, 4, 24,
                            scan.running ? "Scanning UHF tags..." : "No UHF tag yet (S:Scan / P:Stop)",
                            0x9E9E9E, 10);
            } else {
                for (int row = 0; row < visible_rows; ++row) {
                    const int idx = scroll + row;
                    if (idx >= total_rows) break;
                    const auto &item = uhf_table_rows_[static_cast<size_t>(idx)];

                    const int epc_max_chars = std::max(8, (cnt_x - epc_x) / 8 - 1);
                    std::string epc = item.epc;
                    if (static_cast<int>(epc.size()) > epc_max_chars) {
                        if (epc_max_chars > 14) {
                            const int tail_len = epc_max_chars - 14;
                            epc = epc.substr(0, 12) + ".." + epc.substr(epc.size() - tail_len);
                        } else {
                            epc = epc.substr(0, static_cast<size_t>(epc_max_chars));
                        }
                    }

                    char idx_text[8];
                    std::snprintf(idx_text, sizeof(idx_text), "%d", idx + 1);
                    char cnt_text[8];
                    std::snprintf(cnt_text, sizeof(cnt_text), "%5d", item.read_count);

                    const int y = row_y + row * row_h;
                    create_text(detail, idx_x, y, idx_text, 0xD6F0FF, 7);
                    create_text(detail, epc_x, y, epc.c_str(), 0xD6F0FF, 7);
                    create_text(detail, cnt_x, y, cnt_text, 0xD6F0FF, 7);
                }
            }
        } else if (!scan.running && !scan.has_result && scan_log_lines_.empty()) {
            // Idle — nothing scanned yet
            create_text(detail, 4, 10,
                        conn.connected ? "Ready" : "Device not connected",
                        0x9E9E9E, 11);
            create_text(detail, 4, 28, "OK: Menu", 0xF7A600, 10);
            create_text(detail, 4, 42, "Tab: mode  S: scan  P: stop", 0xD8D8D8, 10);

            if (conn.connected) {
                create_text(detail, 4, 56, to_compact(supported_protocols_text(), 52).c_str(), 0x8DB6FF, 10);
            } else {
                const std::string supported = std::string("Supported: ") + transport_supported_devices_text(endpoint.kind);
                create_text(detail, 4, 56, to_compact(supported, 52).c_str(), 0x8DB6FF, 10);
            }

            if (!scan.error.empty())
                if (conn.connected)
                    create_text(detail, 4, 68, to_compact(scan.error, 40).c_str(), 0xFF6060, 10);
        } else {
            int uid_hex_digits = 0;
            for (char ch : record.tag.uid) {
                if (std::isxdigit(static_cast<unsigned char>(ch))) ++uid_hex_digits;
            }
            const int uid_len = uid_hex_digits / 2;

            for (int row = 0; row < visible_lines; ++row) {
                const int idx = log_scroll_offset_ + row;
                if (idx >= total_lines) break;
                const auto &line = scan_log_lines_[idx];
                const int y = 2 + row * LOG_LINE_H;

                const size_t colon = line.find(':');
                bool looks_dump_line = (colon != std::string::npos && colon > 0 && colon <= 3);
                if (looks_dump_line) {
                    for (size_t i = 0; i < colon; ++i) {
                        if (!std::isdigit(static_cast<unsigned char>(line[i]))) {
                            looks_dump_line = false;
                            break;
                        }
                    }
                }

                if (looks_dump_line) {
                    render_dump_line_colored(detail, 2, y, line, uid_len);
                } else {
                    uint32_t color = 0xD0D0D0;
                    if (line.size() >= 2 && line[0] == 'O' && line[1] == 'K') color = 0x00FF88;
                    else if (line.size() >= 3 && line[0] == 'E' && line[1] == 'R' && line[2] == 'R') color = 0xFF6060;
                    else if (!line.empty() && line[0] == '>') color = 0xF7A600;
                    else if (line.size() >= 6 && line.substr(0, 6) == "MAGIC:") color = 0xFFD700;
                    create_text(detail, 4, y, to_compact(line, 52).c_str(), color, 10);
                }
            }
        }
        // No footer — log lines already show status
    }

    void render_saved_tab(lv_obj_t *parent)
    {
        lv_obj_t *list = create_panel(parent, 0, 0, 122, 104, 0x101010);
        lv_obj_t *detail = create_panel(parent, 126, 0, 194, 104, 0x101010);

        if (saved_records_.empty()) {
            create_text(list, 6, 8, "No saved records", 0x7A7A7A, 11);
            create_text(detail, 6, 6, "Save from Read tab first", 0x9E9E9E, 11);
        } else {
            const int visible = saved_records_.size() < 4 ? static_cast<int>(saved_records_.size()) : 4;
            int offset = saved_idx_ - 1;
            if (offset < 0) offset = 0;
            if (offset > static_cast<int>(saved_records_.size()) - visible) offset = static_cast<int>(saved_records_.size()) - visible;
            if (offset < 0) offset = 0;
            for (int row = 0; row < visible; ++row) {
                const int index = offset + row;
                const bool selected = (index == saved_idx_);
                const auto &record = saved_records_[index];
                lv_obj_t *entry = lv_obj_create(list);
                lv_obj_remove_style_all(entry);  // strip theme padding/layout
                lv_obj_set_size(entry, 114, 20);
                lv_obj_set_pos(entry, 4, 8 + row * 24);
                lv_obj_set_style_bg_color(entry, lv_color_hex(selected ? 0xF7A600 : 0x171717), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_opa(entry, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_clear_flag(entry, LV_OBJ_FLAG_SCROLLABLE);
                create_text(entry, 4, 0, to_compact(record.meta.display_name, 14).c_str(), selected ? 0x000000 : 0xFFFFFF, 11);
                create_text(entry, 4, 10, nfc_app::to_string(record.tag.protocol), selected ? 0x2F2F2F : 0x9E9E9E, 10);
            }

            const auto &record = saved_records_[saved_idx_];
            const std::string uid_str = record.tag.uid.empty()
                ? (record.tag.raw_data.empty() ? "(none)" : to_compact(record.tag.raw_data[0], 22))
                : record.tag.uid;
            create_text(detail, 6,  4, to_compact(record.meta.display_name, 22).c_str(), 0xFFFFFF, 12);
            create_text(detail, 6, 19, (std::string("UID: ") + uid_str).c_str(), 0x00D2FF, 11);
            create_text(detail, 6, 33, (std::string("Type: ") + nfc_app::to_string(record.tag.protocol)).c_str(), 0xD8D8D8, 11);
            create_text(detail, 6, 47, (std::string("Src: ") + record.meta.source).c_str(), 0x8DB6FF, 11);
            create_text(detail, 6, 61, to_compact(record.meta.created_at, 22).c_str(), 0x9E9E9E, 10);
            create_text(detail, 6, 75, "OK: upload / edit / rename / delete", 0xF7A600, 10);
            create_text(detail, 6, 88, record.meta.mock ? "[mock]" : "[JSON]", 0x555555, 10);
        }

        create_footer(parent, ui_message_);
    }

    void render_emulator_tab(lv_obj_t *parent)
    {
        const auto connection = service_.connection_state();
        cache_serial_device_kind(connection);
        const auto endpoint = active_endpoint_for_ui(connection);
        const auto emu_device_kind = effective_emu_device_kind(connection);
        const auto protocol = service_.current_emulator_protocol();

        lv_obj_t *left  = create_panel(parent, 0, 0, 80, 104, 0x101010);
        lv_obj_t *right = create_panel(parent, 84, 0, 236, 104, 0x101010);

        if (emu_device_kind == nfc_app::DeviceKind::PN532Killer) {
            // ── HW EMU mode: show PN532Killer hardware slot ──────────────────
            const std::string proto_name =
                (protocol == nfc_app::ProtocolKind::MifareClassic) ? "MFC" :
                (protocol == nfc_app::ProtocolKind::Iso15693)      ? "ISO15693" : "NTAG";

            // Left: slot carousel + probe status
            create_text(left, 6, 4, proto_name.c_str(), 0x00D2FF, 11);
            const std::string slot_str = "HW Slot " + std::to_string(hw_emu_slot_ + 1) + "/8";
            create_text(left, 6, 18, slot_str.c_str(), 0xFFFFFF, 12);

            const auto info = service_.emu_slot_info(protocol, hw_emu_slot_);
            if (service_.emu_probe_running()) {
                create_text(left, 6, 38, "probing...", 0xF7A600, 10);
            } else if (info.probed) {
                if (!info.uid.empty())
                    create_text(left, 6, 38, to_compact(info.uid, 16).c_str(), 0x00FF88, 10);
                else {
                    const std::string err = service_.emu_probe_error();
                    create_text(left, 6, 38, err.empty() ? "(no UID)" : to_compact(err, 16).c_str(), 0xFF8888, 10);
                }
            }
            create_text(left, 6, 56, "Tab:proto", 0xD8D8D8, 10);
            create_text(left, 6, 68, "F/X:slot", 0xD8D8D8, 10);
            create_text(left, 6, 80, "OK:menu", 0xF7A600, 10);

            // Right: dump lines if downloaded, otherwise block0 hex
            static constexpr int DUMP_ROWS = 7;
            static constexpr int ROW_H     = 13;
            const bool showing_dump = info.dump_loaded && !info.dump_lines.empty();
            if (service_.hw_upload_running()) {
                const int prog = service_.hw_upload_progress();
                char prog_buf[32];
                snprintf(prog_buf, sizeof(prog_buf), "Uploading %d/64", prog);
                create_text(right, 6, 6,  "Upload:", 0xF7A600, 10);
                create_text(right, 6, 22, prog_buf, 0xFFFFFF, 11);
                // Simple progress bar (width 0-160 proportional to 0-64)
                lv_obj_t *bar_bg = lv_obj_create(right);
                lv_obj_set_pos(bar_bg, 6, 42);
                lv_obj_set_size(bar_bg, 162, 10);
                lv_obj_set_style_bg_color(bar_bg, lv_color_hex(0x333333), 0);
                lv_obj_set_style_border_width(bar_bg, 0, 0);
                lv_obj_set_style_radius(bar_bg, 3, 0);
                lv_obj_set_style_pad_all(bar_bg, 0, 0);
                const int fill_w = prog * 162 / 64;
                if (fill_w > 0) {
                    lv_obj_t *bar_fill = lv_obj_create(bar_bg);
                    lv_obj_set_pos(bar_fill, 0, 0);
                    lv_obj_set_size(bar_fill, fill_w, 10);
                    lv_obj_set_style_bg_color(bar_fill, lv_color_hex(0x00D2FF), 0);
                    lv_obj_set_style_border_width(bar_fill, 0, 0);
                    lv_obj_set_style_radius(bar_fill, 3, 0);
                    lv_obj_set_style_pad_all(bar_fill, 0, 0);
                }
            } else if (service_.emu_dump_running()) {
                create_text(right, 6, 6,  "Dump:", 0x8E8E8E, 10);
                create_text(right, 6, 22, "(downloading...)", 0xF7A600, 10);
            } else if (showing_dump) {
                const int total = static_cast<int>(info.dump_lines.size());
                const int scroll = std::max(0, std::min(emu_dump_scroll_,
                                             std::max(0, total - DUMP_ROWS)));
                char hdr[24];
                snprintf(hdr, sizeof(hdr), "Blk %d-%d/%d",
                         scroll, std::min(scroll + DUMP_ROWS - 1, total - 1), total);
                create_text(right, 6, 2, hdr, 0x00D2FF, 10);
                for (int r = 0; r < DUMP_ROWS && (scroll + r) < total; ++r)
                    create_text(right, 6, 14 + r * ROW_H,
                                info.dump_lines[scroll + r].c_str(), 0xD8D8D8, 10);
                if (total > DUMP_ROWS)
                    create_text(right, 6, 96, "U/D scroll", 0x555555, 10);
            } else if (service_.emu_probe_running()) {
                create_text(right, 6, 6,  "Block 0:", 0x8E8E8E, 10);
                create_text(right, 6, 22, "(probing...)", 0xF7A600, 10);
            } else if (info.probed && !info.block0_hex.empty()) {
                // Show block 0 in "00: HEXHEX..." format
                const auto &h = info.block0_hex;  // hex string of block0 bytes
                const size_t byte_count = h.size() / 2;
                // 8 bytes per display row (16 hex chars)
                auto row_fmt = [&](int byte_off) -> std::string {
                    std::string s;
                    for (size_t i = 0; i < 8 && (byte_off + (int)i) < (int)byte_count; ++i)
                        s += h.substr(static_cast<size_t>((byte_off + (int)i) * 2), 2);
                    return s;
                };
                create_text(right, 6, 4,  "00: ", 0x8E8E8E, 10);
                create_text(right, 32, 4, row_fmt(0).c_str(), 0xD8D8D8, 10);
                if (byte_count > 8) {
                    create_text(right, 6, 18, "   ", 0x8E8E8E, 10);
                    create_text(right, 32, 18, row_fmt(8).c_str(), 0xD8D8D8, 10);
                }
                create_text(right, 6, 36, "OK>Download for full", 0x444444, 10);
            } else {
                create_text(right, 6, 4,  "Block 0:", 0x8E8E8E, 10);
                create_text(right, 6, 20, "(no data)", 0x555555, 10);
                create_text(right, 6, 36, "F/X to probe slot", 0x444444, 10);
            }
        } else if (emu_device_kind == nfc_app::DeviceKind::PN532) {
            // ── PN532 NDEF target emulation ───────────────────────────────────
            const auto ndef = service_.pn532_ndef_state();
            create_text(left, 6, 4,  "NDEF EMU", 0x00D2FF, 12);
            create_text(left, 6, 22, ndef.running ? "Running" : "Stopped",
                        ndef.running ? 0x00FF88 : 0x9E9E9E, 11);
            create_text(left, 6, 40, "S:start P:stop", 0xF7A600, 10);
            create_text(left, 6, 54, "OK:edit URI", 0x9E9E9E, 10);

            create_text(right, 6, 4,  "PN532 Type4 NDEF", 0x8E8E8E, 11);
            create_text(right, 6, 20, to_compact(pn532_ndef_uri_, 30).c_str(), 0x00D2FF, 10);
            create_text(right, 6, 34, to_compact(std::string("Status: ") + ndef.status, 30).c_str(), 0xD8D8D8, 10);
            if (!ndef.error.empty()) {
                create_text(right, 6, 50, to_compact(std::string("ERR: ") + ndef.error, 44).c_str(), 0xFF8888, 10);
            }
            create_text(right, 6, 76, "Quick key: S/P, OK edits URI", 0x555555, 10);
        } else if (emu_device_kind == nfc_app::DeviceKind::GroveNFC ||
               emu_device_kind == nfc_app::DeviceKind::NFCUnit ||
               emu_device_kind == nfc_app::DeviceKind::ST25RNFC ||
                   endpoint.kind == nfc_app::TransportKind::I2cBus ||
                   (endpoint.kind == nfc_app::TransportKind::SpiBus && connection.connected)) {
            // ── I2C EMU mode (GroveNFC / NFC Unit), 8 slots ───────────────────
            const std::string proto_name =
                (protocol == nfc_app::ProtocolKind::MifareClassic) ? "MFC-1K" :
                (protocol == nfc_app::ProtocolKind::Iso14443B)     ? "ISO14B"  :
                (protocol == nfc_app::ProtocolKind::Iso15693)      ? "ISO15693" :
                                                                                 "NTAG";
            const bool is_st25r =
                (emu_device_kind == nfc_app::DeviceKind::ST25RNFC) ||
                (endpoint.kind == nfc_app::TransportKind::SpiBus && connection.connected);
            const bool is_nfc_unit =
                !is_st25r && ((emu_device_kind == nfc_app::DeviceKind::NFCUnit) ||
                (endpoint.kind == nfc_app::TransportKind::I2cBus &&
                 (emu_device_kind == nfc_app::DeviceKind::Unknown ||
                  emu_device_kind == nfc_app::DeviceKind::NotConnected)));
            const bool is_grove_or_nfcunit =
                !is_st25r && (emu_device_kind == nfc_app::DeviceKind::GroveNFC || is_nfc_unit);
            create_text(left, 6, 4,  is_st25r ? "SPI EMU" : "SW EMU", is_st25r ? 0x00B4FF : 0x00FF88, 12);
            if (is_st25r) {
                create_text(left, 6, 18, "Profile mode", 0xFFFFFF, 12);
            } else {
                create_text(left, 6, 18, proto_name.c_str(), 0xFFFFFF, 12);
            }
            create_text(left, 6, 38, is_st25r ? "Tab:profile" : "Tab:proto", 0xD8D8D8, 10);
            if (is_st25r) {
                create_text(left, 6, 50, "OK:start", 0xF7A600, 10);
            } else {
                create_text(left, 6, 50, "F/X:scroll", 0xD8D8D8, 10);
                create_text(left, 6, 62, "OK:menu", 0xF7A600, 10);
            }
            create_text(left, 6, 80, is_st25r ? "M5 NFC CAP SPI" : (is_nfc_unit ? "NFC Unit I2C" : "GroveNFC I2C"), is_st25r ? 0x00B4FF : 0x00FF88, 10);

            if (is_st25r) {
                create_text(right, 6, 4, service_.spi_profile_label().c_str(), 0x00D2FF, 12);
                const int spi_profile = service_.spi_profile_index();
                const bool running = service_.spi_listener_active();
                create_text(right, 6, 20, "S:start P:stop OK:menu", 0xD8D8D8, 10);
                create_text(right, 6, 34, running ? "Status: RUNNING" : "Status: READY", running ? 0x00FF88 : 0x9E9E9E, 10);
                if (spi_profile == 0) {
                    create_text(right, 6, 52, "UID:11223344 ATQA:0004", 0x9E9E9E, 10);
                    create_text(right, 6, 66, "SAK:08 (MFC profile)", 0x9E9E9E, 10);
                } else if (spi_profile == 1) {
                    create_text(right, 6, 52, "UID:04512233445566", 0x9E9E9E, 10);
                    create_text(right, 6, 66, "ATQA:0044 SAK:00", 0x9E9E9E, 10);
                } else {
                    create_text(right, 6, 52, "UID:0452A1B2C3D4E5", 0x9E9E9E, 10);
                    create_text(right, 6, 66, "ATQA:0044 SAK:00", 0x9E9E9E, 10);
                }
            } else if (is_grove_or_nfcunit) {
                // Show card info + dump blocks — all content scrolls as one block
                auto dump_lines = service_.i2c_emulator_dump_lines(protocol);

                struct ContentLine { std::string text; uint32_t color; bool mono; };
                std::vector<ContentLine> lines;

                // Title line
                lines.push_back({proto_name, 0x00D2FF, true});

                // Read UID from the cache (populated from JSON card.uid by i2c_emulator_dump_lines)
                const auto slot_info = service_.emu_slot_info(protocol, 0);
                std::string uid_str = slot_info.uid;
                if (uid_str.empty()) uid_str = "-";
                // Auto-detect SAK/ATQA from MFC protocol
                std::string sak_str, atqa_str;
                const bool is_mfc = (protocol == nfc_app::ProtocolKind::MifareClassic);
                if (is_mfc) {
                    sak_str = "SAK:08";
                    atqa_str = "ATQA:0004";
                }

                lines.push_back({std::string("UID:") + uid_str, 0x00D2FF, true});
                if (!sak_str.empty()) lines.push_back({sak_str, 0xD8D8D8, true});
                if (!atqa_str.empty()) lines.push_back({atqa_str, 0xD8D8D8, true});

                // Dump header
                lines.push_back({"Dump:", 0x9E9E9E, true});

                if (dump_lines.empty()) {
                    lines.push_back({"(no dump loaded)", 0x666666, true});
                } else {
                    for (int i = 0; i < (int)dump_lines.size(); ++i) {
                        // No word-wrap: each raw dump line = one display line.
                        // Apply the same coloring as READ tab dump (render_dump_line_colored).
                        const std::string &raw = dump_lines[i];
                        std::string text_to_show = raw;
                        uint32_t color = 0xD8D8D8;

                        size_t colon = raw.find(':');
                        bool looks_hex = (colon != std::string::npos && colon > 0);
                        if (looks_hex) {
                            for (size_t ci = 0; ci < colon; ++ci) {
                                if (!std::isdigit((unsigned char)raw[ci])) { looks_hex = false; break; }
                            }
                        }
                        int block_num = looks_hex ? std::stoi(raw.substr(0, colon)) : i;
                        std::string hex = looks_hex ? raw.substr(colon + 1) : raw;

                        if (is_mfc) {
                            bool is_trailer = (block_num % 4 == 3);
                            bool is_block0  = (block_num == 0);
                            if (hex.size() >= 32 && looks_hex) {
                                // Full per-byte coloring (same as render_dump_line_colored)
                                // We'll store a simple 2-char prefix + mark for special rendering below.
                                if (is_trailer) {
                                    // Trailer: KeyA(0-11) green/orange, ACS(12-19) orange, KeyB(20-31) green/orange
                                    lines.push_back({raw, 0x44CC88, true});  // placeholder, real coloring below
                                    // We push individual segments instead for MFC trailers
                                } else if (is_block0) {
                                    // Block0 needs UID/BCC/SAK/ATQA coloring
                                    lines.push_back({raw, 0x44BBFF, true});  // placeholder, real coloring below
                                } else {
                                    lines.push_back({raw, 0xC0C0C0, true});
                                }
                            } else {
                                if (is_trailer) color = 0x44CC88;
                                else if (is_block0) color = 0x44BBFF;
                                else color = 0xC0C0C0;
                                lines.push_back({raw, color, true});
                            }
                        } else {
                            // NTAG / ISO15693: show blocks, append ASCII column
                            std::string ascii_part;
                            std::string pure;
                            for (char c : hex) if (std::isxdigit((unsigned char)c)) pure += (char)std::toupper((unsigned char)c);
                            if (pure.size() >= 2) {
                                ascii_part = " |";
                                for (size_t bi = 0; bi + 1 < pure.size(); bi += 2) {
                                    unsigned long v = std::strtoul(pure.substr(bi, 2).c_str(), nullptr, 16);
                                    char ch = static_cast<char>(v & 0xFF);
                                    ascii_part += (ch >= 32 && ch <= 126) ? ch : '.';
                                }
                            }
                            std::string display = raw + ascii_part;
                            lines.push_back({display, 0xC0C0C0, true});
                        }
                    }
                }

                // Scroll & render — now with per-byte MFC coloring
                static constexpr int ROW_H = 9;
                static constexpr int PANEL_H = 104;
                const int MAX_VISIBLE = (PANEL_H - 4) / ROW_H;
                int total = (int)lines.size();
                int max_scroll = std::max(0, total - MAX_VISIBLE);
                int scroll = std::max(0, std::min(emu_dump_scroll_, max_scroll));

                const int uid_hex_digits = (int)uid_str.size();
                const int uid_len = uid_hex_digits / 2;

                for (int i = 0; i < MAX_VISIBLE && (scroll + i) < total; ++i) {
                    const auto &l = lines[scroll + i];
                    int y = 2 + i * ROW_H;

                    if (l.color == 0x44CC88 || l.color == 0x44BBFF) {
                        // MFC trailer or block0 — render with per-byte colors
                        render_dump_line_colored(right, 4, y, l.text, uid_len);
                    } else {
                        create_text_mono(right, 4, y, l.text.c_str(), l.color, 7);
                    }
                }
            } else {
                create_text(right, 6, 20, "OK menu: Dn/Up/Save", 0xD8D8D8, 10);
                create_text(right, 6, 34, "activate selected slot", 0xD8D8D8, 10);
                create_text(right, 6, 52, "Protocols:", 0x9E9E9E, 10);
                create_text(right, 6, 64, "MFC/NTAG/ISO14B", 0x9E9E9E, 10);
                create_text(right, 6, 76, "ISO15693", 0x9E9E9E, 10);
            }
        } else {
            // ── No device / unknown ───────────────────────────────────────────
            create_text(left, 6, 4,  "EMU", 0x888888, 12);
            create_text(left, 6, 22, "No device", 0xAAAAAA, 11);
            create_text(left, 6, 40, "Connect a device", 0x9E9E9E, 10);

            create_text(right, 6, 4,  "Hardware EMU:", 0x8E8E8E, 11);
            create_text(right, 6, 18, "PN532Killer", 0xFFD700, 11);
            create_text(right, 6, 30, "I2C mode for SW EMU", 0x00FF88, 11);
            create_text(right, 6, 44, "Use Read tab Tab-key", 0x9E9E9E, 10);
            create_text(right, 6, 66, (std::string("Mode: ") + nfc_app::to_string(endpoint.kind)).c_str(), 0x555555, 10);
            create_text(right, 6, 80, (std::string("Status: ") + nfc_app::to_string(emu_device_kind)).c_str(), 0x555555, 10);
        }

        std::string footer_text = ui_message_;
        if (emu_device_kind == nfc_app::DeviceKind::GroveNFC ||
            emu_device_kind == nfc_app::DeviceKind::NFCUnit) {
            footer_text = "Load from " + emulator_source_filename(protocol);
        }
        create_footer(parent, footer_text);
    }

    void render_emulator_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 170, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        const auto conn = service_.connection_state();
        cache_serial_device_kind(conn);
        const auto endpoint = active_endpoint_for_ui(conn);
        const auto emu_device_kind = effective_emu_device_kind(conn);
        const bool pn532_ndef_menu = (emu_device_kind == nfc_app::DeviceKind::PN532);
        const bool st25r_mode =
            (emu_device_kind == nfc_app::DeviceKind::ST25RNFC) ||
            (endpoint.kind == nfc_app::TransportKind::SpiBus && conn.connected);
        const bool grove_mode = (emu_device_kind == nfc_app::DeviceKind::GroveNFC);
        const bool nfc_unit_mode = !st25r_mode && !grove_mode &&
                                   (emu_device_kind == nfc_app::DeviceKind::NFCUnit ||
                                    endpoint.kind == nfc_app::TransportKind::I2cBus);
        const bool i2c_emu_mode = !st25r_mode && (grove_mode || nfc_unit_mode);
        const bool i2c_url_mode = i2c_emu_mode &&
            service_.current_emulator_protocol() == nfc_app::ProtocolKind::Iso14443A;
        const bool pn532k_mode = !st25r_mode && !i2c_emu_mode && !pn532_ndef_menu;
        const int emu_slot = (i2c_emu_mode || st25r_mode) ? 0 : hw_emu_slot_;
        const bool dump_ready = service_.emu_dump_loaded(service_.current_emulator_protocol(), emu_slot);
        // PN532Killer: Download Data, Upload Data, Reset Data
        // I2C emu (GroveNFC/NFCUnit): only Set URL (for NTAG) + Reset Data (no Download/Upload)
        const int n_opts = pn532_ndef_menu ? 1 :
                          (st25r_mode ? 4 :
                          (pn532k_mode ? 3 :
                          (i2c_url_mode ? 2 : 1)));  // i2c_emu_mode: 1=Reset, 2=URL+Reset
        const int visible_opts = std::min(n_opts, 4);
        int first_opt = 0;
        if (n_opts > visible_opts) {
            first_opt = std::max(0, std::min(modal_idx_ - visible_opts + 1, n_opts - visible_opts));
        }
        const lv_coord_t card_h = static_cast<lv_coord_t>(28 + visible_opts * 20);
        lv_obj_t *card = make_modal_card(overlay, 220, card_h, 0xF7A600);
        if (pn532_ndef_menu) {
            create_text(card, 8, 5, "PN532 NDEF", 0xFFFFFF, 12);
        } else {
            if (st25r_mode) {
                create_text(card, 8, 5, (service_.spi_profile_label() + " SPI").c_str(), 0xFFFFFF, 12);
            } else if (i2c_emu_mode) {
                const std::string dev_name = nfc_unit_mode ? "NFC Unit " : "GroveNFC ";
                create_text(card, 8, 5, (dev_name + nfc_app::to_string(service_.current_emulator_protocol())).c_str(), 0xFFFFFF, 12);
            } else {
                const auto slot = service_.selected_slot_index();
                create_text(card, 8, 5, (std::string(nfc_app::to_string(service_.current_emulator_protocol())) + " Slot " + std::to_string(slot)).c_str(), 0xFFFFFF, 12);
            }
        }
        // PN532Killer menu (default)
        const char *options[] = {"Download Data", "Upload Data", "Reset Data"};  // Save via Ctrl+S
        const char *st25r_opts[] = {
            service_.spi_listener_active() ? "Stop Emulation" : "Start Emulating",
            "Download Data",
            "Upload Data",
            "Cancel"
        };
        // I2C EMU (GroveNFC/NFCUnit): NTAG shows Set URL + Reset; others show just Reset
        const char *i2c_url_opts[] = {"Set URL", "Reset Data"};
        const char *i2c_reset_only[] = {"Reset Data"};
        const char *pn532_opts[] = {"Edit URI"};
        for (int row_idx = 0; row_idx < visible_opts; ++row_idx) {
            const int i = first_opt + row_idx;
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 22 + row_idx * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x2A2A2A), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            const char *label = nullptr;
            if (pn532_ndef_menu) label = pn532_opts[i];
            else if (st25r_mode) label = st25r_opts[i];
            else if (pn532k_mode) label = options[i];
            else if (i2c_url_mode) label = i2c_url_opts[i];
            else label = i2c_reset_only[i];
            create_text(row, 6, 4, label, sel ? 0x000000 : 0xD0D0D0, 11);
        }
    }

    void render_pn532_ndef_input_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 170, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        static const char *PFXS[] = {"https://", "http://", "tel:", "mailto:", ""};

        lv_obj_t *card = make_modal_card(overlay, 280, 86, 0x00D2FF);
        create_text(card, 8, 4, uri_edit_for_nfcunit_ ? "Set NTAG213 URL" : "Edit URI", 0x00D2FF, 12);

        // Type indicator: current prefix shown in yellow; Tab to cycle
        const char *pfx = PFXS[pn532_ndef_type_idx_];
        create_text(card, 8, 20,
                    pfx[0] ? pfx : "(custom)",
                    pfx[0] ? 0xF7A600 : 0x888888, 10);
        create_text(card, 170, 20, "[Tab:type]", 0x555555, 9);

        // Body input – tail-compact so cursor stays visible when text is long
        create_text(card, 8, 36,
                    to_tail_compact(pn532_ndef_body_ + "_", 36).c_str(),
                    0xFFFFFF, 11);

        // Hints
        create_text(card, 8, 56, "Bsp:del  Enter:save", 0x555555, 9);
        create_text(card, 8, 70, "Tab:type  ESC:cancel", 0x7A7A7A, 9);
    }

    void handle_pn532_ndef_input_key(uint32_t key)
    {
        static const char *PFXS[] = {"https://", "http://", "tel:", "mailto:", ""};

        if (key == KEY_ESC) {
            uri_edit_for_nfcunit_ = false;
            uri_edit_for_grove_ = false;
            modal_ = Modal::None;
            return;
        }
        if (key == KEY_TAB) {
            pn532_ndef_type_idx_ = (pn532_ndef_type_idx_ + 1) % 5;
            return;
        }
        if (key == KEY_BACKSPACE) {
            if (!pn532_ndef_body_.empty()) pn532_ndef_body_.pop_back();
            return;
        }
        if (key == KEY_ENTER || key == KEY_KPENTER) {
            pn532_ndef_uri_ = std::string(PFXS[pn532_ndef_type_idx_]) + pn532_ndef_body_;
            if (uri_edit_for_nfcunit_) {
                service_.set_nfcunit_ndef_uri(pn532_ndef_uri_);
                ui_message_ = "NTAG213 URL updated";
                uri_edit_for_nfcunit_ = false;
            } else if (uri_edit_for_grove_) {
                if (service_.set_grove_ntag_ndef_uri(pn532_ndef_uri_)) {
                    ui_message_ = "GroveNFC NTAG URL updated";
                } else {
                    ui_message_ = "Set URL failed (save error)";
                }
                uri_edit_for_grove_ = false;
            }
            modal_ = Modal::None;
            return;
        }
        // Character input: prefer Unicode codepoint captured by event_handler
        // (reflects keyboard layout and shift state); fall back to keycode map.
        uint32_t cp = last_key_codepoint_;
        if (cp == 0) {
            const char c = keycode_to_char(key);
            cp = c ? static_cast<uint32_t>(static_cast<unsigned char>(c)) : 0;
        }
        if (cp >= 32 && cp <= 126 && pn532_ndef_body_.size() < 88) {
            pn532_ndef_body_ += static_cast<char>(cp);
        }
    }

    void render_tools_tab(lv_obj_t *parent)
    {
        const bool tool_page_active = (modal_ == Modal::ToolPage);
        const bool modal_full_width = tool_page_active ||
                                      modal_ == Modal::DeviceProbe ||
                                      modal_ == Modal::UartConfig;
        const int panel_h = std::max(80, static_cast<int>(lv_obj_get_height(parent)) - 14);

        lv_obj_t *detail = nullptr;
        if (modal_full_width) {
            if (tool_page_active) {
                // Box + arrow indicator: box with "<" spanning full height
                const int sh = panel_h;
                lv_obj_t *strip = create_panel(parent, 0, 0, 10, sh, 0x1E2D4A);
                create_text(strip, 2, sh / 2 - 5, "<", 0xAAC4FF, 10);
                detail = create_panel(parent, 10, 0, 310, sh, 0x101010);
            } else {
                detail = create_panel(parent, 0, 0, 320, panel_h, 0x101010);
            }
        } else {
            lv_obj_t *list = create_panel(parent, 0, 0, 130, panel_h, 0x101010);
            // Box + arrow on the right edge of the list, spanning full height
            lv_obj_t *arrow = create_panel(parent, 130, 0, 10, panel_h, 0x1E2D4A);
            create_text(arrow, 2, panel_h / 2 - 5, ">", 0xAAC4FF, 10);
            detail = create_panel(parent, 140, 0, 180, panel_h, 0x101010);

            for (int i = 0; i < 4; ++i) {
                const bool selected = (modal_ == Modal::None) ? (tools_idx_ == i) : (active_tool_idx_ == i);
                lv_obj_t *row = lv_obj_create(list);
                lv_obj_remove_style_all(row);
                lv_obj_set_size(row, 132, 18);
                lv_obj_set_pos(row, 4, 6 + i * 19);
                lv_obj_set_style_bg_color(row, lv_color_hex(selected ? 0xF7A600 : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
                create_text(row, 4, 3, to_compact(tool_name(i), 16).c_str(), selected ? 0x000000 : 0xFFFFFF, 11);
            }
        }

        if (modal_ == Modal::ToolPage || modal_ == Modal::DeviceProbe || modal_ == Modal::UartConfig) {
            render_tools_modal(detail);
        } else if (modal_ == Modal::ToolInfo) {
            render_tool_info_modal(parent);
        } else {
            create_text(detail, 6, 6, tool_name(tools_idx_), 0xFFFFFF, 12);
            switch (tools_idx_) {
            case 0:
                create_text(detail, 6, 24, "Manage saved key dict", 0xD8D8D8, 11);
                create_text(detail, 6, 37, "Add / edit / disable keys", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "OK to open manager", 0x8DB6FF, 11);
                break;
            case 1:
                create_text(detail, 6, 22, "Magic MIFARE Classic Card", 0xD8D8D8, 10);
                create_text(detail, 6, 34, "Gen1A  Chinese Magic Card", 0x9E9E9E, 10);
                create_text(detail, 6, 48, "Gen2   CUID", 0x9E9E9E, 10);
                create_text(detail, 6, 60, "Gen3   APDU", 0x9E9E9E, 10);
                create_text(detail, 6, 72, "Gen3   Ultimate Magic Card", 0x9E9E9E, 10);
                break;
            case 2:
                create_text(detail, 6, 22, "MIFARE Classic Sniff", 0xD8D8D8, 11);
                create_text(detail, 6, 35, "without tag present", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "PN532Killer / NFC Unit", 0x8DB6FF, 11);
                break;
            case 3:
                create_text(detail, 6, 22, "MIFARE Classic Sniff", 0xD8D8D8, 11);
                create_text(detail, 6, 35, "with tag present", 0xD8D8D8, 11);
                create_text(detail, 6, 50, "PN532Killer required", 0x8DB6FF, 11);
                break;
            default: break;
            }
        }

        create_footer(parent, ui_message_);
    }

    // ── Post-scan action menu (OK after a scan result) ───────────────────────
    void render_post_scan_modal(lv_obj_t *parent)
    {
        const auto &tag = service_.scan_state().last_record.tag;
        lv_obj_t *card = make_modal_card(parent, 180, 86, 0xF7A600);
        const std::string title = tag.uid.empty() ? "Tag Scanned" : to_compact(tag.uid, 20);
        create_text(card, 8, 6, title.c_str(), 0xFFFFFF, 12);
        const char *options[] = {"Read Again", "Save Tag", "Clear Log"};
        for (int i = 0; i < 3; ++i) {
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 164, 18);
            lv_obj_set_pos(row, 8, 24 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x2A2A2A), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 4, options[i], sel ? 0x000000 : 0xD0D0D0, 11);
        }
    }

    void handle_post_scan_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:   modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN:
        case KEY_X:   modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER: {
            const int action = modal_idx_;
            modal_     = Modal::None;
            modal_idx_ = 0;
            if (action == 0) {
                // Read Again: clear result and scan
                service_.connect_and_scan(&ui_message_);
            } else if (action == 1) {
                // Save Tag
                std::string error;
                if (service_.save_last_scan(&error)) {
                    refresh_saved_records();
                    show_toast("Saved");
                    ui_message_ = "Record saved to JSON";
                } else {
                    ui_message_ = error;
                }
            } else {
                // Clear result + log
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                std::string clear_error;
                if (service_.clear_last_scan_result(&clear_error)) {
                    const auto conn = service_.connection_state();
                    if (conn.connected) {
                        ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn.device_kind);
                    } else {
                        ui_message_ = "Cleared";
                    }
                } else {
                    ui_message_ = clear_error.empty() ? "Clear failed" : clear_error;
                }
            }
            break;
        }
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    // ── ReadMenu modal (device-aware menu) ───────────────────────────────────
    void render_read_menu_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        const auto actions = read_menu_actions();
        const int n_opts = static_cast<int>(actions.size());
        const auto ep = service_.current_endpoint();

        std::string dump_error;
        const bool can_dump = service_.can_dump_last_scan(&dump_error);
        std::string save_error;
        const bool can_save = service_.can_save_last_dump(&save_error);
        const bool uhf_cont_running = service_.uhf_continuous_scan_running();
        const int card_h = 34 + n_opts * 20;

        lv_obj_t *card = make_modal_card(overlay, 220, card_h, 0x00D2FF);
        const char *title = (ep.kind == nfc_app::TransportKind::UsbSerial) ? "USB Actions" :
                            (ep.kind == nfc_app::TransportKind::I2cBus)   ? "I2C Actions" :
                                                                            "UART Actions";
        create_text(card, 8, 5, title, 0x00D2FF, 12);
        for (int i = 0; i < n_opts; ++i) {
            const bool sel = (modal_idx_ == i);
            const auto action = actions[i];
            const bool enabled =
                (action == ReadMenuAction::Dump) ? can_dump :
                (action == ReadMenuAction::Save) ? can_save :
                (action == ReadMenuAction::StartUHFContinuous) ? !uhf_cont_running :
                (action == ReadMenuAction::StopUHFContinuous) ? uhf_cont_running : true;
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 22 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            const uint32_t text_color = sel ? 0x000000 : (enabled ? 0xD0D0D0 : 0x666666);
            create_text(row, 6, 3, read_menu_action_label(action), text_color, 11);
        }

    }

    void handle_read_menu_key(uint32_t key)
    {
        const auto actions = read_menu_actions();
        const int n_opts = std::max(1, static_cast<int>(actions.size()));
        const auto ep = service_.current_endpoint();
        switch (key) {
        case KEY_UP:
        case KEY_F:   modal_idx_ = (modal_idx_ - 1 + n_opts) % n_opts; break;
        case KEY_DOWN:
        case KEY_X:   modal_idx_ = (modal_idx_ + 1) % n_opts; break;
        case KEY_ENTER:
            if (modal_idx_ < 0 || modal_idx_ >= n_opts) {
                modal_idx_ = 0;
                break;
            }
            switch (actions[modal_idx_]) {
            case ReadMenuAction::ConnectDevice: {
                modal_ = Modal::None;
                modal_idx_ = 0;
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                uhf_table_rows_.clear();
                uhf_table_scroll_offset_ = 0;

                if (ep.kind == nfc_app::TransportKind::UsbSerial) {
                    service_.refresh_endpoints();
                    usb_select_list_ = service_.usb_endpoints();
                    if (usb_select_list_.empty()) {
                        ui_message_ = "No USB device";
                        break;
                    }
                    usb_select_idx_ = 0;
                    modal_ = Modal::UsbSelect;
                    modal_idx_ = 0;
                    break;
                }

                if (ep.kind == nfc_app::TransportKind::I2cBus) {
                    scan_log_lines_.push_back("> Scanning I2C buses...");
                    i2c_select_list_ = service_.scan_i2c_devices();
                    if (i2c_select_list_.empty()) {
                        scan_log_lines_.push_back("No I2C device found");
                        ui_message_ = "No I2C device";
                        break;
                    }
                    if (i2c_select_list_.size() > 1) {
                        i2c_select_idx_ = 0;
                        modal_ = Modal::I2cSelect;
                        modal_idx_ = 0;
                        break;
                    }
                    service_.select_i2c_endpoint(i2c_select_list_[0]);
                }

                if (ep.kind == nfc_app::TransportKind::SpiBus) {
                    scan_log_lines_.push_back("> Scanning SPI devices...");
                    spi_select_list_ = service_.enumerate_spi_devices();
                    if (spi_select_list_.empty()) {
                        scan_log_lines_.push_back("No SPI device found");
                        ui_message_ = "No SPI device";
                        break;
                    }
                    if (spi_select_list_.size() > 1) {
                        spi_select_idx_ = 0;
                        modal_ = Modal::SpiSelect;
                        modal_idx_ = 0;
                        break;
                    }
                    service_.select_spi_endpoint(spi_select_list_[0]);
                }

                const auto conn0 = service_.connection_state();
                if (conn0.connected) service_.disconnect();
                const auto connect_ep = service_.current_endpoint();
                scan_log_lines_.push_back("> Connect " + connect_ep.label.substr(0, 22) + "...");
                const bool ok = service_.connect_current();
                const auto conn2 = service_.connection_state();
                if (!ok) {
                    scan_log_lines_.push_back("ERR " + compact_read_connection_detail(conn2));
                    ui_message_ = "Connect failed";
                    break;
                }
                scan_log_lines_.push_back("OK  " + compact_read_connection_detail(conn2));
                scan_log_lines_.push_back(supported_protocols_text());
                ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn2.device_kind);
                modal_ = Modal::None;
                modal_idx_ = 0;
                break;
            }
            case ReadMenuAction::PortSettings:
                if (ep.kind == nfc_app::TransportKind::UartSerial) {
                    uart_edit_buf_ = service_.uart_config();
                    port_settings_field_ = 0;
                    edit_buf_.clear();
                    uart_test_result_.clear();
                    modal_ = Modal::PortSettings;
                    modal_idx_ = 0;
                } else if (ep.kind == nfc_app::TransportKind::I2cBus) {
                    scan_log_lines_.push_back("> Scanning I2C buses...");
                    i2c_select_list_ = service_.scan_i2c_devices();
                    if (i2c_select_list_.empty()) {
                        ui_message_ = "No I2C device";
                    } else {
                        i2c_select_idx_ = 0;
                        modal_ = Modal::I2cSelect;
                        modal_idx_ = 0;
                    }
                }
                break;
            case ReadMenuAction::Scan: {
                // Scan
                modal_ = Modal::None;
                modal_idx_ = 0;
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;

                const auto conn = service_.connection_state();
                if (!conn.connected) {
                    if (ep.kind == nfc_app::TransportKind::UsbSerial) {
                        service_.refresh_endpoints();
                        usb_select_list_ = service_.usb_endpoints();
                        if (usb_select_list_.empty()) {
                            ui_message_ = "No USB device";
                            break;
                        }
                        usb_select_idx_ = 0;
                        modal_ = Modal::UsbSelect;
                        modal_idx_ = 0;
                        break;
                    }
                    if (ep.kind == nfc_app::TransportKind::I2cBus) {
                        scan_log_lines_.push_back("> Scanning I2C buses...");
                        i2c_select_list_ = service_.scan_i2c_devices();
                        if (i2c_select_list_.empty()) {
                            scan_log_lines_.push_back("No I2C device found");
                            ui_message_ = "No I2C device";
                            break;
                        }
                        if (i2c_select_list_.size() > 1) {
                            i2c_select_idx_ = 0;
                            modal_ = Modal::I2cSelect;
                            modal_idx_ = 0;
                            break;
                        }
                        service_.select_i2c_endpoint(i2c_select_list_[0]);
                    }

                    modal_ = Modal::None;
                    scan_log_lines_.push_back("> Connect " + ep.label.substr(0, 22) + "...");
                    const bool ok = service_.connect_current();
                    const auto conn2 = service_.connection_state();
                    if (!ok) {
                        scan_log_lines_.push_back("ERR " + compact_read_connection_detail(conn2));
                        ui_message_ = "Connect failed";
                        break;
                    }
                    scan_log_lines_.push_back("OK  " + compact_read_connection_detail(conn2));
                    scan_log_lines_.push_back(supported_protocols_text());
                } else {
                    scan_log_lines_.push_back("OK  " + compact_read_connection_detail(conn));
                    scan_log_lines_.push_back(supported_protocols_text());
                }

                scan_log_lines_.push_back("> Scan card...");
                if (service_.start_scan()) {
                    ui_message_ = "Scanning...";
                } else {
                    const auto state = service_.scan_state();
                    ui_message_ = state.error.empty() ? "Scan failed" : state.error;
                }
                break;
            }
            case ReadMenuAction::ScanOnceUHF: {
                modal_ = Modal::None;
                modal_idx_ = 0;
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                scan_log_lines_.push_back("> UHF scan once...");
                std::string error;
                if (service_.start_uhf_scan_once(&error)) {
                    ui_message_ = "UHF scanning...";
                } else {
                    ui_message_ = error.empty() ? "UHF scan failed" : error;
                }
                break;
            }
            case ReadMenuAction::StartUHFContinuous: {
                modal_ = Modal::None;
                modal_idx_ = 0;
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                scan_log_lines_.push_back("> UHF inventory start...");
                std::string error;
                if (service_.start_uhf_continuous_scan(&error)) {
                    ui_message_ = "Inventory running";
                } else {
                    ui_message_ = error.empty() ? "Inventory start failed" : error;
                }
                break;
            }
            case ReadMenuAction::StopUHFContinuous: {
                modal_ = Modal::None;
                modal_idx_ = 0;
                std::string error;
                if (service_.stop_uhf_continuous_scan(&error)) {
                    scan_log_lines_.push_back("> Inventory stopped");
                    ui_message_ = "Inventory stopped";
                } else {
                    ui_message_ = error.empty() ? "Inventory stop failed" : error;
                }
                break;
            }
            case ReadMenuAction::ExportUHFCsv: {
                modal_ = Modal::None;
                modal_idx_ = 0;
                std::string path;
                std::string error;
                if (service_.export_uhf_csv(&path, &error)) {
                    show_toast(std::string("CSV: ") + path);
                    ui_message_ = std::string("CSV: ") + to_compact(path, 40);
                } else {
                    ui_message_ = error.empty() ? "CSV export failed" : error;
                }
                break;
            }
            case ReadMenuAction::Dump: {
                // Dump
                modal_ = Modal::None;
                modal_idx_ = 0;
                std::string dump_error;
                if (!service_.can_dump_last_scan(&dump_error)) {
                    ui_message_ = dump_error;
                    break;
                }
                scan_log_lines_.push_back("> Dump card...");
                if (service_.start_dump_last_scan()) {
                    ui_message_ = "Dumping...";
                } else {
                    const auto state = service_.scan_state();
                    ui_message_ = state.error.empty() ? "Dump failed" : state.error;
                }
                break;
            }
            case ReadMenuAction::Save: {
                // Save
                modal_ = Modal::None;
                modal_idx_ = 0;
                std::string error;
                if (service_.save_last_scan(&error)) {
                    refresh_saved_records();
                    show_toast("Saved");
                    ui_message_ = "Record saved to JSON";
                } else {
                    ui_message_ = error;
                }
                break;
            }
            case ReadMenuAction::Clear: {
                // Clear
                modal_ = Modal::None;
                modal_idx_ = 0;
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                uhf_table_rows_.clear();
                uhf_table_scroll_offset_ = 0;
                std::string clear_error;
                if (service_.clear_last_scan_result(&clear_error)) {
                    const auto conn = service_.connection_state();
                    if (conn.connected) {
                        ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn.device_kind);
                    } else {
                        ui_message_ = "Cleared";
                    }
                } else {
                    ui_message_ = clear_error.empty() ? "Clear failed" : clear_error;
                }
                break;
            }
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    // ── UsbSelect modal (multiple USB ports: choose which to connect) ─────────
    void render_usb_select_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        const int n = static_cast<int>(usb_select_list_.size());
        const int card_h = 28 + std::max(1, n) * 20;
        lv_obj_t *card = make_modal_card(overlay, 200, card_h, 0x00D2FF);
        create_text(card, 8, 5, "Select USB Port", 0x00D2FF, 12);

        for (int i = 0; i < n; ++i) {
            const bool sel = (usb_select_idx_ == i);
            // Strip "USB " prefix from label for compactness
            std::string lbl = usb_select_list_[i].label;
            const std::string pfx = "USB ";
            if (lbl.size() > pfx.size() && lbl.compare(0, pfx.size(), pfx) == 0)
                lbl = lbl.substr(pfx.size());
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 184, 18);
            lv_obj_set_pos(row, 8, 22 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 3, lbl.c_str(), sel ? 0x000000 : 0xD0D0D0, 11);
        }
        if (n == 0) {
            create_text(card, 8, 26, "No USB device found", 0xFF4444, 11);
        }
    }

    void handle_usb_select_key(uint32_t key)
    {
        const int n = static_cast<int>(usb_select_list_.size());
        switch (key) {
        case KEY_UP:
        case KEY_F:
            if (n > 0) usb_select_idx_ = (usb_select_idx_ - 1 + n) % n;
            break;
        case KEY_DOWN:
        case KEY_X:
            if (n > 0) usb_select_idx_ = (usb_select_idx_ + 1) % n;
            break;
        case KEY_ENTER:
            if (n > 0 && usb_select_idx_ < n) {
                modal_ = Modal::None;
                modal_idx_ = 0;
                const auto &selected_ep = usb_select_list_[usb_select_idx_];
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                scan_log_lines_.push_back("> Connect " + selected_ep.label.substr(0, 22) + "...");
                pending_usb_connect_ = true;
                pending_usb_connect_path_ = selected_ep.path;
                ui_message_ = "Detecting device...";
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    void perform_pending_usb_connect()
    {
        if (!pending_usb_connect_) return;
        pending_usb_connect_ = false;

        if (!service_.select_usb_endpoint_by_path(pending_usb_connect_path_)) {
            scan_log_lines_.push_back("ERR Select USB failed");
            ui_message_ = "Select USB failed";
            return;
        }

        const bool ok = service_.connect_current();
        const auto conn2 = service_.connection_state();
        if (!ok) {
            scan_log_lines_.push_back("ERR " + compact_read_connection_detail(conn2));
            ui_message_ = "Connect failed";
            return;
        }

        scan_log_lines_.push_back("OK  " + compact_read_connection_detail(conn2));
        scan_log_lines_.push_back(supported_protocols_text());
        ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn2.device_kind);
    }

    // ── I2cSelect modal (scan I2C buses, choose which device to connect) ──────
    void render_i2c_select_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        const int n = static_cast<int>(i2c_select_list_.size());
        const int card_h = 42 + std::max(1, n) * 20;
        lv_obj_t *card = make_modal_card(overlay, 220, card_h, 0x00FF88);
        create_text(card, 8, 5, "Select I2C Device", 0x00FF88, 12);

        for (int i = 0; i < n; ++i) {
            const bool sel = (i2c_select_idx_ == i);
            const std::string &lbl = i2c_select_list_[i].label;
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 22 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00FF88 : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 3, to_compact(lbl, 24).c_str(), sel ? 0x000000 : 0xD0D0D0, 11);
        }
        if (n == 0) {
            create_text(card, 8, 26, "No I2C device found", 0xFF4444, 11);
        }
    }

    void handle_i2c_select_key(uint32_t key)
    {
        const int n = static_cast<int>(i2c_select_list_.size());
        switch (key) {
        case KEY_UP:
        case KEY_F:
            if (n > 0) i2c_select_idx_ = (i2c_select_idx_ - 1 + n) % n;
            break;
        case KEY_DOWN:
        case KEY_X:
            if (n > 0) i2c_select_idx_ = (i2c_select_idx_ + 1) % n;
            break;
        case KEY_ENTER:
            if (n > 0 && i2c_select_idx_ < n) {
                modal_ = Modal::None;
                modal_idx_ = 0;
                const auto &selected_ep = i2c_select_list_[i2c_select_idx_];
                service_.select_i2c_endpoint(selected_ep);
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                scan_log_lines_.push_back("> Connect " + selected_ep.label.substr(0, 22) + "...");
                render_all();
                const bool ok = service_.connect_current();
                const auto conn2 = service_.connection_state();
                if (!ok) {
                    scan_log_lines_.push_back("ERR " + compact_read_connection_detail(conn2));
                    ui_message_ = "Connect failed";
                } else {
                    scan_log_lines_.push_back("OK  " + compact_read_connection_detail(conn2));
                    scan_log_lines_.push_back(supported_protocols_text());
                    ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn2.device_kind);
                }
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    // ── SpiSelect modal (enumerate SPI devices, choose which to connect) ─────
    void render_spi_select_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        const int n = static_cast<int>(spi_select_list_.size());
        const int card_h = 42 + std::max(1, n) * 20;
        lv_obj_t *card = make_modal_card(overlay, 220, card_h, 0x00B4FF);
        create_text(card, 8, 5, "Select SPI Device", 0x00B4FF, 12);

        for (int i = 0; i < n; ++i) {
            const bool sel = (spi_select_idx_ == i);
            const std::string &lbl = spi_select_list_[i].label;
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 22 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00B4FF : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 3, to_compact(lbl, 24).c_str(), sel ? 0x000000 : 0xD0D0D0, 11);
        }
        if (n == 0) {
            create_text(card, 8, 26, "No SPI device found", 0xFF4444, 11);
        }
    }

    void handle_spi_select_key(uint32_t key)
    {
        const int n = static_cast<int>(spi_select_list_.size());
        switch (key) {
        case KEY_UP:
        case KEY_F:
            if (n > 0) spi_select_idx_ = (spi_select_idx_ - 1 + n) % n;
            break;
        case KEY_DOWN:
        case KEY_X:
            if (n > 0) spi_select_idx_ = (spi_select_idx_ + 1) % n;
            break;
        case KEY_ENTER:
            if (n > 0 && spi_select_idx_ < n) {
                modal_ = Modal::None;
                modal_idx_ = 0;
                const auto &selected_ep = spi_select_list_[spi_select_idx_];
                service_.select_spi_endpoint(selected_ep);
                scan_log_lines_.clear();
                log_scroll_offset_ = 0;
                scan_log_lines_.push_back("> Connect " + selected_ep.label.substr(0, 22) + "...");
                render_all();
                const bool ok = service_.connect_current();
                const auto conn2 = service_.connection_state();
                if (!ok) {
                    scan_log_lines_.push_back("ERR " + compact_read_connection_detail(conn2));
                    ui_message_ = "Connect failed";
                } else {
                    scan_log_lines_.push_back("OK  " + compact_read_connection_detail(conn2));
                    scan_log_lines_.push_back(supported_protocols_text());
                    ui_message_ = std::string("Connected: ") + nfc_app::to_string(conn2.device_kind);
                }
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    // ── PortSettings modal — device path info + Test Connection ─────────────
    void render_port_settings_modal(lv_obj_t *parent)
    {
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 160, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *card = make_modal_card(overlay, 260, 90, 0xF7A600);
        create_text(card, 8, 4, "Port Settings", 0xF7A600, 12);

        // Device path (read-only)
        {
            std::string dev = uart_edit_buf_.device_path;
            if (dev.empty()) {
                auto uart_eps = service_.uart_endpoints();
                dev = uart_eps.empty() ? "(no UART port)" : uart_eps[0].path;
            }
            if (dev.rfind("/dev/", 0) == 0) dev = dev.substr(5);
            create_text(card, 8, 24, (std::string("Dev: ") + dev).c_str(), 0x888888, 10);
        }

        // TX/RX pins — always read-only / fixed on this platform
        create_text(card, 8, 38, "TX/RX: 14/15 (fixed by DT)", 0x888888, 10);

        // Test Connection — always selected on open
        {
            const bool sel = true;
            uint32_t col = 0x00FF88;
            create_text(card, 8, 56, "[ Test Connection ]", col, 12);
        }

        // Test result
        if (!uart_test_result_.empty()) {
            const bool ok = uart_test_result_.rfind("OK:", 0) == 0;
            create_text(card, 8, 74, uart_test_result_.c_str(), ok ? 0x00FF88 : 0xFF6060, 10);
        }
    }

    void handle_port_settings_key(uint32_t key)
    {
        if (key == KEY_ESC) {
            nfc_app::UartConfig cfg = service_.uart_config();
            cfg.baud_rate = 115200;
            service_.set_uart_config(cfg);
            ui_message_ = "Port settings saved";
            modal_ = Modal::ReadMenu;
            modal_idx_ = 0;
            edit_buf_.clear();
            uart_test_result_.clear();
            return;
        }
        if (key == KEY_ENTER) {
            uart_test_result_ = "Testing...";
            service_.start_uart_test();
            return;
        }
    }

    // ── Tool info popup ('i' key) ────────────────────────────────────────────
    void render_tool_info_modal(lv_obj_t *parent)    {
        lv_obj_t *card = make_modal_card(parent, 300, 100, 0x00D2FF);
        create_text(card, 8, 5, tool_name(tools_idx_), 0x00D2FF, 12);

        struct ToolDesc {
            const char *lines[3];
        };
        static const ToolDesc descs[4] = {
            {{"Manage MIFARE key dictionary.",
              "Keys used by MFKey32/64 attacks",
              "and sector authentication."}},
            {{"Write UID to Gen1a magic card.",
              "Scan target → type UID → write.",
              "Requires Gen1a/Gen3 card."}},
                        {{"MFKey32v2: nested-nonce attack.",
                            "PN532Killer/NFCUnit sniff same",
              "sector w/o card → recover key."}},
            {{"MFKey64: hardnested attack.",
              "PN532Killer sniff read with card",
              "present → recover key."}},
        };
        const auto &d = descs[tools_idx_];
        for (int i = 0; i < 3; ++i) {
            create_text(card, 8, 24 + i * 18, d.lines[i], 0xD8D8D8, 11);
        }
    }

    // ── Global RFID App intro popup ('i' key, any tab) ───────────────────────
    void render_toast_overlay(lv_obj_t *parent)
    {
        // Semi-transparent centered popup, auto-dismissed after 1 s
        lv_obj_t *card = lv_obj_create(parent);
        lv_obj_remove_style_all(card);
        static constexpr int H = 32;
        static constexpr int MIN_W = 120;
        static constexpr int MAX_W = 312;
        const std::string toast_text = to_tail_compact(toast_msg_, 36);
        const int text_w = static_cast<int>(toast_text.size()) * 8;
        const int W = std::max(MIN_W, std::min(MAX_W, text_w + 20));
        lv_obj_set_size(card, W, H);
        lv_obj_set_pos(card, (320 - W) / 2, (CONTENT_H - H) / 2);
        lv_obj_set_style_radius(card, 6, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(card, lv_color_hex(0x1A3A1A), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(card, 230, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_color(card, lv_color_hex(0x00CC44), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(card, 1, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

        lv_obj_t *lbl = lv_label_create(card);
        lv_label_set_text(lbl, toast_text.c_str());
        lv_label_set_long_mode(lbl, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(lbl, W - 10);
        lv_obj_set_style_text_align(lbl, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x00EE55), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_text_font(lbl, &lv_font_unscii_8, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_center(lbl);
    }

    // ── HexLog modal ─────────────────────────────────────────────────────────

    void handle_hex_log_key(uint32_t key)
    {
        const int total   = nfc_app::NfcHexLog::get().total_lines();
        const int max_off = std::max(0, total - LOG_VISIBLE_HEX_LINES);
        if (key == KEY_ESC) {
            modal_ = Modal::None;
        } else if (key == KEY_UP) {
            hex_log_scroll_ = std::max(0, hex_log_scroll_ - 1);
        } else if (key == KEY_DOWN) {
            hex_log_scroll_ = std::min(max_off, hex_log_scroll_ + 1);
        } else if (key == KEY_DELETE || key == 127 /* LV_KEY_DEL */) {
            // Clear in-memory log lines
            nfc_app::NfcHexLog::get().clear();
            hex_log_scroll_ = 0;
        }
    }

    void render_hex_log_overlay(lv_obj_t *parent)
    {
        // Full-width dark panel covering entire content area
        lv_obj_t *panel = lv_obj_create(parent);
        lv_obj_set_size(panel, 320, 150);
        lv_obj_set_pos(panel, 0, 0);
        lv_obj_set_style_radius(panel, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_color(panel, lv_color_hex(0x050505), LV_PART_MAIN);
        lv_obj_set_style_bg_opa(panel, 245, LV_PART_MAIN);
        lv_obj_set_style_border_width(panel, 0, LV_PART_MAIN);
        lv_obj_set_style_pad_all(panel, 0, LV_PART_MAIN);

        // Title bar
        lv_obj_t *title_bar = lv_obj_create(panel);
        lv_obj_set_size(title_bar, 320, 14);
        lv_obj_set_pos(title_bar, 0, 0);
        lv_obj_set_style_radius(title_bar, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_color(title_bar, lv_color_hex(0x1A1A2E), LV_PART_MAIN);
        lv_obj_set_style_bg_opa(title_bar, 255, LV_PART_MAIN);
        lv_obj_set_style_border_width(title_bar, 0, LV_PART_MAIN);
        lv_obj_set_style_pad_all(title_bar, 0, LV_PART_MAIN);

        const int total = nfc_app::NfcHexLog::get().total_lines();
        char header[64];
        std::snprintf(header, sizeof(header), "HEX LOG  %d lines  [%d-%d]",
                      total,
                      hex_log_scroll_ + 1,
                      std::min(total, hex_log_scroll_ + LOG_VISIBLE_HEX_LINES));
        create_text(title_bar, 4, 2, header, 0x00FFCC, 10);

        // Log lines area
        const auto lines = nfc_app::NfcHexLog::get().get_lines(hex_log_scroll_, LOG_VISIBLE_HEX_LINES);
        const int line_h = 11;
        const int start_y = 15;
        for (int i = 0; i < static_cast<int>(lines.size()); ++i) {
            const std::string &ln = lines[static_cast<size_t>(i)];
            // Colour: TX lines (=>) green, RX lines (<=) yellow, events white
            uint32_t col = 0xCCCCCC;
            if (ln.find("=>") != std::string::npos) col = 0x44FF88;
            else if (ln.find("<=") != std::string::npos) col = 0xFFDD44;
            // Truncate to ~52 chars (monospace) so it fits at font size 10
            std::string display = ln.size() > 52 ? ln.substr(0, 52) : ln;
            create_text(panel, 2, start_y + i * line_h, display.c_str(), col, 10);
        }
        if (lines.empty()) {
            create_text(panel, 2, start_y, "(no log entries yet)", 0x555555, 10);
        }

        // Footer hint
        lv_obj_t *footer = lv_obj_create(panel);
        lv_obj_set_size(footer, 320, 13);
        lv_obj_set_pos(footer, 0, 137);
        lv_obj_set_style_radius(footer, 0, LV_PART_MAIN);
        lv_obj_set_style_bg_color(footer, lv_color_hex(0x1A1A2E), LV_PART_MAIN);
        lv_obj_set_style_bg_opa(footer, 255, LV_PART_MAIN);
        lv_obj_set_style_border_width(footer, 0, LV_PART_MAIN);
        lv_obj_set_style_pad_all(footer, 0, LV_PART_MAIN);
        create_text(footer, 4, 2, "U/D:scroll  Del:clear  ESC:close", 0x888888, 10);
    }

    // ── AppInfo modal ─────────────────────────────────────────────────────────

    void render_app_info_modal(lv_obj_t *parent)
    {
        const auto conn = service_.connection_state();
        const auto ep   = service_.current_endpoint();

        lv_obj_t *card = make_modal_card(parent, 308, 110, 0x00D2FF);
        create_text(card, 8, 4, "Device Info", 0x00D2FF, 12);

        char buf[64];

        // Row 0: device kind
        std::snprintf(buf, sizeof(buf), "Device:  %s", nfc_app::to_string(conn.device_kind));
        create_text(card, 8, 22, buf, 0xFFD700, 11);

        // Row 1: firmware / detail (strip " @ /dev/..." path if appended)
        std::string fw_display = conn.detail;
        {
            auto at = fw_display.find(" @ ");
            if (at != std::string::npos) fw_display = fw_display.substr(0, at);
        }
        const std::string fw_str = fw_display.empty() ? "(none)" : fw_display.substr(0, 46);
        std::snprintf(buf, sizeof(buf), "FW:      %s", fw_str.c_str());
        create_text(card, 8, 35, buf, 0xD8D8D8, 11);

        // Row 2: connection path
        const std::string path_str = ep.path.empty() ? "(none)" : ep.path.substr(0, 46);
        std::snprintf(buf, sizeof(buf), "Port:    %s", path_str.c_str());
        create_text(card, 8, 48, buf, 0xD8D8D8, 11);

        // Row 3: status
        const char *status_str = conn.connected ? "Connected" : "Disconnected";
        std::snprintf(buf, sizeof(buf), "Status:  %s", status_str);
        create_text(card, 8, 61, buf, conn.connected ? 0x44FF88 : 0xFF5555, 11);

        // Row 4: PN532 ready flag (useful for debug)
        std::snprintf(buf, sizeof(buf), "NFC Rdy: %s", conn.pn532_ready ? "yes" : "no");
        create_text(card, 8, 74, buf, conn.pn532_ready ? 0x44FF88 : 0x888888, 11);
    }

    // ── Tools-specific modal overlay ─────────────────────────────────────────
    void render_tools_modal(lv_obj_t *parent)
    {
        if (modal_ == Modal::ToolPage) {
            if (active_tool_idx_ == 0) {
                render_mifare_keys_tool(parent);
                return;
            }
            if (active_tool_idx_ == 1) {
                render_uid_changer_tool(parent);
                return;
            }
            if (active_tool_idx_ == 2 || active_tool_idx_ == 3) {
                render_mfkey_wizard(parent);
                return;
            }
            create_text(parent, 6, 4, tool_name(active_tool_idx_), 0xFFFFFF, 12);
            switch (active_tool_idx_) {
            case 0:
                break;
            case 1:
                create_text(parent, 6, 24, "1. Scan target card", 0xD8D8D8, 11);
                create_text(parent, 6, 38, "2. Type new UID", 0xD8D8D8, 11);
                create_text(parent, 6, 52, "3. Write to magic card", 0x8DB6FF, 11);
                break;
            default: break;
            }
        } else if (modal_ == Modal::DeviceProbe) {
            render_device_probe_modal(parent);
        } else if (modal_ == Modal::UartConfig) {
            render_uart_config_modal(parent);
        }
    }

    void render_uid_changer_tool(lv_obj_t *parent)
    {
        const auto conn = service_.connection_state();
        const bool supported = conn.connected &&
            (conn.device_kind == nfc_app::DeviceKind::PN532 ||
             conn.device_kind == nfc_app::DeviceKind::PN532Killer ||
             conn.device_kind == nfc_app::DeviceKind::NFCUnit);

        const char *gen_labels[4] = {"Gen1A", "Gen2", "Gen3(disabled)", "Gen4"};
        const char *len_labels[2] = {"4B", "7B"};
        const char *source_labels[2] = {"Input", "Scan"};

        uid_changer_fix_generation_for_uid_len();
        const std::string uid_input = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
        const std::string block_input = uid_changer_normalize_hex(uid_changer_block0_input_, 32);
        const std::string gen2_key = uid_changer_normalize_hex(uid_changer_gen2_keya_input_, 12);
        const std::string gen4_pwd = uid_changer_normalize_hex(uid_changer_gen4_pwd_input_, 8);

        // Device + step indicator on same line
        {
            const std::string dev_line = std::string("Device: ") + nfc_app::to_string(conn.device_kind);
            create_text(parent, 6, 4, to_compact(dev_line, 28).c_str(), supported ? 0x00FF88 : 0xFF8888, 10);
            const char *step_ch[3] = {"(1)", "(2)", "(3)"};
            int sx = 210;
            for (int si = 0; si < 3; ++si) {
                const bool cur = (si == uid_changer_step_);
                create_text(parent, sx, 4, step_ch[si], cur ? 0xF7A600 : 0x444444, cur ? 12 : 10);
                sx += cur ? 16 : 14;
            }
        }

        if (uid_changer_step_ == 0) {
            const uint32_t c1 = (uid_changer_field_idx_ == 0) ? 0x00D2FF : 0xD8D8D8;
            const uint32_t c2 = (uid_changer_field_idx_ == 1) ? 0x00D2FF : 0x8DB6FF;

            create_text(parent, 6, 16, "(1) Set UID  [Mifare Classic only]", 0xF7A600, 11);
            // Len toggle row (not a selectable field; Tab toggles it)
            create_text(parent, 6, 29, (std::string("UID Len: ") + len_labels[uid_changer_uid_len_idx_] + "  [Tab]").c_str(), 0x8DB6FF, 10);
            // UID input row
            {
                std::string in = std::string("UID(") + std::to_string(uid_changer_uid_hex_len()) + "): " + uid_input;
                if (uid_changer_field_idx_ == 0) in += "_";
                create_text(parent, 6, 43, to_compact(in, 46).c_str(), c1, 10);
            }
            // Block 0 editable row (auto-filled from UID, or manually edited)
            {
                const std::string b0_disp = uid_changer_normalize_hex(uid_changer_block0_input_, 32);
                std::string b0_line = std::string("Block 0: ") + b0_disp;
                if (uid_changer_field_idx_ == 1) b0_line += "_";
                create_text(parent, 6, 57, to_compact(b0_line, 46).c_str(), c2, 10);
            }
            create_text(parent, 6, 71, "[S] Scan MFC card  (warns if non-MFC)", 0x00FF88, 10);
            create_text(parent, 6, 84, "U/D:field Tab:len Bsp:del [S]:scan Enter:next", 0x666666, 10);
            return;
        }

        if (uid_changer_step_ == 1) {
            const uint32_t c0 = (uid_changer_field_idx_ == 0) ? 0xF7A600 : 0xD8D8D8;
            const uint32_t c1 = (uid_changer_field_idx_ == 1) ? 0x00FF88 : 0x8DB6FF;
            create_text(parent, 6, 16, "(2) Card Type (Mifare Classic)", 0xF7A600, 11);
            create_text(parent, 6, 33, (std::string("Type: ") + gen_labels[uid_changer_generation_idx_] + "  [Tab]").c_str(), c0, 10);
            create_text(parent, 6, 47, (std::string("UID: ") + uid_input).c_str(), 0x8DB6FF, 10);
            create_text(parent, 6, 69, "[ Enter ] Next  Tab:type  ESC back", c1, 10);
            return;
        }

        int row_y = 16;
        int row = 0;
        const auto draw_row = [&](const std::string &text, uint32_t color) {
            create_text(parent, 6, row_y + row * 14, to_compact(text, 46).c_str(), color, 10);
            ++row;
        };

        draw_row("(3) Confirm Write", 0xF7A600);
        draw_row(std::string("UID: ") + uid_input, 0xD8D8D8);
        draw_row(std::string("Type: ") + gen_labels[uid_changer_generation_idx_], 0xD8D8D8);

        int field_idx = 0;
        int keya_field = -1;
        int pwd_field = -1;
        int execute_field = -1;

        if (uid_changer_generation_idx_ == 0) {
            // Gen1A: show Block 0 (set in step 1, not editable here)
            const std::string b0_show = block_input.empty() ? uid_changer_build_block0_from_uid(uid_input) : block_input;
            draw_row(std::string("Block 0: ") + b0_show, 0x8DB6FF);
        } else if (uid_changer_generation_idx_ == 1) {
            keya_field = field_idx++;
            std::string key_line = "Sector0 KeyA(12): " + gen2_key;
            if (uid_changer_field_idx_ == keya_field) key_line += "_";
            draw_row(key_line, uid_changer_field_idx_ == keya_field ? 0x00D2FF : 0xD8D8D8);
        } else if (uid_changer_generation_idx_ == 3) {
            pwd_field = field_idx++;
            std::string pwd_line = "Gen4 PWD(8): " + gen4_pwd;
            if (uid_changer_field_idx_ == pwd_field) pwd_line += "_";
            draw_row(pwd_line, uid_changer_field_idx_ == pwd_field ? 0x00D2FF : 0xD8D8D8);
        }

        execute_field = field_idx++;
        draw_row("[ Enter ] Confirm Write", uid_changer_field_idx_ == execute_field ? 0x00FF88 : 0x8DB6FF);
        draw_row(supported ? "Target ready" : "Connect PN532/Killer/NFC Unit first", supported ? 0x00FF88 : 0xFF8888);
        draw_row("U/D field  ESC back", 0x666666);
    }

    // ── MFKey step-by-step wizard renderer ───────────────────────────────────
    // Full-width (320px parent). Shared by mfkey32v2 (idx=2) and mfkey64 (idx=3).
    void render_mfkey_wizard(lv_obj_t *parent)
    {
        const bool with_card = (active_tool_idx_ == 3);
        const char *title    = with_card ? "MFkey64" : "MFKey32v2";

        // Title bar with step indicator
        create_text(parent, 8, 4, title, 0xFFFFFF, 12);
        // ①②③ step indicator
        {
            const char *step_ch[3] = {"(1)", "(2)", "(3)"};
            int sx = 250;
            for (int si = 0; si < 3; ++si) {
                const bool is_cur = (si == (mfkey_step_ < 3 ? mfkey_step_ : 2));
                const bool is_done = (si < (mfkey_step_ < 3 ? mfkey_step_ : 3));
                const uint32_t col = is_cur ? 0xF7A600 : (is_done ? 0x00AA55 : 0x444444);
                create_text(parent, sx, 4, step_ch[si], col, is_cur ? 12 : 10);
                sx += is_cur ? 16 : 14;
            }
        }

        // ── mfkey32v2 ────────────────────────────────────────────────────────
        if (!with_card) {
            switch (mfkey_step_) {
            case 0: {
                create_text(parent, 8, 22, "(1) Set sniffer UID (optional)", 0xF7A600, 11);
                create_text(parent, 8, 38, "Target card UID (8 hex chars):", 0xD8D8D8, 11);
                const std::string disp = mfkey_uid_input_.empty() ? "_" : mfkey_uid_input_ + "_";
                create_text_mono(parent, 8, 54, disp.c_str(), 0x00FFAA, 12);
                create_text(parent, 8, 74, "Leave empty to use device default UID", 0x888888, 10);
                create_text(parent, 8, 90, "Bsp:del  Enter:confirm  ESC:back", 0x7A7A7A, 10);
                break;
            }
            case 1: {
                create_text(parent, 8, 22, "(2) Sniffer active", 0xF7A600, 11);
                if (mfkey_uid_input_.empty()) {
                    create_text(parent, 8, 38, "No UID set. Device uses its own UID.", 0xD8D8D8, 11);
                } else {
                    create_text_mono(parent, 8, 38, (std::string("UID: ") + mfkey_uid_input_).c_str(), 0xD8D8D8, 11);
                }
                create_text(parent, 8, 54, "Approach reader, capture auth sessions.", 0xD8D8D8, 11);
                create_text(parent, 8, 70, "Press Enter when done sniffing.", 0x8DB6FF, 11);
                create_text(parent, 8, 90, "Enter:stop+crack  ESC:abort", 0x7A7A7A, 10);
                break;
            }
            case 2: {
                const int pct32 = service_.hw_mfkey_progress();
                char buf32[48];
                std::snprintf(buf32, sizeof(buf32), "Cracking... %d%%", pct32);
                create_text(parent, 8, 22, "(3) Calculating keys", 0xF7A600, 11);
                create_text(parent, 8, 38, buf32, 0xF7A600, 12);
                create_text(parent, 8, 56, "Running mfkey32v2 on nonce pairs...", 0xD8D8D8, 11);
                break;
            }
            default:
                render_mfkey_results(parent);
                break;
            }
        } else {
        // ── mfkey64 ──────────────────────────────────────────────────────────
            switch (mfkey_step_) {
            case 0: {
                create_text(parent, 8, 22, "(1) Enter sniffer mode", 0xF7A600, 11);
                create_text(parent, 8, 38, "Place real card on device, then", 0xD8D8D8, 11);
                create_text(parent, 8, 54, "let reader authenticate the card.", 0xD8D8D8, 11);
                create_text(parent, 8, 70, "Press Enter to start sniffing.", 0x8DB6FF, 11);
                create_text(parent, 8, 90, "Enter:start  ESC:back", 0x7A7A7A, 10);
                break;
            }
            case 1: {
                create_text(parent, 8, 22, "(2) Sniffer active (card-present)", 0xF7A600, 11);
                create_text(parent, 8, 38, "Device is in card-present sniffer mode.", 0xD8D8D8, 11);
                create_text(parent, 8, 54, "Hold card near reader, let it auth.", 0xD8D8D8, 11);
                create_text(parent, 8, 70, "Press Enter when auth captured.", 0x8DB6FF, 11);
                create_text(parent, 8, 90, "Enter:stop+crack  ESC:back", 0x7A7A7A, 10);
                break;
            }
            case 2: {
                const int pct64 = service_.hw_mfkey_progress();
                char buf64[48];
                std::snprintf(buf64, sizeof(buf64), "Cracking... %d%%", pct64);
                create_text(parent, 8, 22, "(3) Calculating keys", 0xF7A600, 11);
                create_text(parent, 8, 38, buf64, 0xF7A600, 12);
                create_text(parent, 8, 56, "Running mfkey64 on captured auth...", 0xD8D8D8, 11);
                break;
            }
            default:
                render_mfkey_results(parent);
                break;
            }
        }
    }

    void render_mfkey_results(lv_obj_t *parent)
    {
        if (mfkey_results_.empty()) {
            create_text(parent, 8, 22, "No keys found", 0xFF6666, 12);
            create_text(parent, 8, 42, "Not enough nonce pairs captured.", 0xD8D8D8, 11);
            create_text(parent, 8, 56, "Try again: approach reader more times.", 0xD8D8D8, 11);
            create_text(parent, 8, 90, "R:retry  ESC:back", 0x7A7A7A, 10);
            return;
        }
        // Result list (up to 4 visible rows of 20px each)
        constexpr int visible = 4;
        const int total = static_cast<int>(mfkey_results_.size());
        int offset = mfkey_result_idx_ - 1;
        if (offset < 0) offset = 0;
        if (offset > total - visible) offset = total - visible;
        if (offset < 0) offset = 0;
        for (int r = 0; r < visible; ++r) {
            const int idx = offset + r;
            if (idx >= total) break;
            const bool sel = (idx == mfkey_result_idx_);
            const auto &res = mfkey_results_[static_cast<size_t>(idx)];
            lv_obj_t *row = lv_obj_create(parent);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 306, 18);
            lv_obj_set_pos(row, 6, 18 + r * 19);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x1E1E1E), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            char col[32], val[24];
            std::snprintf(col, sizeof(col), "Sec%02u Key%c", res.sector, res.key_type == 0 ? 'A' : 'B');
            const std::string kd = res.key_hex.empty() ? "(not found)" : res.key_hex;
            std::snprintf(val, sizeof(val), "%s", kd.c_str());
            create_text(row, 4, 1, col, sel ? 0x000000 : 0xFFFFFF, 10);
            create_text_mono(row, 80, 1, val, sel ? 0x2F2F2F : 0x8DB6FF, 10);
        }
        create_text(parent, 6, 92, "Enter:import  S:save all  R:retry  ESC:back", 0x7A7A7A, 10);
        // Save-to-file filename input overlay
        if (mfkey_save_mode_) {
            lv_obj_t *box = create_panel(parent, 16, 26, 288, 62, 0x131320);
            create_text(box, 6, 4, "Save all keys to file (.dic added):", 0xD0D0D0, 11);
            const std::string disp = mfkey_save_filename_.empty() ? "_" : mfkey_save_filename_ + "_";
            create_text(box, 6, 20, disp.c_str(), 0xFFFF00, 12);
            create_text(box, 6, 44, "Enter:confirm  ESC:cancel", 0x7A7A7A, 10);
        }
    }

    void render_mifare_keys_tool(lv_obj_t *parent)
    {
        // Tab line: [Built-in] [Files]
        {
            const char *tabs[2] = {"Built-in", "Files"};
            for (int t = 0; t < 2; ++t) {
                const bool sel = (mifare_keys_file_mode_ == (t == 1));
                create_text(parent, 6 + t * 86, 4, tabs[t], sel ? 0xF7A600 : 0x6A6A6A, 11);
            }
        }
        create_text(parent, 168, 4, "Tab:switch", 0x4A4A4A, 10);

        if (mifare_key_editing_) {
            const uint32_t col_label = (mifare_key_field_idx_ == 0) ? 0xFFFF00 : 0xD8D8D8;
            const uint32_t col_key = (mifare_key_field_idx_ == 1) ? 0xFFFF00 : 0xD8D8D8;
            const uint32_t col_type = (mifare_key_field_idx_ == 2) ? 0xFFFF00 : 0x8DB6FF;
            create_text(parent, 6, 22, (std::string("Label: ") + to_compact(mifare_key_edit_.label.empty() ? "(unnamed)" : mifare_key_edit_.label, 18)).c_str(), col_label, 11);
            create_text_mono(parent, 6, 38, (std::string("Key: ") + (mifare_key_edit_.key_hex.empty() ? "_" : mifare_key_edit_.key_hex + "_")).c_str(), col_key, 11);
            create_text(parent, 6, 54, (std::string("Type: Key ") + nfc_app::to_string(mifare_key_edit_.type)).c_str(), col_type, 11);
            create_text(parent, 6, 70, mifare_key_creating_ ? "New key entry" : "Edit selected key", 0x7A7A7A, 10);
            create_text(parent, 6, 92, "U/D field  Tab type  Enter save  ESC back", 0x7A7A7A, 10);
            return;
        }

        if (mifare_keys_file_mode_) {
            // File browser sub-mode
            if (key_file_keys_.empty()) {
                // Show file list
                const int n = static_cast<int>(key_files_.size());
                if (n == 0) {
                    create_text(parent, 6, 24, "No .dic/.txt files found", 0xFF6666, 11);
                    create_text(parent, 6, 38, "/home/pi/rfid/keys/", 0x7A7A7A, 10);
                } else {
                    constexpr int visible = 4;
                    int offset = key_file_idx_ - 1;
                    if (offset < 0) offset = 0;
                    if (offset > n - visible) offset = n - visible;
                    if (offset < 0) offset = 0;
                    for (int r = 0; r < visible; ++r) {
                        const int idx = offset + r;
                        if (idx >= n) break;
                        const bool sel = (idx == key_file_idx_);
                        lv_obj_t *row = lv_obj_create(parent);
                        lv_obj_remove_style_all(row);
                        lv_obj_set_size(row, 306, 18);
                        lv_obj_set_pos(row, 6, 20 + r * 18);
                        lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
                        const int cnt = (idx < static_cast<int>(key_file_counts_.size())) ? key_file_counts_[static_cast<size_t>(idx)] : 0;
                        const std::string left = to_compact(key_files_[static_cast<size_t>(idx)], 24);
                        const std::string right = std::to_string(cnt) + " keys";
                        create_text(row, 4, 4, left.c_str(), sel ? 0x000000 : 0xD0D0D0, 10);
                        create_text(row, 210, 4, right.c_str(), sel ? 0x1A1A1A : 0x8DB6FF, 10);
                    }
                }
                create_text(parent, 6, 92, "U/D select  Enter:load file  ESC back", 0x7A7A7A, 10);
            } else {
                if (key_file_editing_) {
                    const int total = std::max(1, static_cast<int>(key_file_keys_.size()));
                    if (key_file_key_idx_ >= total) key_file_key_idx_ = total - 1;
                    if (key_file_key_idx_ < 0) key_file_key_idx_ = 0;

                    const std::string fname = key_file_idx_ < static_cast<int>(key_files_.size())
                        ? key_files_[static_cast<size_t>(key_file_idx_)] : "";
                    create_text(parent, 6, 16, to_compact(fname, 28).c_str(), 0x00D2FF, 10);
                    create_text(parent, 190, 16, key_file_dirty_ ? "*dirty" : "saved", key_file_dirty_ ? 0xF7A600 : 0x6A6A6A, 10);

                    constexpr int visible = 4;
                    int offset = key_file_key_idx_ - 1;
                    if (offset < 0) offset = 0;
                    if (offset > total - visible) offset = total - visible;
                    if (offset < 0) offset = 0;
                    for (int r = 0; r < visible; ++r) {
                        const int idx = offset + r;
                        if (idx >= total) break;
                        const bool sel = (idx == key_file_key_idx_);
                        lv_obj_t *row = lv_obj_create(parent);
                        lv_obj_remove_style_all(row);
                        lv_obj_set_size(row, 306, 16);
                        lv_obj_set_pos(row, 6, 28 + r * 16);
                        lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
                        const std::string key_hex = idx < static_cast<int>(key_file_keys_.size()) ? key_file_keys_[static_cast<size_t>(idx)] : "";
                        const std::string disp = key_hex + (sel ? "_" : "");
                        char idx_buf[8];
                        std::snprintf(idx_buf, sizeof(idx_buf), "%03d", idx + 1);
                        create_text(row, 4, 3, idx_buf, sel ? 0x000000 : 0x7A7A7A, 10);
                        create_text_mono(row, 40, 3, to_compact(disp, 24).c_str(), sel ? 0x000000 : 0x8DB6FF, 10);
                    }
                    create_text(parent, 6, 92, "Hex edit  Enter:+line  Del:line  S:save", 0x7A7A7A, 10);
                    create_text(parent, 6, 104, "U/D line  Bsp:erase  ESC back", 0x7A7A7A, 10);
                    return;
                }

                // Show keys from loaded file (browse mode)
                const int total = static_cast<int>(key_file_keys_.size());
                constexpr int visible = 4;
                int offset = key_file_key_idx_ - 1;
                if (offset < 0) offset = 0;
                if (offset > total - visible) offset = total - visible;
                if (offset < 0) offset = 0;
                // Show file name as subtitle
                const std::string fname = key_file_idx_ < static_cast<int>(key_files_.size())
                    ? to_compact(key_files_[static_cast<size_t>(key_file_idx_)], 20) : "";
                create_text(parent, 6, 16, fname.c_str(), 0x00D2FF, 10);
                for (int r = 0; r < visible; ++r) {
                    const int idx = offset + r;
                    if (idx >= total) break;
                    const bool sel = (idx == key_file_key_idx_);
                    lv_obj_t *row = lv_obj_create(parent);
                    lv_obj_remove_style_all(row);
                    lv_obj_set_size(row, 306, 16);
                    lv_obj_set_pos(row, 6, 26 + r * 16);
                    lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00D2FF : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
                    lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
                    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
                    create_text_mono(row, 4, 3, key_file_keys_[static_cast<size_t>(idx)].c_str(), sel ? 0x000000 : 0x8DB6FF, 10);
                }
                char countbuf[32];
                std::snprintf(countbuf, sizeof(countbuf), "%d keys", total);
                create_text(parent, 6, 92, countbuf, 0x7A7A7A, 10);
                create_text(parent, 50, 92, "  Enter:edit file  Bsp:back", 0x7A7A7A, 10);
            }
            return;
        }

        // Built-in key list (original behaviour)
        const int total_rows = static_cast<int>(mifare_keys_.size()) + 1;
        constexpr int visible = 4;
        int offset = mifare_key_idx_ - 1;
        if (offset < 0) offset = 0;
        if (offset > total_rows - visible) offset = total_rows - visible;
        if (offset < 0) offset = 0;

        for (int row = 0; row < visible; ++row) {
            const int index = offset + row;
            if (index >= total_rows) break;
            const bool selected = (index == mifare_key_idx_);
            lv_obj_t *entry = lv_obj_create(parent);
            lv_obj_remove_style_all(entry);
            lv_obj_set_size(entry, 164, 18);
            lv_obj_set_pos(entry, 6, 20 + row * 18);
            lv_obj_set_style_bg_color(entry, lv_color_hex(selected ? 0xF7A600 : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(entry, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(entry, LV_OBJ_FLAG_SCROLLABLE);

            if (index == static_cast<int>(mifare_keys_.size())) {
                create_text(entry, 4, 4, "+ Add Key", selected ? 0x000000 : 0x8DB6FF, 10);
            } else {
                const auto &key = mifare_keys_[index];
                const std::string head = (key.enabled ? "[on] " : "[off] ") + key.label;
                const std::string tail = std::string("K") + nfc_app::to_string(key.type) + " " + key.key_hex;
                create_text(entry, 4, 1, to_compact(head, 18).c_str(), selected ? 0x000000 : 0xFFFFFF, 10);
                create_text_mono(entry, 4, 9, to_compact(tail, 18).c_str(), selected ? 0x2F2F2F : 0x8DB6FF, 10);
            }
        }
        create_text(parent, 6, 92, "U/D select  Enter edit  T on/off  Bsp del  Tab files  ESC back", 0x7A7A7A, 10);
    }

    void render_device_probe_modal(lv_obj_t *parent)
    {
        lv_obj_t *card = parent;
        create_text(card, 6, 4, "Device Probe", 0xFFFFFF, 12);

        const auto results = service_.probe_results();
        const bool running = service_.probe_running();

        if (results.empty()) {
            const char *msg = running ? "Scanning..." : "No USB/UART ports found";
            create_text(card, 6, 22, msg, 0xD8D8D8, 11);
        } else {
            int y = 20;
            for (size_t i = 0; i < results.size() && y < 88; ++i, y += 20) {
                const auto &r = results[i];
                // Port path (short)
                std::string path = r.path;
                const auto slash = path.rfind('/');
                if (slash != std::string::npos) path = path.substr(slash + 1);
                char line1[48];
                if (r.probing) {
                    std::snprintf(line1, sizeof(line1), "%-16s ...", path.c_str());
                } else {
                    std::snprintf(line1, sizeof(line1), "%-16s %s", path.c_str(),
                                  nfc_app::to_string(r.device_kind));
                }
                create_text(card, 6, y, line1, 0xD8D8D8, 11);
                if (!r.firmware.empty()) {
                    create_text(card, 10, y + 10, to_compact(r.firmware, 24).c_str(), 0x8DB6FF, 10);
                    y += 4;  // extra padding for firmware line
                }
            }
            if (running) create_text(card, 6, 88, "Scanning...", 0x8DB6FF, 11);
        }
    }

    void render_uart_config_modal(lv_obj_t *parent)
    {
        lv_obj_t *card = parent;
        create_text(card, 6, 4, "UART Config", 0xFFFFFF, 12);

        // Device path row
        {
            char buf[48];
            const std::string &dev = uart_edit_buf_.device_path;
            std::snprintf(buf, sizeof(buf), "Dev: %s", dev.empty() ? "(none)" : to_compact(dev, 20).c_str());
            uint32_t col = (uart_field_idx_ == 0) ? 0xFFFF00 : 0xD8D8D8;
            create_text(card, 6, 22, buf, col, 11);
        }
        // Pins (informational) / edit buffer when typing device path
        if (uart_field_idx_ == 0 && !edit_buf_.empty()) {
            std::string disp = "> " + edit_buf_;
            create_text(card, 6, 38, disp.c_str(), 0xFFFF88, 11);
        } else {
            char buf[40];
            const auto pins = nfc_app::NfcDeviceService::uart_pin_hint(uart_edit_buf_.device_path);
            if (pins.first >= 0) {
                std::snprintf(buf, sizeof(buf), "TX: GPIO%d  RX: GPIO%d", pins.first, pins.second);
            } else {
                std::snprintf(buf, sizeof(buf), "TX/RX: unknown");
            }
            create_text(card, 6, 38, buf, 0x8DB6FF, 11);
        }
        // Test Connection row (field 1)
        {
            const bool sel = (uart_field_idx_ == 1);
            uint32_t col = sel ? 0x00FF88 : 0x44BB77;
            create_text(card, 6, 54, sel ? "[ Test Connection ]" : "  Test Connection", col, 11);
        }
        // Test result line
        if (!uart_test_result_.empty()) {
            const bool ok = uart_test_result_.rfind("OK:", 0) == 0;
            create_text(card, 6, 68, uart_test_result_.c_str(), ok ? 0x00FF88 : 0xFF6060, 10);
        }
    }

    lv_obj_t *make_modal_card(lv_obj_t *parent)
    {
        // Full-content-area overlay card
        lv_obj_t *card = lv_obj_create(parent);
        lv_obj_set_size(card, 320, 104);
        lv_obj_set_pos(card, 0, 0);
        lv_obj_set_style_bg_color(card, lv_color_hex(0x1A1A2E), 0);
        lv_obj_set_style_bg_opa(card, 245, 0);
        lv_obj_set_style_border_color(card, lv_color_hex(0x3A6FD8), 0);
        lv_obj_set_style_border_width(card, 1, 0);
        lv_obj_set_style_radius(card, 4, 0);
        lv_obj_set_style_pad_all(card, 0, 0);
        lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
        return card;
    }

    void handle_device_probe_key(uint32_t key)
    {
        if (key == KEY_ENTER) {
            service_.start_probe_all();
            ui_message_ = "Probing...";
        } else if (key == KEY_ESC) {
            modal_ = Modal::None;
            ui_message_.clear();
        }
    }

    void handle_uart_config_key(uint32_t key)
    {
        const int FIELDS = 2;  // 0=device path  1=Test Connection
        if (key == KEY_ESC) {
            // Save current values
            if (!uart_edit_buf_.device_path.empty()) {
                auto pins = nfc_app::NfcDeviceService::uart_pin_hint(uart_edit_buf_.device_path);
                uart_edit_buf_.tx_pin = pins.first;
                uart_edit_buf_.rx_pin = pins.second;
            }
            service_.set_uart_config(uart_edit_buf_);
            ui_message_ = "UART saved";
            modal_ = Modal::None;
            edit_buf_.clear();
            uart_test_result_.clear();
            return;
        }
        if (key == KEY_UP)   { uart_field_idx_ = (uart_field_idx_ - 1 + FIELDS) % FIELDS; return; }
        if (key == KEY_DOWN) { uart_field_idx_ = (uart_field_idx_ + 1) % FIELDS; return; }
        if (key == KEY_ENTER) {
            if (uart_field_idx_ == 0 && !edit_buf_.empty()) {
                uart_edit_buf_.device_path = edit_buf_;
                edit_buf_.clear();
            } else if (uart_field_idx_ == 1) {
                // Save current config first, then test
                if (!uart_edit_buf_.device_path.empty()) {
                    auto pins = nfc_app::NfcDeviceService::uart_pin_hint(uart_edit_buf_.device_path);
                    uart_edit_buf_.tx_pin = pins.first;
                    uart_edit_buf_.rx_pin = pins.second;
                }
                service_.set_uart_config(uart_edit_buf_);
                uart_test_result_ = "Testing...";
                service_.start_uart_test();
            }
            return;
        }
        if (key == KEY_BACKSPACE) {
            if (!edit_buf_.empty()) edit_buf_.pop_back();
            return;
        }
        // Typed character — device path only
        if (uart_field_idx_ == 0) {
            char c = keycode_to_char(key);
            if (c >= 32 && c < 127) edit_buf_ += c;
        }
    }

    lv_obj_t *create_panel(lv_obj_t *parent, int x, int y, int w, int h, uint32_t color)
    {
        lv_obj_t *panel = lv_obj_create(parent);
        lv_obj_set_size(panel, w, h);
        lv_obj_set_pos(panel, x, y);
        lv_obj_set_style_radius(panel, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(panel, lv_color_hex(color), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(panel, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(panel, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_pad_all(panel, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(panel, LV_OBJ_FLAG_SCROLLABLE);
        return panel;
    }

    lv_obj_t *create_text(lv_obj_t *parent, int x, int y, const char *text, uint32_t color, int font_size)
    {
        lv_obj_t *label = lv_label_create(parent);
        // Strip default theme padding so position is exact pixel from parent origin
        lv_obj_set_style_pad_all(label, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_label_set_text(label, text);
        lv_obj_set_pos(label, x, y);
        lv_obj_set_style_text_color(label, lv_color_hex(color), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_text_font(label,
            font_size >= 12 ? &lv_font_montserrat_12 :
            font_size >= 10 ? &lv_font_montserrat_10 :
            font_size >= 8  ? &lv_font_montserrat_10 :
                              &lv_font_unscii_8,
            LV_PART_MAIN | LV_STATE_DEFAULT);
        return label;
    }

    lv_obj_t *create_text_mono(lv_obj_t *parent, int x, int y, const char *text, uint32_t color, int font_size)
    {
        lv_obj_t *label = create_text(parent, x, y, text, color, font_size);
        const lv_font_t *mono_font = &lv_font_unscii_8;
        if (font_size >= 12 && g_font_mono_12 != nullptr) mono_font = g_font_mono_12;
        lv_obj_set_style_text_font(label, mono_font, LV_PART_MAIN | LV_STATE_DEFAULT);
        return label;
    }

    void create_action_row(lv_obj_t *parent, int y, const char *label, bool selected)
    {
        lv_obj_t *row = lv_obj_create(parent);
        lv_obj_set_size(row, lv_obj_get_width(parent) - 8, 18);
        lv_obj_set_pos(row, 4, y);
        lv_obj_set_style_radius(row, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(row, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(row, lv_color_hex(selected ? 0xF7A600 : 0x181818), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
        create_text(row, 4, 3, label, selected ? 0x000000 : 0xFFFFFF, 11);
    }

    void create_footer(lv_obj_t *parent, const std::string &text)
    {
        const int footer_y = std::max(0, static_cast<int>(lv_obj_get_height(parent)) - 14);
        lv_obj_t *footer = create_panel(parent, 0, footer_y, 320, 14, 0x0A0A0A);
        // Show full text, left-aligned, use smaller font if available
        lv_obj_t *label = lv_label_create(footer);
        lv_label_set_text(label, text.c_str());
        lv_obj_set_style_text_font(label, &lv_font_unscii_8, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_text_color(label, lv_color_hex(0x7FA5C9), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_pos(label, 2, 1);
        lv_label_set_long_mode(label, LV_LABEL_LONG_CLIP);
        lv_obj_set_width(label, 316);
    }

    // ── Key code helpers (evdev scan codes → printable char) ────────────────

    // General text input (letters + digits + basic symbols, lowercase)
    static char keycode_to_char(uint32_t key)
    {
        if (key >= KEY_1 && key <= KEY_9) return '0' + (int)(key - KEY_1) + 1;
        if (key == KEY_0) return '0';
        static const char qwerty[] = "qwertyuiop";
        if (key >= KEY_Q && key <= KEY_P) return qwerty[key - KEY_Q];
        static const char asdf[] = "asdfghjkl";
        if (key >= KEY_A && key <= KEY_L) return asdf[key - KEY_A];
        static const char zxcv[] = "zxcvbnm";
        if (key >= KEY_Z && key <= KEY_M) return zxcv[key - KEY_Z];
        if (key == KEY_SPACE) return ' ';
        if (key == 52) return '.';   // KEY_DOT
        if (key == 12) return '-';   // KEY_MINUS
        if (key == 51) return ',';   // KEY_COMMA
        if (key == 26) return '[';   // KEY_LEFTBRACE
        if (key == 27) return ']';   // KEY_RIGHTBRACE
        if (key == 39) return ';';   // KEY_SEMICOLON
        if (key == 40) return '\'';  // KEY_APOSTROPHE
        if (key == 53) return '/';   // KEY_SLASH
        return 0;
    }

    // Hex-specific input: 0-9, A-F (uppercase), space, colon
    static char keycode_to_hex_char(uint32_t key)
    {
        if (key >= KEY_1 && key <= KEY_9) return '0' + (int)(key - KEY_1) + 1;
        if (key == KEY_0) return '0';
        // A-F uppercase only
        if (key == KEY_A) return 'A';
        if (key == KEY_B) return 'B';
        if (key == KEY_C) return 'C';
        if (key == KEY_D) return 'D';
        if (key == KEY_E) return 'E';
        if (key == KEY_F) return 'F';
        if (key == KEY_SPACE) return ' ';
        if (key == 39) return ':';   // KEY_SEMICOLON → colon
        return 0;
    }

    // ── String helpers ───────────────────────────────────────────────────────

    static std::string to_compact(const std::string &text, size_t max_len)
    {
        if (text.size() <= max_len) return text;
        if (max_len < 4) return text.substr(0, max_len);
        return text.substr(0, max_len - 3) + "...";
    }

    // For text-input fields: show tail so the cursor "_" is always visible.
    static std::string to_tail_compact(const std::string &text, size_t max_len)
    {
        if (text.size() <= max_len) return text;
        if (max_len < 4) return text.substr(text.size() - max_len);
        return "..." + text.substr(text.size() - (max_len - 3));
    }

    static const char *tool_name(int index)
    {
        static const char *TOOLS[4] = {"MIFARE Keys", "UID Changer", "MFKey32v2", "MFKey64"};
        if (index < 0 || index >= 4) return TOOLS[0];
        return TOOLS[index];
    }

    // ── Modal rendering ─────────────────────────────────────────────────────

    void render_saved_modal(lv_obj_t *parent)
    {
        // Full-area semi-transparent overlay
        lv_obj_t *overlay = lv_obj_create(parent);
        lv_obj_remove_style_all(overlay);
        lv_obj_set_size(overlay, 320, CONTENT_H);
        lv_obj_set_pos(overlay, 0, 0);
        lv_obj_set_style_radius(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_color(overlay, lv_color_hex(0x000000), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_bg_opa(overlay, 170, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(overlay, 0, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_clear_flag(overlay, LV_OBJ_FLAG_SCROLLABLE);

        switch (modal_) {
        case Modal::Action:     render_action_modal_card(overlay);     break;
        case Modal::SlotSelect: render_slot_select_modal_card(overlay); break;
        case Modal::EditName:   render_edit_name_modal_card(overlay);  break;
        case Modal::EditHex:    render_edit_hex_modal_card(overlay);   break;
        case Modal::HexExitConfirm: render_hex_exit_confirm_card(overlay); break;
        default: break;
        }
    }

    lv_obj_t *make_modal_card(lv_obj_t *parent, int w, int h, uint32_t border_color)
    {
        const int OVERLAY_H = CONTENT_H;
        const int mx = (320 - w) / 2;
        const int my = (OVERLAY_H - h) / 2;
        lv_obj_t *card = create_panel(parent, mx, my, w, h, 0x1A1A1A);
        lv_obj_set_style_border_color(card, lv_color_hex(border_color), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(card, 1, LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_radius(card, 2, LV_PART_MAIN | LV_STATE_DEFAULT);
        return card;
    }

    void render_action_modal_card(lv_obj_t *parent)
    {
        const auto conn = service_.connection_state();
        const auto emu_kind = effective_emu_device_kind(conn);
        const bool is_i2c_dev = (emu_kind == nfc_app::DeviceKind::GroveNFC ||
                                 emu_kind == nfc_app::DeviceKind::NFCUnit);
        const bool is_nfcunit = (emu_kind == nfc_app::DeviceKind::NFCUnit);
        // NFCUnit/GroveNFC: Emulate, Write to Tag, Edit Name, Edit Hex, Delete (5 options)
        // Others: Emulate/Upload, Edit Name, Edit Hex, Delete (4 options)
        const int n_opts = is_i2c_dev ? 5 : 4;
        const lv_coord_t card_h = static_cast<lv_coord_t>(24 + n_opts * 20);
        // Width 220, dynamic height based on option count
        lv_obj_t *card = make_modal_card(parent, 220, card_h, 0xF7A600);
        const auto &rec = saved_records_[saved_idx_];
        create_text(card, 8, 6, to_compact(rec.meta.display_name, 26).c_str(), 0xFFFFFF, 12);

        const char *upload_label = is_i2c_dev ? "Emulate" : "Upload to Slot...";
        std::vector<const char *> options = {upload_label};
        if (is_i2c_dev) options.push_back("Write to Tag");
        options.push_back("Edit Name");
        options.push_back("Edit Hex Data");
        options.push_back("Delete");

        for (int i = 0; i < static_cast<int>(options.size()); ++i) {
            const bool sel = (modal_idx_ == i);
            const bool is_delete = (i == static_cast<int>(options.size()) - 1);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);  // must be before set_size (size is a style in LVGL9)
            lv_obj_set_size(row, 204, 18);
            lv_obj_set_pos(row, 8, 24 + i * 20);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? (is_delete ? 0xFF4444 : 0xF7A600) : (is_delete ? 0x3A1A1A : 0x2A2A2A)), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 4, options[i], sel ? 0x000000 : (is_delete ? 0xFF8888 : 0xD0D0D0), 11);
        }
    }

    void render_slot_select_modal_card(lv_obj_t *parent)
    {
        // Width 250, Height 114 → 5 visible slots + header + hint with bottom padding
        lv_obj_t *card = make_modal_card(parent, 250, 114, 0xF7A600);
        const auto protocol = saved_records_[saved_idx_].tag.protocol;
        create_text(card, 8, 5, (std::string(nfc_app::to_string(protocol)) + " Slot (1-8)").c_str(), 0xFFFFFF, 12);

        const auto slots = service_.emulator_slots_padded(protocol);
        constexpr int VISIBLE = 5;
        int offset = slot_select_idx_ - VISIBLE / 2;
        if (offset < 0) offset = 0;
        if (offset > 8 - VISIBLE) offset = 8 - VISIBLE;

        for (int i = 0; i < VISIBLE; ++i) {
            const int si = offset + i;
            if (si >= 8) break;
            const bool sel = (si == slot_select_idx_);
            const auto &slot = slots[si];
            std::string label = "Slot " + std::to_string(si + 1) + ": ";
            if (slot.payload_record_id.empty()) label += "(empty)";
            else label += to_compact(slot.payload_record_id, 12) + "  [" + nfc_app::to_string(slot.protocol) + "]";

            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);  // must be before set_size (size is a style in LVGL9)
            lv_obj_set_size(row, 234, 15);
            lv_obj_set_pos(row, 8, 21 + i * 16);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0xF7A600 : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 4, 2, to_compact(label, 34).c_str(), sel ? 0x000000 : 0xCCCCCC, 10);
        }
    }

    void render_edit_name_modal_card(lv_obj_t *parent)
    {
        lv_obj_t *card = make_modal_card(parent, 300, 70, 0x00D2FF);
        create_text(card, 8, 5, "Edit Name", 0x00D2FF, 12);

        // Symmetric input box margins (8px left/right)
        lv_obj_t *box = create_panel(card, 8, 21, 284, 24, 0x0E1A22);
        lv_obj_set_style_border_color(box, lv_color_hex(0x00D2FF), LV_PART_MAIN | LV_STATE_DEFAULT);
        lv_obj_set_style_border_width(box, 1, LV_PART_MAIN | LV_STATE_DEFAULT);
        const std::string cursor_text = to_compact(edit_buf_, 36) + "_";
        create_text(box, 4, 6, cursor_text.c_str(), 0x00D2FF, 11);
    }

    // Strip a raw_data line to pure uppercase hex (no prefixes, no spaces)
    static std::string strip_to_hex(const std::string &s)
    {
        std::string result;
        // Skip "Block N: " or similar prefix before the first colon+space
        size_t start = 0;
        const size_t colon = s.find(": ");
        if (colon != std::string::npos) start = colon + 2;
        for (size_t i = start; i < s.size(); ++i) {
            const unsigned char c = static_cast<unsigned char>(s[i]);
            if (std::isxdigit(c)) result += static_cast<char>(std::toupper(c));
        }
        return result;
    }

    // Group a compact hex string as bytes: "A1B2C3" -> "A1 B2 C3"
    static std::string hex_with_byte_spaces(const std::string &hex)
    {
        std::string out;
        out.reserve(hex.size() + hex.size() / 2);
        for (size_t i = 0; i < hex.size(); ++i) {
            if (i > 0 && (i % 2) == 0) out.push_back(' ');
            out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(hex[i]))));
        }
        return out;
    }

    int uid_changer_uid_hex_len() const
    {
        return (uid_changer_uid_len_idx_ == 0) ? 8 : 14;
    }

    static bool uid_changer_generation_allowed(int gen_idx, int uid_len_idx)
    {
        if (gen_idx == 2) return false; // UID Changer: disable Gen3 write path.
        if (uid_len_idx == 1 && gen_idx == 1) return false; // Gen2 does not support 7B UID here.
        return gen_idx >= 0 && gen_idx <= 3;
    }

    void uid_changer_fix_generation_for_uid_len()
    {
        if (!uid_changer_generation_allowed(uid_changer_generation_idx_, uid_changer_uid_len_idx_)) {
            // Prefer Gen4, then Gen1A, then Gen2 as fallback.
            if (uid_changer_generation_allowed(3, uid_changer_uid_len_idx_)) uid_changer_generation_idx_ = 3;
            else if (uid_changer_generation_allowed(0, uid_changer_uid_len_idx_)) uid_changer_generation_idx_ = 0;
            else uid_changer_generation_idx_ = 1;
        }
    }

    std::string uid_changer_normalize_hex(const std::string &in, size_t max_chars) const
    {
        std::string out;
        out.reserve(in.size());
        for (char ch : in) {
            if (!std::isxdigit(static_cast<unsigned char>(ch))) continue;
            out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
            if (out.size() >= max_chars) break;
        }
        return out;
    }

    std::string uid_changer_build_block0_from_uid(const std::string &uid_hex) const
    {
        const std::string uid = uid_changer_normalize_hex(uid_hex, static_cast<size_t>(uid_changer_uid_hex_len()));
        if (uid.size() != static_cast<size_t>(uid_changer_uid_hex_len())) return "";

        if (uid_changer_uid_len_idx_ == 0) {
            // 4-byte UID block0: [UID0-3][BCC][SAK=08][ATQA=0400][MFR x8]
            // BCC = UID[0]^UID[1]^UID[2]^UID[3]
            const uint8_t b0 = static_cast<uint8_t>(std::stoul(uid.substr(0, 2), nullptr, 16));
            const uint8_t b1 = static_cast<uint8_t>(std::stoul(uid.substr(2, 2), nullptr, 16));
            const uint8_t b2 = static_cast<uint8_t>(std::stoul(uid.substr(4, 2), nullptr, 16));
            const uint8_t b3 = static_cast<uint8_t>(std::stoul(uid.substr(6, 2), nullptr, 16));
            char bcc[3];
            std::snprintf(bcc, sizeof(bcc), "%02X", static_cast<unsigned>(b0 ^ b1 ^ b2 ^ b3));
            // 8+2+2+4+16 = 32 hex chars
            return uid + bcc + "08" + "0400" + "1122334455667788";
        }

        // 7-byte UID block0: [UID 7 bytes][18][42][00][AA][BB][CC][DD][EE][FF]
        // Total: 16 bytes = 32 hex chars
        return uid + "184200AABBCCDDEEFF";
    }

    nfc_app::UidMagicGeneration uid_changer_generation() const
    {
        switch (uid_changer_generation_idx_) {
        case 0:  return nfc_app::UidMagicGeneration::Gen1A;
        case 1:  return nfc_app::UidMagicGeneration::Gen2;
        case 2:  return nfc_app::UidMagicGeneration::Gen3;
        default: return nfc_app::UidMagicGeneration::Gen4;
        }
    }

    std::string compact_read_connection_detail(const nfc_app::ConnectionState &conn) const
    {
        std::string detail = conn.detail;
        if (conn.device_kind == nfc_app::DeviceKind::NFCUnit) {
            const size_t hw_pos = detail.find(" HW:");
            if (hw_pos != std::string::npos) detail = detail.substr(0, hw_pos);
        }
        return to_compact(detail, 40);
    }

    void render_edit_hex_modal_card(lv_obj_t *parent)
    {
        lv_obj_t *card = make_modal_card(parent, 320, CONTENT_H, 0x00FF88);
        create_text(card, 6, 3, "Hex Editor", 0x00FF88, 12);

        const auto &lines = saved_records_[saved_idx_].tag.raw_data;
        const int total = static_cast<int>(lines.size());
        if (total == 0) {
            create_text(card, 8, 28, "(no data)", 0x666666, 11);
            create_text(card, 8, 108, "ESC close", 0x444444, 10);
            return;
        }

        // Text-editor style: fixed-width index + monospace hex data (unscii_8, 8px/char).
        // unscii_8 is exactly 8px per glyph so bytes always align perfectly.
        // 16 bytes raw hex = 32 chars × 8px = 256px, fits from x=32 to x=288 within 320px card.
        constexpr int VISIBLE = 7;
        constexpr int ROW_H   = 13;
        int offset = edit_hex_line_ - 1;
        if (offset < 0) offset = 0;
        if (offset > total - VISIBLE && total >= VISIBLE) offset = total - VISIBLE;
        if (offset < 0) offset = 0;

        for (int i = 0; i < VISIBLE; ++i) {
            const int li = offset + i;
            if (li >= total) break;
            const bool active = (li == edit_hex_line_);
            const int y = 18 + i * ROW_H;
            char lnum[5]; std::snprintf(lnum, sizeof(lnum), "%02d:", li);
            create_text(card, 4, y, lnum, active ? 0x00FF88 : 0x444444, 7);

            const std::string hex = active ? edit_buf_ : strip_to_hex(lines[li]);
            // Show raw hex (no spaces) – unscii_8 gives perfect per-byte alignment.
            const std::string disp = hex.substr(0, 32) + (active ? "_" : "");
            create_text(card, 32, y, disp.c_str(), active ? 0x00FF88 : 0x888888, 7);
        }

        char hint[32];
        std::snprintf(hint, sizeof(hint), "Line %d/%d  Ctrl+S save  ESC exit",
                      edit_hex_line_ + 1, total);
        create_text(card, 4, 108, hint, 0x444444, 7);
    }

    void render_hex_exit_confirm_card(lv_obj_t *parent)
    {
        lv_obj_t *card = make_modal_card(parent, 230, 82, 0x00FF88);
        create_text(card, 8, 5, "Unsaved Hex Data", 0x00FF88, 12);
        const char *options[] = {"Save and Exit", "Discard", "Cancel"};
        for (int i = 0; i < 3; ++i) {
            const bool sel = (modal_idx_ == i);
            lv_obj_t *row = lv_obj_create(card);
            lv_obj_remove_style_all(row);
            lv_obj_set_size(row, 214, 16);
            lv_obj_set_pos(row, 8, 22 + i * 18);
            lv_obj_set_style_bg_color(row, lv_color_hex(sel ? 0x00FF88 : 0x242424), LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_set_style_bg_opa(row, 255, LV_PART_MAIN | LV_STATE_DEFAULT);
            lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
            create_text(row, 6, 3, options[i], sel ? 0x000000 : 0xD0D0D0, 10);
        }
    }

    void save_edit_hex(bool close_after_save)
    {
        auto &lines = saved_records_[saved_idx_].tag.raw_data;
        if (edit_hex_line_ >= 0 && edit_hex_line_ < static_cast<int>(lines.size())) {
            lines[edit_hex_line_] = edit_buf_;
        }
        std::string err;
        service_.update_record_hex(saved_records_[saved_idx_].meta.record_id, lines, &err);
        ui_message_ = err.empty() ? "Hex saved" : "Hex err: " + err;
        edit_hex_dirty_ = false;
        if (close_after_save) {
            modal_ = Modal::None;
            modal_idx_ = 0;
        } else {
            modal_ = Modal::EditHex;
        }
    }

    // ── Modal key handling ───────────────────────────────────────────────────

    void handle_modal_key(uint32_t key, uint32_t mods)
    {
        switch (modal_) {
        case Modal::Action:     handle_action_key(key);      break;
        case Modal::SlotSelect: handle_slot_select_key(key); break;
        case Modal::EditName:   handle_edit_name_key(key);   break;
        case Modal::EditHex:    handle_edit_hex_key(key, mods);    break;
        case Modal::HexExitConfirm: handle_hex_exit_confirm_key(key); break;
        case Modal::EmulatorAction: handle_emulator_action_key(key); break;
        case Modal::DeviceProbe: handle_device_probe_key(key); break;
        case Modal::UartConfig:  handle_uart_config_key(key);  break;
        case Modal::ToolPage:
            if (active_tool_idx_ == 0) handle_mifare_keys_tool_key(key);
            else if (active_tool_idx_ == 1) handle_uid_changer_tool_key(key);
            else if (active_tool_idx_ == 2 || active_tool_idx_ == 3) handle_mfkey_tool_key(key);
            else if (key == KEY_ESC) modal_ = Modal::None;
            break;
        case Modal::ToolInfo:
            if (key == KEY_ESC) modal_ = Modal::None;
            break;
        case Modal::AppInfo:
            if (key == KEY_ESC || key == KEY_I) {
                modal_ = Modal::None;
            }
            break;
        case Modal::PostScan:
            handle_post_scan_key(key);
            break;
        case Modal::ReadMenu:
            handle_read_menu_key(key);
            break;
        case Modal::PortSettings:
            handle_port_settings_key(key);
            break;
        case Modal::UsbSelect:
            handle_usb_select_key(key);
            break;
        case Modal::I2cSelect:
            handle_i2c_select_key(key);
            break;
        case Modal::SpiSelect:
            handle_spi_select_key(key);
            break;
        case Modal::HexLog:
            handle_hex_log_key(key);
            break;
        case Modal::Pn532NdefInput:
            handle_pn532_ndef_input_key(key);
            break;
        default: break;
        }
        render_all();
    }

    void handle_action_key(uint32_t key)
    {
        const auto conn2 = service_.connection_state();
        const auto emu_kind2 = effective_emu_device_kind(conn2);
        const bool is_i2c_dev = (emu_kind2 == nfc_app::DeviceKind::GroveNFC ||
                                 emu_kind2 == nfc_app::DeviceKind::NFCUnit);
        const bool is_nfcunit = (emu_kind2 == nfc_app::DeviceKind::NFCUnit);
        const int n_opts = is_i2c_dev ? 5 : 4;  // I2C: Emulate/Write/Name/Hex/Delete

        switch (key) {
        case KEY_UP:
        case KEY_F:    modal_idx_ = (modal_idx_ + n_opts - 1) % n_opts; break;
        case KEY_DOWN:
        case KEY_X:    modal_idx_ = (modal_idx_ + 1) % n_opts; break;
        case KEY_ENTER:
            if (modal_idx_ == 0) {
                // Emulate / Upload to Slot
                const bool is_grove = is_i2c_dev;
                if (is_grove && service_.emulation_allowed(&ui_message_)) {
                    const auto &rec = saved_records_[saved_idx_];
                    if (service_.i2c_emulate(rec.tag.protocol, rec, &ui_message_)) {
                        current_tab_ = Tab::Emulator;
                        ui_message_ = "Emulation started";
                    }
                    modal_     = Modal::None;
                    modal_idx_ = 0;
                } else if (service_.emulation_allowed(&ui_message_)) {
                    slot_select_idx_ = service_.selected_slot_index_for_protocol(saved_records_[saved_idx_].tag.protocol);
                    modal_ = Modal::SlotSelect;
                }
            } else if (is_i2c_dev && modal_idx_ == 1) {
                // Write to Tag (NFCUnit only; GroveNFC shows "Hardware not supported")
                const auto &rec = saved_records_[saved_idx_];
                if (!is_nfcunit) {
                    ui_message_ = "Hardware not supported";
                    modal_     = Modal::None;
                    modal_idx_ = 0;
                } else if (rec.tag.protocol != nfc_app::ProtocolKind::MifareClassic &&
                           rec.tag.protocol != nfc_app::ProtocolKind::Iso14443A &&
                           rec.tag.protocol != nfc_app::ProtocolKind::Iso15693) {
                    ui_message_ = "Hardware not supported";
                    modal_     = Modal::None;
                    modal_idx_ = 0;
                } else {
                    // Start async write
                    ui_message_ = "Place tag on NFC Unit...";
                    start_nfcunit_write_async(saved_idx_);
                }
            } else if ((is_i2c_dev && modal_idx_ == 2) || (!is_i2c_dev && modal_idx_ == 1)) {
                // Edit Name
                edit_buf_ = saved_records_[saved_idx_].meta.display_name;
                modal_ = Modal::EditName;
            } else if ((is_i2c_dev && modal_idx_ == 3) || (!is_i2c_dev && modal_idx_ == 2)) {
                // Edit Hex
                const auto &lines = saved_records_[saved_idx_].tag.raw_data;
                edit_hex_line_ = 0;
                edit_buf_ = lines.empty() ? "" : strip_to_hex(lines[0]);
                edit_hex_dirty_ = false;
                modal_ = Modal::EditHex;
            } else {
                // Delete
                std::string err;
                const std::string record_id = saved_records_[saved_idx_].meta.record_id;
                if (service_.delete_saved_record(record_id, &err)) {
                    refresh_saved_records();
                    ui_message_ = "Deleted";
                } else {
                    ui_message_ = err;
                }
                modal_     = Modal::None;
                modal_idx_ = 0;
            }
            break;
        case KEY_ESC:
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    void handle_slot_select_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:    slot_select_idx_ = (slot_select_idx_ + 7) % 8; break;
        case KEY_DOWN:
        case KEY_X:    slot_select_idx_ = (slot_select_idx_ + 1) % 8; break;
        case KEY_ENTER: {
            const auto &record = saved_records_[saved_idx_];
            if (service_.upload_record_to_slot_n(record, slot_select_idx_)) {
                const auto dev_kind = service_.connection_state().device_kind;
                if (dev_kind == nfc_app::DeviceKind::PN532Killer && record.tag.raw_data.size() == 64) {
                    if (service_.hw_start_upload_async(slot_select_idx_, record)) {
                        pending_hw_upload_slot_ = slot_select_idx_;
                        ui_message_ = "Uploading to HW slot " + std::to_string(slot_select_idx_ + 1) + " 0%";
                    } else {
                        ui_message_ = "Slot " + std::to_string(slot_select_idx_ + 1) + " saved (upload busy)";
                    }
                } else {
                    ui_message_ = "Uploaded -> Slot " + std::to_string(slot_select_idx_ + 1) + " (100%)";
                }
            } else {
                ui_message_ = "Upload failed";
            }
            modal_     = Modal::None;
            modal_idx_ = 0;
            break;
        }
        case KEY_ESC:
            modal_ = Modal::Action;
            break;
        default: break;
        }
    }

    void handle_emulator_action_key(uint32_t key)
    {
        const auto conn = service_.connection_state();
        cache_serial_device_kind(conn);
        const auto dev_kind = effective_emu_device_kind(conn);
        const auto endpoint = active_endpoint_for_ui(conn);
        const bool pn532_ndef_menu = (dev_kind == nfc_app::DeviceKind::PN532);
        const bool st25r_mode =
            (dev_kind == nfc_app::DeviceKind::ST25RNFC) ||
            (endpoint.kind == nfc_app::TransportKind::SpiBus && conn.connected);
        const bool grove_mode = (dev_kind == nfc_app::DeviceKind::GroveNFC);
        const bool nfc_unit_mode = !st25r_mode && !grove_mode &&
                                   (dev_kind == nfc_app::DeviceKind::NFCUnit ||
                                    endpoint.kind == nfc_app::TransportKind::I2cBus);
        const bool i2c_emu_mode = !st25r_mode && (grove_mode || nfc_unit_mode);
        const bool i2c_url_mode = i2c_emu_mode &&
            service_.current_emulator_protocol() == nfc_app::ProtocolKind::Iso14443A;
        const int emu_slot = (i2c_emu_mode || st25r_mode) ? 0 : hw_emu_slot_;
        const bool dump_ready = service_.emu_dump_loaded(service_.current_emulator_protocol(), emu_slot);
        const int n_opts = pn532_ndef_menu ? 1 :
                          (st25r_mode ? 4 : (i2c_url_mode ? 4 : 3));
        switch (key) {
        case KEY_UP:
        case KEY_F:    modal_idx_ = (modal_idx_ + n_opts - 1) % n_opts; break;
        case KEY_DOWN:
        case KEY_X:    modal_idx_ = (modal_idx_ + 1) % n_opts; break;
        case KEY_ENTER:
            if (!i2c_emu_mode && !st25r_mode && !service_.emulation_allowed(&ui_message_)) {
                modal_ = Modal::None;
                modal_idx_ = 0;
                break;
            }
            if (pn532_ndef_menu) {
                if (modal_idx_ == 0) {
                    // Edit URI: parse existing URI to pre-fill type + body
                    static const char *PFXS[] = {"https://", "http://", "tel:", "mailto:"};
                    uri_edit_for_nfcunit_ = false;
                    pn532_ndef_type_idx_ = 4; // default: custom
                    pn532_ndef_body_ = pn532_ndef_uri_;
                    for (int i = 0; i < 4; ++i) {
                        const size_t plen = strlen(PFXS[i]);
                        if (pn532_ndef_uri_.size() >= plen &&
                            pn532_ndef_uri_.substr(0, plen) == PFXS[i]) {
                            pn532_ndef_type_idx_ = i;
                            pn532_ndef_body_ = pn532_ndef_uri_.substr(plen);
                            break;
                        }
                    }
                    modal_ = Modal::Pn532NdefInput;
                    modal_idx_ = 0;
                    break;
                }
            }
            if (st25r_mode) {
                if (modal_idx_ == 0) {
                    if (service_.spi_listener_active()) {
                        service_.spi_stop_listener();
                        ui_message_ = "SPI ST25R emulation stopped";
                    } else {
                        std::string emu_err;
                        if (service_.spi_start_current_profile(&emu_err)) {
                            ui_message_ = "SPI ST25R " + service_.spi_profile_label() + " emulating...";
                        } else {
                            ui_message_ = "SPI start failed" +
                                         (emu_err.empty() ? std::string() : (": " + emu_err));
                        }
                    }
                } else if (modal_idx_ == 1) {
                    std::string dump_err;
                    if (service_.cache_i2c_slot_dump(service_.current_emulator_protocol(), emu_slot, &dump_err)) {
                        ui_message_ = "SPI profile dump cached";
                    } else {
                        ui_message_ = "Download failed" +
                                     (dump_err.empty() ? std::string() : (": " + dump_err));
                    }
                } else if (modal_idx_ == 2) {
                    if (!saved_records_.empty()) {
                        if (service_.upload_record_to_profile(service_.current_emulator_protocol(),
                                                              saved_records_[saved_idx_])) {
                            ui_message_ = "Uploaded to SPI profile (100%)";
                        } else {
                            ui_message_ = "Upload failed";
                        }
                    } else {
                        ui_message_ = "Upload failed: no saved data";
                    }
                } else {
                    ui_message_ = "Canceled";
                }
                modal_ = Modal::None;
                modal_idx_ = 0;
                break;
            }
            if (modal_idx_ == 0) {
                // Download Data: pull full block dump from HW slot into cache
                const bool is_i2c_emu = i2c_emu_mode;
                if (is_i2c_emu) {
                    // I2C devs: option 0 is not Download — handle differently
                    if (i2c_url_mode) {
                        // "Set URL"
                        static const char *PFXS_[] = {"https://", "http://", "tel:", "mailto:"};
                        uri_edit_for_nfcunit_ = nfc_unit_mode;
                        uri_edit_for_grove_ = !nfc_unit_mode;
                        pn532_ndef_type_idx_ = 0;
                        pn532_ndef_body_ = "m5stack.com";
                        const std::string cur_uri = service_.nfcunit_ndef_uri();
                        if (!cur_uri.empty()) {
                            pn532_ndef_body_ = cur_uri;
                            for (int pi = 0; pi < 4; ++pi) {
                                const size_t plen = strlen(PFXS_[pi]);
                                if (cur_uri.size() >= plen && cur_uri.substr(0, plen) == PFXS_[pi]) {
                                    pn532_ndef_type_idx_ = pi;
                                    pn532_ndef_body_ = cur_uri.substr(plen);
                                    break;
                                }
                            }
                        }
                        modal_ = Modal::Pn532NdefInput;
                        modal_idx_ = 0;
                        return;
                    } else {
                        // I2C non-NTAG: "Reset Data"
                        const auto proto_r = service_.current_emulator_protocol();
                        bool ok = service_.reset_emulator_json_from_default(proto_r);
                        ui_message_ = ok ? "Reset to default dump" : "Reset failed";
                    }
                } else if (service_.hw_start_emu_dump_async(service_.current_emulator_protocol(), emu_slot)) {
                    ui_message_ = "Downloading slot data...";
                } else {
                    ui_message_ = "Download failed (scan running?)";
                }
            } else if (modal_idx_ == 1) {
                // Upload Data / Activate Emulation — PN532Killer only
                const bool is_i2c_emu = i2c_emu_mode;
                if (is_i2c_emu) {
                    // I2C devs: option 1 is "Reset Data" (NTAG) or N/A
                    if (i2c_url_mode) {
                        const auto proto_r = service_.current_emulator_protocol();
                        bool ok = service_.reset_emulator_json_from_default(proto_r);
                        ui_message_ = ok ? "Reset to default dump" : "Reset failed";
                    }
                } else if (saved_records_.empty()) {
                    ui_message_ = "Upload failed: no saved data";
                } else if (dev_kind == nfc_app::DeviceKind::PN532Killer
                           && saved_records_[saved_idx_].tag.raw_data.size() == 64) {
                    if (service_.hw_start_upload_async(emu_slot, saved_records_[saved_idx_])) {
                        pending_hw_upload_slot_ = emu_slot;
                        ui_message_ = "Uploading to HW slot " + std::to_string(emu_slot + 1) + " 0%";
                    } else {
                        ui_message_ = "Upload failed (busy?)";
                    }
                } else {
                    // Fallback: local slot assignment only
                    if (service_.upload_record_to_slot(saved_records_[saved_idx_])) {
                        ui_message_ = "Uploaded saved data (100%)";
                    } else {
                        ui_message_ = "Upload failed";
                    }
                }
            } else if (modal_idx_ == 2) {
                // PN532Killer: "Reset Data"
                const auto proto_r = service_.current_emulator_protocol();
                bool ok = service_.reset_emulator_json_from_default(proto_r);
                ui_message_ = ok ? "Reset to default dump" : "Reset failed";
            }
            modal_ = Modal::None;
            modal_idx_ = 0;
            break;
        case KEY_ESC:
            modal_ = Modal::None;
            modal_idx_ = 0;
            break;
        default: break;
        }
    }

    void handle_hex_exit_confirm_key(uint32_t key)
    {
        switch (key) {
        case KEY_UP:
        case KEY_F:    modal_idx_ = (modal_idx_ + 2) % 3; break;
        case KEY_DOWN:
        case KEY_X:    modal_idx_ = (modal_idx_ + 1) % 3; break;
        case KEY_ENTER:
            if (modal_idx_ == 0) {
                save_edit_hex(true);
            } else if (modal_idx_ == 1) {
                refresh_saved_records();
                edit_hex_dirty_ = false;
                modal_ = Modal::Action;
                modal_idx_ = 0;
                ui_message_ = "Hex changes discarded";
            } else {
                modal_ = Modal::EditHex;
            }
            break;
        case KEY_ESC:
            modal_ = Modal::EditHex;
            break;
        default: break;
        }
    }

    void handle_edit_name_key(uint32_t key)
    {
        if (key == KEY_ENTER) {
            auto &record = saved_records_[saved_idx_];
            record.meta.display_name = edit_buf_.empty() ? record.meta.display_name : edit_buf_;
            std::string err;
            service_.rename_saved_record(record.meta.record_id, record.meta.display_name, &err);
            ui_message_ = err.empty() ? "Name saved" : "Rename err: " + err;
            modal_     = Modal::None;
            modal_idx_ = 0;
        } else if (key == KEY_ESC) {
            modal_ = Modal::Action;
        } else if (key == KEY_BACKSPACE) {
            if (!edit_buf_.empty()) edit_buf_.pop_back();
        } else {
            char ch = keycode_to_char(key);
            if (ch && edit_buf_.size() < 36) edit_buf_ += ch;
        }
    }

    void handle_edit_hex_key(uint32_t key, uint32_t mods)
    {
        auto &lines = saved_records_[saved_idx_].tag.raw_data;
        const int total = static_cast<int>(lines.size());

        auto commit_current = [&]() {
            if (edit_hex_line_ < total)
                lines[edit_hex_line_] = edit_buf_;  // store as normalized hex
        };

        if ((mods & KBD_MOD_CTRL) && key == KEY_S) {
            commit_current();
            save_edit_hex(false);
        } else if (key == KEY_ESC) {
            commit_current();
            if (edit_hex_dirty_) {
                modal_ = Modal::HexExitConfirm;
                modal_idx_ = 0;
            } else {
                modal_ = Modal::Action;
            }
        } else if (key == KEY_ENTER) {
            commit_current();
            std::vector<std::string> new_lines = lines;
            const int insert_at = new_lines.empty() ? 0 : edit_hex_line_ + 1;
            new_lines.insert(new_lines.begin() + insert_at, std::string());
            lines = new_lines;
            edit_hex_line_ = insert_at;
            edit_buf_.clear();
            edit_hex_dirty_ = true;
        } else if (key == KEY_UP && edit_hex_line_ > 0) {
            commit_current();
            --edit_hex_line_;
            edit_buf_ = strip_to_hex(lines[edit_hex_line_]);
        } else if (key == KEY_DOWN && edit_hex_line_ + 1 < total) {
            commit_current();
            ++edit_hex_line_;
            edit_buf_ = strip_to_hex(lines[edit_hex_line_]);
        } else if (key == KEY_BACKSPACE) {
            if (!edit_buf_.empty()) {
                edit_buf_.pop_back();
                edit_hex_dirty_ = true;
            }
        } else {
            char ch = keycode_to_hex_char(key);
            if (ch && ch != ' ' && ch != ':' && edit_buf_.size() < 80) {
                edit_buf_ += ch;
                edit_hex_dirty_ = true;
            }
        }
    }

    void handle_uid_changer_tool_key(uint32_t key)
    {
        if (key == KEY_ESC) {
            if (uid_changer_step_ > 0) {
                --uid_changer_step_;
                uid_changer_field_idx_ = 0;
            } else {
                modal_ = Modal::None;
            }
            return;
        }

        if (uid_changer_step_ == 0) {
            // [S] key: scan UID from card at any time
            if (key == KEY_S) {
                std::string scanned_uid, scan_err, scanned_type;
                if (service_.scan_uid_once(&scanned_uid, &scan_err, &scanned_type)) {
                    uid_changer_uid_input_ = uid_changer_normalize_hex(scanned_uid, 14);
                    if (uid_changer_uid_input_.size() == 8)  uid_changer_uid_len_idx_ = 0;
                    else if (uid_changer_uid_input_.size() == 14) uid_changer_uid_len_idx_ = 1;
                    uid_changer_fix_generation_for_uid_len();
                    // Auto-rebuild Block 0 from scanned UID
                    uid_changer_block0_manual_ = false;
                    const std::string uid_hex_s = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
                    uid_changer_block0_input_ = uid_changer_build_block0_from_uid(uid_hex_s);
                    // Check if scanned card is Mifare Classic
                    const bool is_mfc = scanned_type.find("MFC") != std::string::npos ||
                                        scanned_type.find("Mifare Classic") != std::string::npos ||
                                        scanned_type.find("MIFARE Classic") != std::string::npos;
                    if (is_mfc) {
                        ui_message_ = "UID scanned " + scanned_type;
                    } else {
                        ui_message_ = "WARNING: Not MFC (" + scanned_type + ")! UID loaded";
                    }
                } else {
                    ui_message_ = scan_err.empty() ? "Scan UID failed" : scan_err;
                }
                return;
            }
            const int field_count = 2; // 0=UID input, 1=Block 0
            if (key == KEY_TAB) {
                uid_changer_uid_len_idx_ = 1 - uid_changer_uid_len_idx_;
                uid_changer_fix_generation_for_uid_len();
                uid_changer_uid_input_ = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
                if (!uid_changer_block0_manual_) {
                    const std::string uid_hex_s = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
                    uid_changer_block0_input_ = uid_changer_build_block0_from_uid(uid_hex_s);
                }
                return;
            }
            if (key == KEY_UP || key == KEY_F) {
                uid_changer_field_idx_ = (uid_changer_field_idx_ + field_count - 1) % field_count;
                return;
            }
            if (key == KEY_DOWN || (uid_changer_field_idx_ != 1 && key == KEY_X)) {
                uid_changer_field_idx_ = (uid_changer_field_idx_ + 1) % field_count;
                return;
            }
            if (uid_changer_field_idx_ == 0) {
                if (key == KEY_BACKSPACE) {
                    if (!uid_changer_uid_input_.empty()) uid_changer_uid_input_.pop_back();
                    if (!uid_changer_block0_manual_) {
                        const std::string uid_hex_s = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
                        uid_changer_block0_input_ = uid_changer_build_block0_from_uid(uid_hex_s);
                    }
                    return;
                }
                const char ch = keycode_to_hex_char(key);
                if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')) {
                    const size_t max_uid = static_cast<size_t>(uid_changer_uid_hex_len());
                    if (uid_changer_uid_input_.size() < max_uid) uid_changer_uid_input_.push_back(ch);
                    if (!uid_changer_block0_manual_) {
                        const std::string uid_hex_s = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
                        uid_changer_block0_input_ = uid_changer_build_block0_from_uid(uid_hex_s);
                    }
                    return;
                }
            }
            if (uid_changer_field_idx_ == 1) {
                if (key == KEY_BACKSPACE) {
                    if (!uid_changer_block0_input_.empty()) {
                        uid_changer_block0_input_.pop_back();
                        uid_changer_block0_manual_ = true;
                    }
                    return;
                }
                const char ch = keycode_to_hex_char(key);
                if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')) {
                    if (uid_changer_block0_input_.size() < 32) {
                        uid_changer_block0_input_.push_back(ch);
                        uid_changer_block0_manual_ = true;
                    }
                    return;
                }
            }
            if (key == KEY_ENTER) {
                const std::string uid_hex = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
                if (uid_hex.size() != static_cast<size_t>(uid_changer_uid_hex_len())) {
                    ui_message_ = "UID incomplete - type or [S] scan";
                    return;
                }
                // BCC validation for 4B UID
                const std::string b0 = uid_changer_normalize_hex(uid_changer_block0_input_, 32);
                if (b0.size() == 32 && uid_changer_uid_len_idx_ == 0) {
                    auto hb = [&](int i) -> uint8_t {
                        auto d = [](char c) -> uint8_t {
                            return (c >= '0' && c <= '9') ? static_cast<uint8_t>(c - '0') : static_cast<uint8_t>(c - 'A' + 10);
                        };
                        return static_cast<uint8_t>((d(b0[i * 2]) << 4) | d(b0[i * 2 + 1]));
                    };
                    const uint8_t expected_bcc = hb(0) ^ hb(1) ^ hb(2) ^ hb(3);
                    const uint8_t got_bcc = hb(4);
                    if (expected_bcc != got_bcc) {
                        char buf[48];
                        std::snprintf(buf, sizeof(buf), "Block 0 BCC: got %02X expect %02X", got_bcc, expected_bcc);
                        ui_message_ = buf;
                        return;
                    }
                }
                uid_changer_step_ = 1;
                uid_changer_field_idx_ = 0;
            }
            return;
        }

        if (uid_changer_step_ == 1) {
            const auto conn = service_.connection_state();
            // NFCUnit supports Gen1A(0), Gen4(3); Gen2(1) is PN532-only.
            // Gen3(2) is disabled in UID Changer.
            if (conn.device_kind == nfc_app::DeviceKind::NFCUnit &&
                uid_changer_generation_idx_ == 1 /* Gen2 */) {
                uid_changer_generation_idx_ = 0; // reset Gen2 to Gen1A
            }
            const int field_count = 2;
            if (key == KEY_UP || key == KEY_F) {
                uid_changer_field_idx_ = (uid_changer_field_idx_ + field_count - 1) % field_count;
                return;
            }
            if (key == KEY_DOWN || key == KEY_X) {
                uid_changer_field_idx_ = (uid_changer_field_idx_ + 1) % field_count;
                return;
            }
            if (key == KEY_TAB) {
                // Tab cycles forward through allowed types.
                // UID Changer disables Gen3(2). NFCUnit also skips Gen2(1).
                int next = uid_changer_generation_idx_;
                for (int i = 0; i < 4; ++i) {
                    next = (next + 1) % 4;
                    if (!uid_changer_generation_allowed(next, uid_changer_uid_len_idx_)) continue;
                    if (conn.device_kind == nfc_app::DeviceKind::NFCUnit &&
                        next == 1 /* Gen2 not supported on NFCUnit */) continue;
                    break;
                }
                uid_changer_generation_idx_ = next;
                return;
            }
            if (key == KEY_ENTER) {
                if (uid_changer_field_idx_ == 1) {
                    uid_changer_step_ = 2;
                    uid_changer_field_idx_ = 0;
                } else {
                    uid_changer_field_idx_ = (uid_changer_field_idx_ + 1) % field_count;
                }
            }
            return;
        }

        int field_count = 0;
        int keya_field = -1;
        int pwd_field = -1;
        int execute_field = -1;
        if (uid_changer_generation_idx_ == 1) {
            keya_field = field_count++;
        } else if (uid_changer_generation_idx_ == 3) {
            pwd_field = field_count++;
        }
        execute_field = field_count++;

        const bool editing_hex = (uid_changer_field_idx_ == keya_field ||
                                  uid_changer_field_idx_ == pwd_field);
        if (key == KEY_UP || (!editing_hex && key == KEY_F)) {
            uid_changer_field_idx_ = (uid_changer_field_idx_ + field_count - 1) % field_count;
            return;
        }
        if (key == KEY_DOWN || (!editing_hex && key == KEY_X)) {
            uid_changer_field_idx_ = (uid_changer_field_idx_ + 1) % field_count;
            return;
        }

        if (key == KEY_BACKSPACE) {
            if (uid_changer_field_idx_ == keya_field && !uid_changer_gen2_keya_input_.empty()) {
                uid_changer_gen2_keya_input_.pop_back();
            } else if (uid_changer_field_idx_ == pwd_field && !uid_changer_gen4_pwd_input_.empty()) {
                uid_changer_gen4_pwd_input_.pop_back();
            }
            return;
        }

        const char ch = keycode_to_hex_char(key);
        if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')) {
            if (uid_changer_field_idx_ == keya_field) {
                if (uid_changer_gen2_keya_input_.size() < 12) uid_changer_gen2_keya_input_.push_back(ch);
                return;
            }
            if (uid_changer_field_idx_ == pwd_field) {
                if (uid_changer_gen4_pwd_input_.size() < 8) uid_changer_gen4_pwd_input_.push_back(ch);
                return;
            }
        }

        if (key != KEY_ENTER) return;

        if (uid_changer_field_idx_ != execute_field) {
            uid_changer_field_idx_ = (uid_changer_field_idx_ + 1) % field_count;
            return;
        }

        const auto conn = service_.connection_state();
        if (!conn.connected ||
            (conn.device_kind != nfc_app::DeviceKind::PN532 &&
             conn.device_kind != nfc_app::DeviceKind::PN532Killer &&
             conn.device_kind != nfc_app::DeviceKind::NFCUnit)) {
            ui_message_ = "Connect PN532/Killer/NFC Unit first";
            return;
        }

        if (conn.device_kind == nfc_app::DeviceKind::NFCUnit &&
            uid_changer_generation() == nfc_app::UidMagicGeneration::Gen2) {
            ui_message_ = "NFC Unit: Gen2 not supported (use Gen1A/Gen4)";
            return;
        }

        if (uid_changer_generation() == nfc_app::UidMagicGeneration::Gen3) {
            ui_message_ = "UID Changer: Gen3 write disabled (use PM3/PN532 tools)";
            return;
        }

        std::string uid_hex = uid_changer_normalize_hex(uid_changer_uid_input_, uid_changer_uid_hex_len());
        if (uid_hex.size() != static_cast<size_t>(uid_changer_uid_hex_len())) {
            ui_message_ = "Invalid UID length";
            return;
        }

        // Use Block 0 from step 0 (uid_changer_block0_input_), fall back to build from UID
        std::string block0_hex = uid_changer_normalize_hex(uid_changer_block0_input_, 32);
        if (block0_hex.size() != 32) {
            block0_hex = uid_changer_build_block0_from_uid(uid_hex);
        }
        if (block0_hex.size() != 32) {
            ui_message_ = "Block 0 build failed";
            return;
        }

        const std::string key_a = uid_changer_normalize_hex(uid_changer_gen2_keya_input_, 12);
        if (key_a.size() != 12) {
            ui_message_ = "KeyA must be 12 hex";
            return;
        }
        const std::string gen4_pwd = uid_changer_normalize_hex(uid_changer_gen4_pwd_input_, 8);
        if (gen4_pwd.size() != 8) {
            ui_message_ = "Gen4 password must be 8 hex";
            return;
        }

        std::string err;
        if (service_.write_magic_uid(uid_changer_generation(), uid_hex, block0_hex, gen4_pwd, key_a, &err)) {
            ui_message_ = "UID write success";
        } else {
            ui_message_ = err.empty() ? "UID write failed" : err;
        }
    }

    void handle_mifare_keys_tool_key(uint32_t key)
    {
        if (mifare_key_editing_) {
            if (key == KEY_ESC) {
                mifare_key_editing_ = false;
                mifare_key_field_idx_ = 0;
                edit_buf_.clear();
                ui_message_ = "Key edit canceled";
                return;
            }
            if (key == KEY_UP) {
                mifare_key_field_idx_ = (mifare_key_field_idx_ + 2) % 3;
                return;
            }
            if (key == KEY_DOWN) {
                mifare_key_field_idx_ = (mifare_key_field_idx_ + 1) % 3;
                return;
            }
            if (key == KEY_TAB || key == KEY_LEFT || key == KEY_RIGHT) {
                if (mifare_key_field_idx_ == 2) {
                    mifare_key_edit_.type = (mifare_key_edit_.type == nfc_app::MifareKeyType::KeyA)
                        ? nfc_app::MifareKeyType::KeyB
                        : nfc_app::MifareKeyType::KeyA;
                }
                return;
            }
            if (key == KEY_BACKSPACE) {
                if (mifare_key_field_idx_ == 0 && !mifare_key_edit_.label.empty()) {
                    mifare_key_edit_.label.pop_back();
                } else if (mifare_key_field_idx_ == 1 && !mifare_key_edit_.key_hex.empty()) {
                    mifare_key_edit_.key_hex.pop_back();
                }
                return;
            }
            if (key == KEY_ENTER) {
                std::string err;
                const int save_index = mifare_key_creating_ ? -1 : mifare_key_idx_;
                if (service_.upsert_mifare_key(save_index, mifare_key_edit_, &err)) {
                    refresh_mifare_keys();
                    if (mifare_key_creating_) mifare_key_idx_ = static_cast<int>(mifare_keys_.size()) - 1;
                    ui_message_ = "Key saved";
                    mifare_key_editing_ = false;
                    mifare_key_field_idx_ = 0;
                } else {
                    ui_message_ = err;
                }
                return;
            }

            if (mifare_key_field_idx_ == 0) {
                char ch = keycode_to_char(key);
                if (ch && mifare_key_edit_.label.size() < 20) mifare_key_edit_.label += ch;
            } else if (mifare_key_field_idx_ == 1) {
                char ch = keycode_to_hex_char(key);
                if (ch && ch != ' ' && ch != ':' && mifare_key_edit_.key_hex.size() < 12) mifare_key_edit_.key_hex += ch;
            }
            return;
        }

        const int total_rows = static_cast<int>(mifare_keys_.size()) + 1;
        if (key == KEY_ESC) {
            if (mifare_keys_file_mode_) {
                if (key_file_editing_) {
                    // Skip browse mode: go directly back to file list
                    key_file_editing_ = false;
                    key_file_dirty_ = false;
                    key_file_keys_.clear();
                    key_file_key_idx_ = 0;
                } else if (!key_file_keys_.empty()) {
                    // Back to file list from browse mode
                    key_file_keys_.clear();
                    key_file_key_idx_ = 0;
                } else {
                    // Exit tool from file list
                    modal_ = Modal::None;
                }
            } else {
                modal_ = Modal::None;
            }
            return;
        }
        // TAB: switch between built-in and file mode
        if (key == KEY_TAB) {
            if (!mifare_keys_file_mode_) {
                mifare_keys_file_mode_ = true;
                refresh_key_files_with_counts();
                key_file_idx_ = 0;
                key_file_keys_.clear();
                key_file_key_idx_ = 0;
                key_file_editing_ = false;
                key_file_dirty_ = false;
            } else {
                mifare_keys_file_mode_ = false;
            }
            return;
        }
        // File mode navigation
        if (mifare_keys_file_mode_) {
            const int fn = static_cast<int>(key_files_.size());
            if (key_file_keys_.empty()) {
                // File list navigation
                if (key == KEY_UP) {
                    if (fn > 0) key_file_idx_ = (key_file_idx_ - 1 + fn) % fn;
                } else if (key == KEY_DOWN) {
                    if (fn > 0) key_file_idx_ = (key_file_idx_ + 1) % fn;
                } else if (key == KEY_ENTER && fn > 0 && key_file_idx_ < fn) {
                    key_file_keys_ = service_.load_key_file(key_files_[static_cast<size_t>(key_file_idx_)]);
                    key_file_key_idx_ = 0;
                    key_file_editing_ = !key_file_keys_.empty(); // enter edit directly
                    key_file_dirty_ = false;
                    if (key_file_keys_.empty()) ui_message_ = "File is empty";
                }
            } else if (!key_file_editing_) {
                // Key list navigation within loaded file
                const int kt = static_cast<int>(key_file_keys_.size());
                if (key == KEY_UP && kt > 0) {
                    key_file_key_idx_ = (key_file_key_idx_ - 1 + kt) % kt;
                } else if (key == KEY_DOWN && kt > 0) {
                    key_file_key_idx_ = (key_file_key_idx_ + 1) % kt;
                } else if (key == KEY_BACKSPACE) {
                    key_file_keys_.clear();
                    key_file_key_idx_ = 0;
                } else if (key == KEY_ENTER && key_file_key_idx_ < kt) {
                    key_file_editing_ = true;
                    key_file_dirty_ = false;
                }
            } else {
                // Dump-style key file editor
                int kt = static_cast<int>(key_file_keys_.size());
                if (kt == 0) {
                    key_file_keys_.push_back("");
                    kt = 1;
                    key_file_key_idx_ = 0;
                }
                if (key == KEY_UP && kt > 0) {
                    key_file_key_idx_ = (key_file_key_idx_ - 1 + kt) % kt;
                } else if (key == KEY_DOWN && kt > 0) {
                    key_file_key_idx_ = (key_file_key_idx_ + 1) % kt;
                } else if (key == KEY_ENTER) {
                    const int insert_at = std::min(key_file_key_idx_ + 1, kt);
                    key_file_keys_.insert(key_file_keys_.begin() + insert_at, std::string());
                    key_file_key_idx_ = insert_at;
                    key_file_dirty_ = true;
                } else if (key == KEY_BACKSPACE) {
                    auto &line = key_file_keys_[static_cast<size_t>(key_file_key_idx_)];
                    if (!line.empty()) {
                        line.pop_back();
                        key_file_dirty_ = true;
                    }
                } else if (key == KEY_DELETE) {
                    if (!key_file_keys_.empty()) {
                        key_file_keys_.erase(key_file_keys_.begin() + key_file_key_idx_);
                        if (key_file_key_idx_ >= static_cast<int>(key_file_keys_.size())) {
                            key_file_key_idx_ = std::max(0, static_cast<int>(key_file_keys_.size()) - 1);
                        }
                        if (key_file_keys_.empty()) key_file_keys_.push_back("");
                        key_file_dirty_ = true;
                    }
                } else if (key == KEY_S) {
                    std::string err;
                    const std::string fname = (key_file_idx_ < fn) ? key_files_[static_cast<size_t>(key_file_idx_)] : "";
                    if (fname.empty()) {
                        ui_message_ = "Missing filename";
                    } else if (service_.save_key_file(fname, key_file_keys_, &err)) {
                        key_file_dirty_ = false;
                        key_file_editing_ = false;
                        refresh_key_files_with_counts();
                        ui_message_ = "Key file saved";
                    } else {
                        ui_message_ = err.empty() ? "Save failed" : err;
                    }
                } else {
                    char ch = keycode_to_hex_char(key);
                    if (ch && ch != ' ' && ch != ':') {
                        auto &line = key_file_keys_[static_cast<size_t>(key_file_key_idx_)];
                        if (line.size() < 12) {
                            line.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
                            key_file_dirty_ = true;
                        }
                    }
                }
            }
            return;
        }
        // Built-in key list navigation
        if (key == KEY_UP) {
            mifare_key_idx_ = (mifare_key_idx_ - 1 + total_rows) % total_rows;
            return;
        }
        if (key == KEY_DOWN) {
            mifare_key_idx_ = (mifare_key_idx_ + 1) % total_rows;
            return;
        }
        if (key == KEY_T && mifare_key_idx_ < static_cast<int>(mifare_keys_.size())) {
            // 'T' key for toggle (TAB is now mode-switch)
            std::string err;
            if (service_.toggle_mifare_key_enabled(mifare_key_idx_, &err)) {
                refresh_mifare_keys();
                ui_message_ = "Key toggled";
            } else {
                ui_message_ = err;
            }
            return;
        }
        if (key == KEY_BACKSPACE && mifare_key_idx_ < static_cast<int>(mifare_keys_.size())) {
            std::string err;
            if (service_.delete_mifare_key(mifare_key_idx_, &err)) {
                refresh_mifare_keys();
                if (mifare_key_idx_ > static_cast<int>(mifare_keys_.size())) mifare_key_idx_ = static_cast<int>(mifare_keys_.size());
                ui_message_ = "Key deleted";
            } else {
                ui_message_ = err;
            }
            return;
        }
        if (key == KEY_ENTER) {
            mifare_key_creating_ = (mifare_key_idx_ >= static_cast<int>(mifare_keys_.size()));
            mifare_key_editing_ = true;
            mifare_key_field_idx_ = 0;
            if (mifare_key_creating_) {
                mifare_key_edit_ = nfc_app::MifareKeyRecord{};
                mifare_key_edit_.created_at = nfc_app::iso8601_now();
            } else {
                mifare_key_edit_ = mifare_keys_[mifare_key_idx_];
            }
            return;
        }
    }

    void handle_mfkey_tool_key(uint32_t key)
    {
        const bool with_card = (active_tool_idx_ == 3);

        // Global: ESC always goes back (or resets step)
        if (key == KEY_ESC) {
            if (mfkey_step_ == 0) {
                modal_ = Modal::None;
            } else {
                // Reset to idle — also switch device back to reader mode if sniffing
                if (mfkey_step_ == 1) {
                    service_.hw_switch_to_reader_mode();
                }
                mfkey_step_      = 0;
                mfkey_uid_input_ = "";
                mfkey_results_.clear();
                mfkey_result_idx_ = 0;
            }
            return;
        }

        if (!with_card) {
            // ── mfkey32v2 flow ──────────────────────────────────────────────
            switch (mfkey_step_) {
            case 0: {
                // UID input — optional
                if (key == KEY_BACKSPACE) {
                    if (!mfkey_uid_input_.empty()) mfkey_uid_input_.pop_back();
                    return;
                }
                if (key == KEY_ENTER) {
                    // If UID provided, set it; if empty, skip set_uid and use device default
                    if (!mfkey_uid_input_.empty()) {
                        if (mfkey_uid_input_.size() < 8) {
                            ui_message_ = "UID must be 8 hex chars (4 bytes)";
                            return;
                        }
                        if (!service_.hw_sniff_set_uid(mfkey_uid_input_)) {
                            ui_message_ = "Failed to set sniffer UID — device connected?";
                            return;
                        }
                    }
                    if (!service_.hw_sniff_enter_mode(false)) {
                        ui_message_ = "Failed to enter sniffer mode";
                        return;
                    }
                    mfkey_step_ = 1;
                    ui_message_ = mfkey_uid_input_.empty()
                        ? "Sniffer active (no UID set). Approach reader."
                        : "Sniffer active (UID set). Approach reader.";
                    return;
                }
                // Hex char input (max 8)
                if (mfkey_uid_input_.size() < 8) {
                    char ch = keycode_to_hex_char(key);
                    if (ch) mfkey_uid_input_ += ch;
                }
                break;
            }
            case 1: {
                // Sniffer active — wait for Enter to stop and crack
                if (key == KEY_ENTER) {
                    // Switch back to reader mode, then start async crack
                    service_.hw_switch_to_reader_mode();
                    mfkey_results_.clear();
                    mfkey_result_idx_ = 0;
                    if (service_.hw_start_mfkey_async(false)) {
                        mfkey_step_ = 2;
                        ui_message_ = "MFKey32v2 cracking...";
                    } else {
                        ui_message_ = "Not connected or already running";
                    }
                }
                break;
            }
            case 2: {
                // Cracking in progress — nothing to do, timer tick advances to step 3
                break;
            }
            default: {
                // Results
                handle_mfkey_results_key(key);
                break;
            }
            }
        } else {
            // ── mfkey64 flow ────────────────────────────────────────────────
            switch (mfkey_step_) {
            case 0: {
                // Ready: Enter enters card-present sniffer mode
                if (key == KEY_ENTER) {
                    if (!service_.hw_sniff_enter_mode(true)) {
                        ui_message_ = "Failed to enter sniffer mode — device connected?";
                        return;
                    }
                    mfkey_step_ = 1;
                    ui_message_ = "Sniffer active (card-present). Hold card near reader.";
                }
                break;
            }
            case 1: {
                // Sniffer active — Enter stops and cracks
                if (key == KEY_ENTER) {
                    service_.hw_switch_to_reader_mode();
                    mfkey_results_.clear();
                    mfkey_result_idx_ = 0;
                    if (service_.hw_start_mfkey_async(true)) {
                        mfkey_step_ = 2;
                        ui_message_ = "MFkey64 cracking...";
                    } else {
                        ui_message_ = "Not connected or already running";
                    }
                }
                break;
            }
            case 2: {
                // Cracking in progress
                break;
            }
            default: {
                handle_mfkey_results_key(key);
                break;
            }
            }
        }
    }

    // Shared result navigation + save for both mfkey tools (step 3+)
    void handle_mfkey_results_key(uint32_t key)
    {
        const bool with_card = (active_tool_idx_ == 3);
        // Save-to-file overlay input handling
        if (mfkey_save_mode_) {
            if (key == KEY_ESC) {
                mfkey_save_mode_ = false;
                mfkey_save_filename_.clear();
            } else if (key == KEY_ENTER) {
                if (mfkey_save_filename_.empty()) {
                    ui_message_ = "Filename required";
                } else {
                    std::vector<std::string> keys;
                    for (const auto &r : mfkey_results_) {
                        if (!r.key_hex.empty()) keys.push_back(r.key_hex);
                    }
                    std::string fname = mfkey_save_filename_;
                    if (fname.find('.') == std::string::npos) fname += ".dic";
                    std::string err;
                    if (service_.save_key_file(fname, keys, &err)) {
                        ui_message_ = "Saved to " + fname;
                        mfkey_save_mode_ = false;
                        mfkey_save_filename_.clear();
                    } else {
                        ui_message_ = err.empty() ? "Save failed" : err;
                    }
                }
            } else if (key == KEY_BACKSPACE) {
                if (!mfkey_save_filename_.empty()) mfkey_save_filename_.pop_back();
            } else {
                char ch = keycode_to_char(key);
                if (ch && ch != ' ' && ch != ',' && mfkey_save_filename_.size() < 24) {
                    mfkey_save_filename_ += ch;
                }
            }
            return;
        }
        switch (key) {
        case KEY_ENTER: {
            if (!mfkey_results_.empty() &&
                mfkey_result_idx_ < static_cast<int>(mfkey_results_.size())) {
                const auto &res = mfkey_results_[static_cast<size_t>(mfkey_result_idx_)];
                if (!res.key_hex.empty()) {
                    std::string err;
                    if (service_.import_mfkey_result(res, &err)) {
                        refresh_mifare_keys();
                        show_toast("Saved");
                        ui_message_ = "Key imported to MIFARE Keys";
                    } else {
                        ui_message_ = err;
                    }
                } else {
                    ui_message_ = "No key to save (not found)";
                }
            }
            break;
        }
        case KEY_R: {
            // Retry: go back to step 0
            mfkey_step_      = 0;
            mfkey_uid_input_ = "";
            mfkey_results_.clear();
            mfkey_result_idx_ = 0;
            ui_message_ = "Retry — reset to step 1";
            break;
        }
        case KEY_UP:
        case KEY_F:
            if (!mfkey_results_.empty())
                mfkey_result_idx_ = (mfkey_result_idx_ - 1 + static_cast<int>(mfkey_results_.size())) % static_cast<int>(mfkey_results_.size());
            break;
        case KEY_DOWN:
        case KEY_X:
            if (!mfkey_results_.empty())
                mfkey_result_idx_ = (mfkey_result_idx_ + 1) % static_cast<int>(mfkey_results_.size());
            break;
        case KEY_S:
            if (!mfkey_results_.empty()) {
                mfkey_save_mode_ = true;
                mfkey_save_filename_.clear();
            }
            break;
        default: break;
        }
        (void)with_card;
    }
};