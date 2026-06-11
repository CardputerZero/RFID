#include "hal_paths.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RFID_APP_PREFIX "/usr/share/APPLaunch/apps/rfid"
#define APPLAUNCH_PREFIX "/usr/share/APPLaunch"

static char s_data_dir[512]         = RFID_APP_PREFIX;
static char s_applications_dir[512] = APPLAUNCH_PREFIX "/applications";
static char s_store_cache_dir[512]  = "/var/cache/APPLaunch/store";
static char s_lock_file[512]        = "/tmp/M5CardputerZero-RFID_fcntl.lock";
static char s_font_dir[512]         = APPLAUNCH_PREFIX "/share/font";
static char s_font_regular[512]     = APPLAUNCH_PREFIX "/share/font/AlibabaPuHuiTi-3-55-Regular.ttf";
static char s_font_mono[512]        = APPLAUNCH_PREFIX "/share/font/LiberationMono-Regular.ttf";
static char s_images_dir[512]       = "share/images";
static char s_audio_dir[512]        = RFID_APP_PREFIX "/share/audio";
static char s_nfc_dumps_dir[512]    = "/home/pi/rfid/dumps";
static char s_nfc_keys_dir[512]     = "/home/pi/rfid/keys";
static char s_mfkey_bin_dir[512]    = RFID_APP_PREFIX "/bin";
static char s_nfc_log_dir[512]      = "/home/pi/rfid/logs";
static const char *KBD_DEVICE       = "/dev/input/by-path/platform-3f804000.i2c-event";
static const char *KBD_MAP          = "/usr/share/keymaps/tca8418_keypad_m5stack_keymap.map";
static char s_store_sync_cmd[512]   = "python3 " APPLAUNCH_PREFIX "/bin/store_cache_sync.py";

static const char *env_or_empty(const char *name)
{
    const char *value = getenv(name);
    return (value && value[0]) ? value : "";
}

void hal_paths_init(const char *exe_dir)
{
    const char *root = env_or_empty("M5CZ_RFID_APP_DIR");
    if (exe_dir && exe_dir[0]) {
        root = exe_dir;
    } else if (!root[0]) {
        root = (access(RFID_APP_PREFIX, F_OK) == 0) ? RFID_APP_PREFIX : ".";
    }

    const char *nfc_root = env_or_empty("M5CZ_NFC_ROOT_DIR");
    const char *nfc_records = env_or_empty("M5CZ_NFC_RECORDS_DIR");
    const char *nfc_keys = env_or_empty("M5CZ_NFC_KEYS_DIR");

    snprintf(s_data_dir, sizeof(s_data_dir), "%s", root);
    snprintf(s_audio_dir, sizeof(s_audio_dir), "%s/share/audio", root);
    snprintf(s_mfkey_bin_dir, sizeof(s_mfkey_bin_dir), "%s/bin", root);

    if (nfc_records[0]) {
        snprintf(s_nfc_dumps_dir, sizeof(s_nfc_dumps_dir), "%s", nfc_records);
    } else if (nfc_root[0]) {
        snprintf(s_nfc_dumps_dir, sizeof(s_nfc_dumps_dir), "%s/dumps", nfc_root);
    } else {
        const char *home = getenv("HOME");
        if (home && home[0]) snprintf(s_nfc_dumps_dir, sizeof(s_nfc_dumps_dir), "%s/rfid/dumps", home);
        else snprintf(s_nfc_dumps_dir, sizeof(s_nfc_dumps_dir), "%s/share/nfc/records", root);
    }

    if (nfc_keys[0]) snprintf(s_nfc_keys_dir, sizeof(s_nfc_keys_dir), "%s", nfc_keys);
    else {
        const char *home = getenv("HOME");
        if (home && home[0]) snprintf(s_nfc_keys_dir, sizeof(s_nfc_keys_dir), "%s/rfid/keys", home);
        else snprintf(s_nfc_keys_dir, sizeof(s_nfc_keys_dir), "%s/share/nfc/keys", root);
    }

    if (nfc_root[0]) snprintf(s_nfc_log_dir, sizeof(s_nfc_log_dir), "%s/log", nfc_root);
}

const char *hal_path_data_dir(void)         { return s_data_dir; }
const char *hal_path_applications_dir(void) { return s_applications_dir; }
const char *hal_path_store_cache_dir(void)  { return s_store_cache_dir; }
const char *hal_path_lock_file(void)        { return s_lock_file; }
const char *hal_path_font_dir(void)         { return s_font_dir; }
const char *hal_path_font_regular(void)     { return s_font_regular; }
const char *hal_path_font_mono(void)        { return s_font_mono; }
const char *hal_path_keyboard_device(void)  { return KBD_DEVICE; }
const char *hal_path_keyboard_map(void)     { return KBD_MAP; }
const char *hal_path_store_sync_cmd(void)   { return s_store_sync_cmd; }
const char *hal_path_images_dir(void)       { return s_images_dir; }
const char *hal_path_audio_dir(void)        { return s_audio_dir; }
const char *hal_path_nfc_dumps_dir(void)    { return s_nfc_dumps_dir; }
const char *hal_path_nfc_keys_dir(void)     { return s_nfc_keys_dir; }
const char *hal_path_mfkey_bin_dir(void)    { return s_mfkey_bin_dir; }
const char *hal_path_nfc_log_dir(void)      { return s_nfc_log_dir; }
