#include "hal_settings.h"

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------
void hal_time_str(char *buf, int buf_size)
{
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    if (tm_info) {
        strftime(buf, buf_size, "%H:%M", tm_info);
    } else {
        snprintf(buf, buf_size, "--:--");
    }
}

// ---------------------------------------------------------------------------
// Battery (read from sysfs if available, otherwise stub)
// ---------------------------------------------------------------------------
hal_battery_info_t hal_battery_read(void)
{
    hal_battery_info_t info = {0};
    // Try to read capacity from sysfs
    FILE *f = fopen("/sys/class/power_supply/BAT0/capacity", "r");
    if (!f) f = fopen("/sys/class/power_supply/battery/capacity", "r");
    if (f) {
        int soc = 0;
        if (fscanf(f, "%d", &soc) == 1) {
            info.soc   = soc;
            info.valid = 1;
        }
        fclose(f);
    }
    return info;
}

// ---------------------------------------------------------------------------
// Backlight (stub)
// ---------------------------------------------------------------------------
int hal_backlight_read(void)  { return 100; }
int hal_backlight_max(void)   { return 100; }
int hal_backlight_write(int v){ (void)v; return 0; }

// ---------------------------------------------------------------------------
// Volume (stub)
// ---------------------------------------------------------------------------
int hal_volume_read(void)       { return 0; }
int hal_volume_write(int v)     { (void)v; return 0; }

// ---------------------------------------------------------------------------
// WiFi (stub — standalone RFID does not manage WiFi)
// ---------------------------------------------------------------------------
hal_wifi_status_t hal_wifi_get_status(void)
{
    hal_wifi_status_t ws = {0};
    return ws;
}
int hal_wifi_scan(hal_wifi_ap_t *out, int max_aps) { (void)out; (void)max_aps; return 0; }
int hal_wifi_connect(const char *ssid, const char *password) { (void)ssid; (void)password; return -1; }
int hal_wifi_disconnect(void) { return 0; }

// ---------------------------------------------------------------------------
// Bluetooth (stub)
// ---------------------------------------------------------------------------
hal_bt_status_t hal_bt_get_status(void) { hal_bt_status_t s = {0}; return s; }
int hal_bt_set_power(int on)              { (void)on; return 0; }
int hal_bt_scan(hal_bt_device_t *out, int max_devices) { (void)out; (void)max_devices; return 0; }
