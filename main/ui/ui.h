#pragma once
// Minimal RFID-standalone stub — replaces APPLaunch's SquareLine-generated ui.h

#include "lvgl/lvgl.h"
#ifdef __cplusplus
#include <keyboard_input.h>
#endif

// Keyboard event macros (same layout as APPLaunch ui.h)
#define LV_EVENT_KEYBOARD_GET_KEY(e)       (((struct key_item *)lv_event_get_param(e))->key_code)
#define LV_EVENT_KEYBOARD_GET_KEY_STATE(e) (((struct key_item *)lv_event_get_param(e))->key_state)
#define IS_KEY_PRESSED(e)  ((lv_event_get_code(e) == (lv_event_code_t)LV_EVENT_KEYBOARD) && (LV_EVENT_KEYBOARD_GET_KEY_STATE(e) > 0))
#define IS_KEY_RELEASED(e) ((lv_event_get_code(e) == (lv_event_code_t)LV_EVENT_KEYBOARD) && (LV_EVENT_KEYBOARD_GET_KEY_STATE(e) == 0))

// Battery event (stub — standalone app has no battery event source)
#ifdef __cplusplus
extern "C" {
#endif
extern volatile uint32_t LV_EVENT_BATTERY;
#ifdef __cplusplus
}
#include "hal/hal_settings.h"
#define LV_EVENT_BATTERY_GET_INFO(e) ((hal_battery_info_t *)lv_event_get_param(e))
#endif

// LVGL 8→9 compat shims
#ifndef lv_mem_alloc
#define lv_mem_alloc lv_malloc
#endif
#ifndef lv_mem_free
#define lv_mem_free  lv_free
#endif
#ifndef lv_event_send
#define lv_event_send(obj, evt, param) lv_obj_send_event(obj, evt, param)
#endif

#define PATH_SEP "/"

// Mono font loaded at runtime (falls back to montserrat_12)
extern lv_font_t *g_font_mono_12;
