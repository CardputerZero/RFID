// RFID Standalone — main.cpp
// Instantiates UINfcPage (ported from APPLaunch) with full original UI.
// Keyboard events are delivered as custom LV_EVENT_KEYBOARD via evdev thread.

#include "lvgl/lvgl.h"

// keyboard_input.h must be included before any C++ headers that use key_item
extern "C" {
#include <keyboard_input.h>
}
extern "C" {
#include "hal/hal_paths.h"
}

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <unistd.h>
#include <pthread.h>
#include <sys/queue.h>

#ifdef __linux__
#include <linux/input.h>
#include <fcntl.h>
#include <errno.h>
#endif

#if LV_USE_SDL
#include "lvgl/src/drivers/sdl/lv_sdl_keyboard.h"
#include "lvgl/src/drivers/sdl/lv_sdl_mouse.h"
#include "lvgl/src/drivers/sdl/lv_sdl_window.h"
#endif

#if LV_USE_LINUX_FBDEV
#include "lvgl/src/drivers/display/fb/lv_linux_fbdev.h"
#endif

#if LV_USE_LINUX_DRM
#include "lvgl/src/drivers/display/drm/lv_linux_drm.h"
#endif

// Must be included after LVGL and keyboard_input.h
#include "page_app/ui_app_nfc.hpp"

// ---------------------------------------------------------------------------
// Globals defined here (declared extern in keyboard_input.h / ui.h)
// ---------------------------------------------------------------------------
volatile uint32_t LV_EVENT_KEYBOARD = 0;
volatile uint32_t LV_EVENT_BATTERY  = 0;
volatile sig_atomic_t g_quit_requested = 0;
lv_font_t *g_font_mono_12 = nullptr;  // set in main() if freetype available

// ---------------------------------------------------------------------------
// Key queue: keyboard thread -> LVGL indev callback (thread-safe)
// ---------------------------------------------------------------------------
struct queued_key {
    uint32_t linux_keycode;
    uint32_t codepoint;
    char     utf8[8];
    int      state;           // 0=released, 1=pressed, 2=repeated
    STAILQ_ENTRY(queued_key) entries;
};
STAILQ_HEAD(key_queue_t, queued_key);
static key_queue_t     g_key_queue = STAILQ_HEAD_INITIALIZER(g_key_queue);
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static void on_signal(int sig)
{
    (void)sig;
    g_quit_requested = 1;
}

// ---------------------------------------------------------------------------
// Modifier tracking
// ---------------------------------------------------------------------------
static bool g_shift_active = false;
static bool g_ctrl_active  = false;
static bool g_alt_active   = false;

// ---------------------------------------------------------------------------
// Evdev keycode -> printable ASCII (unshifted/shifted)
// ---------------------------------------------------------------------------
static uint32_t keycode_to_codepoint(uint32_t keycode, bool shift, bool alt, char *utf8_out)
{
    // Cardputer Sym-layer extended keycodes emitted by some keyboard stacks.
    // Keep these explicit so URI/text input can receive punctuation reliably.
    switch (keycode) {
        case 183: if (utf8_out) { utf8_out[0] = '!'; utf8_out[1] = '\0'; } return '!';
        case 184: if (utf8_out) { utf8_out[0] = '@'; utf8_out[1] = '\0'; } return '@';
        case 185: if (utf8_out) { utf8_out[0] = '#'; utf8_out[1] = '\0'; } return '#';
        case 186: if (utf8_out) { utf8_out[0] = '$'; utf8_out[1] = '\0'; } return '$';
        case 187: if (utf8_out) { utf8_out[0] = '%'; utf8_out[1] = '\0'; } return '%';
        case 188: if (utf8_out) { utf8_out[0] = '^'; utf8_out[1] = '\0'; } return '^';
        case 189: if (utf8_out) { utf8_out[0] = '&'; utf8_out[1] = '\0'; } return '&';
        case 190: if (utf8_out) { utf8_out[0] = '*'; utf8_out[1] = '\0'; } return '*';
        case 191: if (utf8_out) { utf8_out[0] = '('; utf8_out[1] = '\0'; } return '(';
        case 192: if (utf8_out) { utf8_out[0] = ')'; utf8_out[1] = '\0'; } return ')';
        case 193: if (utf8_out) { utf8_out[0] = '~'; utf8_out[1] = '\0'; } return '~';
        case 194: if (utf8_out) { utf8_out[0] = '`'; utf8_out[1] = '\0'; } return '`';
        case 195: if (utf8_out) { utf8_out[0] = '+'; utf8_out[1] = '\0'; } return '+';
        case 196: if (utf8_out) { utf8_out[0] = '-'; utf8_out[1] = '\0'; } return '-';
        case 197: if (utf8_out) { utf8_out[0] = '/'; utf8_out[1] = '\0'; } return '/';
        case 198: if (utf8_out) { utf8_out[0] = '\\'; utf8_out[1] = '\0'; } return '\\';
        case 199: if (utf8_out) { utf8_out[0] = '{'; utf8_out[1] = '\0'; } return '{';
        case 200: if (utf8_out) { utf8_out[0] = '}'; utf8_out[1] = '\0'; } return '}';
        case 201: if (utf8_out) { utf8_out[0] = '['; utf8_out[1] = '\0'; } return '[';
        case 202: if (utf8_out) { utf8_out[0] = ']'; utf8_out[1] = '\0'; } return ']';
        case 203:
        case 233: if (utf8_out) { utf8_out[0] = '|'; utf8_out[1] = '\0'; } return '|';
        case 204:
        case 209: if (utf8_out) { utf8_out[0] = '='; utf8_out[1] = '\0'; } return '=';
        case 205:
        case 210: if (utf8_out) { utf8_out[0] = ':'; utf8_out[1] = '\0'; } return ':';
        case 206:
        case 211: if (utf8_out) { utf8_out[0] = ';'; utf8_out[1] = '\0'; } return ';';
        case 207:
        case 212: if (utf8_out) { utf8_out[0] = '_'; utf8_out[1] = '\0'; } return '_';
        case 208:
        case 213: if (utf8_out) { utf8_out[0] = '?'; utf8_out[1] = '\0'; } return '?';
        case 214: if (utf8_out) { utf8_out[0] = '<'; utf8_out[1] = '\0'; } return '<';
        case 215: if (utf8_out) { utf8_out[0] = '>'; utf8_out[1] = '\0'; } return '>';
        case 216: if (utf8_out) { utf8_out[0] = '\''; utf8_out[1] = '\0'; } return '\'';
        case 217: if (utf8_out) { utf8_out[0] = '"'; utf8_out[1] = '\0'; } return '"';
        case 231: if (utf8_out) { utf8_out[0] = ','; utf8_out[1] = '\0'; } return ',';
        case 232: if (utf8_out) { utf8_out[0] = '.'; utf8_out[1] = '\0'; } return '.';
        default: break;
    }

    struct { uint32_t code; char lo; char hi; } table[] = {
        {KEY_A,'a','A'}, {KEY_B,'b','B'}, {KEY_C,'c','C'}, {KEY_D,'d','D'},
        {KEY_E,'e','E'}, {KEY_F,'f','F'}, {KEY_G,'g','G'}, {KEY_H,'h','H'},
        {KEY_I,'i','I'}, {KEY_J,'j','J'}, {KEY_K,'k','K'}, {KEY_L,'l','L'},
        {KEY_M,'m','M'}, {KEY_N,'n','N'}, {KEY_O,'o','O'}, {KEY_P,'p','P'},
        {KEY_Q,'q','Q'}, {KEY_R,'r','R'}, {KEY_S,'s','S'}, {KEY_T,'t','T'},
        {KEY_U,'u','U'}, {KEY_V,'v','V'}, {KEY_W,'w','W'}, {KEY_X,'x','X'},
        {KEY_Y,'y','Y'}, {KEY_Z,'z','Z'},
        {KEY_0,'0',')'}, {KEY_1,'1','!'}, {KEY_2,'2','@'}, {KEY_3,'3','#'},
        {KEY_4,'4','$'}, {KEY_5,'5','%'}, {KEY_6,'6','^'}, {KEY_7,'7','&'},
        {KEY_8,'8','*'}, {KEY_9,'9','('},
        {KEY_SPACE,' ',' '},
        {KEY_MINUS,'-','_'}, {KEY_EQUAL,'=','+'}, {KEY_LEFTBRACE,'[','{'},
        {KEY_RIGHTBRACE,']','}'}, {KEY_SEMICOLON,';',':'}, {KEY_APOSTROPHE,'\'','"'},
        {KEY_GRAVE,'`','~'}, {KEY_BACKSLASH,'\\','|'}, {KEY_COMMA,',','<'},
        {KEY_DOT,'.','>'}, {KEY_SLASH,'/','?'},
    };
    for (size_t i = 0; i < sizeof(table)/sizeof(table[0]); i++) {
        if (table[i].code == keycode) {
            char c = (shift || alt) ? table[i].hi : table[i].lo;
            if (utf8_out) { utf8_out[0] = c; utf8_out[1] = '\0'; }
            return (uint32_t)(unsigned char)c;
        }
    }
    if (alt) {
        if (keycode == KEY_1) { if (utf8_out) { utf8_out[0] = '!'; utf8_out[1] = '\0'; } return '!'; }
        if (keycode == KEY_2) { if (utf8_out) { utf8_out[0] = '@'; utf8_out[1] = '\0'; } return '@'; }
        if (keycode == KEY_3) { if (utf8_out) { utf8_out[0] = '#'; utf8_out[1] = '\0'; } return '#'; }
        if (keycode == KEY_4) { if (utf8_out) { utf8_out[0] = '$'; utf8_out[1] = '\0'; } return '$'; }
        if (keycode == KEY_5) { if (utf8_out) { utf8_out[0] = '%'; utf8_out[1] = '\0'; } return '%'; }
        if (keycode == KEY_6) { if (utf8_out) { utf8_out[0] = '^'; utf8_out[1] = '\0'; } return '^'; }
        if (keycode == KEY_7) { if (utf8_out) { utf8_out[0] = '&'; utf8_out[1] = '\0'; } return '&'; }
        if (keycode == KEY_8) { if (utf8_out) { utf8_out[0] = '*'; utf8_out[1] = '\0'; } return '*'; }
        if (keycode == KEY_9) { if (utf8_out) { utf8_out[0] = '('; utf8_out[1] = '\0'; } return '('; }
        if (keycode == KEY_0) { if (utf8_out) { utf8_out[0] = ')'; utf8_out[1] = '\0'; } return ')'; }
        if (keycode == KEY_MINUS) { if (utf8_out) { utf8_out[0] = '_'; utf8_out[1] = '\0'; } return '_'; }
        if (keycode == KEY_EQUAL) { if (utf8_out) { utf8_out[0] = '+'; utf8_out[1] = '\0'; } return '+'; }
        if (keycode == KEY_COMMA) { if (utf8_out) { utf8_out[0] = '<'; utf8_out[1] = '\0'; } return '<'; }
        if (keycode == KEY_DOT) { if (utf8_out) { utf8_out[0] = '>'; utf8_out[1] = '\0'; } return '>'; }
        if (keycode == KEY_SLASH) { if (utf8_out) { utf8_out[0] = '?'; utf8_out[1] = '\0'; } return '?'; }
        if (keycode == KEY_SEMICOLON) { if (utf8_out) { utf8_out[0] = ':'; utf8_out[1] = '\0'; } return ':'; }
        if (keycode == KEY_APOSTROPHE) { if (utf8_out) { utf8_out[0] = '"'; utf8_out[1] = '\0'; } return '"'; }
        if (keycode == KEY_GRAVE) { if (utf8_out) { utf8_out[0] = '~'; utf8_out[1] = '\0'; } return '~'; }
        if (keycode == KEY_LEFTBRACE) { if (utf8_out) { utf8_out[0] = '{'; utf8_out[1] = '\0'; } return '{'; }
        if (keycode == KEY_RIGHTBRACE) { if (utf8_out) { utf8_out[0] = '}'; utf8_out[1] = '\0'; } return '}'; }
        if (keycode == KEY_BACKSLASH) { if (utf8_out) { utf8_out[0] = '|'; utf8_out[1] = '\0'; } return '|'; }
    }
    if (utf8_out) utf8_out[0] = '\0';
    return 0;
}

static void enqueue_key(uint32_t linux_keycode, int state)
{
    struct queued_key *qk = (struct queued_key *)malloc(sizeof(*qk));
    if (!qk) return;
    memset(qk, 0, sizeof(*qk));
    qk->linux_keycode = linux_keycode;
    qk->state         = state;
    if (state > 0) {
        qk->codepoint = keycode_to_codepoint(linux_keycode, g_shift_active, g_alt_active, qk->utf8);
    }
    pthread_mutex_lock(&g_key_mutex);
    STAILQ_INSERT_TAIL(&g_key_queue, qk, entries);
    pthread_mutex_unlock(&g_key_mutex);
}

// ---------------------------------------------------------------------------
// Keyboard thread — reads raw Linux evdev
// ---------------------------------------------------------------------------
#ifdef __linux__
static void *rfid_keyboard_thread(void *arg)
{
    (void)arg;
    const char *dev_path = hal_path_keyboard_device();
    int fd = -1;
    for (int attempt = 0; attempt < 20 && fd < 0; attempt++) {
        fd = open(dev_path, O_RDONLY | O_NONBLOCK);
        if (fd < 0) usleep(200000);
    }
    if (fd < 0) {
        fprintf(stderr, "[RFID] Cannot open keyboard %s: %s\n", dev_path, strerror(errno));
        return NULL;
    }

    struct input_event ev;
    while (!g_quit_requested) {
        ssize_t n = read(fd, &ev, sizeof(ev));
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(5000); continue; }
            break;
        }
        if (n < (ssize_t)sizeof(ev)) continue;
        if (ev.type != EV_KEY) continue;

        if (ev.code == KEY_LEFTSHIFT || ev.code == KEY_RIGHTSHIFT)
            g_shift_active = (ev.value > 0);
        if (ev.code == KEY_LEFTCTRL || ev.code == KEY_RIGHTCTRL)
            g_ctrl_active = (ev.value > 0);
        if (ev.code == KEY_LEFTALT || ev.code == KEY_RIGHTALT)
            g_alt_active = (ev.value > 0);

        enqueue_key(ev.code, ev.value);
    }
    close(fd);
    return NULL;
}
#endif

// ---------------------------------------------------------------------------
// LVGL indev callback — dispatches LV_EVENT_KEYBOARD on the LVGL thread
// ---------------------------------------------------------------------------
static void keypad_read_cb(lv_indev_t *indev, lv_indev_data_t *data)
{
    (void)indev;
    data->state = LV_INDEV_STATE_RELEASED;
    data->key   = 0;
    data->continue_reading = false;

    pthread_mutex_lock(&g_key_mutex);
    bool has_key = !STAILQ_EMPTY(&g_key_queue);
    struct queued_key *qk = has_key ? STAILQ_FIRST(&g_key_queue) : nullptr;
    if (has_key) STAILQ_REMOVE_HEAD(&g_key_queue, entries);
    pthread_mutex_unlock(&g_key_mutex);

    if (!has_key) return;

    struct key_item ki;
    memset(&ki, 0, sizeof(ki));
    ki.key_code  = qk->linux_keycode;
    ki.key_state = qk->state;
    ki.codepoint = qk->codepoint;
    if (qk->utf8[0]) memcpy(ki.utf8, qk->utf8, sizeof(ki.utf8));
    if (g_shift_active) ki.mods |= KBD_MOD_SHIFT;
    if (g_ctrl_active)  ki.mods |= KBD_MOD_CTRL;
    if (g_alt_active)   ki.mods |= KBD_MOD_ALT;
    free(qk);

    lv_obj_t *root = lv_screen_active();
    if (root) lv_obj_send_event(root, (lv_event_code_t)LV_EVENT_KEYBOARD, &ki);

    pthread_mutex_lock(&g_key_mutex);
    data->continue_reading = !STAILQ_EMPTY(&g_key_queue);
    pthread_mutex_unlock(&g_key_mutex);
}

// ---------------------------------------------------------------------------
// Display + input init
// ---------------------------------------------------------------------------

// Probe /proc/fb for the fb_st7789v framebuffer (same logic as APPLaunch).
// Falls back to LV_FBDEV env, then /dev/fb0, then /dev/fb1 in that order.
static const char *find_fbdev(char *buf, size_t buf_size)
{
    const char *env = getenv("LV_FBDEV");
    if (env && env[0] != '\0') return env;

    FILE *fp = fopen("/proc/fb", "r");
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, "fb_st7789v")) {
                int num = -1;
                if (sscanf(line, "%d", &num) == 1 && num >= 0) {
                    fclose(fp);
                    snprintf(buf, buf_size, "/dev/fb%d", num);
                    return buf;
                }
            }
        }
        fclose(fp);
    }
    // Try fb0 first, then fb1
    if (access("/dev/fb0", F_OK) == 0) { snprintf(buf, buf_size, "/dev/fb0"); return buf; }
    snprintf(buf, buf_size, "/dev/fb1");
    return buf;
}

static void init_display(void)
{
#if LV_USE_SDL
    lv_sdl_window_create(320, 170);
#elif LV_USE_LINUX_FBDEV
    char fb_buf[64] = {0};
    const char *fb = find_fbdev(fb_buf, sizeof(fb_buf));
    printf("[RFID] Using framebuffer: %s\n", fb);
    fflush(stdout);
    lv_display_t *disp = lv_linux_fbdev_create();
    if (!disp) { fprintf(stderr, "[RFID] lv_linux_fbdev_create failed\n"); return; }
    lv_linux_fbdev_set_file(disp, fb);
#elif LV_USE_LINUX_DRM
    lv_linux_drm_create();
#endif
}

static void init_input(void)
{
#if LV_USE_SDL
    lv_sdl_mouse_create();
    lv_sdl_keyboard_create();
#elif __linux__
    pthread_t tid;
    pthread_create(&tid, NULL, rfid_keyboard_thread, NULL);
    pthread_detach(tid);

    lv_indev_t *indev = lv_indev_create();
    lv_indev_set_type(indev, LV_INDEV_TYPE_KEYPAD);
    lv_indev_set_read_cb(indev, keypad_read_cb);
#endif
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void)
{
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    hal_paths_init(nullptr);
    lv_init();

    LV_EVENT_KEYBOARD = lv_event_register_id();
    LV_EVENT_BATTERY  = lv_event_register_id();

    init_display();
    init_input();

    UINfcPage *nfc_page = new UINfcPage();
    nfc_page->go_back_home = []() { g_quit_requested = 1; };

    lv_screen_load(nfc_page->get_ui());

    while (!g_quit_requested) {
        lv_timer_handler();
        usleep(5000);
    }

    delete nfc_page;
    return 0;
}
