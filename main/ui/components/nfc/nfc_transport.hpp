#pragma once

#include "nfc_models.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <deque>
#include <dirent.h>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/i2c-dev.h>
#include <linux/i2c.h>     // I2C_SMBUS_WRITE/READ/QUICK (moved here in kernel ≥ 3.4)
#include <cstdio>          // fopen / fwrite
#include <cstring>         // strerror
#endif
#ifndef I2C_SLAVE
#define I2C_SLAVE 0x0703
#endif
// Fallback defines for minimal cross-compilation sysroots that ship a stripped
// linux/i2c-dev.h without pulling in the SMBus constant / struct definitions.
#ifndef I2C_SMBUS_WRITE
# define I2C_SMBUS_WRITE   0
#endif
#ifndef I2C_SMBUS_READ
# define I2C_SMBUS_READ    1
#endif
#ifndef I2C_SMBUS_QUICK
# define I2C_SMBUS_QUICK   0
#endif
#ifndef I2C_SMBUS
# define I2C_SMBUS         0x0720
#endif
#ifndef I2C_SMBUS_BLOCK_MAX
# define I2C_SMBUS_BLOCK_MAX 32
  union i2c_smbus_data {
      uint8_t  byte;
      uint16_t word;
      uint8_t  block[I2C_SMBUS_BLOCK_MAX + 2];
  };
  struct i2c_smbus_ioctl_data {
      uint8_t              read_write;
      uint8_t              command;
      uint32_t             size;
      union i2c_smbus_data *data;
  };
#endif
#endif

namespace nfc_app {

struct TransportEndpoint {
    TransportKind kind = TransportKind::Mock;
    std::string path;
    std::string label;
    int baud_rate = 115200;
    int usb_vid = -1;
    int usb_pid = -1;
};

class INfcTransport {
public:
    virtual ~INfcTransport() = default;
    virtual bool open(const TransportEndpoint &endpoint, std::string *error) = 0;
    virtual void close() = 0;
    virtual bool is_open() const = 0;
    virtual ssize_t write_bytes(const uint8_t *data, size_t size, std::string *error) = 0;
    virtual ssize_t read_bytes(uint8_t *buffer, size_t size, int timeout_ms, std::string *error) = 0;
    virtual TransportEndpoint endpoint() const = 0;
};

class MockTransport : public INfcTransport {
public:
    bool open(const TransportEndpoint &endpoint, std::string *error) override
    {
        endpoint_ = endpoint;
        open_ = true;
        if (error) error->clear();
        return true;
    }

    void close() override
    {
        open_ = false;
    }

    bool is_open() const override
    {
        return open_;
    }

    ssize_t write_bytes(const uint8_t *data, size_t size, std::string *error) override
    {
        (void)data;
        if (!open_) {
            if (error) *error = "mock transport not open";
            return -1;
        }
        if (error) error->clear();
        return static_cast<ssize_t>(size);
    }

    ssize_t read_bytes(uint8_t *buffer, size_t size, int timeout_ms, std::string *error) override
    {
        (void)buffer;
        (void)size;
        (void)timeout_ms;
        if (!open_) {
            if (error) *error = "mock transport not open";
            return -1;
        }
        if (error) error->clear();
        return 0;
    }

    TransportEndpoint endpoint() const override
    {
        return endpoint_;
    }

private:
    TransportEndpoint endpoint_;
    bool open_ = false;
};

class SerialTransport : public INfcTransport {
public:
    ~SerialTransport() override
    {
        close();
    }

    bool open(const TransportEndpoint &endpoint, std::string *error) override
    {
        close();
        endpoint_ = endpoint;

#ifdef _WIN32
        if (error) *error = "serial transport unsupported on Windows in v1";
        return false;
#else
        // Open with O_NONBLOCK so open() doesn't hang waiting for DCD/carrier
        // (CH340 and similar USB-serial chips never assert DCD).
        // After open we clear O_NONBLOCK via fcntl so that write() blocks until
        // bytes are fully queued in the kernel tty buffer.
        fd_ = ::open(endpoint.path.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
        if (fd_ < 0) {
            if (error) *error = std::string("open failed: ") + std::strerror(errno);
            return false;
        }
        // Clear O_NONBLOCK so subsequent write()s are reliable
        int flags = fcntl(fd_, F_GETFL, 0);
        if (flags >= 0) fcntl(fd_, F_SETFL, flags & ~O_NONBLOCK);

        struct termios options;
        if (tcgetattr(fd_, &options) != 0) {
            if (error) *error = std::string("tcgetattr failed: ") + std::strerror(errno);
            close();
            return false;
        }

        cfmakeraw(&options);
        cfsetispeed(&options, baud_to_constant(endpoint.baud_rate));
        cfsetospeed(&options, baud_to_constant(endpoint.baud_rate));
        options.c_cflag |= (CLOCAL | CREAD);
        options.c_cflag &= ~CRTSCTS;
        options.c_cflag &= ~PARENB;
        options.c_cflag &= ~CSTOPB;
        options.c_cflag &= ~CSIZE;
        options.c_cflag |= CS8;
        options.c_cc[VMIN] = 0;
        options.c_cc[VTIME] = 1; // 100 ms kernel-level timeout; matched to Python timeout=0.1
        options.c_cflag &= ~HUPCL; // don't lower DTR on close

        if (tcsetattr(fd_, TCSANOW, &options) != 0) {
            if (error) *error = std::string("tcsetattr failed: ") + std::strerror(errno);
            close();
            return false;
        }

        // DTR/RTS handling differs between device types on macOS:
        //
        // PN532Killer (CDC-ACM, /dev/cu.usbmodem*):
        //   Needs DTR=HIGH → DTR=LOW to boot into normal mode.
        //   If DTR stays HIGH, the USB bridge stays in a firmware-update mode
        //   and ignores all PN532 commands.
        //
        // Plain PN532 (USB-serial adapter /dev/cu.usbserial*, e.g. CH340):
        //   DTR is often connected to nRST through a capacitor.
        //   Keeping DTR=HIGH lets the chip run; pulling LOW holds it in reset.
        //   Python pyserial uses DTR=HIGH (default) and works for both cases.
        //
        // Detect by port name:
        //   macOS CDC-ACM: cu.usbmodem*
        //   Linux CDC-ACM: ttyACM*
        // Both need the DTR pulse; plain PN532 / CH340 (ttyUSB*, cu.usbserial*, etc.) keep DTR HIGH.
        const bool is_cdc_acm = endpoint.path.find("usbmodem") != std::string::npos
                             || endpoint.path.find("ttyACM")   != std::string::npos;
        if (is_cdc_acm) {
            // PN532Killer: pulse HIGH → LOW, then stay LOW
            int bits = TIOCM_DTR | TIOCM_RTS;
            ioctl(fd_, TIOCMBIS, &bits);  // HIGH
            usleep(100000);               // 100 ms hold
            ioctl(fd_, TIOCMBIC, &bits);  // LOW
            usleep(10000);                // 10 ms settle
        } else {
            // Plain PN532 / CH340: set DTR=HIGH and keep it
            int bits = TIOCM_DTR | TIOCM_RTS;
            ioctl(fd_, TIOCMBIS, &bits);
            usleep(50000);                // 50 ms: let chip stabilise
        }

        // Only flush RX stale bytes; do NOT flush TX.
        tcflush(fd_, TCIFLUSH);

        if (error) error->clear();
        return true;
#endif
    }

    void close() override
    {
#ifndef _WIN32
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
#endif
    }

    bool is_open() const override
    {
#ifdef _WIN32
        return false;
#else
        return fd_ >= 0;
#endif
    }

    ssize_t write_bytes(const uint8_t *data, size_t size, std::string *error) override
    {
#ifdef _WIN32
        (void)data;
        (void)size;
        if (error) *error = "serial transport unsupported on Windows in v1";
        return -1;
#else
        if (fd_ < 0) {
            if (error) *error = "serial transport not open";
            return -1;
        }
        ssize_t written = ::write(fd_, data, size);
        if (written < 0 && error) *error = std::string("write failed: ") + std::strerror(errno);
        // Do NOT call tcdrain() – it is not called by pyserial and may stall on
        // some CH340 driver revisions on macOS.
        return written;
#endif
    }

    ssize_t read_bytes(uint8_t *buffer, size_t size, int timeout_ms, std::string *error) override
    {
#ifdef _WIN32
        (void)buffer;
        (void)size;
        (void)timeout_ms;
        if (error) *error = "serial transport unsupported on Windows in v1";
        return -1;
#else
        if (fd_ < 0) {
            if (error) *error = "serial transport not open";
            return -1;
        }

        // Use select() + read() rather than VTIME-based blocking read.
        // On macOS with the WCH CH340 USB-serial driver, VTIME-based blocking
        // reads do NOT reliably trigger USB IN polling; select() does.
        // This matches pyserial's internal implementation (serialposix.py).
        size_t got = 0;
        auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(timeout_ms);
        while (got < size) {
            auto remaining_us = std::chrono::duration_cast<std::chrono::microseconds>(
                                    deadline - std::chrono::steady_clock::now()).count();
            if (remaining_us <= 0) break;
            struct timeval tv;
            tv.tv_sec  = (long)(remaining_us / 1000000);
            tv.tv_usec = (long)(remaining_us % 1000000);
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd_, &rfds);
            int r = ::select(fd_ + 1, &rfds, nullptr, nullptr, &tv);
            if (r < 0) {
                if (errno == EINTR) continue;
                if (error) *error = std::string("select failed: ") + std::strerror(errno);
                return -1;
            }
            if (r == 0) break; // timeout
            if (!FD_ISSET(fd_, &rfds)) break;
            ssize_t n = ::read(fd_, buffer + got, 1); // read 1 byte (like pyserial)
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (error) *error = std::string("read failed: ") + std::strerror(errno);
                return -1;
            }
            if (n == 0) break;
            got += (size_t)n;
            // After receiving at least 1 byte, drain any immediately available bytes
            // (avoids extra round-trips when multiple bytes are buffered).
            // For UART-based PN532, full response frames often arrive within a few
            // hundred microseconds; let the drain window be generous so the caller
            // receives the entire frame in one read_bytes() call.
            auto drain_until = std::chrono::steady_clock::now()
                               + std::chrono::milliseconds(5);  // 5 ms inter-byte gap window
            while (got < size) {
                auto us_left = std::chrono::duration_cast<std::chrono::microseconds>(
                                   drain_until - std::chrono::steady_clock::now()).count();
                if (us_left <= 0) break;
                struct timeval tv2;
                tv2.tv_sec  = (long)(us_left / 1000000);
                tv2.tv_usec = (long)(us_left % 1000000);
                fd_set rfds2; FD_ZERO(&rfds2); FD_SET(fd_, &rfds2);
                if (::select(fd_ + 1, &rfds2, nullptr, nullptr, &tv2) <= 0) break;
                if (!FD_ISSET(fd_, &rfds2)) break;
                ssize_t m = ::read(fd_, buffer + got, size - got);
                if (m <= 0) break;
                got += (size_t)m;
                // Reset the drain window on each received byte — keep draining
                // as long as bytes keep arriving within the 5 ms gap.
                drain_until = std::chrono::steady_clock::now()
                              + std::chrono::milliseconds(5);
            }
            break; // return as soon as we have data
        }
        if (error) error->clear();
        return (ssize_t)got;
#endif
    }

    TransportEndpoint endpoint() const override
    {
        return endpoint_;
    }

private:
#ifndef _WIN32
    static speed_t baud_to_constant(int baud)
    {
        switch (baud) {
        case 9600: return B9600;
        case 19200: return B19200;
        case 38400: return B38400;
        case 57600: return B57600;
        case 230400: return B230400;
        default: return B115200;
        }
    }
#endif

    TransportEndpoint endpoint_;
#ifndef _WIN32
    int fd_ = -1;
#endif
};

class NfcTransportFactory {
public:
    static std::vector<TransportEndpoint> enumerate_endpoints()
    {
        std::vector<TransportEndpoint> endpoints;

#ifndef _WIN32
        DIR *dir = opendir("/dev");
        if (!dir) {
            return endpoints;
        }

        struct dirent *entry = nullptr;
        while ((entry = readdir(dir)) != nullptr) {
            const std::string name(entry->d_name);
            TransportKind kind = TransportKind::I2cBus;
            bool matched = false;

            if (starts_with(name, "ttyUSB") || starts_with(name, "ttyACM") ||
                starts_with(name, "cu.usbmodem") || starts_with(name, "cu.usbserial") ||
                starts_with(name, "cu.wchusbserial") || starts_with(name, "cu.SLAB_USBtoUART") ||
                starts_with(name, "cu.usbserial-")) {
                kind = TransportKind::UsbSerial;
                matched = true;
            } else if (starts_with(name, "ttyS") || starts_with(name, "ttyAMA") ||
                       starts_with(name, "serial") || starts_with(name, "ttyTHS")) {
                kind = TransportKind::UartSerial;
                matched = true;
            }

            if (!matched) continue;

            TransportEndpoint endpoint;
            endpoint.kind = kind;
            endpoint.path = std::string("/dev/") + name;
            if (kind == TransportKind::UsbSerial)
                read_usb_vid_pid(name, &endpoint.usb_vid, &endpoint.usb_pid);
            // Try to read USB product name for a friendlier label
            std::string product = read_usb_product_name(name);
            if (!product.empty()) {
                endpoint.label = std::string(to_string(kind)) + " " + product + " (" + name + ")";
            } else {
                endpoint.label = std::string(to_string(kind)) + " " + name;
            }

            if (kind == TransportKind::UsbSerial &&
                is_known_uhf_vid_pid(endpoint.usb_vid, endpoint.usb_pid)) {
                endpoint.label = std::string("USB UHF Reader ") + "(" + name + ")";
            }
            endpoint.baud_rate = 115200;
            endpoints.push_back(endpoint);
        }
        closedir(dir);

        std::sort(endpoints.begin(), endpoints.end(), [](const TransportEndpoint &lhs, const TransportEndpoint &rhs) {
            return lhs.path < rhs.path;
        });

        // On macOS a single USB device can appear under both an Apple-native name
        // (cu.usbmodem*, cu.usbserial-*) and a WCH-driver name (cu.wchusbserial*).
        // Connecting to the first entry locks the port exclusively, making the
        // duplicate entry always fail. Remove WCH entries whose USB serial-number
        // suffix matches an already-present non-WCH entry.
        {
            std::set<std::string> non_wch_suffixes;
            for (size_t i = 0; i < endpoints.size(); ++i) {
                const std::string devname = endpoints[i].path.substr(5); // strip /dev/
                if (!starts_with(devname, "cu.wchusbserial"))
                    non_wch_suffixes.insert(usb_serial_suffix(devname));
            }
            auto it = endpoints.begin();
            while (it != endpoints.end()) {
                const std::string devname = it->path.substr(5);
                if (starts_with(devname, "cu.wchusbserial") &&
                    non_wch_suffixes.count(usb_serial_suffix(devname))) {
                    it = endpoints.erase(it);
                } else {
                    ++it;
                }
            }
        }
#endif

#if defined(__linux__)
        for (auto &ep : probe_i2c_devices())
            endpoints.push_back(ep);
        // Add SPI endpoints (M5 NFC CAP)
        for (auto &ep : enumerate_spi_devices())
            endpoints.push_back(ep);
#endif
        return endpoints;
    }

    // Enumerate /dev/spidev* devices as SpiBus endpoints.
    static std::vector<TransportEndpoint> enumerate_spi_devices()
    {
        std::vector<TransportEndpoint> result;
#if defined(__linux__)
        DIR *d = opendir("/dev");
        if (!d) return result;
        struct dirent *entry = nullptr;
        while ((entry = readdir(d)) != nullptr) {
            const std::string name(entry->d_name);
            if (!starts_with(name, "spidev")) continue;
            TransportEndpoint ep;
            ep.kind      = TransportKind::SpiBus;
            ep.path      = std::string("/dev/") + name;
            ep.label     = std::string("M5 NFC CAP ") + name;
            ep.baud_rate = 0;
            result.push_back(ep);
        }
        closedir(d);
        std::sort(result.begin(), result.end(), [](const TransportEndpoint &a, const TransportEndpoint &b) {
            auto score = [](const std::string &path) {
                if (path.find("/dev/spidev0.2") != std::string::npos) return 0;
                if (path.find("/dev/spidev0.1") != std::string::npos) return 1;
                if (path.find("/dev/spidev0.0") != std::string::npos) return 2;
                return 3;
            };
            const int sa = score(a.path);
            const int sb = score(b.path);
            if (sa != sb) return sa < sb;
            return a.path < b.path;
        });
#endif
        return result;
    }

    // Probe all /dev/i2c-* buses for known NFC devices (NFCUnit @0x50, GroveNFC @0x48).
    // Returns only devices that actually responded to the register read.
    // Safe to call any time (on-demand scan, not only at startup).
    static std::vector<TransportEndpoint> probe_i2c_devices()
    {
        std::vector<TransportEndpoint> result;
#if defined(__linux__)
        // ── Enable Grove 5V power via GROVE_EN (BCM17 = AW35112FDR load switch) ──
        // G17 (BCM17) HIGH = GROVE power on.
        grove_gpio_enable_bcm(17, true);

        // ── Switch GROVE mux to I2C1 mode (BCM4 = G4 = FSW7227 SEL pin) ──
        // From schematic: SEL=L → UART, SEL=H → I2C1.
        // Without this the GROVE connector is routed to UART, not I2C,
        // so GroveNFC can never be found on /dev/i2c-*.
        grove_gpio_enable_bcm(4, true);

        // Allow the load switch and the NFC module to power up.
        // GroveNFC M090 / PN532-based modules need ≥200 ms after supply rise
        // before they respond to I2C traffic.
        {
            struct timespec ts = {0, 300 * 1000 * 1000}; // 300 ms
            nanosleep(&ts, nullptr);
        }

        std::vector<std::string> i2c_buses;
        DIR *i2c_scan = opendir("/dev");
        if (i2c_scan) {
            struct dirent *ie = nullptr;
            while ((ie = readdir(i2c_scan)) != nullptr) {
                // Only include character devices (DT_CHR) or unknown type entries
                // named i2c-* — skip directories to avoid EISDIR on open()
                if (ie->d_type != DT_DIR && starts_with(ie->d_name, "i2c-"))
                    i2c_buses.push_back(std::string("/dev/") + ie->d_name);
            }
            closedir(i2c_scan);
        }
        std::sort(i2c_buses.begin(), i2c_buses.end());

        // (addr, label_prefix) — probe all known Grove NFC module variants
        // PN532 standard I2C address: 0x24
        // GroveNFC (MJS M090): 0x48; M5NFC Unit (ST25R3916/PN532 via I2C): 0x50
        // 0x6a is the onboard IMU — NOT an NFC device, intentionally excluded.
        static const std::pair<uint8_t, const char*> probe_addrs[] = {
            {0x24, "PN532"},
            {0x50, "NFC Unit"},
            {0x48, "GroveNFC"},
        };
        for (const auto &bus : i2c_buses) {
            const std::string bus_name = bus.substr(bus.rfind('/') + 1); // "i2c-1"
            // Open the bus once; skip if not accessible
            int probe_fd = ::open(bus.c_str(), O_RDWR);
            if (probe_fd < 0) continue;
            for (auto &ap : probe_addrs) {
                const uint8_t addr  = ap.first;
                const char   *label = ap.second;
                bool present = false;
                if (::ioctl(probe_fd, I2C_SLAVE, (long)addr) >= 0) {
                    // Match i2cdetect behavior:
                    // EEPROM address range (0x50-0x5F): byte-read probe
                    //   — write probe would advance the internal pointer.
                    // All other addresses (incl. 0x48 GroveNFC M090):
                    //   SMBus quick-write probe (START + ADDR/W + STOP)
                    //   == Arduino Wire beginTransmission()+endTransmission().
                    //   A bare read() without a prior register-address write
                    //   causes M090 to NACK, yielding false-negative.
                    if (addr >= 0x50 && addr <= 0x5F) {
                        uint8_t rbuf = 0;
                        present = (::read(probe_fd, &rbuf, 1) == 1);
                    } else {
                        struct i2c_smbus_ioctl_data args{};
                        args.read_write = I2C_SMBUS_WRITE;
                        args.command    = 0;
                        args.size       = I2C_SMBUS_QUICK;
                        args.data       = nullptr;
                        present = (::ioctl(probe_fd, I2C_SMBUS, &args) >= 0);
                    }
                }
                if (present) {
                    char path_str[64];
                    std::snprintf(path_str, sizeof(path_str), "%s:0x%02x", bus.c_str(), (unsigned)addr);
                    TransportEndpoint ep;
                    ep.kind      = TransportKind::I2cBus;
                    ep.path      = path_str;
                    ep.label     = std::string(label) + " @" + bus_name;
                    ep.baud_rate = 0;
                    result.push_back(ep);
                }
            }
            ::close(probe_fd);
        }
#endif
        return result;
    }

    // ── Grove GPIO helpers ────────────────────────────────────────────────────
    // Find the sysfs base of the gpiochip whose label matches `chip_label`.
    // Returns -1 if not found.
    static int grove_find_chip_base(const char *chip_label)
    {
#if defined(__linux__)
        DIR *d = opendir("/sys/class/gpio");
        if (!d) return -1;
        int found_base = -1;
        struct dirent *de;
        while ((de = readdir(d)) != nullptr) {
            if (!starts_with(de->d_name, "gpiochip")) continue;
            char lpath[320], bpath[320];
            std::snprintf(lpath, sizeof(lpath), "/sys/class/gpio/%s/label",  de->d_name);
            std::snprintf(bpath, sizeof(bpath), "/sys/class/gpio/%s/base",   de->d_name);
            FILE *lf = fopen(lpath, "r");
            if (!lf) continue;
            char label[64] = {};
            (void)fgets(label, sizeof(label), lf);
            fclose(lf);
            // strip trailing newline
            for (int i = (int)std::strlen(label)-1; i >= 0 && (label[i]=='\n'||label[i]=='\r'); --i)
                label[i] = '\0';
            if (std::strcmp(label, chip_label) == 0) {
                FILE *bf = fopen(bpath, "r");
                if (bf) { fscanf(bf, "%d", &found_base); fclose(bf); }
                break;
            }
        }
        closedir(d);
        return found_base;
#else
        (void)chip_label; return -1;
#endif
    }

    // Drive a BCM GPIO pin via sysfs, auto-detecting the gpiochip base.
    // CardputerZero: GROVE_EN=BCM17, active-HIGH (FSW7227 load switch).
    // Silently ignores errors so probe_i2c_devices() never throws.
    static void grove_gpio_enable_bcm(int bcm_pin, bool high)
    {
#if defined(__linux__)
        // Find the base of the BCM/pinctrl chip (label = "pinctrl-bcm2835")
        int base = grove_find_chip_base("pinctrl-bcm2835");
        if (base < 0) base = 0; // fallback: no offset (bare sysfs numbering)
        grove_gpio_enable(base + bcm_pin, high);
#else
        (void)bcm_pin; (void)high;
#endif
    }

    // Drive an absolute sysfs GPIO number.
    static void grove_gpio_enable(int gpio_num, bool high)
    {
#if defined(__linux__)
        char path[64];

        // 1. Export the pin (ignore error if already exported)
        {
            FILE *f = fopen("/sys/class/gpio/export", "w");
            if (f) { std::fprintf(f, "%d", gpio_num); fclose(f); }
        }
        // 2. Set direction = out
        std::snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/direction", gpio_num);
        {
            FILE *f = fopen(path, "w");
            if (f) { std::fputs("out", f); fclose(f); }
        }
        // 3. Set value
        std::snprintf(path, sizeof(path), "/sys/class/gpio/gpio%d/value", gpio_num);
        {
            FILE *f = fopen(path, "w");
            if (f) { std::fprintf(f, "%d", high ? 1 : 0); fclose(f); }
        }
#else
        (void)gpio_num; (void)high;
#endif
    }

    static std::unique_ptr<INfcTransport> create(const TransportEndpoint &endpoint)
    {
        if (endpoint.kind == TransportKind::I2cBus ||
            endpoint.kind == TransportKind::SpiBus) {
            return std::unique_ptr<INfcTransport>(new MockTransport());
        }
        return std::unique_ptr<INfcTransport>(new SerialTransport());
    }

private:
    static bool starts_with(const std::string &value, const std::string &prefix)
    {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }

    // Extract the USB serial-number suffix by stripping known driver-specific
    // prefixes. Longest prefixes are checked first to avoid ambiguity.
    static std::string usb_serial_suffix(const std::string &name)
    {
        static const char *kPrefixes[] = {
            "cu.wchusbserial", "cu.SLAB_USBtoUART",
            "cu.usbserial-", "cu.usbserial", "cu.usbmodem",
            "ttyUSB", "ttyACM", nullptr
        };
        for (const char **p = kPrefixes; *p; ++p) {
            const size_t plen = std::strlen(*p);
            if (name.size() > plen && name.compare(0, plen, *p) == 0)
                return name.substr(plen);
        }
        return name;
    }

    // Read USB product name from sysfs (Linux) or IOKit (macOS).
    // Returns empty string if unavailable.
    static std::string read_usb_product_name(const std::string &devname)
    {
#if defined(__linux__)
        // sysfs path: /sys/class/tty/<dev>/device/../../product
        // The tty device node -> device (usb interface) -> device (usb device) -> product
        static const char *SUFFIXES[] = {"/device/../../product", "/device/../product", nullptr};
        for (const char **s = SUFFIXES; *s; ++s) {
            const std::string path = std::string("/sys/class/tty/") + devname + *s;
            FILE *f = fopen(path.c_str(), "r");
            if (!f) continue;
            char buf[128] = {};
            if (fgets(buf, sizeof(buf), f)) {
                fclose(f);
                // Strip trailing whitespace/newline
                size_t len = strlen(buf);
                while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' '))
                    buf[--len] = '\0';
                if (len > 0) return std::string(buf);
            }
            fclose(f);
        }
#elif defined(__APPLE__)
        // On macOS: run ioreg to extract USB product name matching this serial port device.
        // We look for the IOCalloutDevice property matching /dev/<devname>.
        std::string cmd = std::string("ioreg -l -n IOUSBHostDevice 2>/dev/null | grep -A20 '\"IOCalloutDevice\" = \"/dev/") + devname + "\"' | grep '\"USB Product Name\"' | head -1";
        FILE *f = popen(cmd.c_str(), "r");
        if (f) {
            char buf[256] = {};
            if (fgets(buf, sizeof(buf), f)) {
                pclose(f);
                // Parse: "USB Product Name" = "PN532Killer-UART"
                const char *q = strchr(buf, '"');
                if (q) { q = strchr(q + 1, '"'); }
                if (q) { q = strchr(q + 1, '"'); }
                if (q) { q = strchr(q + 1, '"'); }  // now at opening quote of value
                if (q) {
                    q++; // skip opening "
                    const char *e = strchr(q, '"');
                    if (e && e > q) return std::string(q, e);
                }
            } else {
                pclose(f);
            }
        }
        // Fallback: map known VID/PID via ioreg USB serial number embedded in devname
        // cu.usbmodem<serial> where serial="00000001" → suffix "00000001"
        {
            const std::string suffix = usb_serial_suffix(devname);
            if (!suffix.empty()) {
                std::string cmd2 = std::string("ioreg -l 2>/dev/null | grep -B10 '\"USB Serial Number\" = \"") + suffix + "\"' | grep '\"USB Product Name\"' | tail -1";
                FILE *f2 = popen(cmd2.c_str(), "r");
                if (f2) {
                    char buf2[256] = {};
                    if (fgets(buf2, sizeof(buf2), f2)) {
                        pclose(f2);
                        const char *q = strchr(buf2, '"');
                        if (q) { q = strchr(q + 1, '"'); }
                        if (q) { q = strchr(q + 1, '"'); }
                        if (q) { q = strchr(q + 1, '"'); }
                        if (q) {
                            q++;
                            const char *e = strchr(q, '"');
                            if (e && e > q) return std::string(q, e);
                        }
                    } else {
                        pclose(f2);
                    }
                }
            }
        }
#endif
        return {};
    }

    static bool is_known_uhf_vid_pid(int vid, int pid)
    {
        return (vid == 0x1A86 && pid == 0xFE1C);
    }

    static bool parse_hex_u16(const std::string &text, int *value)
    {
        if (!value) return false;
        std::string hex;
        hex.reserve(text.size());
        for (char ch : text) {
            if (std::isxdigit(static_cast<unsigned char>(ch))) hex.push_back(ch);
        }
        if (hex.empty()) return false;
        char *end = nullptr;
        const unsigned long parsed = std::strtoul(hex.c_str(), &end, 16);
        if (!end || *end != '\0') return false;
        if (parsed > 0xFFFFUL) return false;
        *value = static_cast<int>(parsed);
        return true;
    }

    static bool read_first_line_trimmed(const std::string &path, std::string *out)
    {
        if (!out) return false;
        FILE *f = fopen(path.c_str(), "r");
        if (!f) return false;
        char buf[128] = {};
        const bool ok = (fgets(buf, sizeof(buf), f) != nullptr);
        fclose(f);
        if (!ok) return false;
        std::string line(buf);
        while (!line.empty() &&
               (line.back() == '\n' || line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
            line.pop_back();
        }
        *out = line;
        return !out->empty();
    }

    static bool read_usb_vid_pid(const std::string &devname, int *vid, int *pid)
    {
        if (vid) *vid = -1;
        if (pid) *pid = -1;

#if defined(__linux__)
        static const char *SUFFIXES[] = {
            "/device/../../idVendor", "/device/../idVendor", "/device/idVendor", nullptr
        };
        static const char *PSUFFIXES[] = {
            "/device/../../idProduct", "/device/../idProduct", "/device/idProduct", nullptr
        };

        int found_vid = -1;
        int found_pid = -1;
        for (int i = 0; SUFFIXES[i] != nullptr; ++i) {
            const std::string base = std::string("/sys/class/tty/") + devname;
            const std::string vpath = base + SUFFIXES[i];
            const std::string ppath = base + PSUFFIXES[i];

            std::string vline, pline;
            if (!read_first_line_trimmed(vpath, &vline)) continue;
            if (!read_first_line_trimmed(ppath, &pline)) continue;

            if (!parse_hex_u16(vline, &found_vid)) continue;
            if (!parse_hex_u16(pline, &found_pid)) continue;
            break;
        }

        if (vid) *vid = found_vid;
        if (pid) *pid = found_pid;
        return (found_vid >= 0 && found_pid >= 0);
#elif defined(__APPLE__)
        // macOS fallback via ioreg; best-effort only.
    (void)devname;
    const std::string cmd =
        "ioreg -p IOUSB -l 2>/dev/null | "
        "awk '/idVendor/ {vid=$NF} /idProduct/ {pid=$NF} "
        "END { if (vid != \"\" && pid != \"\") print vid \" \" pid }' | head -1";
        FILE *f = popen(cmd.c_str(), "r");
        if (!f) return false;
        char line[128] = {};
        if (!fgets(line, sizeof(line), f)) {
            pclose(f);
            return false;
        }
        pclose(f);
        std::string txt(line);
        size_t sp = txt.find(' ');
        if (sp == std::string::npos) return false;
        int local_vid = -1;
        int local_pid = -1;
        if (!parse_hex_u16(txt.substr(0, sp), &local_vid)) return false;
        if (!parse_hex_u16(txt.substr(sp + 1), &local_pid)) return false;
        if (vid) *vid = local_vid;
        if (pid) *pid = local_pid;
        return true;
#else
        (void)devname;
        (void)vid;
        (void)pid;
        return false;
#endif
    }
};

} // namespace nfc_app