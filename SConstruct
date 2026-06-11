from pathlib import Path
import os
import platform
import subprocess
import shutil
import sys

arch = platform.machine()
homebrew_toolchain = "/opt/homebrew/bin"
has_homebrew_aarch64 = os.path.exists(os.path.join(homebrew_toolchain, "aarch64-linux-gnu-gcc"))

version = "v0.0.3"
static_lib = "build/static_lib"
update = False

if "CardputerZero" in os.environ:
    if not os.path.exists("build/config/config_tmp.mk"):
        os.makedirs("build/config", exist_ok=True)
        with open("build/config/config_tmp.mk", "w") as f:
            f.write("CONFIG_V9_5_LV_USE_LINUX_FBDEV=y\n")
            f.write("CONFIG_V9_5_LV_USE_SDL=n\n")
            f.write("CONFIG_V9_5_LV_DRAW_SW_ASM_NEON=y\n")
            f.write("CONFIG_V9_5_LV_USE_DRAW_SW_ASM=1\n")
            f.write("CONFIG_V9_5_LV_USE_EVDEV=y\n")
            if has_homebrew_aarch64:
                f.write(f'CONFIG_TOOLCHAIN_PATH="{homebrew_toolchain}"\n')
            f.write('CONFIG_TOOLCHAIN_PREFIX="aarch64-linux-gnu-"\n')
            f.write(f'''CONFIG_TOOLCHAIN_SYSROOT="{os.path.join(sys.path[0], "build", "static_lib")}"\n''')
            f.write(f'''CONFIG_TOOLCHAIN_FLAGS="-I{os.path.join(sys.path[0], "build", "static_lib", "usr", "include", "aarch64-linux-gnu")}"\n''')
            f.write(f'''CONFIG_TOOLCHAIN_FLAGS="-I{os.path.join(sys.path[0], "static_lib", "usr", "include", "aarch64-linux-gnu")}"\n''')
elif arch != "aarch64":
    if not os.path.exists("build/config/config_tmp.mk"):
        os.makedirs("build/config", exist_ok=True)
        with open("build/config/config_tmp.mk", "w") as f:
            f.write("CONFIG_V9_5_LV_USE_SDL=y\n")
else:
    if not os.path.exists("build/config/config_tmp.mk"):
        os.makedirs("build/config", exist_ok=True)
        with open("build/config/config_tmp.mk", "w") as f:
            f.write("CONFIG_V9_5_LV_USE_LINUX_FBDEV=y\n")
            f.write("CONFIG_V9_5_LV_DRAW_SW_ASM_NEON=y\n")
            f.write("CONFIG_V9_5_LV_USE_DRAW_SW_ASM=1\n")
            f.write("CONFIG_V9_5_LV_USE_EVDEV=y\n")

local_path = Path(os.getcwd())
sdk_path = local_path.parent.parent / "SDK"
os.environ["SDK_PATH"] = str(sdk_path)
os.environ["EXT_COMPONENTS_PATH"] = str(sdk_path.parent / "ext_components")

env = SConscript(
    str(sdk_path / "tools" / "scons" / "project.py"),
    variant_dir=os.getcwd(),
    duplicate=0,
)

# ── Inject git commit hash as compile-time define for AppInfo modal ──────────
try:
    import subprocess
    git_hash = subprocess.check_output(
        ["git", "rev-parse", "--short", "HEAD"],
        text=True, cwd=os.getcwd()
    ).strip()
    env.Append(CPPDEFINES={"RFID_BUILD_HASH": '"{}"'.format(git_hash)})
    print("[RFID] Build version: {}".format(git_hash))
except Exception:
    pass  # fallback: code uses __DATE__ __TIME__

if not os.path.exists(static_lib):
    update = True
else:
    try:
        with open(str(Path(static_lib) / "version"), "r") as f:
            if version != f.read().strip():
                update = True
    except Exception:
        update = True

if update and "CardputerZero" in os.environ:
    with open(env["PROJECT_TOOL_S"]) as f:
        exec(f.read())
    down_url = "https://github.com/dianjixz/M5CardputerZero-UserDemo/releases/download/{}/sdk_bsp.tar.gz".format(
        version
    )
    archive_name = "static_lib_{}.tar.gz".format(version)
    try:
        down_path = check_wget_down(down_url, archive_name)
        if os.path.exists(static_lib):
            shutil.rmtree(static_lib)
        shutil.move(down_path, static_lib)
    except Exception as ex:
        print("[RFID] check_wget_down failed, fallback to tar extraction:", ex)
        archive_path = Path(archive_name)
        if not archive_path.exists():
            subprocess.check_call(["curl", "-L", down_url, "-o", str(archive_path)])
        if os.path.exists(static_lib):
            shutil.rmtree(static_lib)
        os.makedirs(static_lib, exist_ok=True)
        subprocess.check_call(["tar", "-xzf", str(archive_path), "-C", static_lib])
        with open(str(Path(static_lib) / "version"), "w") as f:
            f.write(version)
