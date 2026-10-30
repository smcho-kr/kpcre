#!/usr/bin/env python3
"""Check real plugin builds/installs with fake kernel targets in a temporary tree."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="kpcre-install-") as temporary:
    root = Path(temporary)
    source = root / "source"
    for name in ["Makefile", "dkms.conf", "scripts/dkms-install-userspace.sh",
                 "xt_ids/Makefile", "xt_ids/libxt_ids.c", "xt_ids/xt_ids.h", "nft_regex/Makefile",
                 "libc/Makefile", "pcre2/Makefile", "ts_pcre/Makefile", "ts_regex/Makefile"]:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(repo / name, target)
    kernel = root / "kernel"
    kernel.mkdir()
    (kernel / "Makefile").write_text(
        '.PHONY: modules modules_install clean\n'
        'modules modules_install clean:\n'
        '\t@test "$(notdir $(M))" != "$(INSTALL_FAIL_MODULE)"\n'
        '\t@if [ "$@" = modules_install ]; then test -f "$(INSTALL_PLUGIN)"; fi\n'
        '\t@echo "$(notdir $(M)):$@" >> "$(INSTALL_LOG)"\n')
    binaries = root / "bin"
    binaries.mkdir()
    (binaries / "depmod").write_text('#!/bin/sh\nexit 0\n')
    (binaries / "depmod").chmod(0o755)
    destination = root / "destination"
    plugin_dir = "/usr/lib/xtables-test"
    plugin = destination / plugin_dir.lstrip("/") / "libxt_ids.so"
    log = root / "targets.log"
    env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"],
               KERNEL_DIR=str(kernel), DESTDIR=str(destination),
               XTABLES_LIBDIR=plugin_dir, INSTALL_PLUGIN=str(plugin),
               INSTALL_LOG=str(log))

    def run(*args, success=True):
        result = subprocess.run(args, cwd=source, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert (result.returncode == 0) == success, result.stdout
        return result.stdout

    modules = ["libc", "pcre2", "ts_pcre", "ts_regex", "xt_ids", "nft_regex"]
    run("make", "modules")
    assert log.read_text().splitlines() == [m + ":modules" for m in modules]
    assert (source / "xt_ids/libxt_ids.so").read_bytes().startswith(b"\x7fELF")
    run("make", "modules_install")
    assert plugin.read_bytes() == (source / "xt_ids/libxt_ids.so").read_bytes()
    assert log.read_text().splitlines()[len(modules):] == [m + ":modules_install" for m in modules]

    # Directory discovery must work without a manually supplied install path.
    pkgconfig = binaries / "pkg-config"
    pkgconfig.write_text('#!/bin/sh\ncase "$1" in\n'
                         ' --variable=xtlibdir) echo /usr/lib/xtables-test ;;\n'
                         ' --cflags) echo "$XTABLES_CFLAGS" ;;\n'
                         ' *) exit 1 ;;\nesac\n')
    pkgconfig.chmod(0o755)
    del env["XTABLES_LIBDIR"]
    plugin.unlink()
    run("make", "userspace_install")
    assert plugin.exists()
    env["XTABLES_LIBDIR"] = plugin_dir

    # Test fail-fast traversal, and fail before kernel installation on plugin errors.
    log.unlink()
    run("make", "kernel_modules", "INSTALL_FAIL_MODULE=pcre2", success=False)
    assert log.read_text().splitlines() == ["libc:modules"]
    log.unlink()
    run("make", "modules_install", "XTABLES_LIBDIR=", success=False)
    assert not log.exists()
    run("make", "modules_install", "XTABLES_LIBDIR=relative/path", success=False)
    assert not log.exists()
    (source / "xt_ids/libxt_ids.so").unlink()
    run("make", "modules_install", "CC=false", success=False)
    assert not log.exists()

    # Non-8-bit builds must not gain a dependency on the 8-bit xtables plugin.
    run("make", "modules", "CODE_WIDTH=16", "CC=false")
    assert log.read_text().splitlines() == [m + ":modules" for m in modules[:4]]
    log.unlink()

    # Exercise the installed DKMS dispatcher when available, including source symlinks.
    registered = root / "dkms/kpcre/1.0.0/source"
    registered.parent.mkdir(parents=True)
    registered.symlink_to(source, target_is_directory=True)
    dkms = Path(shutil.which("dkms") or "/nonexistent")
    if dkms.exists():
        text = dkms.read_text()
        start = text.index("run_build_script() {")
        end = text.index("\n}\n", start) + 3
        dispatcher = text[start:end]
        script = dispatcher + '\n. ./dkms.conf\nrun_build_script pre_install "$PRE_INSTALL"\n'
        env.update(dkms_tree=str(root / "dkms"), module="kpcre", module_version="1.0.0")
    else:
        script = '. ./dkms.conf\n"$PRE_INSTALL"\n'
    plugin.unlink()
    (source / "xt_ids/libxt_ids.so").write_bytes(b"stale userspace ABI")
    run("bash", "-c", script)
    assert plugin.read_bytes().startswith(b"\x7fELF")
    assert not log.exists(), "DKMS hook must never invoke kernel targets or depmod"
    plugin.unlink()
    env["XTABLES_LIBDIR"] = ""
    run("bash", "-c", script, success=False)
    assert not plugin.exists()
    assert not log.exists()
    print("PASS: real ELF plugin build, staged installs, fail-fast failures, CODE_WIDTH=16, DKMS hook")
