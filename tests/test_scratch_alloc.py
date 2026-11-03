#!/usr/bin/env python3
"""Exercise production scratch allocation branches with userspace slab stubs."""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix="kpcre-scratch-") as temporary:
    work = Path(temporary)
    source = work / "pcre2"
    shutil.copytree(repo / "pcre2", source,
                    ignore=shutil.ignore_patterns("*.o", "*.ko", ".*.cmd"))
    # Select only the three files' kernel branches, retaining userspace PCRE/SLJIT.
    # No host kernel code, module loading, or privileged operations are involved.
    for name in ("pcre2_compile.c", "pcre2_dfa_match.c", "pcre2_jit_match.c"):
        path = source / name
        text = path.read_text().replace("__KERNEL__", "KPCRE_SCRATCH_TEST")
        path.write_text('#include "scratch_alloc_test.h"\n' + text)
    for name in ("linux/version.h", "linux/slab.h", "asm/fpu/api.h", "asm/i387.h"):
        path = work / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('#include "scratch_alloc_test.h"\n')
    objects = re.findall(r"\bpcre2\w*\.o\b", (source / "Makefile").read_text())
    sources = [source / (name[:-2] + ".c") for name in objects]
    assert sources and len(sources) == len(set(sources))
    executable = work / "test"
    command = shlex.split(os.environ.get("CC", "cc"))
    command += shlex.split(os.environ.get("CFLAGS", "-O1 -g"))
    command += ["-std=gnu99", "-DHAVE_CONFIG_H", "-DPCRE2_CODE_UNIT_WIDTH=8",
                "-DKPCRE_SCRATCH_TEST", "-I" + str(source), "-I" + str(work),
                "-I" + str(repo / "tests")]
    command += [str(path) for path in sources]
    command += [str(repo / "tests/scratch_alloc_test.c"), "-o", str(executable)]
    subprocess.run(command, check=True)
    subprocess.run([str(executable)], check=True)
