from pathlib import Path
import json
import r2pipe

DEBUG = True


def debug(msg):
    if DEBUG:
        print(f"[?] {msg}")


def r2cli(r, cmd):
    while "Command must succeed":
        result = r.cmd(cmd)
        if result:
            return result


def r2json(r, cmd: str):
    try:
        while "Command must succeed":
            result = r.cmd(cmd)
            if result:
                return json.loads(result)
    except json.decoder.JSONDecodeError:
        breakpoint()


candidates = []

if not Path("candidates.txt").exists:

    for f in Path(".").glob("samples/sample*"):
        data = open(f, "rb").read()

        r = r2pipe.open(str(f))
        j = r2json(r, "ij")

        if j["bin"]["nx"]:
            debug(f"NX value is wrong for {f}")
            continue

        j = r2json(r, "pij 1")
        try:
            ins = j[0]["disasm"]
        except KeyError:
            j = r2json(r, "pij 1")

        if ins != "xor ebp, ebp":
            debug(f"Instruction is wrong for {f}")
            continue

        hash = r2cli(r, "ph md5 0x20 @ 0x0040404f")
        if hash.strip() != "f3ea40bcc61066261ea3a018560434e2":
            debug(f"Hash is wrong for {f}")
            continue

        candidates.append(f)

    print(f"{len(candidates)} candidates found")

    with open("candidates.txt", "w") as f:
        for c in candidates:
            f.write(f"{c}\n")
