#!/usr/bin/env python3
"""Synthetic tests for compare.py. Usage: python3 test_compare.py  (exit 1 if any case misbehaves)."""
import io, os, subprocess, sys, tarfile, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CAP = "\x01\x00\x00\x02\x00\x20\x00\x00" + "\x00" * 12
XCAP = {"SCHILY.xattr.security.capability": CAP}


def mk(path, entries):
    """entries: list of (name, kind, kwargs) kinds: f d s h w(hiteout-as-file)"""
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        for name, kind, kw in entries:
            ti = tarfile.TarInfo(name)
            ti.mode = kw.get("mode", 0o755 if kind == "d" else 0o644)
            ti.uid, ti.gid, ti.mtime = kw.get("uid", 0), kw.get("gid", 0), 1700000000
            data = kw.get("data", b"")
            if kind == "d":
                ti.type = tarfile.DIRTYPE
            elif kind == "s":
                ti.type, ti.linkname = tarfile.SYMTYPE, kw["link"]
            elif kind == "h":
                ti.type, ti.linkname = tarfile.LNKTYPE, kw["link"]
            else:
                ti.size = len(data)
            if kw.get("x"):
                ti.pax_headers = dict(kw["x"])
            tf.addfile(ti, io.BytesIO(data) if kind in ("f", "w") else None)


def F(name, data=b"", **kw): return (name, "f", dict(kw, data=data))
def D(name, **kw): return (name, "d", kw)
def S(name, link, **kw): return (name, "s", dict(kw, link=link))
def H(name, link, **kw): return (name, "h", dict(kw, link=link))
def W(name): return (name, "w", {})   # whiteout marker file (name must contain .wh.)


CASES = []  # (title, src_layers, flat_layers, expect 'PASS'/'FAIL')


def case(title, src, flat, expect):
    CASES.append((title, src, flat, expect))


# ---- base scenario (setuid, capability xattr, hardlink pair, symlink, whiteout, opaque dir)
L1 = [D("etc"), F("etc/a.txt", b"A"), D("bin"),
      F("bin/ping", b"PING", mode=0o4755, uid=1000, gid=2000, x=XCAP),
      H("bin/ping2", "bin/ping", mode=0o4755, uid=1000, gid=2000),
      D("lib"), S("lib/x", "../etc/a.txt"), D("opt"), F("opt/old1", b"x"), F("opt/old2", b"y"),
      D("data"), F("data/del", b"d")]
L2 = [F("etc/a.txt", b"A2"), W("data/.wh.del"), W("opt/.wh..wh..opq"), F("opt/new", b"n")]


def base_flat(mode=0o4755, cap=True, old=False, hard_first=False, copy=False, sym="../etc/a.txt", a=b"A2"):
    x = XCAP if cap else None
    ping = F("bin/ping", b"PING", mode=mode, uid=1000, gid=2000, x=x)
    link = (F("bin/ping2", b"PING", mode=mode, uid=1000, gid=2000, x=x) if copy
            else H("bin/ping2", "bin/ping", mode=mode, uid=1000, gid=2000))
    pair = [link, ping] if hard_first else [ping, link]
    return [D("etc"), F("etc/a.txt", a), D("bin"), *pair, D("lib"), S("lib/x", sym), D("opt"),
            F("opt/new", b"n")] + ([F("opt/old1", b"x")] if old else []) + [D("data")]


case("base: correct flat", [L1, L2], [base_flat()], "PASS")
case("base: setuid bit lost", [L1, L2], [base_flat(mode=0o755)], "FAIL")
case("base: capability xattr lost", [L1, L2], [base_flat(cap=False)], "FAIL")
case("base: opaque-dir victim kept", [L1, L2], [base_flat(old=True)], "FAIL")
case("base: hardlink before its target (conservative)", [L1, L2], [base_flat(hard_first=True)], "FAIL")
case("base: hardlink replaced by independent copy", [L1, L2], [base_flat(copy=True)], "FAIL")
case("base: symlink target changed", [L1, L2], [base_flat(sym="../etc/b.txt")], "FAIL")
case("base: file content changed", [L1, L2], [base_flat(a=b"A3")], "FAIL")

# ---- Codex case 1: /a OLD + /b hardlink; later /a removed and recreated NEW (separate layers)
A1 = [F("a", b"OLD"), H("b", "a")]
A2 = [W(".wh.a")]
A3 = [F("a", b"NEW")]
case("hl1 recreate across layers: correct flat (b=OLD, a=NEW, separate)", [A1, A2, A3],
     [[F("a", b"NEW"), F("b", b"OLD")]], "PASS")
case("hl1: flat as crane's reverse-merge would emit (b hardlinked to NEW a)", [A1, A2, A3],
     [[F("a", b"NEW"), H("b", "a")]], "FAIL")
case("hl1: b missing in flat", [A1, A2, A3], [[F("a", b"NEW")]], "FAIL")
case("hl1: b has NEW content", [A1, A2, A3], [[F("a", b"NEW"), F("b", b"NEW")]], "FAIL")

# same-layer variant: whiteout and recreate in one layer (OCI: whiteout hides lower layers only)
B2 = [W(".wh.a"), F("a", b"NEW")]
case("hl1b whiteout+recreate in ONE layer: correct flat", [A1, B2], [[F("a", b"NEW"), F("b", b"OLD")]], "PASS")
case("hl1b: a dropped (whiteout wrongly hides same-layer file)", [A1, B2], [[F("b", b"OLD")]], "FAIL")

# ---- Codex case 2: deleting the link target must keep the surviving link's content
case("hl2 target deleted: correct flat (b regular OLD)", [A1, [W(".wh.a")]], [[F("b", b"OLD")]], "PASS")
case("hl2: flat keeps hardlink b->a but a is gone", [A1, [W(".wh.a")]], [[H("b", "a")]], "FAIL")
case("hl2: b content lost", [A1, [W(".wh.a")]], [[F("b", b"")]], "FAIL")
case("hl2: a not deleted", [A1, [W(".wh.a")]], [[F("a", b"OLD"), F("b", b"OLD")]], "FAIL")

# overwrite one link in a later layer by a regular file
case("hl3 one link overwritten later: correct flat", [A1, [F("a", b"NEW")]],
     [[F("a", b"NEW"), F("b", b"OLD")]], "PASS")
case("hl3: flat still groups a and b", [A1, [F("a", b"NEW")]], [[F("a", b"NEW"), H("b", "a")]], "FAIL")

# link group preserved when it should be
case("hl4 untouched hardlink group: flat keeps group", [A1], [[F("a", b"OLD"), H("b", "a")]], "PASS")
case("hl4: flat splits group", [A1], [[F("a", b"OLD"), F("b", b"OLD")]], "FAIL")

# ---- cases the model refuses to guess about
case("symlink traversal in source layer is rejected",
     [[D("usr"), D("usr/lib"), S("lib", "usr/lib")], [F("lib/x", b"1")]], [[D("usr"), D("usr/lib"), S("lib", "usr/lib"), F("usr/lib/x", b"1")]], "FAIL")
case("hardlink to absent target in source is rejected", [[H("h", "t")]], [[F("h", b"")]], "FAIL")
case("duplicate entry in flat layer is rejected", [[F("a", b"1")]], [[F("a", b"1"), F("a", b"1")]], "FAIL")
case("hardlink header metadata disagrees with inode",
     [[F("a", b"1", mode=0o644), H("b", "a", mode=0o600)]], [[F("a", b"1", mode=0o644), H("b", "a", mode=0o600)]], "FAIL")

# ---- directory metadata inheritance and implicit parents
case("dir metadata from top-most layer, children kept: correct flat",
     [[D("d", mode=0o755), F("d/c", b"1")], [D("d", mode=0o700)]], [[D("d", mode=0o700), F("d/c", b"1")]], "PASS")
case("dir metadata: flat kept old mode",
     [[D("d", mode=0o755), F("d/c", b"1")], [D("d", mode=0o700)]], [[D("d", mode=0o755), F("d/c", b"1")]], "FAIL")
case("file replaces directory: correct flat",
     [[D("x"), F("x/c", b"1")], [F("x", b"file")]], [[F("x", b"file")]], "PASS")
case("file replaces directory: flat kept directory",
     [[D("x"), F("x/c", b"1")], [F("x", b"file")]], [[D("x"), F("x/c", b"1")]], "FAIL")
case("implicit parents identical: correct flat",
     [[F("opt/app/file", b"1")]], [[F("opt/app/file", b"1")]], "PASS")
case("implicit parents became explicit in flat",
     [[F("opt/app/file", b"1")]], [[D("opt"), D("opt/app"), F("opt/app/file", b"1")]], "FAIL")


def main():
    bad = 0
    with tempfile.TemporaryDirectory() as td:
        for n, (title, src, flat, expect) in enumerate(CASES):
            sp, fp = [], []
            for i, ent in enumerate(src):
                p = os.path.join(td, f"{n}_s{i}.tar"); mk(p, ent); sp.append(p)
            for i, ent in enumerate(flat):
                p = os.path.join(td, f"{n}_f{i}.tar"); mk(p, ent); fp.append(p)
            r = subprocess.run([sys.executable, os.path.join(HERE, "compare.py"), "--src-tars", *sp, "--flat-tars", *fp],
                               capture_output=True, text=True)
            got = "PASS" if r.returncode == 0 else "FAIL"
            ok = got == expect
            bad += not ok
            why = ""
            if got == "FAIL":
                why = " | " + next((l.strip(" -") for l in r.stdout.splitlines() if l.startswith(" - ")), r.stderr.strip()[:80])
            print(f"{'ok ' if ok else 'BAD'} expect={expect} got={got}  {title}{why[:110]}")
    print(f"\n{len(CASES) - bad}/{len(CASES)} as expected")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
