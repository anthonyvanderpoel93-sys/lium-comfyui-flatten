#!/usr/bin/env python3
"""Verify that a flattened image is equivalent to its source image.

Exit 0 only if every check below passes; any difference exits 1.

Model (merge of layers, done here independently of crane):
  * Filesystem = {path -> inode id}; inode = {kind, mode, uid, gid, names, xattrs, content hash...}.
  * A hardlink entry binds the path to the inode its target path resolves to AT THAT MOMENT
    (like link(2) during extraction). Whiteouts / replacement only unbind a path; the inode
    and any other links to it survive. A new regular file at a path always gets a NEW inode.
  * Whiteouts and opaque markers hide only entries from LOWER layers (OCI rule); entries
    written by the same layer are never hidden.
  * Directory metadata comes from the top-most explicit directory entry; children persist.
    Directories that exist only as parents of other entries ("implicit") carry no metadata
    here; the SET of implicit directories must match between images.
Cases that cannot be modelled safely are FAILURES, not guesses:
  entries whose parent path is a symlink or non-directory, paths escaping the root,
  hardlinks whose target is absent when the link is processed, hardlinks to directories,
  hardlink headers whose metadata disagrees with the inode, duplicate entries in the flat layer.
Conservative policy: in the flat layer a hardlink must come after its target (some extractors
can defer links, but we do not rely on it).
Structure (registry mode): layer count, manifest/config media types, rootfs.diff_ids equal the
sha256 of the uncompressed layer streams read here, layer digest/size equal the compressed
stream read here, history has one non-empty entry per flat layer.
Config: every key except rootfs/history/created must be identical.
mtime differences are warnings only.

Registry mode: compare.py --src-ref REPO@sha256:.. --flat-ref REPO2@sha256:.. [--summary out.json]
               (needs `crane`; layers must be gzip or uncompressed tar)
Test mode:     compare.py --src-tars l1.tar l2.tar ... --flat-tars f.tar
"""
import argparse, hashlib, io, json, posixpath, subprocess, sys, tarfile, zlib

FAIL, WARN = [], []


def norm(name):
    p = posixpath.normpath(name.lstrip("/"))
    return None if p in (".", "") else p


class FS:
    def __init__(self):
        self.paths = {}    # path -> inode id
        self.inodes = {}   # inode id -> meta
        self.n = 0

    def new_inode(self, meta):
        self.n += 1
        self.inodes[self.n] = meta
        return self.n

    def kind(self, p):
        i = self.paths.get(p)
        return self.inodes[i]["kind"] if i is not None else None

    def drop_subtree(self, d, keep):
        pre = d + "/" if d else ""
        for k in [k for k in self.paths if k.startswith(pre) and k != d and k not in keep]:
            del self.paths[k]


def ancestors(p):
    parts = p.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def kind_of(ti):
    for k, f in (("file", ti.isreg), ("dir", ti.isdir), ("sym", ti.issym), ("hard", ti.islnk),
                 ("chr", ti.ischr), ("blk", ti.isblk), ("fifo", ti.isfifo)):
        if f():
            return k
    return "other"


def inode_meta(ti, kind):
    m = {"kind": kind, "mode": ti.mode & 0o7777, "uid": ti.uid, "gid": ti.gid,
         "uname": ti.uname or "", "gname": ti.gname or "", "mtime": int(ti.mtime),
         "xattr": tuple(sorted((k, v) for k, v in ti.pax_headers.items() if "xattr" in k.lower()))}
    if kind == "sym":
        m["link"] = ti.linkname
    elif kind in ("chr", "blk"):
        m["dev"] = (ti.devmajor, ti.devminor)
    return m


def apply_layer(fs, stream, who, is_flat):
    """Apply one layer tar stream to fs. who = 'src'/'flat' for messages."""
    cur = set()
    with tarfile.open(fileobj=stream, mode="r|") as tf:
        for ti in tf:
            p = norm(ti.name)
            if p is None:
                continue
            if p == ".." or p.startswith("../"):
                FAIL.append(f"{who}: unmodelled path escaping root: {ti.name}"); continue
            d, b = posixpath.split(p)
            if b == ".wh..wh..opq":
                fs.drop_subtree(d, cur); continue
            if b.startswith(".wh."):
                t = posixpath.join(d, b[4:])
                if t not in cur:
                    fs.paths.pop(t, None)
                fs.drop_subtree(t, cur); continue
            bad = False
            for a in ancestors(p):
                k = fs.kind(a)
                if k is not None and k != "dir":
                    FAIL.append(f"{who}: unmodelled: {p} has parent {a} of kind {k} (symlink/non-directory traversal)")
                    bad = True; break
            if bad:
                continue
            kind = kind_of(ti)
            if p in cur and is_flat:
                FAIL.append(f"{who}: duplicate entry {p} in flat layer")
            old_kind = fs.kind(p)
            if old_kind == "dir" and kind != "dir":
                fs.drop_subtree(p, cur)
            if kind == "hard":
                t = norm(ti.linkname)
                tid = fs.paths.get(t) if t else None
                if tid is None:
                    FAIL.append(f"{who}: hardlink {p} -> {ti.linkname}: target not present when link is processed"
                                + (" (conservative policy: link before target)" if is_flat else " (cannot model)"))
                    continue
                tm = fs.inodes[tid]
                if tm["kind"] == "dir":
                    FAIL.append(f"{who}: hardlink {p} targets a directory"); continue
                if (ti.mode & 0o7777, ti.uid, ti.gid) != (tm["mode"], tm["uid"], tm["gid"]):
                    FAIL.append(f"{who}: hardlink header metadata for {p} disagrees with inode of {t} (extractor-dependent)")
                fs.paths[p] = tid
                cur.add(p)
                continue
            if kind == "other":
                FAIL.append(f"{who}: unsupported tar entry {p}"); continue
            meta = inode_meta(ti, kind)
            if kind == "file":
                h = hashlib.sha256()
                f = tf.extractfile(ti)
                while True:
                    c = f.read(1 << 20)
                    if not c:
                        break
                    h.update(c)
                meta["size"], meta["sha256"] = ti.size, h.hexdigest()
            fs.paths[p] = fs.new_inode(meta)
            cur.add(p)


def implicit_dirs(fs):
    out = set()
    for p in fs.paths:
        for a in ancestors(p):
            if a not in fs.paths:
                out.add(a)
    return out


def hardlink_groups(fs):
    g = {}
    for p, i in fs.paths.items():
        g.setdefault(i, set()).add(p)
    return {frozenset(s) for s in g.values() if len(s) > 1}


def report(label, items, n=20):
    for x in items[:n]:
        print(f"  {label}: {x}")
    if len(items) > n:
        print(f"  ... {len(items) - n} more {label}")


def compare_fs(a, b):
    pa, pb = set(a.paths), set(b.paths)
    missing, extra = sorted(pa - pb), sorted(pb - pa)
    if missing:
        FAIL.append(f"{len(missing)} paths missing in flat"); report("missing", missing)
    if extra:
        FAIL.append(f"{len(extra)} extra paths in flat"); report("extra", extra)
    bad = []
    for p in sorted(pa & pb):
        ma, mb = a.inodes[a.paths[p]], b.inodes[b.paths[p]]
        for k in sorted(set(ma) | set(mb)):
            if ma.get(k) != mb.get(k):
                (WARN if k == "mtime" else bad).append(f"{p} [{k}] {ma.get(k)!r} != {mb.get(k)!r}")
    if bad:
        FAIL.append(f"{len(bad)} metadata/content differences"); report("diff", bad)
    ga, gb = hardlink_groups(a), hardlink_groups(b)
    if ga != gb:
        FAIL.append("hardlink groups (paths sharing an inode) differ")
        report("only-src", sorted(sorted(g) for g in ga - gb)); report("only-flat", sorted(sorted(g) for g in gb - ga))
    ia, ib = implicit_dirs(a), implicit_dirs(b)
    if ia != ib:
        FAIL.append("implicit (entry-less) parent directories differ")
        report("only-src", sorted(ia - ib)); report("only-flat", sorted(ib - ia))
    print(f"paths: src={len(pa)} flat={len(pb)}  hardlink groups: src={len(ga)} flat={len(gb)}  implicit dirs: {len(ia)}/{len(ib)}")


def fs_bytes(fs):
    seen = {i for i in fs.paths.values()}
    return sum(fs.inodes[i].get("size", 0) for i in seen)


class BlobReader:
    """File-like over `crane blob`; hashes compressed and uncompressed streams."""
    def __init__(self, ref, media_type):
        if "zstd" in media_type:
            raise RuntimeError(f"zstd layers not supported by this verifier: {media_type}")
        self.p = subprocess.Popen(["crane", "blob", ref], stdout=subprocess.PIPE)
        self.zip = "gzip" in media_type
        self.d = zlib.decompressobj(31) if self.zip else None
        self.cs, self.us = hashlib.sha256(), hashlib.sha256()
        self.csize = 0
        self.buf, self.eof = b"", False

    def _fill(self):
        c = self.p.stdout.read(1 << 20)
        if not c:
            self.eof = True
            return
        self.cs.update(c); self.csize += len(c)
        if not self.zip:
            out = c
        else:
            out = b""
            while c:
                out += self.d.decompress(c)
                if self.d.eof:
                    c = self.d.unused_data
                    self.d = zlib.decompressobj(31) if c else self.d
                else:
                    c = b""
        self.us.update(out)
        self.buf += out

    def read(self, n=-1):
        while not self.eof and (n < 0 or len(self.buf) < n):
            self._fill()
        if n < 0:
            n = len(self.buf)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def finish(self):
        while not self.eof:
            self._fill()
        self.buf = b""
        self.p.stdout.close()
        if self.p.wait():
            raise RuntimeError("crane blob failed")
        return "sha256:" + self.cs.hexdigest(), self.csize, "sha256:" + self.us.hexdigest()


class FileLayer:
    def __init__(self, path):
        self.f = open(path, "rb")

    def read(self, n=-1):
        return self.f.read(n)

    def finish(self):
        self.f.close()


def crane_json(*args):
    return json.loads(subprocess.run(["crane", *args], check=True, capture_output=True, text=True).stdout)


def load_side(who, fs, ref, expect_layers):
    """Registry mode: merge all layers of ref, validate structure. Returns summary dict."""
    mf = crane_json("manifest", ref)
    if "layers" not in mf:
        FAIL.append(f"{who}: not a single-image manifest ({mf.get('mediaType')})"); return None, None, None
    cfg = crane_json("config", ref)
    layers = mf["layers"]
    if expect_layers is not None and len(layers) != expect_layers:
        FAIL.append(f"{who}: {len(layers)} layers, expected {expect_layers}")
    rootfs = cfg.get("rootfs", {})
    diffids = rootfs.get("diff_ids", [])
    if rootfs.get("type") != "layers":
        FAIL.append(f"{who}: rootfs.type is {rootfs.get('type')!r}")
    if len(diffids) != len(layers):
        FAIL.append(f"{who}: {len(diffids)} diff_ids vs {len(layers)} manifest layers")
    nonempty = [h for h in cfg.get("history", []) if not h.get("empty_layer")]
    if len(nonempty) != len(layers):
        (FAIL if who == "flat" else WARN).append(f"{who}: {len(nonempty)} non-empty history entries vs {len(layers)} layers")
    repo = ref.split("@")[0]
    for i, l in enumerate(layers):
        r = BlobReader(f"{repo}@{l['digest']}", l["mediaType"])
        apply_layer(fs, r, who, who == "flat")
        cd, cz, ud = r.finish()
        if cd != l["digest"]:
            FAIL.append(f"{who}: layer {i+1} compressed digest {cd} != manifest {l['digest']}")
        if cz != l["size"]:
            FAIL.append(f"{who}: layer {i+1} size {cz} != manifest {l['size']}")
        if i < len(diffids) and ud != diffids[i]:
            FAIL.append(f"{who}: layer {i+1} diff_id {diffids[i]} != computed {ud}")
        print(f"{who} layer {i+1}/{len(layers)} merged ({len(fs.paths)} paths)", flush=True)
    return mf, cfg, sum(l["size"] for l in layers)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src-ref"); ap.add_argument("--flat-ref")
    ap.add_argument("--src-tars", nargs="*"); ap.add_argument("--flat-tars", nargs="*")
    ap.add_argument("--summary")
    a = ap.parse_args()
    src, flat = FS(), FS()
    summary = {}
    if a.src_ref:
        sm, sc, ssz = load_side("src", src, a.src_ref, None)
        fm, fc, fsz = load_side("flat", flat, a.flat_ref, 1)
        if sm and fm:
            if sm["mediaType"] != fm["mediaType"]:
                FAIL.append(f"manifest mediaType {sm['mediaType']} != {fm['mediaType']}")
            if sm["config"]["mediaType"] != fm["config"]["mediaType"]:
                WARN.append(f"config mediaType {sm['config']['mediaType']} != {fm['config']['mediaType']}")
            if sm.get("annotations") != fm.get("annotations"):
                WARN.append("manifest annotations differ")
            drop = ("rootfs", "history", "created")
            ca = {k: v for k, v in sc.items() if k not in drop}
            cb = {k: v for k, v in fc.items() if k not in drop}
            if ca != cb:
                FAIL.append("image config differs")
                for k in sorted(set(ca) | set(cb)):
                    if ca.get(k) != cb.get(k):
                        print(f"  config[{k}]: {ca.get(k)!r} != {cb.get(k)!r}")
            print(f"layers: src={len(sm['layers'])} flat={len(fm['layers'])}; config compared excluding {drop}")
            summary.update(src_layers=len(sm["layers"]), flat_layers=len(fm["layers"]),
                           src_compressed_bytes=ssz, flat_compressed_bytes=fsz)
    else:
        for pth in a.src_tars:
            r = FileLayer(pth); apply_layer(src, r, "src", False); r.finish()
        for pth in a.flat_tars:
            r = FileLayer(pth); apply_layer(flat, r, "flat", True); r.finish()
    compare_fs(src, flat)
    summary.update(src_bytes=fs_bytes(src), flat_bytes=fs_bytes(flat))
    report("warning", WARN)
    summary["result"] = "FAIL" if FAIL else "PASS"
    summary["failures"] = FAIL
    if a.summary:
        json.dump(summary, open(a.summary, "w"), indent=1)
    if FAIL:
        print("\nRESULT: FAIL")
        for f in FAIL:
            print(" -", f)
        sys.exit(1)
    print(f"\nRESULT: PASS ({len(WARN)} warnings)")


if __name__ == "__main__":
    main()
