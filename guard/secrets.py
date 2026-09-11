"""Secret list: values loaded from KEY=value env files, refreshed on mtime.

Never logs or returns a value to anything but the masker. Names only leave here.
"""
import base64
import binascii
import os
import re
import time

_MIN_LEN = 12
_REFRESH_S = 30


def secret_paths(cfg):
    """`secret_files` from the rules config plus LLM_GUARD_SECRET_FILES (colon-separated)."""
    paths = list(cfg.get("secret_files") or [])
    extra = os.environ.get("LLM_GUARD_SECRET_FILES", "")
    paths += [p for p in extra.split(":") if p]
    return paths


def _encoded_forms(value):
    """Base64 (standard and URL-safe, at all three byte alignments) and hex spellings of a
    value, trimmed to the characters that depend on the value alone. A key that leaves via
    `| base64` or `| xxd` is still recognised inside the encoded blob."""
    out = set()
    raw = value.encode("utf-8", "replace")
    for k in (0, 1, 2):
        enc = base64.b64encode(b"\x00" * k + raw).decode().rstrip("=")
        head = (0, 2, 3)[k]                       # chars that mix in the prefix bytes
        tail = 0 if (k + len(raw)) % 3 == 0 else 1  # last char mixes in whatever follows
        core = enc[head:len(enc) - tail] if tail else enc[head:]
        if len(core) >= _MIN_LEN:
            out.add(core)
            out.add(core.replace("+", "-").replace("/", "_"))
    h = binascii.hexlify(raw).decode()
    out.add(h)
    out.add(h.upper())
    return out


def _parse(path):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k.startswith("export "):
                    k = k[len("export "):].strip()
                v = v.strip().strip('"').strip("'")
                if len(v) >= _MIN_LEN and not v.lower().startswith(("http://", "https://")):
                    out[v] = k
    except OSError:
        pass
    return out


class SecretList:
    def __init__(self, paths):
        self.paths = [os.path.expanduser(p) for p in paths]
        self._sig = None
        self._at = 0.0
        self._values = {}      # value (plain or encoded form) -> KEY NAME
        self._n_plain = 0
        self._rx = None
        self.refresh(force=True)

    def _signature(self):
        sig = []
        for p in self.paths:
            try:
                st = os.stat(p)
                sig.append((p, st.st_mtime_ns, st.st_size))
            except OSError:
                sig.append((p, None, None))
        return tuple(sig)

    def refresh(self, force=False):
        now = time.time()
        if not force and now - self._at < _REFRESH_S:
            return
        self._at = now
        sig = self._signature()
        if sig == self._sig and not force:
            return
        self._sig = sig
        vals, plain = {}, 0
        for p in self.paths:
            for v, k in _parse(p).items():
                if v not in vals:
                    plain += 1
                vals.setdefault(v, k)
                for e in _encoded_forms(v):
                    vals.setdefault(e, k)
        self._values = vals
        self._n_plain = plain
        if vals:
            alts = sorted(vals, key=len, reverse=True)
            self._rx = re.compile("|".join(re.escape(v) for v in alts))
        else:
            self._rx = None

    @property
    def names(self):
        return sorted(set(self._values.values()))

    def __len__(self):
        """Number of plain secret values (encoded spellings are not counted)."""
        return self._n_plain

    def mask(self, text, placeholder="<<REDACTED:{name}>>"):
        """Return (masked_text, {key_name: count})."""
        self.refresh()
        if not self._rx or not text:
            return text, {}
        counts = {}

        def sub(m):
            name = self._values.get(m.group(0), "SECRET")
            counts[name] = counts.get(name, 0) + 1
            return placeholder.format(name=name)

        return self._rx.sub(sub, text), counts

    def contains(self, text):
        """Key names whose value occurs in text (no values returned)."""
        self.refresh()
        if not self._rx or not text:
            return []
        return sorted({self._values.get(m.group(0), "SECRET") for m in self._rx.finditer(text)})
