import re, math, datetime as dt
from typing import List, Dict, Optional
import numpy as np
from sklearn.feature_extraction import FeatureHasher
import lightgbm as lgb
import lief
import json, pickle, io

HASH_DIM = 4096
ENTROPY_CLAMP = (0.0, 8.0)
_SECT_KEYS = (".text", ".rdata", ".data", ".rsrc", ".edata", ".idata")

def _clamp_entropy(x: Optional[float]) -> float:
    try: v = float(x)
    except: v = 0.0
    lo, hi = ENTROPY_CLAMP
    return lo if v < lo else hi if v > hi else v

def _count_rx(b: bytes, rx: bytes) -> int:
    try: return len(list(re.finditer(rx, b, flags=re.I)))
    except: return 0

_LIB_DLL_RX = re.compile(r"\.dll$", re.I)
_hasher = FeatureHasher(n_features=HASH_DIM, input_type="string", alternate_sign=False)  # same as training

def _extract_with_lief(bytez: bytes) -> Dict:
    out = {
        "strings": {
            "paths": _count_rx(bytez, br'c:\\\\'),
            "urls": _count_rx(bytez, br'https?://'),
            "registry": _count_rx(bytez, br'HKEY_'),
            "MZ": _count_rx(bytez, br'MZ'),
        },
        "general": {
            "size": len(bytez), "vsize": 0, "has_debug": 0, "imports": 0, "exports": 0,
            "has_relocations": 0, "has_resources": 0, "has_signature": 0, "has_tls": 0, "symbols": 0,
        },
        "header": {"coff": {"timestamp": 0, "machine": ""}, "optional": {"magic": ""}},
        "section": {"sections": []},
        "imports": {}, "exports": [], "flags": {"coff": [], "dll": []},
        "id": {"machine": "", "magic": ""},
    }
    try:
        pe = lief.PE.parse(io.BytesIO(bytez))
    except Exception:
        return out

    g = out["general"]; h = out["header"]; sec = out["section"]

    try:
        g["vsize"] = getattr(pe, "virtual_size", 0) or 0
        g["has_debug"] = int(getattr(pe, "has_debug", False))
        g["imports"] = len(getattr(pe, "imports", []))
        g["exports"] = len(getattr(pe, "exported_functions", []))
        g["has_relocations"] = int(getattr(pe, "has_relocations", False))
        g["has_resources"] = int(getattr(pe, "has_resources", False))
        g["has_signature"] = int(getattr(pe, "has_signature", False))
        g["has_tls"] = int(getattr(pe, "has_tls", False))
        g["symbols"] = len(getattr(pe, "symbols", []))
    except Exception:
        pass

    try:
        if getattr(pe, "header", None):
            h["coff"]["timestamp"] = getattr(pe.header, "time_date_stamps", 0) or 0
            h["coff"]["machine"] = str(getattr(pe.header, "machine", "")).lower()
        if getattr(pe, "optional_header", None):
            opt = pe.optional_header
            for k in ("major_image_version","minor_image_version",
                      "major_linker_version","minor_linker_version",
                      "major_operating_system_version","minor_operating_system_version",
                      "major_subsystem_version","minor_subsystem_version",
                      "sizeof_code","sizeof_headers","sizeof_heap_commit"):
                h["optional"][k] = getattr(opt, k, 0) or 0
            h["optional"]["magic"] = str(getattr(opt, "magic", "")).lower()
            dll_flags = getattr(opt, "dll_characteristics_lists", []) or []
            out["flags"]["dll"] = [str(x).lower() for x in dll_flags]
    except Exception:
        pass

    try:
        for s in getattr(pe, "sections", []) or []:
            nm = str(getattr(s, "name", "")).lower()
            sz = float(getattr(s, "size", 0) or 0)
            ent = _clamp_entropy(getattr(s, "entropy", 0) or 0)
            sec["sections"].append({"name": nm, "size": sz, "entropy": ent})
    except Exception:
        pass

    try:
        ch = getattr(pe.header, "characteristics_list", []) if getattr(pe, "header", None) else []
        out["flags"]["coff"] = [str(x).lower() for x in ch]
    except Exception:
        pass

    try:
        for e in getattr(pe, "exported_functions", []) or []:
            nm = getattr(e, "name", None)
            if nm: out["exports"].append(str(nm).lower())
    except Exception:
        pass

    imports = {}
    try:
        for lib in getattr(pe, "imports", []) or []:
            lib_name = str(getattr(lib, "name", "")).lower()
            funcs = []
            for entry in getattr(lib, "entries", []) or []:
                nm = getattr(entry, "name", None)
                if nm:
                    funcs.append(str(nm).lower())
                else:
                    try:
                        ordv = int(getattr(entry, "ordinal", 0))
                        funcs.append(f"ordinal:{ordv}")
                    except Exception:
                        pass
            if lib_name and funcs:
                imports[lib_name] = funcs
    except Exception:
        pass
    out["imports"] = imports

    out["id"]["machine"] = h["coff"]["machine"]
    out["id"]["magic"] = h["optional"]["magic"]
    return out

def _numeric(sample: Dict) -> np.ndarray:
    out: List[float] = []
    s = sample["strings"]
    out += [ float(s["paths"]), float(s["urls"]), float(s["registry"]), float(s["MZ"]) ]

    g = sample["general"]
    for k in ("size","vsize","has_debug","imports","exports","has_relocations","has_resources","has_signature","has_tls","symbols"):
        out.append(float(g.get(k, 0)))

    ts = float(sample["header"]["coff"]["timestamp"])
    if not (0 <= ts <= 2**31 - 1): ts = 0.0
    out.append(ts)

    opt = sample["header"]["optional"]
    for k in ("major_image_version","minor_image_version",
              "major_linker_version","minor_linker_version",
              "major_operating_system_version","minor_operating_system_version",
              "major_subsystem_version","minor_subsystem_version",
              "sizeof_code","sizeof_headers","sizeof_heap_commit"):
        out.append(float(opt.get(k, 0)))

    year = float(dt.datetime.utcfromtimestamp(ts).year) if ts > 0 else 0.0
    out.append(year)

    secs = sample["section"]["sections"]
    sizes = [ float(x["size"]) for x in secs ]
    ents  = [ _clamp_entropy(x["entropy"]) for x in secs ]
    nsec = float(len(secs))
    size_total = float(np.sum(sizes)) if sizes else 0.0
    size_mean  = float(np.mean(sizes)) if sizes else 0.0
    size_std   = float(np.std(sizes))  if sizes else 0.0
    ent_mean   = float(np.mean(ents))  if ents  else 0.0
    ent_std    = float(np.std(ents))   if ents  else 0.0
    ent_max    = float(np.max(ents))   if ents  else 0.0
    out += [ nsec, size_total, size_mean, size_std, ent_mean, ent_std, ent_max ]

    names = { x["name"] for x in secs }
    for k in _SECT_KEYS:
        out.append(1.0 if k in names else 0.0)

    return np.asarray(out, dtype=np.float32)

def _tokens(sample: Dict) -> List[str]:
    toks: List[str] = []
    mach = sample["id"].get("machine","")
    magic = sample["id"].get("magic","")
    if mach:  toks.append(f"id:machine={mach}")
    if magic: toks.append(f"id:magic={magic}")

    for c in sample["flags"].get("coff", []): toks.append(f"flag:coff={c}")
    for d in sample["flags"].get("dll",  []): toks.append(f"flag:dll={d}")

    for s in sample["section"]["sections"]:
        nm = s.get("name","")
        if nm: toks.append(f"sec:{nm}")

    for e in sample.get("exports", []):
        toks.append(f"exp:{e}")

    for k, v in (sample.get("imports") or {}).items():
        k_str = str(k).lower()
        vs = v if isinstance(v, list) else []
        key_looks_lib = bool(_LIB_DLL_RX.search(k_str)) or ("api" not in k_str and "." in k_str)
        if key_looks_lib:
            lib = k_str
            toks.append(f"lib:{lib}")
            for fn in vs:
                fnl = str(fn).lower()
                toks.append(f"api:{fnl}")
                toks.append(f"libapi:{lib}::{fnl}")
        else:
            fn = k_str
            toks.append(f"api:{fn}")
            for lib in vs:
                libl = str(lib).lower()
                toks.append(f"lib:{libl}")
                toks.append(f"libapi:{libl}::{fn}")
    return toks

def _featurize(bytez: bytes) -> np.ndarray:
    sample = _extract_with_lief(bytez)
    num = _numeric(sample)
    hashed = _hasher.transform([_tokens(sample)]).toarray().astype(np.float32).ravel()
    x = np.concatenate([num, hashed]).astype(np.float32)
    return x.reshape(1, -1)

class LGBMModel:
    """LightGBM (Booster or pickled LGBMClassifier) + hashed features; returns 0/1."""
    def __init__(self, model_file):
        self.threshold = 0.978408
        self.n_features = None

        try:
            model_file.seek(0)
            obj = pickle.load(model_file)
            if isinstance(obj, dict) and "booster_model_str" in obj:
                self.booster = lgb.Booster(model_str=obj["booster_model_str"])
                self.threshold = float(obj.get("threshold", self.threshold))
                self.n_features = int(obj.get("n_features", 0)) or None
            else:
                self.clf = obj
        except Exception:
            model_file.seek(0)
            data = model_file.read()
            if isinstance(data, (bytes, bytearray)):
                data = data.decode("utf-8", errors="ignore")
            self.booster = lgb.Booster(model_str=data)

    def model_info(self):
        return {"name": "LGBMModel", "version": "1.0", "type": "PE malware classifier"}

    def predict(self, bytez: bytes) -> int:
        try:
            X = _featurize(bytez)
            if self.n_features is not None and X.shape[1] != self.n_features:
              return 1
        except Exception:
            return 1

        if self.clf is not None:
            try:
                if hasattr(self.clf, "predict_proba"):
                    p = float(self.clf.predict_proba(X)[0,1])
                    return int(p >= self.threshold)
                pred = int(self.clf.predict(X)[0])
                return 1 if pred >= 1 else 0
            except Exception:
                return 1

        try:
            p = self.booster.predict(X, num_iteration=self.booster.best_iteration)
            p = float(p[0]) if np.ndim(p) else float(p)
            return int(p >= self.threshold)
        except Exception:
            return 1
