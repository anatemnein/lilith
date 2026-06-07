import json
import os
import glob
import secrets


class Workspace:
    def __init__(self):
        self.directory = self._find_or_create()
        print(f"[*] Workspace: {self.directory}")

    def _find_or_create(self):
        if os.environ.get("WORKSPACE"):
            d = os.path.join(os.environ["WORKSPACE"], "lilith")
            os.makedirs(d, exist_ok=True)
            return d

        home = os.path.expanduser("~")
        exegol_base = os.path.join(home, ".exegol", "workspaces")
        if os.path.isdir(exegol_base):
            candidates = [d for d in glob.glob(os.path.join(exegol_base, "*")) if os.path.isdir(d)]
            if candidates:
                ws = max(candidates, key=os.path.getmtime)
                d  = os.path.join(ws, "lilith")
                os.makedirs(d, exist_ok=True)
                return d

        d = os.path.join(home, ".lilith")
        os.makedirs(d, exist_ok=True)
        return d

    def path(self, *parts):
        return os.path.join(self.directory, *parts)

    def enc_files(self):
        return glob.glob(self.path("*.enc"))

    def list_files(self):
        return sorted(os.listdir(self.directory)) if os.path.isdir(self.directory) else []

    # ── Artifact manifest: maps logical tool keys → random filenames ──────────
    # Prevents tool names from leaking into HTTP logs or stager source.

    def _manifest_path(self) -> str:
        return self.path("manifest.json")

    def _load_manifest(self) -> dict:
        p = self._manifest_path()
        if os.path.exists(p):
            try:
                with open(p) as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_manifest(self, m: dict) -> None:
        with open(self._manifest_path(), "w") as f:
            json.dump(m, f, indent=2)

    def alloc_enc_name(self, tool_key: str) -> str:
        """Return a persistent random .enc filename for tool_key, creating one if needed."""
        m = self._load_manifest()
        k = f"enc_{tool_key}"
        if k not in m:
            m[k] = secrets.token_hex(8) + ".enc"
            self._save_manifest(m)
        return m[k]

    def get_enc_name(self, tool_key: str) -> str | None:
        """Return the random .enc filename for tool_key, or None if not yet encoded."""
        return self._load_manifest().get(f"enc_{tool_key}")

    def alloc_stager_name(self, tool_key: str) -> str:
        """Return a persistent random .ps1 filename for tool_key's stager."""
        m = self._load_manifest()
        k = f"stager_{tool_key}"
        if k not in m:
            m[k] = secrets.token_hex(8) + ".ps1"
            self._save_manifest(m)
        return m[k]

    def set_tool_meta(self, tool_key: str, meta: dict) -> None:
        """Store build-time metadata for a tool (e.g. clr path flag, baked args)."""
        m = self._load_manifest()
        m[f"meta_{tool_key}"] = meta
        self._save_manifest(m)

    def get_tool_meta(self, tool_key: str) -> dict:
        """Return build-time metadata for a tool, or empty dict if none."""
        return self._load_manifest().get(f"meta_{tool_key}", {})
