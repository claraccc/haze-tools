import sys
import os
import re
import json
import shutil
import asyncio
import base64
import io
import struct
import zlib
import zipfile
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict
from urllib.parse import urljoin
from datetime import datetime

import httpx
import vdf  # pip install vdf
import requests  # usamos requests pro download dos .lua (igual no teu script PyQt)

from Crypto.Cipher import AES           # pip install pycryptodome
from Crypto.Util.Padding import unpad

from steam.client import SteamClient    # pip install steam
from steam.client.cdn import CDNClient, ContentServer
from steam.protobufs.content_manifest_pb2 import (
    ContentManifestMetadata,
    ContentManifestPayload,
)

# --- GUI (Tkinter + opcional drag-and-drop) ---
import tkinter as tk
from tkinter import (
    messagebox,
    filedialog,
    scrolledtext,
    simpledialog,
)

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD   # pip install tkinterdnd2
    DND_AVAILABLE = True
except ImportError:
    TkinterDnD = tk
    DND_AVAILABLE = False

# Banner / descrição
from PIL import Image, ImageTk  # pip install pillow


# ============================
# TEMA STEAM + IDIOMAS
# ============================

STEAM_COLORS = {
    "bg": "#171A21",        # fundo principal Steam
    "bg_alt": "#1B2838",    # painéis/cards
    "fg": "#C7D5E0",        # texto padrão
    "accent": "#66C0F4",    # azul Steam
    "button_bg": "#2A475E",
    "button_hover": "#66C0F4",
}

LANG_STRINGS = {
    "en": {
        "window_title": "A SteamTools remake",

        # Steam & AppList
        "steam_dir": "Steam directory:",
        "browse": "Browse",
        "open_depotcache": "Open depotcache",
        "applist_dir": "Applist directory:",
        "applist_hint": "Applist is the folder where 0.txt, 1.txt, ... live (Luma/GreenLuma)",

        # Luma / Injector
        "run_luma": "Run Luma/Injector",
        "set_injector": "Set Injector",
        "injector_hint": "● green = Injector configured",

        # Search / Profiles
        "search_game": "Search game (name or AppID):",
        "get_lua_block": "Download Lua and Manifests",
        "get_lua_steam_btn": "Download Manifests from Steam",
        "get_lua_cache_btn": "Download Manifests from Cache",

        "current_profile": "Current profile:",
        "apply_profile": "Apply profile",
        "new_profile": "New profile",
        "duplicate_profile": "Duplicate profile",
        "delete_profile": "Delete profile",
        "export_profile": "Export profile",
        "import_profile": "Import profile",

        "games_in_profile": "Games in this profile:",
        "search": "Search:",

        # Remove? Apenas mantido para compatibilidade
        "copy_appid": "Copy AppID",
        "delete_game": "Delete selected game",

        # Drag-drop area
        "drop_lua":
            "Drop files here:\n"
            ".LUA = Download updated manifests from Steam\n"
            ".ZIP = Install your cached manifests",

        "select_lua": "Select .lua...",
        "select_zip": "Select .zip...",
        "lua_block_title": "Manage Lua & Manifests",        
    },

    "pt": {
        "window_title": "A SteamTools remake",

        # Steam & AppList
        "steam_dir": "Diretório da Steam:",
        "browse": "Procurar",
        "open_depotcache": "Abrir depotcache",
        "applist_dir": "Diretório da AppList:",
        "applist_hint": "A AppList é a pasta onde ficam 0.txt, 1.txt, ... (Luma/GreenLuma)",

        # Luma / Injector
        "run_luma": "Rodar Luma/Injector",
        "set_injector": "Setar Injector",
        "injector_hint": "● verde = Injector configurado",

        # Buscar / Lua / Manifest
        "search_game": "Buscar jogo (nome ou AppID):",
        "get_lua_block": "Baixar Lua e Manifest",
        "get_lua_steam_btn": "Baixar Manifest da Steam",
        "get_lua_cache_btn": "Baixar Manifest do Cache",

        "current_profile": "Profile atual:",
        "apply_profile": "Aplicar profile",
        "new_profile": "Nova profile",
        "duplicate_profile": "Duplicar profile",
        "delete_profile": "Deletar profile",
        "export_profile": "Exportar profile",
        "import_profile": "Importar profile",

        "games_in_profile": "Jogos nesta profile:",
        "search": "Buscar:",

        # Removido mas mantido para segurança
        "copy_appid": "Copiar AppID",
        "delete_game": "Deletar jogo selecionado",

        # Área de arrastar
        "drop_lua":
            "Arraste arquivos aqui:\n"
            ".LUA = Baixa manifests atualizados da Steam\n"
            ".ZIP = Instala seus .manifest do Cache",

        "select_lua": "Selecionar .lua...",
        "select_zip": "Selecionar .zip...",
        "lua_block_title": "Gerenciar Lua e Manifest",
    }
}


# ============================================================
# CAMINHOS BASE (AGORA IGUAL AO TEU PYQT: sys.argv[0])
# ============================================================

SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(sys.argv[0])))

CONFIG_FILE = SCRIPT_DIR / "config.json"
PROFILES_FILE = SCRIPT_DIR / "profiles.json"
CACHE_BANNERS_DIR = SCRIPT_DIR / "cache_banners"
LUA_FILES_DIR = SCRIPT_DIR / "lua_files"
ZIPS_DIR = SCRIPT_DIR / "zips"

LUA_FILES_DIR.mkdir(exist_ok=True)
ZIPS_DIR.mkdir(exist_ok=True)
MAX_APPLIST_IDS = 130

STEAM_HTTP_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; LumaProfileManager/1.0)"
}


def load_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    try:
        with CONFIG_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def save_config(cfg: dict) -> bool:
    try:
        with CONFIG_FILE.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=4)
        return True
    except OSError:
        return False


def load_profiles() -> dict:
    """
    Estrutura:
    {
      "profiles": {
        "Default": {
          "entries": [
             {"app_id": "603850", "name": "No, I'm not a Human", "ids": ["603850","40801",...]},
             ...
          ]
        },
        ...
      },
      "last_profile": "Default"
    }
    """
    base = {"profiles": {}, "last_profile": None}
    if not PROFILES_FILE.exists():
        return base
    try:
        with PROFILES_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            base.update(data)
    except Exception:
        pass
    if not isinstance(base.get("profiles"), dict):
        base["profiles"] = {}
    return base


def save_profiles(data: dict) -> bool:
    try:
        with PROFILES_FILE.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return True
    except OSError:
        return False


# ============================================================
# PARSER DO .LUA
# ============================================================

@dataclass
class DepotKeyPair:
    depot_id: str
    decryption_key: str


@dataclass
class LuaParsedInfo:
    path: Path
    contents: str
    app_id: str
    depots: List[DepotKeyPair]


def parse_lua(lua_path: Path) -> LuaParsedInfo:
    contents = lua_path.read_text(encoding="utf-8", errors="replace")

    app_id_regex = re.compile(r"addappid\s*\(\s*(\d+)\s*\)", re.IGNORECASE)
    depot_dec_key_regex = re.compile(
        r"addappid\s*\(\s*(\d+)\s*,\s*\d+\s*,\s*['\"](\S+)['\"]\s*\)",
        re.IGNORECASE,
    )

    app_match = app_id_regex.search(contents)
    depot_matches = depot_dec_key_regex.findall(contents)

    if not app_match:
        raise RuntimeError("App ID não encontrado no .lua (addappid(appid))")

    app_id = app_match.group(1)

    if not depot_matches:
        raise RuntimeError("Nenhuma decryption key encontrada no .lua")

    depots = [
        DepotKeyPair(depot_id=appid_str, decryption_key=key_str)
        for (appid_str, key_str) in depot_matches
    ]

    return LuaParsedInfo(
        path=lua_path,
        contents=contents,
        app_id=app_id,
        depots=depots,
    )


# ============================================================
# CONFIG.VDF
# ============================================================

def enter_path(obj, *paths, mutate=False, ignore_case=False):
    current = obj
    for key in paths:
        original = key
        if ignore_case and isinstance(key, str):
            key = key.lower()

        key_map = {}
        for x in current:
            if ignore_case and isinstance(x, str):
                key_map[x.lower()] = x
            else:
                key_map[x] = x

        if key in key_map:
            current = current[key_map[key]]
        else:
            if not mutate:
                return type(current)()
            new_node = type(current)()
            current[original] = new_node
            current = new_node
    return current


class VDFLoadAndDumper:
    def __init__(self, vdf_file: Path):
        self.vdf_file = vdf_file
        self.data = None

    def __enter__(self):
        with self.vdf_file.open("r", encoding="utf-8") as f:
            self.data = vdf.load(f)
        return self.data

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None and self.data is not None:
            with self.vdf_file.open("w", encoding="utf-8") as f:
                vdf.dump(self.data, f, pretty=True)
        return False


def add_decryption_keys_to_config(steam_path: Path, lua: LuaParsedInfo, log):
    vdf_file = steam_path / "config" / "config.vdf"
    if not vdf_file.exists():
        raise FileNotFoundError(f"config.vdf não encontrado: {vdf_file}")

    backup = vdf_file.with_suffix(".vdf.backup")
    shutil.copyfile(vdf_file, backup)
    log(f"Backup criado: {backup}")

    with VDFLoadAndDumper(vdf_file) as data:
        for depot in lua.depots:
            depots_dict = enter_path(
                data,
                "InstallConfigStore",
                "Software",
                "Valve",
                "Steam",
                "depots",
                mutate=True,
                ignore_case=True,
            )

            depot_id = depot.depot_id
            if depot_id not in depots_dict:
                depots_dict[depot_id] = {"DecryptionKey": depot.decryption_key}
                log(f"Adicionado: {depot_id}")
            else:
                log(f"Já existia: {depot_id}")


# ============================================================
# .ACF
# ============================================================

INVALID_FILENAME_CHARS = r'<>:"/\\|?*\n\r\t'


def sanitize_filename(x: str) -> str:
    x = re.sub(f"[{re.escape(INVALID_FILENAME_CHARS)}]+", "_", x)
    return x.strip().strip(".")


def try_get_game_name(app_id: str) -> str:
    url = f"https://store.steampowered.com/api/appdetails/?appids={app_id}"
    try:
        r = httpx.get(url, timeout=10, headers=STEAM_HTTP_HEADERS)
        if r.status_code == 200:
            data = r.json()
            if data.get(app_id, {}).get("success"):
                return data[app_id]["data"].get("name", f"App {app_id}")
    except Exception:
        pass
    return f"App {app_id}"


def steam_search_first_app(query: str) -> Optional[Dict[str, str]]:
    """
    Busca pela API storesearch e retorna {"appid": "xxx", "name": "Nome"} ou None
    """
    url = "https://store.steampowered.com/api/storesearch/"
    params = {"term": query, "l": "english", "cc": "US"}
    try:
        r = httpx.get(url, params=params, timeout=10, headers=STEAM_HTTP_HEADERS)
        r.raise_for_status()
        data = r.json()
        items = data.get("items") or []
        if not items:
            return None
        first = items[0]
        appid = first.get("id")
        name = first.get("name") or ""
        if not appid:
            return None
        return {"appid": str(appid), "name": name}
    except Exception:
        return None


def ensure_banner_cache(app_id: str, steam_path: Path, log=None):
    """
    Garante que exista um banner (.jpg) e um .txt com descrição
    em cache_banners para o app_id informado.

    Retorna (caminho_imagem_ou_None, caminho_txt_ou_None).
    """
    CACHE_BANNERS_DIR.mkdir(exist_ok=True)
    img_path = CACHE_BANNERS_DIR / f"{app_id}.jpg"
    txt_path = CACHE_BANNERS_DIR / f"{app_id}.txt"

    # Se já existe tudo, só devolve
    if img_path.exists() and txt_path.exists():
        return img_path, txt_path

    descr = ""
    header_url = ""

    # 1) Tenta pegar infos da API da Steam (nome, descrição, header_image)
    try:
        url = f"https://store.steampowered.com/api/appdetails/?appids={app_id}&l=en"
        r = httpx.get(url, timeout=10, headers=STEAM_HTTP_HEADERS)
        if r.status_code == 200:
            data = r.json()
            app = data.get(app_id, {})
            if app.get("success"):
                appdata = app["data"]
                descr = appdata.get("short_description") or appdata.get("about_the_game", "")
                header_url = appdata.get("header_image", "")
    except Exception as e:
        if log:
            log(f"[AVISO] Falha ao obter descrição/header da Steam: {e}")

    # 2) Tenta copiar do appcache\librarycache
    if not img_path.exists():
        try:
            librarycache = steam_path / "appcache" / "librarycache"
            cand = librarycache / f"{app_id}_header.jpg"
            if cand.exists():
                shutil.copyfile(cand, img_path)
                if log:
                    log(f"Banner copiado do librarycache para: {img_path}")
        except Exception as e:
            if log:
                log(f"[AVISO] Erro copiando banner do librarycache: {e}")

    # 3) Se ainda não tem imagem, baixa da URL header_image
    if not img_path.exists() and header_url:
        try:
            r = httpx.get(header_url, timeout=15)
            if r.status_code == 200:
                img_path.write_bytes(r.content)
                if log:
                    log(f"Banner baixado da Steam e salvo em: {img_path}")
        except Exception as e:
            if log:
                log(f"[AVISO] Falha ao baixar banner: {e}")

    # 4) Salva descrição em .txt
    if descr and not txt_path.exists():
        try:
            txt_path.write_text(descr, encoding="utf-8")
            if log:
                log(f"Descrição salva em: {txt_path}")
        except Exception as e:
            if log:
                log(f"[AVISO] Falha ao salvar descrição: {e}")

    if not img_path.exists():
        img_path = None
    if not txt_path.exists():
        txt_path = None

    return img_path, txt_path


def get_steam_libraries(steam_path: Path) -> List[Path]:
    lib_file = steam_path / "config" / "libraryfolders.vdf"
    if not lib_file.exists():
        return [steam_path]

    try:
        with lib_file.open("r", encoding="utf-8") as f:
            data = vdf.load(f)
        libs = data.get("libraryfolders", {})
        paths = []
        for x in libs.values():
            p = Path(x.get("path", ""))
            if p.exists():
                paths.append(p)
        return paths or [steam_path]
    except Exception:
        return [steam_path]


def write_acf_for_lua(steam_path: Path, lua: LuaParsedInfo, log):
    libs = get_steam_libraries(steam_path)
    lib = libs[0]

    acf_path = lib / "steamapps" / f"appmanifest_{lua.app_id}.acf"
    if acf_path.exists():
        backup = acf_path.with_suffix(".acf.backup")
        shutil.copyfile(acf_path, backup)
        log(f"Backup .acf criado: {backup}")

    name = try_get_game_name(lua.app_id)
    folder = sanitize_filename(name)

    content = {
        "AppState": {
            "AppID": lua.app_id,
            "Universe": "1",
            "name": name,
            "installdir": folder,
            "StateFlags": "4",
        }
    }

    acf_path.parent.mkdir(parents=True, exist_ok=True)
    with acf_path.open("w", encoding="utf-8") as f:
        vdf.dump(content, f, pretty=True)

    log(f".acf criado: {acf_path}")


# ============================================================
# MANIFEST: CRIPTO + GMRC + DOWNLOAD → DEPOTCACHE
# ============================================================

def read_nth_file_from_zip_bytes(nth: int, data: bytes) -> Optional[io.BytesIO]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return io.BytesIO(zf.read(zf.filelist[nth].filename))
    except zipfile.BadZipFile:
        return None


PROTOBUF_PAYLOAD_MAGIC = 0x71F617D0
PROTOBUF_METADATA_MAGIC = 0x1F4812BE
PROTOBUF_SIGNATURE_MAGIC = 0x1B81B817
PROTOBUF_ENDOFMANIFEST_MAGIC = 0x32C415AB


def decrypt_filename(b64_name: str, key_bytes: bytes) -> str:
    try:
        decoded = base64.b64decode(b64_name)

        cipher_ecb = AES.new(key_bytes, AES.MODE_ECB)
        iv = cipher_ecb.decrypt(decoded[:16])

        ciphertext = decoded[16:]
        cipher_cbc = AES.new(key_bytes, AES.MODE_CBC, iv)
        decrypted = cipher_cbc.decrypt(ciphertext)

        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.rstrip(b"\x00").decode("utf-8")
    except Exception:
        return b64_name


def decrypt_manifest(encrypted: bytes, out_path: Path, key_hex: str) -> None:
    stream = read_nth_file_from_zip_bytes(0, encrypted) or io.BytesIO(encrypted)

    magic, payload_len = struct.unpack("<II", stream.read(8))
    if magic != PROTOBUF_PAYLOAD_MAGIC:
        raise ValueError("Bad payload magic")
    payload_bytes = stream.read(payload_len)

    magic, metadata_len = struct.unpack("<II", stream.read(8))
    if magic != PROTOBUF_METADATA_MAGIC:
        raise ValueError("Bad metadata magic")
    metadata_bytes = stream.read(metadata_len)

    payload = ContentManifestPayload()
    payload.ParseFromString(payload_bytes)

    key_bytes = bytes.fromhex(key_hex)
    new_files: List[ContentManifestPayload.FileMapping] = []

    for m in payload.mappings:
        new_m = ContentManifestPayload.FileMapping()
        new_m.CopyFrom(m)
        new_m.filename = decrypt_filename(m.filename, key_bytes)
        if m.linktarget:
            new_m.linktarget = decrypt_filename(m.linktarget, key_bytes)
        new_files.append(new_m)

    fixed_payload = ContentManifestPayload()
    fixed_payload.mappings.extend(new_files)
    fixed_payload_bytes = fixed_payload.SerializeToString()

    length_bytes = struct.pack("<I", len(fixed_payload_bytes))
    crc = zlib.crc32(length_bytes + fixed_payload_bytes) & 0xFFFFFFFF

    metadata = ContentManifestMetadata()
    metadata.ParseFromString(metadata_bytes)
    metadata.crc_clear = crc
    metadata.filenames_encrypted = False
    fixed_metadata_bytes = metadata.SerializeToString()

    out_path.parent.mkdir(exist_ok=True)
    with out_path.open("wb") as f:
        f.write(struct.pack("<II", PROTOBUF_PAYLOAD_MAGIC, len(fixed_payload_bytes)))
        f.write(fixed_payload_bytes)
        f.write(struct.pack("<II", PROTOBUF_METADATA_MAGIC, len(fixed_metadata_bytes)))
        f.write(fixed_metadata_bytes)
        f.write(struct.pack("<II", PROTOBUF_SIGNATURE_MAGIC, 0))
        f.write(struct.pack("<I", PROTOBUF_ENDOFMANIFEST_MAGIC))


async def get_request(url: str, timeout: int = 10) -> Optional[str]:
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return None


async def get_gmrc(manifest_id: str) -> str:
    url = f"http://gmrc.openst.top/manifest/{manifest_id}"
    data = await get_request(url, timeout=20)
    if not data:
        raise RuntimeError(f"GMRC request failed for manifest {manifest_id}")
    code = data.strip()
    if not code:
        raise RuntimeError(f"GMRC returned empty code for manifest {manifest_id}")
    return code


def get_manifest_ids(client: SteamClient, lua: LuaParsedInfo, log) -> Dict[str, str]:
    if not client.logged_on:
        log("Conectando na Steam anonimamente...")
        client.anonymous_login()

    info = client.get_product_info([int(lua.app_id)])
    if not info or "apps" not in info or int(lua.app_id) not in info["apps"]:
        raise RuntimeError("Falha ao obter informações do app via Steam")

    app = info["apps"][int(lua.app_id)]
    depots_dict = app.get("depots", {})

    manifest_ids: Dict[str, str] = {}
    skipped: List[str] = []

    seen_depots = set()
    for d in lua.depots:
        depot_id_str = str(d.depot_id)
        if depot_id_str in seen_depots:
            continue
        seen_depots.add(depot_id_str)

        latest = (
            depots_dict.get(depot_id_str, {})
            .get("manifests", {})
            .get("public", {})
            .get("gid")
        )

        if latest:
            log(f"Depot/App {depot_id_str} -> manifest {latest}")
            manifest_ids[depot_id_str] = latest
        else:
            log(f"[AVISO] App/Depot {depot_id_str} não tem manifest público, será ignorado.")
            skipped.append(depot_id_str)

    if not manifest_ids:
        raise RuntimeError("Nenhum manifest público encontrado para esse app (modo Auto).")

    if skipped:
        log(f"[INFO] Entradas ignoradas: {', '.join(skipped)}")

    return manifest_ids


def download_manifests_to_depotcache(steam_path: Path, lua: LuaParsedInfo, log) -> List[Path]:
    client = SteamClient()
    manifest_ids = get_manifest_ids(client, lua, log)
    cdn = CDNClient(client)

    depotcache_dir = steam_path / "depotcache"
    depotcache_dir.mkdir(exist_ok=True)

    key_map = {d.depot_id: d.decryption_key for d in lua.depots}
    written: List[Path] = []

    for depot_id_str, manifest_id in manifest_ids.items():
        key_hex = key_map.get(depot_id_str)
        if not key_hex:
            log(f"[AVISO] Sem decryption key no lua para depot/app {depot_id_str}, pulando.")
            continue

        log(f"\n=== Baixando manifest {manifest_id} para App/Depot {depot_id_str} ===")
        req_code = asyncio.run(get_gmrc(manifest_id))

        srv: ContentServer = cdn.get_content_server()
        proto = "https" if getattr(srv, "https", False) else "http"
        host = srv.host

        url = urljoin(
            f"{proto}://{host}",
            f"depot/{depot_id_str}/manifest/{manifest_id}/5/{req_code}",
        )
        log(f"GET {url}")

        r = httpx.get(url, timeout=None)
        r.raise_for_status()

        out_path = depotcache_dir / f"{depot_id_str}_{manifest_id}.manifest"
        decrypt_manifest(r.content, out_path, key_hex)
        log(f"Manifest descriptografado salvo em: {out_path}")
        written.append(out_path)

    if not written:
        log("[AVISO] Nenhum manifest foi baixado/descriptografado.")
    else:
        log(f"\nConcluído. {len(written)} manifest(s) salvos em depotcache.")

    return written


# ============================================================
# APPLIST / PROFILES
# ============================================================

def extract_ids_from_manifests(manifests: List[Path], log) -> List[str]:
    ids = []
    for m in manifests:
        name = m.name
        if "_" not in name:
            log(f"[AVISO] manifest sem '_': {name}")
            continue
        first = name.split("_", 1)[0]
        if first.isdigit():
            ids.append(first)
        else:
            log(f"[AVISO] ID inválido em {name}")
    seen = set()
    out = []
    for x in ids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def generate_applist_files(applist_dir: Path, ids: List[str], log, profile_name: str = "PROFILE"):
    applist_dir.mkdir(exist_ok=True)

    log("IDs para AppList: " + ", ".join(ids))

    # limpa tudo antes
    for i in range(MAX_APPLIST_IDS):
        p = applist_dir / f"{i}.txt"
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass

    # Segurança extra: não era pra chegar aqui com mais de MAX_APPLIST_IDS
    if len(ids) > MAX_APPLIST_IDS:
        raise RuntimeError(
            f"Tentativa interna de escrever {len(ids)} arquivos na AppList (limite {MAX_APPLIST_IDS})."
        )

    for idx, id_str in enumerate(ids[:MAX_APPLIST_IDS]):
        tgt = applist_dir / f"{idx}.txt"
        with tgt.open("w", encoding="utf-8") as f:
            f.write(id_str + "\n")
        log(f"Criado {tgt.name} = {id_str}")


# ============================================================
# DOWNLOAD DE LUA (SPIN0ZAI / ROBZOMBIE) – CÓPIA DA LÓGICA PYQT
# ============================================================

def download_lua_from_spin0zai(app_id: str):
    """
    Mesma ideia do Spin0zaiWorker:
      - baixa https://github.com/SPIN0ZAi/SB_manifest_DB/archive/refs/heads/{appid}.zip
      - salva em lua_files/{appid}.zip
      - extrai os .lua
      - apaga o zip
    """
    base_url = "https://github.com/SPIN0ZAi/SB_manifest_DB/archive/refs/heads/"
    url = f"{base_url}{app_id}.zip"
    source_name = "SPIN0ZAi"

    target_dir = LUA_FILES_DIR
    zip_path = target_dir / f"{app_id}.zip"

    try:
        print(f"[{source_name}] Tentando download: {url}")
        resp = requests.get(url, stream=True, timeout=15)

        if resp.status_code == 404:
            msg = f"{source_name}: NOT FOUND (404)"
            print(msg)
            return False, msg, None
        elif resp.status_code != 200:
            msg = f"{source_name}: HTTP {resp.status_code}"
            print(msg)
            return False, msg, None

        if not target_dir.exists():
            target_dir.mkdir(parents=True, exist_ok=True)

        # Salva ZIP em disco
        with open(zip_path, "wb") as fp:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    fp.write(chunk)

        print(f"[{source_name}] ZIP salvo em {zip_path}")

        # Extrai, move .lua e apaga zip
        tmp_dir = target_dir / f"__tmp_spin0zai_{app_id}"
        lua_found_paths = []

        try:
            if not tmp_dir.exists():
                tmp_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp_dir)

            for root, dirs, files in os.walk(tmp_dir):
                for fname in files:
                    if fname.lower().endswith(".lua"):
                        src = Path(root) / fname
                        dst = target_dir / fname
                        print(f"[{source_name}] Encontrado LUA: {src} -> {dst}")
                        shutil.move(str(src), str(dst))
                        lua_found_paths.append(dst)

            # limpa zip e tmp
            if zip_path.exists():
                zip_path.unlink()
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)

            if not lua_found_paths:
                msg = f"{source_name}: Nenhum .lua encontrado dentro do zip."
                print(msg)
                return False, msg, None

            msg = f"{source_name}: SUCESSO! {len(lua_found_paths)} .lua movidos para {target_dir}"
            print(msg)
            return True, msg, lua_found_paths[0]

        except Exception as e:
            msg = f"{source_name}: Erro ao extrair/mover .lua: {e}"
            print(msg)
            try:
                if zip_path.exists():
                    zip_path.unlink()
                if tmp_dir.exists():
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
            return False, msg, None

    except requests.exceptions.RequestException as e:
        msg = f"{source_name}: Erro de rede: {e}"
        print(msg)
        return False, msg, None
    except Exception as e:
        msg = f"{source_name}: Erro inesperado: {type(e).__name__}"
        print(msg)
        return False, msg, None


def download_lua_from_robzombie(app_id: str):
    """
    Mesma ideia do RobZombieWorker:
      - baixa https://codeload.github.com/RobZombie-ux/KsvHub/zip/refs/heads/{appid}
      - salva lua_files/{appid}.zip
      - extrai .lua
      - apaga zip
    """
    base_url = "https://codeload.github.com/RobZombie-ux/KsvHub/zip/refs/heads/"
    url = f"{base_url}{app_id}"
    source_name = "RobZombie-ux"

    target_dir = LUA_FILES_DIR
    zip_path = target_dir / f"{app_id}.zip"

    try:
        print(f"[{source_name}] Tentando download: {url}")
        resp = requests.get(url, stream=True, timeout=15)

        if resp.status_code == 404:
            msg = f"{source_name}: NOT FOUND (404)"
            print(msg)
            return False, msg, None
        elif resp.status_code != 200:
            msg = f"{source_name}: HTTP {resp.status_code}"
            print(msg)
            return False, msg, None

        if not target_dir.exists():
            target_dir.mkdir(parents=True, exist_ok=True)

        with open(zip_path, "wb") as fp:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    fp.write(chunk)

        print(f"[{source_name}] ZIP salvo em {zip_path}")

        tmp_dir = target_dir / f"__tmp_robzombie_{app_id}"
        lua_found_paths = []

        try:
            if not tmp_dir.exists():
                tmp_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp_dir)

            for root, dirs, files in os.walk(tmp_dir):
                for fname in files:
                    if fname.lower().endswith(".lua"):
                        src = Path(root) / fname
                        dst = target_dir / fname
                        print(f"[{source_name}] Encontrado LUA: {src} -> {dst}")
                        shutil.move(str(src), str(dst))
                        lua_found_paths.append(dst)

            if zip_path.exists():
                zip_path.unlink()
            if tmp_dir.exists():
                shutil.rmtree(tmp_dir, ignore_errors=True)

            if not lua_found_paths:
                msg = f"{source_name}: Nenhum .lua encontrado dentro do zip."
                print(msg)
                return False, msg, None

            msg = f"{source_name}: SUCESSO! {len(lua_found_paths)} .lua movidos para {target_dir}"
            print(msg)
            return True, msg, lua_found_paths[0]

        except Exception as e:
            msg = f"{source_name}: Erro ao extrair/mover .lua: {e}"
            print(msg)
            try:
                if zip_path.exists():
                    zip_path.unlink()
                if tmp_dir.exists():
                    shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
            return False, msg, None

    except requests.exceptions.RequestException as e:
        msg = f"{source_name}: Erro de rede: {e}"
        print(msg)
        return False, msg, None
    except Exception as e:
        msg = f"{source_name}: Erro inesperado: {type(e).__name__}"
        print(msg)
        return False, msg, None


def download_lua_with_fallback(app_id: str):
    """
    Tenta SPIN0ZAI, depois RobZombie.
    Retorna (success, msg, Path|None).
    """
    # 1) SPIN0ZAI
    ok, msg, lua_path = download_lua_from_spin0zai(app_id)
    if ok and lua_path:
        return True, msg, lua_path

    # 2) RobZombie
    ok2, msg2, lua_path2 = download_lua_from_robzombie(app_id)
    if ok2 and lua_path2:
        full_msg = msg + "\n" + msg2
        return True, full_msg, lua_path2

    full_msg = msg + "\n" + msg2
    return False, full_msg, None


def download_cache_zip_from_spin0zai(app_id: str):
    """
    Versão 'cache': baixa o mesmo ZIP do repositório SPIN0ZAi,
    mas guarda em ZIPS_DIR sem extrair.
    """
    base_url = "https://github.com/SPIN0ZAi/SB_manifest_DB/archive/refs/heads/"
    url = f"{base_url}{app_id}.zip"
    source_name = "SPIN0ZAi-cache"

    zip_path = ZIPS_DIR / f"{app_id}_spin0zai.zip"

    try:
        print(f"[{source_name}] Tentando download: {url}")
        resp = requests.get(url, stream=True, timeout=15)

        if resp.status_code == 404:
            msg = f"{source_name}: NOT FOUND (404)"
            print(msg)
            return False, msg, None
        elif resp.status_code != 200:
            msg = f"{source_name}: HTTP {resp.status_code}"
            print(msg)
            return False, msg, None

        with open(zip_path, "wb") as fp:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    fp.write(chunk)

        msg = f"{source_name}: ZIP salvo em {zip_path}"
        print(msg)
        return True, msg, zip_path

    except requests.exceptions.RequestException as e:
        msg = f"{source_name}: Erro de rede: {e}"
        print(msg)
        return False, msg, None
    except Exception as e:
        msg = f"{source_name}: Erro inesperado: {type(e).__name__}"
        print(msg)
        return False, msg, None


def download_cache_zip_from_robzombie(app_id: str):
    """
    Versão 'cache' para o repositório do RobZombie-ux.
    """
    base_url = "https://codeload.github.com/RobZombie-ux/KsvHub/zip/refs/heads/"
    url = f"{base_url}{app_id}"
    source_name = "RobZombie-cache"

    zip_path = ZIPS_DIR / f"{app_id}_robzombie.zip"

    try:
        print(f"[{source_name}] Tentando download: {url}")
        resp = requests.get(url, stream=True, timeout=15)

        if resp.status_code == 404:
            msg = f"{source_name}: NOT FOUND (404)"
            print(msg)
            return False, msg, None
        elif resp.status_code != 200:
            msg = f"{source_name}: HTTP {resp.status_code}"
            print(msg)
            return False, msg, None

        with open(zip_path, "wb") as fp:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    fp.write(chunk)

        msg = f"{source_name}: ZIP salvo em {zip_path}"
        print(msg)
        return True, msg, zip_path

    except requests.exceptions.RequestException as e:
        msg = f"{source_name}: Erro de rede: {e}"
        print(msg)
        return False, msg, None
    except Exception as e:
        msg = f"{source_name}: Erro inesperado: {type(e).__name__}"
        print(msg)
        return False, msg, None


def download_cache_zip_with_fallback(app_id: str):
    """
    Tenta SPIN0ZAi, depois RobZombie, só em repositórios GitHub.
    NÃO chama last_option nem GMRC.
    """
    ok, msg, zip_path = download_cache_zip_from_spin0zai(app_id)
    if ok and zip_path:
        return True, msg, zip_path

    ok2, msg2, zip_path2 = download_cache_zip_from_robzombie(app_id)
    if ok2 and zip_path2:
        full_msg = msg + "\n" + msg2
        return True, full_msg, zip_path2

    full_msg = msg + "\n" + msg2
    return False, full_msg, None


# ============================================================
# GUI
# ============================================================

class AppGUI:
    def __init__(self):
        self.config = load_config()
        self.profiles_data = load_profiles()
        self._ensure_profiles_initialized()

        saved_applist = self.config.get("applist_path", "")
        saved_steam = self.config.get("steam_path", r"C:\Program Files (x86)\Steam")

        if DND_AVAILABLE:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()

        # cores / tema Steam
        self.bg = STEAM_COLORS["bg"]
        self.bg_alt = STEAM_COLORS["bg_alt"]
        self.fg = STEAM_COLORS["fg"]
        self.accent = STEAM_COLORS["accent"]

        # idioma
        self.lang = self.config.get("language")
        if self.lang not in ("en", "pt"):
            self.lang = self.ask_language_at_start()
            self.config["language"] = self.lang
            save_config(self.config)

        # título principal da janela
        self.root.title("HAZE TOOLS")
        self.root.geometry("1149x841")
        self.root.configure(bg=self.bg)

        self.steam_path_var = tk.StringVar(value=saved_steam)
        self.applist_path_var = tk.StringVar(value=saved_applist)

        self.current_profile_var = tk.StringVar(value=self.profiles_data["last_profile"])

        # campo de busca na lista de jogos
        self.profile_search_var = tk.StringVar()

        # para log
        self.log_box = None

        self._build_ui()
        self.update_luma_status()
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()

    # --------- Idioma ---------

    def t(self, key: str) -> str:
        return LANG_STRINGS.get(self.lang, LANG_STRINGS["en"]).get(key, key)

    def ask_language_at_start(self) -> str:
        win = tk.Toplevel(self.root)
        win.title("Language / Idioma")
        win.configure(bg=self.bg)
        win.resizable(False, False)
        win.grab_set()
        win.transient(self.root)

        tk.Label(
            win,
            text="Choose interface language / Escolha o idioma da interface:",
            bg=self.bg,
            fg=self.fg,
            padx=20,
            pady=10,
            wraplength=300,
            justify="center",
        ).pack()

        choice_var = tk.StringVar(value="")

        def choose_en():
            choice_var.set("en")
            win.destroy()

        def choose_pt():
            choice_var.set("pt")
            win.destroy()

        btn_frame = tk.Frame(win, bg=self.bg)
        btn_frame.pack(pady=10)

        tk.Button(
            btn_frame,
            text="🇺🇸  English",
            command=choose_en,
            bg=self.bg_alt,
            fg=self.fg,
            activebackground=STEAM_COLORS["button_hover"],
            activeforeground="white",
            relief="flat",
            padx=12,
            pady=4,
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame,
            text="🇧🇷  Português",
            command=choose_pt,
            bg=self.bg_alt,
            fg=self.fg,
            activebackground=STEAM_COLORS["button_hover"],
            activeforeground="white",
            relief="flat",
            padx=12,
            pady=4,
        ).pack(side="left", padx=6)

        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_variable(choice_var)
        lang = choice_var.get() or "en"
        return lang

    # --------- setup internals ---------

    def _ensure_profiles_initialized(self):
        if "profiles" not in self.profiles_data or not isinstance(self.profiles_data["profiles"], dict):
            self.profiles_data["profiles"] = {}
        if not self.profiles_data["profiles"]:
            self.profiles_data["profiles"]["Default"] = {"entries": []}
        if not self.profiles_data.get("last_profile") or \
           self.profiles_data["last_profile"] not in self.profiles_data["profiles"]:
            self.profiles_data["last_profile"] = list(self.profiles_data["profiles"].keys())[0]

    # --------- UI ---------

    def _build_ui(self):
        # ============================
        # HEADER
        # ============================
        header = tk.Frame(self.root, bg=self.bg_alt, height=60)
        header.pack(fill="x", side="top")

        title_lbl = tk.Label(
            header,
            text="HAZE TOOLS",
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 14, "bold"),
            anchor="w",
        )
        title_lbl.pack(side="left", padx=15, pady=(8, 0))

        subtitle = tk.Label(
            header,
            text="A SteamTools remake",
            bg=self.bg_alt,
            fg="#8F98A0",
            font=("Segoe UI", 9),
            anchor="w",
        )
        subtitle.pack(side="left", padx=(10, 0), pady=(28, 0))

        lang_lbl = tk.Label(
            header,
            text="BR PT" if self.lang == "pt" else "EN",
            bg=self.bg_alt,
            fg=self.accent,
            font=("Segoe UI", 10, "bold"),
        )
        lang_lbl.pack(side="right", padx=15, pady=10)

        # ============================
        # ÁREA PRINCIPAL (2 COLUNAS)
        # ============================
        main_frame = tk.Frame(self.root, bg=self.bg)
        main_frame.pack(fill="both", expand=True, padx=10, pady=(5, 0))

        # --------- COLUNA ESQUERDA: LISTA DE JOGOS ---------
        left_frame = tk.Frame(main_frame, bg=self.bg)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        # header da lista: só busca
        library_header = tk.Frame(left_frame, bg=self.bg)
        library_header.pack(fill="x", pady=(0, 4))

        tk.Label(
            library_header,
            text="Buscar:" if self.lang == "pt" else "Search:",
            bg=self.bg,
            fg=self.fg,
            font=("Segoe UI", 9),
        ).pack(side="left", padx=(0, 4))

        entry_search = tk.Entry(
            library_header,
            textvariable=self.profile_search_var,
            width=28,
            bg=self.bg_alt,
            fg=self.fg,
            insertbackground=self.fg,
            relief="flat",
        )
        entry_search.pack(side="left")
        
        self.profile_search_var.trace_add("write", lambda *args: self.refresh_profile_view())

        # CARD da lista de jogos: canvas + frame (para scroll)
        library_card = tk.Frame(left_frame, bg=self.bg_alt, bd=1, relief="solid")
        library_card.pack(fill="both", expand=True)

        self.games_canvas = tk.Canvas(library_card, bg=self.bg, highlightthickness=0, bd=0)
        self.games_canvas.pack(side="left", fill="both", expand=True)

        games_scrollbar = tk.Scrollbar(library_card, orient="vertical", command=self.games_canvas.yview)
        games_scrollbar.pack(side="right", fill="y")

        self.games_canvas.configure(yscrollcommand=games_scrollbar.set)

        self.cards_frame = tk.Frame(self.games_canvas, bg=self.bg)
        self.games_canvas.create_window((0, 0), window=self.cards_frame, anchor="nw")

        def _on_cards_configure(event):
            self.games_canvas.configure(scrollregion=self.games_canvas.bbox("all"))

        self.cards_frame.bind("<Configure>", _on_cards_configure)

        # Rodapé quota/contagem
        library_footer = tk.Frame(left_frame, bg=self.bg)
        library_footer.pack(fill="x", pady=(4, 0))

        self.profile_quota_label = tk.Label(
            library_footer,
            text="",
            bg=self.bg,
            fg=self.accent,
            font=("Segoe UI", 9, "bold"),
        )
        self.profile_quota_label.pack(side="left")

        self.profile_summary_label = tk.Label(
            library_footer,
            text="",
            bg=self.bg,
            fg=self.fg,
            font=("Segoe UI", 9),
        )
        self.profile_summary_label.pack(side="right")

        # inicializa contagem para 0, já respeitando o idioma
        self.update_profile_footer(num_games=0, total_ids=0)

        # --------- COLUNA DIREITA: CONTROLES ---------
        right_frame = tk.Frame(main_frame, bg=self.bg)
        right_frame.pack(side="right", fill="y", padx=(5, 0))

        # ---- Steam & AppList
        paths_card = tk.Frame(right_frame, bg=self.bg_alt, bd=1, relief="solid")
        paths_card.pack(fill="x", pady=(0, 6))

        title_paths = tk.Label(
            paths_card,
            text="Steam & AppList",
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 10, "bold"),
        )
        title_paths.pack(anchor="w", padx=8, pady=(6, 2))

        frame1 = tk.Frame(paths_card, bg=self.bg_alt)
        frame1.pack(fill="x", padx=8, pady=2)

        tk.Label(
            frame1,
            text=self.t("steam_dir"),
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 9),
        ).pack(side="left")
        tk.Entry(
            frame1,
            textvariable=self.steam_path_var,
            width=32,
            bg=self.bg,
            fg=self.fg,
            insertbackground=self.fg,
            relief="flat",
        ).pack(side="left", padx=4)
        tk.Button(
            frame1,
            text=self.t("browse"),
            command=self.browse_steam,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left", padx=2)
        tk.Button(
            frame1,
            text=self.t("open_depotcache"),
            command=self.open_depotcache,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left", padx=2)

        frame2 = tk.Frame(paths_card, bg=self.bg_alt)
        frame2.pack(fill="x", padx=8, pady=(2, 8))

        tk.Label(
            frame2,
            text=self.t("applist_dir"),
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 9),
        ).pack(side="left")
        tk.Entry(
            frame2,
            textvariable=self.applist_path_var,
            width=32,
            bg=self.bg,
            fg=self.fg,
            insertbackground=self.fg,
            relief="flat",
        ).pack(side="left", padx=4)
        tk.Button(
            frame2,
            text=self.t("browse"),
            command=self.browse_applist,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left", padx=2)

        hint_lbl = tk.Label(
            paths_card,
            text=self.t("applist_hint"),
            bg=self.bg_alt,
            fg="#8F98A0",
            font=("Segoe UI", 8),
            wraplength=260,
            justify="left",
        )
        hint_lbl.pack(fill="x", padx=8, pady=(0, 6))

        # ---- Luma / Injector
        luma_card = tk.Frame(right_frame, bg=self.bg_alt, bd=1, relief="solid")
        luma_card.pack(fill="x", pady=(0, 6))

        title_luma = tk.Label(
            luma_card,
            text="Luma / Injector",
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 10, "bold"),
        )
        title_luma.pack(anchor="w", padx=8, pady=(6, 2))

        frame_luma = tk.Frame(luma_card, bg=self.bg_alt)
        frame_luma.pack(fill="x", padx=8, pady=4)

        self.btn_run_luma = tk.Button(
            frame_luma,
            text=self.t("run_luma"),
            command=self.run_luma,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        )
        self.btn_run_luma.pack(side="left")

        tk.Button(
            frame_luma,
            text=self.t("set_injector"),
            command=self.select_dllinjector,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left", padx=4)

        self.luma_status_label = tk.Label(frame_luma, text="●", fg="red", bg=self.bg_alt)
        self.luma_status_label.pack(side="left", padx=6)

        tk.Label(
            frame_luma,
            text=self.t("injector_hint"),
            bg=self.bg_alt,
            fg="#8F98A0",
            font=("Segoe UI", 8),
        ).pack(side="left")

                # ---- Profiles
        profile_card = tk.Frame(right_frame, bg=self.bg_alt, bd=1, relief="solid")
        profile_card.pack(fill="x", pady=(0, 6))

        title_profile = tk.Label(
            profile_card,
            text="Profiles",
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 10, "bold"),
        )
        title_profile.pack(anchor="w", padx=8, pady=(6, 2))

        prof_row1 = tk.Frame(profile_card, bg=self.bg_alt)
        prof_row1.pack(fill="x", padx=8, pady=2)

        tk.Label(
            prof_row1,
            text=self.t("current_profile"),
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 9),
        ).pack(side="left")

        self.profile_optionmenu = tk.OptionMenu(prof_row1, self.current_profile_var, "")
        self.profile_optionmenu.pack(side="left", padx=4)
        self.profile_optionmenu.config(
            bg=self.bg,
            fg=self.fg,
            relief="flat",
            highlightthickness=0,
            activebackground=self.accent,
            activeforeground="white",
        )
        self.profile_optionmenu["menu"].config(bg=self.bg, fg=self.fg)

        prof_row2 = tk.Frame(profile_card, bg=self.bg_alt)
        prof_row2.pack(fill="x", padx=8, pady=2)

        tk.Button(
            prof_row2,
            text=self.t("apply_profile"),
            command=self.on_apply_profile_clicked,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=12,
        ).pack(side="left", padx=2)
        tk.Button(
            prof_row2,
            text=self.t("new_profile"),
            command=self.on_add_profile_clicked,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=12,
        ).pack(side="left", padx=2)

        prof_row3 = tk.Frame(profile_card, bg=self.bg_alt)
        prof_row3.pack(fill="x", padx=8, pady=2)

        tk.Button(
            prof_row3,
            text=self.t("duplicate_profile"),
            command=self.duplicate_profile,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=12,
        ).pack(side="left", padx=2)
        tk.Button(
            prof_row3,
            text=self.t("delete_profile"),
            command=self.delete_profile,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=12,
        ).pack(side="left", padx=2)

        prof_row4 = tk.Frame(profile_card, bg=self.bg_alt)
        prof_row4.pack(fill="x", padx=8, pady=(2, 8))

        tk.Button(
            prof_row4,
            text=self.t("export_profile"),
            command=self.export_profile,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=12,
        ).pack(side="left", padx=2)
        tk.Button(
            prof_row4,
            text=self.t("import_profile"),
            command=self.import_profile,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=12,
        ).pack(side="left", padx=2)

        # ---- Get Lua / Manifests
        getlua_card = tk.Frame(right_frame, bg=self.bg_alt, bd=1, relief="solid")
        getlua_card.pack(fill="x", pady=(0, 6))

        title_getlua = tk.Label(
            getlua_card,
            text=self.t("get_lua_block"),
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 10, "bold"),
        )
        title_getlua.pack(anchor="w", padx=8, pady=(6, 2))

        frame_getlua = tk.Frame(getlua_card, bg=self.bg_alt)
        frame_getlua.pack(fill="x", padx=8, pady=4)

        self.search_steam_var = tk.StringVar()
        tk.Label(
            frame_getlua,
            text=self.t("search_game"),
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 9),
        ).pack(side="top", anchor="w")

        sub_getlua = tk.Frame(frame_getlua, bg=self.bg_alt)
        sub_getlua.pack(fill="x", pady=(2, 0))

        tk.Entry(
            sub_getlua,
            textvariable=self.search_steam_var,
            width=23,
            bg=self.bg,
            fg=self.fg,
            insertbackground=self.fg,
            relief="flat",
        ).pack(side="left", padx=(0, 4))

        # Botão principal: Baixar Manifest da Steam
        tk.Button(
            sub_getlua,
            text=self.t("get_lua_steam_btn"),
            command=self.on_get_lua_clicked,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left")

        # Botão secundário: Baixar Manifest do Cache (ainda será implementado)
        tk.Button(
            sub_getlua,
            text=self.t("get_lua_cache_btn"),
            command=self.on_get_lua_cache_clicked,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left", padx=(4, 0))


        # ---- Lua / Manifest card
        lua_card = tk.Frame(right_frame, bg=self.bg_alt, bd=1, relief="solid")
        lua_card.pack(fill="x", pady=(0, 6))

        title_lua = tk.Label(
            lua_card,
            text=self.t("lua_block_title"),
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 10, "bold"),
        )
        title_lua.pack(anchor="w", padx=8, pady=(6, 2))

        frame_drop = tk.Frame(lua_card, bg=self.bg, bd=1, relief="groove")
        frame_drop.pack(fill="x", padx=8, pady=4)

        self.lbl_drop = tk.Label(
            frame_drop,
            text=self.t("drop_lua"),
            height=None,
            bg=self.bg,
            fg=self.fg,
            wraplength=260,   # menor pra não quebrar tanto
            justify="center",
        )
        self.lbl_drop.pack(expand=True, fill="both")

        if DND_AVAILABLE:
            self.lbl_drop.drop_target_register(DND_FILES)
            self.lbl_drop.dnd_bind("<<Drop>>", self.on_drop)

        # linha de botões: selecionar .lua e .zip
        lua_btn_row = tk.Frame(lua_card, bg=self.bg_alt)
        lua_btn_row.pack(fill="x", padx=8, pady=(0, 6))

        tk.Button(
            lua_btn_row,
            text=self.t("select_lua"),
            command=self.select_lua,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left")

        tk.Button(
            lua_btn_row,
            text=self.t("select_zip"),
            command=self.select_zip,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
        ).pack(side="left", padx=(4, 0))

        # ---- LOG (canto inferior direito)
        log_card = tk.Frame(right_frame, bg=self.bg_alt, bd=1, relief="solid")
        log_card.pack(fill="both", expand=True, pady=(0, 6))

        log_title = tk.Label(
            log_card,
            text="Log",
            bg=self.bg_alt,
            fg=self.fg,
            font=("Segoe UI", 10, "bold"),
        )
        log_title.pack(anchor="w", padx=8, pady=(6, 2))

        self.log_box = scrolledtext.ScrolledText(
            log_card,
            height=8,
            state="disabled",
            bg=self.bg,
            fg=self.fg,
            insertbackground=self.fg,
            relief="flat",
            borderwidth=1,
            font=("Consolas", 9),
        )
        self.log_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # --------- util GUI ---------

    def log(self, msg: str, end: str = "\n"):
        if not self.log_box:
            return
        self.log_box.config(state="normal")
        self.log_box.insert("end", msg + end)
        self.log_box.see("end")
        self.log_box.config(state="disabled")
        self.root.update_idletasks()

    def update_luma_status(self):
        dll_path = self.config.get("dllinjector_path")
        if dll_path and Path(dll_path).exists():
            self.luma_status_label.config(text="●", fg="green")
        else:
            self.luma_status_label.config(text="●", fg="red")

    # --------- Paths / Luma / depotcache ---------

    def browse_steam(self):
        f = filedialog.askdirectory()
        if not f:
            return

        self.steam_path_var.set(f)
        self.config["steam_path"] = f
        if not save_config(self.config):
            if self.lang == "pt":
                messagebox.showerror(
                    "Erro ao salvar config.json",
                    "Não foi possível escrever o arquivo config.json."
                )
            else:
                messagebox.showerror(
                    "Error saving config.json",
                    "Could not write config.json file."
                )

    def open_depotcache(self):
        steam = Path(self.steam_path_var.get())
        depotcache = steam / "depotcache"
        if not depotcache.exists():
            if self.lang == "pt":
                messagebox.showerror(
                    "Erro",
                    f"Pasta depotcache não encontrada em:\n{depotcache}",
                )
            else:
                messagebox.showerror(
                    "Error",
                    f"Depotcache folder not found at:\n{depotcache}",
                )
            return
        try:
            os.startfile(depotcache)
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao abrir depotcache", str(e))
            else:
                messagebox.showerror("Error opening depotcache", str(e))

    def browse_applist(self):
        f = filedialog.askdirectory()
        if f:
            self.applist_path_var.set(f)
            self.config["applist_path"] = f
            if not save_config(self.config):
                if self.lang == "pt":
                    messagebox.showerror(
                        "Erro ao salvar config.json",
                        "Não foi possível escrever o arquivo config.json.",
                    )
                else:
                    messagebox.showerror(
                        "Error saving config.json",
                        "Could not write the config.json file.",
                    )

    def select_dllinjector(self):
        file = filedialog.askopenfilename(
            title="Selecione DLLInjector.exe" if self.lang == "pt" else "Select DLLInjector.exe",
            filetypes=[
                ("Executável", "*.exe") if self.lang == "pt" else ("Executable", "*.exe"),
                ("Todos", "*.*") if self.lang == "pt" else ("All files", "*.*"),
            ],
        )
        if file:
            self.config["dllinjector_path"] = file
            if not save_config(self.config):
                if self.lang == "pt":
                    messagebox.showerror(
                        "Erro ao salvar config.json",
                        "Não foi possível escrever o arquivo config.json.",
                    )
                else:
                    messagebox.showerror(
                        "Error saving config.json",
                        "Could not write the config.json file.",
                    )
            self.update_luma_status()

    def run_luma(self):
        dll_path = self.config.get("dllinjector_path")
        if not dll_path:
            if self.lang == "pt":
                messagebox.showerror(
                    "DLLInjector não configurado",
                    "Use o botão 'Setar Injector' para escolher o DLLInjector.exe.",
                )
            else:
                messagebox.showerror(
                    "DLLInjector not configured",
                    "Use the 'Set Injector' button to choose DLLInjector.exe.",
                )
            return

        exe = Path(dll_path)
        if not exe.exists():
            if self.lang == "pt":
                messagebox.showerror(
                    "DLLInjector não encontrado",
                    f"O caminho salvo não existe mais:\n{dll_path}\n\nSelecione novamente o executável.",
                )
            else:
                messagebox.showerror(
                    "DLLInjector not found",
                    f"The saved path no longer exists:\n{dll_path}\n\nPlease select the executable again.",
                )
            self.update_luma_status()
            return

        try:
            subprocess.Popen([str(exe)], cwd=str(exe.parent))
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao executar DLLInjector", str(e))
            else:
                messagebox.showerror("Error running DLLInjector", str(e))

    # --------- Profiles helpers ---------

    def refresh_profile_optionmenu(self):
        menu = self.profile_optionmenu["menu"]
        menu.delete(0, "end")
        names = sorted(self.profiles_data["profiles"].keys())
        current = self.profiles_data["last_profile"]
        if current not in names:
            current = names[0]
            self.profiles_data["last_profile"] = current
            save_profiles(self.profiles_data)
        for name in names:
            menu.add_command(label=name, command=lambda v=name: self.on_profile_selected(v))
        self.current_profile_var.set(current)

    def get_current_profile(self) -> Dict:
        name = self.current_profile_var.get()
        return self.profiles_data["profiles"].setdefault(name, {"entries": []})

    def get_current_entries(self) -> List[Dict]:
        prof = self.get_current_profile()
        entries = prof.setdefault("entries", [])
        return entries

    def on_profile_selected(self, name: str):
        self.current_profile_var.set(name)
        self.profiles_data["last_profile"] = name
        save_profiles(self.profiles_data)
        self.refresh_profile_view()

    def on_add_profile_clicked(self):
        name = simpledialog.askstring(
            "Nova profile" if self.lang == "pt" else "New profile",
            "Nome da profile:" if self.lang == "pt" else "Profile name:",
        )
        if not name:
            return
        if name in self.profiles_data["profiles"]:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Já existe uma profile com esse nome.")
            else:
                messagebox.showerror("Error", "A profile with this name already exists.")
            return
        self.profiles_data["profiles"][name] = {"entries": []}
        self.profiles_data["last_profile"] = name
        save_profiles(self.profiles_data)
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()

    def duplicate_profile(self):
        current = self.current_profile_var.get()
        if not current:
            return
        entries = self.get_current_entries()
        entries_copy = json.loads(json.dumps(entries))

        suggested = f"{current} - copia"
        title = "Duplicar profile" if self.lang == "pt" else "Duplicate profile"
        prompt = (
            "Nome da nova profile:"
            if self.lang == "pt"
            else "New profile name:"
        )
        name = simpledialog.askstring(title, prompt, initialvalue=suggested)
        if not name:
            return
        if name in self.profiles_data["profiles"]:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Já existe uma profile com esse nome.")
            else:
                messagebox.showerror("Error", "A profile with this name already exists.")
            return

        self.profiles_data["profiles"][name] = {"entries": entries_copy}
        self.profiles_data["last_profile"] = name
        save_profiles(self.profiles_data)
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()
        self.log(
            f"Profile '{current}' duplicada como '{name}'."
            if self.lang == "pt"
            else f"Profile '{current}' duplicated as '{name}'."
        )

    def delete_profile(self):
        name = self.current_profile_var.get()
        if not name:
            return

        applist_dir_str = self.applist_path_var.get().strip()
        applist_dir = Path(applist_dir_str) if applist_dir_str else None

        # Caso especial: profile "Default" não é apagada, só limpa
        if name == "Default":
            if self.lang == "pt":
                msg = (
                    "Isto irá limpar todos os jogos da profile 'Default' e apagar os .txt da AppList.\n\n"
                    "O nome 'Default' será mantido, apenas os jogos serão removidos.\n\n"
                    "Isso NÃO apaga nenhum jogo do disco.\n\n"
                    "Continuar?"
                )
                title = "Limpar profile Default"
            else:
                msg = (
                    "This will clear all games from the 'Default' profile and delete the AppList .txt files.\n\n"
                    "The name 'Default' will be kept, only the games will be removed.\n\n"
                    "This does NOT delete any game from disk.\n\n"
                    "Continue?"
                )
                title = "Clear 'Default' profile"

            if not messagebox.askyesno(title, msg):
                return

            entries = self.get_current_entries()
            entries.clear()
            save_profiles(self.profiles_data)
            self.refresh_profile_view()

            if applist_dir and applist_dir.exists():
                for i in range(130):
                    p = applist_dir / f"{i}.txt"
                    if p.exists():
                        try:
                            p.unlink()
                        except Exception:
                            pass
                if self.lang == "pt":
                    self.log("Profile 'Default' limpa e AppList esvaziada.")
                else:
                    self.log("Profile 'Default' cleared and AppList emptied.")
            return

        # Demais profiles: deletar mesmo
        if self.lang == "pt":
            msg = (
                f"Isto irá apagar a profile '{name}' e todos os jogos dela.\n"
                "Também irá apagar os arquivos .txt da AppList.\n\n"
                "Isso NÃO apaga os jogos do disco.\n\n"
                "Tem certeza?"
            )
            title = "Deletar profile"
        else:
            msg = (
                f"This will delete the profile '{name}' and all of its games.\n"
                "It will also delete the AppList .txt files.\n\n"
                "This does NOT delete the games from disk.\n\n"
                "Are you sure?"
            )
            title = "Delete profile"

        if not messagebox.askyesno(title, msg):
            return

        try:
            del self.profiles_data["profiles"][name]
        except KeyError:
            return

        # garante que sempre exista pelo menos a Default
        if not self.profiles_data["profiles"]:
            self.profiles_data["profiles"]["Default"] = {"entries": []}

        new_current = self.profiles_data.get("last_profile")
        if new_current == name or new_current not in self.profiles_data["profiles"]:
            new_current = sorted(self.profiles_data["profiles"].keys())[0]
        self.profiles_data["last_profile"] = new_current
        save_profiles(self.profiles_data)

        if applist_dir and applist_dir.exists():
            for i in range(130):
                p = applist_dir / f"{i}.txt"
                if p.exists():
                    try:
                        p.unlink()
                    except Exception:
                        pass
            if self.lang == "pt":
                self.log(f"Profile '{name}' deletada e AppList esvaziada.")
            else:
                self.log(f"Profile '{name}' deleted and AppList emptied.")

        self.refresh_profile_optionmenu()
        self.refresh_profile_view()

    # ---------- Helpers de overflow de AppList ----------

    def ask_overflow_action(self) -> Optional[str]:
        """
        Mostra um diálogo customizado:
        - 'move'   = Selecionar outra profile
        - 'create' = Criar nova profile
        - None     = Cancelar tudo
        """
        if self.lang == "pt":
            title = "Limite de 130 arquivos"
            msg = (
                "Esse jogo ultrapassa o limite de 130 arquivos na AppList da profile atual.\n\n"
                "O que deseja fazer?"
            )
            txt_move = "Selecionar outra profile"
            txt_create = "Criar nova profile"
            txt_cancel = "Cancelar"
        else:
            title = "130 files limit"
            msg = (
                "This game would exceed the 130 files limit in the current profile.\n\n"
                "What do you want to do?"
            )
            txt_move = "Move to another profile"
            txt_create = "Create new profile"
            txt_cancel = "Cancel"

        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.bg_alt)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        tk.Label(
            win,
            text=msg,
            bg=self.bg_alt,
            fg=self.fg,
            justify="left",
            wraplength=320,
        ).pack(padx=12, pady=(10, 8))

        action_var = tk.StringVar(value="")

        btn_frame = tk.Frame(win, bg=self.bg_alt)
        btn_frame.pack(pady=(0, 10))

        def choose_move():
            action_var.set("move")
            win.destroy()

        def choose_create():
            action_var.set("create")
            win.destroy()

        def choose_cancel():
            action_var.set("")
            win.destroy()

        tk.Button(
            btn_frame,
            text=txt_move,
            command=choose_move,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=12,
            pady=4,
        ).pack(side="left", padx=4)

        tk.Button(
            btn_frame,
            text=txt_create,
            command=choose_create,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=12,
            pady=4,
        ).pack(side="left", padx=4)

        tk.Button(
            btn_frame,
            text=txt_cancel,
            command=choose_cancel,
            bg=self.bg,
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=12,
            pady=4,
        ).pack(side="left", padx=4)

        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_variable(action_var)
        val = action_var.get() or None
        return val

    def choose_profile_overflow(self, app_id_str: str, game_name: str, combined_ids: List[str]) -> Optional[str]:
        """
        Abre uma janelinha com dropdown para escolher outra profile.
        Retorna o nome da profile ou None se o usuário cancelar.
        """
        all_profiles = sorted(self.profiles_data["profiles"].keys())
        current = self.current_profile_var.get()
        available = [p for p in all_profiles if p != current]

        if not available:
            if self.lang == "pt":
                messagebox.showerror(
                    "Nenhuma profile disponível",
                    "Não há outra profile para mover este jogo.\n"
                    "Crie uma nova profile e tente novamente."
                )
            else:
                messagebox.showerror(
                    "No profile available",
                    "There is no other profile to move this game to.\n"
                    "Create a new profile and try again."
                )
            return None

        if self.lang == "pt":
            title = "Selecionar outra profile"
            label_text = "Escolha a profile de destino:"
        else:
            title = "Select another profile"
            label_text = "Choose the target profile:"

        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.bg_alt)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        tk.Label(
            win,
            text=label_text,
            bg=self.bg_alt,
            fg=self.fg,
            justify="left",
        ).pack(padx=12, pady=(10, 4))

        sel_var = tk.StringVar(value=available[0])

        opt = tk.OptionMenu(win, sel_var, *available)
        opt.config(
            bg=self.bg,
            fg=self.fg,
            relief="flat",
            highlightthickness=0,
            activebackground=self.accent,
            activeforeground="white",
            width=22,
        )
        opt["menu"].config(bg=self.bg, fg=self.fg)
        opt.pack(padx=12, pady=(0, 8))

        result_var = tk.StringVar(value="")

        def on_ok():
            result_var.set(sel_var.get())
            win.destroy()

        def on_cancel():
            result_var.set("")
            win.destroy()

        btn_frame = tk.Frame(win, bg=self.bg_alt)
        btn_frame.pack(pady=(0, 10))

        tk.Button(
            btn_frame,
            text="OK",
            command=on_ok,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=8,
        ).pack(side="left", padx=4)

        tk.Button(
            btn_frame,
            text="Cancelar" if self.lang == "pt" else "Cancel",
            command=on_cancel,
            bg=self.bg,
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=8,
        ).pack(side="left", padx=4)

        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_variable(result_var)
        chosen = result_var.get() or None
        return chosen

    def create_new_profile_overflow(self, base_name: Optional[str] = None) -> Optional[str]:
        """
        Cria uma nova profile perguntando o nome.
        Retorna o nome criado ou None se o usuário cancelar.
        A janela fica sempre na frente do programa.
        """
        if base_name is None:
            base_name = f"{self.current_profile_var.get()} - extra"

        prompt_title = "Nome da nova profile" if self.lang == "pt" else "New profile name"
        prompt_text = "Nome da nova profile:" if self.lang == "pt" else "New profile name:"

        name = simpledialog.askstring(
            prompt_title,
            prompt_text,
            initialvalue=base_name,
            parent=self.root,   # <- abre sempre na frente
        )
        if not name:
            return None

        if name in self.profiles_data["profiles"]:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Já existe uma profile com esse nome.")
            else:
                messagebox.showerror("Error", "A profile with this name already exists.")
            return None

        self.profiles_data["profiles"][name] = {"entries": []}
        self.profiles_data["last_profile"] = name
        save_profiles(self.profiles_data)

        self.current_profile_var.set(name)
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()

        return name


    def flatten_current_profile_ids(self) -> List[str]:
        """
        Retorna TODOS os IDs da profile atual, sem limite.
        O limite de 130 é tratado em outro lugar.
        """
        ids: List[str] = []
        for e in self.get_current_entries():
            for id_str in e.get("ids", []):
                ids.append(id_str)
        return ids

    # --------- Limite de 130 arquivos / Profiles ---------

    def flatten_profile_ids(self, profile_name: str) -> List[str]:
        """Retorna todos os IDs de uma profile específica."""
        prof = self.profiles_data["profiles"].get(profile_name, {"entries": []})
        ids: List[str] = []
        for e in prof.get("entries", []):
            for id_str in e.get("ids", []):
                ids.append(id_str)
        return ids

    def _would_fit_in_profile(self, profile_name: str, new_ids: List[str]) -> bool:
        """Verifica se new_ids cabem na profile sem passar de 130 IDs únicos."""
        existing = self.flatten_profile_ids(profile_name)
        existing_set = set(existing)
        unique_new = [x for x in new_ids if x not in existing_set]
        total = len(existing) + len(unique_new)
        return total <= 130

    def _dialog_overflow_choice(self, main_text_pt: str, main_text_en: str) -> Optional[str]:
        """
        Abre uma janelinha com dois botões:
          - 'select'  -> Selecionar outra profile
          - 'create'  -> Criar outra profile e colocar nela
        Retorna 'select', 'create' ou None (cancelado).
        """
        if self.lang == "pt":
            title = "Limite de 130 atingido"
            label_text = main_text_pt
            btn_select = "Selecionar outra Profile"
            btn_create = "Criar outra Profile e colocar nela"
        else:
            title = "130 limit reached"
            label_text = main_text_en
            btn_select = "Select another profile"
            btn_create = "Create another profile and put game there"

        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.bg_alt)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        tk.Label(
            win,
            text=label_text,
            bg=self.bg_alt,
            fg=self.fg,
            wraplength=320,
            justify="left",
            padx=20,
            pady=10,
        ).pack()

        choice_var = tk.StringVar(value="")

        def choose_select():
            choice_var.set("select")
            win.destroy()

        def choose_create():
            choice_var.set("create")
            win.destroy()

        btn_frame = tk.Frame(win, bg=self.bg_alt)
        btn_frame.pack(pady=(0, 12))

        tk.Button(
            btn_frame,
            text=btn_select,
            command=choose_select,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=10,
            pady=4,
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame,
            text=btn_create,
            command=choose_create,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=10,
            pady=4,
        ).pack(side="left", padx=6)

        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_variable(choice_var)
        choice = choice_var.get() or None
        return choice

    def _dialog_select_profile(self) -> Optional[str]:
        """Janelinha para escolher uma profile existente."""
        names = sorted(self.profiles_data["profiles"].keys())
        if not names:
            return None

        if self.lang == "pt":
            title = "Selecionar Profile"
            label_text = "Selecione a profile onde o jogo será colocado:"
        else:
            title = "Select Profile"
            label_text = "Select the profile where the game will be placed:"

        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.bg_alt)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        tk.Label(
            win,
            text=label_text,
            bg=self.bg_alt,
            fg=self.fg,
            wraplength=320,
            justify="left",
            padx=20,
            pady=10,
        ).pack()

        choice_var = tk.StringVar(value=names[0])

        opt = tk.OptionMenu(win, choice_var, *names)
        opt.config(
            bg=self.bg,
            fg=self.fg,
            relief="flat",
            highlightthickness=0,
            activebackground=self.accent,
            activeforeground="white",
        )
        opt["menu"].config(bg=self.bg, fg=self.fg)
        opt.pack(pady=4, padx=20, fill="x")

        result_var = tk.StringVar(value="")

        def on_ok():
            result_var.set(choice_var.get())
            win.destroy()

        def on_cancel():
            result_var.set("")
            win.destroy()

        btn_frame = tk.Frame(win, bg=self.bg_alt)
        btn_frame.pack(pady=(8, 12))

        tk.Button(
            btn_frame,
            text="OK",
            command=on_ok,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=10,
            pady=4,
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame,
            text="Cancelar",
            command=on_cancel,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=10,
            pady=4,
        ).pack(side="left", padx=6)

        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_variable(result_var)
        name = result_var.get() or None
        return name

    def _add_game_to_profile_name(self, profile_name: str, app_id: str, game_name: str, ids: List[str]):
        """Adiciona/atualiza o jogo em uma profile específica (sem mexer na atual)."""
        prof = self.profiles_data["profiles"].setdefault(profile_name, {"entries": []})
        entries = prof.setdefault("entries", [])
        for e in entries:
            if e.get("app_id") == app_id:
                e["name"] = game_name
                e["ids"] = ids
                break
        else:
            entries.append({"app_id": app_id, "name": game_name, "ids": ids})

        save_profiles(self.profiles_data)

        # Se a profile aberta é a mesma, atualiza a view
        if self.current_profile_var.get() == profile_name:
            self.refresh_profile_view()
        self.refresh_profile_optionmenu()

    def _create_new_profile_with_game(self, app_id: str, game_name: str, ids: List[str]) -> Optional[str]:
        """Cria uma nova profile contendo apenas esse jogo."""
        if self.lang == "pt":
            title = "Nova profile"
            prompt = "Nome da nova profile:"
            suggested = f"{self.current_profile_var.get()} - 2"
        else:
            title = "New profile"
            prompt = "New profile name:"
            suggested = f"{self.current_profile_var.get()} - 2"

        name = simpledialog.askstring(title, prompt, initialvalue=suggested)
        if not name:
            return None

        if name in self.profiles_data["profiles"]:
            messagebox.showerror(
                "Erro",
                f"Já existe uma profile chamada '{name}'."
                if self.lang == "pt"
                else f"A profile named '{name}' already exists.",
            )
            return None

        self.profiles_data["profiles"][name] = {"entries": [{"app_id": app_id, "name": game_name, "ids": ids}]}
        self.profiles_data["last_profile"] = name
        save_profiles(self.profiles_data)
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()

        return name

    def handle_applist_overflow(self, app_id: str, game_name: str, combined_ids: List[str]):
        """
        Fluxo quando adicionar este jogo faria a profile atual passar de 130 IDs.
        Não mexe na AppList automaticamente (para não destruir nada).
        """
        # 1) Mensagem principal
        choice = self._dialog_overflow_choice(
            main_text_pt=(
                "Esse jogo ultrapassa o limite de 130 arquivos na AppList.\n\n"
                "Você pode:\n"
                " - Selecionar outra Profile;\n"
                " - Criar outra Profile e colocar nela.\n"
            ),
            main_text_en=(
                "This game would exceed the 130 files limit in the AppList.\n\n"
                "You can:\n"
                " - Select another profile;\n"
                " - Create a new profile and put the game there.\n"
            ),
        )

        if not choice:
            self.log("Operação cancelada pelo usuário (limite 130).")
            return

        target_profile = None

        if choice == "select":
            while True:
                name = self._dialog_select_profile()
                if not name:
                    self.log("Usuário cancelou seleção de profile (limite 130).")
                    return

                if self._would_fit_in_profile(name, combined_ids):
                    target_profile = name
                    break

                # Profile escolhida também estoura
                self._dialog_overflow_choice(
                    main_text_pt=(
                        "A Profile selecionada também passa do limite de 130 arquivos na AppList.\n\n"
                        "Selecione outra Profile ou crie uma nova."
                    ),
                    main_text_en=(
                        "The selected profile would also exceed the 130 files limit.\n\n"
                        "Select another profile or create a new one."
                    ),
                )
                # loop continua até o usuário escolher uma que caiba ou cancelar

        elif choice == "create":
            name = self._create_new_profile_with_game(app_id, game_name, combined_ids)
            if not name:
                return
            target_profile = name

        if not target_profile:
            return

        # adiciona o jogo na profile escolhida (se não foi criada já com o jogo)
        if target_profile in self.profiles_data["profiles"]:
            # se veio do caminho "select", precisamos colocar o jogo lá
            # no caminho "create", a função já criou com o jogo dentro
            if not any(e.get("app_id") == app_id for e in self.profiles_data["profiles"][target_profile]["entries"]):
                self._add_game_to_profile_name(target_profile, app_id, game_name, combined_ids)

        # mensagem final (não alteramos AppList automaticamente)
        if self.lang == "pt":
            msg = (
                f"O jogo '{game_name}' foi colocado na profile '{target_profile}', "
                "mas a AppList não foi alterada para evitar ultrapassar o limite de 130 arquivos.\n\n"
                "Quando quiser usar essa profile, selecione-a e clique em 'Aplicar profile'."
            )
            title = "Jogo adicionado em outra profile"
        else:
            msg = (
                f"The game '{game_name}' was added to profile '{target_profile}', "
                "but the AppList was not changed to avoid exceeding the 130 files limit.\n\n"
                "When you want to use that profile, select it and click 'Apply profile'."
            )
            title = "Game added to another profile"

        messagebox.showinfo(title, msg)
        self.log(f"Jogo '{game_name}' ({app_id}) adicionado na profile '{target_profile}' por causa do limite 130.")

    # -------------------------------------------------
    # Cálculo de quantos IDs teria uma profile com o jogo novo
    # -------------------------------------------------
    def compute_total_ids_with_game(self, profile_name: str, app_id: str, combined_ids: List[str]) -> int:
        """
        Soma todos os IDs da profile + os IDs do jogo novo.
        Ignora o jogo antigo com o mesmo app_id (caso seja atualização).
        """
        MAX_APPLIST_IDS = 130  # só para referência local

        prof = self.profiles_data["profiles"].get(profile_name, {})
        entries = prof.get("entries", [])

        total_ids: List[str] = []

        for e in entries:
            if str(e.get("app_id")) == str(app_id):
                # Se já existe esse jogo na profile, não conta os IDs antigos
                # (vamos substituir pelos IDs novos)
                continue
            for _id in e.get("ids", []):
                total_ids.append(_id)

        # adiciona os IDs do jogo novo
        for _id in combined_ids:
            total_ids.append(_id)

        return len(total_ids)

    # -------------------------------------------------
    # Diálogo customizado: “Mover” x “Criar”
    # -------------------------------------------------
    def ask_applist_overflow_action(self) -> Optional[str]:
        """
        Retorna:
          - "move"  -> usuário quer mover para outra profile
          - "create" -> usuário quer criar nova profile
          - None -> cancelou
        """
        win = tk.Toplevel(self.root)
        win.title("Limite de 130 arquivos" if self.lang == "pt" else "130 files limit")
        win.configure(bg=self.bg_alt)
        win.resizable(False, False)
        win.grab_set()
        win.transient(self.root)

        if self.lang == "pt":
            msg = (
                "Esse jogo ultrapassa o limite de 130 arquivos na AppList da profile atual.\n\n"
                "O que deseja fazer?"
            )
            btn_move_text = "Mover para outra profile"
            btn_create_text = "Criar nova profile e colocar nela"
        else:
            msg = (
                "This game would exceed the 130-file limit in the current profile.\n\n"
                "What do you want to do?"
            )
            btn_move_text = "Move to another profile"
            btn_create_text = "Create new profile and put it there"

        lbl = tk.Label(
            win,
            text=msg,
            bg=self.bg_alt,
            fg=self.fg,
            wraplength=320,
            justify="left",
            padx=15,
            pady=15,
        )
        lbl.pack(fill="x")

        result = {"choice": None}

        def on_move():
            result["choice"] = "move"
            win.destroy()

        def on_create():
            result["choice"] = "create"
            win.destroy()

        btn_frame = tk.Frame(win, bg=self.bg_alt)
        btn_frame.pack(pady=(0, 12))

        tk.Button(
            btn_frame,
            text=btn_move_text,
            command=on_move,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=10,
            pady=3,
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text=btn_create_text,
            command=on_create,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            padx=10,
            pady=3,
        ).pack(side="left", padx=5)

        # Centralizar
        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_window(win)
        return result["choice"]

    # -------------------------------------------------
    # Diálogo para escolher profile de destino (dropdown)
    # -------------------------------------------------
    def ask_profile_destination(self, exclude_profile: str) -> Optional[str]:
        """
        Abre um diálogo com dropdown para o usuário escolher
        uma profile de destino (exceto a atual).
        Retorna o nome da profile escolhida ou None (cancelar).
        """
        names = [
            name
            for name in sorted(self.profiles_data["profiles"].keys())
            if name != exclude_profile
        ]
        if not names:
            if self.lang == "pt":
                messagebox.showerror(
                    "Sem outras profiles",
                    "Não há outras profiles disponíveis.\nCrie uma nova profile.",
                )
            else:
                messagebox.showerror(
                    "No other profiles",
                    "There are no other profiles.\nCreate a new one.",
                )
            return None

        win = tk.Toplevel(self.root)
        win.title("Selecionar outra profile" if self.lang == "pt" else "Select another profile")
        win.configure(bg=self.bg_alt)
        win.resizable(False, False)
        win.grab_set()
        win.transient(self.root)

        if self.lang == "pt":
            top_text = "Escolha a profile de destino:"
        else:
            top_text = "Choose the target profile:"

        tk.Label(
            win,
            text=top_text,
            bg=self.bg_alt,
            fg=self.fg,
            padx=15,
            pady=10,
            anchor="w",
        ).pack(fill="x")

        choice_var = tk.StringVar(value=names[0])

        opt_frame = tk.Frame(win, bg=self.bg_alt)
        opt_frame.pack(padx=15, pady=(0, 10), fill="x")

        opt_menu = tk.OptionMenu(opt_frame, choice_var, *names)
        opt_menu.config(
            bg=self.bg,
            fg=self.fg,
            relief="flat",
            highlightthickness=0,
            activebackground=self.accent,
            activeforeground="white",
            width=25,
        )
        opt_menu["menu"].config(bg=self.bg, fg=self.fg)
        opt_menu.pack(side="left")

        result = {"value": None}

        def on_ok():
            result["value"] = choice_var.get()
            win.destroy()

        def on_cancel():
            result["value"] = None
            win.destroy()

        btn_frame = tk.Frame(win, bg=self.bg_alt)
        btn_frame.pack(pady=(0, 12))

        ok_text = "OK"
        cancel_text = "Cancelar" if self.lang == "pt" else "Cancel"

        tk.Button(
            btn_frame,
            text=ok_text,
            command=on_ok,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=10,
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text=cancel_text,
            command=on_cancel,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=10,
        ).pack(side="left", padx=5)

        # Centralizar
        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_window(win)
        return result["value"]

    # -------------------------------------------------
    # Escolher profile respeitando limite (pode reabrir se estiver cheia)
    # -------------------------------------------------
    def choose_profile_for_overflow(self, app_id: str, game_name: str, combined_ids: List[str]) -> Optional[str]:
        """
        Abre o seletor de profile (dropdown) e verifica se a profile
        escolhida teria espaço com o jogo novo.
        Se também estourar o limite, avisa e deixa escolher de novo.
        """
        MAX_APPLIST_IDS = 130
        current_profile = self.current_profile_var.get() or "Default"

        while True:
            target_profile = self.ask_profile_destination(exclude_profile=current_profile)
            if not target_profile:
                # usuário cancelou
                return None

            total_target = self.compute_total_ids_with_game(target_profile, app_id, combined_ids)
            if total_target > MAX_APPLIST_IDS:
                # Profile também cheia -> avisa e volta para o loop
                if self.lang == "pt":
                    messagebox.showerror(
                        "Profile cheia",
                        f"A profile '{target_profile}' também passaria do limite de {MAX_APPLIST_IDS} arquivos.\n\n"
                        "Escolha outra profile ou crie uma nova.",
                    )
                else:
                    messagebox.showerror(
                        "Profile full",
                        f"Profile '{target_profile}' would also exceed the {MAX_APPLIST_IDS}-file limit.\n\n"
                        "Choose another profile or create a new one.",
                    )
                continue

            return target_profile

    # -------------------------------------------------
    # Fluxo completo de instalação respeitando limite e profiles
    # -------------------------------------------------
    def install_game_with_ids(self, app_id_str: str, game_name: str, combined_ids: List[str]):
        """
        Faz o fluxo completo:
        - decide em qual profile o jogo vai ficar
        - respeita o limite de 130 IDs
        - grava AppList
        """
        current_profile = self.current_profile_var.get() or "Default"

        # 1) Tenta colocar na profile atual
        total_current = self.compute_total_ids_with_game(current_profile, app_id_str, combined_ids)

        if total_current <= MAX_APPLIST_IDS:
            target_profile = current_profile
        else:
            # Estourou limite da profile atual -> loop de decisão
            while True:
                action = self.ask_overflow_action()
                if action is None:
                    # Usuário cancelou tudo
                    if self.lang == "pt":
                        self.log("Instalação cancelada pelo usuário devido ao limite de 130 arquivos na AppList.")
                    else:
                        self.log("Install cancelled by user due to 130 files limit.")
                    return

                if action == "move":
                    # Selecionar outra profile
                    target_profile = self.choose_profile_overflow(app_id_str, game_name, combined_ids)
                    if target_profile is None:
                        # Cancelar aqui volta para o menu anterior
                        continue
                elif action == "create":
                    # Criar nova profile
                    target_profile = self.create_new_profile_overflow()
                    if target_profile is None:
                        # Cancelar aqui também volta para o menu anterior
                        continue
                else:
                    # Algo inesperado -> cancela
                    return

                # Verifica se a profile escolhida também passa do limite
                total_target = self.compute_total_ids_with_game(target_profile, app_id_str, combined_ids)
                if total_target <= MAX_APPLIST_IDS:
                    break  # OK, podemos usar essa profile

                # Profile escolhida também cheia -> pergunta se quer criar outra
                if self.lang == "pt":
                    msg = (
                        f"A profile '{target_profile}' também passaria do limite de 130 arquivos.\n\n"
                        "Criar nova profile para este jogo?"
                    )
                    title = "Profile cheia"
                else:
                    msg = (
                        f"The profile '{target_profile}' would also exceed the 130 files limit.\n\n"
                        "Create a new profile for this game?"
                    )
                    title = "Profile full"

                resp = messagebox.askyesno(title, msg)
                if resp:
                    # Tenta criar nova profile
                    new_name = self.create_new_profile_overflow(base_name=f"{target_profile} - extra")
                    if not new_name:
                        # Cancelou a criação -> volta pro menu principal
                        continue
                    target_profile = new_name
                    break
                else:
                    # Não quis criar nova -> volta pro menu principal (Mover/Criar/Cancelar)
                    continue

        # 2) Ajusta profile destino na UI
        self.current_profile_var.set(target_profile)
        self.profiles_data["last_profile"] = target_profile
        save_profiles(self.profiles_data)

        # 3) Adiciona / atualiza jogo na profile de destino (AGORA com AppID correto)
        self.add_or_update_game_in_profile(app_id_str, game_name, combined_ids)

        # Atualiza menu / lista (caso algo precise redesenhar)
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()

        # 3) Aplica AppList baseada na profile de destino
        applist_dir_str = self.applist_path_var.get().strip()
        if not applist_dir_str:
            if self.lang == "pt":
                self.log("Diretório da AppList não definido. Profile salva, mas AppList não foi escrita.")
            else:
                self.log("Applist directory not defined. Profile saved, but AppList was not written.")
            return

        applist_dir = Path(applist_dir_str)
        if not applist_dir.exists():
            if self.lang == "pt":
                messagebox.showerror("Erro", "Diretório da AppList inválido.")
            else:
                messagebox.showerror("Error", "Invalid Applist directory.")
            return

        try:
            ids = self.flatten_current_profile_ids()
            profile_name = self.current_profile_var.get() or "PROFILE"
            generate_applist_files(applist_dir, ids, self.log, profile_name)
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao escrever AppList", str(e))
            else:
                messagebox.showerror("Error writing AppList", str(e))
            return

        if self.lang == "pt":
            self.log(f"Instalação concluída com sucesso na profile '{target_profile}'.")
        else:
            self.log(f"Install completed successfully in profile '{target_profile}'.")


    def apply_profile_to_applist(self):
        applist_dir_str = self.applist_path_var.get().strip()
        if not applist_dir_str:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Diretório da AppList não definido.")
            else:
                messagebox.showerror("Error", "AppList directory is not set.")
            return

        applist_dir = Path(applist_dir_str)
        if not applist_dir.exists():
            if self.lang == "pt":
                messagebox.showerror("Erro", "Diretório da AppList inválido.")
            else:
                messagebox.showerror("Error", "Invalid AppList directory.")
            return

        ids = self.flatten_current_profile_ids()
        if len(ids) > MAX_APPLIST_IDS:
            if self.lang == "pt":
                message = (
                    f"Esta profile possui {len(ids)} IDs, mas o limite da AppList é {MAX_APPLIST_IDS}.\n\n"
                    "Remova alguns jogos ou divida em mais profiles."
                )
                title = "Limite de 130 arquivos"
            else:
                message = (
                    f"This profile has {len(ids)} IDs, but the AppList limit is {MAX_APPLIST_IDS}.\n\n"
                    "Remove some games or split them across more profiles."
                )
                title = "130 files limit"
            messagebox.showerror(title, message)
            return

        profile_name = self.current_profile_var.get() or "PROFILE"
        generate_applist_files(applist_dir, ids, self.log, profile_name)
        if self.lang == "pt":
            self.log("Profile aplicada na AppList.")
        else:
            self.log("Profile applied to AppList.")

    def on_apply_profile_clicked(self):
        self.apply_profile_to_applist()

    def add_or_update_game_in_profile(self, app_id: str, name: str, ids: List[str]):
        entries = self.get_current_entries()
        for e in entries:
            if e.get("app_id") == app_id:
                e["name"] = name
                e["ids"] = ids
                break
        else:
            entries.append({"app_id": app_id, "name": name, "ids": ids})

        self.profiles_data["last_profile"] = self.current_profile_var.get()
        save_profiles(self.profiles_data)
        self.refresh_profile_view()

    def reload_profiles(self):
        self.profiles_data = load_profiles()
        self._ensure_profiles_initialized()
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()
        self.log("Profiles recarregadas do disco.")

    def refresh_profile_view(self):
        """Recria os cards de jogos no estilo Steam."""
        entries = self.get_current_entries()

        # ordena por nome
        entries.sort(key=lambda e: (e.get("name") or "").lower())

        # limpa cards atuais
        for w in self.cards_frame.winfo_children():
            w.destroy()

        filter_text = self.profile_search_var.get().strip().lower()
        total_ids = sum(len(e.get("ids", [])) for e in entries)
        num_games = len(entries)

        steam_path = Path(self.steam_path_var.get())

        for e in entries:
            name = e.get("name", "Sem nome")
            app_id = e.get("app_id", "?")
            ids = e.get("ids", [])

            if filter_text:
                if filter_text not in (name.lower() + " " + str(app_id)):
                    continue

            # garante que temos banner/descrição em cache
            try:
                ensure_banner_cache(app_id, steam_path, self.log)
            except Exception:
                pass

            # card externo (margem)
            card_outer = tk.Frame(self.cards_frame, bg=self.bg)
            card_outer.pack(fill="x", pady=4)

            # "gradiente fake": fundo escuro + faixa mais clara
            card_inner = tk.Frame(card_outer, bg="#273246")
            card_inner.pack(fill="x", padx=4, pady=0)

            left_area = tk.Frame(card_inner, bg="#273246")
            left_area.pack(side="left", padx=8, pady=8)

            mid_area = tk.Frame(card_inner, bg="#2f3c52")
            mid_area.pack(side="left", fill="both", expand=True, pady=8)

            right_area = tk.Frame(card_inner, bg="#2f3c52")
            right_area.pack(side="right", padx=15, pady=8)

            # banner
            banner_path = CACHE_BANNERS_DIR / f"{app_id}.jpg"
            banner_img = None
            if banner_path.exists():
                try:
                    img = Image.open(banner_path)
                    img = img.resize((220, 90), Image.LANCZOS)
                    banner_img = ImageTk.PhotoImage(img)
                except Exception:
                    banner_img = None

            banner_lbl = tk.Label(
                left_area,
                image=banner_img,
                bg="#273246",
            )
            banner_lbl.image = banner_img
            banner_lbl.pack()

            # nome do jogo
            title_lbl = tk.Label(
                mid_area,
                text=name,
                bg="#2f3c52",
                fg="white",
                font=("Segoe UI", 11, "bold"),
                anchor="w",
            )
            title_lbl.pack(fill="x", padx=8, pady=(8, 0))

            # AppID em menor (opcional, embaixo)
            appid_lbl = tk.Label(
                mid_area,
                text=f"AppID: {app_id}",
                bg="#2f3c52",
                fg="#c7d5e0",
                font=("Segoe UI", 8),
                anchor="w",
            )
            appid_lbl.pack(fill="x", padx=8, pady=(0, 8))

            # botão deletar minimalista (apenas um "X")
            delete_btn = tk.Button(
                right_area,
                text="✕",
                command=lambda a=app_id: self.delete_game_card(a),
                bg=STEAM_COLORS["button_bg"],
                fg=self.fg,
                activebackground=self.accent,
                activeforeground="white",
                relief="flat",
                width=3,
                height=1,
                font=("Segoe UI", 9, "bold"),
            )    
            delete_btn.pack(anchor="e", pady=4)

        self.update_profile_footer(num_games, total_ids)

        # ajusta scrollregion
        self.cards_frame.update_idletasks()
        self.games_canvas.configure(scrollregion=self.games_canvas.bbox("all"))

    def update_profile_footer(self, num_games: int, total_ids: int):
        """Atualiza o rodapé de contagem de forma bilingue."""
        # quota simples
        self.profile_quota_label.config(text=f"{total_ids}/130")

        if self.lang == "pt":
            summary = f"{num_games} jogo(s) nesta profile • {total_ids} id(s)"
        else:
            game_word = "game" if num_games == 1 else "games"
            summary = f"{num_games} {game_word} in this profile • {total_ids} id(s)"

        self.profile_summary_label.config(text=summary)

    def delete_game_card(self, app_id: str):
        """Deleta o jogo pelo app_id (card)."""
        entries = self.get_current_entries()
        target = None
        for e in entries:
            if str(e.get("app_id")) == str(app_id):
                target = e
                break
        if not target:
            return

        # nome do jogo
        if self.lang == "pt":
            name = target.get("name", "Sem nome")
        else:
            name = target.get("name", "No name")

        # confirmação bilingue
        if self.lang == "pt":
            title = "Remover do profile"
            msg = (
                f"Isto irá remover '{name}' (appid {app_id}) da profile e da AppList (.txt).\n\n"
                "Isso NÃO apaga o jogo do disco.\n"
                "Continuar?"
            )
        else:
            title = "Remove from profile"
            msg = (
                f"This will remove '{name}' (appid {app_id}) from the profile and from the AppList (.txt).\n\n"
                "This does NOT delete the game from disk.\n"
                "Continue?"
            )

        if not messagebox.askyesno(title, msg):
            return

        # apaga cache de banner
        try:
            img_path = CACHE_BANNERS_DIR / f"{app_id}.jpg"
            txt_path = CACHE_BANNERS_DIR / f"{app_id}.txt"
            for p in (img_path, txt_path):
                if p.exists():
                    p.unlink()
        except Exception as e2:
            if self.lang == "pt":
                self.log(f"[AVISO] Erro ao apagar cache do banner: {e2}")
            else:
                self.log(f"[WARNING] Error while deleting banner cache: {e2}")

        # remove do profile e salva
        entries.remove(target)
        save_profiles(self.profiles_data)
        self.refresh_profile_view()

        # re-aplica AppList se diretório for válido
        applist_dir_str = self.applist_path_var.get().strip()
        if applist_dir_str and Path(applist_dir_str).exists():
            try:
                ids = self.flatten_current_profile_ids()
                profile_name = self.current_profile_var.get() or "PROFILE"
                generate_applist_files(Path(applist_dir_str), ids, self.log, profile_name)
            except Exception as e2:
                if self.lang == "pt":
                    messagebox.showerror("Erro ao re-aplicar profile", str(e2))
                else:
                    messagebox.showerror("Error re-applying profile", str(e2))

    # --------- Export/Import profiles ---------

    def export_profile(self):
        name = self.current_profile_var.get()
        entries = self.get_current_entries()
        if not entries:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Esta profile não possui jogos para exportar.")
            else:
                messagebox.showerror("Error", "This profile has no games to export.")
            return

        data = {
            "profile_name": name,
            "entries": entries,
        }

        title = "Exportar profile" if self.lang == "pt" else "Export profile"
        file = filedialog.asksaveasfilename(
            title=title,
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"{name}.json",
        )
        if not file:
            return

        try:
            with open(file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            if self.lang == "pt":
                self.log(f"Profile '{name}' exportada para: {file}")
            else:
                self.log(f"Profile '{name}' exported to: {file}")
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao exportar profile", str(e))
            else:
                messagebox.showerror("Error exporting profile", str(e))

    def import_profile(self):
        title = "Importar profile" if self.lang == "pt" else "Import profile"
        file = filedialog.askopenfilename(
            title=title,
            filetypes=[("JSON", "*.json"), ("Todos", "*.*")] if self.lang == "pt"
            else [("JSON", "*.json"), ("All files", "*.*")],
        )
        if not file:
            return

        try:
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao ler arquivo", str(e))
            else:
                messagebox.showerror("Error reading file", str(e))
            return

        entries = data.get("entries")
        if not isinstance(entries, list):
            if self.lang == "pt":
                messagebox.showerror("Erro", "Arquivo JSON não contém uma profile válida.")
            else:
                messagebox.showerror("Error", "JSON file does not contain a valid profile.")
            return

        suggested_name = data.get("profile_name") or Path(file).stem
        title_name = (
            "Nome da profile importada"
            if self.lang == "pt"
            else "Imported profile name"
        )
        prompt = (
            f"Nome sugerido: {suggested_name}"
            if self.lang == "pt"
            else f"Suggested name: {suggested_name}"
        )
        name = simpledialog.askstring(title_name, prompt, initialvalue=suggested_name)
        if not name:
            return

        if name in self.profiles_data["profiles"]:
            if self.lang == "pt":
                overwrite = messagebox.askyesno(
                    "Substituir profile",
                    f"Já existe uma profile chamada '{name}'. Substituir?",
                )
            else:
                overwrite = messagebox.askyesno(
                    "Replace profile",
                    f"There is already a profile named '{name}'. Replace it?",
                )
            if not overwrite:
                return

        self.profiles_data["profiles"][name] = {"entries": entries}
        self.profiles_data["last_profile"] = name
        save_profiles(self.profiles_data)
        self.refresh_profile_optionmenu()
        self.refresh_profile_view()
        if self.lang == "pt":
            self.log(f"Profile importada como '{name}'.")
        else:
            self.log(f"Profile imported as '{name}'.")

    # --------- Eventos de .lua ---------

    def on_drop(self, evt):
        files = self.root.tk.splitlist(evt.data)
        if not files:
            return

        p = Path(files[0])
        ext = p.suffix.lower()

        if ext == ".lua":
            self.process_lua(p)
        elif ext == ".zip":
            self.install_cache_zip_with_prompt(p)
        else:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Arraste apenas arquivos .lua ou .zip.")
            else:
                messagebox.showerror("Error", "Please drag only .lua or .zip files.")


    def select_lua(self):
        file = filedialog.askopenfilename(
            title="Selecione um arquivo .lua",
            filetypes=[("Lua files", "*.lua"), ("Todos", "*.*")],
        )
        if file:
            self.process_lua(Path(file))

    def select_zip(self):
        file = filedialog.askopenfilename(
            title="Selecione um arquivo .zip",
            filetypes=[("Arquivos ZIP", "*.zip"), ("Todos", "*.*")],
        )
        if file:
            self.install_cache_zip_with_prompt(Path(file))

    def ask_install_cache_now(self, zip_path: Path) -> bool:
        """
        Pergunta se deve instalar o cache agora.
        Tem checkbox 'Não perguntar novamente', salvo em config.json.
        """
        # se o usuário já marcou pra sempre instalar, não pergunta de novo
        if self.config.get("auto_install_cache_zip", False):
            return True

        if self.lang == "pt":
            title = "Instalar manifests do cache?"
            msg = (
                f"O arquivo ZIP abaixo será usado para instalar os manifests do cache:\n\n"
                f"{zip_path.name}\n\n"
                "Isso NÃO baixa nada da Steam, usa apenas os .lua/.manifest dentro do ZIP.\n\n"
                "Deseja continuar?"
            )
            chk_text = "Não perguntar novamente (sempre instalar automaticamente)"
            yes_text = "Sim"
            no_text = "Não"
        else:
            title = "Install cached manifests?"
            msg = (
                f"The ZIP file below will be used to install cached manifests:\n\n"
                f"{zip_path.name}\n\n"
                "No download from Steam will be done, only .lua/.manifest inside the ZIP.\n\n"
                "Do you want to continue?"
            )
            chk_text = "Don't ask again (always install automatically)"
            yes_text = "Yes"
            no_text = "No"

        win = tk.Toplevel(self.root)
        win.title(title)
        win.configure(bg=self.bg_alt)
        win.resizable(False, False)
        win.grab_set()
        win.transient(self.root)

        lbl = tk.Label(
            win,
            text=msg,
            bg=self.bg_alt,
            fg=self.fg,
            justify="left",
            wraplength=380,
        )
        lbl.pack(padx=15, pady=(15, 8))

        dont_ask_var = tk.BooleanVar(value=False)
        chk = tk.Checkbutton(
            win,
            text=chk_text,
            variable=dont_ask_var,
            bg=self.bg_alt,
            fg=self.fg,
            selectcolor=self.bg,
            activebackground=self.bg_alt,
            activeforeground=self.fg,
        )
        chk.pack(anchor="w", padx=15, pady=(0, 10))

        result_var = tk.BooleanVar(value=False)

        def on_yes():
            result_var.set(True)
            if dont_ask_var.get():
                self.config["auto_install_cache_zip"] = True
                save_config(self.config)
            win.destroy()

        def on_no():
            result_var.set(False)
            win.destroy()

        btn_frame = tk.Frame(win, bg=self.bg_alt)
        btn_frame.pack(pady=(0, 12))

        tk.Button(
            btn_frame,
            text=yes_text,
            command=on_yes,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=10,
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text=no_text,
            command=on_no,
            bg=STEAM_COLORS["button_bg"],
            fg=self.fg,
            activebackground=self.accent,
            activeforeground="white",
            relief="flat",
            width=10,
        ).pack(side="left", padx=5)

        win.update_idletasks()
        x = (win.winfo_screenwidth() - win.winfo_reqwidth()) // 2
        y = (win.winfo_screenheight() - win.winfo_reqheight()) // 2
        win.geometry(f"+{x}+{y}")

        self.root.wait_variable(result_var)
        return bool(result_var.get())

    def install_cache_zip_with_prompt(self, zip_path: Path):
        if not zip_path.exists():
            if self.lang == "pt":
                messagebox.showerror("Erro", f"Arquivo não encontrado:\n{zip_path}")
            else:
                messagebox.showerror("Error", f"File not found:\n{zip_path}")
            return

        if not self.ask_install_cache_now(zip_path):
            if self.lang == "pt":
                self.log("Instalação via cache cancelada pelo usuário.")
            else:
                self.log("Cache installation cancelled by user.")
            return

        self._install_cache_zip(zip_path)

    def _install_cache_zip(self, zip_path: Path):
        # limpa log
        if self.log_box is not None:
            self.log_box.config(state="normal")
            self.log_box.delete("1.0", "end")
            self.log_box.config(state="disabled")

        steam = Path(self.steam_path_var.get())
        if not steam.exists():
            if self.lang == "pt":
                messagebox.showerror("Erro", "Diretório da Steam inválido.")
            else:
                messagebox.showerror("Error", "Invalid Steam directory.")
            return

        if self.lang == "pt":
            self.log(f"Instalando a partir do cache ZIP: {zip_path}")
        else:
            self.log(f"Installing from cache ZIP: {zip_path}")

        tmp_dir = SCRIPT_DIR / "__tmp_cache_install"
        if tmp_dir.exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)
        tmp_dir.mkdir(parents=True, exist_ok=True)

        # 1) Extrair o ZIP
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmp_dir)
        except Exception as e:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            if self.lang == "pt":
                messagebox.showerror(
                    "Erro",
                    f"Falha ao extrair o ZIP:\n{e}",
                )
            else:
                messagebox.showerror(
                    "Error",
                    f"Failed to extract ZIP:\n{e}",
                )
            return

        try:
            # 2) Procurar .lua e .manifest dentro do tmp
            lua_candidates = []
            manifest_files = []

            for root, dirs, files in os.walk(tmp_dir):
                for fname in files:
                    full = Path(root) / fname
                    low = fname.lower()
                    if low.endswith(".lua"):
                        lua_candidates.append(full)
                    elif low.endswith(".manifest"):
                        manifest_files.append(full)

            if not lua_candidates:
                if self.lang == "pt":
                    messagebox.showerror(
                        "Erro",
                        "Nenhum arquivo .lua encontrado dentro do ZIP.",
                    )
                else:
                    messagebox.showerror(
                        "Error",
                        "No .lua file found inside the ZIP.",
                    )
                return

            lua_path = lua_candidates[0]
            if self.lang == "pt":
                self.log(f"Lua do cache: {lua_path}")
            else:
                self.log(f"Cache Lua: {lua_path}")

            # 3) Parse do .lua
            try:
                info = parse_lua(lua_path)
            except Exception as e:
                if self.lang == "pt":
                    messagebox.showerror("Erro ao ler .lua", str(e))
                else:
                    messagebox.showerror("Error reading .lua", str(e))
                return

            # 4) Atualiza config.vdf e .acf (modo cache)
            try:
                if self.lang == "pt":
                    self.log("Atualizando config.vdf (cache)...")
                else:
                    self.log("Updating config.vdf (cache)...")
                add_decryption_keys_to_config(steam, info, self.log)
            except Exception as e:
                if self.lang == "pt":
                    messagebox.showerror("Erro em config.vdf", str(e))
                else:
                    messagebox.showerror("Error in config.vdf", str(e))
                return

            try:
                if self.lang == "pt":
                    self.log("Gerando .acf (cache)...")
                else:
                    self.log("Generating .acf (cache)...")
                write_acf_for_lua(steam, info, self.log)
            except Exception as e:
                if self.lang == "pt":
                    messagebox.showerror("Erro ao gerar .acf", str(e))
                else:
                    messagebox.showerror("Error generating .acf", str(e))
                return

            # 5) Copiar manifests para depotcache
            depotcache_dir = steam / "depotcache"
            depotcache_dir.mkdir(exist_ok=True)

            manifest_out_paths: List[Path] = []
            for mf in manifest_files:
                dest = depotcache_dir / mf.name
                try:
                    shutil.copy2(mf, dest)
                    manifest_out_paths.append(dest)
                    if self.lang == "pt":
                        self.log(f"Manifest copiado para depotcache: {dest}")
                    else:
                        self.log(f"Manifest copied to depotcache: {dest}")
                except Exception as e:
                    if self.lang == "pt":
                        self.log(f"[AVISO] Falha ao copiar manifest {mf}: {e}")
                    else:
                        self.log(f"[WARNING] Failed to copy manifest {mf}: {e}")

            if not manifest_out_paths:
                if self.lang == "pt":
                    self.log(
                        "Nenhum manifest encontrado no ZIP. Profile não será atualizada."
                    )
                else:
                    self.log(
                        "No manifest found in the ZIP. Profile will not be updated."
                    )
                return

            # 6) Extrair IDs de depot e combinar com AppID
            depot_ids = extract_ids_from_manifests(manifest_out_paths, self.log)
            combined: List[str] = []
            seen = set()
            for x in [info.app_id] + depot_ids:
                if x not in seen:
                    seen.add(x)
                    combined.append(x)

            game_name = try_get_game_name(info.app_id)
            if self.lang == "pt":
                self.log(f"Nome do jogo detectado: {game_name}")
                self.log(f"IDs combinados (App + Depots): {', '.join(combined)}")
            else:
                self.log(f"Detected game name: {game_name}")
                self.log(f"Combined IDs (App + Depots): {', '.join(combined)}")

            # 7) Preparar cache de banner (se possível)
            try:
                ensure_banner_cache(info.app_id, steam, self.log)
            except Exception as e:
                if self.lang == "pt":
                    self.log(f"[AVISO] Falha ao preparar cache de banner: {e}")
                else:
                    self.log(f"[WARNING] Failed to prepare banner cache: {e}")

            # 8) Instalar jogo na profile respeitando limite de 130 e AppList
            self.install_game_with_ids(info.app_id, game_name, combined)

        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # --------- Lógica principal (.lua) ---------
    def process_lua(self, lua_path: Path):
        # limpa log
        self.log_box.config(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.config(state="disabled")

        steam = Path(self.steam_path_var.get())
        if not steam.exists():
            if self.lang == "pt":
                messagebox.showerror("Erro", "Diretório da Steam inválido.")
            else:
                messagebox.showerror("Error", "Invalid Steam directory.")
            return

        if self.lang == "pt":
            self.log(f"Lendo lua: {lua_path}")
        else:
            self.log(f"Reading lua: {lua_path}")

        # 1) Ler e interpretar o .lua
        try:
            info = parse_lua(lua_path)
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao ler .lua", str(e))
            else:
                messagebox.showerror("Error reading .lua", str(e))
            return

        # 2) Atualizar config.vdf com as DecryptionKeys
        try:
            if self.lang == "pt":
                self.log("Atualizando config.vdf...")
            else:
                self.log("Updating config.vdf...")
            add_decryption_keys_to_config(steam, info, self.log)
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro em config.vdf", str(e))
            else:
                messagebox.showerror("Error in config.vdf", str(e))
            return

        # 3) Gerar .acf
        try:
            if self.lang == "pt":
                self.log("Gerando .acf...")
            else:
                self.log("Generating .acf...")
            write_acf_for_lua(steam, info, self.log)
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao gerar .acf", str(e))
            else:
                messagebox.showerror("Error generating .acf", str(e))
            return

        # 4) Baixar + descriptografar manifests para depotcache
        try:
            if self.lang == "pt":
                self.log("Baixando e descriptografando manifests para depotcache...")
            else:
                self.log("Downloading and decrypting manifests to depotcache...")
            manifest_paths = download_manifests_to_depotcache(steam, info, self.log)
        except Exception as e:
            if self.lang == "pt":
                messagebox.showerror("Erro ao baixar manifests", str(e))
            else:
                messagebox.showerror("Error downloading manifests", str(e))
            return

        if not manifest_paths:
            if self.lang == "pt":
                self.log("Nenhum manifest baixado. Profile não será atualizada.")
            else:
                self.log("No manifest was downloaded. Profile will not be updated.")
            return

        # 5) Extrair IDs de depot + combinar com AppID
        depot_ids = extract_ids_from_manifests(manifest_paths, self.log)
        combined: List[str] = []
        seen = set()
        for x in [info.app_id] + depot_ids:
            if x not in seen:
                seen.add(x)
                combined.append(x)

        game_name = try_get_game_name(info.app_id)

        if self.lang == "pt":
            self.log(f"Nome do jogo detectado: {game_name}")
            self.log(f"IDs combinados (App + Depots): {', '.join(combined)}")
        else:
            self.log(f"Detected game name: {game_name}")
            self.log(f"Combined IDs (App + Depots): {', '.join(combined)}")

        # 6) Banner / descrição em cache (não é crítico se falhar)
        try:
            ensure_banner_cache(info.app_id, steam, self.log)
        except Exception as e:
            if self.lang == "pt":
                self.log(f"[AVISO] Falha ao preparar cache de banner: {e}")
            else:
                self.log(f"[WARNING] Failed to prepare banner cache: {e}")

        # 7) Delega para o helper que cuida de limite 130 + profile + AppList
        self.install_game_with_ids(info.app_id, game_name, combined)

    # --------- Get Lua integrado ---------

    def on_get_lua_clicked(self):
        query = self.search_steam_var.get().strip()
        if not query:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Digite o nome do jogo ou o AppID.")
            else:
                messagebox.showerror("Error", "Type the game name or AppID.")
            return

        # Descobrir AppID + nome
        if query.isdigit():
            appid = query
            name = try_get_game_name(appid)
        else:
            result = steam_search_first_app(query)
            if not result:
                if self.lang == "pt":
                    messagebox.showerror("Erro", "Não encontrei nenhum jogo com esse termo.")
                else:
                    messagebox.showerror("Error", "Could not find any game with that term.")
                return
            appid = result["appid"]
            name = result["name"] or try_get_game_name(appid)

        # Log da tentativa nas fontes automáticas
        if self.lang == "pt":
            self.log(f"Buscando .lua para {name} (AppID: {appid}) via fontes externas...")
        else:
            self.log(f"Fetching .lua for {name} (AppID: {appid}) from external sources...")

        ok, msg, lua_path = download_lua_with_fallback(appid)
        self.log(msg)

        # ❌ Falhou nas fontes automáticas
        if not ok or not lua_path:
            # Janela de confirmação PT/EN ANTES de abrir o get_lua_alternative.py
            if self.lang == "pt":
                title = "Arquivo não encontrado"
                text = (
                    "Não foi possível baixar o arquivo .lua automaticamente "
                    "(SPIN0ZAi / RobZombie).\n\n"
                    "Gostaria de tentar a terceira opção?\n"
                    "Após isso, arraste ou importe o .lua no Haze Tools."
                )
            else:
                title = "File not found"
                text = (
                    "The .lua file could not be downloaded automatically "
                    "(SPIN0ZAi / RobZombie).\n\n"
                    "Would you like to try the third option?\n"
                    "After that, drag or import the .lua into Haze Tools."
                )

            if not messagebox.askyesno(title, text):
                return

            # Agora tenta abrir o get_lua_alternative.py
            alt_script = SCRIPT_DIR / "get_lua_alternative.py"
            if alt_script.exists():
                if self.lang == "pt":
                    self.log("Abrindo get_lua_alternative.py (terceira opção)...")
                else:
                    self.log("Opening get_lua_alternative.py (third option)...")
                try:
                    subprocess.Popen([sys.executable, str(alt_script)], cwd=str(SCRIPT_DIR))
                except Exception as e:
                    if self.lang == "pt":
                        messagebox.showerror(
                            "Erro",
                            "Ocorreu um erro ao abrir get_lua_alternative.py:\n\n" + str(e),
                        )
                    else:
                        messagebox.showerror(
                            "Error",
                            "An error occurred while opening get_lua_alternative.py:\n\n" + str(e),
                        )
            else:
                if self.lang == "pt":
                    messagebox.showerror(
                        "Erro",
                        "O arquivo 'get_lua_alternative.py' não foi encontrado na pasta do Haze Tools.\n"
                        "Coloque o script lá e tente novamente."
                    )
                else:
                    messagebox.showerror(
                        "Error",
                        "The file 'get_lua_alternative.py' was not found in the Haze Tools folder.\n"
                        "Place the script there and try again."
                    )
            return

        # ✔ Sucesso → pergunta se quer instalar agora
        if self.lang == "pt":
            title = "Lua baixado"
            text = (
                f".lua gerado na pasta 'lua_files':\n{lua_path.name}\n\n"
                "Deseja instalar agora (usar como se fosse arrastado)?"
            )
        else:
            title = "Lua downloaded"
            text = (
                f".lua created in the 'lua_files' folder:\n{lua_path.name}\n\n"
                "Do you want to install it now (use it as if it was dragged)?"
            )

        resp = messagebox.askyesno(title, text)
        if resp:
            self.process_lua(lua_path)

    def on_get_lua_cache_clicked(self):
        """
        Baixa o ZIP de cache dos repositórios GitHub e, se falhar,
        oferece a mesma 'terceira opção' (get_lua_alternative.py).
        """
        query = self.search_steam_var.get().strip()
        if not query:
            if self.lang == "pt":
                messagebox.showerror("Erro", "Digite o nome do jogo ou o AppID.")
            else:
                messagebox.showerror("Error", "Type the game name or AppID.")
            return

        # Descobrir AppID + nome
        if query.isdigit():
            appid = query
            name = try_get_game_name(appid)
        else:
            result = steam_search_first_app(query)
            if not result:
                if self.lang == "pt":
                    messagebox.showerror("Erro", "Não encontrei nenhum jogo com esse termo.")
                else:
                    messagebox.showerror("Error", "Could not find any game with that term.")
                return
            appid = result["appid"]
            name = result["name"] or try_get_game_name(appid)

        if self.lang == "pt":
            self.log(f"Baixando pacote de cache (.zip) para {name} (AppID: {appid})...")
        else:
            self.log(f"Downloading cache package (.zip) for {name} (AppID: {appid})...")

        ok, msg, zip_path = download_cache_zip_with_fallback(appid)
        self.log(msg)

        # ❌ Falhou o ZIP → oferece terceira opção também
        if not ok or not zip_path:
            if self.lang == "pt":
                title = "Arquivo não encontrado"
                text = (
                    "Não foi possível baixar o pacote de cache (.zip) automaticamente.\n\n"
                    "Gostaria de tentar a terceira opção de .lua manual?\n"
                    "Após isso, arraste ou importe o .lua no Haze Tools."
                )
            else:
                title = "File not found"
                text = (
                    "The cache package (.zip) could not be downloaded automatically.\n\n"
                    "Would you like to try the third manual .lua option?\n"
                    "After that, drag or import the .lua into Haze Tools."
                )

            if not messagebox.askyesno(title, text):
                return

            alt_script = SCRIPT_DIR / "get_lua_alternative.py"
            if alt_script.exists():
                if self.lang == "pt":
                    self.log("Abrindo get_lua_alternative.py (terceira opção - cache falhou)...")
                else:
                    self.log("Opening get_lua_alternative.py (third option - cache failed)...")
                try:
                    subprocess.Popen([sys.executable, str(alt_script)], cwd=str(SCRIPT_DIR))
                except Exception as e:
                    if self.lang == "pt":
                        messagebox.showerror(
                            "Erro",
                            "Ocorreu um erro ao abrir get_lua_alternative.py:\n\n" + str(e),
                        )
                    else:
                        messagebox.showerror(
                            "Error",
                            "An error occurred while opening get_lua_alternative.py:\n\n" + str(e),
                        )
            else:
                if self.lang == "pt":
                    messagebox.showerror(
                        "Erro",
                        "O arquivo 'get_lua_alternative.py' não foi encontrado na pasta do Haze Tools.\n"
                        "Coloque o script lá e tente novamente."
                    )
                else:
                    messagebox.showerror(
                        "Error",
                        "The file 'get_lua_alternative.py' was not found in the Haze Tools folder.\n"
                        "Place the script there and try again."
                    )
            return

        # ✔ Sucesso → segue instalando ZIP normalmente
        self.install_cache_zip_with_prompt(zip_path)

    # --------- run ---------

    def run(self):
        self.root.mainloop()



# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    AppGUI().run()
