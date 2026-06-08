"""Helpers d'authentification Evoliz + persistance Gist + admin access.

Repris de Banana Import Club / Je gère ma clôture mensuelle — version online-only,
multi-société uniquement (scope prescriber_users). Gist filename / description
séparés pour découpler cette app des deux autres.
"""
import os
import json
import hashlib

import requests
import streamlit as st


# --- Constantes ---
APP_DIR = os.path.dirname(os.path.abspath(__file__))
ACCESS_FILE = os.path.join(APP_DIR, ".access_tokens.json")
GIST_FILENAME = "liste_societes_plateforme_access_tokens.json"
GIST_DESCRIPTION_PREFIX = "Liste societes plateforme"
GIST_DESCRIPTION = f"{GIST_DESCRIPTION_PREFIX} — Access Tokens"
EVOLIZ_API = "https://www.evoliz.io/api"
INACTIVITY_TIMEOUT = 30 * 60  # 30 minutes


# --- Auth Evoliz ---
def refresh_evoliz_token():
    """Re-login Evoliz avec les credentials stockés en session. True si succès."""
    pk = st.session_state.get("_evoliz_pk")
    sk = st.session_state.get("_evoliz_sk")
    if not pk or not sk:
        return False
    try:
        r = requests.post(f"{EVOLIZ_API}/login",
                          json={"public_key": pk, "secret_key": sk}, timeout=15)
        if r.status_code == 200:
            tok = r.json().get("access_token")
            if tok:
                st.session_state.token_headers = {
                    "Authorization": f"Bearer {tok}",
                    "Accept": "application/json",
                }
                return True
    except Exception:
        pass
    return False


def authed_request(method, url, **kwargs):
    """requests.<method> avec re-login automatique sur 401."""
    kwargs.pop("headers", None)
    h = st.session_state.get("token_headers", {})
    r = requests.request(method, url, headers=h, **kwargs)
    if r.status_code == 401 and refresh_evoliz_token():
        h = st.session_state.get("token_headers", {})
        r = requests.request(method, url, headers=h, **kwargs)
    return r


def fetch_paginated(endpoint_path: str, params: dict | None = None) -> tuple[list, str | None]:
    """Récupère toutes les pages d'un endpoint Evoliz (relatif à /api/v1/).

    Retourne (liste_items, erreur). Si erreur, liste_items peut être partielle.
    """
    base = f"{EVOLIZ_API}/v1"
    params = dict(params or {})
    params.setdefault("per_page", 100)
    all_items: list = []
    page = 1
    while True:
        params["page"] = page
        try:
            r = authed_request("GET", f"{base}/{endpoint_path}", params=params, timeout=20)
        except requests.exceptions.RequestException as e:
            return all_items, f"Réseau indisponible : {type(e).__name__}"
        if r.status_code != 200:
            return all_items, f"HTTP {r.status_code} : {r.text[:200]}"
        d = r.json()
        all_items.extend(d.get("data", []))
        last_page = d.get("meta", {}).get("last_page", 1)
        if page >= last_page:
            break
        page += 1
    return all_items, None


def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


# --- Gist persistance ---
def get_gist_token():
    try:
        return st.secrets.get("GITHUB_GIST_TOKEN", "") or os.environ.get("GITHUB_GIST_TOKEN", "")
    except Exception:
        return os.environ.get("GITHUB_GIST_TOKEN", "")


def discover_gist_id():
    """Cherche un Gist existant matchant notre filename ou description prefix."""
    pat = get_gist_token()
    if not pat:
        return ""
    cached = st.session_state.get("_discovered_gist_id")
    if cached is not None:
        return cached
    found = ""
    try:
        r = requests.get("https://api.github.com/gists",
                         headers={"Authorization": f"token {pat}", "Accept": "application/json"},
                         params={"per_page": 100}, timeout=10)
        if r.status_code == 200:
            for g in r.json():
                if GIST_FILENAME in (g.get("files") or {}):
                    found = g.get("id", "")
                    break
                if GIST_DESCRIPTION_PREFIX in (g.get("description") or ""):
                    found = g.get("id", "")
                    break
    except Exception:
        pass
    st.session_state["_discovered_gist_id"] = found
    if found:
        try:
            data = {}
            if os.path.exists(ACCESS_FILE):
                with open(ACCESS_FILE) as f:
                    data = json.load(f)
            data["_gist_id"] = found
            with open(ACCESS_FILE, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    return found


def get_gist_id():
    """secrets/env > fichier local > auto-découverte."""
    try:
        _id = st.secrets.get("GITHUB_GIST_ID", "") or os.environ.get("GITHUB_GIST_ID", "")
        if _id:
            return _id
    except Exception:
        pass
    try:
        if os.path.exists(ACCESS_FILE):
            with open(ACCESS_FILE) as f:
                _id = json.load(f).get("_gist_id", "")
                if _id:
                    return _id
    except Exception:
        pass
    return discover_gist_id()


def load_from_gist():
    pat = get_gist_token()
    gid = get_gist_id()
    if not pat or not gid:
        return None
    try:
        r = requests.get(f"https://api.github.com/gists/{gid}",
                         headers={"Authorization": f"token {pat}", "Accept": "application/json"},
                         timeout=10)
        if r.status_code == 200:
            content = r.json().get("files", {}).get(GIST_FILENAME, {}).get("content", "{}")
            return json.loads(content)
    except Exception:
        pass
    return None


def save_to_gist(data):
    """Sauvegarde dans le Gist privé. Retourne (success, error_msg)."""
    pat = get_gist_token()
    if not pat:
        return False, "GITHUB_GIST_TOKEN absent (pas de persistance Cloud)"
    gid = get_gist_id()
    payload = {"files": {GIST_FILENAME: {"content": json.dumps(data, indent=2, ensure_ascii=False)}}}
    try:
        if gid:
            r = requests.patch(f"https://api.github.com/gists/{gid}",
                               headers={"Authorization": f"token {pat}", "Accept": "application/json"},
                               json=payload, timeout=10)
            if r.status_code == 200:
                return True, ""
            return False, f"PATCH gist {gid[:8]} HTTP {r.status_code} : {r.text[:200]}"
        payload["description"] = GIST_DESCRIPTION
        payload["public"] = False
        r = requests.post("https://api.github.com/gists",
                          headers={"Authorization": f"token {pat}", "Accept": "application/json"},
                          json=payload, timeout=10)
        if r.status_code != 201:
            return False, f"POST gist HTTP {r.status_code} : {r.text[:200]} (vérifier scope 'gist')"
        new_id = r.json().get("id", "")
        if new_id:
            data["_gist_id"] = new_id
            try:
                with open(ACCESS_FILE, "w") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
            payload["files"][GIST_FILENAME]["content"] = json.dumps(data, indent=2, ensure_ascii=False)
            requests.patch(f"https://api.github.com/gists/{new_id}",
                           headers={"Authorization": f"token {pat}", "Accept": "application/json"},
                           json=payload, timeout=10)
            st.session_state.pop("_discovered_gist_id", None)
        return True, ""
    except Exception as e:
        return False, f"Exception : {e}"


def load_access():
    """Charge les accès : Gist prioritaire, fichier local en fallback."""
    data = load_from_gist()
    if data:
        try:
            with open(ACCESS_FILE, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
        return data
    try:
        if os.path.exists(ACCESS_FILE):
            with open(ACCESS_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {"tokens": {}, "admin_hash": ""}


def save_access(data):
    """Sauvegarde fichier local + Gist."""
    try:
        with open(ACCESS_FILE, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass
    ok, err = save_to_gist(data)
    st.session_state["_last_gist_save"] = {"ok": ok, "err": err}
