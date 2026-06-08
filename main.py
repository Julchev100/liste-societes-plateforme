"""Liste des sociétés de la plateforme — app sœur de Banana Import Club.

Liste tous les dossiers (companyid + nom) visibles par une clé API multi-société
(scope prescriber_users) et déplie EN COLONNES toutes les informations disponibles
sur chaque société, avec des libellés rendus lisibles (statut juridique, pays, site
de rattachement, conditions de paiement, code APE/NAF…).

Lecture seule. Auth + gate admin/tiers + persistance Gist repris des apps sœurs.
"""
import io
import json
import os
import secrets as _secrets
import time
from datetime import datetime as dt_datetime

import pandas as pd
import requests
import streamlit as st

import evoliz_admin as ea

# >>> Pour renommer l'app : changer APP_NAME ici (+ GIST_* dans evoliz_admin.py). <<<
APP_NAME = "Liste des sociétés de la plateforme"

st.set_page_config(page_title=APP_NAME, layout="wide", page_icon="🏢")


# ===========================================================================
# Table de référence NAF/APE (résolution code -> libellé)
# ===========================================================================
@st.cache_data
def load_naf_index() -> dict:
    """Index NAF normalisé : code sans points/espaces (majuscule) -> libellé."""
    path = os.path.join(ea.APP_DIR, "naf_rev2.json")
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {}
    idx = {}
    for code, label in raw.items():
        key = str(code).replace(".", "").replace(" ", "").upper()
        idx[key] = label
    return idx


def naf_label(code) -> str:
    if not code:
        return ""
    idx = load_naf_index()
    key = str(code).replace(".", "").replace(" ", "").upper()
    return idx.get(key, "")


# ===========================================================================
# Gate : admin password ou tiers token (?token=...)
# ===========================================================================
_url_params = st.query_params
_url_token = _url_params.get("token", "")
_access_data = ea.load_access()
_is_admin = False
_access_label = ""

if _url_token:
    _tok_info = _access_data.get("tokens", {}).get(_url_token)
    if _tok_info and _tok_info.get("status") == "active":
        _access_label = _tok_info.get("label", "Tiers")
    elif _tok_info and _tok_info.get("status") == "suspended":
        st.error("⛔ Accès suspendu. Contactez l'administrateur.")
        st.stop()
    else:
        st.error("⛔ Token invalide ou révoqué.")
        st.stop()
else:
    _admin_hash = _access_data.get("admin_hash", "")
    if not _admin_hash:
        _is_admin = True  # première utilisation : accès libre pour configurer
    elif st.session_state.get("_admin_auth"):
        _is_admin = True
    else:
        st.title(f"🏢 {APP_NAME}")
        st.subheader("🔒 Accès administrateur")
        st.caption("Cette application est protégée. Saisissez le mot de passe administrateur.")
        _pw = st.text_input("Mot de passe", type="password", key="admin_gate_pw")
        if st.button("🔓 Accéder", type="primary", use_container_width=True, key="btn_admin_gate"):
            if ea.hash_pw(_pw) == _admin_hash:
                st.session_state["_admin_auth"] = True
                st.rerun()
            else:
                st.error("❌ Mot de passe incorrect.")
        st.stop()


# ===========================================================================
# Header + timeout d'inactivité
# ===========================================================================
st.markdown(f"#### 🏢 {APP_NAME}")
if _access_label:
    st.caption(f"🔑 Accès : **{_access_label}**")
else:
    st.caption("Mode administrateur")

_now = time.time()
if "last_activity" not in st.session_state:
    st.session_state.last_activity = _now
if _now - st.session_state.last_activity > ea.INACTIVITY_TIMEOUT:
    for _k in list(st.session_state.keys()):
        del st.session_state[_k]
    st.warning("⏱️ Session expirée (30 minutes d'inactivité). Veuillez recharger.")
    st.stop()
st.session_state.last_activity = _now


# ===========================================================================
# Init session_state
# ===========================================================================
for _k, _default in [
    ("token_headers", {}),
    ("companies_list", []),
    ("_key_mode", None),
    ("_scopes", []),
]:
    if _k not in st.session_state:
        st.session_state[_k] = _default

_is_tiers = bool(_url_token) and not _is_admin
_logged_in = bool(st.session_state.token_headers)


# ===========================================================================
# Helpers de login (multi-société uniquement)
# ===========================================================================
def do_login(pk: str, sk: str) -> bool:
    """Login Evoliz et remplit session_state. Retourne True si OK.

    Cette app suppose des clés MULTI-SOCIÉTÉ (scope prescriber_users). Si la clé
    ne donne pas accès à la liste des dossiers, un avertissement est affiché.
    """
    try:
        r = requests.post(f"{ea.EVOLIZ_API}/login",
                          json={"public_key": pk, "secret_key": sk}, timeout=15)
    except Exception as e:
        st.error(f"Erreur réseau : {e}")
        return False
    if r.status_code == 401:
        st.error("❌ Clés API invalides.")
        return False
    if r.status_code != 200:
        st.error(f"❌ Échec login HTTP {r.status_code} — {r.text[:200]}")
        return False

    login_data = r.json()
    h = {"Authorization": f"Bearer {login_data.get('access_token')}", "Accept": "application/json"}
    st.session_state.token_headers = h
    st.session_state["_evoliz_pk"] = pk
    st.session_state["_evoliz_sk"] = sk

    scopes = login_data.get("scopes", []) or []
    if isinstance(scopes, str):
        scopes = [s.strip() for s in scopes.split(",") if s.strip()]
    st.session_state["_scopes"] = scopes
    st.session_state["_key_mode"] = "multi" if "prescriber_users" in scopes else "autre"
    # On purge un éventuel annuaire en cache de la session précédente.
    st.session_state.pop("_companies_cache", None)
    return True


def do_logout():
    for _k in ("token_headers", "companies_list", "_evoliz_pk", "_evoliz_sk",
               "_key_mode", "_scopes", "_companies_cache"):
        if _k in st.session_state:
            _v = st.session_state[_k]
            if isinstance(_v, dict):
                st.session_state[_k] = {}
            elif isinstance(_v, list):
                st.session_state[_k] = []
            else:
                st.session_state[_k] = None


# ===========================================================================
# Aplatissement société -> ligne plate + libellés lisibles
# ===========================================================================
# Libellés FR par chemin (clé aplatie). Tout chemin non listé reçoit un libellé
# auto-généré (humanize) pour rester exhaustif si l'API renvoie de nouveaux champs.
COLUMN_LABELS = {
    "companyid": "ID dossier",
    "company_code": "Code dossier",
    "company_name": "Nom de la société",
    "legal_status.label": "Statut juridique",
    "legal_status.legal_status_code": "Code statut juridique",
    "legal_status.other_label": "Statut juridique (autre)",
    "mode": "Mode fonctionnel",
    "live": "Production",
    "email": "Email",
    "phone": "Téléphone",
    "access_path": "Chemin d'accès",
    "lastconnect": "Dernière connexion",
    "address.addr": "Adresse",
    "address.addr2": "Complément d'adresse",
    "address.postcode": "Code postal",
    "address.town": "Ville",
    "address.country.label": "Pays",
    "address.country.iso2": "Code pays",
    "home_site.home_site": "Site de rattachement",
    "home_site.home_siteid": "ID site",
    "business_number": "SIRET",
    "activity_number": "Code APE/NAF",
    "_naf_label": "Libellé APE/NAF",
    "vat_number": "N° TVA intracom.",
    "immat_number": "Immatriculation (RCS/RM)",
    "accounting.beginning_date": "Début exercice",
    "accounting.ending_date": "Fin exercice",
    "term.payterm.label": "Délai de paiement (défaut)",
    "term.payterm.paytermid": "ID délai paiement",
    "term.paytype.label": "Moyen de paiement (défaut)",
    "term.paytype.paytypeid": "ID moyen paiement",
    "template_menu.label": "Modèle de menu",
    "template_menu.template_menuid": "ID modèle de menu",
}

# Ordre d'affichage privilégié (les colonnes présentes hors liste suivent, triées).
PREFERRED_ORDER = [
    "companyid", "company_code", "company_name",
    "legal_status.label", "mode", "live",
    "email", "phone",
    "address.addr", "address.addr2", "address.postcode", "address.town",
    "address.country.label", "address.country.iso2",
    "home_site.home_site", "home_site.home_siteid",
    "business_number", "activity_number", "_naf_label",
    "vat_number", "immat_number",
    "accounting.beginning_date", "accounting.ending_date",
    "term.payterm.label", "term.paytype.label",
    "access_path", "lastconnect",
]

_MODE_FR = {"BUSINESS": "Facturation (Business)", "BANKING": "Banque (Banking)"}


def flatten(obj, prefix="") -> dict:
    """Aplatit récursivement un dict imbriqué : {'a': {'b': 1}} -> {'a.b': 1}.
    Les listes sont encodées en JSON compact (rares sur l'objet company)."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict):
                out.update(flatten(v, path))
            elif isinstance(v, list):
                out[path] = json.dumps(v, ensure_ascii=False) if v else ""
            else:
                out[path] = v
    return out


def humanize(path: str) -> str:
    return path.replace(".", " · ").replace("_", " ").strip().capitalize()


def format_value(path: str, value):
    """Met en forme une valeur pour affichage selon son chemin."""
    if value is None:
        return ""
    last = path.rsplit(".", 1)[-1]
    if last == "mode" and isinstance(value, str):
        return _MODE_FR.get(value.upper(), value)
    if last == "live":
        return "✅ Production" if value else "🧪 Démo / test"
    if isinstance(value, bool):
        return "Oui" if value else "Non"
    if last in ("lastconnect",) and isinstance(value, str) and "T" in value:
        return value[:19].replace("T", " ")
    return value


def company_to_row(company: dict) -> dict:
    """Société brute -> dict {libellé FR: valeur formatée}, NAF résolu en plus."""
    flat = flatten(company)
    # Résolution NAF -> colonne dérivée juste après le code APE.
    ape = flat.get("activity_number")
    if ape:
        flat["_naf_label"] = naf_label(ape)
    row = {}
    for path, value in flat.items():
        label = COLUMN_LABELS.get(path) or humanize(path)
        row[label] = format_value(path, value)
    return row


def build_dataframe(companies: list) -> pd.DataFrame:
    """Construit le DataFrame annuaire avec colonnes ordonnées et libellées."""
    rows = [company_to_row(c) for c in companies]
    df = pd.DataFrame(rows)
    # Ordre des colonnes : préférées (présentes) d'abord, puis le reste trié.
    preferred_labels = [COLUMN_LABELS.get(p, p) for p in PREFERRED_ORDER]
    ordered = [c for c in preferred_labels if c in df.columns]
    rest = sorted(c for c in df.columns if c not in ordered)
    return df[ordered + rest]


def to_excel_bytes(df: pd.DataFrame) -> bytes:
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Sociétés")
    return buf.getvalue()


def fetch_companies(with_detail: bool):
    """Récupère toutes les sociétés visibles. Si with_detail, enrichit chaque
    dossier via GET /companies/{id} (plus lent, généralement inutile). Retourne
    (liste, erreur)."""
    companies, err = ea.fetch_paginated("companies")
    if err:
        return companies, err
    if not with_detail or not companies:
        return companies, None

    enriched = []
    prog = st.progress(0.0, text="Chargement du détail des dossiers…")
    total = len(companies)
    for i, c in enumerate(companies, start=1):
        cid = c.get("companyid")
        merged = dict(c)
        if cid is not None:
            try:
                r = ea.authed_request(
                    "GET", f"{ea.EVOLIZ_API}/v1/companies/{cid}", timeout=15)
                if r.status_code == 200:
                    detail = r.json() or {}
                    merged.update({k: v for k, v in detail.items() if v is not None})
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.65)  # respecte la limite de 100 req/min
        enriched.append(merged)
        prog.progress(i / total, text=f"Détail {i}/{total}…")
    prog.empty()
    return enriched, None


# ===========================================================================
# Tiers non connectés : écran de login plein écran
# ===========================================================================
if _is_tiers and not _logged_in:
    st.subheader("🔑 Connexion Evoliz")
    st.caption("Saisissez vos clés API Evoliz (multi-société) pour accéder à l'annuaire.")
    st.caption("🛡️ Aucune clé n'est sauvegardée. Effacées de la mémoire dès le token obtenu.")
    _saved = _access_data.get("tokens", {}).get(_url_token, {})
    col_pk, col_sk = st.columns(2)
    pk = col_pk.text_input("Public Key", value=_saved.get("pk", ""), key="tiers_pk")
    sk = col_sk.text_input("Secret Key", type="password", value=_saved.get("sk", ""), key="tiers_sk")
    if st.button("🔗 CONNECTER", type="primary", use_container_width=True, key="btn_login_tiers"):
        if pk and sk:
            with st.spinner("Connexion..."):
                if do_login(pk, sk):
                    st.rerun()
        else:
            st.warning("Saisissez la Public Key et la Secret Key.")
    st.stop()


# ===========================================================================
# Sidebar : administration (admin uniquement) + recap session
# ===========================================================================
with st.sidebar:
    if _is_admin:
        with st.expander("🔒 Administration des accès", expanded=False):
            _ad = ea.load_access()
            _admin_hash = _ad.get("admin_hash", "")

            if not _admin_hash:
                st.warning("⚠️ Aucun mot de passe admin défini.")
                _new_pw = st.text_input("Définir le mot de passe", type="password", key="admin_pw_init")
                if st.button("✅ Enregistrer", key="btn_save_pw_init") and _new_pw:
                    _ad["admin_hash"] = ea.hash_pw(_new_pw)
                    ea.save_access(_ad)
                    st.success("Mot de passe admin enregistré.")
                    st.rerun()
            else:
                if not st.session_state.get("_admin_auth"):
                    _pw = st.text_input("🔑 Mot de passe admin", type="password", key="admin_pw_check")
                    if st.button("Déverrouiller", key="btn_unlock_admin") and _pw:
                        if ea.hash_pw(_pw) == _admin_hash:
                            st.session_state["_admin_auth"] = True
                            st.rerun()
                        else:
                            st.error("Mot de passe incorrect.")
                else:
                    st.success("🔓 Admin déverrouillé")
                    st.divider()

                    _saved_base = _ad.get("base_url", "")
                    _base = st.text_input("🌐 URL de base", value=_saved_base,
                                          placeholder="https://votre-app.streamlit.app",
                                          key="admin_base_url",
                                          help="URL de l'app. Utilisée pour construire les liens par tiers.")
                    if _base != _saved_base and _base:
                        _ad["base_url"] = _base.rstrip("/")
                        ea.save_access(_ad)
                    _base_eff = _base.rstrip("/") if _base else ""

                    st.divider()

                    _tokens = _ad.get("tokens", {})
                    st.markdown(f"**📋 {len(_tokens)} accès**")
                    for _tk, _info in sorted(_tokens.items(), key=lambda x: x[1].get("label", "")):
                        _status = _info.get("status", "active")
                        _icon = {"active": "🟢", "suspended": "🟡"}.get(_status, "🔴")
                        _has_keys = " 🔑" if _info.get("pk") else ""
                        st.markdown(f"{_icon} **{_info.get('label', '?')}**{_has_keys}")
                        _url = f"{_base_eff}/?token={_tk}" if _base_eff else f"⚠️ URL de base manquante — ?token={_tk}"
                        st.text_input("URL", value=_url, key=f"url_{_tk}",
                                      disabled=True, label_visibility="collapsed")
                        st.caption(f"Créé le {_info.get('created', '?')}")
                        c1, c2 = st.columns(2)
                        if _status == "active":
                            if c1.button("⏸️ Suspendre", key=f"susp_{_tk}", use_container_width=True):
                                _ad["tokens"][_tk]["status"] = "suspended"
                                ea.save_access(_ad)
                                st.rerun()
                        else:
                            if c1.button("▶️ Réactiver", key=f"act_{_tk}", use_container_width=True):
                                _ad["tokens"][_tk]["status"] = "active"
                                ea.save_access(_ad)
                                st.rerun()
                        if c2.button("🗑️ Révoquer", key=f"rev_{_tk}", use_container_width=True):
                            del _ad["tokens"][_tk]
                            ea.save_access(_ad)
                            st.rerun()
                        st.divider()

                    st.markdown("**➕ Nouvel accès**")
                    _new_label = st.text_input("Nom du tiers", key="new_label", placeholder="Ex: Cabinet XYZ")
                    _new_pk = st.text_input("Public Key (optionnel)", key="new_pk")
                    _new_sk = st.text_input("Secret Key (optionnel)", type="password", key="new_sk")
                    if st.button("✅ Créer l'accès", key="btn_new_access",
                                 type="primary", use_container_width=True) and _new_label:
                        _new_tok = _secrets.token_urlsafe(24)
                        _ad.setdefault("tokens", {})[_new_tok] = {
                            "label": _new_label,
                            "status": "active",
                            "created": dt_datetime.now().strftime("%Y-%m-%d %H:%M"),
                            "pk": _new_pk or "",
                            "sk": _new_sk or "",
                        }
                        ea.save_access(_ad)
                        st.rerun()

                    st.divider()
                    _has_pat = bool(ea.get_gist_token())
                    _gid = ea.get_gist_id()
                    if _has_pat and _gid:
                        st.caption(f"💾 Stockage : **GitHub Gist** — `{_gid[:10]}...`")
                    elif _has_pat:
                        st.caption("💾 Stockage : **GitHub Gist** (créé au prochain enregistrement)")
                    else:
                        st.caption("💾 Stockage : **fichier local** (perdu au redéploi Cloud)")
                        with st.popover("☁️ Activer la persistance Cloud"):
                            st.markdown("""
**1.** Créer un [GitHub Personal Access Token](https://github.com/settings/tokens) (**classic**) avec scope **`gist`**

**2.** Dans Streamlit Cloud → **Settings → Secrets** :
```toml
GITHUB_GIST_TOKEN = "ghp_votre_token_ici"
```

**3.** Redémarrer l'app — le gist sera créé au prochain enregistrement.
""")
                    _last = st.session_state.get("_last_gist_save")
                    if _last and not _last.get("ok") and _last.get("err"):
                        st.error(f"⚠️ Dernier save Gist en échec : {_last['err']}")

                    st.divider()
                    with st.popover("🔧 Changer le mot de passe"):
                        _new_pw2 = st.text_input("Nouveau mot de passe", type="password", key="admin_pw_change")
                        if st.button("Enregistrer", key="btn_change_pw") and _new_pw2:
                            _ad["admin_hash"] = ea.hash_pw(_new_pw2)
                            ea.save_access(_ad)
                            st.success("Mot de passe modifié.")
        st.divider()

    # Recap session (visible admin ET tiers)
    if _logged_in:
        _mode = st.session_state.get("_key_mode")
        if _mode == "multi":
            st.success("🔑 Clé multi-société")
        else:
            st.warning("🔑 Clé non multi-société")
        _n = len(st.session_state.get("_companies_cache") or [])
        if _n:
            st.caption(f"📂 {_n} dossier(s) chargé(s)")
        if st.button("🔌 Se déconnecter", key="btn_sb_logout", use_container_width=True):
            do_logout()
            st.rerun()


# ===========================================================================
# Onglets
# ===========================================================================
tab_api, tab_dir = st.tabs(["🔑 Connexion API", "🏢 Liste des sociétés"])


# --------- Onglet 1 : Connexion API ----------
with tab_api:
    if not _logged_in:
        st.subheader("🔑 Connexion Evoliz")
        st.caption("Saisissez vos clés API Evoliz **multi-société** (scope prescriber_users).")
        col_pk, col_sk = st.columns(2)
        pk_in = col_pk.text_input("Public Key", key="api_pk")
        sk_in = col_sk.text_input("Secret Key", type="password", key="api_sk")
        if st.button("🔗 CONNECTER", type="primary", use_container_width=True, key="btn_api_login"):
            if pk_in and sk_in:
                with st.spinner("Connexion..."):
                    if do_login(pk_in, sk_in):
                        st.rerun()
            else:
                st.warning("Saisissez la Public Key et la Secret Key.")
    else:
        st.success("✅ Connecté à Evoliz.")
        _scopes = st.session_state.get("_scopes", [])
        st.caption(f"Scopes : `{', '.join(_scopes) if _scopes else '—'}`")
        if st.session_state.get("_key_mode") != "multi":
            st.warning(
                "⚠️ Cette clé n'expose pas le scope `prescriber_users`. L'annuaire "
                "multi-société peut être vide ou inaccessible. Utilisez une clé "
                "multi-société pour de meilleurs résultats."
            )
        if st.button("🔌 Se déconnecter", key="btn_api_logout"):
            do_logout()
            st.rerun()


# --------- Onglet 2 : Annuaire ----------
with tab_dir:
    if not _logged_in:
        st.info("🔑 Connectez-vous d'abord dans l'onglet **Connexion API**.")
    else:
        col_a, col_b = st.columns([1, 2])
        with col_a:
            _with_detail = st.checkbox(
                "Détail complet par dossier",
                value=False,
                help="Appelle /companies/{id} pour chaque dossier (plus lent, ~0,65 s/dossier). "
                     "Généralement inutile : la liste renvoie déjà tous les champs.",
            )
        with col_b:
            if st.button("🔄 Charger / rafraîchir la liste", type="primary", key="btn_load_dir"):
                with st.spinner("Récupération des sociétés…"):
                    comps, err = fetch_companies(_with_detail)
                if err:
                    st.error(f"Erreur de récupération : {err}")
                st.session_state["_companies_cache"] = comps or []

        _companies = st.session_state.get("_companies_cache")
        if _companies is None:
            st.info("Cliquez sur **Charger / rafraîchir la liste** pour afficher les sociétés.")
        elif not _companies:
            st.warning("Aucune société visible avec cette clé API.")
        else:
            df = build_dataframe(_companies)

            # --- Filtres ---
            st.markdown(f"**{len(df)} société(s)**")
            fcol1, fcol2, fcol3 = st.columns([2, 1, 1])
            _search = fcol1.text_input("🔎 Rechercher (nom, code, ville…)", key="dir_search")

            # Filtre par site si la colonne existe
            _site_col = COLUMN_LABELS["home_site.home_site"]
            if _site_col in df.columns:
                _sites = sorted({str(v) for v in df[_site_col].dropna() if str(v).strip()})
                _site_sel = fcol2.selectbox("Site", ["— Tous —"] + _sites, key="dir_site")
            else:
                _site_sel = "— Tous —"

            _mode_col = COLUMN_LABELS["mode"]
            if _mode_col in df.columns:
                _modes = sorted({str(v) for v in df[_mode_col].dropna() if str(v).strip()})
                _mode_sel = fcol3.selectbox("Mode", ["— Tous —"] + _modes, key="dir_mode")
            else:
                _mode_sel = "— Tous —"

            view = df
            if _search:
                _s = _search.lower()
                mask = view.apply(
                    lambda r: _s in " ".join(str(x) for x in r.values).lower(), axis=1)
                view = view[mask]
            if _site_sel != "— Tous —" and _site_col in view.columns:
                view = view[view[_site_col].astype(str) == _site_sel]
            if _mode_sel != "— Tous —" and _mode_col in view.columns:
                view = view[view[_mode_col].astype(str) == _mode_sel]

            st.caption(f"{len(view)} affichée(s) · {len(df.columns)} colonnes")
            st.dataframe(view, use_container_width=True, hide_index=True)

            # --- Exports ---
            exp1, exp2 = st.columns(2)
            _csv = view.to_csv(index=False).encode("utf-8-sig")
            exp1.download_button("⬇️ Export CSV", _csv,
                                 file_name="liste_societes_plateforme.csv",
                                 mime="text/csv", use_container_width=True)
            try:
                _xlsx = to_excel_bytes(view)
                exp2.download_button("⬇️ Export Excel", _xlsx,
                                     file_name="liste_societes_plateforme.xlsx",
                                     mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                     use_container_width=True)
            except Exception:
                exp2.caption("Export Excel indisponible (openpyxl manquant).")
