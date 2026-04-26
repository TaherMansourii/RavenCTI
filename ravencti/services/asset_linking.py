from ravencti.db.connection import get_db


# =========================
# LOAD ASSETS (clients + products)
# =========================
def load_assets():
    with get_db() as db:
        rows = db.execute("""
            SELECT 
                id, 
                company_name AS name, 
                'client' AS type, 
                criticality,
                country_code
            FROM clients

            UNION ALL

            SELECT 
                id, 
                product_name AS name, 
                'product' AS type, 
                criticality,
                vendor
            FROM products
        """).fetchall()

    return [dict(r) for r in rows]


# =========================
# MATCH ASSETS TO INCIDENT
# =========================
def match_assets_to_incident(incident, assets):
    # 🔥 MUCH stronger context
    searchable_text = " ".join([
        str(incident.get("indicator", "")),
        str(incident.get("title", "")),
        str(incident.get("description", "")),
        str(incident.get("raw_content", "")),
        str(incident.get("url", "")),
    ]).lower()

    matches = []

    for asset in assets:
        name = (asset.get("name") or "").lower()

        if name and name in searchable_text:
            matches.append(asset)
            continue

        vendor = (asset.get("vendor") or "").lower()
        if vendor and vendor in searchable_text:
            matches.append(asset)
            continue

        country = (asset.get("country_code") or "").lower()
        if country and country in searchable_text:
            matches.append(asset)
            continue

    return matches