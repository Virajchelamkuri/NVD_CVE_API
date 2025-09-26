# main.py
import os
import json
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor

# ---------- Config ----------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # When running locally you can set a .env or export DATABASE_URL
    raise RuntimeError("DATABASE_URL environment variable not set. Set it before starting the app.")

# ---------- FastAPI ----------
app = FastAPI(title="NVD CVE Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for production
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend from ./frontend folder (repo root)
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")
if not os.path.exists(FRONTEND_DIR):
    raise RuntimeError(f"Frontend directory not found at {FRONTEND_DIR}")
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

# ---------- DB helpers ----------
def get_connection():
    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)

def build_where_clause(
    year: Optional[int],
    min_score_v3: Optional[float],
    min_score_v2: Optional[float],
    last_n_days: Optional[int],
    cve_id: Optional[str],
):
    conditions = ["TRUE"]
    params: List = []
    if year:
        conditions.append("EXTRACT(YEAR FROM published_date) = %s")
        params.append(year)
    if min_score_v3 is not None:
        conditions.append("base_score_v3 >= %s")
        params.append(min_score_v3)
    if min_score_v2 is not None:
        conditions.append("base_score_v2 >= %s")
        params.append(min_score_v2)
    if last_n_days:
        conditions.append("last_modified >= NOW() - INTERVAL '%s days'")
        params.append(last_n_days)
    if cve_id:
        conditions.append("cve_id ILIKE %s")
        params.append(f"%{cve_id}%")
    where_clause = " AND ".join(conditions)
    return where_clause, params

# ---------- API Endpoints ----------

@app.get("/cves/list")
def list_cves(
    page: int = Query(1, ge=1),
    results_per_page: int = Query(10, ge=1, le=100),
    sort_by: str = Query("published_date"),
    sort_order: str = Query("desc"),
    year: Optional[int] = None,
    min_score_v3: Optional[float] = None,
    min_score_v2: Optional[float] = None,
    last_n_days: Optional[int] = None,
    cve_id: Optional[str] = None,
):
    """
    Returns paginated CVE list with filters:
    - year, min_score_v3, min_score_v2, last_n_days, cve_id
    - server-side sorting (published_date or last_modified)
    """
    if sort_by not in ("published_date", "last_modified"):
        sort_by = "published_date"
    if sort_order.lower() not in ("asc", "desc"):
        sort_order = "desc"

    offset = (page - 1) * results_per_page

    where_clause, params = build_where_clause(year, min_score_v3, min_score_v2, last_n_days, cve_id)

    # Data query
    sql = f"""
        SELECT cve_id,
               EXTRACT(YEAR FROM published_date) AS year,
               published_date,
               last_modified,
               base_score_v3,
               base_score_v2,
               description
        FROM cves
        WHERE {where_clause}
        ORDER BY {sort_by} {sort_order.upper()}
        LIMIT %s OFFSET %s
    """
    params_for_query = params + [results_per_page, offset]

    # Count query (same where clause)
    count_sql = f"SELECT COUNT(*) AS total FROM cves WHERE {where_clause}"

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, params_for_query)
        rows = cur.fetchall()
        # convert rows (list of tuples) to list of dicts with keys - use RealDictCursor for convenience instead
        # But simpler: re-run with RealDictCursor
        cur.close()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, params_for_query)
        data = cur.fetchall()

        cur.execute(count_sql, params)
        total = cur.fetchone()["total"]
    finally:
        conn.close()

    return {
        "page": page,
        "results_per_page": results_per_page,
        "total_records": total,
        "cves": data,
    }

@app.get("/cves/{cve_id}")
def get_cve(cve_id: str):
    """
    Returns parsed CVE details (no raw JSON). Extracts CVSSv2/v3 metrics, impacts, references and CPEs.
    """
    sql = "SELECT cve_id, published_date, last_modified, base_score_v3, base_score_v2, description, raw_json FROM cves WHERE cve_id = %s"
    conn = get_connection()
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(sql, (cve_id,))
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="CVE not found")

    # raw_json is a dict (we stored it as JSONB). Extract useful fields
    raw = row.get("raw_json") or {}
    metrics = raw.get("metrics", {}) if isinstance(raw, dict) else {}

    # CVSS v2
    cvss_v2 = {}
    try:
        v2_list = metrics.get("cvssMetricV2") or metrics.get("cvssMetricV2", [])
        if v2_list and isinstance(v2_list, list) and len(v2_list) > 0:
            v2 = v2_list[0].get("cvssData", {})
            # fields expected from NVD v2 cvssData
            cvss_v2 = {
                "baseScore": v2.get("baseScore"),
                "vectorString": v2.get("vectorString"),
                "accessVector": v2.get("accessVector"),
                "accessComplexity": v2.get("accessComplexity"),
                "authentication": v2.get("authentication"),
                "confidentialityImpact": v2.get("confidentialityImpact"),
                "integrityImpact": v2.get("integrityImpact"),
                "availabilityImpact": v2.get("availabilityImpact"),
                "exploitabilityScore": v2.get("exploitabilityScore"),
                "impactScore": v2.get("impactScore"),
            }
    except Exception:
        cvss_v2 = {}

    # CVSS v3 (if present)
    cvss_v3 = {}
    try:
        v3_list = metrics.get("cvssMetricV3") or []
        if v3_list and isinstance(v3_list, list) and len(v3_list) > 0:
            v3 = v3_list[0].get("cvssData", {})
            cvss_v3 = {
                "baseScore": v3.get("baseScore"),
                "vectorString": v3.get("vectorString"),
                "attackVector": v3.get("attackVector"),
                "attackComplexity": v3.get("attackComplexity"),
                "privilegesRequired": v3.get("privilegesRequired"),
                "userInteraction": v3.get("userInteraction"),
                "scope": v3.get("scope"),
                "confidentialityImpact": v3.get("confidentialityImpact"),
                "integrityImpact": v3.get("integrityImpact"),
                "availabilityImpact": v3.get("availabilityImpact"),
            }
    except Exception:
        cvss_v3 = {}

    # References
    references = []
    try:
        ref_list = raw.get("references", {}).get("reference_data", [])
        for r in (ref_list or []):
            references.append({"url": r.get("url"), "name": r.get("name")})
    except Exception:
        references = []

    # Vulnerable products (CPEs) - parse configurations.nodes.*.cpe_match
    products = []
    try:
        nodes = raw.get("configurations", {}).get("nodes", []) or []
        for node in nodes:
            # cpe_match could be under node or node.children etc. flatten a bit:
            for match in (node.get("cpe_match") or []):
                criteria = match.get("cpe23Uri")
                match_id = match.get("matchCriteriaId")
                vulnerable = match.get("vulnerable", False)
                if criteria:
                    products.append({"criteria": criteria, "matchCriteriaId": match_id, "vulnerable": vulnerable})
            # some nodes have children with cpe_match too
            for child in (node.get("children") or []):
                for match in (child.get("cpe_match") or []):
                    criteria = match.get("cpe23Uri")
                    match_id = match.get("matchCriteriaId")
                    vulnerable = match.get("vulnerable", False)
                    if criteria:
                        products.append({"criteria": criteria, "matchCriteriaId": match_id, "vulnerable": vulnerable})
    except Exception:
        products = []

    # Build response (important user-facing fields only)
    resp = {
        "cve_id": row.get("cve_id"),
        "description": row.get("description"),
        "published_date": row.get("published_date"),
        "last_modified": row.get("last_modified"),
        "base_score_v2": row.get("base_score_v2"),
        "base_score_v3": row.get("base_score_v3"),
        "cvss_v2": cvss_v2,
        "cvss_v3": cvss_v3,
        "references": references,
        "products": products
    }
    return resp
