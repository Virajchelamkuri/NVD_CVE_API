from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from pathlib import Path

# ---------- DB CONFIG ----------
DB_CONFIG = {
    "dbname": "neondb",
    "user": "neondb_owner",
    "password": "npg_C0rMuPzQB5qd",
    "host": "ep-round-voice-a1cdpuk5-pooler.ap-southeast-1.aws.neon.tech",
    "port": "5432",
    "sslmode": "require"
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def query_db(sql, params=None, fetch_one=False):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(sql, params or {})
    result = cur.fetchone() if fetch_one else cur.fetchall()
    cur.close()
    conn.close()
    return result

# ---------- FastAPI ----------
app = FastAPI(title="NVD CVE Dashboard")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- CVE LIST ----------
@app.get("/cves/list")
def list_cves(
    page: int = 1,
    results_per_page: int = 10,
    sort_by: str = "published_date",
    sort_order: str = "desc",
    year: int = None,
    min_score_v3: float = None,
    min_score_v2: float = None,
    last_n_days: int = None,
    cve_id: str = None
):
    offset = (page - 1) * results_per_page
    conditions = []
    params = {}

    if year: conditions.append("EXTRACT(YEAR FROM published_date) = %(year)s"); params["year"] = year
    if min_score_v3 is not None: conditions.append("base_score_v3 >= %(min_score_v3)s"); params["min_score_v3"] = min_score_v3
    if min_score_v2 is not None: conditions.append("base_score_v2 >= %(min_score_v2)s"); params["min_score_v2"] = min_score_v2
    if last_n_days: dt = datetime.utcnow() - timedelta(days=last_n_days); conditions.append("last_modified >= %(since)s"); params["since"] = dt
    if cve_id: conditions.append("cve_id ILIKE %(cve_id)s"); params["cve_id"] = f"%{cve_id}%"

    where_clause = " AND ".join(conditions) if conditions else "TRUE"

    if sort_by not in ["published_date", "last_modified"]:
        sort_by = "published_date"
    if sort_order.lower() not in ["asc", "desc"]:
        sort_order = "desc"

    sql = f"""
        SELECT cve_id, EXTRACT(YEAR FROM published_date) AS year, published_date, last_modified,
               base_score_v3, base_score_v2, description, raw_json
        FROM cves
        WHERE {where_clause}
        ORDER BY {sort_by} {sort_order.upper()}
        LIMIT %(limit)s OFFSET %(offset)s
    """
    params.update({"limit": results_per_page, "offset": offset})
    cves = query_db(sql, params)
    total = query_db(f"SELECT COUNT(*) as total FROM cves WHERE {where_clause}", params, fetch_one=True)["total"]
    return {"page": page, "results_per_page": results_per_page, "total_records": total, "cves": cves}

# ---------- CVE DETAIL ----------
@app.get("/cves/{cve_id}")
def get_cve(cve_id: str):
    sql = "SELECT * FROM cves WHERE cve_id=%(cve_id)s"
    cve = query_db(sql, {"cve_id": cve_id}, fetch_one=True)
    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")
    return cve

# ---------- Serve Frontend ----------
FRONTEND_DIR = Path(__file__).parent / "frontend"

@app.get("/", include_in_schema=False)
def serve_index():
    return FileResponse(FRONTEND_DIR / "index.html")

@app.get("/detail.html", include_in_schema=False)
def serve_detail():
    return FileResponse(FRONTEND_DIR / "detail.html")

# ---------- Run ----------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
