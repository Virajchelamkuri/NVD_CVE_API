import os
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Optional

app = FastAPI(title="CVE Dashboard")

# Enable CORS if frontend is served separately
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Or specify your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")

# Connect to Neon DB using environment variable
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not set!")

conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
cur = conn.cursor()

# ==============================
# API Endpoints
# ==============================

@app.get("/cves/list")
def list_cves(year: Optional[int] = None, score_min: Optional[float] = None, last_modified_days: Optional[int] = None, limit: int = 10, offset: int = 0):
    try:
        query = "SELECT cve_id, published_date, last_modified, base_score_v3, base_score_v2, description FROM cves WHERE TRUE"
        params = []

        if year:
            query += " AND EXTRACT(YEAR FROM published_date) = %s"
            params.append(year)

        if score_min:
            query += " AND (COALESCE(base_score_v3,0) >= %s OR COALESCE(base_score_v2,0) >= %s)"
            params.extend([score_min, score_min])

        if last_modified_days:
            query += " AND last_modified >= NOW() - INTERVAL '%s days'"
            params.append(last_modified_days)

        query += " ORDER BY published_date DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, params)
        rows = cur.fetchall()

        # Total count
        cur.execute("SELECT COUNT(*) FROM cves")
        total_count = cur.fetchone()["count"]

        return {"total_records": total_count, "cves": rows}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/cves/{cve_id}")
def get_cve_detail(cve_id: str):
    try:
        query = """
        SELECT cve_id, published_date, last_modified, base_score_v3, base_score_v2, description
        FROM cves
        WHERE cve_id = %s
        """
        cur.execute(query, (cve_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="CVE not found")
        return row
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
