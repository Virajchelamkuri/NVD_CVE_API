import os
import psycopg2
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# ✅ FastAPI app
app = FastAPI()

# ✅ Database connection (Render env var)
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not found in environment variables")

# ✅ Connect to DB
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

# ✅ Mount frontend
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

# ✅ API endpoint to get CVEs
@app.get("/api/cves")
def get_cves():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, cve_id, description, severity, score FROM cves LIMIT 50;")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [{"id": r[0], "cve_id": r[1], "description": r[2], "severity": r[3], "score": r[4]} for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ✅ API endpoint to get CVE details by ID
@app.get("/api/cves/{cve_id}")
def get_cve_details(cve_id: str):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT cve_id, description, severity, score, exploitability_score, impact_score, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact
            FROM cves WHERE cve_id = %s
        """, (cve_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            raise HTTPException(status_code=404, detail="CVE not found")

        return {
            "cve_id": row[0],
            "description": row[1],
            "severity": row[2],
            "score": row[3],
            "exploitability_score": row[4],
            "impact_score": row[5],
            "access_vector": row[6],
            "access_complexity": row[7],
            "authentication": row[8],
            "confidentiality_impact": row[9],
            "integrity_impact": row[10],
            "availability_impact": row[11]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ✅ Serve index.html
@app.get("/")
def read_root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
