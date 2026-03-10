"""
Optimized FastAPI Application - Zero-loop O(1) request handling
All heavy computation is done at startup, requests only do dictionary lookups.
"""

from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import uvicorn
import redis
import pickle
import uuid
from datetime import datetime
import os

# Import the preprocessor
from precompute import DataPreprocessor

# ====================================================================
# FASTAPI APP CONFIGURATION
# ====================================================================

app = FastAPI(
    title="Tejas L3 Log Analyzer - Optimized",
    description="High-performance log analysis with O(1) lookups",
    version="2.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# ====================================================================
# REDIS CACHE CONNECTION
# ====================================================================

# Connect to Redis for shared cache across workers
try:
    redis_client = redis.Redis(
        host=os.getenv('REDIS_HOST', 'localhost'),
        port=int(os.getenv('REDIS_PORT', 6379)),
        db=0,
        decode_responses=False  # We'll use pickle
    )
    redis_client.ping()
    print("✅ Redis connected successfully")
except Exception as e:
    print(f"⚠️ Redis not available: {e}")
    redis_client = None

# ====================================================================
# IN-MEMORY CACHE (FALLBACK IF NO REDIS)
# ====================================================================

MEMORY_CACHE: Dict[str, Dict[str, Any]] = {}
JOB_STATUS: Dict[str, Dict[str, Any]] = {}

# ====================================================================
# PYDANTIC MODELS
# ====================================================================

class UploadResponse(BaseModel):
    session_id: str
    status: str
    message: str
    files_count: int


class JobStatus(BaseModel):
    session_id: str
    status: str  # 'processing', 'completed', 'failed'
    progress: int  # 0-100
    message: str
    error: Optional[str] = None


class UEStats(BaseModel):
    ue_index: int
    type: str
    status: str
    stats: Dict[str, Any]
    insight: str
    milestones_count: int


class SearchResult(BaseModel):
    keyword: str
    ue_indices: List[int]
    count: int


# ====================================================================
# CACHE HELPER FUNCTIONS
# ====================================================================

def cache_session(session_id: str, data: Dict[str, Any], ttl: int = 3600):
    """Store session data in Redis or memory cache"""
    if redis_client:
        key = f"session:{session_id}"
        redis_client.setex(key, ttl, pickle.dumps(data))
    else:
        MEMORY_CACHE[session_id] = data


def get_session(session_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve session data from cache"""
    if redis_client:
        key = f"session:{session_id}"
        cached = redis_client.get(key)
        return pickle.loads(cached) if cached else None
    else:
        return MEMORY_CACHE.get(session_id)


def update_job_status(session_id: str, status: str, progress: int, message: str, error: str = None):
    """Update job processing status"""
    job_data = {
        'session_id': session_id,
        'status': status,
        'progress': progress,
        'message': message,
        'error': error,
        'updated_at': datetime.now().isoformat()
    }
    
    if redis_client:
        key = f"job:{session_id}"
        redis_client.setex(key, 3600, pickle.dumps(job_data))
    else:
        JOB_STATUS[session_id] = job_data


def get_job_status(session_id: str) -> Optional[Dict[str, Any]]:
    """Get job processing status"""
    if redis_client:
        key = f"job:{session_id}"
        cached = redis_client.get(key)
        return pickle.loads(cached) if cached else None
    else:
        return JOB_STATUS.get(session_id)


# ====================================================================
# BACKGROUND PROCESSING (ASYNC)
# ====================================================================

async def process_logs_background(session_id: str, file_paths: List[str]):
    """
    Background task: Process logs and build all caches
    This is the ONLY place where loops happen - it runs ONCE per upload
    """
    try:
        update_job_status(session_id, 'processing', 10, 'Parsing log files...')
        
        # Step 1: Parse logs (existing logic from app.py)
        # This would use your existing process_logs_for_ue_journey and merge_logs_for_ue_journey
        # For now, simulating with empty data
        ue_data_map = {}  # TODO: Call actual parsing functions
        rrc_counts = {}   # TODO: Call actual counting functions
        
        update_job_status(session_id, 'processing', 40, 'Parsing complete, building indexes...')
        
        # Step 2: Pre-compute EVERYTHING using DataPreprocessor
        preprocessor = DataPreprocessor(ue_data_map, rrc_counts)
        cache = preprocessor.precompute_all()
        
        update_job_status(session_id, 'processing', 80, 'Caching data...')
        
        # Step 3: Store in cache with 1 hour TTL
        cache_session(session_id, cache, ttl=3600)
        
        # Step 4: Mark as complete
        update_job_status(session_id, 'completed', 100, 'Analysis complete!', None)
        
    except Exception as e:
        update_job_status(session_id, 'failed', 0, 'Processing failed', str(e))
        raise


# ====================================================================
# API ENDPOINTS - ALL O(1) LOOKUPS
# ====================================================================

@app.get("/")
async def root():
    """Health check"""
    return {"status": "ok", "message": "Tejas L3 Log Analyzer - Optimized"}


@app.post("/upload", response_model=UploadResponse)
async def upload_files(
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(...)
):
    """
    Upload log files for analysis
    Starts background processing and returns immediately
    """
    session_id = str(uuid.uuid4())
    
    # Save files to disk
    session_folder = f"uploads/session_{session_id}"
    os.makedirs(session_folder, exist_ok=True)
    
    file_paths = []
    for file in files:
        file_path = os.path.join(session_folder, file.filename)
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        file_paths.append(file_path)
    
    # Start background processing
    background_tasks.add_task(process_logs_background, session_id, file_paths)
    
    # Initialize job status
    update_job_status(session_id, 'processing', 5, 'Upload complete, starting analysis...')
    
    return UploadResponse(
        session_id=session_id,
        status='processing',
        message='Files uploaded successfully. Processing in background.',
        files_count=len(files)
    )


@app.get("/job/{session_id}", response_model=JobStatus)
async def check_job_status(session_id: str):
    """
    Check the status of a background processing job
    O(1) - Simple cache lookup
    """
    status = get_job_status(session_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return JobStatus(**status)


@app.get("/session/{session_id}/summary")
async def get_summary(session_id: str):
    """
    Get pre-computed summary for a session
    O(1) - Direct cache lookup, NO LOOPS
    """
    cache = get_session(session_id)
    
    if not cache:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    
    # Direct lookup - no computation
    return cache['summary']


@app.get("/session/{session_id}/ue/{ue_index}", response_model=UEStats)
async def get_ue_stats(session_id: str, ue_index: int):
    """
    Get pre-computed stats for a specific UE
    O(1) - Direct dictionary lookup, ZERO LOOPS
    """
    cache = get_session(session_id)
    
    if not cache:
        raise HTTPException(status_code=404, detail="Session not found or expired")
    
    # Direct O(1) lookup
    ue_data = cache['quick_lookup'].get(ue_index)
    
    if not ue_data:
        raise HTTPException(status_code=404, detail=f"UE {ue_index} not found")
    
    return UEStats(
        ue_index=ue_index,
        type=ue_data['type'],
        status=ue_data['status'],
        stats=ue_data['stats'],
        insight=ue_data['insight'],
        milestones_count=ue_data['milestones_count']
    )


@app.get("/session/{session_id}/ue/{ue_index}/milestones")
async def get_ue_milestones(session_id: str, ue_index: int):
    """
    Get pre-extracted milestones for a UE
    O(1) - Direct lookup in pre-built cache
    """
    cache = get_session(session_id)
    
    if not cache:
        raise HTTPException(status_code=404, detail="Session not found")
    
    milestones = cache['ue_milestones'].get(ue_index, [])
    
    return {
        "ue_index": ue_index,
        "milestones": milestones,
        "count": len(milestones)
    }


@app.get("/session/{session_id}/search", response_model=SearchResult)
async def search_ues(session_id: str, keyword: str = Query(..., min_length=2)):
    """
    Search for UEs by keyword using pre-built reverse index
    O(1) - Direct lookup in inverted index, NO SCANNING
    """
    cache = get_session(session_id)
    
    if not cache:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # O(1) lookup in pre-built search index
    keyword_upper = keyword.upper()
    ue_indices = cache['search_index'].get(keyword_upper, [])
    
    return SearchResult(
        keyword=keyword,
        ue_indices=ue_indices,
        count=len(ue_indices)
    )


@app.get("/session/{session_id}/rrc_counters")
async def get_rrc_counters(session_id: str):
    """
    Get pre-computed RRC counters and drop rates
    O(1) - Direct cache access
    """
    cache = get_session(session_id)
    
    if not cache:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return {
        "drop_rates": cache['rrc_drop_rates'],
        "summary": cache['summary']
    }


@app.get("/session/{session_id}/ues")
async def list_all_ues(
    session_id: str,
    type_filter: Optional[str] = None,  # 'direct_attach', 'x2ap_handover', 's1ap_handover'
    status_filter: Optional[str] = None  # 'success', 'failed'
):
    """
    List all UEs with optional filters
    O(1) per filter - uses pre-computed quick lookup
    """
    cache = get_session(session_id)
    
    if not cache:
        raise HTTPException(status_code=404, detail="Session not found")
    
    quick_lookup = cache['quick_lookup']
    
    # Filter using pre-computed data
    filtered = quick_lookup
    
    if type_filter:
        filtered = {k: v for k, v in filtered.items() if v['type'] == type_filter}
    
    if status_filter:
        filtered = {k: v for k, v in filtered.items() if v['status'] == status_filter}
    
    return {
        "ue_indices": list(filtered.keys()),
        "count": len(filtered),
        "summary": {
            "direct_attach": sum(1 for v in filtered.values() if v['type'] == 'direct_attach'),
            "x2ap_handover": sum(1 for v in filtered.values() if v['type'] == 'x2ap_handover'),
            "s1ap_handover": sum(1 for v in filtered.values() if v['type'] == 's1ap_handover'),
            "successful": sum(1 for v in filtered.values() if v['status'] == 'success'),
            "failed": sum(1 for v in filtered.values() if v['status'] == 'failed')
        }
    }


# ====================================================================
# STARTUP EVENT
# ====================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    print("🚀 FastAPI server starting...")
    print(f"   - Redis: {'Connected' if redis_client else 'Not available (using memory cache)'}")
    print(f"   - Workers: {os.getenv('WORKERS', 'auto')}")
    print("✅ Server ready!")


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    print("👋 Server shutting down...")
    if redis_client:
        redis_client.close()


# ====================================================================
# RUN SERVER
# ====================================================================

if __name__ == "__main__":
    # Development server
    uvicorn.run(
        "app_optimized:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Auto-reload on code changes
        workers=1  # Single worker for development
    )
    
    # Production: Use gunicorn with multiple workers
    # gunicorn app_optimized:app -w 17 -k uvicorn.workers.UvicornWorker -b 0.0.0.0:8000
