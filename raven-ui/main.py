from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import datetime

app = FastAPI()

# Set up templates and static files
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Sample scan history
scans = [
    {"target": "example.com", "type": "API", "timestamp": "2025-03-14 12:30", "vulnerabilities": ["SQLi", "XSS"]},
    {"target": "testsite.com", "type": "Web", "timestamp": "2025-03-13 15:45", "vulnerabilities": ["CSRF"]}
]

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Render the main dashboard with scan history and summary."""
    high = sum(1 for scan in scans if len(scan["vulnerabilities"]) >= 2)
    medium = sum(1 for scan in scans if len(scan["vulnerabilities"]) == 1)
    low = max(0, len(scans) - high - medium)

    return templates.TemplateResponse("index.html", {
        "request": request,
        "scan_history": scans,
        "summary": {"high": high, "medium": medium, "low": low}
    })

@app.get("/api/scans")
async def get_scans():
    """API to fetch scan history."""
    return {"history": scans}

@app.post("/api/scan")
async def start_scan(target: str, scan_type: str):
    """Simulate a scan and add it to history."""
    new_scan = {
        "target": target,
        "type": scan_type,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "vulnerabilities": ["LFI"] if scan_type == "Web" else ["Broken Auth"]
    }
    scans.append(new_scan)
    return {"message": "Scan started", "scan": new_scan}
