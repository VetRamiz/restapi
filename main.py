import os
import base64
import hmac
import hashlib
import logging
from datetime import datetime
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import asyncio

# --------------------------------------------------
# ENVIRONMENT
# --------------------------------------------------

load_dotenv()

ACUITY_USER_ID = os.getenv("ACUITY_USER_ID")
ACUITY_API_KEY = os.getenv("ACUITY_API_KEY")
ACUITY_WEBHOOK_SECRET = os.getenv("ACUITY_WEBHOOK_SECRET")

CASPIO_BASE_URL = os.getenv("CASPIO_BASE_URL")
CASPIO_CLIENT_ID = os.getenv("CASPIO_CLIENT_ID")
CASPIO_CLIENT_SECRET = os.getenv("CASPIO_CLIENT_SECRET")
CASPIO_TABLE = os.getenv("CASPIO_APPOINTMENTS_TABLE")

ACUITY_BASE = "https://acuityscheduling.com/api/v1"

# --------------------------------------------------
# LOGGING (PHI SAFE)
# --------------------------------------------------

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("acuity-proxy")

# --------------------------------------------------
# FASTAPI APP
# --------------------------------------------------

app = FastAPI(
    title="Acuity ↔ Caspio Proxy",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------
# GLOBAL STATE
# --------------------------------------------------

recent_webhooks = set()
_caspio_token_cache = {}

from pydantic import BaseModel
from typing import List, Optional

class BulkAvailabilityRequest(BaseModel):
    appointmentTypeID: int
    calendarIDs: List[int]
    date: str
    timezone: Optional[str] = "America/New_York"
# --------------------------------------------------
# AUTH HELPERS
# --------------------------------------------------

def acuity_headers():
    token = base64.b64encode(
        f"{ACUITY_USER_ID}:{ACUITY_API_KEY}".encode()
    ).decode()

    return {
        "Authorization": f"Basic {token}",
        "Content-Type": "application/json"
    }


async def get_caspio_token():

    now = datetime.utcnow().timestamp()

    if (
        _caspio_token_cache.get("token")
        and _caspio_token_cache.get("expires_at", 0) > now + 60
    ):
        return _caspio_token_cache["token"]

    async with httpx.AsyncClient(timeout=10) as client:

        resp = await client.post(
            f"{CASPIO_BASE_URL}/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": CASPIO_CLIENT_ID,
                "client_secret": CASPIO_CLIENT_SECRET
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    if resp.status_code != 200:
        log.error("Caspio token request failed")
        raise HTTPException(500, "Caspio authentication failed")

    data = resp.json()

    _caspio_token_cache["token"] = data["access_token"]
    _caspio_token_cache["expires_at"] = now + data.get("expires_in", 3600)

    return data["access_token"]


async def caspio_headers():

    token = await get_caspio_token()

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

# --------------------------------------------------
# SECURITY HELPERS
# --------------------------------------------------

def verify_acuity_signature(raw_body: bytes, signature: Optional[str]):

    if not signature:
        return False

    expected = hmac.new(
        ACUITY_WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, signature)

# --------------------------------------------------
# CASPIO SYNC HELPERS
# --------------------------------------------------

async def caspio_upsert_appointment(appointment: dict):

    apt_id = appointment.get("id")

    if not apt_id:
        return

    headers = await caspio_headers()

    record = {
        "AcuityID": apt_id,
        "FirstName": appointment.get("firstName", ""),
        "LastName": appointment.get("lastName", ""),
        "Email": appointment.get("email", ""),
        "AppointmentDate": appointment.get("date", ""),
        "AppointmentTime": appointment.get("time", ""),
        "CalendarName": appointment.get("calendar", ""),
        "Status": "Canceled" if appointment.get("canceled") else "Scheduled",
        "LastUpdated": datetime.utcnow().isoformat()
    }

    async with httpx.AsyncClient(timeout=15) as client:

        check = await client.get(
            f"{CASPIO_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
            headers=headers,
            params={
                "q.where": f"AcuityID={apt_id}",
                "q.limit": 1
            }
        )

        existing = check.json().get("Result", [])

        if existing:

            await client.put(
                f"{CASPIO_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                params={"q.where": f"AcuityID={apt_id}"},
                json=record
            )

        else:

            await client.post(
                f"{CASPIO_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                json=record
            )

    log.info(f"Appointment {apt_id} synced to Caspio")

# --------------------------------------------------
# HEALTH ENDPOINT
# --------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "time": datetime.utcnow()
    }

# --------------------------------------------------
# ROOT
# --------------------------------------------------

@app.get("/")
async def root():
    return {"service": "acuity-caspio-proxy", "status": "running"}

# --------------------------------------------------
# ACUITY ENDPOINTS
# --------------------------------------------------

@app.get("/appointment-types")
async def get_appointment_types():

    async with httpx.AsyncClient(timeout=10) as client:

        resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )

    if resp.status_code != 200:
        raise HTTPException(500, "Unable to fetch appointment types")

    return resp.json()

# --------------------------------------------------
# BOOK APPOINTMENT
# --------------------------------------------------

@app.post("/appointments")
async def create_appointment(body: dict, background_tasks: BackgroundTasks):

    async with httpx.AsyncClient(timeout=15) as client:

        resp = await client.post(
            f"{ACUITY_BASE}/appointments",
            headers=acuity_headers(),
            json=body
        )

    if resp.status_code not in (200, 201):
        raise HTTPException(500, "Appointment creation failed")

    appointment = resp.json()

    background_tasks.add_task(caspio_upsert_appointment, appointment)

    return appointment

@app.post("/availability/bulk")
async def availability_bulk(body: BulkAvailabilityRequest):

    results = []

    async with httpx.AsyncClient(timeout=10) as client:

        tasks = []

        for calendar_id in body.calendarIDs:

            params = {
                "appointmentTypeID": body.appointmentTypeID,
                "calendarID": calendar_id,
                "date": body.date,
                "timezone": body.timezone
            }

            tasks.append(
                client.get(
                    f"{ACUITY_BASE}/availability/times",
                    headers=acuity_headers(),
                    params=params
                )
            )

        responses = await asyncio.gather(*tasks)

        for i, resp in enumerate(responses):

            if resp.status_code == 200:

                slots = resp.json()

                results.append({
                    "calendarID": body.calendarIDs[i],
                    "slots": slots
                })

            else:

                results.append({
                    "calendarID": body.calendarIDs[i],
                    "slots": [],
                    "error": "unable to fetch"
                })

    return {"results": results}
# --------------------------------------------------
# WEBHOOK (REPLACES ZAPIER)
# --------------------------------------------------

@app.post("/webhooks/acuity")
async def acuity_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_acuity_signature: Optional[str] = Header(None)
):

    raw_body = await request.body()

    if not verify_acuity_signature(raw_body, x_acuity_signature):
        raise HTTPException(401, "Invalid webhook signature")

    data = await request.json()

    action = data.get("action")
    apt_id = data.get("id")

    webhook_id = f"{action}_{apt_id}"

    if webhook_id in recent_webhooks:
        return {"status": "duplicate ignored"}

    recent_webhooks.add(webhook_id)

    if action in [
        "scheduling.scheduled",
        "scheduling.rescheduled",
        "scheduling.changed"
    ]:

        async with httpx.AsyncClient(timeout=10) as client:

            resp = await client.get(
                f"{ACUITY_BASE}/appointments/{apt_id}",
                headers=acuity_headers()
            )

        if resp.status_code == 200:
            background_tasks.add_task(
                caspio_upsert_appointment,
                resp.json()
            )

    log.info(f"Webhook processed: {action} {apt_id}")

    return {"status": "processed"}