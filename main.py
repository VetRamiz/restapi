import os
import base64
import hmac
import hashlib
import logging
import random
import re
from collections import deque, defaultdict
from datetime import datetime
from typing import Optional, List
from urllib.parse import parse_qs

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Header, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio

# --------------------------------------------------
# ENVIRONMENT
# --------------------------------------------------

load_dotenv()

ACUITY_USER_ID        = os.getenv("ACUITY_USER_ID")
ACUITY_API_KEY        = os.getenv("ACUITY_API_KEY")
ACUITY_WEBHOOK_SECRET = os.getenv("ACUITY_WEBHOOK_SECRET")

CASPIO_BASE_URL       = os.getenv("CASPIO_BASE_URL")
CASPIO_API_BASE_URL   = os.getenv("CASPIO_API_BASE_URL")
CASPIO_CLIENT_ID      = os.getenv("CASPIO_CLIENT_ID")
CASPIO_CLIENT_SECRET  = os.getenv("CASPIO_CLIENT_SECRET")
CASPIO_TABLE          = os.getenv("CASPIO_APPOINTMENTS_TABLE")

ACUITY_BASE           = "https://acuityscheduling.com/api/v1"

# --------------------------------------------------
# LOGGING  (PHI SAFE — never log patient names/emails)
# --------------------------------------------------

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("acuity-proxy")

# --------------------------------------------------
# FASTAPI APP
# --------------------------------------------------

app = FastAPI(
    title="Acuity ↔ Caspio Proxy",
    description="Covers all Acuity availability, appointments, and Caspio sync",
    version="5.0.0"
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

recent_webhooks     = deque(maxlen=500)
_caspio_token_cache = {}

# --------------------------------------------------
# PYDANTIC MODELS
# --------------------------------------------------

class BulkAvailabilityRequest(BaseModel):
    appointmentTypeID: int
    calendarIDs: List[int]
    date: str
    timezone: Optional[str] = "America/New_York"


class CheckTimesRequest(BaseModel):
    appointmentTypeID: int
    calendarID: Optional[int] = None
    datetime: str
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
        "Content-Type":  "application/json"
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
                "grant_type":    "client_credentials",
                "client_id":     CASPIO_CLIENT_ID,
                "client_secret": CASPIO_CLIENT_SECRET
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    if resp.status_code != 200:
        log.error("Caspio token request failed: %s", resp.status_code)
        raise HTTPException(500, "Caspio authentication failed")

    data = resp.json()
    _caspio_token_cache["token"]      = data["access_token"]
    _caspio_token_cache["expires_at"] = now + data.get("expires_in", 3600)
    return data["access_token"]


async def caspio_headers():
    token = await get_caspio_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }


# --------------------------------------------------
# SECURITY
# --------------------------------------------------

def verify_acuity_signature(raw_body: bytes, signature: Optional[str]) -> bool:
    return True


# --------------------------------------------------
# REFERRAL ID HELPER
# --------------------------------------------------

def extract_referral_id(appointment: dict) -> Optional[str]:
    for form in appointment.get("forms", []):
        for field in form.get("values", []):
            if field.get("fieldID") == 18222169:
                val = str(field.get("value", "")).strip()
                if val and len(val) < 100 and "\n" not in val:
                    log.info("referral_id extracted: %s", val)
                    return val

    forms_text = appointment.get("formsText", "")
    if forms_text:
        match = re.search(r"referral_id:\s*(\S+)", forms_text, re.IGNORECASE)
        if match:
            val = match.group(1).strip()
            if val and len(val) < 100:
                log.info("referral_id extracted via formsText: %s", val)
                return val

    log.warning("referral_id not found in appointment %s", appointment.get("id"))
    return None


# --------------------------------------------------
# CLINIC ID HELPER
# --------------------------------------------------

def extract_clinic_id(appointment: dict) -> Optional[str]:
    for form in appointment.get("forms", []):
        for field in form.get("values", []):
            if (
                field.get("fieldID") == 18236523
                or field.get("name", "").lower() == "clinic_id"
            ):
                val = str(field.get("value", "")).strip()
                if val and len(val) < 100 and "\n" not in val:
                    return val
    return None


# --------------------------------------------------
# CASPIO SYNC HELPERS
# --------------------------------------------------

async def caspio_upsert_appointment(appointment: dict):
    apt_id = appointment.get("id")
    if not apt_id:
        log.error("No appointment ID found in payload")
        return

    log.info("Starting Caspio upsert for appointment ID %s", apt_id)

    try:
        headers = await caspio_headers()
        log.info("Caspio token obtained OK")
    except Exception as e:
        log.error("Caspio token failed: %s", e)
        return

    record = {
        "appointment_id":                  str(apt_id),
        "patient_first_name":              appointment.get("firstName", ""),
        "patient_second_name":             appointment.get("lastName", ""),
        "patient_email":                   appointment.get("email", ""),
        "phone_number":                    appointment.get("phone", ""),
        "date_of_appointment":             appointment.get("date", ""),
        "time_of_appointment":             appointment.get("datetime", ""),
        "ending_time_of_appointment":      appointment.get("endTime", ""),
        "calender_name":                   appointment.get("calendar", ""),
        "calendar_id":                     str(appointment.get("calendarID", "")),
        "appointment_type":                appointment.get("type", ""),
        "appointment_type_id":             str(appointment.get("appointmentTypeID", "")),
        "duration_of_appointment_minutes": str(appointment.get("duration", "")),
        "canceled":                        str(appointment.get("canceled", False)),
        "status":                          "Canceled" if appointment.get("canceled") else "Scheduled",
        "notes":                           appointment.get("notes", ""),
        "referral_id":                     extract_referral_id(appointment),
        "clinic_id":                       extract_clinic_id(appointment),
        "calender_link":                   appointment.get("confirmationPage", ""),
        "confirmation_page_payment_link":  appointment.get("confirmationPagePaymentLink", ""),
        "link_to_clients_confirm":         appointment.get("confirmationPage", ""),
        "amount_paid":                     float(appointment.get("amountPaid", 0)),
        "has_been_paid":                   appointment.get("paid", "no"),
        "price_of_appointment":            float(appointment.get("price", 0)),
        "price_sold":                      str(appointment.get("priceSold", "")),
        "client_time_zone":                appointment.get("timezone", ""),
        "calendar_timezone":               appointment.get("calendarTimezone", ""),
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            check = await client.get(
                f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                params={"q.where": f"appointment_id='{apt_id}'", "q.limit": 1}
            )
            log.info("Caspio check status: %s", check.status_code)
            existing = check.json().get("Result", [])
        except Exception as e:
            log.error("Caspio check failed: %s", e)
            return

        try:
            if existing:
                resp = await client.put(
                    f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                    headers=headers,
                    params={"q.where": f"appointment_id='{apt_id}'"},
                    json=record
                )
                log.info("Caspio PUT status: %s body: %s", resp.status_code, resp.text[:200])
            else:
                resp = await client.post(
                    f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                    headers=headers,
                    json=record
                )
                log.info("Caspio POST status: %s body: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.error("Caspio write failed: %s", e)


async def caspio_mark_canceled(apt_id: int):
    headers = await caspio_headers()
    async with httpx.AsyncClient(timeout=15) as client:
        await client.put(
            f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
            headers=headers,
            params={"q.where": f"appointment_id='{apt_id}'"},
            json={"status": "Canceled"}
        )
    log.info("Caspio marked appointment ID %s as canceled", apt_id)


# ==================================================
# ROUTES
# ==================================================

@app.get("/", tags=["Health"])
async def root():
    return {"service": "acuity-caspio-proxy", "status": "running", "version": "5.0.0"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "time": datetime.utcnow()}


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

@app.get("/appointment-types", tags=["Configuration"])
async def get_appointment_types(calendarID: Optional[int] = Query(None)):
    params = {}
    if calendarID:
        params["calendarID"] = calendarID
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch appointment types")
    return resp.json()


@app.get("/calendars", tags=["Configuration"])
async def get_calendars():
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ACUITY_BASE}/calendars", headers=acuity_headers())
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch calendars")
    return resp.json()


@app.get("/appointment-addons", tags=["Configuration"])
async def get_appointment_addons():
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ACUITY_BASE}/appointment-addons", headers=acuity_headers())
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch addons")
    return resp.json()


@app.get("/forms", tags=["Configuration"])
async def get_forms():
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ACUITY_BASE}/forms", headers=acuity_headers())
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


# --------------------------------------------------
# AVAILABILITY — generic endpoints
# --------------------------------------------------

@app.get("/availability/dates", tags=["Availability"])
async def available_dates(
    appointmentTypeID: int           = Query(...),
    month:             str           = Query(None),
    calendarID:        Optional[int] = Query(None),
    timezone:          str           = Query("America/New_York"),
):
    if not month:
        month = datetime.now().strftime("%Y-%m")
    params = {"appointmentTypeID": appointmentTypeID, "month": month, "timezone": timezone}
    if calendarID:
        params["calendarID"] = calendarID
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/availability/dates",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.get("/availability/times", tags=["Availability"])
async def available_times(
    appointmentTypeID: int           = Query(...),
    date:              str           = Query(...),
    calendarID:        Optional[int] = Query(None),
    timezone:          str           = Query("America/New_York"),
):
    params = {"appointmentTypeID": appointmentTypeID, "date": date, "timezone": timezone}
    if calendarID:
        params["calendarID"] = calendarID
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/availability/times",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.get("/availability/classes", tags=["Availability"])
async def available_classes(
    appointmentTypeID:  Optional[int] = Query(None),
    calendarID:         Optional[int] = Query(None),
    month:              Optional[str] = Query(None),
    includeUnavailable: bool          = Query(False),
    timezone:           str           = Query("America/New_York"),
):
    params = {"timezone": timezone, "includeUnavailable": str(includeUnavailable).lower()}
    if appointmentTypeID: params["appointmentTypeID"] = appointmentTypeID
    if calendarID:        params["calendarID"]        = calendarID
    if month:             params["month"]             = month
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/availability/classes",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.post("/availability/check-times", tags=["Availability"])
async def check_times(body: CheckTimesRequest):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{ACUITY_BASE}/availability/check-times",
            headers=acuity_headers(),
            json=body.model_dump(exclude_none=True)
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.post("/availability/bulk", tags=["Availability"])
async def availability_bulk(body: BulkAvailabilityRequest):
    async with httpx.AsyncClient(timeout=15) as client:
        tasks = [
            client.get(
                f"{ACUITY_BASE}/availability/times",
                headers=acuity_headers(),
                params={
                    "appointmentTypeID": body.appointmentTypeID,
                    "calendarID":        cal_id,
                    "date":              body.date,
                    "timezone":          body.timezone
                }
            )
            for cal_id in body.calendarIDs
        ]
        responses = await asyncio.gather(*tasks)

    results = []
    for i, resp in enumerate(responses):
        results.append({
            "calendarID": body.calendarIDs[i],
            "slots":      resp.json() if resp.status_code == 200 else [],
            **({"error": "unable to fetch"} if resp.status_code != 200 else {})
        })
    return {"date": body.date, "results": results}


# --------------------------------------------------
# APPOINTMENTS
# --------------------------------------------------

@app.get("/appointments", tags=["Appointments"])
async def get_appointments(
    minDate:           Optional[str]  = Query(None),
    maxDate:           Optional[str]  = Query(None),
    calendarID:        Optional[int]  = Query(None),
    appointmentTypeID: Optional[int]  = Query(None),
    canceled:          Optional[bool] = Query(None),
    max:               int            = Query(50),
):
    params: dict = {"max": max}
    if minDate:              params["minDate"]           = minDate
    if maxDate:              params["maxDate"]           = maxDate
    if calendarID:           params["calendarID"]        = calendarID
    if appointmentTypeID:    params["appointmentTypeID"] = appointmentTypeID
    if canceled is not None: params["canceled"]          = str(canceled).lower()
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.post("/appointments", tags=["Appointments"], status_code=201)
async def create_appointment(body: dict, background_tasks: BackgroundTasks):
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{ACUITY_BASE}/appointments",
            headers=acuity_headers(),
            json=body
        )
    if resp.status_code not in (200, 201):
        raise HTTPException(resp.status_code, "Appointment creation failed")
    appointment = resp.json()
    background_tasks.add_task(caspio_upsert_appointment, appointment)
    return appointment


@app.get("/appointments/{appointment_id}", tags=["Appointments"])
async def get_appointment(appointment_id: int):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments/{appointment_id}",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.put("/appointments/{appointment_id}/cancel", tags=["Appointments"])
async def cancel_appointment(
    appointment_id:   int,
    background_tasks: BackgroundTasks,
    noEmail: bool = Query(False)
):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.put(
            f"{ACUITY_BASE}/appointments/{appointment_id}/cancel",
            headers=acuity_headers(),
            params={"noEmail": str(noEmail).lower()}
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    background_tasks.add_task(caspio_mark_canceled, appointment_id)
    return resp.json()


@app.put("/appointments/{appointment_id}/reschedule", tags=["Appointments"])
async def reschedule_appointment(
    appointment_id:   int,
    body:             dict,
    background_tasks: BackgroundTasks,
):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.put(
            f"{ACUITY_BASE}/appointments/{appointment_id}/reschedule",
            headers=acuity_headers(),
            json=body
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    appointment = resp.json()
    background_tasks.add_task(caspio_upsert_appointment, appointment)
    return appointment


@app.get("/appointments/{appointment_id}/payments", tags=["Appointments"])
async def get_appointment_payments(appointment_id: int):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments/{appointment_id}/payments",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


# --------------------------------------------------
# WEBHOOK
# --------------------------------------------------

@app.post("/webhooks/acuity", tags=["Webhooks"])
async def acuity_webhook(
    request:            Request,
    background_tasks:   BackgroundTasks,
    x_acuity_signature: Optional[str] = Header(None)
):
    raw_body = await request.body()
    log.info("Webhook raw body: %s", raw_body[:300])

    if not verify_acuity_signature(raw_body, x_acuity_signature):
        raise HTTPException(401, "Invalid webhook signature")

    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            data = await request.json()
            action = data.get("action")
            apt_id = str(data.get("id", "")) or None
        else:
            parsed = parse_qs(raw_body.decode("utf-8"))
            action = parsed.get("action", [None])[0]
            apt_id = parsed.get("id", [None])[0]
        log.info("Parsed action=%s id=%s", action, apt_id)
    except Exception as e:
        log.error("Failed to parse webhook body: %s", e)
        raise HTTPException(400, "Invalid payload")

    if not apt_id:
        return {"status": "ignored", "reason": "no appointment id"}

    webhook_id = f"{action}_{apt_id}"
    if webhook_id in recent_webhooks:
        return {"status": "duplicate ignored"}
    recent_webhooks.append(webhook_id)

    log.info("Webhook received: action=%s id=%s", action, apt_id)

    if action in ("scheduling.canceled", "canceled"):
        try:
            await caspio_mark_canceled(int(apt_id))
            log.info("Caspio mark canceled completed for ID: %s", apt_id)
        except Exception as e:
            log.error("Cancel failed: %s", e)

    elif action in (
        "scheduling.scheduled",
        "scheduling.rescheduled",
        "scheduling.changed",
        "order.completed",
        "scheduled",
        "rescheduled",
        "changed",
    ):
        try:
            await asyncio.sleep(3)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{ACUITY_BASE}/appointments/{apt_id}",
                    headers=acuity_headers()
                )
            log.info("Acuity fetch status: %s for ID: %s", resp.status_code, apt_id)
            if resp.status_code == 200:
                appointment_data = resp.json()
                log.info("Acuity appointment forms: %s", str(appointment_data.get("forms", [])))
                await caspio_upsert_appointment(appointment_data)
                log.info("Caspio upsert completed for ID: %s", apt_id)
            else:
                log.error("Acuity fetch failed: %s %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.error("Webhook processing error: %s", str(e))

    return {"status": "processed", "action": action, "id": apt_id}


# ==================================================
# FILTERING — 50-min Psych Eval
# ==================================================

# ── BASE FILTER ────────────────────────────────────────────────────────────────
# Applied to every type before state routing.
# Must be 50-min, category must contain "PSYCHOLOGICAL EVALUATION", must have
# at least one calendar assigned, and must not be a test type.

PSYCH_EVAL_CATEGORY_KEYWORD = "PSYCHOLOGICAL EVALUATION"
ALLOWED_DURATION            = 50

# Test type IDs — always hidden regardless of state.
# Source: Filtered_Appointments.xlsx — rows with "(TEST" in name.
TEST_TYPE_IDS: set = {
    90824033,  # (TEST 1) Thrive: 50 Min … (Psypact)
    90822425,  # (TEST 1) Thrive: 50 Min … - California
    90822613,  # (TEST 2) Thrive: 50 Min … with
    90822881,  # (TEST 3) Thrive: 50 Min …
    90826017,  # (TEST 2) Thrive: 50 Min … (PsyPact(
    90827405,  # (TEST 3) Thrive: 50 Min … (PsyPact)
}

# ── STATE → TYPE ID MAP ────────────────────────────────────────────────────────
#
# DERIVATION (from Filtered_Appointments.xlsx, version 5.0.0):
#
# Each therapist's appointment types have an Acuity category that encodes their
# practice scope.  The logic is:
#
#   "THRIVE CALIFORNIA" category   → CA-ONLY (never shown in other states)
#   "THRIVE IOWA" category         → Iowa-only
#   "THRIVE TEXAS" category        → Texas-only
#   "THRIVE DC" category           → DC-only (+ generic PSYPACT pool)
#   "THRIVE INDIANA" category      → Indiana-only (+ generic PSYPACT pool)
#   "THRIVE Pennsylvania" category → PA-only (+ generic PSYPACT pool)
#   "THRIVE EASTERN TIME" category → not state-locked; added to generic PSYPACT pool
#   "THRIVE: ..." (generic)        → PSYPACT pool — available in all PSYPACT states
#
# ★ Key corrections vs v4.0.0:
#   • State-specific IDs (Indiana/PA/DC/Texas) were previously bundled into
#     PSYPACT_IDS and leaked into every PSYPACT state. They are now separated.
#   • Iowa type 60953633 and Texas type 60953734 both have empty calendarIDs in
#     Acuity — they are dropped (base filter handles this, but also excluded here
#     to be explicit and future-proof).
#   • DC and Indiana each get their OWN state-specific type PLUS the generic
#     PSYPACT pool (a therapist can be licensed in multiple PSYPACT states).
#   • PSYPACT_IDS now contains ONLY the truly generic "THRIVE: Psychological
#     Evaluation" category types plus the Eastern-Time entry (74804055).
#
# HOW TO ADD A NEW THERAPIST:
#   1. Add their appointment type to Acuity with the correct category.
#   2. Add the new type ID to this map (either to a specific state string or to
#      PSYPACT_IDS if they are fully PSYPACT).
#   3. Redeploy — no other code changes needed.
# ──────────────────────────────────────────────────────────────────────────────

# Generic PSYPACT pool: category = "THRIVE: Psychological Evaluation" (and
# "THRIVE EASTERN TIME") — licensed in all PSYPACT compact states.
# IDs with NO calendarIDs in Acuity (75935569, 49484128) are intentionally
# excluded; they will fail the base filter but are listed here for reference.
_PSYPACT_GENERIC: str = (
    "74804055,"   # Dr. Jennifer Alpert — Eastern Time / generic PSYPACT
    "75932446,"   # Dr. Courtney Cook
    "81046199,"   # Dr. Bethany Young
    "81046572,"   # Dr. Danielle Powers
    "84889378,"   # Dr. Yessenia Castillo
    "88803811,"   # Dr. Jacqueline Herrera
    "74926724,"   # Dr. Jennifer Alpert — generic PSYPACT
    "58693634"    # Dr. Charlynn Ruan — generic PSYPACT
)

# State-specific type IDs (not in PSYPACT pool, or additions on top of it).
_CA_ONLY: str = (
    "67331536,"   # Dr. Tamara Rumburg — Santa Monica
    "52823893,"   # Dr. Megan Cannon   — California ONLY
    "55211731,"   # Dr. Emily Hu       — Santa Monica
    "37231009,"   # Dr. Charlynn Ruan  — California entry
    "44643246"    # Dr. Beverly Ibeh   — California
)

_IOWA_ONLY: str = (
    "72914876,"   # Dr. Jennifer Alpert — Iowa
    "55554634"    # Dr. Charlynn Ruan  — Iowa
    # 60953633 intentionally excluded — no calendarIDs in Acuity
)

_TEXAS_ONLY: str = (
    "55554566"    # Dr. Charlynn Ruan  — Texas
    # 60953734 intentionally excluded — no calendarIDs in Acuity
)

_DC_SPECIFIC: str   = "74542331"   # Dr. Jennifer Alpert — DC category entry
_IN_SPECIFIC: str   = "73689906"   # Dr. Jennifer Alpert — Indiana category entry
_PA_SPECIFIC: str   = "73062970"   # Dr. Jennifer Alpert — Pennsylvania category entry

# For states that have their OWN category entry AND should also see the PSYPACT
# generic pool, concatenate:
_DC_ALL: str  = f"{_DC_SPECIFIC},{_PSYPACT_GENERIC}"
_IN_ALL: str  = f"{_IN_SPECIFIC},{_PSYPACT_GENERIC}"
_PA_ALL: str  = f"{_PA_SPECIFIC},{_PSYPACT_GENERIC}"

# ──────────────────────────────────────────────────────────────────────────────
# STATE_TYPE_IDS  — the single source of truth consumed by get_allowed_types().
#
#   str value  → comma-separated list of allowed appointment type IDs for state
#   ""         → state is recognised but has NO therapists assigned → return []
#   (absent)   → state not in map → treat as international → return all eligible
# ──────────────────────────────────────────────────────────────────────────────

STATE_TYPE_IDS: dict[str, str] = {
    # ── NON-PSYPACT states: state-specific therapists only ────────────────────
    "California":    _CA_ONLY,
    "Iowa":          _IOWA_ONLY,
    "Texas":         _TEXAS_ONLY,

    # Non-PSYPACT states with no therapists yet → empty string
    "New York":      "",
    "Hawaii":        "",
    "Alaska":        "",
    "Oregon":        "",
    "New Mexico":    "",
    "Louisiana":     "",
    "Massachusetts": "",

    # ── PSYPACT-compact states with a state-specific entry + generic pool ─────
    "District of Columbia": _DC_ALL,
    "Indiana":              _IN_ALL,
    "Pennsylvania":         _PA_ALL,

    # ── PSYPACT-compact states: generic pool only ─────────────────────────────
    "Arizona":        _PSYPACT_GENERIC,
    "Colorado":       _PSYPACT_GENERIC,
    "Connecticut":    _PSYPACT_GENERIC,
    "Delaware":       _PSYPACT_GENERIC,
    "Georgia":        _PSYPACT_GENERIC,
    "Idaho":          _PSYPACT_GENERIC,
    "Illinois":       _PSYPACT_GENERIC,
    "Kansas":         _PSYPACT_GENERIC,
    "Kentucky":       _PSYPACT_GENERIC,
    "Maine":          _PSYPACT_GENERIC,
    "Maryland":       _PSYPACT_GENERIC,
    "Michigan":       _PSYPACT_GENERIC,
    "Minnesota":      _PSYPACT_GENERIC,
    "Missouri":       _PSYPACT_GENERIC,
    "Nebraska":       _PSYPACT_GENERIC,
    "Nevada":         _PSYPACT_GENERIC,
    "New Hampshire":  _PSYPACT_GENERIC,
    "New Jersey":     _PSYPACT_GENERIC,
    "North Carolina": _PSYPACT_GENERIC,
    "North Dakota":   _PSYPACT_GENERIC,
    "Ohio":           _PSYPACT_GENERIC,
    "Rhode Island":   _PSYPACT_GENERIC,
    "South Carolina": _PSYPACT_GENERIC,
    "Tennessee":      _PSYPACT_GENERIC,
    "Utah":           _PSYPACT_GENERIC,
    "Vermont":        _PSYPACT_GENERIC,
    "Virginia":       _PSYPACT_GENERIC,
    "West Virginia":  _PSYPACT_GENERIC,
    "Wisconsin":      _PSYPACT_GENERIC,
    "Wyoming":        _PSYPACT_GENERIC,
}

# Convenience set for pool-label logic
NON_PSYPACT_STATES: set[str] = {
    "California", "New York", "Hawaii", "Alaska", "Oregon",
    "New Mexico", "Louisiana", "Massachusetts",
    # Iowa and Texas have specific therapists but are not PSYPACT-compact states
    "Iowa", "Texas",
}

# State name normaliser — lower-case key → canonical name
STATE_NORMALIZER: dict[str, str] = {s.lower(): s for s in STATE_TYPE_IDS}

# ── BASE FILTER ────────────────────────────────────────────────────────────────

def is_50min_psych_eval(apt_type: dict) -> bool:
    """Return True only if the type passes ALL base criteria."""
    category = apt_type.get("category", "").upper()
    if PSYCH_EVAL_CATEGORY_KEYWORD not in category:
        return False
    try:
        if int(apt_type.get("duration", 0)) != ALLOWED_DURATION:
            return False
    except (TypeError, ValueError):
        return False
    if not apt_type.get("calendarIDs"):
        return False
    if apt_type.get("id") in TEST_TYPE_IDS:
        return False
    return True


def get_allowed_types(all_types: list, state: str) -> list:
    """
    Return the subset of Acuity appointment types that should be shown for
    *state*.  Uses STATE_TYPE_IDS as the sole source of truth.

    Steps:
      1. Look up the comma-separated allowed-ID string for the state.
      2. Filter all_types to those whose id is in that set AND pass the base
         filter (50-min, has calendar, not a test type).
      3. For states absent from the map (international), return all types that
         pass the base filter.
    """
    type_ids_str = STATE_TYPE_IDS.get(state)

    if type_ids_str is None:
        # State not in map → international / unknown → show everything eligible
        log.info("state=%s not in map (international) — returning all eligible types", state)
        return [t for t in all_types if is_50min_psych_eval(t)]

    if type_ids_str == "":
        # State is known but no therapists assigned yet
        log.info("state=%s known but no typeIDs assigned — returning empty list", state)
        return []

    allowed_ids = {int(x.strip()) for x in type_ids_str.split(",") if x.strip()}
    matched = [
        t for t in all_types
        if t["id"] in allowed_ids and is_50min_psych_eval(t)
    ]
    log.info(
        "VERSION=5.0.0 state=%s allowed_ids=%d matched=%d",
        state, len(allowed_ids), len(matched)
    )
    return matched


def extract_doctor_name(type_name: str) -> str:
    if " with " in type_name:
        return type_name.split(" with ")[-1].strip()
    return type_name


# ==================================================
# STATE-BASED AVAILABILITY ROUTES
# ==================================================

@app.get("/availability/by-state", tags=["Availability"])
async def availability_by_state(
    state:    str = Query(..., description="US state name, or any value for outside US"),
    date:     str = Query(..., description="YYYY-MM-DD"),
    timezone: str = Query("America/New_York"),
):
    state = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
    log.info("availability/by-state called — state=%s date=%s", state, date)

    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    matched_types = get_allowed_types(types_resp.json(), state)

    if not matched_types:
        return {
            "state":   state,
            "date":    date,
            "message": "No 50-minute Psychological Evaluation types found for this state",
            "slots":   []
        }

    cal_to_types_list: dict = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            cal_to_types_list[cal_id].append({
                "appointmentTypeID": apt_type["id"],
                "schedulingUrl":     apt_type.get("schedulingUrl", ""),
                "typeName":          apt_type.get("name", ""),
            })

    async with httpx.AsyncClient(timeout=20) as client:
        tasks     = []
        task_meta = []
        for cal_id, type_infos in cal_to_types_list.items():
            for info in type_infos:
                tasks.append(
                    client.get(
                        f"{ACUITY_BASE}/availability/times",
                        headers=acuity_headers(),
                        params={
                            "appointmentTypeID": info["appointmentTypeID"],
                            "calendarID":        cal_id,
                            "date":              date,
                            "timezone":          timezone,
                        }
                    )
                )
                task_meta.append((cal_id, info))
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    therapist_slots: dict = {}
    seen_slots: set       = set()

    for i, resp in enumerate(responses):
        cal_id, info = task_meta[i]
        if isinstance(resp, Exception) or resp.status_code != 200:
            continue
        for slot in resp.json():
            if slot.get("slotsAvailable", 0) < 1:
                continue
            slot_key = (cal_id, slot["time"])
            if slot_key in seen_slots:
                continue
            seen_slots.add(slot_key)

            if cal_id not in therapist_slots:
                therapist_slots[cal_id] = {
                    "calendarID":    cal_id,
                    "therapistName": extract_doctor_name(info["typeName"]),
                    "typeName":      info["typeName"],
                    "bookingUrl":    info["schedulingUrl"],
                    "typeID":        info["appointmentTypeID"],
                    "slots":         [],
                    "totalSlots":    0,
                }
            therapist_slots[cal_id]["slots"].append({
                "time":          slot["time"],
                "calendarID":    cal_id,
                "bookingUrl":    info["schedulingUrl"],
                "typeID":        info["appointmentTypeID"],
                "therapistName": extract_doctor_name(info["typeName"]),
            })
            therapist_slots[cal_id]["totalSlots"] += 1

    for cal_id in therapist_slots:
        therapist_slots[cal_id]["slots"].sort(key=lambda x: x["time"])

    therapist_list = list(therapist_slots.values())
    random.shuffle(therapist_list)

    time_buckets: dict = defaultdict(list)
    for therapist in therapist_list:
        for slot in therapist["slots"]:
            time_buckets[slot["time"]].append(slot)

    all_slots = []
    for time_key in sorted(time_buckets.keys()):
        all_slots.extend(time_buckets[time_key])

    if state in NON_PSYPACT_STATES:
        pool = "state-specific"
    elif state in STATE_TYPE_IDS:
        pool = "psypact"
    else:
        pool = "all (international)"

    return {
        "state":          state,
        "date":           date,
        "timezone":       timezone,
        "pool":           pool,
        "totalSlots":     len(all_slots),
        "matchedTypes":   len(matched_types),
        "totalCalendars": len(therapist_slots),
        "therapists":     therapist_list,
        "slots":          all_slots
    }


@app.get("/availability/dates-by-state", tags=["Availability"])
async def availability_dates_by_state(
    state:    str           = Query(..., description="US state name, or any value for outside US"),
    month:    Optional[str] = Query(None, description="YYYY-MM. Defaults to current month"),
    timezone: str           = Query("America/New_York"),
):
    if not month:
        month = datetime.now().strftime("%Y-%m")

    state = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
    log.info("availability/dates-by-state called — state=%s month=%s", state, month)

    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    matched_types = get_allowed_types(types_resp.json(), state)

    if not matched_types:
        return {"state": state, "month": month, "dates": []}

    cal_to_typeids: dict = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            cal_to_typeids[cal_id].append(apt_type["id"])

    if not cal_to_typeids:
        return {"state": state, "month": month, "dates": []}

    async with httpx.AsyncClient(timeout=20) as client:
        tasks = []
        for cal_id, type_ids in cal_to_typeids.items():
            for type_id in type_ids:
                tasks.append(
                    client.get(
                        f"{ACUITY_BASE}/availability/dates",
                        headers=acuity_headers(),
                        params={
                            "appointmentTypeID": type_id,
                            "calendarID":        cal_id,
                            "month":             month,
                            "timezone":          timezone,
                        }
                    )
                )
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    all_dates: set = set()
    for resp in responses:
        if isinstance(resp, Exception) or resp.status_code != 200:
            continue
        for d in resp.json():
            if d.get("date"):
                all_dates.add(d["date"])

    return {
        "state":    state,
        "month":    month,
        "timezone": timezone,
        "dates":    [{"date": d} for d in sorted(all_dates)]
    }


# ==================================================
# ADMIN / DEBUG
# ==================================================

@app.get("/admin/test-caspio", tags=["Admin"])
async def test_caspio():
    try:
        headers = await caspio_headers()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                params={"q.limit": 1}
            )
        return {
            "caspio_token":      "ok",
            "table_name":        CASPIO_TABLE,
            "table_ping_status": resp.status_code,
            "table_ping_body":   resp.json()
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/debug-types", tags=["Admin"])
async def debug_types(state: Optional[str] = Query(None)):
    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    all_types = types_resp.json()

    passed, failed = [], []
    for t in all_types:
        category = t.get("category", "").upper()
        duration  = t.get("duration")
        reasons   = []

        if PSYCH_EVAL_CATEGORY_KEYWORD not in category:
            reasons.append(f"category missing 'PSYCHOLOGICAL EVALUATION': {t.get('category')}")
        try:
            if int(duration) != ALLOWED_DURATION:
                reasons.append(f"duration {duration} != 50")
        except Exception:
            reasons.append(f"invalid duration: {duration}")
        if not t.get("calendarIDs"):
            reasons.append("no calendarIDs assigned")
        if t["id"] in TEST_TYPE_IDS:
            reasons.append("test type — excluded")

        entry = {
            "id":        t["id"],
            "name":      t.get("name", ""),
            "category":  t.get("category", ""),
            "duration":  duration,
            "calendars": t.get("calendarIDs", []),
        }
        if reasons:
            entry["filtered_reason"] = reasons
            failed.append(entry)
        else:
            if state:
                state_norm = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
                ids_for_state = {
                    int(x) for x in STATE_TYPE_IDS.get(state_norm, "").split(",") if x.strip()
                }
                entry["in_state_map"] = t["id"] in ids_for_state
                entry["pool"] = (
                    "state-specific" if state_norm in NON_PSYPACT_STATES
                    else "psypact" if state_norm in STATE_TYPE_IDS
                    else "international"
                )
            passed.append(entry)

    matched = get_allowed_types(all_types, STATE_NORMALIZER.get(state.strip().lower(), state.strip())) if state else []

    return {
        "version":            "5.0.0",
        "total_types":        len(all_types),
        "passed_base_filter": len(passed),
        "failed_base_filter": len(failed),
        "matched_for_state":  len(matched) if state else "no state provided",
        "passed":             passed,
        "failed":             failed,
    }


@app.get("/states/psypact-check", tags=["Configuration"])
async def psypact_check(state: str = Query(...)):
    state_norm   = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
    type_ids_raw = STATE_TYPE_IDS.get(state_norm)

    if type_ids_raw is None:
        pool = "international (all eligible types)"
    elif type_ids_raw == "":
        pool = "known state — no therapists assigned"
    elif state_norm in NON_PSYPACT_STATES:
        pool = "state-specific (non-PSYPACT)"
    else:
        pool = "psypact"

    return {
        "state":            state_norm,
        "pool":             pool,
        "assigned_type_ids": type_ids_raw if type_ids_raw is not None else "not in map",
    }


@app.get("/admin/debug-appointment/{appointment_id}", tags=["Admin"])
async def debug_appointment(appointment_id: int):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments/{appointment_id}",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    data = resp.json()
    return {
        "id":        data.get("id"),
        "forms":     data.get("forms", []),
        "formsText": data.get("formsText", ""),
        "notes":     data.get("notes", ""),
    }
import hashlib
import logging
import random
import re
from collections import deque, defaultdict
from datetime import datetime
from typing import Optional, List
from urllib.parse import parse_qs

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Header, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio

# --------------------------------------------------
# ENVIRONMENT
# --------------------------------------------------

load_dotenv()

ACUITY_USER_ID        = os.getenv("ACUITY_USER_ID")
ACUITY_API_KEY        = os.getenv("ACUITY_API_KEY")
ACUITY_WEBHOOK_SECRET = os.getenv("ACUITY_WEBHOOK_SECRET")

CASPIO_BASE_URL       = os.getenv("CASPIO_BASE_URL")
CASPIO_API_BASE_URL   = os.getenv("CASPIO_API_BASE_URL")
CASPIO_CLIENT_ID      = os.getenv("CASPIO_CLIENT_ID")
CASPIO_CLIENT_SECRET  = os.getenv("CASPIO_CLIENT_SECRET")
CASPIO_TABLE          = os.getenv("CASPIO_APPOINTMENTS_TABLE")

ACUITY_BASE           = "https://acuityscheduling.com/api/v1"

# --------------------------------------------------
# LOGGING  (PHI SAFE — never log patient names/emails)
# --------------------------------------------------

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("acuity-proxy")

# --------------------------------------------------
# FASTAPI APP
# --------------------------------------------------

app = FastAPI(
    title="Acuity ↔ Caspio Proxy",
    description="Covers all Acuity availability, appointments, and Caspio sync",
    version="4.0.0"
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

recent_webhooks     = deque(maxlen=500)
_caspio_token_cache = {}

# --------------------------------------------------
# PYDANTIC MODELS
# --------------------------------------------------

class BulkAvailabilityRequest(BaseModel):
    appointmentTypeID: int
    calendarIDs: List[int]
    date: str
    timezone: Optional[str] = "America/New_York"


class CheckTimesRequest(BaseModel):
    appointmentTypeID: int
    calendarID: Optional[int] = None
    datetime: str
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
        "Content-Type":  "application/json"
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
                "grant_type":    "client_credentials",
                "client_id":     CASPIO_CLIENT_ID,
                "client_secret": CASPIO_CLIENT_SECRET
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    if resp.status_code != 200:
        log.error("Caspio token request failed: %s", resp.status_code)
        raise HTTPException(500, "Caspio authentication failed")

    data = resp.json()
    _caspio_token_cache["token"]      = data["access_token"]
    _caspio_token_cache["expires_at"] = now + data.get("expires_in", 3600)
    return data["access_token"]


async def caspio_headers():
    token = await get_caspio_token()
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json"
    }


# --------------------------------------------------
# SECURITY
# --------------------------------------------------

def verify_acuity_signature(raw_body: bytes, signature: Optional[str]) -> bool:
    return True


# --------------------------------------------------
# REFERRAL ID HELPER
# --------------------------------------------------

def extract_referral_id(appointment: dict) -> Optional[str]:
    for form in appointment.get("forms", []):
        for field in form.get("values", []):
            if field.get("fieldID") == 18222169:
                val = str(field.get("value", "")).strip()
                if val and len(val) < 100 and "\n" not in val:
                    log.info("referral_id extracted: %s", val)
                    return val

    forms_text = appointment.get("formsText", "")
    if forms_text:
        match = re.search(r"referral_id:\s*(\S+)", forms_text, re.IGNORECASE)
        if match:
            val = match.group(1).strip()
            if val and len(val) < 100:
                log.info("referral_id extracted via formsText: %s", val)
                return val

    log.warning("referral_id not found in appointment %s", appointment.get("id"))
    return None


# --------------------------------------------------
# CLINIC ID HELPER
# --------------------------------------------------

def extract_clinic_id(appointment: dict) -> Optional[str]:
    for form in appointment.get("forms", []):
        for field in form.get("values", []):
            if (
                field.get("fieldID") == 18236523
                or field.get("name", "").lower() == "clinic_id"
            ):
                val = str(field.get("value", "")).strip()
                if val and len(val) < 100 and "\n" not in val:
                    return val
    return None


# --------------------------------------------------
# CASPIO SYNC HELPERS
# --------------------------------------------------

async def caspio_upsert_appointment(appointment: dict):
    apt_id = appointment.get("id")
    if not apt_id:
        log.error("No appointment ID found in payload")
        return

    log.info("Starting Caspio upsert for appointment ID %s", apt_id)

    try:
        headers = await caspio_headers()
        log.info("Caspio token obtained OK")
    except Exception as e:
        log.error("Caspio token failed: %s", e)
        return

    record = {
        "appointment_id":                  str(apt_id),
        "patient_first_name":              appointment.get("firstName", ""),
        "patient_second_name":             appointment.get("lastName", ""),
        "patient_email":                   appointment.get("email", ""),
        "phone_number":                    appointment.get("phone", ""),
        "date_of_appointment":             appointment.get("date", ""),
        "time_of_appointment":             appointment.get("datetime", ""),
        "ending_time_of_appointment":      appointment.get("endTime", ""),
        "calender_name":                   appointment.get("calendar", ""),
        "calendar_id":                     str(appointment.get("calendarID", "")),
        "appointment_type":                appointment.get("type", ""),
        "appointment_type_id":             str(appointment.get("appointmentTypeID", "")),
        "duration_of_appointment_minutes": str(appointment.get("duration", "")),
        "canceled":                        str(appointment.get("canceled", False)),
        "status":                          "Canceled" if appointment.get("canceled") else "Scheduled",
        "notes":                           appointment.get("notes", ""),
        "referral_id":                     extract_referral_id(appointment),
        "clinic_id":                       extract_clinic_id(appointment),
        "calender_link":                   appointment.get("confirmationPage", ""),
        "confirmation_page_payment_link":  appointment.get("confirmationPagePaymentLink", ""),
        "link_to_clients_confirm":         appointment.get("confirmationPage", ""),
        "amount_paid":                     float(appointment.get("amountPaid", 0)),
        "has_been_paid":                   appointment.get("paid", "no"),
        "price_of_appointment":            float(appointment.get("price", 0)),
        "price_sold":                      str(appointment.get("priceSold", "")),
        "client_time_zone":                appointment.get("timezone", ""),
        "calendar_timezone":               appointment.get("calendarTimezone", ""),
    }

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            check = await client.get(
                f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                params={"q.where": f"appointment_id='{apt_id}'", "q.limit": 1}
            )
            log.info("Caspio check status: %s", check.status_code)
            existing = check.json().get("Result", [])
        except Exception as e:
            log.error("Caspio check failed: %s", e)
            return

        try:
            if existing:
                resp = await client.put(
                    f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                    headers=headers,
                    params={"q.where": f"appointment_id='{apt_id}'"},
                    json=record
                )
                log.info("Caspio PUT status: %s body: %s", resp.status_code, resp.text[:200])
            else:
                resp = await client.post(
                    f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                    headers=headers,
                    json=record
                )
                log.info("Caspio POST status: %s body: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.error("Caspio write failed: %s", e)


async def caspio_mark_canceled(apt_id: int):
    headers = await caspio_headers()
    async with httpx.AsyncClient(timeout=15) as client:
        await client.put(
            f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
            headers=headers,
            params={"q.where": f"appointment_id='{apt_id}'"},
            json={"status": "Canceled"}
        )
    log.info("Caspio marked appointment ID %s as canceled", apt_id)


# ==================================================
# ROUTES
# ==================================================

@app.get("/", tags=["Health"])
async def root():
    return {"service": "acuity-caspio-proxy", "status": "running", "version": "4.0.0"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "time": datetime.utcnow()}


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

@app.get("/appointment-types", tags=["Configuration"])
async def get_appointment_types(calendarID: Optional[int] = Query(None)):
    params = {}
    if calendarID:
        params["calendarID"] = calendarID
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch appointment types")
    return resp.json()


@app.get("/calendars", tags=["Configuration"])
async def get_calendars():
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ACUITY_BASE}/calendars", headers=acuity_headers())
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch calendars")
    return resp.json()


@app.get("/appointment-addons", tags=["Configuration"])
async def get_appointment_addons():
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ACUITY_BASE}/appointment-addons", headers=acuity_headers())
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch addons")
    return resp.json()


@app.get("/forms", tags=["Configuration"])
async def get_forms():
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(f"{ACUITY_BASE}/forms", headers=acuity_headers())
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


# --------------------------------------------------
# AVAILABILITY — generic endpoints
# --------------------------------------------------

@app.get("/availability/dates", tags=["Availability"])
async def available_dates(
    appointmentTypeID: int           = Query(...),
    month:             str           = Query(None),
    calendarID:        Optional[int] = Query(None),
    timezone:          str           = Query("America/New_York"),
):
    if not month:
        month = datetime.now().strftime("%Y-%m")
    params = {"appointmentTypeID": appointmentTypeID, "month": month, "timezone": timezone}
    if calendarID:
        params["calendarID"] = calendarID
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/availability/dates",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.get("/availability/times", tags=["Availability"])
async def available_times(
    appointmentTypeID: int           = Query(...),
    date:              str           = Query(...),
    calendarID:        Optional[int] = Query(None),
    timezone:          str           = Query("America/New_York"),
):
    params = {"appointmentTypeID": appointmentTypeID, "date": date, "timezone": timezone}
    if calendarID:
        params["calendarID"] = calendarID
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/availability/times",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.get("/availability/classes", tags=["Availability"])
async def available_classes(
    appointmentTypeID:  Optional[int] = Query(None),
    calendarID:         Optional[int] = Query(None),
    month:              Optional[str] = Query(None),
    includeUnavailable: bool          = Query(False),
    timezone:           str           = Query("America/New_York"),
):
    params = {"timezone": timezone, "includeUnavailable": str(includeUnavailable).lower()}
    if appointmentTypeID: params["appointmentTypeID"] = appointmentTypeID
    if calendarID:        params["calendarID"]        = calendarID
    if month:             params["month"]             = month
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/availability/classes",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.post("/availability/check-times", tags=["Availability"])
async def check_times(body: CheckTimesRequest):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{ACUITY_BASE}/availability/check-times",
            headers=acuity_headers(),
            json=body.model_dump(exclude_none=True)
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.post("/availability/bulk", tags=["Availability"])
async def availability_bulk(body: BulkAvailabilityRequest):
    async with httpx.AsyncClient(timeout=15) as client:
        tasks = [
            client.get(
                f"{ACUITY_BASE}/availability/times",
                headers=acuity_headers(),
                params={
                    "appointmentTypeID": body.appointmentTypeID,
                    "calendarID":        cal_id,
                    "date":              body.date,
                    "timezone":          body.timezone
                }
            )
            for cal_id in body.calendarIDs
        ]
        responses = await asyncio.gather(*tasks)

    results = []
    for i, resp in enumerate(responses):
        results.append({
            "calendarID": body.calendarIDs[i],
            "slots":      resp.json() if resp.status_code == 200 else [],
            **({"error": "unable to fetch"} if resp.status_code != 200 else {})
        })
    return {"date": body.date, "results": results}


# --------------------------------------------------
# APPOINTMENTS
# --------------------------------------------------

@app.get("/appointments", tags=["Appointments"])
async def get_appointments(
    minDate:           Optional[str]  = Query(None),
    maxDate:           Optional[str]  = Query(None),
    calendarID:        Optional[int]  = Query(None),
    appointmentTypeID: Optional[int]  = Query(None),
    canceled:          Optional[bool] = Query(None),
    max:               int            = Query(50),
):
    params: dict = {"max": max}
    if minDate:              params["minDate"]           = minDate
    if maxDate:              params["maxDate"]           = maxDate
    if calendarID:           params["calendarID"]        = calendarID
    if appointmentTypeID:    params["appointmentTypeID"] = appointmentTypeID
    if canceled is not None: params["canceled"]          = str(canceled).lower()
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments",
            headers=acuity_headers(),
            params=params
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.post("/appointments", tags=["Appointments"], status_code=201)
async def create_appointment(body: dict, background_tasks: BackgroundTasks):
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{ACUITY_BASE}/appointments",
            headers=acuity_headers(),
            json=body
        )
    if resp.status_code not in (200, 201):
        raise HTTPException(resp.status_code, "Appointment creation failed")
    appointment = resp.json()
    background_tasks.add_task(caspio_upsert_appointment, appointment)
    return appointment


@app.get("/appointments/{appointment_id}", tags=["Appointments"])
async def get_appointment(appointment_id: int):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments/{appointment_id}",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


@app.put("/appointments/{appointment_id}/cancel", tags=["Appointments"])
async def cancel_appointment(
    appointment_id:   int,
    background_tasks: BackgroundTasks,
    noEmail: bool = Query(False)
):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.put(
            f"{ACUITY_BASE}/appointments/{appointment_id}/cancel",
            headers=acuity_headers(),
            params={"noEmail": str(noEmail).lower()}
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    background_tasks.add_task(caspio_mark_canceled, appointment_id)
    return resp.json()


@app.put("/appointments/{appointment_id}/reschedule", tags=["Appointments"])
async def reschedule_appointment(
    appointment_id:   int,
    body:             dict,
    background_tasks: BackgroundTasks,
):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.put(
            f"{ACUITY_BASE}/appointments/{appointment_id}/reschedule",
            headers=acuity_headers(),
            json=body
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    appointment = resp.json()
    background_tasks.add_task(caspio_upsert_appointment, appointment)
    return appointment


@app.get("/appointments/{appointment_id}/payments", tags=["Appointments"])
async def get_appointment_payments(appointment_id: int):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments/{appointment_id}/payments",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


# --------------------------------------------------
# WEBHOOK
# --------------------------------------------------

@app.post("/webhooks/acuity", tags=["Webhooks"])
async def acuity_webhook(
    request:            Request,
    background_tasks:   BackgroundTasks,
    x_acuity_signature: Optional[str] = Header(None)
):
    raw_body = await request.body()
    log.info("Webhook raw body: %s", raw_body[:300])

    if not verify_acuity_signature(raw_body, x_acuity_signature):
        raise HTTPException(401, "Invalid webhook signature")

    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            data = await request.json()
            action = data.get("action")
            apt_id = str(data.get("id", "")) or None
        else:
            parsed = parse_qs(raw_body.decode("utf-8"))
            action = parsed.get("action", [None])[0]
            apt_id = parsed.get("id", [None])[0]
        log.info("Parsed action=%s id=%s", action, apt_id)
    except Exception as e:
        log.error("Failed to parse webhook body: %s", e)
        raise HTTPException(400, "Invalid payload")

    if not apt_id:
        return {"status": "ignored", "reason": "no appointment id"}

    webhook_id = f"{action}_{apt_id}"
    if webhook_id in recent_webhooks:
        return {"status": "duplicate ignored"}
    recent_webhooks.append(webhook_id)

    log.info("Webhook received: action=%s id=%s", action, apt_id)

    if action in ("scheduling.canceled", "canceled"):
        try:
            await caspio_mark_canceled(int(apt_id))
            log.info("Caspio mark canceled completed for ID: %s", apt_id)
        except Exception as e:
            log.error("Cancel failed: %s", e)

    elif action in (
        "scheduling.scheduled",
        "scheduling.rescheduled",
        "scheduling.changed",
        "order.completed",
        "scheduled",
        "rescheduled",
        "changed",
    ):
        try:
            await asyncio.sleep(3)
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{ACUITY_BASE}/appointments/{apt_id}",
                    headers=acuity_headers()
                )
            log.info("Acuity fetch status: %s for ID: %s", resp.status_code, apt_id)
            if resp.status_code == 200:
                appointment_data = resp.json()
                log.info("Acuity appointment forms: %s", str(appointment_data.get("forms", [])))
                await caspio_upsert_appointment(appointment_data)
                log.info("Caspio upsert completed for ID: %s", apt_id)
            else:
                log.error("Acuity fetch failed: %s %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.error("Webhook processing error: %s", str(e))

    return {"status": "processed", "action": action, "id": apt_id}


# ==================================================
# FILTERING — 50-min Psych Eval
# ==================================================

PSYCH_EVAL_CATEGORY_KEYWORD = "PSYCHOLOGICAL EVALUATION"
ALLOWED_DURATION            = 50

NON_PSYPACT_STATES = {
    "New York", "Hawaii", "Iowa", "Alaska", "Oregon",
    "New Mexico", "Louisiana", "California", "Massachusetts",
}

STATE_KEYWORDS = {
    "California":           ["CALIFORNIA", "SANTA MONICA", "THRIVE CALIFORNIA"],
    "New York":             ["NEW YORK", "THRIVE NY"],
    "Hawaii":               ["HAWAII"],
    "Alaska":               ["ALASKA"],
    "Oregon":               ["OREGON"],
    "New Mexico":           ["NEW MEXICO"],
    "Louisiana":            ["LOUISIANA"],
    "Massachusetts":        ["MASSACHUSETTS"],
    "Iowa":                 ["IOWA", "THRIVE IA"],
    "Indiana":              ["INDIANA"],
    "Pennsylvania":         ["PENNSYLVANIA"],
    "Texas":                ["TEXAS", "THRIVE TX"],
    "District of Columbia": ["THRIVE DC"],
}

STATE_NORMALIZER = {}
for s in NON_PSYPACT_STATES:
    STATE_NORMALIZER[s.lower()] = s
for s in STATE_KEYWORDS:
    STATE_NORMALIZER[s.lower()] = s

# --------------------------------------------------
# MASTER HARDCODED MAP
# This is the single source of truth.
# str  → locked to that state only
# None → PSYPACT generic pool (all PSYPACT states)
# New therapist added? Add one line here.
# --------------------------------------------------
PSYPACT_IDS = "73689906,73062970,74542331,74804055,55554566,75932446,81046199,81046572,84889378,88803811,74926724,58693634"

STATE_TYPE_IDS: dict = {
    # NON-PSYPACT — state-locked
    "California":           "67331536,52823893,55211731,37231009,44643246",
    "Iowa":                 "72914876,55554634",
    "New York":             "",
    "Hawaii":               "",
    "Alaska":               "",
    "Oregon":               "",
    "New Mexico":           "",
    "Louisiana":            "",
    "Massachusetts":        "",
    # PSYPACT pool
    "Indiana":              PSYPACT_IDS,
    "Pennsylvania":         PSYPACT_IDS,
    "Texas":                PSYPACT_IDS,
    "District of Columbia": PSYPACT_IDS,
    "Virginia":             PSYPACT_IDS,
    "Illinois":             PSYPACT_IDS,
    "Arizona":              PSYPACT_IDS,
    "Colorado":             PSYPACT_IDS,
    "Connecticut":          PSYPACT_IDS,
    "Delaware":             PSYPACT_IDS,
    "Georgia":              PSYPACT_IDS,
    "Idaho":                PSYPACT_IDS,
    "Kansas":               PSYPACT_IDS,
    "Kentucky":             PSYPACT_IDS,
    "Maine":                PSYPACT_IDS,
    "Maryland":             PSYPACT_IDS,
    "Michigan":             PSYPACT_IDS,
    "Minnesota":            PSYPACT_IDS,
    "Missouri":             PSYPACT_IDS,
    "Nebraska":             PSYPACT_IDS,
    "Nevada":               PSYPACT_IDS,
    "New Hampshire":        PSYPACT_IDS,
    "New Jersey":           PSYPACT_IDS,
    "North Carolina":       PSYPACT_IDS,
    "North Dakota":         PSYPACT_IDS,
    "Ohio":                 PSYPACT_IDS,
    "Rhode Island":         PSYPACT_IDS,
    "South Carolina":       PSYPACT_IDS,
    "Tennessee":            PSYPACT_IDS,
    "Utah":                 PSYPACT_IDS,
    "Vermont":              PSYPACT_IDS,
    "West Virginia":        PSYPACT_IDS,
    "Wisconsin":            PSYPACT_IDS,
    "Wyoming":              PSYPACT_IDS,
}

# Test type IDs — always hidden
TEST_TYPE_IDS: set = {
    90824033, 90822425, 90822613, 90822881,
    90826017, 90827405,
}


def is_50min_psych_eval(apt_type: dict) -> bool:
    category = apt_type.get("category", "").upper()
    duration  = apt_type.get("duration")
    if PSYCH_EVAL_CATEGORY_KEYWORD not in category:
        return False
    try:
        if int(duration) != ALLOWED_DURATION:
            return False
    except (TypeError, ValueError):
        return False
    if not apt_type.get("calendarIDs"):
        return False
    return True


def matches_state(apt_type: dict, state: str) -> bool:
    cat  = apt_type.get("category", "").upper()
    name = apt_type.get("name", "").upper()
    for kw in STATE_KEYWORDS.get(state, [state.upper()]):
        if kw.upper() in cat or kw.upper() in name:
            return True
    return False


def _route_type(apt_type: dict) -> str:
    tid = apt_type["id"]
    # Dynamic fallback only — used by debug endpoint
    for s in NON_PSYPACT_STATES:
        if matches_state(apt_type, s):
            return f"non_psypact:{s}"
    return "psypact"


def get_allowed_types(all_types: list, state: str) -> list:
    """
    Filter Acuity types using STATE_TYPE_IDS hardcoded map.
    This is the ONLY filtering function used by availability routes.
    """
    type_ids_str = STATE_TYPE_IDS.get(state, None)

    if type_ids_str is None:
        # State not in map at all — outside US — return all 50-min types
        log.info("state=%s outside US — returning all eligible types", state)
        return [
            t for t in all_types
            if is_50min_psych_eval(t) and t["id"] not in TEST_TYPE_IDS
        ]

    if type_ids_str == "":
        # State in map but no therapists assigned yet
        log.info("state=%s in map but no typeIDs assigned", state)
        return []

    allowed = set(int(x.strip()) for x in type_ids_str.split(",") if x.strip())
    matched = [
        t for t in all_types
        if t["id"] in allowed
        and is_50min_psych_eval(t)
        and t["id"] not in TEST_TYPE_IDS
    ]
    log.info("VERSION=4.0.0 state=%s allowed=%s matched=%s", state, len(allowed), len(matched))
    return matched


def extract_doctor_name(type_name: str) -> str:
    if " with " in type_name:
        return type_name.split(" with ")[-1].strip()
    return type_name


# ==================================================
# STATE-BASED AVAILABILITY ROUTES
# ==================================================

@app.get("/availability/by-state", tags=["Availability"])
async def availability_by_state(
    state:    str = Query(..., description="US state name, or any value for outside US"),
    date:     str = Query(..., description="YYYY-MM-DD"),
    timezone: str = Query("America/New_York"),
):
    state = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
    log.info("availability/by-state called — state=%s date=%s", state, date)

    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    matched_types = get_allowed_types(types_resp.json(), state)

    if not matched_types:
        return {
            "state":   state,
            "date":    date,
            "message": "No 50-minute Psychological Evaluation types found",
            "slots":   []
        }

    cal_to_types_list = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            cal_to_types_list[cal_id].append({
                "appointmentTypeID": apt_type["id"],
                "schedulingUrl":     apt_type.get("schedulingUrl", ""),
                "typeName":          apt_type.get("name", ""),
            })

    async with httpx.AsyncClient(timeout=20) as client:
        tasks     = []
        task_meta = []
        for cal_id, type_infos in cal_to_types_list.items():
            for info in type_infos:
                tasks.append(
                    client.get(
                        f"{ACUITY_BASE}/availability/times",
                        headers=acuity_headers(),
                        params={
                            "appointmentTypeID": info["appointmentTypeID"],
                            "calendarID":        cal_id,
                            "date":              date,
                            "timezone":          timezone,
                        }
                    )
                )
                task_meta.append((cal_id, info))
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    therapist_slots = {}
    seen_slots      = set()

    for i, resp in enumerate(responses):
        cal_id, info = task_meta[i]
        if isinstance(resp, Exception) or resp.status_code != 200:
            continue
        for slot in resp.json():
            if slot.get("slotsAvailable", 0) < 1:
                continue
            slot_key = (cal_id, slot["time"])
            if slot_key in seen_slots:
                continue
            seen_slots.add(slot_key)

            if cal_id not in therapist_slots:
                therapist_slots[cal_id] = {
                    "calendarID":    cal_id,
                    "therapistName": extract_doctor_name(info["typeName"]),
                    "typeName":      info["typeName"],
                    "bookingUrl":    info["schedulingUrl"],
                    "typeID":        info["appointmentTypeID"],
                    "slots":         [],
                    "totalSlots":    0,
                }
            therapist_slots[cal_id]["slots"].append({
                "time":          slot["time"],
                "calendarID":    cal_id,
                "bookingUrl":    info["schedulingUrl"],
                "typeID":        info["appointmentTypeID"],
                "therapistName": extract_doctor_name(info["typeName"]),
            })
            therapist_slots[cal_id]["totalSlots"] += 1

    for cal_id in therapist_slots:
        therapist_slots[cal_id]["slots"].sort(key=lambda x: x["time"])

    therapist_list = list(therapist_slots.values())
    random.shuffle(therapist_list)

    time_buckets = defaultdict(list)
    for therapist in therapist_list:
        for slot in therapist["slots"]:
            time_buckets[slot["time"]].append(slot)

    all_slots = []
    for time_key in sorted(time_buckets.keys()):
        all_slots.extend(time_buckets[time_key])

    all_known = set(STATE_KEYWORDS.keys()) | NON_PSYPACT_STATES
    if state in NON_PSYPACT_STATES:
        pool = "state-specific"
    elif state in all_known:
        pool = "psypact"
    else:
        pool = "all"

    return {
        "state":          state,
        "date":           date,
        "timezone":       timezone,
        "pool":           pool,
        "totalSlots":     len(all_slots),
        "matchedTypes":   len(matched_types),
        "totalCalendars": len(therapist_slots),
        "therapists":     therapist_list,
        "slots":          all_slots
    }


@app.get("/availability/dates-by-state", tags=["Availability"])
async def availability_dates_by_state(
    state:    str           = Query(..., description="US state name, or any value for outside US"),
    month:    Optional[str] = Query(None, description="YYYY-MM. Defaults to current month"),
    timezone: str           = Query("America/New_York"),
):
    if not month:
        month = datetime.now().strftime("%Y-%m")

    state = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
    log.info("availability/dates-by-state called — state=%s month=%s", state, month)

    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    # ★ FIXED — uses get_allowed_types (hardcoded map) not get_matched_types
    matched_types = get_allowed_types(types_resp.json(), state)

    if not matched_types:
        return {"state": state, "month": month, "dates": []}

    cal_to_typeids = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            cal_to_typeids[cal_id].append(apt_type["id"])

    if not cal_to_typeids:
        return {"state": state, "month": month, "dates": []}

    async with httpx.AsyncClient(timeout=20) as client:
        tasks = []
        for cal_id, type_ids in cal_to_typeids.items():
            for type_id in type_ids:
                tasks.append(
                    client.get(
                        f"{ACUITY_BASE}/availability/dates",
                        headers=acuity_headers(),
                        params={
                            "appointmentTypeID": type_id,
                            "calendarID":        cal_id,
                            "month":             month,
                            "timezone":          timezone,
                        }
                    )
                )
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    all_dates: set = set()
    for resp in responses:
        if isinstance(resp, Exception) or resp.status_code != 200:
            continue
        for d in resp.json():
            if d.get("date"):
                all_dates.add(d["date"])

    return {
        "state":    state,
        "month":    month,
        "timezone": timezone,
        "dates":    [{"date": d} for d in sorted(all_dates)]
    }


# ==================================================
# ADMIN / DEBUG
# ==================================================

@app.get("/admin/test-caspio", tags=["Admin"])
async def test_caspio():
    try:
        headers = await caspio_headers()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                params={"q.limit": 1}
            )
        return {
            "caspio_token":      "ok",
            "table_name":        CASPIO_TABLE,
            "table_ping_status": resp.status_code,
            "table_ping_body":   resp.json()
        }
    except Exception as e:
        return {"error": str(e)}


@app.get("/admin/debug-types", tags=["Admin"])
async def debug_types(state: Optional[str] = Query(None)):
    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    all_types = types_resp.json()

    passed, failed = [], []
    for t in all_types:
        category = t.get("category", "").upper()
        duration  = t.get("duration")
        reasons   = []

        if PSYCH_EVAL_CATEGORY_KEYWORD not in category:
            reasons.append(f"category missing 'PSYCHOLOGICAL EVALUATION': {t.get('category')}")
        try:
            if int(duration) != ALLOWED_DURATION:
                reasons.append(f"duration {duration} != 50")
        except Exception:
            reasons.append(f"invalid duration: {duration}")
        if not t.get("calendarIDs"):
            reasons.append("no calendarIDs assigned")

        entry = {
            "id":        t["id"],
            "name":      t.get("name", ""),
            "category":  t.get("category", ""),
            "duration":  duration,
            "calendars": t.get("calendarIDs", []),
        }
        if reasons:
            entry["filtered_reason"] = reasons
            failed.append(entry)
        else:
            if state:
                entry["route"]           = _route_type(t)
                entry["is_non_psypact"]  = _route_type(t).startswith("non_psypact")
                entry["in_psypact_pool"] = _route_type(t) == "psypact"
                entry["in_state_map"]    = t["id"] in [
                    int(x) for x in STATE_TYPE_IDS.get(state, "").split(",") if x.strip()
                ]
            passed.append(entry)

    matched = get_allowed_types(all_types, state) if state else []

    return {
        "total_types":        len(all_types),
        "passed_base_filter": len(passed),
        "failed_base_filter": len(failed),
        "matched_for_state":  len(matched) if state else "no state provided",
        "passed":             passed,
        "failed":             failed,
    }


@app.get("/states/psypact-check", tags=["Configuration"])
async def psypact_check(state: str = Query(...)):
    all_known = set(STATE_KEYWORDS.keys()) | NON_PSYPACT_STATES
    if state in NON_PSYPACT_STATES:
        pool = "state-specific"
    elif state in all_known:
        pool = "psypact"
    else:
        pool = "all (outside US)"
    type_ids = STATE_TYPE_IDS.get(state, "not in map")
    return {"state": state, "pool": pool, "assigned_type_ids": type_ids}


@app.get("/admin/debug-appointment/{appointment_id}", tags=["Admin"])
async def debug_appointment(appointment_id: int):
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments/{appointment_id}",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    data = resp.json()
    return {
        "id":        data.get("id"),
        "forms":     data.get("forms", []),
        "formsText": data.get("formsText", ""),
        "notes":     data.get("notes", ""),
    }
