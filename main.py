import os
import base64
import hmac
import hashlib
import logging
from collections import deque
from datetime import datetime
import random
from typing import Optional, List

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

CASPIO_BASE_URL       = os.getenv("CASPIO_BASE_URL")       # for token
CASPIO_API_BASE_URL   = os.getenv("CASPIO_API_BASE_URL")   # for records
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
    version="2.1.0"
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

recent_webhooks     = deque(maxlen=500)   # auto-drops old entries
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
    calendarID: Optional[int]  = None
    datetime: str
    timezone: Optional[str]    = "America/New_York"


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
        "Content-Type": "application/json"
    }


# --------------------------------------------------
# SECURITY HELPERS
# --------------------------------------------------

def verify_acuity_signature(raw_body: bytes, signature: Optional[str]) -> bool:
    if not ACUITY_WEBHOOK_SECRET:
        return True                # skip if secret not configured
    if not signature:
        return False
    expected = hmac.new(
        ACUITY_WEBHOOK_SECRET.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


# --------------------------------------------------
# REFERRAL ID HELPER
# --------------------------------------------------

def extract_referral_id(appointment: dict):
    """Extract referral_id from Acuity appointment forms by field ID 18222169."""
    for form in appointment.get("forms", []):
        for field in form.get("values", []):
            # match by field ID (most reliable) or name as fallback
            if field.get("fieldID") == 18222169 or field.get("name", "").lower() == "referral_id":
                val = field.get("value", "")
                try:
                    return int(val) if val else None
                except (ValueError, TypeError):
                    return None
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
    "referral_id": int(extract_referral_id(appointment)) if extract_referral_id(appointment) else None,
    "calender_link":                   appointment.get("confirmationPage", ""),
    "confirmation_page_payment_link":  appointment.get("confirmationPagePaymentLink", ""),
    "link_to_clients_confirm":         appointment.get("confirmationPage", ""),
    "amount_paid":                     float(appointment.get("amountPaid", 0)),
    "has_been_paid":                   appointment.get("paid", "no"),
    "price_of_appointment":            float(appointment.get("price", 0)),
    "price_sold":                      str(appointment.get("priceSold", "")),
    "client_time_zone":                appointment.get("timezone", ""),
    "calendar_timezone":               appointment.get("calendarTimezone", ""),
    # ★ REMOVED: added_on, date_created, datetime_created, datetime, PK_ID, ID
    # These are auto-generated by Caspio — never write to them
}

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            check = await client.get(
                f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                params={"q.where": f"appointment_id={apt_id}", "q.limit": 1}
            )
            log.info("Caspio check status: %s body: %s", check.status_code, check.text[:200])
            existing = check.json().get("Result", [])
        except Exception as e:
            log.error("Caspio check failed: %s", e)
            return

        try:
            if existing:
                resp = await client.put(
                    f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                    headers=headers,
                    params={"q.where": f"appointment_id={apt_id}"},
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
            params={"q.where": f"appointment_id={apt_id}"},
            json={
                "status":      "Canceled",        # ✅ lowercase to match Caspio column
                "updated_on":  datetime.utcnow().isoformat()
            }
        )
    log.info("Caspio marked appointment ID %s as canceled", apt_id)


# ==================================================
# ROUTES
# ==================================================

# --------------------------------------------------
# HEALTH + ROOT
# --------------------------------------------------

@app.get("/", tags=["Health"])
async def root():
    return {"service": "acuity-caspio-proxy", "status": "running"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "time": datetime.utcnow()}


# --------------------------------------------------
# CONFIGURATION ENDPOINTS
# --------------------------------------------------

@app.get("/appointment-types", tags=["Configuration"])
async def get_appointment_types(
    calendarID: Optional[int] = Query(None, description="Filter by calendar ID")
):
    """List all appointment types (raw passthrough from Acuity — no filtering applied here)."""
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
    """List all therapist calendars with their IDs. Use these IDs in availability calls."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/calendars",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch calendars")
    return resp.json()


@app.get("/appointment-addons", tags=["Configuration"])
async def get_appointment_addons():
    """List all add-ons available. Use addonIDs when booking appointments."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointment-addons",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, "Unable to fetch addons")
    return resp.json()


# --------------------------------------------------
# AVAILABILITY ENDPOINTS
# --------------------------------------------------

@app.get("/availability/dates", tags=["Availability"])
async def available_dates(
    appointmentTypeID: int           = Query(...,  description="Appointment type ID — get from /appointment-types"),
    month:             str           = Query(None, description="YYYY-MM format. Defaults to current month"),
    calendarID:        Optional[int] = Query(None, description="Specific therapist calendar ID"),
    timezone:          str           = Query("America/New_York", description="Timezone string"),
):
    """
    GET available dates for a calendar in a given month.
    Returns array of { date: YYYY-MM-DD } objects.
    """
    if not month:
        month = datetime.now().strftime("%Y-%m")

    params = {
        "appointmentTypeID": appointmentTypeID,
        "month":             month,
        "timezone":          timezone,
    }
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
    appointmentTypeID: int           = Query(..., description="Appointment type ID"),
    date:              str           = Query(..., description="YYYY-MM-DD format"),
    calendarID:        Optional[int] = Query(None, description="Specific therapist calendar ID"),
    timezone:          str           = Query("America/New_York"),
):
    """
    GET available time slots for a specific date.
    Returns array of { time, slotsAvailable } objects.
    """
    params = {
        "appointmentTypeID": appointmentTypeID,
        "date":              date,
        "timezone":          timezone,
    }
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
    appointmentTypeID:  Optional[int] = Query(None, description="Filter by appointment type"),
    calendarID:         Optional[int] = Query(None, description="Filter by calendar"),
    month:              Optional[str] = Query(None, description="YYYY-MM format"),
    includeUnavailable: bool          = Query(False, description="Include full/unavailable classes"),
    timezone:           str           = Query("America/New_York"),
):
    """GET available class/group session slots."""
    params = {
        "timezone":           timezone,
        "includeUnavailable": str(includeUnavailable).lower(),
    }
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
    """
    POST to verify a specific datetime slot is still available.
    Call this RIGHT BEFORE booking to avoid double-booking.
    """
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
    """
    Fetch available times for MULTIPLE therapist calendars at once.
    All requests fire in parallel — fast even with 10+ therapists.
    """
    async with httpx.AsyncClient(timeout=15) as client:
        tasks = [
            client.get(
                f"{ACUITY_BASE}/availability/times",
                headers=acuity_headers(),
                params={
                    "appointmentTypeID": body.appointmentTypeID,
                    "calendarID":        calendar_id,
                    "date":              body.date,
                    "timezone":          body.timezone
                }
            )
            for calendar_id in body.calendarIDs
        ]
        responses = await asyncio.gather(*tasks)

    results = []
    for i, resp in enumerate(responses):
        if resp.status_code == 200:
            results.append({
                "calendarID": body.calendarIDs[i],
                "slots":      resp.json()
            })
        else:
            results.append({
                "calendarID": body.calendarIDs[i],
                "slots":      [],
                "error":      "unable to fetch"
            })

    return {"date": body.date, "results": results}


# --------------------------------------------------
# APPOINTMENTS
# --------------------------------------------------

@app.get("/appointments", tags=["Appointments"])
async def get_appointments(
    minDate:           Optional[str]  = Query(None, description="Min date YYYY-MM-DD"),
    maxDate:           Optional[str]  = Query(None, description="Max date YYYY-MM-DD"),
    calendarID:        Optional[int]  = Query(None),
    appointmentTypeID: Optional[int]  = Query(None),
    canceled:          Optional[bool] = Query(None),
    max:               int            = Query(50, description="Max records to return"),
):
    """List appointments with optional filters."""
    params: dict = {"max": max}
    if minDate:              params["minDate"]            = minDate
    if maxDate:              params["maxDate"]            = maxDate
    if calendarID:           params["calendarID"]         = calendarID
    if appointmentTypeID:    params["appointmentTypeID"]  = appointmentTypeID
    if canceled is not None: params["canceled"]           = str(canceled).lower()

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
    """
    Book a new appointment. Syncs to Caspio automatically in background.
    Pass referral_id in the fields array to track it through to Caspio:

    {
      "appointmentTypeID": 999,
      "calendarID": 111,
      "datetime": "2025-03-15T10:00:00-0500",
      "firstName": "Jane",
      "lastName": "Doe",
      "email": "jane@example.com",
      "fields": [
        { "id": "YOUR_ACUITY_FIELD_ID", "value": "REF-12345" }
      ]
    }

    Get YOUR_ACUITY_FIELD_ID from GET /forms on the Acuity API.
    """
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
    """Get a single appointment by Acuity ID."""
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
    noEmail: bool = Query(False, description="Suppress cancellation email")
):
    """Cancel an appointment. Updates Caspio Status to Canceled."""
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
    """
    Reschedule to a new datetime. Updates Caspio with new date/time.
    Body: { "datetime": "2025-03-20T11:00:00-0500" }
    """
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
    """Get payment records for a specific appointment."""
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(
            f"{ACUITY_BASE}/appointments/{appointment_id}/payments",
            headers=acuity_headers()
        )
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()


# --------------------------------------------------
# WEBHOOK  (replaces Zapier)
# --------------------------------------------------

@app.post("/webhooks/acuity", tags=["Webhooks"])
async def acuity_webhook(
    request:            Request,
    background_tasks:   BackgroundTasks,
    x_acuity_signature: Optional[str] = Header(None)
):
    raw_body = await request.body()

    if not verify_acuity_signature(raw_body, x_acuity_signature):
        raise HTTPException(401, "Invalid webhook signature")

    # Acuity sends form-encoded data, not JSON
    try:
        from urllib.parse import parse_qs
        parsed = parse_qs(raw_body.decode("utf-8"))
        data = {k: v[0] for k, v in parsed.items()}
    except Exception as e:
        log.error("Failed to parse webhook body: %s | raw: %s", e, raw_body[:200])
        raise HTTPException(400, "Invalid payload")

    action = data.get("action")
    apt_id = data.get("id")

    log.info("Webhook parsed: action=%s id=%s", action, apt_id)

    if not apt_id:
        return {"status": "ignored", "reason": "no appointment id"}

    webhook_id = f"{action}_{apt_id}"
    if webhook_id in recent_webhooks:
        return {"status": "duplicate ignored"}
    recent_webhooks.append(webhook_id)

    log.info("Webhook received: action=%s id=%s", action, apt_id)

    if action == "scheduling.canceled":
        background_tasks.add_task(caspio_mark_canceled, int(apt_id))

    elif action in (
        "scheduling.scheduled",
        "scheduling.rescheduled",
        "scheduling.changed",
        "order.completed",
    ):
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{ACUITY_BASE}/appointments/{apt_id}",
                headers=acuity_headers()
            )
        if resp.status_code == 200:
            background_tasks.add_task(caspio_upsert_appointment, resp.json())
        else:
            log.error("Failed to fetch appointment %s for webhook sync", apt_id)

    return {"status": "processed", "action": action, "id": apt_id}

# ==================================================
# FILTERING CONSTANTS  (50-min Psych Eval only)
# ==================================================

# Matches category strings like:
#   "THRIVE CALIFORNIA: Psychological Evaluation"
#   "THRIVE NEW YORK: PSYCHOLOGICAL EVALUATION"
PSYCH_EVAL_CATEGORY_KEYWORD = "PSYCHOLOGICAL EVALUATION"

# Only 50-minute evaluations
ALLOWED_DURATION = 50

STATE_KEYWORDS = {
    "California":     ["CALIFORNIA"],
    "New York":       ["NEW YORK"],
    "Connecticut":    ["CONNECTICUT"],
    "Florida":        ["FLORIDA"],
    "Georgia":        ["GEORGIA"],
    "Illinois":       ["ILLINOIS"],
    "Maine":          ["MAINE"],
    "North Carolina": ["NORTH CAROLINA"],
    "Pennsylvania":   ["PENNSYLVANIA"],
    "Tennessee":      ["TENNESSEE"],
    "Texas":          ["TEXAS"],
    "Washington":     ["WASHINGTON"],
    "Wyoming":        ["WYOMING", "(WY)"],
    "Virginia":       ["VIRGINIA"],
    "Massachusetts":  ["MASSACHUSETTS"],
    "Ohio":           ["OHIO"],
    "Michigan":       ["MICHIGAN"],
    "Colorado":       ["COLORADO"],
    "Arizona":        ["ARIZONA"],
    "New Jersey":     ["NEW JERSEY"],
    "Maryland":       ["MARYLAND"],
    "Wisconsin":      ["WISCONSIN"],
    "Minnesota":      ["MINNESOTA"],
    "Indiana":        ["INDIANA"],
    "Missouri":       ["MISSOURI"],
    "Oklahoma":       ["OKLAHOMA"],
    "Louisiana":      ["LOUISIANA"],
    "Alabama":        ["ALABAMA"],
    "Kentucky":       ["KENTUCKY"],
    "South Carolina": ["SOUTH CAROLINA"],
    "Rhode Island":   ["RHODE ISLAND"],
    "Vermont":        ["VERMONT"],
}

ALL_STATES_KEYWORDS = ["ALL STATES", "THRIVE ONLINE"]


def is_50min_psych_eval(apt_type: dict) -> bool:
    """
    Returns True only for 50-minute Online Psychological Evaluations.

    Rules:
      - category must contain "PSYCHOLOGICAL EVALUATION"
      - duration must be exactly 50 minutes
      - must have at least one calendarID assigned (inactive/unassigned types are skipped)

    This approach is robust: new doctors added in Acuity are picked up automatically
    without any code changes, as long as they follow the same category naming pattern.
    """
    category = apt_type.get("category", "").upper()
    duration  = apt_type.get("duration")

    if PSYCH_EVAL_CATEGORY_KEYWORD not in category:
        return False

    if duration != ALLOWED_DURATION:
        return False

    if not apt_type.get("calendarIDs"):
        return False

    return True


def matches_state(apt_type: dict, state: str) -> bool:
    """Returns True if this appointment type serves the given state."""
    cat  = apt_type.get("category", "").upper()
    name = apt_type.get("name", "").upper()

    keywords = STATE_KEYWORDS.get(state, [state.upper()])
    for kw in keywords:
        if kw.upper() in cat or kw.upper() in name:
            return True
    return False


def is_all_states(apt_type: dict) -> bool:
    """Returns True if this appointment type serves all states."""
    cat = apt_type.get("category", "").upper()
    for kw in ALL_STATES_KEYWORDS:
        if kw.upper() in cat:
            return True
    return False


# ==================================================
# STATE-BASED AVAILABILITY ROUTES
# ==================================================
def extract_doctor_name(type_name: str) -> str:
    """Extract doctor name from appointment type name.
    e.g. 'Thrive Santa Monica: 50 Minute Online Psychological Evaluation with Dr. Tamara Rumburg'
    → 'Dr. Tamara Rumburg'
    """
    if " with " in type_name:
        return type_name.split(" with ")[-1].strip()
    return type_name
@app.get("/availability/by-state", tags=["Availability"])
async def availability_by_state(
    state:    str = Query(..., description="Full state name e.g. 'California', 'New York'"),
    date:     str = Query(..., description="YYYY-MM-DD"),
    timezone: str = Query("America/New_York"),
):
    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    all_types = types_resp.json()

    state_types = [
        t for t in all_types
        if is_50min_psych_eval(t) and matches_state(t, state)
    ]
    all_states_types = [
        t for t in all_types
        if is_50min_psych_eval(t) and is_all_states(t)
    ]

    matched_types = state_types if state_types else all_states_types
    if state_types and all_states_types:
        existing_ids = {t["id"] for t in state_types}
        for t in all_states_types:
            if t["id"] not in existing_ids:
                matched_types.append(t)

    if not matched_types:
        return {
            "state":   state,
            "date":    date,
            "message": "No 50-minute Psychological Evaluation types found for this state",
            "slots":   [],
            "therapists": []
        }

    calendar_type_map = {}
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            if cal_id not in calendar_type_map:
                calendar_type_map[cal_id] = {
                    "appointmentTypeID": apt_type["id"],
                    "schedulingUrl":     apt_type.get("schedulingUrl", ""),
                    "typeName":          apt_type.get("name", ""),
                }

    async with httpx.AsyncClient(timeout=20) as client:
        cal_ids = list(calendar_type_map.keys())
        tasks = [
            client.get(
                f"{ACUITY_BASE}/availability/times",
                headers=acuity_headers(),
                params={
                    "appointmentTypeID": calendar_type_map[cal_id]["appointmentTypeID"],
                    "calendarID":        cal_id,
                    "date":              date,
                    "timezone":          timezone,
                }
            )
            for cal_id in cal_ids
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

    # Build per-therapist slot groups
    therapist_slots = {}
    for i, resp in enumerate(responses):
        cal_id = cal_ids[i]
        info   = calendar_type_map[cal_id]
        if isinstance(resp, Exception) or resp.status_code != 200:
            continue

        slots = []
        for slot in resp.json():
            if slot.get("slotsAvailable", 0) < 1:
                continue
            slots.append({
                "time":          slot["time"],
                "calendarID":    cal_id,
                "bookingUrl":    info["schedulingUrl"],
                "typeID":        info["appointmentTypeID"],
                "therapistName": extract_doctor_name(info["typeName"]),
            })

        if slots:
            therapist_slots[cal_id] = {
                "calendarID":    cal_id,
                "therapistName": extract_doctor_name(info["typeName"]),
                "typeName":      info["typeName"],
                "bookingUrl":    info["schedulingUrl"],
                "typeID":        info["appointmentTypeID"],
                "slots":         sorted(slots, key=lambda x: x["time"]),
                "totalSlots":    len(slots),
            }

    # Shuffle therapist order on every request
    therapist_list = list(therapist_slots.values())
    random.shuffle(therapist_list)

    # ★ Interleave slots by time across therapists so same-time
    # slots from different therapists are mixed, not blocked together
    # e.g. 9am-BeverlyIbeh, 9am-MeganCannon, 10am-BeverlyIbeh ...
    from collections import defaultdict
    time_buckets = defaultdict(list)
    for therapist in therapist_list:
        for slot in therapist["slots"]:
            time_buckets[slot["time"]].append(slot)

    # Within each time bucket therapists are already shuffled above
    # so just flatten sorted by time
    all_slots = []
    for time_key in sorted(time_buckets.keys()):
        all_slots.extend(time_buckets[time_key])

    return {
        "state":          state,
        "date":           date,
        "timezone":       timezone,
        "totalSlots":     len(all_slots),
        "matchedTypes":   len(matched_types),
        "totalCalendars": len(therapist_slots),
        "therapists":     therapist_list,  # grouped view — use in Caspio to show per-therapist
        "slots":          all_slots        # flat interleaved view — shuffled within each time
    }

@app.get("/availability/dates-by-state", tags=["Availability"])
async def availability_dates_by_state(
    state:    str           = Query(..., description="Full state name"),
    month:    Optional[str] = Query(None, description="YYYY-MM. Defaults to current month"),
    timezone: str           = Query("America/New_York"),
):
    """
    Get available DATES for 50-min Psych Evals in a state for a given month.
    Caspio calls this first to show date chips to the patient.

    Example:
      /availability/dates-by-state?state=New York&month=2026-04
      /availability/dates-by-state?state=California&month=2026-04
    """
    if not month:
        month = datetime.now().strftime("%Y-%m")

    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    all_types = types_resp.json()

    state_types = [
        t for t in all_types
        if is_50min_psych_eval(t) and matches_state(t, state)
    ]
    all_states_types = [
        t for t in all_types
        if is_50min_psych_eval(t) and is_all_states(t)
    ]

    matched_types = state_types if state_types else all_states_types
    if state_types and all_states_types:
        existing_ids = {t["id"] for t in state_types}
        for t in all_states_types:
            if t["id"] not in existing_ids:
                matched_types.append(t)

    calendar_type_map = {}
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            if cal_id not in calendar_type_map:
                calendar_type_map[cal_id] = apt_type["id"]

    if not calendar_type_map:
        return {"state": state, "month": month, "dates": []}

    async with httpx.AsyncClient(timeout=20) as client:
        cal_ids = list(calendar_type_map.keys())
        tasks = [
            client.get(
                f"{ACUITY_BASE}/availability/dates",
                headers=acuity_headers(),
                params={
                    "appointmentTypeID": calendar_type_map[cal_id],
                    "calendarID":        cal_id,
                    "month":             month,
                    "timezone":          timezone,
                }
            )
            for cal_id in cal_ids
        ]
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

#Temporary code..
@app.get("/admin/test-caspio", tags=["Admin"])
async def test_caspio():
    """Test Caspio connection and return token status."""
    try:
        token = await get_caspio_token()
        headers = await caspio_headers()
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{CASPIO_API_BASE_URL}/v2/tables/{CASPIO_TABLE}/records",
                headers=headers,
                params={"q.limit": 1}
            )
        return {
            "caspio_token": "ok",
            "table_ping_status": resp.status_code,
            "table_ping_body": resp.json()
        }
    except Exception as e:
        return {"error": str(e)}
    


@app.post("/webhooks/acuity", tags=["Webhooks"])
async def acuity_webhook(
    request:            Request,
    background_tasks:   BackgroundTasks,
    x_acuity_signature: Optional[str] = Header(None)
):
    raw_body = await request.body()
    log.info("Webhook raw body: %s", raw_body[:200])
    log.info("Webhook signature header: %s", x_acuity_signature)