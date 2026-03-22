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

CASPIO_BASE_URL       = os.getenv("CASPIO_BASE_URL")        # token endpoint base
CASPIO_API_BASE_URL   = os.getenv("CASPIO_API_BASE_URL")    # records endpoint base
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
    version="3.0.0"
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
    timezone: Optional[str]   = "America/New_York"


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
    # Disabled — Acuity signing key not available in UI
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
                    log.info("referral_id extracted: %s", val)  # ← add this
                    return val

    forms_text = appointment.get("formsText", "")
    if forms_text:
        match = re.search(r"referral_id:\s*(\S+)", forms_text, re.IGNORECASE)
        if match:
            val = match.group(1).strip()
            if val and len(val) < 100:
                log.info("referral_id extracted via formsText: %s", val)  # ← add this
                return val

    log.warning("referral_id not found in appointment %s", appointment.get("id"))
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
    "appointment_id":                  str(apt_id),          # ★ Text field — use str not int
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
    "calender_link":                   appointment.get("confirmationPage", ""),
    "confirmation_page_payment_link":  appointment.get("confirmationPagePaymentLink", ""),
    "link_to_clients_confirm":         appointment.get("confirmationPage", ""),
    "amount_paid":                     float(appointment.get("amountPaid", 0)),
    "has_been_paid":                   appointment.get("paid", "no"),
    "price_of_appointment":            float(appointment.get("price", 0)),
    "price_sold":                      str(appointment.get("priceSold", "")),
    "client_time_zone":                appointment.get("timezone", ""),
    "calendar_timezone":               appointment.get("calendarTimezone", ""),
    # ★ REMOVED: added_on, updated_on — both Timestamp, auto-managed by Caspio
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
            json={
                "status":     "Canceled",
                "updated_on": datetime.utcnow().isoformat()
            }
        )
    log.info("Caspio marked appointment ID %s as canceled", apt_id)


# ==================================================
# ROUTES
# ==================================================

# --------------------------------------------------
# HEALTH
# --------------------------------------------------

@app.get("/", tags=["Health"])
async def root():
    return {"service": "acuity-caspio-proxy", "status": "running", "version": "3.0.0"}


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "time": datetime.utcnow()}


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

@app.get("/appointment-types", tags=["Configuration"])
async def get_appointment_types(
    calendarID: Optional[int] = Query(None)
):
    """Raw passthrough — returns all Acuity appointment types unfiltered."""
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
    """Get all Acuity form fields and their IDs."""
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
    """
    Book a new appointment. Pass referral_id via fields array:
    { ..., "fields": [{ "id": 18222169, "value": "ZDHMRJPJ" }] }
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
    """Body: { "datetime": "2025-03-20T11:00:00-0500" }"""
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
    """
    Register this URL in Acuity → Integrations → Webhooks.
    Acuity sends form-encoded POST — handled correctly here.

    Events:
      scheduling.scheduled   → INSERT into Caspio
      scheduling.rescheduled → UPDATE in Caspio
      scheduling.changed     → UPDATE in Caspio
      scheduling.canceled    → Mark Canceled in Caspio
      order.completed        → UPDATE in Caspio
    """
    raw_body = await request.body()
    log.info("Webhook raw body: %s", raw_body[:300])

    if not verify_acuity_signature(raw_body, x_acuity_signature):
        raise HTTPException(401, "Invalid webhook signature")

    # Acuity sends application/x-www-form-urlencoded — NOT JSON
    # Accept both form-encoded (real Acuity) and JSON (manual curl testing)
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

    # Deduplicate
    webhook_id = f"{action}_{apt_id}"
    if webhook_id in recent_webhooks:
        return {"status": "duplicate ignored"}
    recent_webhooks.append(webhook_id)

    log.info("Webhook received: action=%s id=%s", action, apt_id)

    if action == "scheduling.canceled":
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
    ):
        try:
            # ★ Wait 3 seconds — gives Acuity time to save form data
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

# States shown with THEIR OWN therapists only (not pooled)
NON_PSYPACT_STATES = {
    "New York",
    "Hawaii",
    "Iowa",
    "Alaska",
    "Oregon",
    "New Mexico",
    "Louisiana",
    "California",
    "Massachusetts",
}

# Keywords per state — used for both non-PSYPACT filtering
# and for excluding non-PSYPACT types from the PSYPACT pool
STATE_KEYWORDS = {
    "California":           ["CALIFORNIA", "SANTA MONICA"],
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


def is_50min_psych_eval(apt_type: dict) -> bool:
    """
    Core filter:
    - Category must contain 'PSYCHOLOGICAL EVALUATION'
    - Duration must be exactly 50 (handles string or int)
    - Must have at least one calendarID assigned
    """
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
    """True if type's category or name contains any keyword for the given state."""
    cat  = apt_type.get("category", "").upper()
    name = apt_type.get("name", "").upper()
    for kw in STATE_KEYWORDS.get(state, [state.upper()]):
        if kw.upper() in cat or kw.upper() in name:
            return True
    return False


def is_non_psypact_type(apt_type: dict) -> bool:
    """True if this type is specific to a non-PSYPACT state."""
    for state in NON_PSYPACT_STATES:
        if matches_state(apt_type, state):
            return True
    return False


def get_matched_types(all_types: list, state: str) -> list:
    """
    Three-way routing:

    1. NON-PSYPACT state (CA, NY, IA etc.)
       → only types matching that specific state

    2. PSYPACT / other US state
       → all types NOT belonging to a non-PSYPACT state
       → includes: generic 'THRIVE: Psychological Evaluation' types
       → includes: Indiana, DC, PA, TX specific types
       → excludes: CA, NY, IA, OR etc.

    3. Outside US (any unrecognized location)
       → ALL 50-min psych eval types, no filter
    """
    eligible = [t for t in all_types if is_50min_psych_eval(t)]

    # Case 1 — non-PSYPACT state
    if state in NON_PSYPACT_STATES:
        return [t for t in eligible if matches_state(t, state)]

    # Case 2 — known US state → PSYPACT pool
    all_known_states = set(STATE_KEYWORDS.keys()) | NON_PSYPACT_STATES
    if state in all_known_states:
        return [t for t in eligible if not is_non_psypact_type(t)]

    # Case 3 — outside US or unrecognized → all therapists
    return eligible

def pick_best_type(types_for_calendar: list, state: str) -> dict:
    """
    When multiple appointment types share the same calendarID,
    pick the most state-relevant one:
    1. Exact state match (e.g. THRIVE INDIANA for Indiana query)
    2. Generic THRIVE: type (no state)
    3. Any other PSYPACT type
    """
    # Priority 1 — exact state match
    for t in types_for_calendar:
        if matches_state(t, state):
            return t
    # Priority 2 — generic THRIVE: type
    for t in types_for_calendar:
        if t.get("category", "").upper().strip() == "THRIVE: PSYCHOLOGICAL EVALUATION":
            return t
    # Priority 3 — first available
    return types_for_calendar[0]

def extract_doctor_name(type_name: str) -> str:
    """'...with Dr. Tamara Rumburg' → 'Dr. Tamara Rumburg'"""
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
    """
    ★ MAIN CASPIO ENDPOINT

    Routing:
    - Non-PSYPACT (CA, NY, IA etc.) → state-specific therapists only
    - PSYPACT state (Indiana, TX etc.) → full PSYPACT therapist pool
    - Outside US → all therapists, no filter

    Response includes 'pool' field: 'state-specific' | 'psypact' | 'all'
    """
    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    matched_types = get_matched_types(types_resp.json(), state)

    if not matched_types:
        return {
            "state":   state,
            "date":    date,
            "message": "No 50-minute Psychological Evaluation types found",
            "slots":   []
        }

    # Build calendarID → LIST of all type infos
    # Query ALL types per calendar so we catch availability regardless
    # of which type the therapist configured their schedule against
    cal_to_types_list = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            cal_to_types_list[cal_id].append({
                "appointmentTypeID": apt_type["id"],
                "schedulingUrl":     apt_type.get("schedulingUrl", ""),
                "typeName":          apt_type.get("name", ""),
            })

    # Fetch times for ALL types per calendar in parallel
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

    # Build per-therapist slot groups
    # seen_slots deduplicates same (calendarID + time) across multiple types
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
                continue  # already found this time from another type
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

    # Sort each therapist's slots by time
    for cal_id in therapist_slots:
        therapist_slots[cal_id]["slots"].sort(key=lambda x: x["time"])

    # Shuffle therapist order on every request
    therapist_list = list(therapist_slots.values())
    random.shuffle(therapist_list)

    # Interleave by time — within same timeslot therapists are shuffled
    time_buckets = defaultdict(list)
    for therapist in therapist_list:
        for slot in therapist["slots"]:
            time_buckets[slot["time"]].append(slot)

    all_slots = []
    for time_key in sorted(time_buckets.keys()):
        all_slots.extend(time_buckets[time_key])

    # Determine pool label
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
    """
    Get available DATES for 50-min Psych Evals. Same routing as /availability/by-state.
    Caspio calls this first to show date chips to the patient.
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

    matched_types = get_matched_types(types_resp.json(), state)

    if not matched_types:
        return {"state": state, "month": month, "dates": []}

    # Build calendarID → LIST of all typeIDs
    # Query ALL types per calendar — same reason as by-state above
    cal_to_typeids = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in apt_type.get("calendarIDs", []):
            cal_to_typeids[cal_id].append(apt_type["id"])

    if not cal_to_typeids:
        return {"state": state, "month": month, "dates": []}

    # Fetch dates for ALL types per calendar in parallel
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
    """Test Caspio token and table connectivity."""
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
    """Show which types pass the 50-min psych eval filter and why others fail."""
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
            "id":       t["id"],
            "name":     t.get("name", ""),
            "category": t.get("category", ""),
            "duration": duration,
            "calendars": t.get("calendarIDs", []),
        }
        if reasons:
            entry["filtered_reason"] = reasons
            failed.append(entry)
        else:
            if state:
                entry["matches_state"]   = matches_state(t, state)
                entry["is_non_psypact"]  = is_non_psypact_type(t)
                entry["in_psypact_pool"] = not is_non_psypact_type(t)
            passed.append(entry)

    matched = get_matched_types(all_types, state) if state else []

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
    """Check routing pool for a given state."""
    all_known = set(STATE_KEYWORDS.keys()) | NON_PSYPACT_STATES
    if state in NON_PSYPACT_STATES:
        pool = "state-specific"
    elif state in all_known:
        pool = "psypact"
    else:
        pool = "all (outside US)"
    return {"state": state, "pool": pool}

@app.get("/admin/debug-appointment/{appointment_id}", tags=["Admin"])
async def debug_appointment(appointment_id: int):
    """Show raw forms data from Acuity for debugging referral_id extraction."""
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