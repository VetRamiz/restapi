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
    version="7.1.0"
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
    return {"service": "acuity-caspio-proxy", "status": "running", "version": "7.1.0"}


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
# FILTERING  —  v6.0.0
# ==================================================
#
# TWO appointment-type families are supported, selected via ?appt_type=
#
#   "psych"    (default) — legacy 50-min Psych Eval, manual STATE_TYPE_IDS map
#   "fertility"          — new Fertility Eval, fully dynamic category-based routing
#
# ── SHARED CONSTANTS ──────────────────────────────────────────────────────────

PSYCH_EVAL_CATEGORY_KEYWORD = "PSYCHOLOGICAL EVALUATION"

# Test types — excluded from ALL families regardless of category.
# Detected by name prefix "(TEST" — no hard-coded IDs needed going forward,
# but legacy IDs kept for safety.
TEST_TYPE_IDS: set = {
    90824033, 90822425, 90822613, 90822881, 90826017, 90827405,
}

def _is_test_type(apt_type: dict) -> bool:
    name = apt_type.get("name", "")
    return apt_type.get("id") in TEST_TYPE_IDS or name.strip().startswith("(TEST")

# ── ALL US STATES (canonical names) ───────────────────────────────────────────
ALL_US_STATES: set = {
    "Alabama","Alaska","Arizona","Arkansas","California","Colorado",
    "Connecticut","Delaware","Florida","Georgia","Hawaii","Idaho",
    "Illinois","Indiana","Iowa","Kansas","Kentucky","Louisiana",
    "Maine","Maryland","Massachusetts","Michigan","Minnesota",
    "Mississippi","Missouri","Montana","Nebraska","Nevada",
    "New Hampshire","New Jersey","New Mexico","New York",
    "North Carolina","North Dakota","Ohio","Oklahoma","Oregon",
    "Pennsylvania","Rhode Island","South Carolina","South Dakota",
    "Tennessee","Texas","Utah","Vermont","Virginia","Washington",
    "West Virginia","Wisconsin","Wyoming","District of Columbia",
}
_STATE_UPPER_MAP: dict = {s.upper(): s for s in ALL_US_STATES}

# PSYPACT compact states — therapists with this licence show here.
# Florida and Washington are PSYPACT compact; they ALSO get state-specific
# non-PSYPACT therapists on top (via THRIVE FLORIDA / THRIVE WASHINGTON category).
PSYPACT_COMPACT_STATES: set = {
    "Alabama","Arkansas","Arizona","Colorado","Connecticut","Delaware",
    "District of Columbia","Florida","Georgia","Idaho","Illinois","Indiana",
    "Kansas","Kentucky","Maine","Maryland","Massachusetts","Michigan",
    "Minnesota","Mississippi","Missouri","Montana","Nebraska","Nevada",
    "New Hampshire","New Jersey","North Carolina","North Dakota","Ohio",
    "Oklahoma","Pennsylvania","Rhode Island","South Carolina","South Dakota",
    "Tennessee","Utah","Vermont","Virginia","Washington","West Virginia",
    "Wisconsin","Wyoming",
}

# Non-PSYPACT states (for pool label in API response)
NON_PSYPACT_STATES: set = ALL_US_STATES - PSYPACT_COMPACT_STATES
# = California, Iowa, Texas, New York, Hawaii, Alaska, Oregon,
#   New Mexico, Louisiana, Massachusetts + any future additions

# State name normaliser — lower-case → canonical
STATE_NORMALIZER: dict = {s.lower(): s for s in ALL_US_STATES}

# ── CALENDAR OVERRIDES ────────────────────────────────────────────────────────
# Acuity sometimes returns calendarIDs=[] for a type that has real availability.
# Override map: { type_id (int) → [calendar_id, ...] }
# Source: confirmed from direct Acuity booking URLs /calendar/{ID}.
# An override of [] means "intentionally excluded — keep dropped even if Acuity
# later assigns a calendar".
CALENDAR_OVERRIDES: dict = {
    44643246: [7083363],  # Dr. Beverly Ibeh — CA psych eval
    60953633: [],         # Dr. Emily Hu — Iowa psych eval (no calendar)
    60953734: [],         # Dr. Emily Hu — Texas psych eval (no calendar)
    75935569: [],         # Dr. Chemarum — generic (no calendar)
    49484128: [],         # Dr. Toni Leo — generic (no calendar)
}

def resolve_calendar_ids(apt_type: dict) -> list:
    """Return effective calendarIDs, applying CALENDAR_OVERRIDES if present."""
    tid = apt_type.get("id")
    if tid in CALENDAR_OVERRIDES:
        overridden = CALENDAR_OVERRIDES[tid]
        if overridden != apt_type.get("calendarIDs", []):
            log.info("CALENDAR_OVERRIDE type=%s %s→%s",
                     tid, apt_type.get("calendarIDs"), overridden)
        return overridden
    return apt_type.get("calendarIDs", [])


# ==================================================
# FAMILY 1 — PSYCH EVAL  (manual map, 50-min only)
# ==================================================
#
# Routing is controlled by STATE_TYPE_IDS.
# Add a new therapist: add their type ID to the correct string below + redeploy.
#
# Map semantics:
#   str value  → comma-separated allowed type IDs
#   ""         → state known, no therapists yet → returns []
#   (absent)   → international → returns all eligible types
# ──────────────────────────────────────────────────────────────────────────────

PSYCH_EVAL_ALLOWED_DURATION = 50

_PE_PSYPACT: str = (
    "74804055,"   # Dr. Jennifer Alpert — Eastern Time
    "75932446,"   # Dr. Courtney Cook
    "81046199,"   # Dr. Bethany Young
    "81046572,"   # Dr. Danielle Powers
    "84889378,"   # Dr. Yessenia Castillo
    "88803811,"   # Dr. Jacqueline Herrera
    "74926724,"   # Dr. Jennifer Alpert — generic PSYPACT
    "58693634"    # Dr. Charlynn Ruan — generic PSYPACT
)
_PE_CA: str = (
    "67331536,"   # Dr. Tamara Rumburg
    "52823893,"   # Dr. Megan Cannon — CA ONLY
    "55211731,"   # Dr. Emily Hu
    "37231009,"   # Dr. Charlynn Ruan
    "44643246"    # Dr. Beverly Ibeh
)
_PE_IOWA:  str = "72914876,55554634"
_PE_TEXAS: str = "55554566"
_PE_DC:    str = f"74542331,{_PE_PSYPACT}"
_PE_IN:    str = f"73689906,{_PE_PSYPACT}"
_PE_PA:    str = f"73062970,{_PE_PSYPACT}"

STATE_TYPE_IDS: dict = {
    "California":    _PE_CA,
    "Iowa":          _PE_IOWA,
    "Texas":         _PE_TEXAS,
    "New York":      "", "Hawaii": "", "Alaska": "", "Oregon": "",
    "New Mexico":    "", "Louisiana": "", "Massachusetts": "",
    "District of Columbia": _PE_DC,
    "Indiana":       _PE_IN,
    "Pennsylvania":  _PE_PA,
    **{s: _PE_PSYPACT for s in PSYPACT_COMPACT_STATES
       if s not in ("District of Columbia", "Indiana", "Pennsylvania")},
}


def _is_psych_eval_eligible(apt_type: dict) -> bool:
    """Base filter for the Psych Eval family."""
    cat = apt_type.get("category", "").upper()
    if PSYCH_EVAL_CATEGORY_KEYWORD not in cat:
        return False
    try:
        if int(apt_type.get("duration", 0)) != PSYCH_EVAL_ALLOWED_DURATION:
            return False
    except (TypeError, ValueError):
        return False
    if not resolve_calendar_ids(apt_type):
        return False
    if _is_test_type(apt_type):
        return False
    # ↓ DELETE THIS BLOCK — Acuity has renamed ALL types to include "Fertility".
    # The ID-based STATE_TYPE_IDS map already handles psych vs fertility separation.
    # if "FERTILITY" in apt_type.get("name", "").upper():
    #     return False
    return True


def get_allowed_types_psych(all_types: list, state: str) -> list:
    """Return Psych Eval types allowed for *state* using the manual map."""
    type_ids_str = STATE_TYPE_IDS.get(state)

    if type_ids_str is None:
        log.info("psych state=%s → international, returning all eligible", state)
        return [t for t in all_types if _is_psych_eval_eligible(t)]

    if type_ids_str == "":
        log.info("psych state=%s → known, no types assigned", state)
        return []

    allowed_ids = {int(x.strip()) for x in type_ids_str.split(",") if x.strip()}
    matched = [t for t in all_types
               if t["id"] in allowed_ids and _is_psych_eval_eligible(t)]
    log.info("psych VERSION=7.1.0 state=%s allowed=%d matched=%d",
             state, len(allowed_ids), len(matched))
    return matched


# ==================================================
# FAMILY 2 — FERTILITY EVAL  (fully dynamic, v7.1)
# ==================================================
#
# Routing derived entirely from appointment type NAME and CATEGORY.
# NO duration filter — fertility types are 50 or 60 min (mixed).
# NO manual ID list.
#
# KEY RULE: Name prefix checked FIRST, before category.
# "Thrive FLORIDA: ..." → Florida only (even though category is PSYPACT)
# "Thrive PSYPACT: ..."  → PSYPACT is not a US state → falls to PSYPACT pool
# "Thrive: ..."          → no state prefix → falls to PSYPACT pool
#
# Category                              Routes to
# THRIVE: ... PSYPACT                   All PSYPACT states (if no state in name)
# THRIVE NON-PSYPACT: ...               State from name prefix
# THRIVE CALIFORNIA: ...                California (name prefix handles too)
# Any with "Thrive {STATE}:" in name    That state ONLY
#
# Test types: id in TEST_TYPE_IDS OR name starts with "(TEST"
# ─────────────────────────────────────────────────────────────────────────────

_FERT_CAT_PSYPACT     = "PSYPACT"
_FERT_CAT_NON_PSYPACT = "NON-PSYPACT"


def _state_from_name_prefix(name: str) -> Optional[str]:
    """
    Extract US state from 'Thrive FLORIDA: Fertility ...' → 'Florida'.
    Returns None if prefix is not a valid US state name.
    e.g. 'Thrive PSYPACT:' → None, 'Thrive:' → None.
    """
    m = re.match(r"^Thrive\s+([A-Z][A-Z\s]+?):\s+", name, re.IGNORECASE)
    if not m:
        return None
    return _STATE_UPPER_MAP.get(m.group(1).strip().upper())


def _fertility_eligible(apt_type: dict) -> bool:
    """
    Base filter for fertility types.
    NO duration restriction — fertility types are 50 or 60 min (mixed).
    """
    cat  = (apt_type.get("category") or "").upper()
    name = (apt_type.get("name")     or "").upper()
    if PSYCH_EVAL_CATEGORY_KEYWORD not in cat:
        return False
    if "FERTILITY" not in name:
        return False
    if _is_test_type(apt_type):
        return False
    if not resolve_calendar_ids(apt_type):
        return False
    return True


def _fertility_routes_to(apt_type: dict) -> set:
    """Return the set of states this fertility type should appear in."""
    cat  = (apt_type.get("category") or "").upper()
    name = (apt_type.get("name")     or "")

    if not _fertility_eligible(apt_type):
        return set()

    # Step 1: Name prefix takes priority over category
    # Handles FL/WA types whose category is PSYPACT but name encodes specific state
    state_from_name = _state_from_name_prefix(name)
    if state_from_name:
        return {state_from_name}

    # Step 2: No US state in name prefix — use category
    if _FERT_CAT_PSYPACT in cat and _FERT_CAT_NON_PSYPACT not in cat:
        return set(PSYPACT_COMPACT_STATES)

    if _FERT_CAT_NON_PSYPACT in cat:
        log.warning("fertility NON-PSYPACT type '%s' has no parseable state in name — skipped", name)
        return set()

    if "CALIFORNIA" in cat:
        return {"California"}

    log.warning("fertility type '%s' unrecognised category '%s' — skipped",
                name, apt_type.get("category", ""))
    return set()


def get_allowed_types_fertility(all_types: list, state: str) -> list:
    """
    Return fertility types for *state*.
    International (state not in ALL_US_STATES): return all eligible fertility types.
    """
    if state not in ALL_US_STATES:
        matched = [t for t in all_types if _fertility_eligible(t)]
        log.info("fertility international state=%s matched=%d", state, len(matched))
        return matched

    matched = [t for t in all_types if state in _fertility_routes_to(t)]
    log.info("fertility v7.1 state=%s matched=%d", state, len(matched))
    return matched


# ==================================================
# UNIFIED DISPATCHER
# ==================================================

def get_allowed_types(all_types: list, state: str,
                      appt_type: str = "psych") -> list:
    """Route to the correct family. 'both' merges psych + fertility deduplicated."""
    if appt_type == "fertility":
        return get_allowed_types_fertility(all_types, state)
    if appt_type == "psych":
        return get_allowed_types_psych(all_types, state)
    # "both" — merge, deduplicated by type ID
    psych  = get_allowed_types_psych(all_types, state)
    fert   = get_allowed_types_fertility(all_types, state)
    seen   = {t["id"] for t in psych}
    merged = psych + [t for t in fert if t["id"] not in seen]
    log.info("both v7.1 state=%s psych=%d fert=%d merged=%d",
             state, len(psych), len(fert), len(merged))
    return merged


def extract_doctor_name(type_name: str) -> str:
    if " with " in type_name:
        return type_name.split(" with ")[-1].strip()
    return type_name


# ==================================================
# STATE-BASED AVAILABILITY ROUTES
# ==================================================

@app.get("/availability/by-state", tags=["Availability"])
async def availability_by_state(
    state:     str = Query(..., description="US state name, or any value for outside US"),
    date:      str = Query(..., description="YYYY-MM-DD"),
    timezone:  str = Query("America/New_York"),
    appt_type: str = Query("psych", description="'psych' (default), 'fertility', or 'both'"),
):
    state = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
    appt_type = appt_type.strip().lower()
    if appt_type not in ("psych", "fertility", "both"):
        raise HTTPException(400, "appt_type must be 'psych', 'fertility', or 'both'")
    log.info("availability/by-state called — state=%s date=%s appt_type=%s",
             state, date, appt_type)

    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    matched_types = get_allowed_types(types_resp.json(), state, appt_type)

    if not matched_types:
        return {
            "state":     state,
            "date":      date,
            "appt_type": appt_type,
            "message":   "No appointment types found for this state",
            "slots":     []
        }

    cal_to_types_list: dict = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in resolve_calendar_ids(apt_type):
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

    if appt_type == "fertility":
        if state in PSYPACT_COMPACT_STATES:
            pool = "psypact+state-specific" if state in {"Florida", "Washington"} else "psypact"
        else:
            pool = "state-specific"
    elif state in NON_PSYPACT_STATES:
        pool = "state-specific"
    elif state in STATE_TYPE_IDS:
        pool = "psypact"
    else:
        pool = "all (international)"

    return {
        "state":          state,
        "date":           date,
        "timezone":       timezone,
        "appt_type":      appt_type,
        "pool":           pool,
        "totalSlots":     len(all_slots),
        "matchedTypes":   len(matched_types),
        "totalCalendars": len(therapist_slots),
        "therapists":     therapist_list,
        "slots":          all_slots
    }


@app.get("/availability/dates-by-state", tags=["Availability"])
async def availability_dates_by_state(
    state:     str           = Query(..., description="US state name, or any value for outside US"),
    month:     Optional[str] = Query(None, description="YYYY-MM. Defaults to current month"),
    timezone:  str           = Query("America/New_York"),
    appt_type: str           = Query("psych", description="'psych' (default), 'fertility', or 'both'"),
):
    if not month:
        month = datetime.now().strftime("%Y-%m")

    state = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
    appt_type = appt_type.strip().lower()
    if appt_type not in ("psych", "fertility", "both"):
        raise HTTPException(400, "appt_type must be 'psych', 'fertility', or 'both'")
    log.info("availability/dates-by-state called — state=%s month=%s appt_type=%s",
             state, month, appt_type)

    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    if types_resp.status_code != 200:
        raise HTTPException(500, "Could not fetch appointment types")

    matched_types = get_allowed_types(types_resp.json(), state, appt_type)

    if not matched_types:
        return {"state": state, "month": month, "dates": []}

    cal_to_typeids: dict = defaultdict(list)
    for apt_type in matched_types:
        for cal_id in resolve_calendar_ids(apt_type):
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
async def debug_types(
    state:     Optional[str] = Query(None),
    appt_type: str           = Query("psych", description="'psych', 'fertility', or 'both'"),
):
    async with httpx.AsyncClient(timeout=15) as client:
        types_resp = await client.get(
            f"{ACUITY_BASE}/appointment-types",
            headers=acuity_headers()
        )
    all_types = types_resp.json()
    appt_type = appt_type.strip().lower()

    passed, failed = [], []
    for t in all_types:
        category = t.get("category", "").upper()
        duration  = t.get("duration")
        reasons   = []

        if PSYCH_EVAL_CATEGORY_KEYWORD not in category:
            reasons.append(f"category missing 'PSYCHOLOGICAL EVALUATION': {t.get('category')}")
        # Use resolve_calendar_ids so CALENDAR_OVERRIDES are respected in debug output
        if not resolve_calendar_ids(t):
            reasons.append("no calendarIDs assigned (after overrides)")
        if _is_test_type(t):
            reasons.append("test type — excluded")

        entry = {
            "id":               t["id"],
            "name":             t.get("name", ""),
            "category":         t.get("category", ""),
            "duration":         duration,
            "calendars_raw":    t.get("calendarIDs", []),
            "calendars_eff":    resolve_calendar_ids(t),
        }
        if reasons:
            entry["filtered_reason"] = reasons
            failed.append(entry)
        else:
            if state:
                state_norm = STATE_NORMALIZER.get(state.strip().lower(), state.strip())
                if appt_type == "fertility":
                    routed = _fertility_routes_to(t)
                    entry["routed_states_sample"] = sorted(routed)[:10]
                    entry["in_state"]             = state_norm in routed
                else:
                    ids_for_state = {
                        int(x) for x in STATE_TYPE_IDS.get(state_norm, "").split(",") if x.strip()
                    }
                    entry["in_state_map"] = t["id"] in ids_for_state
            passed.append(entry)

    state_norm = STATE_NORMALIZER.get(state.strip().lower(), state.strip()) if state else None
    matched = get_allowed_types(all_types, state_norm, appt_type) if state_norm else []

    return {
        "version":            "7.1.0",
        "appt_type":          appt_type,
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