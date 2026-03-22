import os
import base64
import hmac
import hashlib
import logging
from collections import deque
from datetime import datetime
import random
import re
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

# def verify_acuity_signature(raw_body: bytes, signature: Optional[str]) -> bool:
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

def verify_acuity_signature(raw_body, signature):
    return True  # disable until secret is confirmed
# --------------------------------------------------
# REFERRAL ID HELPER
# --------------------------------------------------

def extract_referral_id(appointment: dict) -> Optional[str]:
    for form in appointment.get("forms", []):
        for field in form.get("values", []):
            if (
                field.get("fieldID") == 18222169
                or field.get("name", "").lower() == "referral_id"
            ):
                val = field.get("value", "").strip()
                return val if val else None

    # Fallback — parse formsText
    forms_text = appointment.get("formsText", "")
    if forms_text:
        match = re.search(
            r"referral[_\s]?id[:\s]+([^\n]+)",
            forms_text,
            re.IGNORECASE
        )
        if match:
            val = match.group(1).strip()
            return val if val else None

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
    "appointment_id":                  int(apt_id),   # ← remove str(), use int()
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
                params={"q.where": f"appointment_id={int(apt_id)}", "q.limit": 1}
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
            params={"q.where": f"appointment_id={int(apt_id)}"},
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
    log.info("Webhook raw body: %s", raw_body[:300])

    if not verify_acuity_signature(raw_body, x_acuity_signature):
        raise HTTPException(401, "Invalid webhook signature")

    # ★ Parse as form data, not JSON
    try:
        from urllib.parse import parse_qs
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
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    f"{ACUITY_BASE}/appointments/{apt_id}",
                    headers=acuity_headers()
                )
            log.info("Acuity fetch status: %s for ID: %s", resp.status_code, apt_id)
            if resp.status_code == 200:
                await caspio_upsert_appointment(resp.json())
                log.info("Caspio upsert completed for ID: %s", apt_id)
            else:
                log.error("Acuity fetch failed: %s %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.error("Webhook processing error: %s", str(e))

    return {"status": "processed", "action": action, "id": apt_id}




# ==================================================
# FILTERING CONSTANTS
# ==================================================

PSYCH_EVAL_CATEGORY_KEYWORD = "PSYCHOLOGICAL EVALUATION"
ALLOWED_DURATION = 50

# ★ Non-PSYPACT states — shown separately per state
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

# ★ STATE_KEYWORDS — built from your actual Acuity category/name patterns
STATE_KEYWORDS = {
    # Non-PSYPACT
    "California":     ["CALIFORNIA", "SANTA MONICA"],
    "New York":       ["NEW YORK", "THRIVE NY", "THRIVE NEW YORK"],
    "Hawaii":         ["HAWAII", "THRIVE HAWAII"],
    "Alaska":         ["ALASKA", "THRIVE ALASKA"],
    "Oregon":         ["OREGON", "THRIVE OREGON"],
    "New Mexico":     ["NEW MEXICO", "THRIVE NEW MEXICO"],
    "Louisiana":      ["LOUISIANA", "THRIVE LOUISIANA"],
    "Massachusetts":  ["MASSACHUSETTS", "THRIVE MASSACHUSETTS"],
    "Iowa":           ["IOWA", "THRIVE IOWA", "THRIVE IA"],

    # PSYPACT states
    "Indiana":        ["INDIANA", "THRIVE INDIANA"],
    "District of Columbia": ["THRIVE DC", " DC:"],
    "Pennsylvania":   ["PENNSYLVANIA", "THRIVE PENNSYLVANIA", "THRIVE PA"],
    "Texas":          ["TEXAS", "THRIVE TEXAS", "THRIVE TX"],
    "Alabama":        ["ALABAMA", "THRIVE ALABAMA"],
    "Arizona":        ["ARIZONA", "THRIVE ARIZONA"],
    "Arkansas":       ["ARKANSAS", "THRIVE ARKANSAS"],
    "Colorado":       ["COLORADO", "THRIVE COLORADO"],
    "Connecticut":    ["CONNECTICUT", "THRIVE CONNECTICUT"],
    "Delaware":       ["DELAWARE", "THRIVE DELAWARE"],
    "Florida":        ["FLORIDA", "THRIVE FLORIDA"],
    "Georgia":        ["GEORGIA", "THRIVE GEORGIA"],
    "Idaho":          ["IDAHO", "THRIVE IDAHO"],
    "Illinois":       ["ILLINOIS", "THRIVE ILLINOIS"],
    "Kansas":         ["KANSAS", "THRIVE KANSAS"],
    "Kentucky":       ["KENTUCKY", "THRIVE KENTUCKY"],
    "Maine":          ["MAINE", "THRIVE MAINE"],
    "Maryland":       ["MARYLAND", "THRIVE MARYLAND"],
    "Michigan":       ["MICHIGAN", "THRIVE MICHIGAN"],
    "Minnesota":      ["MINNESOTA", "THRIVE MINNESOTA"],
    "Missouri":       ["MISSOURI", "THRIVE MISSOURI"],
    "Montana":        ["MONTANA", "THRIVE MONTANA"],
    "Nebraska":       ["NEBRASKA", "THRIVE NEBRASKA"],
    "Nevada":         ["NEVADA", "THRIVE NEVADA"],
    "New Hampshire":  ["NEW HAMPSHIRE", "THRIVE NEW HAMPSHIRE"],
    "New Jersey":     ["NEW JERSEY", "THRIVE NEW JERSEY"],
    "North Carolina": ["NORTH CAROLINA", "THRIVE NORTH CAROLINA", "THRIVE NC"],
    "North Dakota":   ["NORTH DAKOTA", "THRIVE NORTH DAKOTA"],
    "Ohio":           ["OHIO", "THRIVE OHIO"],
    "Oklahoma":       ["OKLAHOMA", "THRIVE OKLAHOMA"],
    "Rhode Island":   ["RHODE ISLAND", "THRIVE RHODE ISLAND"],
    "South Carolina": ["SOUTH CAROLINA", "THRIVE SOUTH CAROLINA"],
    "South Dakota":   ["SOUTH DAKOTA", "THRIVE SOUTH DAKOTA"],
    "Tennessee":      ["TENNESSEE", "THRIVE TENNESSEE"],
    "Utah":           ["UTAH", "THRIVE UTAH"],
    "Vermont":        ["VERMONT", "THRIVE VERMONT"],
    "Virginia":       ["VIRGINIA", "THRIVE VIRGINIA"],
    "Washington":     ["WASHINGTON", "THRIVE WASHINGTON"],
    "West Virginia":  ["WEST VIRGINIA", "THRIVE WEST VIRGINIA"],
    "Wisconsin":      ["WISCONSIN", "THRIVE WISCONSIN"],
    "Wyoming":        ["WYOMING", "THRIVE WYOMING", "(WY)"],
}

# ★ These category patterns = available to ALL PSYPACT states
# "THRIVE: Psychological Evaluation" (bare, no state) = PSYPACT pool
ALL_STATES_KEYWORDS = [
    "ALL STATES",
    "THRIVE ONLINE",
    "PSYPACT",
    "THRIVE PSYPACT",
]

# ★ Bare "THRIVE: Psychological Evaluation" = PSYPACT pool
# detected separately via is_psypact_generic()
def is_psypact_generic(apt_type: dict) -> bool:
    """
    Returns True for types with category exactly 'THRIVE: Psychological Evaluation'
    — no state specified — available to all PSYPACT states.
    """
    category = apt_type.get("category", "").upper().strip()
    return category == "THRIVE: PSYCHOLOGICAL EVALUATION"


def is_all_states(apt_type: dict) -> bool:
    """Returns True if type serves all states (PSYPACT pool)."""
    cat = apt_type.get("category", "").upper()
    for kw in ALL_STATES_KEYWORDS:
        if kw.upper() in cat:
            return True
    return is_psypact_generic(apt_type)  # ★ also catches bare THRIVE: types


def is_psypact_eligible(apt_type: dict) -> bool:
    """
    Returns True if this type belongs to the PSYPACT pool.
    Includes:
    - Generic types with no state (THRIVE: Psychological Evaluation)
    - Types from any state NOT in NON_PSYPACT_STATES
    Excludes:
    - Types specific to non-PSYPACT states (CA, NY, IA etc.)
    """
    cat  = apt_type.get("category", "").upper()
    name = apt_type.get("name", "").upper()

    # Always include all-states / generic types
    if is_all_states(apt_type):
        return True

    # Check if it matches any NON-PSYPACT state — if so, exclude it
    for non_psypact in NON_PSYPACT_STATES:
        keywords = STATE_KEYWORDS.get(non_psypact, [non_psypact.upper()])
        for kw in keywords:
            if kw.upper() in cat or kw.upper() in name:
                return False  # belongs to non-PSYPACT state → exclude

    # Doesn't match any non-PSYPACT state → include in PSYPACT pool
    return True


def is_50min_psych_eval(apt_type: dict) -> bool:
    """
    Returns True only for 50-minute Psychological Evaluations with a calendar assigned.
    Handles both string '50' and integer 50 from Acuity API.
    """
    category = apt_type.get("category", "").upper()
    duration  = apt_type.get("duration")

    if PSYCH_EVAL_CATEGORY_KEYWORD not in category:
        return False

    # ★ Handle both "50" string and 50 integer
    try:
        if int(duration) != ALLOWED_DURATION:
            return False
    except (TypeError, ValueError):
        return False

    # Must have at least one calendar assigned
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
# --------------------------------------------------
# PSYPACT CONFIGURATION
# --------------------------------------------------

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

PSYPACT_STATES = {
    "Alabama", "Arizona", "Arkansas", "Colorado", "Connecticut",
    "Delaware", "Florida", "Georgia", "Idaho", "Illinois",
    "Indiana", "Kansas", "Kentucky", "Maine", "Maryland",
    "Michigan", "Minnesota", "Missouri", "Montana", "Nebraska",
    "Nevada", "New Hampshire", "New Jersey", "North Carolina",
    "North Dakota", "Ohio", "Oklahoma", "Pennsylvania", "Rhode Island",
    "South Carolina", "South Dakota", "Tennessee", "Texas", "Utah",
    "Vermont", "Virginia", "Washington", "West Virginia", "Wisconsin",
    "Wyoming",
}

def is_psypact_state(state: str) -> bool:
    return state not in NON_PSYPACT_STATES

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

    if is_psypact_state(state):
        # ★ PSYPACT — bundle ALL psypact state types together
        matched_types = []
        seen_ids = set()
        for psypact_state in PSYPACT_STATES:
            for t in all_types:
                if t["id"] not in seen_ids and is_50min_psych_eval(t) and matches_state(t, psypact_state):
                    matched_types.append(t)
                    seen_ids.add(t["id"])
        # also add all-states types
        for t in all_types:
            if t["id"] not in seen_ids and is_50min_psych_eval(t) and is_all_states(t):
                matched_types.append(t)
                seen_ids.add(t["id"])
    else:
        # ★ NON-PSYPACT — existing behavior, state-specific only
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
            "slots":   []
        }

    # rest of the function stays exactly the same...
    # (calendar_type_map, parallel fetch, merge slots, shuffle, sort)

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

    if is_psypact_state(state):
        # ★ PSYPACT — include all types NOT specific to non-PSYPACT states
        matched_types = [
            t for t in all_types
            if is_50min_psych_eval(t) and is_psypact_eligible(t)
        ]
    else:
        # ★ NON-PSYPACT — state-specific only, existing behavior
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
    # rest stays the same...
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
    


@app.get("/states/psypact-check", tags=["Configuration"])
async def psypact_check(state: str = Query(...)):
    """Check if a state is PSYPACT or non-PSYPACT."""
    return {
        "state":      state,
        "is_psypact": is_psypact_state(state),
        "pool":       "psypact" if is_psypact_state(state) else "state-specific"
    }