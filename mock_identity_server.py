"""
mock_identity_server.py — Fake Identity Provider for IAM Audit Tool testing.

Mimics the APIs of:
  - Okta           → http://localhost:5000/okta
  - Microsoft Entra → http://localhost:5000/entra
  - Google Workspace→ http://localhost:5000/google
  - BambooHR        → http://localhost:5000/bamboohr
  - Workday         → http://localhost:5000/workday
  - GitHub          → http://localhost:5000/github
  - AWS IAM         → http://localhost:5000/aws
  - Salesforce      → http://localhost:5000/salesforce

Run:  python mock_identity_server.py
Test: http://localhost:5000/health

Seeded violations (visible across all connectors):
  - Terminated employees with active accounts
  - Post-termination logins
  - Dormant accounts (180+ days no login)
  - MFA not enabled
  - Mover with stale access
  - Contractor without expiry
  - Orphaned accounts
  - SoD violations (Finance + Payroll)
  - Privilege creep (5 roles)
  - Generic/shared accounts
"""

from flask import Flask, jsonify, request
from datetime import date, datetime, timedelta
import math

app = Flask(__name__)

TODAY      = date.today()
BASE_URL   = "http://localhost:5000"

def d(days_ago):
    return (TODAY - timedelta(days=days_ago)).isoformat() + "T00:00:00.000Z"

def future(days_ahead):
    return (TODAY + timedelta(days=days_ahead)).isoformat() + "T00:00:00.000Z"

# ─────────────────────────────────────────────────────────────────────────────
#  MASTER USER DATASET — single source of truth for all connectors
# ─────────────────────────────────────────────────────────────────────────────

USERS = [
    # ── CLEAN ACTIVE USERS ──────────────────────────────────────────────────
    {
        "id": "usr001", "email": "alice.johnson@acmecorp.com",
        "firstName": "Alice",  "lastName": "Johnson",
        "department": "Finance", "title": "Finance Manager",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(730), "lastLogin": d(1), "passwordChanged": d(45),
        "mfaEnrolled": True, "groups": ["finance", "finance_team"],
        "manager": "cfo@acmecorp.com",
    },
    {
        "id": "usr002", "email": "bob.smith@acmecorp.com",
        "firstName": "Bob",    "lastName": "Smith",
        "department": "IT", "title": "Systems Administrator",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(1100), "lastLogin": d(1), "passwordChanged": d(20),
        "mfaEnrolled": True, "groups": ["admins", "it_team"],
        "manager": "cto@acmecorp.com",
    },
    {
        "id": "usr003", "email": "carol.white@acmecorp.com",
        "firstName": "Carol",  "lastName": "White",
        "department": "HR", "title": "HR Business Partner",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(500), "lastLogin": d(5), "passwordChanged": d(30),
        "mfaEnrolled": True, "groups": ["hr", "hr_team"],
        "manager": "chro@acmecorp.com",
    },
    {
        "id": "usr004", "email": "david.brown@acmecorp.com",
        "firstName": "David",  "lastName": "Brown",
        "department": "Sales", "title": "Account Executive",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(365), "lastLogin": d(3), "passwordChanged": d(55),
        "mfaEnrolled": True, "groups": ["crm", "crm_users"],
        "manager": "sales.director@acmecorp.com",
    },
    {
        "id": "usr005", "email": "frank.miller@acmecorp.com",
        "firstName": "Frank",  "lastName": "Miller",
        "department": "IT", "title": "IT Security Analyst",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(900), "lastLogin": d(1), "passwordChanged": d(15),
        "mfaEnrolled": True, "groups": ["admins", "it_security"],
        "manager": "ciso@acmecorp.com",
    },
    {
        "id": "usr006", "email": "grace.wilson@acmecorp.com",
        "firstName": "Grace",  "lastName": "Wilson",
        "department": "Legal", "title": "Legal Counsel",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(450), "lastLogin": d(10), "passwordChanged": d(40),
        "mfaEnrolled": True, "groups": ["readonly"],
        "manager": "clo@acmecorp.com",
    },

    # ── VIOLATION: TERMINATED — access not removed ───────────────────────
    {
        "id": "usr007", "email": "mark.harris@acmecorp.com",
        "firstName": "Mark",   "lastName": "Harris",
        "department": "Sales", "title": "Sales Director",
        "employeeType": "employee", "status": "ACTIVE",  # Should be DEPROVISIONED
        "created": d(900), "lastLogin": d(125), "passwordChanged": d(200),
        "mfaEnrolled": True, "groups": ["crm"],
        "terminationDate": d(120),
        "hrStatus": "Terminated",
        "manager": "ceo@acmecorp.com",
    },
    {
        "id": "usr008", "email": "nancy.martin@acmecorp.com",
        "firstName": "Nancy",  "lastName": "Martin",
        "department": "HR", "title": "HR Manager",
        "employeeType": "employee", "status": "ACTIVE",  # Should be DEPROVISIONED
        "created": d(730), "lastLogin": d(65), "passwordChanged": d(150),
        "mfaEnrolled": False,  # MFA disabled too
        "groups": ["hr"],
        "terminationDate": d(60),
        "hrStatus": "Terminated",
        "manager": "chro@acmecorp.com",
    },

    # ── VIOLATION: POST-TERMINATION LOGIN ────────────────────────────────
    {
        "id": "usr009", "email": "oliver.garcia@acmecorp.com",
        "firstName": "Oliver", "lastName": "Garcia",
        "department": "Finance", "title": "Senior Accountant",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(1200), "lastLogin": d(10),   # Logged in AFTER termination
        "passwordChanged": d(100),
        "mfaEnrolled": True, "groups": ["finance"],
        "terminationDate": d(30),   # Terminated 30 days ago
        "hrStatus": "Terminated",
        "manager": "cfo@acmecorp.com",
    },

    # ── VIOLATION: DORMANT (180+ days no login) ──────────────────────────
    {
        "id": "usr010", "email": "quinn.robinson@acmecorp.com",
        "firstName": "Quinn",  "lastName": "Robinson",
        "department": "Operations", "title": "Operations Analyst",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(540), "lastLogin": d(180), "passwordChanged": d(300),
        "mfaEnrolled": True, "groups": ["support"],
        "manager": "ops.director@acmecorp.com",
    },

    # ── VIOLATION: MFA NOT ENABLED ───────────────────────────────────────
    {
        "id": "usr011", "email": "emily.davis@acmecorp.com",
        "firstName": "Emily",  "lastName": "Davis",
        "department": "Finance", "title": "Payroll Analyst",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(600), "lastLogin": d(6), "passwordChanged": d(200),
        "mfaEnrolled": False,   # MFA disabled on Payroll user
        "groups": ["payroll", "finance"],
        "manager": "cfo@acmecorp.com",
    },

    # ── VIOLATION: CONTRACTOR WITHOUT EXPIRY ─────────────────────────────
    {
        "id": "usr012", "email": "kate.thomas@acmecorp.com",
        "firstName": "Kate",   "lastName": "Thomas",
        "department": "IT", "title": "DevOps Contractor",
        "employeeType": "contractor", "status": "ACTIVE",
        "created": d(120), "lastLogin": d(3), "passwordChanged": d(40),
        "mfaEnrolled": True, "groups": ["admins"],
        "terminationDate": None,   # No expiry date set
        "manager": "cto@acmecorp.com",
    },

    # ── VIOLATION: SoD — Finance + Payroll ──────────────────────────────
    {
        "id": "usr013", "email": "liam.jackson@acmecorp.com",
        "firstName": "Liam",   "lastName": "Jackson",
        "department": "Finance", "title": "Finance Contractor",
        "employeeType": "contractor", "status": "ACTIVE",
        "created": d(60), "lastLogin": d(8), "passwordChanged": d(25),
        "mfaEnrolled": True, "groups": ["finance", "payroll"],  # SoD violation
        "terminationDate": future(45),
        "manager": "cfo@acmecorp.com",
    },

    # ── VIOLATION: PRIVILEGE CREEP (5 roles) ─────────────────────────────
    {
        "id": "usr014", "email": "james.anderson@acmecorp.com",
        "firstName": "James",  "lastName": "Anderson",
        "department": "Finance", "title": "Financial Controller",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(820), "lastLogin": d(2), "passwordChanged": d(35),
        "mfaEnrolled": True,
        "groups": ["finance", "admins", "payroll", "hr", "crm"],  # 5 roles
        "manager": "cfo@acmecorp.com",
    },

    # ── VIOLATION: ORPHANED ACCOUNT (no HR record) ───────────────────────
    {
        "id": "usr015", "email": "ghost.user@acmecorp.com",
        "firstName": "Ghost",  "lastName": "User",
        "department": "Unknown", "title": "",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(500), "lastLogin": d(15), "passwordChanged": d(180),
        "mfaEnrolled": False, "groups": ["finance"],
        "manager": "",
        "hrRecord": False,   # Not in HR system
    },

    # ── VIOLATION: GENERIC/SHARED ACCOUNT ────────────────────────────────
    {
        "id": "usr016", "email": "admin@acmecorp.com",
        "firstName": "Shared", "lastName": "Admin",
        "department": "IT", "title": "Shared Account",
        "employeeType": "service", "status": "ACTIVE",
        "created": d(1500), "lastLogin": d(0), "passwordChanged": d(120),
        "mfaEnrolled": False, "groups": ["admins"],
        "manager": "",
    },

    # ── VIOLATION: SERVICE ACCOUNT ────────────────────────────────────────
    {
        "id": "usr017", "email": "svc_backup@acmecorp.com",
        "firstName": "Backup", "lastName": "Service",
        "department": "IT", "title": "Service Account",
        "employeeType": "service", "status": "ACTIVE",
        "created": d(2000), "lastLogin": d(1), "passwordChanged": d(400),
        "mfaEnrolled": False, "groups": ["admins"],
        "manager": "",
    },

    # ── VIOLATION: PASSWORD NEVER EXPIRED ────────────────────────────────
    {
        "id": "usr018", "email": "henry.moore@acmecorp.com",
        "firstName": "Henry",  "lastName": "Moore",
        "department": "Operations", "title": "Operations Manager",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(280), "lastLogin": d(4), "passwordChanged": d(400),
        "mfaEnrolled": True, "groups": ["support"],
        "manager": "ops.director@acmecorp.com",
    },

    # ── VIOLATION: NEAR-MATCH EMAIL ───────────────────────────────────────
    {
        "id": "usr019", "email": "carol.whit@acmecorp.com",   # Missing 'e'
        "firstName": "Carol",  "lastName": "Whit",
        "department": "HR", "title": "HR Analyst",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(400), "lastLogin": d(20), "passwordChanged": d(90),
        "mfaEnrolled": True, "groups": ["hr"],
        "manager": "chro@acmecorp.com",
    },

    # ── VIOLATION: SUPER-USER OUTSIDE IT ─────────────────────────────────
    {
        "id": "usr020", "email": "patricia.lee@acmecorp.com",
        "firstName": "Patricia", "lastName": "Lee",
        "department": "Finance", "title": "Finance Director",
        "employeeType": "employee", "status": "ACTIVE",
        "created": d(800), "lastLogin": d(2), "passwordChanged": d(45),
        "mfaEnrolled": True, "groups": ["admins", "finance"],  # Admin in Finance dept
        "manager": "cfo@acmecorp.com",
    },
]

# HR records — subset of users (ghost.user deliberately excluded = orphan)
HR_EMPLOYEES = [u for u in USERS if u.get("hrRecord", True) and u["email"] != "ghost.user@acmecorp.com"]

# Groups / departments
GROUPS = [
    {"id": "grp001", "name": "admins",       "description": "System Administrators"},
    {"id": "grp002", "name": "finance",      "description": "Finance Team"},
    {"id": "grp003", "name": "finance_team", "description": "Finance Department"},
    {"id": "grp004", "name": "hr",           "description": "Human Resources"},
    {"id": "grp005", "name": "hr_team",      "description": "HR Department"},
    {"id": "grp006", "name": "crm",          "description": "CRM Users"},
    {"id": "grp007", "name": "crm_users",    "description": "CRM Department"},
    {"id": "grp008", "name": "payroll",      "description": "Payroll Team"},
    {"id": "grp009", "name": "readonly",     "description": "Read Only Users"},
    {"id": "grp010", "name": "support",      "description": "Support Team"},
    {"id": "grp011", "name": "it_team",      "description": "IT Department"},
    {"id": "grp012", "name": "it_security",  "description": "IT Security"},
]

# ─────────────────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def paginate(items, limit=200, after=None):
    """Simple cursor-based pagination matching Okta's model."""
    limit = min(int(request.args.get("limit", limit)), 200)
    start = 0
    if after:
        for i, item in enumerate(items):
            if item.get("id") == after:
                start = i + 1
                break
    page  = items[start:start + limit]
    links = []
    if start + limit < len(items):
        next_cursor = page[-1]["id"] if page else ""
        next_url    = f"{request.base_url}?limit={limit}&after={next_cursor}"
        links.append(f'<{next_url}>; rel="next"')
    return page, "; ".join(links)


def build_okta_user(user):
    """Format a user as a real Okta API response object."""
    status = "ACTIVE" if user.get("hrStatus") not in ("Terminated","Resigned") else "DEPROVISIONED"
    # Deliberately leave terminated users as ACTIVE to seed violations
    status = user.get("status", "ACTIVE")
    return {
        "id":            user["id"],
        "status":        status,
        "created":       user["created"],
        "activated":     user["created"],
        "lastLogin":     user["lastLogin"],
        "lastUpdated":   user.get("passwordChanged", user["created"]),
        "passwordChanged": user.get("passwordChanged"),
        "statusChanged": user.get("terminationDate"),
        "profile": {
            "firstName":    user["firstName"],
            "lastName":     user["lastName"],
            "email":        user["email"],
            "login":        user["email"],
            "department":   user["department"],
            "title":        user["title"],
            "organization": "Acme Corp",
            "employeeType": user.get("employeeType", "employee"),
        },
        "credentials": {
            "password":    {},
            "provider":    {"type": "OKTA", "name": "OKTA"},
        },
        "_links": {
            "self": {"href": f"{BASE_URL}/okta/api/v1/users/{user['id']}"},
        }
    }


# ─────────────────────────────────────────────────────────────────────────────
#  HEALTH CHECK
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status": "running",
        "org":    "Acme Corp (Mock)",
        "users":  len(USERS),
        "endpoints": {
            "okta":       f"{BASE_URL}/okta",
            "entra":      f"{BASE_URL}/entra",
            "google":     f"{BASE_URL}/google",
            "bamboohr":   f"{BASE_URL}/bamboohr",
            "workday":    f"{BASE_URL}/workday",
            "github":     f"{BASE_URL}/github",
            "aws":        f"{BASE_URL}/aws",
            "salesforce": f"{BASE_URL}/salesforce",
        },
        "test_credentials": {
            "okta_domain":        "http://localhost:5000/okta",
            "okta_api_token":     "mock_ssws_token_acmecorp",
            "entra_tenant_id":    "mock-tenant-acmecorp",
            "entra_client_id":    "mock-client-id",
            "entra_client_secret":"mock-client-secret",
            "google_domain":      "acmecorp.com",
            "google_admin_email": "admin@acmecorp.com",
            "bamboohr_subdomain": "acmecorp",
            "bamboohr_api_key":   "mock_bamboohr_key",
            "workday_tenant":     "acmecorp",
            "workday_username":   "mock_workday_user",
            "workday_password":   "mock_workday_pass",
            "github_org":         "acmecorp",
            "github_token":       "mock_github_pat",
            "aws_access_key":     "MOCKAWSACCESSKEY123",
            "aws_secret_key":     "mockAWSsecretKey456",
            "sf_instance_url":    "http://localhost:5000/salesforce",
            "sf_access_token":    "mock_sf_token",
        }
    })


# ─────────────────────────────────────────────────────────────────────────────
#  OKTA MOCK ENDPOINTS
#  Matches real Okta API: https://developer.okta.com/docs/reference/api/users/
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/okta/api/v1/users")
def okta_users():
    """GET /api/v1/users — list all users with pagination."""
    token = request.headers.get("Authorization", "")
    if "mock_ssws_token" not in token:
        return jsonify({"errorCode": "E0000011", "errorSummary": "Invalid token"}), 401

    after = request.args.get("after")
    page, link_header = paginate(USERS, after=after)
    okta_users_page   = [build_okta_user(u) for u in page]

    response = jsonify(okta_users_page)
    if link_header:
        response.headers["Link"] = link_header
    return response


@app.route("/okta/api/v1/users/<user_id>")
def okta_user(user_id):
    """GET /api/v1/users/{id} — get single user."""
    user = next((u for u in USERS if u["id"] == user_id), None)
    if not user:
        return jsonify({"errorCode": "E0000007", "errorSummary": "Not found"}), 404
    return jsonify(build_okta_user(user))


@app.route("/okta/api/v1/groups")
def okta_groups():
    """GET /api/v1/groups — list all groups."""
    result = [{
        "id":       g["id"],
        "status":   "ACTIVE",
        "profile":  {"name": g["name"], "description": g["description"]},
        "_links":   {"users": {"href": f"{BASE_URL}/okta/api/v1/groups/{g['id']}/users"}},
    } for g in GROUPS]
    return jsonify(result)


@app.route("/okta/api/v1/groups/<group_id>/users")
def okta_group_users(group_id):
    """GET /api/v1/groups/{id}/users — list members of a group."""
    group = next((g for g in GROUPS if g["id"] == group_id), None)
    if not group:
        return jsonify([])
    members = [u for u in USERS if group["name"] in u.get("groups", [])]
    return jsonify([build_okta_user(u) for u in members])


@app.route("/okta/api/v1/users/<user_id>/factors")
def okta_user_factors(user_id):
    """GET /api/v1/users/{id}/factors — MFA factors for a user."""
    user = next((u for u in USERS if u["id"] == user_id), None)
    if not user:
        return jsonify([])
    if user.get("mfaEnrolled", True):
        return jsonify([{
            "id":          f"fct_{user_id}",
            "factorType":  "token:software:totp",
            "provider":    "GOOGLE",
            "status":      "ACTIVE",
            "created":     user["created"],
            "lastUpdated": user["created"],
        }])
    return jsonify([])


# ─────────────────────────────────────────────────────────────────────────────
#  MICROSOFT ENTRA ID (AZURE AD) MOCK ENDPOINTS
#  Matches Microsoft Graph API: https://graph.microsoft.com/v1.0/users
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/entra/token", methods=["POST"])
def entra_token():
    """POST /token — OAuth2 client credentials token endpoint."""
    return jsonify({
        "token_type":   "Bearer",
        "access_token": "mock_entra_access_token_acmecorp",
        "expires_in":   3600,
        "scope":        "https://graph.microsoft.com/.default",
    })


@app.route("/entra/v1.0/users")
def entra_users():
    """GET /v1.0/users — Microsoft Graph users list."""
    auth = request.headers.get("Authorization", "")
    if "mock_entra_access_token" not in auth:
        return jsonify({"error": {"code": "InvalidAuthenticationToken"}}), 401

    def build_entra_user(user):
        emp_status = user.get("hrStatus", "Active")
        return {
            "id":                    user["id"],
            "displayName":           f"{user['firstName']} {user['lastName']}",
            "givenName":             user["firstName"],
            "surname":               user["lastName"],
            "mail":                  user["email"],
            "userPrincipalName":     user["email"],
            "department":            user["department"],
            "jobTitle":              user["title"],
            "employeeType":          user.get("employeeType","employee"),
            "accountEnabled":        user["status"] == "ACTIVE",
            "createdDateTime":       user["created"],
            "signInActivity": {
                "lastSignInDateTime":             user["lastLogin"],
                "lastNonInteractiveSignInDateTime": user["lastLogin"],
            },
            "passwordProfile": {
                "lastPasswordChangeDateTime": user.get("passwordChanged"),
            },
            "onPremisesExtensionAttributes": {
                "extensionAttribute1": emp_status,
                "extensionAttribute2": user.get("terminationDate",""),
            },
            "assignedLicenses": [],
        }

    after = request.args.get("$skiptoken")
    start = 0
    if after:
        for i, u in enumerate(USERS):
            if u["id"] == after:
                start = i + 1
                break

    limit = 100
    page  = USERS[start:start + limit]
    result = {"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
              "value": [build_entra_user(u) for u in page]}

    if start + limit < len(USERS):
        result["@odata.nextLink"] = f"{BASE_URL}/entra/v1.0/users?$skiptoken={page[-1]['id']}"

    return jsonify(result)


@app.route("/entra/v1.0/groups")
def entra_groups():
    """GET /v1.0/groups — Microsoft Graph groups."""
    def build_entra_group(g):
        return {
            "id":          g["id"],
            "displayName": g["name"],
            "description": g["description"],
            "groupTypes":  [],
            "securityEnabled": True,
        }
    result = {
        "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#groups",
        "value": [build_entra_group(g) for g in GROUPS]
    }
    return jsonify(result)


@app.route("/entra/v1.0/groups/<group_id>/members")
def entra_group_members(group_id):
    """GET /v1.0/groups/{id}/members."""
    group = next((g for g in GROUPS if g["id"] == group_id), None)
    if not group:
        return jsonify({"value": []})
    members = [u for u in USERS if group["name"] in u.get("groups", [])]
    return jsonify({
        "value": [{"id": u["id"], "mail": u["email"]} for u in members]
    })


@app.route("/entra/v1.0/reports/authenticationMethods/userRegistrationDetails")
def entra_mfa_report():
    """GET MFA registration details for all users."""
    result = {
        "value": [{
            "id":                  u["id"],
            "userPrincipalName":   u["email"],
            "isMfaRegistered":     u.get("mfaEnrolled", True),
            "isMfaCapable":        u.get("mfaEnrolled", True),
            "methodsRegistered":   ["microsoftAuthenticatorPush"] if u.get("mfaEnrolled") else [],
        } for u in USERS]
    }
    return jsonify(result)


# ─────────────────────────────────────────────────────────────────────────────
#  GOOGLE WORKSPACE MOCK ENDPOINTS
#  Matches Admin SDK Directory API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/google/token", methods=["POST"])
def google_token():
    return jsonify({
        "access_token": "mock_google_access_token_acmecorp",
        "token_type":   "Bearer",
        "expires_in":   3600,
        "scope":        "https://www.googleapis.com/auth/admin.directory.user.readonly",
    })


@app.route("/google/admin/directory/v1/users")
def google_users():
    """GET /admin/directory/v1/users — Google Workspace users."""
    auth = request.headers.get("Authorization", "")
    if "mock_google_access_token" not in auth:
        return jsonify({"error": {"code": 401, "message": "Unauthorized"}}), 401

    def build_google_user(user):
        return {
            "id":              user["id"],
            "primaryEmail":    user["email"],
            "name":            {"givenName": user["firstName"], "familyName": user["lastName"],
                                "fullName":  f"{user['firstName']} {user['lastName']}"},
            "orgUnitPath":     f"/{user['department']}",
            "department":      user["department"],
            "title":           user["title"],
            "suspended":       user["status"] != "ACTIVE",
            "agreedToTerms":   True,
            "creationTime":    user["created"],
            "lastLoginTime":   user["lastLogin"],
            "isAdmin":         "admins" in user.get("groups", []),
            "isDelegatedAdmin": False,
            "isEnrolledIn2Sv": user.get("mfaEnrolled", True),
            "isEnforcedIn2Sv": user.get("mfaEnrolled", True),
            "customSchemas": {
                "Employment": {
                    "employeeType":    user.get("employeeType","employee"),
                    "terminationDate": user.get("terminationDate",""),
                }
            },
        }

    page_token = request.args.get("pageToken")
    start = 0
    if page_token:
        for i, u in enumerate(USERS):
            if u["id"] == page_token:
                start = i + 1
                break

    limit  = 100
    page   = USERS[start:start + limit]
    result = {"users": [build_google_user(u) for u in page], "kind": "admin#directory#users"}

    if start + limit < len(USERS):
        result["nextPageToken"] = page[-1]["id"]

    return jsonify(result)


@app.route("/google/admin/directory/v1/groups")
def google_groups():
    def build_google_group(g):
        return {
            "id":    g["id"], "email": f"{g['name']}@acmecorp.com",
            "name":  g["name"], "description": g["description"],
            "directMembersCount": str(sum(1 for u in USERS if g["name"] in u.get("groups",[]))),
        }
    return jsonify({"groups": [build_google_group(g) for g in GROUPS]})


@app.route("/google/admin/directory/v1/groups/<group_key>/members")
def google_group_members(group_key):
    group_name = group_key.split("@")[0]
    members    = [u for u in USERS if group_name in u.get("groups", [])]
    return jsonify({"members": [{"email": u["email"], "role": "MEMBER", "type": "USER"} for u in members]})


# ─────────────────────────────────────────────────────────────────────────────
#  BAMBOOHR MOCK ENDPOINTS
#  Matches BambooHR API v1
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/bamboohr/api/gateway.php/<company>/v1/employees/directory")
def bamboohr_directory(company):
    """GET employee directory — HR Master data."""
    auth = request.headers.get("Authorization", "")
    if not auth:
        return jsonify({"error": "Unauthorized"}), 401

    def build_bamboo_employee(user):
        status = user.get("hrStatus","Active")
        return {
            "id":              user["id"],
            "displayName":     f"{user['firstName']} {user['lastName']}",
            "firstName":       user["firstName"],
            "lastName":        user["lastName"],
            "workEmail":       user["email"],
            "department":      user["department"],
            "jobTitle":        user["title"],
            "employmentHistoryStatus": status,
            "employeeType":    user.get("employeeType","employee").title(),
            "hireDate":        (TODAY - timedelta(days=730)).isoformat(),
            "terminationDate": user.get("terminationDate",""),
            "supervisor":      user.get("manager",""),
            "location":        "London, UK",
            "division":        user["department"],
        }

    employees = [build_bamboo_employee(u) for u in HR_EMPLOYEES]
    return jsonify({"employees": employees, "fields": []})


# ─────────────────────────────────────────────────────────────────────────────
#  WORKDAY MOCK ENDPOINTS
#  Simplified REST API (real Workday uses SOAP/RAAS reports)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/workday/ccx/service/<tenant>/Human_Resources/v40.1/workers")
def workday_workers(tenant):
    """GET workers — Workday HR data."""
    auth = request.headers.get("Authorization", "")
    if not auth:
        return jsonify({"error": "Unauthorized"}), 401

    def build_workday_worker(user):
        status = user.get("hrStatus","Active")
        emp_active = status not in ("Terminated","Resigned","Left")
        return {
            "Worker_ID":            user["id"],
            "Worker_Type":          {"ID": user.get("employeeType","employee").title()},
            "Personal_Data": {
                "Name_Data": {
                    "Legal_Name_Data": {
                        "Name_Detail_Data": {
                            "First_Name": user["firstName"],
                            "Last_Name":  user["lastName"],
                        }
                    }
                },
                "Contact_Data": {
                    "Email_Address_Data": [{"Email_Address": user["email"], "Primary": True}]
                }
            },
            "Employment_Data": {
                "Worker_Status_Data": {
                    "Active":            emp_active,
                    "Hire_Date":         (TODAY - timedelta(days=730)).isoformat(),
                    "Termination_Date":  user.get("terminationDate",""),
                    "Employment_Status": status,
                },
                "Position_Data": {
                    "Department_Reference": {"Descriptor": user["department"]},
                    "Job_Profile_Name":     user["title"],
                    "Worker_Type":          user.get("employeeType","employee").title(),
                    "Manager_as_of_last_detected_manager_change_Reference": {
                        "Descriptor": user.get("manager","")
                    }
                }
            }
        }

    workers = [build_workday_worker(u) for u in HR_EMPLOYEES]
    return jsonify({
        "Report_Entry": workers,
        "total": len(workers),
    })


# ─────────────────────────────────────────────────────────────────────────────
#  GITHUB MOCK ENDPOINTS
#  Matches GitHub REST API v3
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/github/orgs/<org>/members")
def github_org_members(org):
    """GET /orgs/{org}/members — list org members."""
    auth = request.headers.get("Authorization","")
    if "mock_github_pat" not in auth:
        return jsonify({"message": "Bad credentials"}), 401

    members = [{
        "id":         int(u["id"].replace("usr","")),
        "login":      u["email"].split("@")[0],
        "email":      u["email"],
        "name":       f"{u['firstName']} {u['lastName']}",
        "role":       "admin" if "admins" in u.get("groups",[]) else "member",
        "created_at": u["created"],
        "updated_at": u["lastLogin"],
    } for u in USERS if u["status"] == "ACTIVE"]

    return jsonify(members)


@app.route("/github/orgs/<org>/teams")
def github_teams(org):
    return jsonify([{
        "id":   int(g["id"].replace("grp","")),
        "name": g["name"],
        "slug": g["name"].replace("_","-"),
        "description": g["description"],
        "members_count": sum(1 for u in USERS if g["name"] in u.get("groups",[])),
    } for g in GROUPS])


@app.route("/github/orgs/<org>/teams/<team_slug>/members")
def github_team_members(org, team_slug):
    group_name = team_slug.replace("-","_")
    members    = [u for u in USERS if group_name in u.get("groups",[])]
    return jsonify([{
        "login": u["email"].split("@")[0],
        "email": u["email"],
        "role":  "maintainer" if "admins" in u.get("groups",[]) else "member",
    } for u in members])


# ─────────────────────────────────────────────────────────────────────────────
#  AWS IAM MOCK ENDPOINTS
#  Matches AWS IAM API (simplified JSON — real AWS uses XML query API)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/aws/iam/users")
def aws_iam_users():
    """List IAM users."""
    auth = request.headers.get("Authorization","")
    if not auth:
        return jsonify({"Error": {"Code": "InvalidClientTokenId"}}), 401

    def build_aws_user(user):
        groups    = user.get("groups",[])
        has_admin = "admins" in groups
        return {
            "UserName":         user["email"].split("@")[0],
            "UserId":           user["id"],
            "Arn":              f"arn:aws:iam::123456789012:user/{user['email'].split('@')[0]}",
            "Path":             f"/{user['department'].lower()}/",
            "CreateDate":       user["created"],
            "PasswordLastUsed": user["lastLogin"],
            "Groups":           groups,
            "MFAEnabled":       user.get("mfaEnrolled", True),
            "PasswordLastChanged": user.get("passwordChanged"),
            "Tags": [
                {"Key": "Department",  "Value": user["department"]},
                {"Key": "Email",       "Value": user["email"]},
                {"Key": "EmployeeType","Value": user.get("employeeType","employee")},
            ],
            "AccessKeys": [{
                "AccessKeyId":  f"AKIA{user['id'].upper()}",
                "Status":       "Active",
                "CreateDate":   user["created"],
                "LastUsedDate": user["lastLogin"],
            }],
            "AttachedPolicies": [
                {"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
            ] if has_admin else [
                {"PolicyName": "ReadOnlyAccess", "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
            ],
        }

    return jsonify({
        "Users":   [build_aws_user(u) for u in USERS],
        "IsTruncated": False,
    })


@app.route("/aws/iam/groups")
def aws_iam_groups():
    return jsonify({
        "Groups": [{
            "GroupName": g["name"],
            "GroupId":   g["id"],
            "Arn":       f"arn:aws:iam::123456789012:group/{g['name']}",
            "Path":      "/",
            "CreateDate": d(1000),
        } for g in GROUPS],
        "IsTruncated": False,
    })


# ─────────────────────────────────────────────────────────────────────────────
#  SALESFORCE MOCK ENDPOINTS
#  Matches Salesforce REST API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/salesforce/services/oauth2/token", methods=["POST"])
def salesforce_token():
    return jsonify({
        "access_token": "mock_sf_token_acmecorp",
        "token_type":   "Bearer",
        "instance_url": BASE_URL + "/salesforce",
        "id":           BASE_URL + "/salesforce/id/00Dxx0000001gYL",
    })


@app.route("/salesforce/services/data/v58.0/query")
def salesforce_query():
    """SOQL query endpoint — handles User queries."""
    auth = request.headers.get("Authorization","")
    if "mock_sf_token" not in auth:
        return jsonify({"message": "Session expired or invalid"}), 401

    q = request.args.get("q","").upper()

    if "FROM USER" in q or "FROM SALESFORCE_USER" in q:
        def build_sf_user(user):
            groups = user.get("groups",[])
            profile = (
                "System Administrator" if "admins" in groups else
                "Finance User"         if "finance" in groups else
                "Sales User"           if "crm" in groups else
                "Standard User"
            )
            return {
                "Id":               user["id"],
                "Username":         user["email"],
                "Email":            user["email"],
                "FirstName":        user["firstName"],
                "LastName":         user["lastName"],
                "IsActive":         user["status"] == "ACTIVE",
                "Profile":          {"Name": profile},
                "UserRole":         {"Name": user["title"]},
                "Department":       user["department"],
                "Title":            user["title"],
                "LastLoginDate":    user["lastLogin"],
                "CreatedDate":      user["created"],
                "UserType":         "Standard" if user.get("employeeType")=="employee" else "Guest",
                "ReceivesAdminInfoEmails": "admins" in groups,
            }
        return jsonify({
            "totalSize": len(USERS),
            "done":      True,
            "records":   [build_sf_user(u) for u in USERS],
        })

    return jsonify({"totalSize": 0, "done": True, "records": []})


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "="*60)
    print("  ACME CORP — Mock Identity Server")
    print("="*60)
    print(f"  Health check : http://localhost:5000/health")
    print(f"  Okta         : http://localhost:5000/okta")
    print(f"  Entra ID     : http://localhost:5000/entra")
    print(f"  Google WS    : http://localhost:5000/google")
    print(f"  BambooHR     : http://localhost:5000/bamboohr")
    print(f"  Workday      : http://localhost:5000/workday")
    print(f"  GitHub       : http://localhost:5000/github")
    print(f"  AWS IAM      : http://localhost:5000/aws")
    print(f"  Salesforce   : http://localhost:5000/salesforce")
    print("="*60)
    print(f"\n  Seeded users : {len(USERS)}")
    print(f"  Violations   : Terminated active, Post-term login,")
    print(f"                 Dormant, MFA off, Contractor no expiry,")
    print(f"                 SoD violation, Privilege creep,")
    print(f"                 Orphaned, Generic account, Super-user")
    print("\n  Credentials in /health endpoint")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
