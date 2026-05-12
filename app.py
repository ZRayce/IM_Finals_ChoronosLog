"""
app.py - ChronosLog FastAPI Application
"""

import csv
import hashlib
import io
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Optional

import database as db
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(levelname)s │ %(name)s │ %(message)s")
logger = logging.getLogger("chronoslog")

app = FastAPI(title="ChronosLog", version="1.0.0", docs_url="/api/docs")

BASE_DIR = os.path.dirname(__file__)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

SESSION_TTL_HOURS = 24
STANDARD_HOURS = 8.0          
OVERTIME_MULTIPLIER = 1.5

@app.on_event("startup")
async def startup():
    db.init_db()
    logger.info("ChronosLog is running ✓")

def hash_password(plain: str) -> str:
    return hashlib.sha256(plain.encode()).hexdigest()

def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

def today_str() -> str:
    return datetime.now().strftime("%Y-%m-%d")

def hours_between(start_iso: str, end_iso: str) -> float:
    fmt = "%Y-%m-%dT%H:%M:%S"
    try:
        start = datetime.fromisoformat(start_iso)
        end   = datetime.fromisoformat(end_iso)
    except ValueError:
        start = datetime.strptime(start_iso[:19], fmt)
        end   = datetime.strptime(end_iso[:19],   fmt)
    delta = (end - start).total_seconds() / 3600
    return round(max(delta, 0), 2)

# =============================================================================
# Security Audit Helper
# =============================================================================
def log_audit(employee_id: int, action: str, details: str, request: Request = None):
    ip = request.client.host if request and request.client else "Unknown"
    db.execute(
        "INSERT INTO SystemAuditLogs (employeeID, action, details, ipAddress, timestamp) VALUES (?, ?, ?, ?, ?)",
        (employee_id, action, details, ip, now_iso())
    )

def _get_session(token: str) -> dict:
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = token.replace("Bearer ", "").strip()
    session = db.fetchone(
        "SELECT s.*, e.role, e.departmentID, e.firstName, e.lastName, e.email, e.status "
        "FROM Sessions s JOIN Employees e ON s.employeeID = e.employeeID "
        "WHERE s.sessionID = ? AND s.expiresAt > ?",
        (token, now_iso())
    )
    if not session:
        raise HTTPException(status_code=401, detail="Session expired or invalid")
    if session["status"] != "active":
        raise HTTPException(status_code=403, detail="Account is not active")
    return session

def get_current_session(authorization: Optional[str] = Header(None)) -> dict:
    return _get_session(authorization or "")

# =============================================================================
# Pydantic Models
# =============================================================================
class LoginRequest(BaseModel):
    email: str
    password: str

class EmployeeCreate(BaseModel):
    departmentID: Optional[int] = None
    firstName: str
    lastName: str
    email: str
    password: str
    hireDate: str
    hourlyRate: float = 0.0
    status: str = "active"
    role: str = "employee"

class EmployeeUpdate(BaseModel):
    departmentID: Optional[int] = None
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    hireDate: Optional[str] = None
    hourlyRate: Optional[float] = None
    status: Optional[str] = None
    role: Optional[str] = None

class DepartmentCreate(BaseModel):
    name: str
    costCenter: str
    budgetedHours: float = 0.0

class DepartmentUpdate(BaseModel):
    name: Optional[str] = None
    costCenter: Optional[str] = None
    budgetedHours: Optional[float] = None

class ShiftCreate(BaseModel):
    departmentID: int
    name: str
    startTime: str
    endTime: str

class ShiftUpdate(BaseModel):
    departmentID: Optional[int] = None
    name: Optional[str] = None
    startTime: Optional[str] = None
    endTime: Optional[str] = None

class ProjectCreate(BaseModel):
    departmentID: int
    name: str
    budgetedHours: float = 0.0
    startDate: str
    endDate: Optional[str] = None
    status: str = "active"

class ProjectUpdate(BaseModel):
    departmentID: Optional[int] = None
    name: Optional[str] = None
    budgetedHours: Optional[float] = None
    startDate: Optional[str] = None
    endDate: Optional[str] = None
    status: Optional[str] = None

class ClockInRequest(BaseModel):
    projectID: Optional[int] = None
    shiftID: Optional[int] = None

class ClockOutRequest(BaseModel):
    taskDescription: Optional[str] = None
    projectID: Optional[int] = None

class LeaveRequest(BaseModel):
    startDate: str
    endDate: str
    reason: str
    leaveType: str = "vacation"

class LeaveReviewRequest(BaseModel):
    note: Optional[str] = None

class AnalyticsGenerateRequest(BaseModel):
    periodStart: str
    periodEnd: str
    departmentID: Optional[int] = None

# =============================================================================
# Routes
# =============================================================================
@app.get("/")
async def serve_frontend(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/login")
async def login(body: LoginRequest, request: Request):
    employee = db.fetchone(
        "SELECT * FROM Employees WHERE email = ?", (body.email.strip().lower(),)
    )
    if not employee or employee["passwordHash"] != hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if employee["status"] != "active":
        raise HTTPException(status_code=403, detail="Account is inactive")

    token     = str(uuid.uuid4())
    expires   = (datetime.now() + timedelta(hours=SESSION_TTL_HOURS)).isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO Sessions (sessionID, employeeID, expiresAt) VALUES (?, ?, ?)",
        (token, employee["employeeID"], expires)
    )

    dept = None
    if employee["departmentID"]:
        dept = db.fetchone(
            "SELECT * FROM Departments WHERE departmentID = ?", (employee["departmentID"],)
        )

    # Log the successful biometric/password login
    log_audit(employee["employeeID"], "LOGIN_SUCCESS", "User authenticated via Biometric/Password bypass", request)

    return {
        "token": token,
        "employee": {
            "employeeID":   employee["employeeID"],
            "firstName":    employee["firstName"],
            "lastName":     employee["lastName"],
            "email":        employee["email"],
            "role":         employee["role"],
            "departmentID": employee["departmentID"],
            "department":   dept["name"] if dept else None,
            "hourlyRate":   employee["hourlyRate"],
        }
    }

@app.post("/api/logout")
async def logout(request: Request, authorization: Optional[str] = Header(None)):
    if authorization:
        token = authorization.replace("Bearer ", "").strip()
        session = db.fetchone("SELECT employeeID FROM Sessions WHERE sessionID = ?", (token,))
        if session:
            # Log the secure session disconnection
            log_audit(session["employeeID"], "LOGOUT", "User disconnected session securely", request)
        db.execute("DELETE FROM Sessions WHERE sessionID = ?", (token,))
    return {"message": "Logged out"}

@app.get("/api/me")
async def get_me(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    emp = db.fetchone(
        "SELECT e.*, d.name AS departmentName "
        "FROM Employees e LEFT JOIN Departments d ON e.departmentID = d.departmentID "
        "WHERE e.employeeID = ?",
        (session["employeeID"],)
    )
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    emp.pop("passwordHash", None)
    return emp

@app.get("/api/departments")
async def list_departments(authorization: Optional[str] = Header(None)):
    get_current_session(authorization)
    return db.fetchall(
        "SELECT d.*, "
        "  (SELECT COUNT(*) FROM Employees e WHERE e.departmentID = d.departmentID AND e.status='active') AS headCount "
        "FROM Departments d ORDER BY d.name"
    )

@app.post("/api/departments", status_code=201)
async def create_department(body: DepartmentCreate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    dept_id = db.execute(
        "INSERT INTO Departments (name, costCenter, budgetedHours) VALUES (?,?,?)",
        (body.name, body.costCenter, body.budgetedHours)
    )
    return db.fetchone("SELECT * FROM Departments WHERE departmentID = ?", (dept_id,))

@app.put("/api/departments/{dept_id}")
async def update_department(dept_id: int, body: DepartmentUpdate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    set_clause = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE Departments SET {set_clause} WHERE departmentID=?",
               (*fields.values(), dept_id))
    return db.fetchone("SELECT * FROM Departments WHERE departmentID = ?", (dept_id,))

@app.get("/api/employees")
async def list_employees(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] == "employee":
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    if session["role"] == "manager":
        rows = db.fetchall(
            "SELECT e.employeeID, e.firstName, e.lastName, e.email, e.role, e.status, "
            "       e.hireDate, e.hourlyRate, e.departmentID, d.name AS departmentName "
            "FROM Employees e LEFT JOIN Departments d ON e.departmentID = d.departmentID "
            "WHERE e.departmentID = ? ORDER BY e.lastName",
            (session["departmentID"],)
        )
    else:
        rows = db.fetchall(
            "SELECT e.employeeID, e.firstName, e.lastName, e.email, e.role, e.status, "
            "       e.hireDate, e.hourlyRate, e.departmentID, d.name AS departmentName "
            "FROM Employees e LEFT JOIN Departments d ON e.departmentID = d.departmentID "
            "ORDER BY e.lastName"
        )
    return rows

@app.post("/api/employees", status_code=201)
async def create_employee(body: EmployeeCreate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    existing = db.fetchone("SELECT employeeID FROM Employees WHERE email=?", (body.email.lower(),))
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    emp_id = db.execute(
        "INSERT INTO Employees (departmentID, firstName, lastName, email, passwordHash, "
        "hireDate, hourlyRate, status, role) VALUES (?,?,?,?,?,?,?,?,?)",
        (body.departmentID, body.firstName, body.lastName, body.email.lower(),
         hash_password(body.password), body.hireDate, body.hourlyRate, body.status, body.role)
    )
    emp = db.fetchone(
        "SELECT e.*, d.name AS departmentName "
        "FROM Employees e LEFT JOIN Departments d ON e.departmentID = d.departmentID "
        "WHERE e.employeeID = ?", (emp_id,)
    )
    emp.pop("passwordHash", None)
    return emp

@app.put("/api/employees/{emp_id}")
async def update_employee(emp_id: int, body: EmployeeUpdate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    fields: dict[str, Any] = {}
    data = body.dict()
    for k, v in data.items():
        if v is None:
            continue
        if k == "password":
            fields["passwordHash"] = hash_password(v)
        elif k == "email":
            fields["email"] = v.lower()
        else:
            fields[k] = v
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    set_clause = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE Employees SET {set_clause} WHERE employeeID=?",
               (*fields.values(), emp_id))
    emp = db.fetchone(
        "SELECT e.*, d.name AS departmentName "
        "FROM Employees e LEFT JOIN Departments d ON e.departmentID = d.departmentID "
        "WHERE e.employeeID = ?", (emp_id,)
    )
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    emp.pop("passwordHash", None)
    return emp

@app.delete("/api/employees/{emp_id}")
async def deactivate_employee(emp_id: int, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    if emp_id == session["employeeID"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")
    db.execute("UPDATE Employees SET status='inactive' WHERE employeeID=?", (emp_id,))
    return {"message": "Employee deactivated"}

@app.get("/api/shifts")
async def list_shifts(authorization: Optional[str] = Header(None)):
    get_current_session(authorization)
    return db.fetchall(
        "SELECT s.*, d.name AS departmentName "
        "FROM Shifts s JOIN Departments d ON s.departmentID = d.departmentID "
        "ORDER BY d.name, s.startTime"
    )

@app.post("/api/shifts", status_code=201)
async def create_shift(body: ShiftCreate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    shift_id = db.execute(
        "INSERT INTO Shifts (departmentID, name, startTime, endTime) VALUES (?,?,?,?)",
        (body.departmentID, body.name, body.startTime, body.endTime)
    )
    return db.fetchone(
        "SELECT s.*, d.name AS departmentName FROM Shifts s "
        "JOIN Departments d ON s.departmentID = d.departmentID WHERE s.shiftID=?",
        (shift_id,)
    )

@app.put("/api/shifts/{shift_id}")
async def update_shift(shift_id: int, body: ShiftUpdate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    set_clause = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE Shifts SET {set_clause} WHERE shiftID=?", (*fields.values(), shift_id))
    return db.fetchone(
        "SELECT s.*, d.name AS departmentName FROM Shifts s "
        "JOIN Departments d ON s.departmentID = d.departmentID WHERE s.shiftID=?",
        (shift_id,)
    )

@app.delete("/api/shifts/{shift_id}")
async def delete_shift(shift_id: int, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    db.execute("DELETE FROM Shifts WHERE shiftID=?", (shift_id,))
    return {"message": "Shift deleted"}

@app.get("/api/projects")
async def list_projects(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] == "admin":
        return db.fetchall(
            "SELECT p.*, d.name AS departmentName, "
            "  COALESCE((SELECT SUM(t.hoursWorked) FROM TimeSheets t WHERE t.projectID=p.projectID),0) AS loggedHours "
            "FROM Projects p JOIN Departments d ON p.departmentID=d.departmentID "
            "ORDER BY p.status, p.name"
        )
    dept_id = session["departmentID"]
    return db.fetchall(
        "SELECT p.*, d.name AS departmentName, "
        "  COALESCE((SELECT SUM(t.hoursWorked) FROM TimeSheets t WHERE t.projectID=p.projectID),0) AS loggedHours "
        "FROM Projects p JOIN Departments d ON p.departmentID=d.departmentID "
        "WHERE p.departmentID=? ORDER BY p.status, p.name",
        (dept_id,)
    )

@app.post("/api/projects", status_code=201)
async def create_project(body: ProjectCreate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Admin or Manager only")
    proj_id = db.execute(
        "INSERT INTO Projects (departmentID, name, budgetedHours, startDate, endDate, status) "
        "VALUES (?,?,?,?,?,?)",
        (body.departmentID, body.name, body.budgetedHours, body.startDate, body.endDate, body.status)
    )
    return db.fetchone(
        "SELECT p.*, d.name AS departmentName FROM Projects p "
        "JOIN Departments d ON p.departmentID=d.departmentID WHERE p.projectID=?",
        (proj_id,)
    )

@app.put("/api/projects/{project_id}")
async def update_project(project_id: int, body: ProjectUpdate, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Admin or Manager only")
    fields = {k: v for k, v in body.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    set_clause = ", ".join(f"{k}=?" for k in fields)
    db.execute(f"UPDATE Projects SET {set_clause} WHERE projectID=?", (*fields.values(), project_id))
    return db.fetchone(
        "SELECT p.*, d.name AS departmentName FROM Projects p "
        "JOIN Departments d ON p.departmentID=d.departmentID WHERE p.projectID=?",
        (project_id,)
    )

@app.get("/api/attendance/active")
async def get_active_session(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    row = db.fetchone(
        "SELECT t.*, p.name AS projectName, s.name AS shiftName "
        "FROM TimeSheets t "
        "LEFT JOIN Projects p ON t.projectID = p.projectID "
        "LEFT JOIN Shifts   s ON t.shiftID   = s.shiftID "
        "WHERE t.employeeID=? AND t.status='active'",
        (session["employeeID"],)
    )
    return row  

@app.post("/api/attendance/clock-in", status_code=201)
async def clock_in(body: ClockInRequest, request: Request, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    emp_id  = session["employeeID"]
    today   = today_str()
    now     = now_iso()

    active = db.fetchone(
        "SELECT timesheetID FROM TimeSheets WHERE employeeID=? AND date=? AND status='active'",
        (emp_id, today)
    )
    if active:
        raise HTTPException(status_code=409, detail="Already clocked in today")

    ts_id = db.execute(
        "INSERT INTO TimeSheets (employeeID, projectID, shiftID, date, clockInTime, status) "
        "VALUES (?,?,?,?,?,'active')",
        (emp_id, body.projectID, body.shiftID, today, now)
    )
    
    # Log the clock in
    log_audit(emp_id, "CLOCK_IN", f"Shift initialized. ProjectID: {body.projectID}", request)

    return db.fetchone(
        "SELECT t.*, p.name AS projectName, s.name AS shiftName "
        "FROM TimeSheets t "
        "LEFT JOIN Projects p ON t.projectID=p.projectID "
        "LEFT JOIN Shifts   s ON t.shiftID  =s.shiftID "
        "WHERE t.timesheetID=?",
        (ts_id,)
    )

@app.post("/api/attendance/clock-out")
async def clock_out(body: ClockOutRequest, request: Request, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    emp_id  = session["employeeID"]
    now     = now_iso()

    active = db.fetchone(
        "SELECT * FROM TimeSheets WHERE employeeID=? AND status='active'",
        (emp_id,)
    )
    if not active:
        raise HTTPException(status_code=404, detail="No active clock-in found")

    clock_in_time  = active["clockInTime"]
    hours_worked   = hours_between(clock_in_time, now)
    overtime_hours = max(0.0, hours_worked - STANDARD_HOURS)

    project_id = body.projectID or active["projectID"]

    db.execute(
        "UPDATE TimeSheets SET clockOutTime=?, hoursWorked=?, overtimeHours=?, "
        "taskDescription=?, projectID=?, status='completed', submittedAt=? "
        "WHERE timesheetID=?",
        (now, hours_worked, overtime_hours,
         body.taskDescription, project_id, now, active["timesheetID"])
    )
    
    # Log the clock out
    log_audit(emp_id, "CLOCK_OUT", f"Shift ended. Hours logged: {hours_worked}", request)

    return db.fetchone(
        "SELECT t.*, p.name AS projectName, s.name AS shiftName "
        "FROM TimeSheets t "
        "LEFT JOIN Projects p ON t.projectID=p.projectID "
        "LEFT JOIN Shifts   s ON t.shiftID  =s.shiftID "
        "WHERE t.timesheetID=?",
        (active["timesheetID"],)
    )

@app.get("/api/attendance")
async def get_my_attendance(
    limit: int = 30,
    offset: int = 0,
    authorization: Optional[str] = Header(None)
):
    session = get_current_session(authorization)
    return db.fetchall(
        "SELECT t.*, p.name AS projectName, s.name AS shiftName "
        "FROM TimeSheets t "
        "LEFT JOIN Projects p ON t.projectID=p.projectID "
        "LEFT JOIN Shifts   s ON t.shiftID  =s.shiftID "
        "WHERE t.employeeID=? ORDER BY t.date DESC, t.clockInTime DESC LIMIT ? OFFSET ?",
        (session["employeeID"], limit, offset)
    )

@app.get("/api/attendance/department")
async def get_department_attendance(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    session = get_current_session(authorization)
    if session["role"] not in ("manager", "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    dept_id   = session["departmentID"]
    date_from = date_from or (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d")
    date_to   = date_to   or today_str()

    if session["role"] == "admin":
        rows = db.fetchall(
            "SELECT t.*, "
            "  e.firstName||' '||e.lastName AS employeeName, e.hourlyRate, "
            "  p.name AS projectName, s.name AS shiftName, d.name AS departmentName "
            "FROM TimeSheets t "
            "JOIN Employees   e ON t.employeeID   = e.employeeID "
            "JOIN Departments d ON e.departmentID  = d.departmentID "
            "LEFT JOIN Projects p ON t.projectID = p.projectID "
            "LEFT JOIN Shifts   s ON t.shiftID   = s.shiftID "
            "WHERE t.date BETWEEN ? AND ? "
            "ORDER BY t.date DESC, e.lastName",
            (date_from, date_to)
        )
    else:
        rows = db.fetchall(
            "SELECT t.*, "
            "  e.firstName||' '||e.lastName AS employeeName, e.hourlyRate, "
            "  p.name AS projectName, s.name AS shiftName, d.name AS departmentName "
            "FROM TimeSheets t "
            "JOIN Employees   e ON t.employeeID  = e.employeeID "
            "JOIN Departments d ON e.departmentID = d.departmentID "
            "LEFT JOIN Projects p ON t.projectID = p.projectID "
            "LEFT JOIN Shifts   s ON t.shiftID   = s.shiftID "
            "WHERE e.departmentID=? AND t.date BETWEEN ? AND ? "
            "ORDER BY t.date DESC, e.lastName",
            (dept_id, date_from, date_to)
        )
    return rows

@app.put("/api/attendance/{ts_id}/approve")
async def approve_timesheet(ts_id: int, request: Request, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] not in ("manager", "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    db.execute(
        "UPDATE TimeSheets SET status='approved', approvedBy=? WHERE timesheetID=?",
        (session["employeeID"], ts_id)
    )
    log_audit(session["employeeID"], "TIMESHEET_APPROVED", f"Approved timesheet {ts_id}", request)
    return {"message": "Timesheet approved"}

@app.post("/api/leave", status_code=201)
async def file_leave(body: LeaveRequest, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    emp_id  = session["employeeID"]
    now     = now_iso()

    if body.startDate > body.endDate:
        raise HTTPException(status_code=400, detail="startDate must be ≤ endDate")

    overlap = db.fetchone(
        "SELECT leaveID FROM LeaveRequests "
        "WHERE employeeID=? AND status IN ('pending','approved') "
        "AND NOT (endDate < ? OR startDate > ?)",
        (emp_id, body.startDate, body.endDate)
    )
    if overlap:
        raise HTTPException(status_code=409, detail="Overlapping leave request already exists")

    leave_id = db.execute(
        "INSERT INTO LeaveRequests (employeeID, startDate, endDate, reason, leaveType, requestedAt) "
        "VALUES (?,?,?,?,?,?)",
        (emp_id, body.startDate, body.endDate, body.reason, body.leaveType, now)
    )
    return db.fetchone("SELECT * FROM LeaveRequests WHERE leaveID=?", (leave_id,))

@app.get("/api/leave")
async def get_my_leave(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    return db.fetchall(
        "SELECT lr.*, "
        "  e2.firstName||' '||e2.lastName AS reviewerName "
        "FROM LeaveRequests lr "
        "LEFT JOIN Employees e2 ON lr.reviewedBy = e2.employeeID "
        "WHERE lr.employeeID=? ORDER BY lr.requestedAt DESC",
        (session["employeeID"],)
    )

@app.get("/api/leave/department")
async def get_department_leaves(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] not in ("manager", "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    if session["role"] == "admin":
        return db.fetchall(
            "SELECT lr.*, "
            "  e.firstName||' '||e.lastName AS employeeName, "
            "  d.name AS departmentName, "
            "  e2.firstName||' '||e2.lastName AS reviewerName "
            "FROM LeaveRequests lr "
            "JOIN Employees e ON lr.employeeID = e.employeeID "
            "LEFT JOIN Departments d ON e.departmentID = d.departmentID "
            "LEFT JOIN Employees e2 ON lr.reviewedBy = e2.employeeID "
            "ORDER BY lr.requestedAt DESC"
        )
    return db.fetchall(
        "SELECT lr.*, "
        "  e.firstName||' '||e.lastName AS employeeName, "
        "  d.name AS departmentName, "
        "  e2.firstName||' '||e2.lastName AS reviewerName "
        "FROM LeaveRequests lr "
        "JOIN Employees e ON lr.employeeID = e.employeeID "
        "LEFT JOIN Departments d ON e.departmentID = d.departmentID "
        "LEFT JOIN Employees e2 ON lr.reviewedBy = e2.employeeID "
        "WHERE e.departmentID=? ORDER BY lr.requestedAt DESC",
        (session["departmentID"],)
    )

def _enforce_48h_window(requested_at_iso: str) -> None:
    try:
        requested_at = datetime.fromisoformat(requested_at_iso)
    except ValueError:
        return  
    elapsed = (datetime.now() - requested_at).total_seconds()
    if elapsed > 48 * 3600:
        raise HTTPException(
            status_code=400,
            detail="Review window exceeded: leave requests must be reviewed within 48 hours"
        )

@app.put("/api/leave/{leave_id}/approve")
async def approve_leave(leave_id: int, body: LeaveReviewRequest,
                        request: Request, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] not in ("manager", "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    leave = db.fetchone("SELECT * FROM LeaveRequests WHERE leaveID=?", (leave_id,))
    if not leave:
        raise HTTPException(status_code=404, detail="Leave request not found")
    if leave["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Leave is already '{leave['status']}'")

    if session["role"] == "manager":
        emp = db.fetchone("SELECT departmentID FROM Employees WHERE employeeID=?",
                          (leave["employeeID"],))
        if emp and emp["departmentID"] != session["departmentID"]:
            raise HTTPException(status_code=403, detail="Leave belongs to another department")

    _enforce_48h_window(leave["requestedAt"])

    now = now_iso()
    db.execute(
        "UPDATE LeaveRequests SET status='approved', reviewedBy=?, reviewedAt=?, reviewNote=? "
        "WHERE leaveID=?",
        (session["employeeID"], now, body.note, leave_id)
    )

    db.execute(
        "UPDATE TimeSheets SET status='excused', approvedBy=? "
        "WHERE employeeID=? AND date BETWEEN ? AND ? AND status IN ('active','completed')",
        (session["employeeID"], leave["employeeID"], leave["startDate"], leave["endDate"])
    )
    
    log_audit(session["employeeID"], "LEAVE_APPROVED", f"Approved leave request {leave_id}", request)
    return {"message": "Leave approved"}

@app.put("/api/leave/{leave_id}/reject")
async def reject_leave(leave_id: int, body: LeaveReviewRequest,
                       request: Request, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] not in ("manager", "admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    leave = db.fetchone("SELECT * FROM LeaveRequests WHERE leaveID=?", (leave_id,))
    if not leave:
        raise HTTPException(status_code=404, detail="Leave request not found")
    if leave["status"] != "pending":
        raise HTTPException(status_code=400, detail=f"Leave is already '{leave['status']}'")

    if session["role"] == "manager":
        emp = db.fetchone("SELECT departmentID FROM Employees WHERE employeeID=?",
                          (leave["employeeID"],))
        if emp and emp["departmentID"] != session["departmentID"]:
            raise HTTPException(status_code=403, detail="Leave belongs to another department")

    _enforce_48h_window(leave["requestedAt"])

    db.execute(
        "UPDATE LeaveRequests SET status='rejected', reviewedBy=?, reviewedAt=?, reviewNote=? "
        "WHERE leaveID=?",
        (session["employeeID"], now_iso(), body.note, leave_id)
    )
    log_audit(session["employeeID"], "LEAVE_REJECTED", f"Rejected leave request {leave_id}", request)
    return {"message": "Leave rejected"}

@app.get("/api/analytics")
async def get_analytics(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] not in ("admin", "manager"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    records = db.fetchall(
        "SELECT la.*, d.name AS departmentName "
        "FROM LaborAnalytics la JOIN Departments d ON la.departmentID=d.departmentID "
        "ORDER BY la.generatedAt DESC LIMIT 100"
    )

    summary = db.fetchone(
        "SELECT "
        "  SUM(t.hoursWorked) AS totalHours, "
        "  SUM(t.overtimeHours) AS totalOvertime, "
        "  COUNT(DISTINCT t.employeeID) AS activeEmployees "
        "FROM TimeSheets t WHERE t.date >= date('now','-30 days')"
    )
    dept_breakdown = db.fetchall(
        "SELECT d.name, "
        "  SUM(t.hoursWorked) AS hours, "
        "  SUM(t.overtimeHours) AS overtime, "
        "  SUM(t.hoursWorked * e.hourlyRate + t.overtimeHours * e.hourlyRate * ?) AS laborCost "
        "FROM TimeSheets t "
        "JOIN Employees e ON t.employeeID=e.employeeID "
        "JOIN Departments d ON e.departmentID=d.departmentID "
        "WHERE t.date >= date('now','-30 days') "
        "GROUP BY d.departmentID ORDER BY d.name",
        (OVERTIME_MULTIPLIER,)
    )
    return {"records": records, "summary": summary, "deptBreakdown": dept_breakdown}

@app.post("/api/analytics/generate", status_code=201)
async def generate_analytics(body: AnalyticsGenerateRequest,
                             authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    if body.periodStart > body.periodEnd:
        raise HTTPException(status_code=400, detail="periodStart must be ≤ periodEnd")

    if body.departmentID:
        depts = db.fetchall("SELECT * FROM Departments WHERE departmentID=?", (body.departmentID,))
    else:
        depts = db.fetchall("SELECT * FROM Departments")

    generated = []
    for dept in depts:
        did = dept["departmentID"]
        stats = db.fetchone(
            "SELECT "
            "  COALESCE(SUM(t.hoursWorked), 0)     AS totalHours, "
            "  COALESCE(SUM(t.overtimeHours), 0)   AS overtimeHours, "
            "  COALESCE(SUM(t.hoursWorked * e.hourlyRate "
            "             + t.overtimeHours * e.hourlyRate * ?), 0) AS laborCost "
            "FROM TimeSheets t "
            "JOIN Employees e ON t.employeeID = e.employeeID "
            "WHERE e.departmentID=? AND t.date BETWEEN ? AND ? "
            "AND t.status IN ('completed','approved','excused')",
            (OVERTIME_MULTIPLIER, did, body.periodStart, body.periodEnd)
        )
        budgeted = dept["budgetedHours"]
        util_rate = round((stats["totalHours"] / budgeted * 100) if budgeted > 0 else 0, 2)

        rec_id = db.execute(
            "INSERT INTO LaborAnalytics "
            "(departmentID, periodStart, periodEnd, totalHours, overtimeHours, utilizationRate, laborCost) "
            "VALUES (?,?,?,?,?,?,?)",
            (did, body.periodStart, body.periodEnd,
             stats["totalHours"], stats["overtimeHours"], util_rate, stats["laborCost"])
        )
        rec = db.fetchone("SELECT * FROM LaborAnalytics WHERE id=?", (rec_id,))
        rec["departmentName"] = dept["name"]
        generated.append(rec)

    return {"generated": len(generated), "records": generated}

@app.get("/api/export")
async def export_timesheets(
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    authorization: Optional[str] = Header(None)
):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")

    date_from = date_from or (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    date_to   = date_to   or today_str()

    rows = db.fetchall(
        "SELECT "
        "  t.timesheetID, t.date, t.clockInTime, t.clockOutTime, "
        "  t.hoursWorked, t.overtimeHours, t.taskDescription, t.status, t.submittedAt, "
        "  e.firstName||' '||e.lastName AS employee, "
        "  e.email, e.hourlyRate, "
        "  d.name AS department, d.costCenter, "
        "  p.name AS project, "
        "  s.name AS shift, "
        "  (t.hoursWorked * e.hourlyRate + t.overtimeHours * e.hourlyRate * ?) AS totalPay "
        "FROM TimeSheets t "
        "JOIN Employees e ON t.employeeID = e.employeeID "
        "LEFT JOIN Departments d ON e.departmentID = d.departmentID "
        "LEFT JOIN Projects p ON t.projectID = p.projectID "
        "LEFT JOIN Shifts   s ON t.shiftID   = s.shiftID "
        "WHERE t.date BETWEEN ? AND ? "
        "ORDER BY t.date, e.lastName",
        (OVERTIME_MULTIPLIER, date_from, date_to)
    )

    output  = io.StringIO()
    headers = [
        "timesheetID", "date", "clockInTime", "clockOutTime",
        "hoursWorked", "overtimeHours", "taskDescription", "status", "submittedAt",
        "employee", "email", "hourlyRate",
        "department", "costCenter", "project", "shift", "totalPay"
    ]
    writer = csv.DictWriter(output, fieldnames=headers, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    output.seek(0)

    filename = f"chronoslog_timesheets_{date_from}_{date_to}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )

@app.get("/api/dashboard/stats")
async def dashboard_stats(authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    emp_id  = session["employeeID"]
    role    = session["role"]
    today   = today_str()

    if role == "employee":
        active_ts = db.fetchone(
            "SELECT * FROM TimeSheets WHERE employeeID=? AND status='active'", (emp_id,)
        )
        week_hours = db.fetchone(
            "SELECT COALESCE(SUM(hoursWorked),0) AS total FROM TimeSheets "
            "WHERE employeeID=? AND date >= date('now','weekday 1','-7 days')",
            (emp_id,)
        )
        pending_leave = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM LeaveRequests WHERE employeeID=? AND status='pending'",
            (emp_id,)
        )
        return {
            "clockedIn": active_ts is not None,
            "activeTimesheet": active_ts,
            "weekHours": week_hours["total"] if week_hours else 0,
            "pendingLeaves": pending_leave["cnt"] if pending_leave else 0,
        }

    dept_id = session["departmentID"]
    if role == "manager":
        today_present = db.fetchone(
            "SELECT COUNT(DISTINCT t.employeeID) AS cnt "
            "FROM TimeSheets t JOIN Employees e ON t.employeeID=e.employeeID "
            "WHERE e.departmentID=? AND t.date=? AND t.status IN ('active','completed','approved')",
            (dept_id, today)
        )
        headcount = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM Employees WHERE departmentID=? AND status='active'",
            (dept_id,)
        )
        pending_leaves = db.fetchone(
            "SELECT COUNT(*) AS cnt FROM LeaveRequests lr "
            "JOIN Employees e ON lr.employeeID=e.employeeID "
            "WHERE e.departmentID=? AND lr.status='pending'",
            (dept_id,)
        )
        week_hours = db.fetchone(
            "SELECT COALESCE(SUM(t.hoursWorked),0) AS total FROM TimeSheets t "
            "JOIN Employees e ON t.employeeID=e.employeeID "
            "WHERE e.departmentID=? AND t.date >= date('now','weekday 1','-7 days')",
            (dept_id,)
        )
        return {
            "todayPresent": today_present["cnt"] if today_present else 0,
            "headcount": headcount["cnt"] if headcount else 0,
            "pendingLeaves": pending_leaves["cnt"] if pending_leaves else 0,
            "weekHours": week_hours["total"] if week_hours else 0,
        }

    total_emp = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM Employees WHERE status='active'"
    )
    today_active = db.fetchone(
        "SELECT COUNT(DISTINCT employeeID) AS cnt FROM TimeSheets WHERE date=? AND status='active'",
        (today,)
    )
    pending_leaves = db.fetchone(
        "SELECT COUNT(*) AS cnt FROM LeaveRequests WHERE status='pending'"
    )
    month_hours = db.fetchone(
        "SELECT COALESCE(SUM(hoursWorked),0) AS total FROM TimeSheets "
        "WHERE date >= date('now','start of month')"
    )
    return {
        "totalEmployees": total_emp["cnt"] if total_emp else 0,
        "todayActive": today_active["cnt"] if today_active else 0,
        "pendingLeaves": pending_leaves["cnt"] if pending_leaves else 0,
        "monthHours": month_hours["total"] if month_hours else 0,
    }

# =============================================================================
# Security Audit Endpoint
# =============================================================================
@app.get("/api/audit")
async def get_audit_logs(limit: int = 200, offset: int = 0, authorization: Optional[str] = Header(None)):
    session = get_current_session(authorization)
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    
    return db.fetchall(
        "SELECT a.*, e.firstName, e.lastName, e.role "
        "FROM SystemAuditLogs a "
        "LEFT JOIN Employees e ON a.employeeID = e.employeeID "
        "ORDER BY a.timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )