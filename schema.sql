-- =============================================================================
-- ChronosLog: Automated Workforce Analytics & Labor Allocation
-- Database Schema - Strict 3NF with Foreign Key Constraints
-- =============================================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- =============================================================================
-- TABLE: Departments
-- =============================================================================
CREATE TABLE IF NOT EXISTS Departments (
    departmentID  INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    costCenter    TEXT    NOT NULL,
    budgetedHours REAL    NOT NULL DEFAULT 0,
    createdAt     TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- =============================================================================
-- TABLE: Employees
-- =============================================================================
CREATE TABLE IF NOT EXISTS Employees (
    employeeID   INTEGER PRIMARY KEY AUTOINCREMENT,
    departmentID INTEGER,
    firstName    TEXT    NOT NULL,
    lastName     TEXT    NOT NULL,
    email        TEXT    NOT NULL UNIQUE,
    passwordHash TEXT    NOT NULL,
    hireDate     TEXT    NOT NULL,
    hourlyRate   REAL    NOT NULL DEFAULT 0,
    status       TEXT    NOT NULL DEFAULT 'active'
                         CHECK(status IN ('active','inactive','on_leave')),
    role         TEXT    NOT NULL DEFAULT 'employee'
                         CHECK(role IN ('employee','manager','admin')),
    createdAt    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (departmentID) REFERENCES Departments(departmentID)
                               ON UPDATE CASCADE ON DELETE SET NULL
);

-- =============================================================================
-- TABLE: Projects
-- =============================================================================
CREATE TABLE IF NOT EXISTS Projects (
    projectID      INTEGER PRIMARY KEY AUTOINCREMENT,
    departmentID   INTEGER NOT NULL,
    name           TEXT    NOT NULL,
    budgetedHours  REAL    NOT NULL DEFAULT 0,
    startDate      TEXT    NOT NULL,
    endDate        TEXT,
    status         TEXT    NOT NULL DEFAULT 'active'
                           CHECK(status IN ('active','completed','on_hold')),
    createdAt      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (departmentID) REFERENCES Departments(departmentID)
                               ON UPDATE CASCADE ON DELETE RESTRICT
);

-- =============================================================================
-- TABLE: Shifts
-- =============================================================================
CREATE TABLE IF NOT EXISTS Shifts (
    shiftID      INTEGER PRIMARY KEY AUTOINCREMENT,
    departmentID INTEGER NOT NULL,
    name         TEXT    NOT NULL,
    startTime    TEXT    NOT NULL,   -- HH:MM (24h)
    endTime      TEXT    NOT NULL,   -- HH:MM (24h)
    createdAt    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (departmentID) REFERENCES Departments(departmentID)
                               ON UPDATE CASCADE ON DELETE RESTRICT
);

-- =============================================================================
-- TABLE: TimeSheets
-- =============================================================================
CREATE TABLE IF NOT EXISTS TimeSheets (
    timesheetID     INTEGER PRIMARY KEY AUTOINCREMENT,
    projectID       INTEGER,
    employeeID      INTEGER NOT NULL,
    shiftID         INTEGER,
    approvedBy      INTEGER,
    date            TEXT    NOT NULL,
    clockInTime     TEXT,               -- ISO datetime
    clockOutTime    TEXT,               -- ISO datetime
    hoursWorked     REAL    DEFAULT 0,
    overtimeHours   REAL    DEFAULT 0,
    taskDescription TEXT,
    status          TEXT    NOT NULL DEFAULT 'active'
                            CHECK(status IN ('active','completed','approved','excused')),
    submittedAt     TEXT,
    createdAt       TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (projectID)  REFERENCES Projects(projectID)
                             ON UPDATE CASCADE ON DELETE SET NULL,
    FOREIGN KEY (employeeID) REFERENCES Employees(employeeID)
                             ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (shiftID)    REFERENCES Shifts(shiftID)
                             ON UPDATE CASCADE ON DELETE SET NULL,
    FOREIGN KEY (approvedBy) REFERENCES Employees(employeeID)
                             ON UPDATE CASCADE ON DELETE SET NULL
);

-- Prevent duplicate active clock-ins on the same day
CREATE UNIQUE INDEX IF NOT EXISTS idx_active_clockin
    ON TimeSheets(employeeID, date)
    WHERE status = 'active';

-- =============================================================================
-- TABLE: LeaveRequests
-- =============================================================================
CREATE TABLE IF NOT EXISTS LeaveRequests (
    leaveID     INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeID  INTEGER NOT NULL,
    startDate   TEXT    NOT NULL,
    endDate     TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    leaveType   TEXT    NOT NULL DEFAULT 'vacation'
                        CHECK(leaveType IN ('vacation','sick','personal','emergency','other')),
    status      TEXT    NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending','approved','rejected','expired')),
    requestedAt TEXT    NOT NULL DEFAULT (datetime('now')),
    reviewedBy  INTEGER,
    reviewedAt  TEXT,
    reviewNote  TEXT,
    FOREIGN KEY (employeeID) REFERENCES Employees(employeeID)
                             ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (reviewedBy) REFERENCES Employees(employeeID)
                             ON UPDATE CASCADE ON DELETE SET NULL
);

-- =============================================================================
-- TABLE: LaborAnalytics
-- =============================================================================
CREATE TABLE IF NOT EXISTS LaborAnalytics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    departmentID    INTEGER NOT NULL,
    periodStart     TEXT    NOT NULL,
    periodEnd       TEXT    NOT NULL,
    totalHours      REAL    DEFAULT 0,
    overtimeHours   REAL    DEFAULT 0,
    utilizationRate REAL    DEFAULT 0,  -- percentage: actualHours / budgetedHours * 100
    laborCost       REAL    DEFAULT 0,
    generatedAt     TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (departmentID) REFERENCES Departments(departmentID)
                               ON UPDATE CASCADE ON DELETE CASCADE
);

-- =============================================================================
-- TABLE: Sessions
-- =============================================================================
CREATE TABLE IF NOT EXISTS Sessions (
    sessionID  TEXT    PRIMARY KEY,
    employeeID INTEGER NOT NULL,
    createdAt  TEXT    NOT NULL DEFAULT (datetime('now')),
    expiresAt  TEXT    NOT NULL,
    FOREIGN KEY (employeeID) REFERENCES Employees(employeeID)
                             ON UPDATE CASCADE ON DELETE CASCADE
);

-- =============================================================================
-- TABLE: SystemAuditLogs
-- =============================================================================
CREATE TABLE IF NOT EXISTS SystemAuditLogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    employeeID  INTEGER,
    action      TEXT    NOT NULL,
    details     TEXT,
    ipAddress   TEXT,
    timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (employeeID) REFERENCES Employees(employeeID)
                             ON UPDATE CASCADE ON DELETE SET NULL
);

-- =============================================================================
-- SEED DATA
-- All passwords = "password" (SHA-256)
-- Hash: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
-- =============================================================================

-- Departments
INSERT OR IGNORE INTO Departments (name, costCenter, budgetedHours) VALUES
    ('Engineering',  'CC-ENG-001', 2000),
    ('Marketing',    'CC-MKT-002', 1200),
    ('Human Resources', 'CC-HR-003', 800);

-- Employees: Admin
INSERT OR IGNORE INTO Employees
    (departmentID, firstName, lastName, email, passwordHash, hireDate, hourlyRate, status, role)
VALUES
    (NULL, 'System', 'Administrator', 'admin@chronos.com',
     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
     '2020-01-01', 0.00, 'active', 'admin');

-- Employees: Managers
INSERT OR IGNORE INTO Employees
    (departmentID, firstName, lastName, email, passwordHash, hireDate, hourlyRate, status, role)
VALUES
    (1, 'Marcus', 'Reyes', 'm.reyes@chronos.com',
     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
     '2021-03-15', 55.00, 'active', 'manager'),
    (2, 'Sandra', 'Chen', 's.chen@chronos.com',
     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
     '2021-06-01', 50.00, 'active', 'manager');

-- Employees: Staff
INSERT OR IGNORE INTO Employees
    (departmentID, firstName, lastName, email, passwordHash, hireDate, hourlyRate, status, role)
VALUES
    (1, 'John',  'Doe',    'j.doe@chronos.com',
     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
     '2022-02-14', 38.00, 'active', 'employee'),
    (1, 'Aisha', 'Patel',  'a.patel@chronos.com',
     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
     '2022-08-01', 40.00, 'active', 'employee'),
    (2, 'Luis',  'Gomez',  'l.gomez@chronos.com',
     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
     '2023-01-10', 34.00, 'active', 'employee'),
    (3, 'Nina',  'Torres', 'n.torres@chronos.com',
     '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
     '2023-04-20', 36.00, 'active', 'employee');

-- Projects
INSERT OR IGNORE INTO Projects (departmentID, name, budgetedHours, startDate, endDate, status) VALUES
    (1, 'Platform API v3 Refactor',   600, '2025-01-01', '2025-06-30', 'active'),
    (1, 'Infrastructure Migration',   400, '2025-03-01', '2025-12-31', 'active'),
    (2, 'Q2 Brand Campaign',          200, '2025-04-01', '2025-06-30', 'active'),
    (2, 'Website Redesign',           300, '2025-01-15', '2025-05-31', 'completed'),
    (3, 'Onboarding Automation',      150, '2025-02-01', '2025-07-31', 'active');

-- Shifts
INSERT OR IGNORE INTO Shifts (departmentID, name, startTime, endTime) VALUES
    (1, 'Morning Shift',   '07:00', '15:00'),
    (1, 'Standard Shift',  '09:00', '17:00'),
    (1, 'Evening Shift',   '13:00', '21:00'),
    (2, 'Standard Shift',  '09:00', '17:00'),
    (2, 'Flex Shift',      '10:00', '18:00'),
    (3, 'Standard Shift',  '08:30', '16:30');

-- Historical Timesheets (last 5 business days of sample data)
INSERT OR IGNORE INTO TimeSheets
    (employeeID, projectID, shiftID, date, clockInTime, clockOutTime,
     hoursWorked, overtimeHours, taskDescription, status, submittedAt)
VALUES
    -- John Doe (employeeID=4), Engineering
    (4, 1, 2, date('now','-5 days'),
     datetime('now','-5 days','start of day','+9 hours'),
     datetime('now','-5 days','start of day','+17 hours'),
     8.0, 0.0, 'Refactored authentication module; updated JWT logic', 'approved',
     datetime('now','-5 days','start of day','+17 hours')),

    (4, 1, 2, date('now','-4 days'),
     datetime('now','-4 days','start of day','+9 hours'),
     datetime('now','-4 days','start of day','+18 hours 30 minutes'),
     9.5, 1.5, 'API endpoint testing, wrote unit tests for auth endpoints', 'approved',
     datetime('now','-4 days','start of day','+18 hours 30 minutes')),

    (4, 2, 2, date('now','-3 days'),
     datetime('now','-3 days','start of day','+9 hours'),
     datetime('now','-3 days','start of day','+17 hours'),
     8.0, 0.0, 'Docker container configuration for staging environment', 'completed',
     datetime('now','-3 days','start of day','+17 hours')),

    -- Aisha Patel (employeeID=5), Engineering
    (5, 1, 2, date('now','-5 days'),
     datetime('now','-5 days','start of day','+9 hours'),
     datetime('now','-5 days','start of day','+17 hours'),
     8.0, 0.0, 'Frontend component refactoring; responsive design fixes', 'approved',
     datetime('now','-5 days','start of day','+17 hours')),

    (5, 2, 2, date('now','-4 days'),
     datetime('now','-4 days','start of day','+9 hours'),
     datetime('now','-4 days','start of day','+19 hours'),
     10.0, 2.0, 'Cloud storage migration scripts, data validation layer', 'approved',
     datetime('now','-4 days','start of day','+19 hours')),

    -- Luis Gomez (employeeID=6), Marketing
    (6, 3, 4, date('now','-5 days'),
     datetime('now','-5 days','start of day','+9 hours'),
     datetime('now','-5 days','start of day','+17 hours'),
     8.0, 0.0, 'Social media calendar planning for Q2 campaign', 'approved',
     datetime('now','-5 days','start of day','+17 hours')),

    (6, 3, 4, date('now','-3 days'),
     datetime('now','-3 days','start of day','+9 hours'),
     datetime('now','-3 days','start of day','+17 hours'),
     8.0, 0.0, 'Campaign asset creation and copywriting review', 'completed',
     datetime('now','-3 days','start of day','+17 hours'));

-- Sample Leave Request
INSERT OR IGNORE INTO LeaveRequests
    (employeeID, startDate, endDate, reason, leaveType, status, requestedAt)
VALUES
    (4, date('now','+7 days'), date('now','+9 days'),
     'Family vacation planned months in advance', 'vacation', 'pending',
     datetime('now','-1 hours')),
    (6, date('now','+2 days'), date('now','+2 days'),
     'Medical appointment requiring full-day absence', 'sick', 'pending',
     datetime('now','-30 minutes'));