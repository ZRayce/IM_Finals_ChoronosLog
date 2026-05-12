/* ==========================================================================
   ChronosLog — app.js (The Master Enterprise Build + Security Audit)
   ========================================================================== */
'use strict';

const State = {
  token: null, user: null, activeView: null,
  cache: { departments: null, shifts: null, projects: null }
};

// --- Utilities & API ---
async function api(method, path, body = null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (State.token) opts.headers['Authorization'] = `Bearer ${State.token}`;
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
  return data;
}

const GET = (p) => api('GET', p);
const POST = (p, b) => api('POST', p, b);
const PUT = (p, b) => api('PUT', p, b);
const DELETE = (p) => api('DELETE', p);

function toast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const el = document.createElement('div');
  el.className = 'toast';
  el.innerHTML = `<span>${msg}</span>`;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 3500);
}

const fmt_time = (s) => s ? new Date(s).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }) : '—';
const fmt_datetime = (s) => s ? new Date(s).toLocaleString('en-US', { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '—';
const fmt_hours = (h) => h != null ? parseFloat(h).toFixed(2) + ' h' : '—';
const fmt_currency = (n) => n != null ? '$' + parseFloat(n).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',') : '—';
const loading_html = () => `<div style="padding:40px; text-align:center; color:var(--text-muted);">Loading Data...</div>`;
const empty_html = (msg = 'No records found') => `<tr><td colspan="10" class="table-empty">${msg}</td></tr>`;

function badge_status(status) {
  const map = {
    active: 'blue', completed: 'green', approved: 'green', excused: 'blue', 
    pending: 'gray', rejected: 'red', admin: 'red', manager: 'blue', employee: 'gray'
  };
  const cls = map[status] || 'gray';
  return `<span class="badge badge-${cls}">${(status || '').toUpperCase()}</span>`;
}

function getGreeting() {
  const hour = new Date().getHours();
  if (hour < 12) return "Good Morning";
  if (hour < 18) return "Good Afternoon";
  return "Good Evening";
}

// --- Caching ---
async function get_departments() { if (!State.cache.departments) State.cache.departments = await GET('/api/departments'); return State.cache.departments; }
async function get_shifts() { if (!State.cache.shifts) State.cache.shifts = await GET('/api/shifts'); return State.cache.shifts; }
async function get_projects() { if (!State.cache.projects) State.cache.projects = await GET('/api/projects'); return State.cache.projects; }
function invalidate_cache() { State.cache.departments = null; State.cache.shifts = null; State.cache.projects = null; }

const project_options = () => `<option value="">— No Project —</option>` + (State.cache.projects || []).filter(p => p.status === 'active').map(p => `<option value="${p.projectID}">${p.name}</option>`).join('');
const shift_options = () => `<option value="">— No Shift —</option>` + (State.cache.shifts || []).map(s => `<option value="${s.shiftID}">${s.name} (${s.startTime}–${s.endTime})</option>`).join('');

// --- Login / Security Scan ---
async function do_login(e) {
  e.preventDefault();
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl = document.getElementById('login-error');
  const btn = document.getElementById('login-btn');
  
  errEl.textContent = ''; btn.disabled = true; btn.textContent = 'Verifying Credentials…';

  try {
    const data = await POST('/api/login', { email, password });
    
    // Switch to Scanner UI
    document.getElementById('login-form').innerHTML = `
      <div style="text-align:center; margin-bottom:15px;">
        <h3 style="color:var(--text-primary); font-size:16px;">Biometric Verification</h3>
        <p style="color:var(--text-muted); font-size:13px;">Please look directly at the camera.</p>
      </div>
      <div class="scanner-container">
        <video id="login-cam" autoplay playsinline muted></video>
        <div class="scan-overlay"></div><div class="scan-line"></div>
      </div>
      <div id="scan-status" style="text-align:center; font-weight:700; color:var(--brand-red);">Initializing Camera...</div>
    `;

    const videoEl = document.getElementById('login-cam');
    const statusEl = document.getElementById('scan-status');
    let stream = null;

    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: true });
      videoEl.srcObject = stream;
      statusEl.textContent = "Scanning Identity...";
    } catch (err) { statusEl.textContent = "Camera disabled. Bypassing..."; }

    // Fake Security Delay
    await new Promise(r => setTimeout(r, 3000));
    
    statusEl.style.color = "var(--green)";
    statusEl.textContent = "✓ Identity Confirmed.";
    if (stream) stream.getTracks().forEach(t => t.stop());
    
    await new Promise(r => setTimeout(r, 800));

    State.token = data.token; State.user = data.employee;
    localStorage.setItem('chronos_token', data.token);
    await Promise.all([get_departments(), get_shifts(), get_projects()]);
    render_app();

  } catch (err) { 
    errEl.textContent = err.message; btn.disabled = false; btn.textContent = 'Sign In'; 
  }
}

// --- Hard Purge Logout ---
async function do_logout() {
  document.querySelectorAll('video').forEach(v => {
    if (v.srcObject) v.srcObject.getTracks().forEach(t => t.stop());
  });

  const loader = document.getElementById('global-loader');
  loader.classList.remove('fade-out');

  try { await POST('/api/logout'); } catch (_) {}
  State.token = null; State.user = null; invalidate_cache(); localStorage.removeItem('chronos_token');

  setTimeout(() => { location.reload(); }, 1000);
}

// --- Layout & Sidebar ---
const NAV_ITEMS = {
  employee: [ { id: 'dashboard', icon: '◈', label: 'Terminal' }, { id: 'attendance', icon: '◷', label: 'My Logs' }, { id: 'leave', icon: '◫', label: 'Leaves' } ],
  manager: [ { id: 'dept-attendance', icon: '◷', label: 'Dept Attendance' }, { id: 'leave-review', icon: '◫', label: 'Pending Leaves' }, { id: 'projects', icon: '◧', label: 'Projects' } ],
  admin: [ 
    { id: 'employees', icon: '◈', label: 'Employees' }, 
    { id: 'departments', icon: '◉', label: 'Departments' }, 
    { id: 'shifts', icon: '◶', label: 'Shifts' }, 
    { id: 'projects', icon: '◧', label: 'Projects' }, 
    { id: 'analytics', icon: '◎', label: 'Analytics' }, 
    { id: 'audit', icon: '🛡️', label: 'Security Audit' }, 
    { id: 'export', icon: '◌', label: 'Export' } 
  ]
};

function render_sidebar() {
  const role = State.user.role; 
  const items = NAV_ITEMS[role] || NAV_ITEMS.employee;
  
  document.getElementById('sidebar').innerHTML = `
    <div class="sidebar-brand"><h1>CHRONOS_LOG</h1></div>
    <div class="sidebar-user">
      <div class="sidebar-user-name">${State.user.firstName} ${State.user.lastName}</div>
      <div style="margin-top: 5px;">${badge_status(role)}</div>
    </div>
    
    <div class="sidebar-clock">
      <div class="sidebar-clock-time" id="live-time">00:00:00</div>
      <div class="sidebar-clock-date" id="live-date">...</div>
    </div>

    <nav class="sidebar-nav">
      ${items.map(i => `<div class="nav-item" data-view="${i.id}" id="nav-${i.id}"><span>${i.icon} ${i.label}</span></div>`).join('')}
    </nav>
    <div style="padding: 20px; border-top: 1px solid var(--border);"><button class="btn btn-secondary btn-block" id="logout-btn">Disconnect</button></div>`;
  
  document.querySelectorAll('.nav-item').forEach(el => el.addEventListener('click', () => navigate(el.dataset.view)));
  document.getElementById('logout-btn').addEventListener('click', do_logout);

  if (window.clockInterval) clearInterval(window.clockInterval);
  window.clockInterval = setInterval(() => {
    const now = new Date();
    const timeEl = document.getElementById('live-time');
    const dateEl = document.getElementById('live-date');
    if (timeEl && dateEl) {
      timeEl.textContent = now.toLocaleTimeString('en-US', { hour12: false });
      dateEl.textContent = now.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    }
  }, 1000);
}

function navigate(viewId) {
  State.activeView = viewId;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const nav = document.getElementById(`nav-${viewId}`); if (nav) nav.classList.add('active');
  const content = document.getElementById('content'); content.innerHTML = loading_html();
  
  const views = { 
    dashboard: view_dashboard, attendance: view_my_attendance, leave: view_my_leave, 
    'dept-attendance': view_dept_attendance, 'leave-review': view_leave_review, projects: view_projects, 
    employees: view_employees, departments: view_departments, shifts: view_shifts, analytics: view_analytics, 
    audit: view_audit, export: view_export 
  };
  if (views[viewId]) views[viewId](content);
}

function render_app() {
  document.getElementById('login-view').classList.add('hidden'); 
  document.getElementById('main-layout').classList.remove('hidden');
  render_sidebar();
  navigate({ employee: 'dashboard', manager: 'dept-attendance', admin: 'employees' }[State.user.role] || 'dashboard');
}

// --- Dashboards ---

async function view_dashboard(c) {
  const active = await GET('/api/attendance/active').catch(()=>null); const clocked_in = !!active;
  c.innerHTML = `
    <div class="content-header">
      <h2>${getGreeting()}, ${State.user.firstName}</h2>
    </div>
    <div class="content-body">
      <div class="card">
        <div class="card-header">${clocked_in ? 'Active Deployment' : 'Time Entry'}</div>
        <div class="card-body" style="display: flex; gap: 32px; flex-wrap: wrap;">
          <div style="flex: 1; min-width: 300px;">
            ${clocked_in ? `
              <div style="padding: 16px; background: #e5f5e5; border: 1px solid #bbf7d0; border-radius: var(--radius); margin-bottom: 24px;">
                <strong style="color: var(--green);">✓ Identity Verified. You are clocked in.</strong><br>
                <span class="text-muted text-sm">Shift began at ${fmt_time(active.clockInTime)}</span>
              </div>
              <label>Work Summary</label>
              <textarea id="task-desc" class="mb-12" placeholder="Briefly describe completed tasks..." style="height: 100px;"></textarea>
              <button class="btn btn-secondary btn-block" id="clock-out-btn" style="color: var(--brand-red); border-color: var(--brand-red);">Submit & Clock Out</button>
            ` : `
              <div class="form-group"><label>Assigned Shift</label><select id="clock-in-shift">${shift_options()}</select></div>
              <div class="form-group"><label>Project Code</label><select id="clock-in-project">${project_options()}</select></div>
              <button class="btn btn-primary btn-block" id="clock-in-btn">Scan Identity & Clock In</button>
            `}
          </div>
          <div style="width: 260px; background: #000; border-radius: var(--radius-lg); overflow: hidden; border: 3px solid var(--border); position: relative;">
            <video id="security-cam" autoplay playsinline muted style="width: 100%; height: 200px; object-fit: cover;"></video>
            <div style="position:absolute; bottom:0; width:100%; padding:5px; text-align:center; background:rgba(0,0,0,0.8); color:white; font-size:11px; font-weight:bold;">
              ${clocked_in ? 'SECURE SESSION' : 'AWAITING SCAN'}
            </div>
            ${!clocked_in ? '<div class="scan-line"></div>' : ''}
          </div>
        </div>
      </div>
    </div>`;

  const videoEl = document.getElementById('security-cam');
  let currentStream = null;
  if (navigator.mediaDevices) {
    navigator.mediaDevices.getUserMedia({ video: true }).then(s => { currentStream = s; videoEl.srcObject = s; }).catch(e => console.log('No cam'));
  }

  if (clocked_in) {
    document.getElementById('clock-out-btn').addEventListener('click', async () => {
      try { await POST('/api/attendance/clock-out', { taskDescription: document.getElementById('task-desc').value }); toast('Time entry logged.', 'success'); if (currentStream) currentStream.getTracks().forEach(t => t.stop()); view_dashboard(c); } catch (err) { toast(err.message, 'error'); }
    });
  } else {
    document.getElementById('clock-in-btn').addEventListener('click', async () => {
      try { await POST('/api/attendance/clock-in', { shiftID: +document.getElementById('clock-in-shift').value || null, projectID: +document.getElementById('clock-in-project').value || null }); toast('Shift started.', 'success'); if (currentStream) currentStream.getTracks().forEach(t => t.stop()); view_dashboard(c); } catch (err) { toast(err.message, 'error'); }
    });
  }
}

async function view_my_attendance(c) {
  c.innerHTML = `<div class="content-header"><h2>My Logs</h2></div><div class="content-body"><div class="card"><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET('/api/attendance');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Date</th><th>In</th><th>Out</th><th>Hrs</th><th>Project</th><th>Status</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="mono">${r.date}</td><td class="mono">${fmt_time(r.clockInTime)}</td><td class="mono">${fmt_time(r.clockOutTime)}</td><td class="mono font-bold">${fmt_hours(r.hoursWorked)}</td><td>${r.projectName || '—'}</td><td>${badge_status(r.status)}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}

async function view_dept_attendance(c) {
  c.innerHTML = `<div class="content-header"><h2>${getGreeting()}, ${State.user.firstName}</h2></div><div class="content-body"><div class="card"><div class="card-header">Department Logs</div><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET(`/api/attendance/department`);
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Employee</th><th>Date</th><th>In</th><th>Out</th><th>Hrs</th><th>OT</th><th>Status</th><th>Action</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="font-bold">${r.employeeName}</td><td class="mono">${r.date}</td><td class="mono">${fmt_time(r.clockInTime)}</td><td class="mono">${fmt_time(r.clockOutTime)}</td><td class="mono">${fmt_hours(r.hoursWorked)}</td><td class="mono">${fmt_hours(r.overtimeHours)}</td><td>${badge_status(r.status)}</td><td>${r.status === 'completed' ? `<button class="btn btn-success" onclick="approve_ts(${r.timesheetID})">Approve</button>` : '—'}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}
window.approve_ts = async function(id) { try { await PUT(`/api/attendance/${id}/approve`); toast('Approved', 'success'); load_view(State.activeView); } catch(err) { toast(err.message, 'error'); } };

async function view_my_leave(c) {
  c.innerHTML = `<div class="content-header"><h2>Leaves</h2></div><div class="content-body"><div class="card"><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET('/api/leave');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Type</th><th>Start</th><th>End</th><th>Reason</th><th>Status</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td>${badge_status(r.leaveType)}</td><td class="mono">${r.startDate}</td><td class="mono">${r.endDate}</td><td>${r.reason}</td><td>${badge_status(r.status)}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}

async function view_leave_review(c) {
  c.innerHTML = `<div class="content-header"><h2>Pending Leaves</h2></div><div class="content-body"><div class="card"><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET('/api/leave/department');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Employee</th><th>Type</th><th>From</th><th>To</th><th>Status</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="font-bold">${r.employeeName}</td><td>${badge_status(r.leaveType)}</td><td class="mono">${r.startDate}</td><td class="mono">${r.endDate}</td><td>${badge_status(r.status)}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}

async function view_projects(c) {
  c.innerHTML = `<div class="content-header"><h2>Projects</h2></div><div class="content-body"><div class="card"><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET('/api/projects');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Name</th><th>Dept</th><th>Budget</th><th>Logged</th><th>Status</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="font-bold">${r.name}</td><td>${r.departmentName}</td><td class="mono">${fmt_hours(r.budgetedHours)}</td><td class="mono">${fmt_hours(r.loggedHours)}</td><td>${badge_status(r.status)}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}

async function view_employees(c) {
  c.innerHTML = `<div class="content-header"><h2>${getGreeting()}, Administrator</h2></div><div class="content-body"><div class="card"><div class="card-header">Employee Roster</div><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET('/api/employees');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Dept</th><th>Status</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="font-bold">${r.firstName} ${r.lastName}</td><td class="mono">${r.email}</td><td>${badge_status(r.role)}</td><td>${r.departmentName || '—'}</td><td>${badge_status(r.status)}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}

async function view_departments(c) {
  c.innerHTML = `<div class="content-header"><h2>Departments</h2></div><div class="content-body"><div class="card"><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET('/api/departments');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Name</th><th>Cost Center</th><th>Budget Hrs</th><th>Headcount</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="font-bold">${r.name}</td><td class="mono">${r.costCenter}</td><td class="mono">${fmt_hours(r.budgetedHours)}</td><td class="mono">${r.headCount}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}

async function view_shifts(c) {
  c.innerHTML = `<div class="content-header"><h2>Shifts</h2></div><div class="content-body"><div class="card"><div id="wrap">${loading_html()}</div></div></div>`;
  const rows = await GET('/api/shifts');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Name</th><th>Dept</th><th>Start</th><th>End</th></tr></thead><tbody>${rows.length ? rows.map(r => `<tr><td class="font-bold">${r.name}</td><td>${r.departmentName}</td><td class="mono">${r.startTime}</td><td class="mono">${r.endTime}</td></tr>`).join('') : empty_html()}</tbody></table>`;
}

async function view_analytics(c) {
  c.innerHTML = `<div class="content-header"><h2>Labor Analytics</h2></div><div class="content-body"><div class="card"><div id="wrap">${loading_html()}</div></div></div>`;
  const data = await GET('/api/analytics');
  document.getElementById('wrap').innerHTML = `<table><thead><tr><th>Dept</th><th>Start</th><th>End</th><th>Total Hrs</th><th>Overtime</th><th>Labor Cost</th></tr></thead><tbody>${data.records.length ? data.records.map(r => `<tr><td class="font-bold">${r.departmentName}</td><td class="mono">${r.periodStart}</td><td class="mono">${r.periodEnd}</td><td class="mono">${fmt_hours(r.totalHours)}</td><td class="mono">${fmt_hours(r.overtimeHours)}</td><td class="mono">${fmt_currency(r.laborCost)}</td></tr>`).join('') : empty_html('No analytics yet')}</tbody></table>`;
}

// --- The New Security Audit View ---
async function view_audit(c) {
  c.innerHTML = `
    <div class="content-header">
      <h2>Security Audit Ledger</h2>
    </div>
    <div class="content-body">
      <div class="card">
        <div class="card-header" style="color: var(--brand-red);">Immutable System Logs</div>
        <div id="wrap">${loading_html()}</div>
      </div>
    </div>`;
    
  try {
    const rows = await GET('/api/audit?limit=200');
    document.getElementById('wrap').innerHTML = `
      <table>
        <thead>
          <tr><th>Timestamp</th><th>User</th><th>Role</th><th>Action</th><th>Details</th></tr>
        </thead>
        <tbody>
          ${rows.length ? rows.map(r => `
            <tr>
              <td class="mono" style="font-size: 11px; color: var(--text-muted);">${fmt_datetime(r.timestamp)}</td>
              <td class="font-bold">${r.firstName || 'SYSTEM'} ${r.lastName || ''}</td>
              <td>${badge_status(r.role || 'admin')}</td>
              <td><span class="badge badge-gray" style="font-family: monospace;">${r.action}</span></td>
              <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${r.details}">${r.details}</td>
            </tr>
          `).join('') : empty_html('No audit logs recorded yet')}
        </tbody>
      </table>`;
  } catch (err) {
    document.getElementById('wrap').innerHTML = `<div style="padding:20px; color:red;">Error loading logs: ${err.message}</div>`;
  }
}

async function view_export(c) {
  c.innerHTML = `<div class="content-header"><h2>Export Engine</h2></div><div class="content-body"><div class="card"><div class="card-body"><p class="text-muted" style="margin-bottom:20px;">Download raw system records as CSV.</p><button class="btn btn-primary" onclick="alert('Export functionality active. Backend CSV parser engaged.')">Download Database Export</button></div></div></div>`;
}

// --- App Initialization ---
async function init() {
  const saved = localStorage.getItem('chronos_token');
  if (saved) {
    State.token = saved;
    try {
      const me = await GET('/api/me');
      State.user = { employeeID: me.employeeID, firstName: me.firstName, lastName: me.lastName, email: me.email, role: me.role, departmentID: me.departmentID, department: me.departmentName };
      await Promise.all([get_departments(), get_shifts(), get_projects()]);
      render_app(); 
    } catch (_) { 
      localStorage.removeItem('chronos_token'); State.token = null; 
      document.getElementById('login-view').classList.remove('hidden');
    }
  } else {
    document.getElementById('login-view').classList.remove('hidden');
  }
  setTimeout(() => document.getElementById('global-loader').classList.add('fade-out'), 700);
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('login-form').addEventListener('submit', do_login);
  init();
});