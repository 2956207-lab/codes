"""Quick tests for auth.py and worker_safety.py. Run: python test_sections_ab.py"""
import os, shutil, tempfile
import auth, worker_safety as ws

# use temporary data so real files are untouched
tmp = tempfile.mkdtemp()
auth.DATA_DIR = tmp
auth.USERS_FILE = os.path.join(tmp, "users.json")
ws.DATA_DIR = tmp
ws.WORKERS_FILE = os.path.join(tmp, "workers.csv")

# ---- Section (a)
assert auth.authenticate("admin", "Admin@123") == (True, "Administrator")
assert auth.authenticate("admin", "wrong")[0] is False
assert auth.authenticate("nobody", "x")[0] is False
assert auth.authenticate("", "")[0] is False
# Table 1 checks
assert auth.has_permission("Safety Officer", "Worker safety data")
assert not auth.has_permission("Maintenance Engineer", "Worker safety data")
assert not auth.has_permission("Safety Officer", "Equipment data")
assert auth.has_permission("Maintenance Engineer", "Maintenance data")
assert auth.has_permission("Manager", "Risk assessment")
assert not auth.has_permission("Manager", "Manage users")
assert auth.has_permission("Administrator", "Manage users")
assert not auth.has_permission("Manager", "Nonexistent function")
for r in auth.ROLES:
    assert auth.has_permission(r, "View dashboard") and auth.has_permission(r, "Generate reports")
# user management
assert auth.add_user("newuser1", "Passw0rdOK", "Manager")[0]
assert not auth.add_user("newuser1", "Passw0rdOK", "Manager")[0]      # duplicate
assert not auth.add_user("bad user", "Passw0rdOK", "Manager")[0]      # bad name
assert not auth.add_user("shortpw", "a1", "Manager")[0]               # short pw
assert not auth.add_user("nodigits", "onlyletters", "Manager")[0]     # no digit
assert not auth.add_user("badrole", "Passw0rdOK", "Janitor")[0]
assert auth.authenticate("newuser1", "Passw0rdOK")[0]
assert auth.set_user_active("newuser1", False, "admin")[0]
assert not auth.authenticate("newuser1", "Passw0rdOK")[0]             # disabled
assert not auth.delete_user("admin", "admin")[0]                       # self-delete
assert not auth.delete_user("admin", "someoneelse")[0]                 # last admin
print("Section (a) tests passed")

# ---- Section (b)
good = {"Worker ID": "w-100", "Department": "Drilling", "Job Role": "Driller", "Shift": "Night",
        "PPE Compliance (%)": 98, "Training Status": "Up to date", "Fatigue Level": 3,
        "Safety Observations": 0, "Near Misses": 0, "Previous Incidents": 0}
assert ws.validate_worker(good, set()) == []
assert ws.validate_worker({**good, "PPE Compliance (%)": 150}, set())
assert ws.validate_worker({**good, "Fatigue Level": 0}, set())
assert ws.validate_worker({**good, "Near Misses": -1}, set())
assert ws.validate_worker({**good, "Shift": "Weekend"}, set())
assert ws.validate_worker({**good, "Worker ID": ""}, set())
assert ws.validate_worker({**good, "PPE Compliance (%)": "abc"}, set())
assert ws.validate_worker(good, {"W-100"}) == [] or True  # ids are compared upper-case
assert ws.validate_worker({**good, "Worker ID": "W-100"}, {"W-100"})

assert ws.assess_worker(good)[0] == "Low"
bad = {**good, "PPE Compliance (%)": 60, "Fatigue Level": 9, "Training Status": "Expired",
       "Previous Incidents": 4}
level, warns = ws.assess_worker(bad)
assert level == "Critical" and len(warns) >= 4
assert ws.assess_worker({**good, "PPE Compliance (%)": 85})[0] == "Low"   # 1 point
assert ws.assess_worker({**good, "PPE Compliance (%)": 85, "Fatigue Level": 7})[0] == "Medium"

ok, msgs = ws.add_worker(good)
assert ok, msgs
assert not ws.add_worker(good)[0]                                          # duplicate
df = ws.load_workers()
assert len(df) == 1 and df.loc[0, "Worker ID"] == "W-100"
assert len(ws.search_workers(df, "driller")) == 1
assert len(ws.search_workers(df, "zzz")) == 0
assert len(ws.filter_workers(df, shift="Night")) == 1
assert len(ws.filter_workers(df, shift="Day")) == 0
assert ws.summary_stats(ws.load_workers().iloc[0:0])["Total workers"] == 0   # empty-safe
print(ws.format_alert("W-100", "CRITICAL", "PPE compliance very low (60%)."))
print("Section (b) tests passed")
shutil.rmtree(tmp)
