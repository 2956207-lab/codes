"""
auth.py - Section (a): Access Control (login + role-based access control)
MINN2020A Mining Health, Safety and Equipment Monitoring Application

Design:
  * Users are stored in data/users.json (username -> salt, password hash, role, active flag)
  * Passwords are never stored in plain text: PBKDF2-HMAC-SHA256 with a random salt
  * Permissions come from one lookup table (PERMISSIONS) that mirrors Table 1 of the brief
  * Other team members' pages call: require_permission("Equipment data")
"""

import hashlib
import hmac
import json
import os
import secrets

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")

ROLES = ["Administrator", "Safety Officer", "Mining Engineer",
         "Maintenance Engineer", "Manager"]

# Table 1 of the project brief: function -> roles that may use it
PERMISSIONS = {
    "View dashboard":      ["Administrator", "Safety Officer", "Mining Engineer", "Maintenance Engineer", "Manager"],
    "Worker safety data":  ["Administrator", "Safety Officer", "Mining Engineer", "Manager"],
    "Safety incidents":    ["Administrator", "Safety Officer", "Mining Engineer", "Manager"],
    "Equipment data":      ["Administrator", "Mining Engineer", "Maintenance Engineer", "Manager"],
    "Maintenance data":    ["Administrator", "Mining Engineer", "Maintenance Engineer", "Manager"],
    "Risk assessment":     ["Administrator", "Safety Officer", "Mining Engineer", "Manager"],
    "Generate reports":    ["Administrator", "Safety Officer", "Mining Engineer", "Maintenance Engineer", "Manager"],
    "Manage users":        ["Administrator"],
}

ITERATIONS = 100_000
MIN_PASSWORD_LENGTH = 8


# ---------------------------------------------------------------- hashing
def hash_password(password, salt=None):
    """Return (salt_hex, hash_hex) for a password."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt), ITERATIONS)
    return salt, digest.hex()


def verify_password(password, salt, stored_hash):
    _, new_hash = hash_password(password, salt)
    return hmac.compare_digest(new_hash, stored_hash)  # constant-time compare


# ---------------------------------------------------------------- storage
def load_users():
    if not os.path.exists(USERS_FILE):
        create_default_users()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def create_default_users():
    """Seed one demo account per role. Change these passwords before real use."""
    defaults = {
        "admin":       ("Admin@123",    "Administrator"),
        "safety":      ("Safety@123",   "Safety Officer"),
        "engineer":    ("Engineer@123", "Mining Engineer"),
        "maintenance": ("Maint@1234",   "Maintenance Engineer"),
        "manager":     ("Manager@123",  "Manager"),
    }
    users = {}
    for username, (pw, role) in defaults.items():
        salt, h = hash_password(pw)
        users[username] = {"salt": salt, "hash": h, "role": role, "active": True}
    save_users(users)


# ---------------------------------------------------------------- core logic
def authenticate(username, password):
    """Return (True, role) on success, (False, message) on failure."""
    username = (username or "").strip().lower()
    if not username or not password:
        return False, "Please enter both username and password."
    users = load_users()
    user = users.get(username)
    # same generic message for unknown user / wrong password / disabled account
    if user is None or not user["active"] \
            or not verify_password(password, user["salt"], user["hash"]):
        return False, "Invalid username or password."
    return True, user["role"]


def has_permission(role, function):
    """True if the role may use the function (unknown function -> False)."""
    return role in PERMISSIONS.get(function, [])


def allowed_functions(role):
    return [fn for fn, roles in PERMISSIONS.items() if role in roles]


def validate_new_user(username, password, role, users):
    username = username.strip().lower()
    if not username.isalnum():
        return False, "Username must contain letters and numbers only."
    if username in users:
        return False, "That username already exists."
    if len(password) < MIN_PASSWORD_LENGTH:
        return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if not (any(c.isdigit() for c in password) and any(c.isalpha() for c in password)):
        return False, "Password must contain letters and digits."
    if role not in ROLES:
        return False, "Invalid role."
    return True, username


def add_user(username, password, role):
    users = load_users()
    ok, result = validate_new_user(username, password, role, users)
    if not ok:
        return False, result
    salt, h = hash_password(password)
    users[result] = {"salt": salt, "hash": h, "role": role, "active": True}
    save_users(users)
    return True, f"User '{result}' created as {role}."


def set_user_active(username, active, acting_user):
    users = load_users()
    if username not in users:
        return False, "User not found."
    if username == acting_user and not active:
        return False, "You cannot disable your own account."
    users[username]["active"] = active
    save_users(users)
    return True, f"User '{username}' {'enabled' if active else 'disabled'}."


def delete_user(username, acting_user):
    users = load_users()
    if username not in users:
        return False, "User not found."
    if username == acting_user:
        return False, "You cannot delete your own account."
    admins = [u for u, d in users.items() if d["role"] == "Administrator" and d["active"]]
    if users[username]["role"] == "Administrator" and len(admins) <= 1:
        return False, "Cannot delete the last active administrator."
    del users[username]
    save_users(users)
    return True, f"User '{username}' deleted."


# ---------------------------------------------------------------- Streamlit UI
def login_page(st):
    """Draw the login form. Stores username and role in st.session_state."""
    st.title("Khwezi Mining: Health, Safety and Equipment Monitoring")
    st.subheader("Sign in")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")
    if submitted:
        ok, result = authenticate(username, password)
        if ok:
            st.session_state["user"] = username.strip().lower()
            st.session_state["role"] = result
            st.rerun()
        else:
            st.error(result)
    with st.expander("Demo accounts"):
        st.write("admin / Admin@123, safety / Safety@123, engineer / Engineer@123, "
                 "maintenance / Maint@1234, manager / Manager@123")


def logout_button(st):
    st.sidebar.write(f"Signed in as **{st.session_state['user']}** ({st.session_state['role']})")
    if st.sidebar.button("Log out"):
        for key in ("user", "role"):
            st.session_state.pop(key, None)
        st.rerun()


def is_logged_in(st):
    return "role" in st.session_state


def require_permission(st, function):
    """Call at top of a page. Stops the page with an error if role lacks access."""
    if not is_logged_in(st):
        st.warning("Please log in.")
        st.stop()
    if not has_permission(st.session_state["role"], function):
        st.error(f"Access denied: the {st.session_state['role']} role cannot open '{function}'.")
        st.stop()


def manage_users_page(st):
    require_permission(st, "Manage users")
    st.header("Manage users")
    users = load_users()

    st.subheader("Existing users")
    st.table([{"Username": u, "Role": d["role"],
               "Status": "Active" if d["active"] else "Disabled"} for u, d in users.items()])

    st.subheader("Add user")
    with st.form("add_user", clear_on_submit=True):
        nu = st.text_input("Username")
        npw = st.text_input("Password", type="password")
        nr = st.selectbox("Role", ROLES)
        if st.form_submit_button("Create user"):
            ok, msg = add_user(nu, npw, nr)
            (st.success if ok else st.error)(msg)

    st.subheader("Enable, disable or delete")
    target = st.selectbox("User", list(users.keys()))
    c1, c2, c3 = st.columns(3)
    me = st.session_state["user"]
    if c1.button("Enable"):
        st.info(set_user_active(target, True, me)[1])
    if c2.button("Disable"):
        st.info(set_user_active(target, False, me)[1])
    if c3.button("Delete"):
        st.info(delete_user(target, me)[1])
