"""
app.py - minimal entry point for testing sections (a) and (b) on their own.
Run with:  streamlit run app.py
The full team app can import auth and worker_safety the same way.
"""
import streamlit as st
import auth
import worker_safety

st.set_page_config(page_title="Mining Safety Monitor", layout="wide")

if not auth.is_logged_in(st):
    auth.login_page(st)
    st.stop()

auth.logout_button(st)

# Sidebar shows only the pages this role is allowed to open
pages = {}
if auth.has_permission(st.session_state["role"], "Worker safety data"):
    pages["Worker safety"] = worker_safety.worker_safety_page
if auth.has_permission(st.session_state["role"], "Manage users"):
    pages["Manage users"] = auth.manage_users_page

if not pages:
    st.info("Your role has no pages in this demo build (other sections are built by teammates).")
    st.write("Functions your role may use:", ", ".join(auth.allowed_functions(st.session_state["role"])))
    st.stop()

choice = st.sidebar.radio("Navigation", list(pages.keys()))
pages[choice](st)
