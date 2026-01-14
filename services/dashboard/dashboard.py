import streamlit as st
import pandas as pd
import os, requests, time
from sqlalchemy import create_engine, text

# ==============================================================================
# 1. CORE CONFIGURATION
# ==============================================================================
st.set_page_config(layout="wide", page_title="TITAN V17.2: MASTER FORGE", page_icon="👺")
engine = create_engine(os.getenv("DATABASE_URL"))

# Professional Dark UI Styling
st.markdown("""
    <style>
    .main { background-color: #0d1117; color: #c9d1d9; }
    .stMetric { background-color: #161b22; padding: 15px; border-radius: 10px; border: 1px solid #30363d; }
    .stDataFrame { border: 1px solid #30363d; }
    .stTabs [data-baseweb="tab-list"] { gap: 24px; }
    .stTabs [data-baseweb="tab"] { height: 50px; white-space: pre-wrap; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

st.title("👺 TITAN V17.2: OMNISCIENT FORGE")

# ==========================================================================
# 2. SIDEBAR - CONTROL PANEL
# ==========================================================================
st.sidebar.header("☢️ Laboratory Input")
project = st.sidebar.text_input("Project Name", placeholder="e.g. apple.com")
code_input = st.sidebar.text_area("Paste JavaScript Code", height=250, placeholder="Paste DevTools Source Here...")

if st.sidebar.button("Execute Deep Scan"):
    if project and code_input:
        with st.sidebar.status("Igniting Forge...") as status:
            try:
                payload = {
                    "domain": project, 
                    "filename": f"scan_{int(time.time())}.js", 
                    "code": code_input
                }
                resp = requests.post("http://api:8000/blackops/manual", json=payload, timeout=10)
                if resp.status_code == 200:
                    status.update(label="Analysis Dispatched!", state="complete")
                    st.sidebar.toast("Nuclear Analysis Started!", icon="🔥")
                else:
                    st.sidebar.error("API Rejected Request")
            except Exception as e:
                st.sidebar.error(f"Connection Failed: {e}")
    else:
        st.sidebar.warning("Project Name and Code are required.")

st.sidebar.divider()
st.sidebar.header("🛠️ Forge Maintenance")

# NUCLEAR WIPE
if st.sidebar.button("🗑️ Wipe All Database Data"):
    with engine.connect() as conn:
        conn.execute(text("TRUNCATE targets, assets, findings RESTART IDENTITY CASCADE;"))
        conn.commit()
    st.sidebar.success("Database Reset to Zero.")
    st.rerun()

# LIVE REFRESH SETTINGS
live_mode = st.sidebar.toggle("Live Refresh (Auto-Update)", value=True)
refresh_rate = st.sidebar.slider("Refresh Speed (Seconds)", 2, 10, 4)

# ==========================================================================
# 3. DATA ENGINE
# ==========================================================================
try:
    targets_df = pd.read_sql("SELECT * FROM targets", engine)
    
    if not targets_df.empty:
        # PROJECT SELECTOR
        sel_domain = st.selectbox("🎯 Select Active Project", targets_df['domain'])
        tid = int(targets_df[targets_df['domain'] == sel_domain]['id'].values[0])

        # DATA FETCHING
        # Use a join to get all findings for the specific target
        query = text("""
            SELECT f.id, f.type, f.severity, f.evidence, f.line, a.url 
            FROM findings f 
            JOIN assets a ON f.asset_id = a.id 
            WHERE a.target_id = :tid
            ORDER BY f.id DESC
        """)
        findings = pd.read_sql(query, engine, params={"tid": tid})

        # METRICS DISPLAY
        m1, m2, m3 = st.columns(3)
        crit_count = len(findings[findings['severity'] == 'CRITICAL'])
        intel_count = len(findings[findings['type'] == 'INTEL_MATCH'])
        api_count = len(findings[findings['type'] == 'SHADOW_API'])
        
        m1.metric("Critical Vulnerabilities", crit_count)
        m2.metric("Intelligence Hits", intel_count)
        m3.metric("Shadow Endpoints", api_count)

        # MAIN TABS
        t_vulns, t_delete, t_source = st.tabs(["🔥 VULNERABILITIES", "🗑️ SURGICAL DELETE", "🧬 SOURCE VIEWER"])

        with t_vulns:
            if not findings.empty:
                st.write(f"Showing results for **{sel_domain}**")
                # Clean evidence of common noise for display
                st.dataframe(findings, use_container_width=True, hide_index=True)
            else:
                st.info("No findings yet. The Forge is still working...")

        with t_delete:
            st.subheader("Surgical Removal")
            col_d1, col_d2 = st.columns(2)
            
            with col_d1:
                fid = st.number_input("Enter Finding ID to Remove", step=1, value=0)
                if st.button("Delete Specific ID"):
                    with engine.connect() as conn:
                        conn.execute(text("DELETE FROM findings WHERE id = :fid"), {"fid": fid})
                        conn.commit()
                    st.success(f"ID {fid} Removed.")
                    st.rerun()
            
            with col_d2:
                st.write("Danger Zone")
                if st.button(f"Clear All Findings for {sel_domain}"):
                    with engine.connect() as conn:
                        conn.execute(text("""
                            DELETE FROM findings 
                            WHERE asset_id IN (SELECT id FROM assets WHERE target_id = :tid)
                        """), {"tid": tid})
                        conn.commit()
                    st.success("Project Cleaned.")
                    st.rerun()

        with t_source:
            # VIRTUALIZED SOURCE VIEWER (Titanic Fix)
            assets = pd.read_sql(f"SELECT * FROM assets WHERE target_id={tid}", engine)
            if not assets.empty:
                sel_a = st.selectbox("Select File to Inspect", assets['url'])
                path = assets[assets['url'] == sel_a]['local_path'].values[0]
                
                if os.path.exists(path):
                    f_size = os.path.getsize(path) / (1024 * 1024) # Size in MB
                    st.text(f"File Path: {path} | Size: {f_size:.2f} MB")
                    
                    # Performance Gate: Don't render more than 5MB in the browser
                    if f_size > 5:
                        st.warning("Titanic File Detected! Displaying only the first 2,000 lines for performance.")
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            head = [next(f) for _ in range(2000)]
                            st.code("".join(head), language="javascript")
                        st.info("To see the full code, inspect it directly in your Parrot OS terminal at the path shown above.")
                    else:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            st.code(f.read(), language="javascript", line_numbers=True)
                else:
                    st.error("File not found on local disk.")
            else:
                st.info("No source assets found.")

    else:
        st.info("The Forge is cold. Paste code in the sidebar to begin your first hunt.")

except Exception as e:
    st.error(f"Forge Engine Offline: {e}")

# ==========================================================================
# 4. REFRESH LOOP
# ==========================================================================
if live_mode:
    time.sleep(refresh_rate)
    st.rerun()
