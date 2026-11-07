import streamlit as st
import hashlib
import hmac
import html
import json
import math
import random
import re
import statistics
import time
import urllib.request
from datetime import date, datetime, timedelta

# --- PAGE CONFIGURATION & STYLING ---
st.set_page_config(
    page_title="Field Shift - NASA Farm Climate Intelligence",
    page_icon="🌱",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
    .main { background-color: #0b0914; color: #f3f4f6; }
    .stSidebar { background-color: #110c21; border-right: 1px solid #2d2050; }
    .metric-card {
        background-color: #151026;
        border: 1px solid #2d2050;
        padding: 16px;
        border-radius: 12px;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }
    .metric-card h3 { color: #c084fc; font-size: 0.85rem; margin-bottom: 4px; }
    .metric-card h2 { color: #f3f4f6; font-size: 1.4rem; }
    .stButton>button {
        width: 100%;
        background: linear-gradient(135deg, #7c3aed, #6d28d9);
        color: white;
        border: none;
        border-radius: 8px;
        font-weight: 600;
        padding: 10px;
    }
    h1, h2, h3 {
        background: linear-gradient(to right, #c084fc, #8b5cf6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    </style>
""", unsafe_allow_html=True)

# --- SECURITY ENGINE (SHA-256 Hashing, Anti-XSS, Brute-Force Protection) ---
ADMIN_USERNAME = "admin"
# Pre-computed SHA-256 hash for default admin password: "fieldshift2026"
ADMIN_PASSWORD_HASH = hashlib.sha256("fieldshift2026".encode("utf-8")).hexdigest()

def verify_password(input_password: str, stored_hash: str) -> bool:
    """Uses constant-time comparison to block timing attacks."""
    input_hash = hashlib.sha256(input_password.encode("utf-8")).hexdigest()
    return hmac.compare_digest(input_hash, stored_hash)

def sanitize_input(text: str) -> str:
    """Escapes HTML/JS characters to block Cross-Site Scripting (XSS) injection."""
    return html.escape(text.strip())

def is_valid_email(email: str) -> bool:
    """Strict regex validation for standard email addresses."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email.strip())) and len(email) <= 100

# Initialize Session State for Security & Editable App Config
if "auth_role" not in st.session_state:
    st.session_state["auth_role"] = None  # None, "user", or "admin"
if "user_identity" not in st.session_state:
    st.session_state["user_identity"] = ""
if "failed_attempts" not in st.session_state:
    st.session_state["failed_attempts"] = 0
if "lockout_until" not in st.session_state:
    st.session_state["lockout_until"] = 0.0

# Initialize Editable Crop Configuration in Session State (Admin-only editable)
if "crops_config" not in st.session_state:
    st.session_state["crops_config"] = {
        "rice":   dict(tbase=10, heat=35, frost=8,  water_mm_week=35, wet_ok=(0.5, 0.95)),
        "wheat":  dict(tbase=4,  heat=32, frost=2,  water_mm_week=20, wet_ok=(0.35, 0.8)),
        "maize":  dict(tbase=10, heat=35, frost=4,  water_mm_week=30, wet_ok=(0.4, 0.85)),
        "cotton": dict(tbase=15, heat=37, frost=8,  water_mm_week=25, wet_ok=(0.35, 0.8)),
        "tomato": dict(tbase=10, heat=33, frost=5,  water_mm_week=30, wet_ok=(0.45, 0.8)),
        "potato": dict(tbase=7,  heat=30, frost=1,  water_mm_week=25, wet_ok=(0.5, 0.85)),
        "soybean":dict(tbase=10, heat=35, frost=4,  water_mm_week=28, wet_ok=(0.4, 0.85)),
    }

if "site_banner" not in st.session_state:
    st.session_state["site_banner"] = "Live NASA POWER Satellite Telemetry Active — Select your crop and region."

# --- AUTHENTICATION PORTAL (DUAL LOGIN: USER EMAIL vs ADMIN) ---
if st.session_state["auth_role"] is None:
    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
            <div style="background-color: #151026; border: 1px solid #2d2050; padding: 25px; border-radius: 16px; text-align: center; margin-bottom: 15px;">
                <h2>🌱 Field Shift Security Gateway</h2>
                <p style="color: #9ca3af; font-size: 0.9rem;">Sign in with your email for climate reports, or log in as Admin to edit system configurations.</p>
            </div>
        """, unsafe_allow_html=True)

        tab_user, tab_admin = st.tabs(["👤 User Email Login (View Only)", "🔐 Admin Login (Full Edit Access)"])

        with tab_user:
            with st.form("user_login_form"):
                email_input = st.text_input("Enter your Email Address", placeholder="farmer@example.com")
                user_submit = st.form_submit_button("Continue to Dashboard")
                if user_submit:
                    clean_email = sanitize_input(email_input)
                    if is_valid_email(clean_email):
                        st.session_state["auth_role"] = "user"
                        st.session_state["user_identity"] = clean_email
                        st.rerun()
                    else:
                        st.error("❌ Please enter a valid email address.")

        with tab_admin:
            now = time.time()
            if now < st.session_state["lockout_until"]:
                remaining = int(st.session_state["lockout_until"] - now)
                st.error(f"🛡️ Brute-Force Protection Active: Locked for {remaining} seconds.")
            else:
                with st.form("admin_login_form"):
                    admin_user = st.text_input("Admin Username")
                    admin_pass = st.text_input("Admin Password", type="password")
                    admin_submit = st.form_submit_button("Unlock Admin Controls")
                    if admin_submit:
                        clean_user = sanitize_input(admin_user)
                        if clean_user == ADMIN_USERNAME and verify_password(admin_pass, ADMIN_PASSWORD_HASH):
                            st.session_state["auth_role"] = "admin"
                            st.session_state["user_identity"] = "Administrator"
                            st.session_state["failed_attempts"] = 0
                            st.rerun()
                        else:
                            st.session_state["failed_attempts"] += 1
                            attempts_left = 5 - st.session_state["failed_attempts"]
                            if attempts_left <= 0:
                                st.session_state["lockout_until"] = time.time() + 60
                                st.session_state["failed_attempts"] = 0
                                st.error("🛡️ Too many failed attempts! Admin login locked for 60 seconds.")
                            else:
                                st.error(f"❌ Invalid Admin credentials. ({attempts_left} attempts remaining)")
    st.stop()

# --- NASA POWER API & MODEL ENGINE ---
POWER_URL = (
    "https://power.larc.nasa.gov/api/temporal/daily/point"
    "?parameters=T2M,T2M_MAX,T2M_MIN,PRECTOTCORR,ALLSKY_SFC_SW_DWN,RH2M,GWETROOT"
    "&community=AG&longitude={lon}&latitude={lat}&start={start}&end={end}&format=JSON"
)
MISSING = -999.0

@st.cache_data(ttl=86400)
def fetch_power(lat, lon, start, end):
    url = POWER_URL.format(lat=lat, lon=lon, start=start.strftime("%Y%m%d"), end=end.strftime("%Y%m%d"))
    with urllib.request.urlopen(url, timeout=30) as r:
        raw = json.load(r)
    p = raw["properties"]["parameter"]
    days = sorted(p["T2M"].keys())
    rows = []
    for d in days:
        row = {"date": datetime.strptime(d, "%Y%m%d").date()}
        for k in ("T2M", "T2M_MAX", "T2M_MIN", "PRECTOTCORR", "ALLSKY_SFC_SW_DWN", "RH2M", "GWETROOT"):
            v = p[k].get(d, MISSING)
            row[k] = None if v == MISSING else v
        rows.append(row)
    return rows

def synthetic(lat, start, end, seed=7):
    random.seed(seed)
    rows, d = [], start
    soil = 0.5
    while d <= end:
        doy = d.timetuple().tm_yday
        mean_t = 26 + 6 * math.sin((doy - 100) / 365 * 2 * math.pi)
        recent = (end - d).days < 20
        tmax = mean_t + 5 + random.gauss(0, 1.5) + (3 if recent else 0)
        tmin = mean_t - 5 + random.gauss(0, 1.2)
        rain_p = 0.45 if 160 < doy < 270 else 0.1
        if recent: rain_p *= 0.2
        rain = random.expovariate(1 / 12) if random.random() < rain_p else 0.0
        soil = min(1, max(0.05, soil + rain / 150 - 0.03))
        rows.append({"date": d, "T2M": mean_t, "T2M_MAX": tmax, "T2M_MIN": tmin,
                     "PRECTOTCORR": rain, "ALLSKY_SFC_SW_DWN": 18 + random.gauss(0, 3),
                     "RH2M": 60 + 25 * (rain > 0) + random.gauss(0, 5), "GWETROOT": soil})
        d += timedelta(days=1)
    return rows

def clean(vals): return [v for v in vals if v is not None]
def mean(vals):
    v = clean(vals)
    return statistics.fmean(v) if v else float("nan")

def longest_dry_spell(rain, thresh=1.0):
    best = cur = 0
    for r in rain:
        if r is not None and r < thresh:
            cur += 1
            best = max(best, cur)
        else: cur = 0
    return best

def clamp(x, lo=0, hi=100): return max(lo, min(hi, x))
def scale(x, lo, hi): return 0 if hi == lo else clamp((x - lo) / (hi - lo) * 100)

def window_stats(rows, crop):
    tmax = [r["T2M_MAX"] for r in rows]
    tmin = [r["T2M_MIN"] for r in rows]
    rain = [r["PRECTOTCORR"] for r in rows]
    return {
        "tmean": mean([r["T2M"] for r in rows]),
        "heat_days": sum(1 for t in clean(tmax) if t > crop["heat"]),
        "frost_days": sum(1 for t in clean(tmin) if t <= crop["frost"]),
        "rain_total": sum(clean(rain)),
        "dry_spell": longest_dry_spell(rain),
        "max_3day_rain": max((sum(clean(rain[i:i+3])) for i in range(max(1, len(rain)-2))), default=0),
        "soil": mean([r["GWETROOT"] for r in rows]),
        "rh": mean([r["RH2M"] for r in rows]),
        "gdd": sum(max(0, (a + b) / 2 - crop["tbase"]) for a, b in zip(tmax, tmin) if a is not None and b is not None),
    }

def assess(rows, crop_name, window):
    crop = st.session_state["crops_config"][crop_name]
    end = rows[-1]["date"]
    start = end - timedelta(days=window - 1)
    current = [r for r in rows if start <= r["date"] <= end]

    base = []
    for y in range(1, 10):
        try:
            s = date(start.year - y, start.month, start.day)
            e = date(end.year - y, end.month, end.day)
        except ValueError: continue
        w = [r for r in rows if s <= r["date"] <= e]
        if len(w) >= window * 0.8: base.append(window_stats(w, crop))
    cur = window_stats(current, crop)

    def b(key):
        v = [x[key] for x in base if not math.isnan(x[key])]
        return statistics.fmean(v) if v else float("nan")

    base_rain = b("rain_total")
    rain_anom_pct = ((cur["rain_total"] - base_rain) / base_rain * 100) if base_rain and not math.isnan(base_rain) else 0
    temp_anom = cur["tmean"] - b("tmean") if base else 0

    heat = clamp(scale(cur["heat_days"], 0, window * 0.5) + max(0, temp_anom) * 8)
    cold = clamp(scale(cur["frost_days"], 0, max(3, window * 0.2)) + max(0, -temp_anom) * 6)
    weekly_rain = cur["rain_total"] / (window / 7)
    water_gap = clamp(1 - weekly_rain / crop["water_mm_week"], 0, 1)
    soil_dry = clamp(1 - cur["soil"] / crop["wet_ok"][0], 0, 1) if not math.isnan(cur["soil"]) else 0
    drought = clamp(40 * water_gap + 35 * soil_dry + scale(cur["dry_spell"], 5, 21) * 0.25 + max(0, -rain_anom_pct) * 0.15)
    flood = clamp(scale(cur["max_3day_rain"], 50, 200) * 0.6 + (scale(cur["soil"], crop["wet_ok"][1], 1.0) * 0.4 if not math.isnan(cur["soil"]) else 0))
    warm_ok = 1 - min(1, abs(cur["tmean"] - 25) / 10)
    humid = clamp((cur["rh"] - 70) / 25, 0, 1) if not math.isnan(cur["rh"]) else 0
    disease = clamp(100 * warm_ok * humid * (0.5 + min(0.5, cur["rain_total"] / 200)))

    scores = {"Heat stress": heat, "Cold / frost": cold, "Drought": drought, "Flood / waterlogging": flood, "Disease pressure": disease}
    top = max(scores.values())
    overall = clamp(0.6 * top + 0.4 * statistics.fmean(scores.values()))
    level = "FAVOURABLE" if overall < 25 else "WATCH" if overall < 45 else "WARNING" if overall < 65 else "CRITICAL"
    return dict(crop=crop_name, window=window, end=end, current=cur, rain_anom_pct=rain_anom_pct, temp_anom=temp_anom, scores=scores, overall=overall, level=level, rows=current)

ADVICE = {
    "Heat stress": ["Shift irrigation to early morning/evening; mulch to cut soil temperature.", "Consider heat-tolerant varieties or move sowing earlier next season."],
    "Cold / frost": ["Cover seedlings or irrigate lightly before cold nights (wet soil holds heat).", "Delay sowing until night temperatures stay above frost limit."],
    "Drought": ["Prioritise drip/sprinkler irrigation at critical growth stages.", "Mulch, reduce tillage, and harvest rainwater in farm ponds."],
    "Flood / waterlogging": ["Open drainage channels now; avoid fertiliser before heavy rain.", "Use raised beds or ridge planting."],
    "Disease pressure": ["Scout fields every 2-3 days for fungal signs (blight, rust, blast).", "Improve airflow and apply preventive bio-fungicides."]
}

# --- SIDEBAR CONTROLS & ROLE STATUS ---
with st.sidebar:
    role_badge = "👑 ADMIN MODE (Edit Enabled)" if st.session_state["auth_role"] == "admin" else "👤 USER MODE (View Only)"
    st.markdown(f"**Session:** `{role_badge}`")
    st.caption(f"Signed in as: {st.session_state['user_identity']}")
    if st.button("🔒 Logout"):
        st.session_state["auth_role"] = None
        st.session_state["user_identity"] = ""
        st.rerun()
    st.divider()

    st.header("⚙️ Farm Parameters")
    lat = st.number_input("Latitude", value=22.57, min_value=-90.0, max_value=90.0, step=0.01)
    lon = st.number_input("Longitude", value=88.36, min_value=-180.0, max_value=180.0, step=0.01)
    crop = st.selectbox("Target Crop", list(st.session_state["crops_config"].keys()))
    window = st.slider("Assessment Window (Days)", min_value=10, max_value=90, value=30)
    years = st.slider("Baseline History (Years)", min_value=3, max_value=15, value=10)
    use_demo = st.checkbox("Use Offline Demo Mode", value=False)

# --- ADMIN-ONLY WEB EDITOR PANEL ---
st.title("🌱 Field Shift: Adapting Farms with NASA Data")
st.info(f"📢 **System Notice:** {st.session_state['site_banner']}")

if st.session_state["auth_role"] == "admin":
    with st.expander("🛠️ Admin Control Center (Edit Crop Thresholds & Web Notice)", expanded=False):
        st.markdown("Only administrators can see this panel and modify model thresholds.")
        new_banner = st.text_input("Update Web Announcement Banner", value=st.session_state["site_banner"])
        
        c_edit1, c_edit2, c_edit3 = st.columns(3)
        current_crop_cfg = st.session_state["crops_config"][crop]
        with c_edit1:
            new_heat = st.number_input(f"{crop.capitalize()} Heat Limit (°C)", value=float(current_crop_cfg["heat"]), min_value=15.0, max_value=50.0)
        with c_edit2:
            new_frost = st.number_input(f"{crop.capitalize()} Frost Limit (°C)", value=float(current_crop_cfg["frost"]), min_value=-10.0, max_value=20.0)
        with c_edit3:
            new_water = st.number_input(f"{crop.capitalize()} Weekly Water (mm)", value=float(current_crop_cfg["water_mm_week"]), min_value=5.0, max_value=100.0)

        if st.button("💾 Save Admin Changes"):
            st.session_state["site_banner"] = sanitize_input(new_banner)
            st.session_state["crops_config"][crop]["heat"] = new_heat
            st.session_state["crops_config"][crop]["frost"] = new_frost
            st.session_state["crops_config"][crop]["water_mm_week"] = new_water
            st.success(f"✅ Security verified: Updated parameters for {crop.capitalize()} and web banner!")
            st.rerun()

# --- RUN NASA CLIMATE ASSESSMENT ---
end = date.today() - timedelta(days=3)
start = date(end.year - years, 1, 1)

with st.spinner("Fetching telemetry data from NASA POWER satellites..."):
    try:
        rows = synthetic(lat, start, end) if use_demo else fetch_power(lat, lon, start, end)
        res = assess(rows, crop, window)
    except Exception as e:
        st.error(f"Failed to fetch live NASA data ({e}). Enable 'Use Offline Demo Mode' in the sidebar.")
        st.stop()

lvl_colors = {"FAVOURABLE": "#10b981", "WATCH": "#3b82f6", "WARNING": "#f59e0b", "CRITICAL": "#ef4444"}
st.markdown(f"""
    <div style="padding: 16px; border-radius: 12px; background-color: {lvl_colors[res['level']]}22; border: 1px solid {lvl_colors[res['level']]}; text-align: center; margin-bottom: 20px;">
        <h2 style="color: {lvl_colors[res['level']]}; margin: 0;">OVERALL STATUS: {res['level']} (Risk Score: {res['overall']:.0f}/100)</h2>
    </div>
""", unsafe_allow_html=True)

c1, c2, c3, c4 = st.columns(4)
c, cur = res["current"], res
with c1: st.markdown(f'<div class="metric-card"><h3>Avg Temperature</h3><h2>{c["tmean"]:.1f} °C</h2><p style="font-size:0.75rem; color:#9ca3af;">{cur["temp_anom"]:+.1f}°C vs normal</p></div>', unsafe_allow_html=True)
with c2: st.markdown(f'<div class="metric-card"><h3>Total Rainfall</h3><h2>{c["rain_total"]:.0f} mm</h2><p style="font-size:0.75rem; color:#9ca3af;">{cur["rain_anom_pct"]:+.0f}% vs normal</p></div>', unsafe_allow_html=True)
with c3: st.markdown(f'<div class="metric-card"><h3>Root Soil Wetness</h3><h2>{c["soil"]:.2f}</h2><p style="font-size:0.75rem; color:#9ca3af;">Scale 0.0 to 1.0</p></div>', unsafe_allow_html=True)
with c4: st.markdown(f'<div class="metric-card"><h3>Growing Degree Days</h3><h2>{c["gdd"]:.0f} GDD</h2><p style="font-size:0.75rem; color:#9ca3af;">Thermal accumulation</p></div>', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)
col_left, col_right = st.columns([1, 1])

with col_left:
    st.subheader("⚠️ Agricultural Risk Scores (0-100)")
    for name, score in sorted(res["scores"].items(), key=lambda x: -x[1]):
        st.markdown(f"**{name}** ({score:.1f}/100)")
        st.progress(int(score))

with col_right:
    st.subheader("💡 Actionable Farm Recommendations")
    risky = [n for n, s in sorted(res["scores"].items(), key=lambda kv: -kv[1]) if s >= 30]
    if not risky:
        st.success("All climate conditions look favourable for your crop. Continue routine monitoring!")
    else:
        for n in risky[:3]:
            st.markdown(f"**Action required for {n}:**")
            for tip in ADVICE[n]:
                st.markdown(f"- {tip}")

st.markdown("<br>", unsafe_allow_html=True)
st.subheader("📈 Recent Temperature & Rainfall Trend")
chart_data = {
    "Date": [r["date"] for r in res["rows"]],
    "Max Temp (°C)": [r["T2M_MAX"] for r in res["rows"]],
    "Rainfall (mm)": [r["PRECTOTCORR"] for r in res["rows"]]
}
st.line_chart(chart_data, x="Date")