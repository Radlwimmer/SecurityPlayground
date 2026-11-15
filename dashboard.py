import streamlit as st
from src.database import get_events, get_alerts
from collections import defaultdict
from datetime import datetime, timedelta

st.set_page_config(
    page_title="SecurityPlayground",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SecurityPlayground")
st.subheader("Security Monitoring Dashboard")
# st.caption("Monitoring SSH authentication activity and detecting suspicious login patterns.")

events = get_events()
alerts = get_alerts()
st.write("Total events loaded:", len(events))

event_counts = defaultdict(lambda: {"FAILED": 0, "SUCCESS": 0})
for event in events:
    timestamp = datetime.fromisoformat(event[1])
    time_bucket = timestamp.replace(
        minute=(timestamp.minute // 5) * 5,
        second=0,
        microsecond=0
    )
    event_counts[time_bucket][event[4]] += 1
high_alerts = sum(1 for alert in alerts if alert[4] == "HIGH")
critical_alerts = sum(1 for alert in alerts if alert[4] == "CRITICAL")

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Events", len(events))
with col2:
    st.metric("Total Alerts", len(alerts))
with col3:
    st.metric("Critical Alerts", critical_alerts)

st.subheader("SSH Activity Timeline")

filter_col, chart_col = st.columns([1, 3])

with filter_col:
    timeline_filter = st.selectbox(
        "Show login activity",
        ["All", "Failed logins", "Successful logins"]
    )

with chart_col:
    if event_counts:
        chart_data = {}

        if timeline_filter in ["All", "Failed logins"]:
            chart_data["Failed logins"] = [
                counts["FAILED"]
                for _, counts in sorted(event_counts.items())
            ]

        if timeline_filter in ["All", "Successful logins"]:
            chart_data["Successful logins"] = [
                counts["SUCCESS"]
                for _, counts in sorted(event_counts.items())
            ]

        st.line_chart(chart_data)
    else:
        st.info("No events available for the timeline.")

total_alerts = max(len(alerts), 1)

st.write("")
st.divider()

st.subheader("Security Alerts")
alert_filter_col, alerts_col = st.columns([1, 3])

with alert_filter_col:
    st.subheader("Filters")

    severity_filter = st.selectbox(
        "Alert Severity",
        ["All", "HIGH", "CRITICAL"]
    )

if severity_filter == "All":
    filtered_alerts = alerts
else:
    filtered_alerts = [
        alert for alert in alerts
        if alert[4] == severity_filter
    ]

with alerts_col:
    st.caption(f"Showing {len(filtered_alerts)} of {len(alerts)} alerts")

    with st.container(height=400, border=True):
        for alert in filtered_alerts:
            with st.container(border=True):
                st.write(f"**Alert:** {alert[3]}")
                if alert[4] == "CRITICAL":
                    st.error(f"Severity: {alert[4]}")
                elif alert[4] == "HIGH":
                    st.warning(f"Severity: {alert[4]}")
                else:
                    st.info(f"Severity: {alert[4]}")
                st.write(f"**Source IP:** {alert[2]}")
                st.write(f"**Description:** {alert[5]}")
                st.write(f"**Count:** {alert[6]}")

st.write("")
st.divider()

st.subheader("Recent Security Events")
filter_col, events_col = st.columns([1, 3])

with filter_col:
    st.subheader("Filters")

    user_filter = st.multiselect(
        "Username",
        sorted({event[2] for event in events})
    )

    ip_filter = st.multiselect(
        "Source IP",
        sorted({event[3] for event in events})
    )

    event_filter = st.multiselect(
        "Event Type",
        ["FAILED", "SUCCESS"]
    )

filtered_events = [
    event for event in events
    if (not user_filter or event[2] in user_filter)
    and (not ip_filter or event[3] in ip_filter)
    and (not event_filter or event[4] in event_filter)
]

with events_col:
    st.caption(
        f"Showing {min(len(filtered_events), 100)} of {len(filtered_events)} matching events"
    )

    with st.container(height=400, border=True):
        for event in filtered_events[:100]:
            with st.container(border=True):
                st.write(f"**Timestamp:** {event[1]}")
                st.write(f"**Username:** {event[2]}")
                st.write(f"**Source IP:** {event[3]}")
                st.write(f"**Event Type:** {event[4]}")
