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

events = get_events()
alerts = get_alerts()

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

incident_counts = defaultdict(
    lambda: {
        "BRUTE_FORCE": 0,
        "PASSWORD_SPRAYING": 0,
        "SUCCESS_AFTER_FAILURES": 0
    }
)

for alert in alerts:
    timestamp = datetime.fromisoformat(alert[1])

    time_bucket = timestamp.replace(
        minute=(timestamp.minute // 5) * 5,
        second=0,
        microsecond=0
    )

    incident_counts[time_bucket][alert[3]] += 1


st.subheader("SSH Activity")

# FILTERS
user_col, ip_col, event_col = st.columns(3)

with user_col:
    user_filter = st.multiselect(
        "Username",
        sorted({event[2] for event in events}),
        key="ssh_user_filter"
    )

with ip_col:
    ip_filter = st.multiselect(
        "Source IP",
        sorted({event[3] for event in events}),
        key="ssh_ip_filter"
    )

with event_col:
    event_filter = st.multiselect(
        "Event Type",
        ["FAILED", "SUCCESS"],
        key="ssh_event_filter"
    )

# FILTERED EVENTS
filtered_events = [
    event for event in events
    if (not user_filter or event[2] in user_filter)
    and (not ip_filter or event[3] in ip_filter)
    and (not event_filter or event[4] in event_filter)
]

# EVENT LIST AND TIMELINE
list_col, chart_col = st.columns([2, 4])

with list_col:
    st.subheader("Recent Events")

    st.caption(
        f"Showing {min(len(filtered_events), 100)} of "
        f"{len(filtered_events)} matching events"
    )

    with st.container(height=400, border=True):
        for event in filtered_events[:100]:
            with st.container(border=True):
                st.write(f"**Timestamp:** {event[1]}")
                st.write(f"**Username:** {event[2]}")
                st.write(f"**Source IP:** {event[3]}")
                st.write(f"**Event Type:** {event[4]}")


with chart_col:
    st.write("")
    st.subheader("SSH Activity Timeline")

    filtered_event_counts = defaultdict(
        lambda: {"FAILED": 0, "SUCCESS": 0}
    )

    for event in filtered_events:
        timestamp = datetime.fromisoformat(event[1])

        time_bucket = timestamp.replace(
            minute=(timestamp.minute // 5) * 5,
            second=0,
            microsecond=0
        )

        filtered_event_counts[time_bucket][event[4]] += 1

    if filtered_event_counts:
        sorted_buckets = sorted(filtered_event_counts.items())

        chart_data = {
            "Time": [
                timestamp for timestamp, _ in sorted_buckets
            ],
            "Failed logins": [
                counts["FAILED"]
                for _, counts in sorted_buckets
            ],
            "Successful logins": [
                counts["SUCCESS"]
                for _, counts in sorted_buckets
            ]
        }
        st.write("")
        st.write("")
        st.line_chart(chart_data, x="Time")
    else:
        st.info("No events match the selected filters.")


total_alerts = max(len(alerts), 1)

st.write("")
st.divider()


st.subheader("Security Alerts")

# FILTERS AT THE TOP
filter_col1, filter_col2 = st.columns(2)

with filter_col1:
    severity_filter = st.selectbox(
        "Alert Severity",
        ["All", "HIGH", "CRITICAL"],
        key="alert_severity_filter"
    )

with filter_col2:
    incident_filter = st.selectbox(
        "Alert Type",
        [
            "All",
            "BRUTE_FORCE",
            "PASSWORD_SPRAYING",
            "SUCCESS_AFTER_FAILURES"
        ],
        key="alert_type_filter"
    )

filtered_alerts = [
    alert for alert in alerts
    if (severity_filter == "All" or alert[4] == severity_filter)
    and (incident_filter == "All" or alert[3] == incident_filter)
]

# ALERT LIST AND TIMELINE SIDE BY SIDE
alert_list_col, incident_chart_col = st.columns([2, 4])

with alert_list_col:
    st.subheader("Logged Alerts")

    st.caption(
        f"Showing {len(filtered_alerts)} of {len(alerts)} alerts"
    )

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

                st.write(f"**Timestamp:** {alert[1]}")
                st.write(f"**Source IP:** {alert[2]}")
                st.write(f"**Description:** {alert[5]}")
                st.write(f"**Count:** {alert[6]}")

with incident_chart_col:
    st.write("")
    st.subheader("Alert Timeline")

    filtered_incident_counts = defaultdict(
        lambda: {
            "BRUTE_FORCE": 0,
            "PASSWORD_SPRAYING": 0,
            "SUCCESS_AFTER_FAILURES": 0
        }
    )

    for alert in filtered_alerts:
        timestamp = datetime.fromisoformat(alert[1])

        time_bucket = timestamp.replace(
            minute=(timestamp.minute // 5) * 5,
            second=0,
            microsecond=0
        )

        filtered_incident_counts[time_bucket][alert[3]] += 1

    if filtered_incident_counts:
        sorted_buckets = sorted(filtered_incident_counts.items())

        incident_chart_data = {
            "Time": [
                timestamp for timestamp, _ in sorted_buckets
            ]
        }

        incident_chart_data["Brute Force"] = [
            counts["BRUTE_FORCE"]
            for _, counts in sorted_buckets
        ]

        incident_chart_data["Password Spraying"] = [
            counts["PASSWORD_SPRAYING"]
            for _, counts in sorted_buckets
        ]

        incident_chart_data["Successful Login After Failures"] = [
            counts["SUCCESS_AFTER_FAILURES"]
            for _, counts in sorted_buckets
        ]

        st.write("")
        st.write("")
        st.line_chart(incident_chart_data, x="Time")
    else:
        st.info("No incidents match the selected filters.")



