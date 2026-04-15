"""Human-readable labels and descriptions for alert types."""

# Short title shown in email subject and ntfy X-Title header
ALERT_TITLES: dict[str, str] = {
    "PORT_SCAN":       "Network scan detected",
    "BRUTE_FORCE":     "Login hack attempt detected",
    "EXFILTRATION":    "Large data upload detected",
    "NEW_IP":          "Unknown device on network",
    "TOR_EXIT":        "Tor anonymous traffic detected",
    "ADULT_DOMAIN":    "Adult content site accessed",
    "TRACKER_DOMAIN":  "Tracking software phoning home",
    "DATA_HOG":        "Device using excessive bandwidth",
}

# One-sentence plain-English explanation shown in the notification body
ALERT_SUMMARIES: dict[str, str] = {
    "PORT_SCAN":       "A device is scanning your network for open doors — typical behavior before an attack.",
    "BRUTE_FORCE":     "Someone is repeatedly trying to log in to a device on your network.",
    "EXFILTRATION":    "A device is sending an unusually large amount of data off your network.",
    "NEW_IP":          "An unrecognized device just appeared on your network.",
    "TOR_EXIT":        "Traffic is going through Tor, an anonymous network sometimes used to hide activity.",
    "ADULT_DOMAIN":    "An adult content website was accessed from your network.",
    "TRACKER_DOMAIN":  "An app or device is contacting ad/tracking servers in the background.",
    "DATA_HOG":        "A device is consuming an unusually high amount of bandwidth.",
}


def get_title(alert_type: str) -> str:
    return ALERT_TITLES.get(alert_type, alert_type.replace("_", " ").title())


def get_summary(alert_type: str) -> str:
    return ALERT_SUMMARIES.get(alert_type, "")
