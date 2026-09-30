import re
import requests
import dns.resolver
from email import policy
from email.parser import BytesParser


# =========================================
# PARSE EML FILE
# =========================================

def parse_eml(file_bytes):

    msg = BytesParser(
        policy=policy.default
    ).parsebytes(file_bytes)

    subject = msg.get("Subject", "")
    sender = msg.get("From", "")
    receiver = msg.get("To", "")
    reply_to = msg.get("Reply-To", "")

    body = ""

    if msg.is_multipart():

        for part in msg.walk():

            content_type = part.get_content_type()

            if content_type == "text/plain":

                try:
                    body += part.get_content()
                except Exception:
                    pass

    else:

        try:
            body = msg.get_content()
        except Exception:
            body = ""

    received_headers = msg.get_all(
        "Received",
        []
    )

    return {
        "subject": subject,
        "from": sender,
        "to": receiver,
        "reply_to": reply_to,
        "body": body,
        "received": received_headers
    }


# =========================================
# EXTRACT URLS
# =========================================

def extract_urls(text):

    url_pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(
        url_pattern,
        text
    )

    return list(set(urls))


# =========================================
# EXTRACT IP ADDRESSES
# =========================================

def extract_ips(text):

    ip_pattern = (
        r'\b(?:'
        r'(?:25[0-5]|2[0-4][0-9]|'
        r'1[0-9]{2}|[1-9]?[0-9])\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|'
        r'1[0-9]{2}|[1-9]?[0-9])\b'
    )

    ips = re.findall(
        ip_pattern,
        text
    )

    return list(set(ips))


# =========================================
# IP GEOLOCATION
# =========================================

def get_geolocation(ip):

    try:

        response = requests.get(
            f"https://ipapi.co/{ip}/json/",
            timeout=5
        )

        data = response.json()

        return {
            "IP": ip,
            "Country": data.get(
                "country_name",
                "Unknown"
            ),
            "Region": data.get(
                "region",
                "Unknown"
            ),
            "City": data.get(
                "city",
                "Unknown"
            ),
            "ISP": data.get(
                "org",
                "Unknown"
            ),
            "Latitude": data.get(
                "latitude",
                "Unknown"
            ),
            "Longitude": data.get(
                "longitude",
                "Unknown"
            )
        }

    except Exception as e:

        return {
            "IP": ip,
            "Country": "Unknown",
            "Region": "Unknown",
            "City": "Unknown",
            "ISP": "Unknown",
            "Latitude": "Unknown",
            "Longitude": "Unknown"
        }


# =========================================
# EXTRACT DOMAIN
# =========================================

def extract_domain(email_address):

    match = re.search(
        r'@([A-Za-z0-9.-]+)',
        email_address
    )

    if match:

        return match.group(1).lower()

    return ""


# =========================================
# SPF CHECK
# =========================================

def check_spf(domain):

    if not domain:

        return "Not Available"

    try:

        answers = dns.resolver.resolve(
            domain,
            "TXT"
        )

        for record in answers:

            text = record.to_text()

            if "v=spf1" in text.lower():

                return "PASS"

        return "FAIL"

    except Exception:

        return "UNKNOWN"


# =========================================
# DMARC CHECK
# =========================================

def check_dmarc(domain):

    if not domain:

        return "Not Available"

    try:

        dmarc_domain = (
            "_dmarc."
            + domain
        )

        answers = dns.resolver.resolve(
            dmarc_domain,
            "TXT"
        )

        for record in answers:

            text = record.to_text()

            if "v=dmarc1" in text.lower():

                return "PASS"

        return "FAIL"

    except Exception:

        return "UNKNOWN"


# =========================================
# DKIM CHECK
# =========================================

def check_dkim(domain):

    """
    DKIM verification normally requires
    the DKIM selector from the email header.

    Without the selector, we cannot perform
    complete DKIM signature verification.
    """

    if not domain:

        return "Not Available"

    return "NOT VERIFIED"