import requests


API_KEY = "YOUR_API_KEY"


def check_ip(ip_address):

    url = "https://api.abuseipdb.com/api/v2/check"


    headers = {
        "Key": "6272f8863d518a8eeec03e16f498f359fbd8230a30a5ed24fe02ea9ffaa148dd381e607ff464fb5f",
        "Accept": "application/json"
    }


    params = {
        "ipAddress": ip_address
    }


    response = requests.get(
        url,
        headers=headers,
        params=params
    )


    data = response.json()


    score = data["data"]["abuseConfidenceScore"]


    if score > 50:
        status = "Malicious"

    else:
        status = "Clean"


    return status, score