import re


def detect_sql_injection(data):

    patterns = [
        "select",
        "union",
        "drop",
        "insert",
        "delete",
        "' or '1'='1",
        "1=1",
        "--"
    ]

    for pattern in patterns:

        if pattern.lower() in data.lower():
            return True

    return False