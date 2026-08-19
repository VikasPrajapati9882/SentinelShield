import re
import html
from urllib.parse import unquote

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



def detect_xss(input_data):

    if not input_data:
        return False

    # Decode common URL/HTML encoding
    decoded = unquote(input_data)
    decoded = html.unescape(decoded)

    # Convert to lowercase for case-insensitive detection
    data = decoded.lower()

    xss_patterns = [

        # Script tags
        r"<\s*script\b",

        # JavaScript event handlers
        r"\bon\w+\s*=",

        # javascript: protocol
        r"javascript\s*:",

        # iframe/object/embed tags
        r"<\s*iframe\b",
        r"<\s*object\b",
        r"<\s*embed\b",

        # Common XSS functions
        r"\balert\s*\(",
        r"\bprompt\s*\(",
        r"\bconfirm\s*\(",

        # SVG-based XSS
        r"<\s*svg\b",

        # data URI
        r"data\s*:\s*text/html",

    ]

    for pattern in xss_patterns:

        if re.search(pattern, data, re.IGNORECASE):
            return True

    return False




def detect_path_traversal(input_data):

    if not input_data:
        return False

    data = unquote(input_data).lower()

    patterns = [

        r"\.\./",          # ../
        r"\.\.\\",         # ..\
        r"%2e%2e%2f",      # encoded ../
        r"%2e%2e%5c",      # encoded ..\
        r"/etc/passwd",    # Linux target
        r"boot\.ini",      # Windows target
        r"win\.ini",       # Windows target
        r"system32",       # Windows system directory

    ]

    for pattern in patterns:
        if re.search(pattern, data):
            return True

    return False


def detect_command_injection(input_data):

    if not input_data:
        return False

    data = unquote(input_data).lower()

    patterns = [
        r";\s*(whoami|id|uname|cat|ls|dir|ipconfig|ifconfig)",
        r"\|\s*(whoami|id|uname|cat|ls|dir)",
        r"&&\s*(whoami|id|uname|cat|ls|dir)",
        r"\$\([^)]*\)",
        r"`[^`]+`",
        r"\b(whoami|ipconfig|ifconfig|uname)\b"
    ]

    return any(
        re.search(pattern, data, re.IGNORECASE)
        for pattern in patterns
    )