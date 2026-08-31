from flask import Flask, render_template, request , redirect,url_for
from datetime import datetime
from detector import detect_sql_injection,detect_xss,detect_path_traversal
from database import get_statistics
from functools import wraps
from database import update_alert_info
import time
import os
from flask import session
from flask_socketio import SocketIO
from database import get_attack_statistics
from database import get_metrics
from threat_intel import check_ip
from database import get_alerts
from database import save_alert
from database import verify_user


app = Flask(__name__)

socketio = SocketIO(app)
app.secret_key = "sentinelshield_secret"

failed_attempts = {}




def role_required(role):

    def decorator(function):

        @wraps(function)
        def wrapper(*args, **kwargs):

            if "username" not in session:
                return redirect("/")


            if session.get("role") != role:

                return "Access Denied: You don't have permission"


            return function(*args, **kwargs)


        return wrapper

    return decorator


@app.route("/logout")
def logout():

    # Clear all session data
    session.clear()

    # Redirect user to login page
    return redirect("/")




@app.route("/admin")
@role_required("Admin")
def admin():

    return "Welcome Admin"



@app.route("/alerts")
@role_required("SOC Analyst")
def alerts_page():

    alerts = get_alerts()

    return render_template(
        "alerts.html",
        alerts=alerts
    )



@app.route("/update_incident", methods=["POST"])
def update_incident_route():


    if "username" not in session:
        return redirect("/")


    alert_id=request.form["alert_id"]

    status=request.form["status"]

    comment=request.form["comment"]

    username=session["username"]


    update_alert_info(
        alert_id,
        username,
        status,
        comment
    )


    return redirect("/dashboard")


@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        xss_detected = detect_xss(username)
        #ip_address = request.remote_addr
        ip_address =  request.headers.get(
        "X-Forwarded-For",
        request.remote_addr
    )
        user = verify_user(
            username,
            password
        )

        if user:

            session["username"] = user["username"]

            session["role"] = user["role"]

        

        

        threat_status, threat_score = check_ip(ip_address)

        time = datetime.now()

        user_input = username + password

        if detect_sql_injection(user_input):
            event = "SQL Injection Attempt Detected"
            severity = "HIGH"

        elif  xss_detected:

            event = "XSS Attempt"
            severity = "HIGH"


        elif  detect_path_traversal(username) or detect_path_traversal(password):

            event = "Path Traversal Attempt"
            severity = "HIGH"


        


        else:

            if ip_address not in failed_attempts:
                 failed_attempts[ip_address] = 1

            else:
                failed_attempts[ip_address] += 1


            if failed_attempts[ip_address] >= 5:

                event = "Possible Brute Force Attack"
                severity = "HIGH"

            else:

                event = "Normal Login Attempt"
                severity = "LOW"


        log = f"""
Time: {time}
IP Address: {ip_address}
Username: {username}
Event: {event}
Severity: {severity}
-------------------------
"""

        alert_id = save_alert(
    ip_address,
    username,
    event,
    severity,
    threat_status,
    threat_score
)     
        
        # print(alert_id);
               
        socketio.emit(
    "new_alert",
    {   "id": alert_id,
        "timestamp": str(datetime.now()),
        "ip_address": ip_address,
        "username": username,
        "event": event,
        "severity": severity,
        "threat_status": threat_status,
        "threat_score": threat_score,
        "incident_status": "OPEN"
    }
)
        if user:

          return redirect("/dashboard")


    return render_template("login.html")


@app.route("/dashboard")
def dashboard():

    print(session)

    if not session.get("username"):
        return redirect("/")
    


    alerts = get_alerts()
    critical_events = 0
    metrics = get_metrics()
    statistics = get_statistics()
    attack_statistics = get_attack_statistics()

    for alert in alerts:
        if alert["severity"] == "HIGH":
            critical_events += 1

    return render_template(
        "dashboard.html",
         alerts=alerts,
         metrics=metrics,
         statistics=statistics,
         attack_statistics=attack_statistics
    )

if __name__ == "__main__":
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
