import mysql.connector


def get_connection():

    connection = mysql.connector.connect(

        host="sql.freedb.tech",
        user="u_VMJUZx",
        password="TtcGf47cAxTt",
        database="freedb_bmXdWHJA"

    )

    return connection

def save_alert(ip, username, event, severity,threat_status,threat_score):

    conn = get_connection()

    cursor = conn.cursor()


    query = """
    INSERT INTO alerts
    (timestamp, ip_address, username, event, severity,threat_status, threat_score,incident_status)

    VALUES
    (NOW(), %s, %s, %s, %s,%s, %s,%s)
    """


    values = (
        ip,
        username,
        event,
        severity,
        threat_status,
        threat_score,
        "OPEN"
    )


    cursor.execute(query, values)

    conn.commit()
    
    alert_id = cursor.lastrowid

    cursor.close()

    conn.close()

    return alert_id

    


def get_alerts():

    conn = get_connection()

    cursor = conn.cursor(dictionary=True)


    query = """
    SELECT *
    FROM alerts
    ORDER BY timestamp DESC
    """


    cursor.execute(query)


    alerts = cursor.fetchall()


    cursor.close()
    conn.close()


    return alerts

def get_metrics():

    conn = get_connection()

    cursor = conn.cursor(dictionary=True)


    query = """
    SELECT

    COUNT(*) AS total_alerts,

    SUM(severity='HIGH') AS high_alerts,

    SUM(severity='MEDIUM') AS medium_alerts,

    SUM(severity='LOW') AS low_alerts,

    SUM(threat_status='Malicious') AS malicious_ips

    FROM alerts
    """


    cursor.execute(query)

    metrics = cursor.fetchone()


    cursor.close()
    conn.close()


    return metrics

def get_statistics():

    conn = get_connection()

    cursor = conn.cursor(dictionary=True)


    query = """
    SELECT severity, COUNT(*) as total
    FROM alerts
    GROUP BY severity
    """


    cursor.execute(query)

    stats = cursor.fetchall()


    cursor.close()
    conn.close()


    return stats

def get_attack_statistics():

    conn = get_connection()

    cursor = conn.cursor(dictionary=True)


    query = """
    SELECT event, COUNT(*) AS total
    FROM alerts
    GROUP BY event
    """


    cursor.execute(query)


    attacks = cursor.fetchall()


    cursor.close()
    conn.close()


    return attacks

def verify_user(username,password):

    conn = get_connection()

    cursor = conn.cursor(dictionary=True)


    query = """
    SELECT *
    FROM users
    WHERE username=%s
    AND password=%s
    """


    cursor.execute(
        query,
        (username,password)
    )


    user = cursor.fetchone()


    cursor.close()

    conn.close()


    return user

def update_alert_info(alert_id, assignee, status, comment):

    conn = get_connection()

    cursor = conn.cursor()


    # Save investigation details
    query = """
    INSERT INTO alert_info
    (
        alert_id,
        assignee,
        status,
        comment
    )
    VALUES
    (%s,%s,%s,%s)

    ON DUPLICATE KEY UPDATE

    assignee=%s,
    status=%s,
    comment=%s

    """


    values = (
        alert_id,
        assignee,
        status,
        comment,

        assignee,
        status,
        comment
    )


    cursor.execute(query, values)



    # Update main alert status
    update_query = """
    UPDATE alerts
    SET incident_status=%s
    WHERE id=%s
    """


    cursor.execute(
        update_query,
        (
            status,
            alert_id
        )
    )


    conn.commit()


    cursor.close()
    conn.close()
