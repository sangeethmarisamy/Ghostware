sessions = {}


def add_session(session_id, username, tty, source_ip):
    sessions[session_id] = {
        "username": username,
        "tty": tty,
        "source_ip": source_ip,
    }


def get_session(session_id):
    return sessions.get(session_id)
