from app.log_parser import parse_log_line


def test_parse_failed_ssh_login():
    log_line = "Jun 24 16:30:01 server sshd[1234]: Failed password for sander from 192.168.1.20 port 52222 ssh2"

    event = parse_log_line(log_line)

    assert event is not None
    assert event.event_type == "FAILED_SSH_LOGIN"
    assert event.username == "sander"
    assert event.source_ip == "192.168.1.20"


def test_parse_failed_ssh_login_invalid_user():
    log_line = "Jun 24 16:31:01 server sshd[1235]: Failed password for invalid user admin from 10.0.0.5 port 51111 ssh2"

    event = parse_log_line(log_line)

    assert event is not None
    assert event.event_type == "FAILED_SSH_LOGIN"
    assert event.username == "admin"
    assert event.source_ip == "10.0.0.5"


def test_ignore_non_security_log():
    log_line = "Jun 24 16:32:01 server systemd[1]: Started Daily apt download activities."

    event = parse_log_line(log_line)

    assert event is None
