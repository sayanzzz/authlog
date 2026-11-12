import unittest
from authlog_guard import parse_log, detect

YEAR = 2026


def fail(sec, ip, user="root"):
    return f"Nov 12 10:00:{sec:02d} srv sshd[1]: Failed password for {user} from {ip} port 22 ssh2"


def ok(sec, ip, user="root"):
    return f"Nov 12 10:01:{sec:02d} srv sshd[1]: Accepted password for {user} from {ip} port 22 ssh2"


class TestDetection(unittest.TestCase):
    def test_brute_force(self):
        lines = [fail(s, "1.2.3.4") for s in range(6)]
        rules = {a.rule for a in detect(parse_log(lines, YEAR))}
        self.assertIn("BRUTE_FORCE", rules)

    def test_below_threshold_is_quiet(self):
        lines = [fail(s, "1.2.3.4") for s in range(3)]
        self.assertEqual(detect(parse_log(lines, YEAR)), [])

    def test_password_spraying(self):
        lines = [fail(i, "5.6.7.8", user=f"user{i}") for i in range(6)]
        rules = {a.rule for a in detect(parse_log(lines, YEAR), threshold=50)}
        self.assertIn("PASSWORD_SPRAYING", rules)

    def test_success_after_failures_is_critical(self):
        lines = [fail(s, "9.9.9.9") for s in range(4)] + [ok(5, "9.9.9.9")]
        alerts = detect(parse_log(lines, YEAR))
        self.assertEqual(alerts[0].severity, "CRITICAL")

    def test_normal_login_ignored(self):
        self.assertEqual(detect(parse_log([ok(1, "10.0.0.1", "sayan")], YEAR)), [])

    def test_garbage_lines_ignored(self):
        self.assertEqual(parse_log(["not a log line", ""], YEAR), [])


if __name__ == "__main__":
    unittest.main()
