import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app, ensure_database, get_db_connection


class WaliyaHospitalAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_hospital.db"
        self.app = create_app(self.db_path)
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        ensure_database(self.db_path)
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_homepage_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Waliya Medical Center", response.get_data(as_text=True))

    def test_patient_login_success(self):
        response = self.client.post(
            "/patient-login",
            data={"username": "patient1", "password": "PatientPass!2025"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/patient-dashboard", response.headers["Location"])

        dashboard = self.client.get("/patient-dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Selam Desta", dashboard.get_data(as_text=True))

    def test_failed_login_already_logged(self):
        response = self.client.post(
            "/patient-login",
            data={"username": "patient1", "password": "wrong-pass"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password.", response.get_data(as_text=True))

        conn = get_db_connection(self.db_path)
        failed_count = conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE outcome = 'failure' AND username = 'patient1'"
        ).fetchone()[0]
        conn.close()
        self.assertGreaterEqual(failed_count, 1)

    def test_staff_dashboard_requires_staff_login(self):
        response = self.client.get("/staff-dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/staff-login", response.headers["Location"])

        login_response = self.client.post(
            "/staff-login",
            data={"username": "dr_abel", "password": "Staff@2025"},
            follow_redirects=False,
        )
        self.assertEqual(login_response.status_code, 302)
        self.assertIn("/staff-dashboard", login_response.headers["Location"])

        dashboard = self.client.get("/staff-dashboard")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Protected staff dashboard", dashboard.get_data(as_text=True))

    def test_appointment_booking_storage(self):
        response = self.client.post(
            "/appointments",
            data={
                "patient_name": "Demo Patient",
                "phone": "+251 911 444 444",
                "service": "General Consultation",
                "doctor": "Dr. Meles Worku",
                "appointment_date": "2026-12-16",
                "visit_type": "In-person",
                "notes": "Demo appointment for testing.",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("scheduled successfully", response.get_data(as_text=True))

        conn = get_db_connection(self.db_path)
        row = conn.execute(
            "SELECT patient_name, service FROM appointments WHERE patient_name = ? ORDER BY id DESC LIMIT 1",
            ("Demo Patient",),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["service"], "General Consultation")


if __name__ == "__main__":
    unittest.main()
