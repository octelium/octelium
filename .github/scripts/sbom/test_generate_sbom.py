import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error

import generate_sbom


class GenerateSBOMTest(unittest.TestCase):
    endpoint = "https://api.github.com/repos/octelium/octelium/dependency-graph/sbom"
    report_url = f"{endpoint}/fetch-report/1234-abcd"
    download_url = "https://downloads.example.com/sbom.json?signature=temporary"
    sbom = {"SPDXID": "SPDXRef-DOCUMENT", "spdxVersion": "SPDX-2.3", "packages": []}

    def setUp(self):
        self.transport = self.enterContext(mock.patch.object(generate_sbom, "request"))
        self.clock = self.enterContext(
            mock.patch.object(generate_sbom.time, "monotonic", return_value=0)
        )
        self.sleep = self.enterContext(mock.patch.object(generate_sbom.time, "sleep"))
        self.generated = (201, {}, json.dumps({"sbom_url": self.report_url}).encode())
        self.ready = (302, {"Location": self.download_url}, b"")
        self.downloaded = (200, {}, json.dumps(self.sbom).encode())

    def export(self, **kwargs):
        return generate_sbom.generate_sbom("octelium/octelium", "test-token", **kwargs)

    def test_pending_export_is_polled_and_downloaded_without_credentials(self):
        self.transport.side_effect = [self.generated, (202, {}, b""), self.ready, self.downloaded]

        self.assertEqual(self.export(), self.sbom)

        calls = self.transport.call_args_list
        self.assertEqual([call.args[0] for call in calls], [
            f"{self.endpoint}/generate-report", self.report_url, self.report_url, self.download_url
        ])
        for call in calls[:3]:
            self.assertEqual(call.args[1]["Authorization"], "Bearer test-token")
            self.assertEqual(call.args[1]["X-GitHub-Api-Version"], "2026-03-10")
        self.assertNotIn("Authorization", calls[-1].args[1])
        self.assertNotIn("X-GitHub-Api-Version", calls[-1].args[1])
        self.sleep.assert_called_once_with(5)

    def test_ready_export_does_not_sleep(self):
        self.transport.side_effect = [self.generated, self.ready, self.downloaded]

        self.assertEqual(self.export(), self.sbom)
        self.sleep.assert_not_called()

    def test_public_export_can_run_without_a_token(self):
        self.transport.side_effect = [self.generated, self.ready, self.downloaded]

        self.assertEqual(generate_sbom.generate_sbom("octelium/octelium", ""), self.sbom)
        for call in self.transport.call_args_list:
            self.assertNotIn("Authorization", call.args[1])

    def test_download_redirects_never_receive_credentials(self):
        redirected = "https://storage.example.com/sbom.json"
        self.transport.side_effect = [
            self.generated, self.ready, (307, {"Location": redirected}, b""), self.downloaded
        ]

        self.assertEqual(self.export(), self.sbom)
        for call in self.transport.call_args_list[2:]:
            self.assertNotIn("Authorization", call.args[1])
        self.assertEqual(self.transport.call_args.args[0], redirected)

    def test_generation_errors_stop_the_export(self):
        for status in [200, 202, 403, 404, 500]:
            with self.subTest(status=status):
                self.transport.reset_mock(side_effect=True)
                self.transport.return_value = (status, {}, b"{}")
                with self.assertRaisesRegex(RuntimeError, f"generation returned HTTP {status}"):
                    self.export()
                self.transport.assert_called_once()

    def test_report_url_must_belong_to_the_expected_repository_endpoint(self):
        for report_url in [
            None,
            42,
            "https://evil.example.com/fetch-report/id",
            f"{self.endpoint}/fetch-report/",
            self.report_url + "?redirect=elsewhere",
            self.report_url + "/../../other",
            self.report_url.replace("octelium/octelium", "other/repository"),
        ]:
            with self.subTest(report_url=report_url):
                self.transport.side_effect = [(201, {}, json.dumps({"sbom_url": report_url}).encode())]
                with self.assertRaisesRegex(ValueError, "invalid SBOM report URL"):
                    self.export()

    def test_malformed_generation_json_is_rejected(self):
        for body in [b"not json", b"null", b"[]", b"{}"]:
            with self.subTest(body=body):
                self.transport.side_effect = [(201, {}, body)]
                with self.assertRaises(ValueError):
                    self.export()

    def test_polling_errors_are_not_treated_as_pending(self):
        for status in [200, 201, 403, 404, 500]:
            with self.subTest(status=status):
                self.transport.side_effect = [self.generated, (status, {}, b"{}")]
                with self.assertRaisesRegex(RuntimeError, f"polling returned HTTP {status}"):
                    self.export()

    def test_polling_stops_at_the_deadline(self):
        self.clock.side_effect = [0, 0, 0, 298, 300]
        self.transport.side_effect = [self.generated, (202, {}, b"")]

        with self.assertRaisesRegex(TimeoutError, "Timed out"):
            self.export()
        self.sleep.assert_called_once_with(2)
        self.assertEqual(self.transport.call_count, 2)

    def test_request_timeout_uses_the_remaining_budget(self):
        self.clock.side_effect = [0, 290, 295, 299]
        self.transport.side_effect = [self.generated, self.ready, self.downloaded]

        self.assertEqual(self.export(), self.sbom)
        self.assertEqual([call.args[2] for call in self.transport.call_args_list], [10, 5, 1])

    def test_download_url_requires_https_without_credentials(self):
        for location in [
            "http://downloads.example.com/sbom",
            "file:///tmp/sbom",
            "https://user:pass@example.com/sbom",
        ]:
            with self.subTest(location=location):
                self.transport.side_effect = [self.generated, (302, {"Location": location}, b"")]
                with self.assertRaisesRegex(ValueError, "HTTPS without embedded credentials"):
                    self.export()

    def test_download_redirect_cannot_downgrade_to_http(self):
        self.transport.side_effect = [
            self.generated, self.ready, (302, {"Location": "http://downloads.example.com/sbom"}, b"")
        ]

        with self.assertRaisesRegex(ValueError, "HTTPS without embedded credentials"):
            self.export()
        self.assertEqual(self.transport.call_count, 3)

    def test_missing_download_locations_are_rejected(self):
        for responses in [
            [self.generated, (302, {}, b"")],
            [self.generated, self.ready, (307, {}, b"")],
        ]:
            with self.subTest(responses=responses):
                self.transport.side_effect = responses
                with self.assertRaisesRegex(ValueError, "missing the download URL"):
                    self.export()

    def test_download_redirects_are_bounded(self):
        self.transport.side_effect = [self.generated] + [self.ready] * 7

        with self.assertRaisesRegex(RuntimeError, "redirect limit"):
            self.export()
        self.assertEqual(self.transport.call_count, 8)

    def test_download_errors_are_rejected(self):
        for status in [202, 403, 404, 500]:
            with self.subTest(status=status):
                self.transport.side_effect = [self.generated, self.ready, (status, {}, b"{}")]
                with self.assertRaisesRegex(RuntimeError, f"download returned HTTP {status}"):
                    self.export()

    def test_download_must_be_an_spdx_document(self):
        for document in [
            None, [], {}, {"message": "error"}, {"sbom": self.sbom},
            {**self.sbom, "SPDXID": "other"},
            {**self.sbom, "spdxVersion": 23},
            {**self.sbom, "packages": None},
        ]:
            with self.subTest(document=document):
                self.transport.side_effect = [self.generated, self.ready, (200, {}, json.dumps(document).encode())]
                with self.assertRaisesRegex(ValueError, "not an SPDX JSON document"):
                    self.export()

    def test_download_must_be_valid_json(self):
        self.transport.side_effect = [self.generated, self.ready, (200, {}, b"<html>error</html>")]

        with self.assertRaises(ValueError):
            self.export()

    def test_invalid_configuration_does_not_make_requests(self):
        for repository, api_url in [
            ("", "https://api.github.com"),
            ("octelium/../other", "https://api.github.com"),
            ("octelium/octelium", "http://api.github.com"),
            ("octelium/octelium", "https://user:pass@api.github.com"),
            ("octelium/octelium", "https://api.github.com?query=value"),
        ]:
            with self.subTest(repository=repository, api_url=api_url):
                with self.assertRaises(ValueError):
                    generate_sbom.generate_sbom(repository, "test-token", api_url=api_url)
        self.transport.assert_not_called()

    def test_main_saves_only_the_validated_spdx_document(self):
        self.transport.side_effect = [self.generated, self.ready, self.downloaded]

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "release files" / "sbom.json"
            with mock.patch.dict(
                generate_sbom.os.environ,
                {"GITHUB_REPOSITORY": "octelium/octelium", "GH_TOKEN": "test-token"},
                clear=True,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(generate_sbom.main([str(output)]), 0)
            self.assertEqual(json.loads(output.read_text()), self.sbom)
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_failed_export_preserves_existing_output(self):
        self.transport.return_value = (403, {}, b"{}")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "sbom.json"
            output.write_text("previous export")
            with mock.patch.dict(generate_sbom.os.environ, {"GITHUB_REPOSITORY": "octelium/octelium"}, clear=True):
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(generate_sbom.main([str(output)]), 1)
            self.assertIn("HTTP 403", errors.getvalue())
            self.assertEqual(output.read_text(), "previous export")


class RequestTest(unittest.TestCase):
    def test_redirect_is_returned_without_following_it(self):
        paths = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                paths.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/download")
                self.end_headers()

            def log_message(self, format, *args):
                pass

        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            worker = threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
            )
            worker.start()
            try:
                status, headers, body = generate_sbom.request(
                    f"http://127.0.0.1:{server.server_port}/report",
                    {"Authorization": "Bearer test-token"},
                    5,
                )
            finally:
                server.shutdown()
                worker.join()

        self.assertEqual(paths, ["/report"])
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], "/download")
        self.assertEqual(body, b"")

    def test_transport_errors_fail_clearly(self):
        with mock.patch.object(generate_sbom.urllib.request, "build_opener") as opener:
            opener.return_value.open.side_effect = urllib.error.URLError("connection failed")

            with self.assertRaisesRegex(RuntimeError, "SBOM request failed"):
                generate_sbom.request("https://api.github.com/report", {}, 10)


if __name__ == "__main__":
    unittest.main()
