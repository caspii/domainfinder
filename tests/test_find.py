import io
import json
import sys
import types
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import find


def http_error(url, code, body=b""):
    return urllib.error.HTTPError(url, code, "error", Message(), io.BytesIO(body))


class Response:
    def __init__(self, status, body=b"{}"):
        self.status = status
        self._body = body if isinstance(body, bytes) else body.encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FindTestCase(unittest.TestCase):
    def setUp(self):
        find._bootstrap_services = None

    def write_input(self, directory, text):
        path = Path(directory) / "input.txt"
        path.write_text(text, encoding="utf-8")
        return path


class InputAndCliTests(FindTestCase):
    def test_reads_prefix_and_suffix_sections(self):
        with self.temporary_input() as path:
            prefixes, suffixes = find.read_input_file(path)
        self.assertEqual(prefixes, ["signup"])
        self.assertEqual(suffixes, ["abc", "now", "zap"])

    def test_generates_com_names(self):
        self.assertEqual(
            find.generate_domains(["signup"], ["abc", "now", "zap"], ".com"),
            ["signupabc.com", "signupnow.com", "signupzap.com"],
        )

    def test_cli_defaults(self):
        with mock.patch("sys.argv", ["find.py"]):
            args = find.parse_arguments()
        self.assertEqual(args.tld, ".com")
        self.assertEqual(args.input, "input.txt")
        self.assertEqual(args.output, "free-domains.txt")
        self.assertEqual(args.checked, "checked-domains.txt")

    def temporary_input(self):
        import tempfile

        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        path = self.write_input(
            self._tmp.name,
            "--prefixes\nsignup\n\n--suffixes\nabc\nnow\nzap\n",
        )
        return _OpenPath(path)


class _OpenPath:
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        return self.path

    def __exit__(self, *_args):
        return False


class RdapTests(FindTestCase):
    def test_com_404_is_available_without_bootstrap(self):
        seen = []

        def urlopen(request, timeout=None):
            seen.append(request.full_url)
            if request.full_url.endswith("/domain/signupzap.com"):
                raise http_error(request.full_url, 404, b"")
            raise AssertionError(request.full_url)

        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertTrue(find.domain_is_available("signupzap.com", ".com"))

        self.assertEqual(seen, ["https://rdap.verisign.com/com/v1/domain/signupzap.com"])

    def test_com_200_is_taken(self):
        def urlopen(request, timeout=None):
            return Response(200, b'{"objectClassName":"domain","ldhName":"SIGNUPNOW.COM"}')

        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertFalse(find.domain_is_available("signupnow.com", ".com"))

    def test_net_uses_verisign_net_base(self):
        seen = []

        def urlopen(request, timeout=None):
            seen.append(request.full_url)
            raise http_error(request.full_url, 404, b"")

        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertTrue(find.domain_is_available("example.net", ".net"))

        self.assertEqual(seen, ["https://rdap.verisign.com/net/v1/domain/example.net"])

    def test_other_tld_uses_iana_bootstrap(self):
        bootstrap = {
            "version": "1.0",
            "services": [
                [["org"], ["https://rdap.example.test/org/"]],
                [["io"], ["https://rdap.example.test/io"]],
            ],
        }
        seen = []

        def urlopen(request, timeout=None):
            seen.append(request.full_url)
            if request.full_url == find.IANA_RDAP_BOOTSTRAP_URL:
                return Response(200, json.dumps(bootstrap))
            if request.full_url == "https://rdap.example.test/io/domain/example.io":
                return Response(200, b'{"objectClassName":"domain"}')
            raise AssertionError(request.full_url)

        with mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertFalse(find.domain_is_available("example.io", ".io"))

        self.assertEqual(
            seen,
            [
                find.IANA_RDAP_BOOTSTRAP_URL,
                "https://rdap.example.test/io/domain/example.io",
            ],
        )


class WhoisFallbackTests(FindTestCase):
    def install_whois(self, whois_fn, *, modern=True, legacy=False):
        whois_mod = types.ModuleType("whois")
        parser_mod = types.ModuleType("whois.parser")
        modules = {"whois": whois_mod, "whois.parser": parser_mod}
        whois_mod.parser = parser_mod
        whois_mod.whois = whois_fn

        if modern:
            exceptions_mod = types.ModuleType("whois.exceptions")

            class WhoisError(Exception):
                pass

            class WhoisDomainNotFoundError(WhoisError):
                pass

            exceptions_mod.WhoisError = WhoisError
            exceptions_mod.WhoisDomainNotFoundError = WhoisDomainNotFoundError
            whois_mod.exceptions = exceptions_mod
            modules["whois.exceptions"] = exceptions_mod
            # 0.9.6 keeps PywhoisError off the parser. Touching it must not crash.
            self.assertFalse(hasattr(parser_mod, "PywhoisError"))
        else:
            # Block the real whois.exceptions module so this looks like 0.9.4.
            modules["whois.exceptions"] = None

        if legacy:
            class PywhoisError(Exception):
                pass

            parser_mod.PywhoisError = PywhoisError

        return modules

    def test_rdap_outage_uses_modern_not_found_exception(self):
        def whois_fn(_domain):
            raise sys.modules["whois"].exceptions.WhoisDomainNotFoundError('No match for "signupzap.com"')

        modules = self.install_whois(whois_fn, modern=True, legacy=False)

        def urlopen(request, timeout=None):
            raise urllib.error.URLError("timed out")

        with mock.patch.dict(sys.modules, modules), mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertTrue(find.domain_is_available("signupzap.com", ".com"))

    def test_rdap_outage_uses_legacy_parser_error(self):
        def whois_fn(_domain):
            raise sys.modules["whois"].parser.PywhoisError('No match for "signupzap.com"')

        modules = self.install_whois(whois_fn, modern=False, legacy=True)

        def urlopen(request, timeout=None):
            raise urllib.error.URLError("connection refused")

        with mock.patch.dict(sys.modules, modules), mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertTrue(find.domain_is_available("signupzap.com", ".com"))

    def test_whois_transport_error_is_not_reported_as_free(self):
        def whois_fn(_domain):
            raise sys.modules["whois"].exceptions.WhoisError("Whois command returned no output")

        modules = self.install_whois(whois_fn, modern=True, legacy=False)

        def urlopen(request, timeout=None):
            raise http_error(request.full_url, 503, b"unavailable")

        with mock.patch.dict(sys.modules, modules), mock.patch("urllib.request.urlopen", side_effect=urlopen):
            with self.assertRaises(find.AvailabilityUnknown):
                find.domain_is_available("signupabc.com", ".com")

    def test_installed_python_whois_not_found_type_resolves(self):
        import whois.exceptions
        import whois.parser

        resolved = find.not_found_exceptions()
        self.assertIn(whois.exceptions.WhoisDomainNotFoundError, resolved)
        # python-whois 0.9.6 removed this. The old except clause crashed here.
        self.assertFalse(hasattr(whois.parser, "PywhoisError"))

    def test_successful_rdap_does_not_call_whois(self):
        def whois_fn(_domain):
            raise AssertionError("WHOIS should not run when RDAP answers")

        modules = self.install_whois(whois_fn)

        def urlopen(request, timeout=None):
            return Response(200, b'{"objectClassName":"domain"}')

        with mock.patch.dict(sys.modules, modules), mock.patch("urllib.request.urlopen", side_effect=urlopen):
            self.assertFalse(find.domain_is_available("signupabc.com", ".com"))


class SampleRunTests(FindTestCase):
    SAMPLE = "--prefixes\nsignup\n\n--suffixes\nabc\nnow\nzap\n"

    def fake_sample_urlopen(self, request, timeout=None):
        url = request.full_url
        if url.endswith("/domain/signupzap.com"):
            raise http_error(url, 404, b"")
        if url.endswith("/domain/signupabc.com") or url.endswith("/domain/signupnow.com"):
            return Response(200, b'{"objectClassName":"domain"}')
        raise AssertionError(url)

    def test_sample_input_reports_free_and_taken(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.txt"
            output_path = Path(tmp) / "free.txt"
            checked_path = Path(tmp) / "checked.txt"
            input_path.write_text(self.SAMPLE, encoding="utf-8")
            argv = [
                "find.py",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--checked",
                str(checked_path),
            ]
            with mock.patch("sys.argv", argv), mock.patch("find.sleep"), mock.patch(
                "urllib.request.urlopen", side_effect=self.fake_sample_urlopen
            ):
                find.main()

            self.assertEqual(output_path.read_text(encoding="utf-8").splitlines(), ["signupzap.com"])
            self.assertEqual(
                checked_path.read_text(encoding="utf-8").splitlines(),
                ["signupabc.com", "signupnow.com", "signupzap.com"],
            )

    def test_failed_lookup_is_not_marked_checked(self):
        import tempfile

        def urlopen(request, timeout=None):
            raise urllib.error.URLError("network down")

        def whois_fn(_domain):
            raise TimeoutError("timed out")

        modules = WhoisFallbackTests.install_whois(self, whois_fn)
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.txt"
            output_path = Path(tmp) / "free.txt"
            checked_path = Path(tmp) / "checked.txt"
            input_path.write_text(self.SAMPLE, encoding="utf-8")
            argv = [
                "find.py",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--checked",
                str(checked_path),
            ]
            with mock.patch("sys.argv", argv), mock.patch("find.sleep"), mock.patch(
                "urllib.request.urlopen", side_effect=urlopen
            ), mock.patch.dict(sys.modules, modules):
                with self.assertRaises(SystemExit) as ctx:
                    find.main()

            self.assertEqual(ctx.exception.code, 1)
            self.assertEqual(output_path.read_text(encoding="utf-8"), "")
            self.assertEqual(checked_path.read_text(encoding="utf-8"), "")

    def test_skips_domains_already_checked(self):
        import tempfile

        seen = []

        def urlopen(request, timeout=None):
            seen.append(request.full_url)
            raise http_error(request.full_url, 404, b"")

        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "input.txt"
            output_path = Path(tmp) / "free.txt"
            checked_path = Path(tmp) / "checked.txt"
            input_path.write_text(self.SAMPLE, encoding="utf-8")
            checked_path.write_text("signupabc.com\nsignupnow.com\n", encoding="utf-8")
            argv = [
                "find.py",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--checked",
                str(checked_path),
            ]
            with mock.patch("sys.argv", argv), mock.patch("find.sleep"), mock.patch(
                "urllib.request.urlopen", side_effect=urlopen
            ):
                find.main()

            self.assertEqual(seen, ["https://rdap.verisign.com/com/v1/domain/signupzap.com"])
            self.assertEqual(output_path.read_text(encoding="utf-8").splitlines(), ["signupzap.com"])
            self.assertEqual(
                checked_path.read_text(encoding="utf-8").splitlines(),
                ["signupabc.com", "signupnow.com", "signupzap.com"],
            )


if __name__ == "__main__":
    unittest.main()
