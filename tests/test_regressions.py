import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT.parent
if str(PARENT) not in sys.path:
    sys.path.insert(0, str(PARENT))

from vulnscan.core.http_client import AdaptiveHTTPClient
from vulnscan.modules.ssl_scanner import SSLScanner
from vulnscan.modules.subdomain_scanner import SubdomainScanner


class RegressionTests(unittest.TestCase):
    def test_http_client_supports_options_and_request(self):
        client = AdaptiveHTTPClient()

        with mock.patch.object(client.session, "request", return_value="ok") as mocked_request:
            result = client.options("https://example.com", headers={})

        self.assertEqual(result, "ok")
        mocked_request.assert_called_once()
        method, url = mocked_request.call_args.args[:2]
        headers = mocked_request.call_args.kwargs["headers"]
        self.assertEqual(method, "OPTIONS")
        self.assertEqual(url, "https://example.com")
        self.assertIn("User-Agent", headers)

    def test_ssl_wildcard_matching_is_single_label_only(self):
        scanner = SSLScanner()

        self.assertTrue(scanner._match_hostname("app.example.com", "*.example.com"))
        self.assertFalse(scanner._match_hostname("example.com", "*.example.com"))
        self.assertFalse(scanner._match_hostname("deep.app.example.com", "*.example.com"))

    def test_subdomain_enumeration_keeps_https_results_without_callback(self):
        scanner = SubdomainScanner(client=mock.Mock())
        scanner._check_single_domain = mock.Mock(
            side_effect=lambda domain: {
                "subdomain": domain,
                "ip": "127.0.0.1",
                "http": False,
                "https": True,
                "status": 200,
            }
        )

        results = scanner.enumerate(
            "example.com",
            use_wordlist=False,
            use_crtsh=False,
            callback=None,
        )

        self.assertEqual(
            {result["subdomain"] for result in results},
            {"example.com", "www.example.com"},
        )


    # ── SSL two-pass certificate retrieval regressions ──────────────────

    @mock.patch("vulnscan.modules.ssl_scanner.socket.create_connection")
    @mock.patch("vulnscan.modules.ssl_scanner.ssl.create_default_context")
    def test_ssl_valid_cert_returns_full_cert_dict(self, mock_ctx_factory, mock_conn):
        """Pass 1 succeeds for a valid cert — cert dict must be non-empty."""
        fake_cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Let's Encrypt"),),),
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "subjectAltName": (("DNS", "example.com"),),
        }
        fake_binary = b"\x30\x82"

        mock_ssock = mock.MagicMock()
        mock_ssock.getpeercert.side_effect = lambda binary_form=False: (
            fake_binary if binary_form else fake_cert
        )
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = mock.Mock(return_value=mock_ssock)
        mock_ssock.__exit__ = mock.Mock(return_value=False)

        mock_ctx = mock.MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_factory.return_value = mock_ctx

        mock_sock = mock.MagicMock()
        mock_sock.__enter__ = mock.Mock(return_value=mock_sock)
        mock_sock.__exit__ = mock.Mock(return_value=False)
        mock_conn.return_value = mock_sock

        scanner = SSLScanner()
        info = scanner._get_certificate_info("example.com")

        self.assertIsNotNone(info)
        self.assertEqual(info["cert"], fake_cert)
        self.assertIsNone(info["validation_error"])

        # Running _check_certificate should NOT produce "No SSL Certificate"
        findings = scanner._check_certificate("example.com", info)
        vuln_classes = [f.vuln_class for f in findings]
        self.assertNotIn("No SSL Certificate", vuln_classes)

    @mock.patch("vulnscan.modules.ssl_scanner.socket.create_connection")
    @mock.patch("vulnscan.modules.ssl_scanner.ssl.create_default_context")
    def test_ssl_self_signed_classified_correctly(self, mock_ctx_factory, mock_conn):
        """Self-signed cert: Pass 1 raises SSLCertVerificationError,
        Pass 2 grabs binary cert — finding should be 'Self-Signed Certificate'."""
        import ssl as _ssl

        # Pass 1 context raises verification error
        mock_ctx_pass1 = mock.MagicMock()
        mock_ssock_fail = mock.MagicMock()
        mock_ssock_fail.__enter__ = mock.Mock(return_value=mock_ssock_fail)
        mock_ssock_fail.__exit__ = mock.Mock(return_value=False)
        mock_ssock_fail.getpeercert.side_effect = _ssl.SSLCertVerificationError(
            "self-signed certificate"
        )
        # Make wrap_socket raise on the first call (Pass 1)
        pass1_err = _ssl.SSLCertVerificationError("[SSL: CERTIFICATE_VERIFY_FAILED] self-signed certificate")

        # Pass 2 context succeeds with CERT_NONE
        mock_ssock_ok = mock.MagicMock()
        mock_ssock_ok.getpeercert.return_value = b"\x30\x82"
        mock_ssock_ok.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock_ok.version.return_value = "TLSv1.3"
        mock_ssock_ok.__enter__ = mock.Mock(return_value=mock_ssock_ok)
        mock_ssock_ok.__exit__ = mock.Mock(return_value=False)

        mock_ctx_pass2 = mock.MagicMock()
        mock_ctx_pass2.wrap_socket.return_value = mock_ssock_ok

        # First call returns pass1 ctx (raises), second returns pass2 ctx
        mock_ctx_pass1.wrap_socket.side_effect = pass1_err
        mock_ctx_factory.side_effect = [mock_ctx_pass1, mock_ctx_pass2]

        mock_sock = mock.MagicMock()
        mock_sock.__enter__ = mock.Mock(return_value=mock_sock)
        mock_sock.__exit__ = mock.Mock(return_value=False)
        mock_conn.return_value = mock_sock

        scanner = SSLScanner()
        info = scanner._get_certificate_info("selfsigned.example.com")

        self.assertIsNotNone(info)
        self.assertEqual(info["cert"], {})
        self.assertIsNotNone(info["cert_binary"])
        self.assertIn("self-signed", info["validation_error"].lower())

        # Classification should produce "Self-Signed Certificate", NOT "No SSL Certificate"
        findings = scanner._check_certificate("selfsigned.example.com", info)
        vuln_classes = [f.vuln_class for f in findings]
        self.assertIn("Self-Signed Certificate", vuln_classes)
        self.assertNotIn("No SSL Certificate", vuln_classes)


if __name__ == "__main__":
    unittest.main()
