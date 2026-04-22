"""
MITMProxy addon that strips Content Security Policy headers from HTTP responses.
This allows the Chromebook to execute inline scripts and load resources that
would normally be blocked by CSP.
"""

from mitmproxy import http
import logging

CSP_HEADERS = [
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-security-policy",
    "x-webkit-csp",
    "x-csp",
]

class StripCSP:
    def __init__(self):
        self.stripped_count = 0

    def response(self, flow: http.HTTPFlow) -> None:
        """
        Intercept HTTP responses and remove CSP-related headers.
        """
        for header in CSP_HEADERS:
            if header in flow.response.headers:
                del flow.response.headers[header]
                self.stripped_count += 1
                logging.info(
                    f"[StripCSP] Removed '{header}' from {flow.request.pretty_url}"
                )

    def done(self):
        logging.info(f"[StripCSP] Total CSP headers stripped: {self.stripped_count}")


addons = [StripCSP()]
