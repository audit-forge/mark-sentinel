import unittest

from edge_dns import classify_domain, event_for_line, parse_query


CATALOG = [
    {"domain": "openai.com", "provider": "OpenAI", "category": "generative_ai", "confidence": "high"}
]


class EdgeDnsTests(unittest.TestCase):
    def test_parses_dnsmasq_query(self):
        self.assertEqual(
            parse_query("dnsmasq[1]: query[A] chat.openai.com from 192.168.1.143", "dnsmasq"),
            ("192.168.1.143", "chat.openai.com"),
        )

    def test_parses_unbound_query(self):
        self.assertEqual(
            parse_query("unbound: info: 192.168.1.236 api.openai.com. A IN", "unbound"),
            ("192.168.1.236", "api.openai.com"),
        )

    def test_matches_subdomain_and_minimizes_event(self):
        event = event_for_line(
            "dnsmasq[1]: query[A] api.openai.com from 192.168.1.143",
            "dnsmasq", "site-a", CATALOG,
        )
        self.assertEqual(event["provider"], "OpenAI")
        self.assertNotIn("raw_log", event)

    def test_does_not_match_unrelated_domain(self):
        self.assertIsNone(classify_domain("example.com", CATALOG))


if __name__ == "__main__":
    unittest.main()
