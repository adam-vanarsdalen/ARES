import unittest
from unittest import mock

import tools.network_tools as network_tools
from utils.scope_validator import Scope, ScopeValidator


class TestPortScanXML(unittest.TestCase):
    def test_port_scan_parses_nmap_xml_output(self):
        xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.19.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.49"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
        completed = mock.Mock(stdout=xml)
        scope = ScopeValidator(Scope(domains=["example.com", "*.example.com"]))

        with mock.patch.object(network_tools.subprocess, "run", return_value=completed):
            out = network_tools.port_scan("example.com", "80,443", scope)

        self.assertEqual(
            out["open_ports"],
            [
                "80/tcp open http nginx/1.19.0",
                "443/tcp open https Apache httpd/2.4.49",
            ],
        )
        names = [t["name"] for t in out["detected_tech"]]
        self.assertIn("nginx 1.19.0", names)
        self.assertIn("Apache 2.4.49", names)


if __name__ == "__main__":
    unittest.main()
