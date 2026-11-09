import socket
import unittest

from wifit3_bridge.examples.windows_wpa_smoke import (
    _EapSimDbServer,
    _sim_triplets,
)


class EapSimDbTransportTests(unittest.TestCase):
    def test_loopback_udp_exchange(self):
        server = _EapSimDbServer(None, _sim_triplets())
        try:
            server.start()
            self.assertTrue(server.endpoint.startswith("udp:127.0.0.1:"))
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(1.0)
            try:
                client.sendto(b"SIM-REQ-AUTH 123456789012345 3", ("127.0.0.1", server.port))
                response, _ = client.recvfrom(4096)
            finally:
                client.close()
            self.assertTrue(response.startswith(b"SIM-RESP-AUTH 123456789012345 "))
            self.assertEqual(response.count(b":"), 4)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()
