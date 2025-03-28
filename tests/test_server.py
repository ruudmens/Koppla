import unittest
from koppla.server import query_ad

class TestServer(unittest.TestCase):
    def test_query_ad(self):
        result = query_ad("list_groups")
        self.assertIn("status", result)

if __name__ == "__main__":
    unittest.main()
