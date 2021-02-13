import unittest
import id_pkg as intrusion_detect


class LogParseTest(unittest.TestCase):
    """Unit test structure for LogParse"""
    def test_log_parse(self):
        """Basic test case to show that LogParse loads OK"""
        lp = intrusion_detect.LogParse()
        self.assertEqual('LogParse', lp.log_parse_id())


if __name__ == '__main__':
    unittest.main()
