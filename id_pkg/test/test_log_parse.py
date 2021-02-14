# https://docs.python.org/3/library/unittest.html
import unittest
import id_pkg as intrusion_detect
import git
import os


class LogParseTest(unittest.TestCase):
    """Unit test structure for LogParse"""
    # https://docs.python.org/3/library/unittest.html#unittest.TestCase
    def test_log_parse(self):
        """Basic test case to show that LogParse loads OK"""
        lp = intrusion_detect.LogParse()
        self.assertEqual('LogParse', lp.log_parse_id())

    def test_syslog_file(self):
        """Checks to make sure the syslog file appears valid"""
        # Find the path to the package directory in the current working git repo
        # Use os.path to make sure paths are platform independent
        pkg_path = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
        data_path = os.path.join(pkg_path, 'data')

        # https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog/syslogs-sev-level.html
        fname = 'syslogs.txt'

        # Open the syslog file
        # https://docs.python.org/3/tutorial/inputoutput.html
        with open(os.path.join(data_path, fname)) as f:
            line_num = 1
            for line in f:
                # create a string with the current file name and line number
                # for use in error messages
                ln = fname+':'+str(line_num)+' '

                # expect all lines to begin with %ASA-
                # https://docs.python.org/3/library/unittest.html#unittest.TestCase.assertRegex
                self.assertRegex(line, r'^%ASA-', ln+'does not start with %ASA-')

                # Make sure there are no other %ASA which would indicate a
                # merged line or other problem in the syslog file
                self.assertNotRegex(line, r'.%ASA', ln+'extra %ASA found')

                line_num += 1


if __name__ == '__main__':
    unittest.main()
