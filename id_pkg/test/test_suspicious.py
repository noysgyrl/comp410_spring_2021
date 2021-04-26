import unittest
import os
import git
import id_pkg

class TestSuspicious(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    intrusionLog = os.path.join(git_root, 'data', 'intrusion_logs.txt')

    log = id_pkg.IdParse(intrusionLog)

    def test_get_low_severity(self):
        #finds low severity messages from log (severity >= 6)
        low_severity = self.log.get_low_severity()

        print('Unique low severity messages:')
        print(low_severity['ID'].unique())

        self.assertListEqual([305011, 713160], list(low_severity['ID'].unique()))

    def test_get_high_severity(self):
        #finds high severity messages from log (severity <= 5)
        high_severity = self.log.get_high_severity()

        print('Unique high severity messages:')
        print(high_severity['ID'].unique())

        #prints unique IP addresses of high severity attacks
        attacker_ip = high_severity['Source'].dropna().unique()
        print(attacker_ip)

        low_severity = self.log.get_low_severity()
        suspicious = low_severity[low_severity['Source'].isin(attacker_ip)]
        suspicious.to_excel('suspicious.xlsx')

        #force fail
        self.assertTrue(True)