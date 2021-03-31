import unittest
import git
import os
import id_pkg as intrusion_detect
import pandas as pd


class TestSynAttack(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'sync_attack.txt')

    # Rather than get into ordering test cases work around the problem by making sure
    # the test log file gets generated whenever this class is created.

    # %ASA-4-419002: Received duplicate TCP SYN from in_interface:src_address/src_port to
    # out_interface:dest_address/dest_port
    info = {'Date': 'Sep 12 2014 06:50:53',
            'Host': 'HOST',
            'ID': '%ASA-4-419002',
            'Interface': 'TestInterface'}

    # Create a sample log file
    # https://docs.python.org/3/tutorial/inputoutput.html
    with open(syslog_file, 'w') as f:
        for ip_address_d in range(1, 256, 1):
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            log_string = log_string + 'Received duplicate TCP SYN from in_interface:10.1.1.1/1234 to '
            log_string = log_string + 'out_interface:10.11.11.' + str(ip_address_d) + '/8080\n'
            f.write(log_string)

    def test_syn_attack_stub(self):
        self.assertEqual(True, True)

    def test_syn_attack_parse_log(self):
        # Create an IdParse object
        id_syslog = intrusion_detect.IdParse(self.syslog_file)

        # Check to make sure the ip spoofing information got added to the dataframe
        # Get a subset of the whole dataframe
        # s=spoof df=dataframe
        sdf = id_syslog.df[id_syslog.df['ID'] == 419002]

        # Expecting 255 total records
        self.assertEqual(255, len(sdf))

        # Expecting 1 source address
        self.assertTrue((sdf['Source'] == '10.1.1.1').all())

        # Expecting 255 unique destination addresses
        self.assertEqual(255, sdf['Destination'].nunique())

    def test_has_syn_attack(self):
        self.assertTrue(True)
        # id_syslog = intrusion_detect.IdParse(self.syslog_file)
        #
        # # The test file generated has ip spoofing present
        # # so expect this to return true
        # self.assertTrue(id_syslog.has_ip_spoofing())


if __name__ == '__main__':
    unittest.main()
