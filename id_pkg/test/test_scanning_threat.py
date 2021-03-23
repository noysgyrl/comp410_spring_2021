import unittest
import git
import os


# import pandas as pd

class TestScanningThreat(unittest.TestCase):
    def test_scanning_threat_stub(self):
        self.assertEqual(True, True)

    def test_scanning_threat_create_sample_log(self):
        # % ASA - 4 - 733101: Object objectIP ( is targeted | is attacking). Current burst rate is burst_rate per second,
        #  max configured rate is max_rate1; Current average rate is average_rate per second, max configured rate is max_rate2;
        #  Cumulative total count is total_cnt.

        info = {'Date': 'March 30 2021 03:30:30',
                'Host': 'TEAMNULL',
                'Type': 'targeted',
                'ID': '%ASA-4-733101',
                'burst_rate': '20',
                'max_rate1': '10',
                'average_rate': '1',
                'max_rate2': '5',
                'total_cnt': '100'}

        # Get the path to the data directory in the git repo
        git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
        data_path = os.path.join(git_root, 'data')

        # Create a sample log file
        with open(os.path.join(data_path, 'scanning_threat.txt'), 'w') as f:
            for ip_address_d in range(1, 256, 1):
                # Create first part of the message
                log_string = info['Date'] + ' ' + info['ID'] + ': ' + info['Host'] + ' 10.11.11.' + str(ip_address_d)
                # Next add whether the port is attacking or being targeted
                log_string = log_string + ' is ' + info['Type']
                # Next add all of the burst rates
                log_string = log_string + 'Current burst rate is ' + info['burst_rate'] + ' per second, '
                log_string = log_string + 'max configured rate is ' + info['max_rate1'] + '; '
                log_string = log_string + 'Current average rate is ' + info['average_rate'] + ' per second, '
                log_string = log_string + 'max configured rate is ' + info['max_rate2'] + '; '
                log_string = log_string + 'Cumulative total count is ' + info['total_cnt'] + '\n'
                f.write(log_string)


if __name__ == '__main__':
    unittest.main()
