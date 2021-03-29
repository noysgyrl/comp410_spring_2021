import unittest
import os
import git
import id_pkg


class TestICMPDenial(unittest.TestCase):

    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'ICMP_denied.txt')

    # %ASA-4-313004: Denied ICMP type=icmp_type, from source_address on interface
    # interface_name to dest_address:no matching session

    info = {'Date': 'January 1 2021 11:11:11',
            'Host': 'HOST',
            'ID': '%ASA-4-313004',
            'Interface': 'interface_name'
            }

    # Creates sample log file
    with open(syslog_file, 'w') as outfile:
        icmp = 0
        for ip1 in range(1, 256, 1):
            # Increment ICMP type by 1 until it hits 40
            # then reset it to 1
            icmp += 1
            if icmp > 40:
                icmp = 1
                # basic message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # add ICMP type
            log_string = log_string + 'Denied ICMP type=' + str(icmp) + ", from "
            # add source address (?????)
            log_string = log_string + '10.1.1.' + str(ip1)
            # add interface
            log_string = log_string + ' on interface ' + info['Interface']
            # add destination address (?????)
            log_string = log_string + ' to ' + '172.18.1.' + str(ip1) + ':no matching session' + '\n'
            outfile.write(log_string)

    def test_denied_icmp_stub(self):
        self.assertEqual(True, True)

    def test_denied_icmp_parse_log(self):
        id_syslog = id_pkg.IdParse(self.syslog_file)

        # get dataframe logs with this ID
        dataframe = id_syslog.df[id_syslog.df['ID'] == 313004]

        # should have 255 entries
        self.assertEqual(255, len(dataframe))

        # should have 255 unique source addresses
        self.assertTrue(255, dataframe['Source'].nunique())

        # should have 255 unique destination addresses
        self.assertTrue(255, dataframe['Destination'].nunique())

        # should have 40 different icmp types
        self.assertTrue(40, dataframe['ICMPType'].nunique())

    def test_has_denied_icmp(self):
        id_syslog = id_pkg.IdParse(self.syslog_file)
        # test file should contain denied ICMP, this should be true
        self.assertTrue(id_syslog.has_denied_icmp())


if __name__ == '__main__':
    unittest.main()