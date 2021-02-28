import unittest
import git
import os


class TestIpSpoofing(unittest.TestCase):
    def test_ip_spoofing_stub(self):
        self.assertEqual(True, True)

    def test_ip_spoofing_create_sample_log(self):
        # %ASA-2-106016: Deny IP spoof from (IP_address) to IP_address on interface interface_name.
        # Sep 12 2014 06:50:53 HOST : %ASA-2-106016: Deny IP spoof from (10.1.1.1) to 10.11.11.11 on
        #   interface TestInterface
        info = {'Date': 'Sep 12 2014 06:50:53',
                'Host': 'HOST',
                'ID': '%ASA-2-106016',
                'Interface': 'TestInterface'}

        # Get the path to the data directory in the git repo
        git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
        data_path = os.path.join(git_root, 'data')

        # Create a sample log file
        # https://docs.python.org/3/tutorial/inputoutput.html
        with open(os.path.join(data_path,'ip_spoofing.txt'), 'w') as f:
            for ip_address_d in range(1,256,1):
                # Create the first part of the message
                log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
                # Next add the source IP address message
                log_string = log_string + 'Deny IP spoof from (10.1.1.1) to '
                # Now add the destination IP
                log_string = log_string + 'to 10.11.11.' + str(ip_address_d)
                # Terminate the message with the interface name
                log_string = log_string + ' on interface ' + info['Interface'] + '\n'
                f.write(log_string)


if __name__ == '__main__':
    unittest.main()
