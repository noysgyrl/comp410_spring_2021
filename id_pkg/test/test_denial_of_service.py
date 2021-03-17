import unittest
import os
import git
import random


class TestDenialOfService(unittest.TestCase):
    git_root = os.path.join(git.Repo('.', search_parent_directories=True).working_tree_dir, 'id_pkg')
    syslog_file = os.path.join(git_root, 'data', 'denial_of_service.txt')

    def test_denial_of_service_stub(self):
        self.assertEqual(True, True)


    # %ASA-4-109017: User at IP_address exceeded auth proxy connection limit (max)
    info = {
        'Date': 'Mar 28 2021 06:50:53',
        'Host': 'TEAMNULL',
        'ID': '%ASA-4-109017',
    }

    # Create a sample log file
    with open(syslog_file, 'w') as f:
        # Generate a random IPv4 address in four parts
        ip_address_1 = "10"
        ip_address_2 = str(random.randint(1, 255))
        ip_address_3 = str(random.randint(1, 255))
        ip_address_4 = str(random.randint(1, 255))

        for ip_address_d in range(1,256,1):
            # Create the first part of the message
            log_string = info['Date'] + ' ' + info['Host'] + ' : ' + info['ID'] + ': '
            # Next add the source IP address message
            log_string = log_string + 'User at ' + ip_address_1 + '.' + ip_address_2 + '.' + ip_address_3 + '.' + ip_address_4
            # Terminate the message
            log_string = log_string + ' exceeded auth proxy connection limit (max)' + '\n'
            f.write(log_string)


if __name__ == '__main__':
    unittest.main()
