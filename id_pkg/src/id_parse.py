from id_pkg import LogParse
import pandas as pd
import re


class IdParse(LogParse):
    df = pd.DataFrame()

    def __init__(self, syslog_file):
        self.syslog_to_dataframe(syslog_file)

    def has_ip_spoofing(self):
        # https://pandas.pydata.org/docs/reference/api/pandas.Series.any.html
        # Returns true if the ip spoofing id appears in the dataframe
        return (self.df['ID'] == 106016).any()

    def has_dos_attack(self):
        return (self.df['ID'] == 109017).any()

    def has_firewall(self):
        return (self.df['ID'] == 713162).any()

    def has_acldrop(self):
        return (self.df['ID'] == 733100).any()

    def has_interface(self):
        return (self.df['ID'] == 106001).any()

    def has_scanning_threat(self):
        return (self.df['ID'] == 733101).any()

    def has_denied_icmp(self):
        return (self.df['ID'] == 313004).any()

    def has_syn_attack(self):
        return (self.df['ID'] == 419002).any()

    def has_granted_access_firewall(self):
        return (self.df['ID'] == 713160).any()

    def has_new_translation_slot(self):
        return (self.df['ID'] == 305011).any()

    def get_low_severity(self):
        return self.df[self.df['Severity'] >= 6]

    def get_high_severity(self):
        return self.df[self.df['Severity'] <= 5]

    def get_all(self):
        return self.get_low_severity() + self.get_high_severity()

    def handle_asa_message(self, rec):
        """Implement ASA specific messages"""
        # %ASA-2-106016: Deny IP spoof from (10.1.1.1) to 10.11.11.19 on interface TestInterface
        if rec['ID'] == 106016:
            m = re.search(r'from \((\d+\.\d+\.\d+\.\d+)\) to (\d+\.\d+\.\d+\.\d+) on interface (\w+)', rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['Destination'] = m.group(2)
                rec['Interface'] = m.group(3)

        # %ASA-4-109017: User at IP_address exceeded auth proxy connection limit (max)
        if rec['ID'] == 109017:
            m = re.search(r'User at (\d+\.\d+\.\d+\.\d+) exceeded auth proxy connection limit \(max\)', rec['Text'])
            if m:
                rec['Source'] = m.group(1)

        # %ASA-3-713162: Remote user (session Id - id) has been rejected by the Firewall Server
        if rec['ID'] == 713162:
            m = re.search(r'user \((\w+) - (\w+)\)', rec['Text'])
            if m:
                rec['Session'] = m.group(1)
                rec['Identifier'] = m.group(2)

            # %ASA-4-733100: Object drop rate rate_ID exceeded.
            # Current burst rate is rate_val per second,
            # max configured rate is rate_val;
            # Current average rate is rate_val per second,
            # max configured rate is rate_val;
            # Cumulative total count is total_cnt

        if rec['ID'] == 733100:
            m = re.search(r'rate-(\d+) exceeded. Current burst rate is (\d+) per second, max configured rate is ('
                          r'\d+); Current average rate is (\d+) per second, max configured rate is (\d+); Cumulative '
                          r'total count is (\d+)', rec['Text'])
            if m:
                rec['DropRate'] = m.group(1)
                rec['BurstRate'] = m.group(2)
                rec['MaxConfigRate1'] = m.group(3)
                rec['CurrentAverageRate'] = m.group(4)
                rec['MaxConfigRate2'] = m.group(5)
                rec['TotalCount'] = m.group(6)

        # %ASA-2-106001: Inbound TCP connection denied from 10.132.0.147/2257 to 172.16.10.10/80 flags SYN on interface inside
        if rec['ID'] == 106001:
            m = re.search(r'denied from (\d+\.\d+\.\d+.\d+)\/(\d+) to (\d+.\d+.\d+.\d+)\/(\d+)', rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['SourcePort'] = m.group(2)
                rec['Destination'] = m.group(3)
                rec['DestinationPort'] = m.group(4)

        # % ASA - 4 - 733101: Object objectIP ( is targeted | is attacking). Current burst rate is rate_val per second,
        # max configured rate is rate_val; Current average rate is rate_val per second, max configured rate is rate_val;
        # Cumulative total count is total_cnt.

        if rec['ID'] == 733101:
            m = re.search(r'Current burst rate is (\d+) per second, max configured rate is (\d+); '
                          r'Current average rate is (\d+) per second, max configured rate is (\d+); '
                          r'Cumulative total count is (\d+)', rec['Text'])
            if m:
                rec['Burst_Rate'] = int(m.group(1))
                rec['Max Configured Rate 1'] = int(m.group(2))
                rec['Average Rate'] = int(m.group(3))
                rec['Max Configured Rate 2'] = int(m.group(4))
                rec['Total Count'] = int(m.group(5))

        # %ASA-4-313004: Denied ICMP type=icmp_type, from source_address on interface interface_name to dest_address:no matching session
        if rec['ID'] == 313004:
            m = re.search(r'Denied ICMP type=(\d+), from (\d+\.\d+\.\d+\.\d+) on interface (\w+) '
                          r'to (\d+\.\d+\.\d+\.\d+):no matching session', rec['Text'])
            if m:
                rec['ICMPType'] = m.group(1)
                rec['Source'] = m.group(2)
                rec['Interface'] = m.group(3)
                rec['Destination'] = m.group(4)

        # %ASA-4-419002: Received duplicate TCP SYN from in_interface:src_address/src_port to
        # out_interface:dest_address/dest_port
        if rec['ID'] == 419002:
            m = re.search(
                r'Received duplicate TCP SYN from in_interface:(\d+\.\d+\.\d+\.\d+)/(\d+) to out_interface:(\d+\.\d+\.\d+\.\d+)/(\d+)',
                rec['Text'])
            if m:
                rec['Source'] = m.group(1)
                rec['Source Port'] = m.group(2)
                rec['Destination'] = m.group(3)
                rec['Destination Port'] = m.group(4)

        #%ASA-7-713160: Remote user (session Id - id) has been granted access by the Firewall Server
        if rec['ID'] == 713160:
            m = re.search(r' user \((\w+) - (\w+)\)', rec['Text'])
            if m:
                rec['Session'] = m.group(1)
                rec['Identifier'] = m.group(2)

        # %ASA-6-305011: Built {dynamic|static} {TCP|UDP|ICMP} translation from interface_name :real_address/real_port [(idfw_user )] to interface_name :mapped_address/mapped_port
        if rec['ID'] == 305011:
            m = re.search(r' from interface_name \((\w+) to interface_name (\w+)\)', rec['Text'])
            if m:
                rec['Real Address'] = m.group(1)
                rec['Mapped Address'] = m.group(2)

        return rec

    def handle_syslog_message(self, line):
        """Parses basic information out of a syslog file"""
        m = re.search(r'^(\w+ \w+ \w+ \d+:\d+:\d+) (\w+) : %(\w+)-(\d)-(\d+): (.+)', line)
        # If the re matched
        if m:
            return self.handle_asa_message({'Date': m.group(1),
                                            'Host': m.group(2),
                                            'Type': m.group(3),
                                            'Severity': int(m.group(4)),
                                            'ID': int(m.group(5)),
                                            'Text': m.group(6)})
        else:
            return {}

    def syslog_to_dataframe(self, syslog_file):
        """Returns a dataframe from a sample syslog file"""
        # Improve pandas performance by creating a list first
        rec_list = []
        # Read the syslog file and parse it into our dataframe
        with open(syslog_file, encoding='utf-8') as f:
            for line in f:
                # Create a record to hold this line in the syslog file
                rec_list.append(self.handle_syslog_message(line))
        # Create the dataframe from the list
        self.df = pd.DataFrame(rec_list)