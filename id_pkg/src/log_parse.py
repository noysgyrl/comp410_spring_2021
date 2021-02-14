import pandas as pd
import re


class LogParse:
    """Parser for firewall logs"""
    def log_parse_id(self):
        """For testing purposes simply return a text message"""
        return 'LogParse'

    def handle_message(self, df, id):
        """Handles specific syslog messages"""
        # %ASA-1-103004: (Primary) Other firewall reports this firewall failed. Reason: reason-string.
        if id == 103004:
            (message, reason) = df.loc[id, 'Text'].split('Reason: ')
            df.loc[id, 'Message'] = message.rstrip()
            df.loc[id, 'Reason'] = reason.rstrip()

        return df

    def parse_syslog_file(self, syslog_file):
        """Returns a dataframe of parsed syslogs"""

        # https://pandas.pydata.org/docs/user_guide/index.html
        df = pd.DataFrame()

        with open(syslog_file) as f:
            for line in f:
                # https://developers.google.com/edu/python/regular-expressions
                # %(Type)-(Severity)-(id): (Text)
                m = re.search(r'^%(\w+)-(\d)-(\d+): (.+)', line)
                # If the re matched
                if m:
                    id = int(m.group(3))
                    df.loc[id, 'Type'] = m.group(1)
                    df.loc[id, 'Severity'] = int(m.group(2))
                    df.loc[id, 'Text'] = m.group(4).rstrip()

                    df = self.handle_message(df, id)

        return df
