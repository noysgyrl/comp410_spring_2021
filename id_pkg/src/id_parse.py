from id_pkg import LogParse
import pandas as pd


class IdParse(LogParse):
    df = pd.DataFrame()

    def __init__(self, syslog_file):
        self.df = self.syslog_to_dataframe(syslog_file)
