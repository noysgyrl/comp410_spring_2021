import pandas as pd
import id_pkg as intrusion_detect
import os


def show_aggie_pride():
    # https://pandas.pydata.org/docs/user_guide/index.html
    df = pd.DataFrame(['Aggie Pride', 'Worldwide', 'Aggies Do', 'Go Aggies', 'Aggies', 'GHOE!',
                       'Achievement', 'We Graduating!!', 'A-G-G-I-E', 'NCAT',
                       'Aggie Born, Aggie Bred, When I\'m gone I\'ll be Aggie Dead',
                       'Greatest Homecoming On Earth', 'Mens et Manus (Mind and Hand)',
                       'yay aggies','AGGIES CODE!', 'Aggie Land Forever'])
    print(df)

    # Basic check to show LopParse is working
    lp = intrusion_detect.LogParse()
    print('---')
    print(lp.log_parse_id())

    # Show the total number of messages
    # s=sys l=log
    file_path = os.path.join('id_pkg', 'data')
    sl = lp.parse_syslog_file(os.path.join(file_path, 'syslogs.txt'))
    print('Total Syslog Types', end=':')
    print(len(sl))


if __name__ == "__main__":
    show_aggie_pride()
