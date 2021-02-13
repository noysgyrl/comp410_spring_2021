import pandas as pd
import id_pkg as intrusion_detect


def show_aggie_pride():
    df = pd.DataFrame(['Aggie Pride', 'Worldwide', 'Aggies Do', 'Go Aggies', 'Aggies', 'GHOE!',
                       'Achievement', 'We Graduating!!', 'A-G-G-I-E', 'NCAT',
                       'Aggie Born, Aggie Bred, When I\'m gone I\'ll be Aggie Dead',
                       'Greatest Homecoming On Earth', 'Mens et Manus (Mind and Hand)',
                       'yay aggies','AGGIES CODE!'])
    print(df)

    # Basic check to show LopParse is working
    lp = intrusion_detect.LogParse()
    print(lp.log_parse_id())


if __name__ == "__main__":
    show_aggie_pride()
