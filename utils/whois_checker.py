import whois
from datetime import datetime


def get_domain_age(url):

    try:

        domain = url.replace("https://", "")
        domain = domain.replace("http://", "")
        domain = domain.split("/")[0]
        domain = domain.replace("www.", "")

        info = whois.whois(domain)

        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date: 
            return None

        age_days = (
            datetime.now(creation_date.tzinfo)
            - creation_date
        ).days

        return age_days

    except Exception as e:

        print("WHOIS ERROR:", e)

        return None