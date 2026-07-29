'''
all the things are orchestrated in main.py ;)
'''


import re
from pathlib import Path
from datetime import datetime


#-----------------------------------------
#VAR DECLARE

LOG_PATH= Path('data') / 'today_log.txt'
LOG_PATTERN = re.compile(r"""
                                (?P<timestamp>\w{3}\s\d\d?\s\d{2}:\d{2}:\d{2})   # Timestamp
                                \s
                                (?P<hostname>\w+)                               # Hostname
                                \s
                                (?P<process>[\w-]+)                             # Process
                                \[
                                (?P<pid>\d+)
                                \]
                                :
                                \s
                                (?P<message>.*)                                 # Message
                                """, re.VERBOSE) #verbose used for writing this long ahh line in multiple lines
IP_REGEX = re.compile(r"from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

#----------------------------------

#PARSE EM boiII!
def parser():
    try:
        parsed_logs = []
        with LOG_PATH.open(encoding="utf-8") as f:
            for line in f:
                match=LOG_PATTERN.match(line.strip())
                if not match:
                    continue

                log_data = match.groupdict()
                message = log_data['message']
                raw_time = log_data["timestamp"]
                parsed_time = datetime.strptime(f"2026 {raw_time}", "%Y %b %d %H:%M:%S")
                log_data["parsed_time"] = parsed_time
                log_data["pid"] = int(log_data["pid"])
                parsed_logs.append(log_data)

        print("analysis complete !!")
        print(f"Parsed {len(parsed_logs)} log entries.")

        # display 5 for now
        print("preview :)  :\n")
        for log in parsed_logs[:5]:
            print(log)
        '''
        #display all
        for log in parsed_logs:
            print(log)
        '''
        return parsed_logs

    except FileNotFoundError:
        print(f"{LOG_PATH} wasn't found !")
        print("no such file !!! :(")

#------------------
#call
if __name__ == "__main__":
    parser()