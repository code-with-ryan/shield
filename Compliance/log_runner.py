import datetime

# This file is used to log messages to a file and to the console. 
FILE_LOCATION = "./log.txt"


def log_message(message):
    current_time = datetime.datetime.now()
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{formatted_time} - {message}"
    
    print(log_entry)
    with open(FILE_LOCATION, 'a') as log_file:
        log_file.write(log_entry + '\n')
