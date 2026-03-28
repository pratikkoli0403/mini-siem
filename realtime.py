import time

LOG_FILE = "/var/log/auth.log"

def follow(file):
    file.seek(0, 2)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def stream_logs(callback):
    with open(LOG_FILE, "r") as file:
        for line in follow(file):
            callback(line)
