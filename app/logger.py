import json
from datetime import datetime

def log_event(data):

    log = {
        "timestamp": datetime.utcnow().isoformat(),
        **data
    }

    with open("logs.json", "a") as f:
        f.write(json.dumps(log) + "\n")