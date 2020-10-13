from datetime import datetime
def get_date_and_time():
    now = datetime.now()
    string = now.strftime("%m%d%y_%H%M%S")
    return string
print(get_date_and_time())