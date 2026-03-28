import requests

def get_country(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        data = res.json()
        return data.get("country", "Unknown")
    except:
        return "Unknown"
