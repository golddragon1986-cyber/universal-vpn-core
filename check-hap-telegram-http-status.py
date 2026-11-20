import json
from urllib.request import ProxyHandler,build_opener
from urllib.error import HTTPError
opener=build_opener(ProxyHandler({'https':'http://127.0.0.1:1080'}));rows=[]
for _ in range(3):
    try:
        with opener.open('https://telegram.org',timeout=8) as response:response.read(1024);rows.append({'http':response.status})
    except HTTPError as error:rows.append({'http':error.code})
    except Exception as error:rows.append({'error':type(error).__name__})
print(json.dumps(rows))
