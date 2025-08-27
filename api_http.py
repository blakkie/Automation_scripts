import requests   
query = {'lat':'45', 'lon':'180'}
try:
    response = requests.get('http://api.open-notify.org/iss-pass.json', params=query)
    print(response.json())
    print('Headers requests:')
    print(response.content)
    print(response.json())
except requests.exceptions.RequestException as e:
    print(e)

print('Headers response:')
for header, value in response.headers.items():
    print(header, '-->', value)

    print('Headers response:')
    for header, value in response.headers.items():
        print(header, '-->', value)
        



    
    
