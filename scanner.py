import requests
from tabulate import tabulate

url = 'https://www.adultswithautism.org.uk'  
vulnerabilities = []

lfi_url = f'{url}/wp-config.php'
response = requests.get(lfi_url)
if response.status_code == 200:
    vulnerabilities.append(['LFI Vulnerability', lfi_url])

wp_json_url = f'{url}/wp-json/wp/v2/users'
response = requests.get(wp_json_url)
if "rest_user_cannot_view" in response.text:
    vulnerabilities.append(['wp-json Vulnerability', wp_json_url])

xmlrpc_url = f'{url}/xmlrpc.php'
response = requests.post(xmlrpc_url, data='<methodCall><methodName>system.listMethods</methodName></methodCall>')
if "system.multicall" in response.text:
    vulnerabilities.append(['xml-rpc Vulnerability', xmlrpc_url])

    print(tabulate(vulnerabilities, headers=['Vulnerability Type', 'URL']))