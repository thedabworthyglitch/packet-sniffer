import requests
import csv
def fetch_iana_protocol_numbers():
    url = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv'
    response = requests.get(url)
    lines = response.text.split('\n')
    protocol_mapping = {}
    for line in lines[1:]:
        if line:
            parts = line.split(',')
            if len(parts) >= 2:
                try:
                    number = int(parts[0])
                    name = parts[1].strip()
                    protocol_mapping[number] = name
                except ValueError:
                    continue
    return protocol_mapping

def print_protocol_mapping(protocol_mapping):
    for number, name in protocol_mapping.items():
        print(f"{number}: '{name}',")

if __name__ == '__main__':
    iana_protocol_mapping = fetch_iana_protocol_numbers()
    print_protocol_mapping(iana_protocol_mapping)
