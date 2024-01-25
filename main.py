import ipaddress
import functions as func

def ip_input():
    while True:
        ip_address = input('Gebe eine IP-Adresse ein:')
        if func.is_valid_ip(ip_address):
            return ip_address
        else:
            print('IP-Adresse ist nicht valide. \n Beispiel für eine valide IP-Adresse: 127.0.0.1')

def subnet_input(ip):
    while True:
        subnet_mask = input('Gebe eine Subnetzmaske ein:')
        if func.is_valid_subnet_mask(ip, subnet_mask):
            return subnet_mask
        else:
            print('Deine eingegebene Subnetzmaske ist nicht valide.')

def convert_to_binary(number):
        binary = bin(number)[2:]
        print(binary)
        print('0' * (8 - len(binary)) + binary, )
        return '0' * (8 - len(binary)) + binary
 
def ip_and_subnet_to_binary(ip_address, subnet_mask):
    # try:
    #     ip_object = ipaddress.ip_address(ip_address)
    #     subnet_object = ipaddress.ip_network(f"{ip_address}/{subnet_mask}", strict=False)
        
    #     binary_ip_sections = [format(int(x), '08b') for x in ip_object.packed]
    #     binary_subnet_sections = [format(int(x), '08b') for x in subnet_object.netmask.packed]

    #     binary_ip = '.'.join(binary_ip_sections)
    #     binary_subnet = '.'.join(binary_subnet_sections)
    #     return binary_ip, binary_subnet
    # except ValueError:
    #     return "Invalid IP address or Subnet mask"

    try:
        # Split IP address into octets and convert to binary
        ip_sections = [int(x) for x in ip_address.split('.')]
        binary_ip_sections = [convert_to_binary(x) for x in ip_sections]
        binary_ip = '.'.join(binary_ip_sections)

        # Split subnet mask into octets and convert to binary
        subnet_sections = [int(x) for x in subnet_mask.split('.')]
        binary_subnet_sections = [convert_to_binary(x) for x in subnet_sections]
        binary_subnet = '.'.join(binary_subnet_sections)

        return binary_ip, binary_subnet
    except ValueError:
        return "Invalid IP address or Subnet mask"
    
def calculate_addresses(ip, subnet_mask):
    # network = ipaddress.IPv4Network(f'{ip}/{subnet_mask}', strict=False)

    # net_address = network.network_address
    # broadcast_address = network.broadcast_address
    # # Get the total number of IP addresses in the network
    # total_ip_addresses = network.num_addresses
    # # Get the number of host addresses (excluding network and broadcast addresses)
    # host_addresses = total_ip_addresses - 2
    # return net_address, broadcast_address, total_ip_addresses, host_addresses

    try:
        # Split IP address into octets and convert to binary
        ip_sections = [int(x) for x in ip.split('.')]
        binary_ip_sections = [convert_to_binary(x) for x in ip_sections]
        binary_ip = '.'.join(binary_ip_sections)

        # Split subnet mask into octets and convert to binary
        subnet_sections = [int(x) for x in subnet_mask.split('.')]
        binary_subnet_sections = [convert_to_binary(x) for x in subnet_sections]
        binary_subnet = '.'.join(binary_subnet_sections)

        # Calculate network and broadcast addresses
        net_address = '.'.join(str(int(a, 2) & int(b, 2)) for a, b in zip(binary_ip_sections, binary_subnet_sections))
        broadcast_address = '.'.join(str(int(a, 2) | (255 - int(b, 2))) for a, b in zip(binary_ip_sections, binary_subnet_sections))

        # Calculate total IP addresses, including network and broadcast addresses
        total_ip_addresses = 2**(32 - binary_subnet.count('0'))

        # Calculate the number of host addresses (excluding network and broadcast addresses)
        host_addresses = total_ip_addresses - 2

        return net_address, broadcast_address, total_ip_addresses, host_addresses
    except ValueError:
        return "Invalid IP address or Subnet mask"

def calculate_bits(subnet_mask):
    # # Convert the subnet mask to binary representation
    # binary_subnet = bin(int(ipaddress.IPv4Address(subnet_mask)))[2:]

    # # Count the number of network bits (counting consecutive leading '1' bits)
    # network_bits = binary_subnet.count('1')

    # # Count the number of host bits (counting consecutive trailing '0' bits)
    # host_bits = binary_subnet.count('0')

    # return network_bits, host_bits

    try:
        # Split subnet mask into octets and convert to binary
        subnet_sections = [int(x) for x in subnet_mask.split('.')]
        binary_subnet_sections = [convert_to_binary(x) for x in subnet_sections]
        binary_subnet = '.'.join(binary_subnet_sections)

        # Count the number of network bits (counting consecutive leading '1' bits)
        network_bits = binary_subnet.count('1')

        # Count the number of host bits (counting consecutive trailing '0' bits)
        host_bits = binary_subnet.count('0')

        return network_bits, host_bits
    except ValueError:
        return "Invalid Subnet mask"
    
def print_colored_binary(binary_string, color_1, color_0):
    for i, bit in enumerate(binary_string):
        if bit == '1':
            print("\033[{}m{}\033[0m".format(color_1, bit), end='')
        elif bit == '0':
            print("\033[{}m{}\033[0m".format(color_0, bit), end='')
        elif bit == '.':
            print('.', end='')  # Add dot after each octet

if __name__ == '__main__':
    ip = ip_input()
    subnet_mask = subnet_input(ip)

    ip_binary, subnet_binary = ip_and_subnet_to_binary(ip, subnet_mask)
    net_address, broadcast_address, total_ips, host_ips = calculate_addresses(ip, subnet_mask)
    network_bits, host_bits = calculate_bits(subnet_mask)

    print('\nIP in Binär:', ip_binary)
    print('Netzmaske in Binär:', end=' ')
    print_colored_binary(subnet_binary, '92', '91')
    print('\nAnzahl an IPs:', total_ips)
    print('Anzahl an Host-Adressen', host_ips)
    print('Netzadresse:', net_address)
    print('Broadcast Adresse:', broadcast_address)
    print(f'Anzahl der Netzwerk-Bits: {network_bits}')
    print(f'Anzahl der Host-Bits: {host_bits}')
