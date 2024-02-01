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
        total_ip_addresses = 2**(binary_subnet.count('0'))

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


def colorize_ip(ip, network_bits):
    parts = ip.split('.')
    binary_parts = [format(int(part), '08b') for part in parts]

    # ANSI escape codes for red and green
    red = '\033[31m'
    green = '\033[32m'
    reset = '\033[0m'

    colored_parts = []
    for i, part in enumerate(binary_parts):
        if (i+1) * 8 <= network_bits:
            colored_parts.append(red + part + reset)
        elif i * 8 < network_bits < (i+1) * 8:
            split_index = network_bits - i * 8
            colored_parts.append(red + part[:split_index] + reset + green + part[split_index:] + reset)
        else:
            colored_parts.append(green + part + reset)

    return '.'.join(colored_parts)


if __name__ == '__main__':
    ip = ip_input()
    subnet_mask = subnet_input(ip)

    ip_binary, subnet_binary = ip_and_subnet_to_binary(ip, subnet_mask)
    net_address, broadcast_address, total_ips, host_ips = calculate_addresses(ip, subnet_mask)
    network_bits, host_bits = calculate_bits(subnet_mask)

    print("\n-----------------------------------------")
    print("""
    Um die IP-Adresse und die Subnetzmaske in Binärformat zu formatieren, gibt es ein einfaches Muster, dem Sie folgen 
    können: Die binäre Darstellung der Dezimalzahl 255 lautet:
    x*2^7 + x*2^6 + x*2^5 + x*2^4 + x*2^3 + x*2^2 + x*2^1 + x*2^0
    wobei alle Summanden den Faktor x = 1 haben.
    Umgekehrt hat die binäre Darstellung der Dezimalzahl 0 die gleiche Formel, 
    aber der Faktor x = 0.
    Mit dieser Formel können Sie die binäre Darstellung jeder Dezimalzahl finden,
    indem Sie überprüfen, ob jeder Summand von links nach rechts in die Dezimalzahl passt.
    Wenn ja, ist der Faktor x = 1, wenn nicht, ist der Faktor x = 0.
    Der Faktor für jeden Summanden ist die binäre Ziffer.
    Wenn Sie dies für jedes Oktett durchführen, erhalten Sie die binäre Darstellung der Dezimalzahl.
    Beispiel:
    Nehmen Sie die Dezimalzahl 192:
    Der erste Summand 2^7 = 128 passt, also setzen wir das erste Bit auf 1.
    192 - 128 = 64
    Wir nehmen den zweiten Summanden 2^6 = 64, passt also setzen wir das zweite Bit auf 1.
    64 - 64 = 0, also sind wir in diesem Fall fertig und setzen die anderen Bits auf null.
    Die binäre Darstellung der Dezimalzahl 192 lautet also 11000000.
    """)
    print('\nIP in Binär:', colorize_ip(ip, network_bits))
    print('Netzmaske in Binär:', colorize_ip(subnet_mask, network_bits))
    print("\n-------------------Anzahl IPs----------------------")
    print('Die Anzahl der IPs berechnet sich durch 2^n, wobei n die Anzahl der Nullen bei der Subnetzmaske ist:')
    print('Anzahl an IPs:', total_ips)
    print("\n------------------Anzahl Host Adressen-----------------------")
    print('Die Anzahl der Hostadressen ist dann 2^n-2, da Broadcast- und die Netzadresse selbst abgezogen werden müssen:')
    print('Anzahl an Host-Adressen', host_ips)
    print("\n---------------Netzadresse--------------------------")
    print("Die Netzadresse berechnet sich durch die logische AND Verknüpfung von IP Adresse und Subnetzmaske in binärer Darstellung:")
    print(colorize_ip(ip, network_bits))
    print("AND")
    print(colorize_ip(subnet_mask, network_bits))
    print("=")
    print(colorize_ip(net_address, network_bits))
    print("zurück in die Dezimalform konvertiert ist die Netzadresse: ")
    print(net_address)
    print("\n----------------Broadcast-------------------------")
    print('Die Broadcast Adresse berechnet sich durch die Netzwerkadresse + 2^n-1, da es die letzte Adresse im Subnetz ist:')
    print('Broadcast Adresse:', broadcast_address)
    print("\n----------------CIDR-------------------------")
    print('Die Subnetzmaske in der CIDR Notation berechnet sich durch 32-n:')
    print(f'Subnetzmaske in CIDR Notation: /{network_bits}')
    print("\n----------------Netzwerk- & Hostbits-------------------------")
    print('Die Anzahl der Netzwerkbits ist die gleiche Zahl wie die CIDR Notation und die Anzahl der Host Bits ist 32-Anzahl der Netzwerkbits:')
    print(f'Anzahl der Netzwerk-Bits: {network_bits}')
    print(f'Anzahl der Host-Bits: {host_bits}')
    print("-----------------------------------------")
    input('Drücke Enter zum Beenden')