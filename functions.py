import ipaddress

def is_valid_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False
        
def is_valid_subnet_mask(ip, subnet_mask):
    try:
        network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
        return True
    except ValueError:
        return False

def mbinary(ip):
    string_ip = str(ip)
    splitted_ip = string_ip.split('.')
    octed_list = []

    for part_ip in splitted_ip:
        temp_octet = list('00000000')
        part_ip = int(part_ip)
        if (part_ip >= 128):
            temp_octet[0] = '1'
            part_ip -= 128
        if (part_ip >= 64):
            temp_octet[1] = '1'
            part_ip -=64
        if (part_ip >= 32):
            temp_octet[2] = '1'
            part_ip -= 32
        if (part_ip >= 16):
            temp_octet[3] = '1'
            part_ip -= 16
        if (part_ip >= 8):
            temp_octet[4] = '1'
            part_ip -= 8
        if (part_ip >= 4):
            temp_octet[5] = '1'
            part_ip -= 4
        if (part_ip >= 2):
            temp_octet[6] = '1'
            part_ip -= 2
        if (part_ip >= 1):
            temp_octet[7] = '1'
        temp_octet = ''.join(temp_octet)
        octed_list.append(temp_octet)
    
    print('.'.join(octed_list))

if __name__ == '__main__':
    mbinary('192.16.200.245')