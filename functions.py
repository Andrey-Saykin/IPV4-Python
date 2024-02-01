# def is_valid_ip(ip):
#     try:
#         ipaddress.IPv4Address(ip)
#         return True
#     except ipaddress.AddressValueError:
#         try:
#             ipaddress.IPv6Address(ip)
#             return True
#         except ipaddress.AddressValueError:
#             return False
        
# def is_valid_subnet_mask(ip, subnet_mask):
#     try:
#         network = ipaddress.IPv4Network(f"{ip}/{subnet_mask}", strict=False)
#         return True
#     except ValueError:
#         return False
    
def is_valid_ip(ip):
    """
    Check if the given IP address is valid.

    Args:
        ip (str): The IP address to be checked.

    Returns:
        bool: True if the IP address is valid, False otherwise.
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for item in parts:
        if not 0 <= int(item) <= 255:
            return False
    return True

def is_valid_subnet_mask(ip, subnet_mask):
    """
    Check if the given subnet mask is valid for the given IP address.

    Args:
        ip (str): The IP address.
        subnet_mask (str): The subnet mask.

    Returns:
        bool: True if the subnet mask is valid, False otherwise.
    """
    if not is_valid_ip(ip) or not is_valid_ip(subnet_mask):
        return False

    mask_parts = subnet_mask.split('.')
    valid_masks = [0, 128, 192, 224, 240, 248, 252, 254, 255]
    if len(mask_parts) != 4:
        return False

    for i in range(4):
        if int(mask_parts[i]) not in valid_masks:
            return False
        if i > 0 and int(mask_parts[i-1]) < int(mask_parts[i]):
            return False

    return True

def mbinary(ip):
    """
    Convert the given IP address to binary representation.

    Args:
        ip (str): The IP address to be converted.

    Returns:
        None
    """
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