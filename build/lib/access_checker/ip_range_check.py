#! /usr/bin/python3
import copy


def in_range(uip_addr, aip_addr):  # uip stands for user ip and aip stands for ACL ip
    top_uip, bottom_uip = range_expander(uip_addr)
    top_aip, bottom_aip = range_expander(aip_addr)
    result1 = octet_check(top_uip, top_aip, bottom_aip)
    result2 = octet_check(bottom_uip, top_aip, bottom_aip)
    return result1 and result2


def octet_check(u_ip, top_aip, bottom_aip):
    j = 0
    while j < 4:
        if u_ip[j] != top_aip[j]:
            if not (int(top_aip[j]) <= int(u_ip[j]) <= int(bottom_aip[j])):
                return False
        j += 1
    return True


def range_expander(ip_addr):
    ip, mask = ip_addr.split('/')
    ip = ip.split('.')
    octet, edge = get_octet(int(mask))
    edge -= int(mask)
    edge = 2 ** edge
    tmp1 = int(int(ip[octet]) / edge)
    nid = tmp1 * edge
    network_id = copy.deepcopy(ip)
    network_id[octet] = str(nid)
    bid = nid + edge - 1
    broadcast_id = copy.deepcopy(ip)
    broadcast_id[octet] = str(bid)
    octet += 1
    while octet < 4:
        network_id[octet] = '0'
        broadcast_id[octet] = '255'
        octet += 1
    return network_id, broadcast_id


def get_octet(change):
    if 0 <= change <= 8:
        octet, edge = 0, 8
    elif 8 < change <= 16:
        octet, edge = 1, 16
    elif 16 < change <= 24:
        octet, edge = 2, 24
    else:
        octet, edge = 3, 32
    return octet, edge

