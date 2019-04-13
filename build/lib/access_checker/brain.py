#! /usr/bin/python3

from access_checker.ip_range_check import in_range
from access_checker.port_and_protocols import protocol
from access_checker.port_and_protocols import to_numeric_port


def access_check(usr_src_ip, usr_dst_ip, usr_src_port, usr_dst_port, usr_protocol, table):
    protocol_check = protocol(usr_protocol, table['acl_protocol'])
    if protocol_check:
        if not str(usr_dst_port).isdigit():
            usr_dst_port = to_numeric_port(usr_dst_port)

        if not str(usr_src_port).isdigit():
            usr_src_port = to_numeric_port(usr_src_port)

        acl_src_port = table['acl_src_port']
        if '-' in acl_src_port:
            acl_src_port = table['acl_src_port'].split('-')
            if not str(acl_src_port[0]).isdigit():
                acl_src_port[0] = to_numeric_port(acl_src_port[0])
            if not str(acl_src_port[1]).isdigit():
                acl_src_port[1] = to_numeric_port(acl_src_port[1])
            if int(acl_src_port[0]) <= int(usr_src_port) <= int(acl_src_port[1]):
                result1 = True
            else:
                result1 = False
        elif '_' in acl_src_port:
            acl_src_port = table['acl_src_port'].split('_')
            acl_src_port_num = []
            for item in acl_src_port:
                if not str(item).isdigit():
                    item = to_numeric_port(item)
                acl_src_port_num.append(item)
            if str(usr_src_port) in acl_src_port_num:
                result1 = True
            else:
                result1 = False
        else:
            result1 = False

        acl_dst_port = table['acl_dst_port']
        if '-' in acl_dst_port:
            acl_dst_port = table['acl_dst_port'].split('-')
            if not str(acl_dst_port[0]).isdigit():
                acl_dst_port[0] = to_numeric_port(acl_dst_port[0])
            if not str(acl_dst_port[1]).isdigit():
                acl_dst_port[1] = to_numeric_port(acl_dst_port[1])
            if int(acl_dst_port[0]) <= int(usr_dst_port) <= int(acl_dst_port[1]):
                result2 = True
            else:
                result2 = False

        elif '_' in acl_dst_port:
            acl_dst_port = table['acl_dst_port'].split('_')
            acl_dst_port_num = []
            for item in acl_dst_port:
                if not str(item).isdigit():
                    item = to_numeric_port(item)
                acl_dst_port_num.append(item)
            if str(usr_dst_port) in acl_dst_port_num:
                result2 = True
            else:
                result2 = False
        else:
            result2 = False

        if result2 and result1:
            if in_range(usr_src_ip, table['acl_src_ip']):
                if in_range(usr_dst_ip, table['acl_dst_ip']):
                    return True

    else:
        return False
