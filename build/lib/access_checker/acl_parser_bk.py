#! /usr/bin/python3

from access_checker.wc_mask_to_cidr import to_cidr
from access_checker.brain import access_check
import copy


def cisco_acl(usr_src_ip, usr_dst_ip, usr_src_port, usr_dst_port, usr_protocol, input_acl):

    input_acl = input_acl.split('\n')
    for line in input_acl:
        if ('deny' in line or 'permit' in line) and 'established' not in line:
            tmp1 = line.split()
            tmp2 = copy.deepcopy(tmp1)
            # counter = j, ip address counter = i, port counter = k. i.e when source ports gets captured k becomes 1
            j, i, k = 0, 0, 0
            table = {}
            for element in tmp2:
                if element == 'permit' or element == 'deny':
                    break
                else:
                    del tmp1[0]
            while j < len(tmp1):
                if 'permit' in tmp1[j] or 'deny' in tmp1[j]:
                    table['acl_action'] = tmp1[j]
                    table['acl_protocol'] = tmp1[j + 1]
                    j += 1
                elif tmp1[j] == 'host' and i == 0:
                    table['acl_src_ip'] = tmp1[j + 1] + '/32'
                    j += 1
                    i += 1
                    if tmp1[j + 1] not in ['range', 'eq', 'lt', 'gt']:
                        k += 1
                        table['acl_src_port'] = '0-65535'
                elif tmp1[j] == 'any' and i == 0:
                    table['acl_src_ip'] = '0.0.0.0/0'
                    i += 1
                    if tmp1[j + 1] not in ['range', 'eq', 'lt', 'gt']:
                        k += 1
                        table['acl_src_port'] = '0-65535'
                elif (tmp1[j] != 'host' and tmp1[j] != 'any') and i == 0 and j != 0:
                    if '/' in tmp1[j]:
                        table['acl_src_ip'] = tmp1[j]
                        i += 1
                        if tmp1[j + 1] not in ['range', 'eq', 'lt', 'gt']:
                            k += 1
                            table['acl_src_port'] = '0-65535'
                    else:
                        cidr = to_cidr(tmp1[j + 1])
                        table['acl_src_ip'] = tmp1[j] + '/' + cidr
                        j += 1
                        i += 1
                        if tmp1[j + 1] not in ['range', 'eq', 'lt', 'gt']:
                            k += 1
                            table['acl_src_port'] = '0-65535'
                elif tmp1[j] == 'range' and k == 0:
                    table['acl_src_port'] = tmp1[j + 1] + '-' + tmp1[j + 2]
                    j += 2
                    k += 1
                elif tmp1[j] == 'eq' and k == 0:
                    table['acl_src_port'] = tmp1[j + 1] + '_' + tmp1[j + 1]
                    j += 1
                    k += 1
                    n = j + 1
                    src_port_list = []
                    src_port_list.append(table['acl_src_port'])

                    while n < len(tmp1):
                        check = ['any', 'host', '.']
                        if any(element in tmp1[n] for element in check):
                            break
                        else:
                            src_port_list.append(tmp1[n])
                            j += 1
                        n += 1

                    src_port_list = '_'.join(src_port_list)
                    table['acl_src_port'] = src_port_list

                elif tmp1[j] == 'lt' and k == 0:
                    num = int(tmp1[j + 1]) - 1
                    table['acl_src_port'] = '0' + '-' + str(num)
                    j += 1
                    k += 1
                elif tmp1[j] == 'gt' and k == 0:
                    num = int(tmp1[j + 1]) + 1
                    table['acl_src_port'] = str(num) + '-' + '65535'
                    j += 1
                    k += 1
                elif tmp1[j] == 'host' and i == 1:
                    table['acl_dst_ip'] = tmp1[j + 1] + '/32'
                    j += 1
                    i += 1
                elif tmp1[j] == 'any' and i == 1:
                    table['acl_dst_ip'] = '0.0.0.0/0'
                    i += 1
                elif (tmp1[j] != 'host' and tmp1[j] != 'any') and i == 1 and j != 0:
                    if '/' in tmp1[j]:
                        table['acl_dst_ip'] = tmp1[j]
                        i += 1
                    else:
                        cidr = to_cidr(tmp1[j + 1])
                        table['acl_dst_ip'] = tmp1[j] + '/' + cidr
                        j += 1
                        i += 1
                elif tmp1[j] == 'range' and k == 1 and i == 2:
                    table['acl_dst_port'] = tmp1[j + 1] + '-' + tmp1[j + 2]
                    j += 2
                    k += 1
                elif tmp1[j] == 'eq' and k == 1 and i == 2:
                    table['acl_dst_port'] = tmp1[j + 1] + '_' + tmp1[j + 1]
                    j += 1
                    k += 1
                    n = 0
                    dst_port_list = []
                    dst_port_list.append(table['acl_dst_port'])
                    while n < (len(tmp1) - j):
                        dst_port_list.append(tmp1[j])
                        j += 1
                    dst_port_list = '_'.join(dst_port_list)
                    table['acl_dst_port'] = dst_port_list

                elif tmp1[j] == 'lt' and k == 1 and i == 2:
                    num = int(tmp1[j + 1]) - 1
                    table['acl_dst_port'] = '0' + '-' + str(num)
                    j += 1
                    k += 1
                elif tmp1[j] == 'gt' and k == 1 and i == 2:
                    num = int(tmp1[j + 1]) + 1
                    table['acl_dst_port'] = str(num) + '-' + '65535'
                    j += 1
                    k += 1
                j += 1
            if table['acl_protocol'] == 'ip':
                table['acl_dst_port'] = '0-65535'
            if k < 2:
                table['acl_dst_port'] = '0-65535'
            result = access_check(usr_src_ip, usr_dst_ip, usr_src_port, usr_dst_port, usr_protocol, table)
            if result:
                #   print('-' * 150)
                a = '{}: Matching on this line --------> {}'.format(table['acl_action'].upper(), line.strip())
                #   print('-' * 150)
                return a
            else:
                pass

    print('-' * 150)
    a = 'DENY:  No full matching entries, hence implicit deny at ' \
        'the end. Partial access will be flagged as DENY'
    print('-' * 150)
    return a
