#! /usr/bin/python3


def protocol(usr_protocol, acl_protocol):
    if usr_protocol == 'ip':
        usr_protocol = 'tcp-udp'
    if acl_protocol == 'ip':
        acl_protocol = 'tcp-udp'
    if usr_protocol in acl_protocol:
        return True
    else:
        return False


def to_numeric_port(usr_dst_port):
    numeric_port = {'http': '80', 'www': '80', 'https': '443', 'telnet': '23', 'ssh': '22', 'domain': '53', 'bootpc': '68', 'bootps': '67',
                    'smtp': '25', 'imap': '143', 'rdp': '3389', 'pop3': '110', 'tftp': '69', 'ftp': '21', 'snmp': '161'}
    return numeric_port[usr_dst_port]


