#! /usr/bin/python3


def to_cidr(inverse_mask):
    inverse_mask = inverse_mask.split('.')
    cidr_mask = 0
    for item in inverse_mask:
        mask = 255 - int(item)
        mask = bin(mask)
        mask = mask.count('1')
        cidr_mask += mask
    return str(cidr_mask)

