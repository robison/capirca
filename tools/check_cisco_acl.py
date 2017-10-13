#!/usr/bin/env python
#
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This is an sample tool which will locate the first matching access in a
# Cisco ACL for a given set of src/dst addresses & dst port/protocol


__author__ = ('robison@packetized.io')

# system imports
import json
import re
import socket
import struct
import sys
sys.path.append("..")

# capirca imports
from lib import aclgenerator
from lib import nacaddr
from lib import naming
from lib import policy

# Set up our table of allowable actions for access control entries
_ACTION_TABLE = {'permit': 'accept',
                 'deny': 'deny'}

# this is a fake-out; we're overriding the value of policy.DEFINITIONS here
# so that we have a `def` dir to look in, but that's also empty. this goes
# along with having naming.py trying to cast a name to an nacaddr.IP
# object before raising UndefinedAddressError() in naming.Naming.GetNet()
# there is most likely a better way of doing this
policy.DEFINITIONS = naming.Naming(sys.path[0] + '/../def')

# some very nice regexes for strictly matching on IPv4 & IPv6 addresses,
# including IPv6 zone ID support (RFC6874)
# originally from https://gist.github.com/mnordhoff/2213179
IPV4_ADDRESS = (r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-'
                '9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
IPV6_ADDRESS = (r'(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2['
                '0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:)'
                '{5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}'
                '?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?'
                ':[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0'
                '-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f'
                ']{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]'
                ')\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{'
                '1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2'
                '}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1'
                ',4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9]'
                '[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?'
                ':[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-'
                '9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0'
                '-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4'
                '})?::)')
IPV6_ADDRZ = (r'(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4'
              '][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:'
              '[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|'
              '[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f'
              ']{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]'
              '|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-'
              '9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-'
              '9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{'
              '1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.)'
              '{3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::'
              '[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0'
              '-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{'
              '1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){'
              '3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::['
              '0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)%25(?:[A-Za-z0-9\\\._~-]|%[0-9A-Fa-f]{'
              '2})+')
IPV6_ADDRESS_OR_ADDRZ = (r'(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-'
                         '9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0'
                         '-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0'
                         '-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1'
                         ',4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1'
                         '[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:['
                         '0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{'
                         '1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{'
                         '2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}'
                         ':){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-'
                         '5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0'
                         '-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-'
                         '9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'
                         '(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:['
                         '0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-'
                         '9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa'
                         '-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)(?:%25(?:[A-Za-z0-9\\\._~-]|%[0-9A-Fa-f]{2})+)?')

# Long and terrible regexes for parsing a Cisco ACL line. Should probably do
# some cleanup or more robust testing here. Also, look at supporting IPv6
# in the near to medium future.
IPV4_ACL_REGEX = (r'^ ?(?P<action>permit|deny) (?P<protocol>tcp|udp|icmp|ip|esp|ah|\d{1,3})\ (?:(?P<src_any>any)|(?:h'
                  'ost (?P<src_host>(?:host )?' + IPV4_ADDRESS + '(?:\/32|\s0.0.0.0)?))|(?P<src_net>' + IPV4_ADDRESS +
                  ' ' + IPV4_ADDRESS + '))(?:\s*(?:eq (?P<sport_eq>\d{1,5})|range (?P<sport_start>\d{1,5}) (?P<sport_'
                  'end>\d{1,5})))?(?: (?P<dst_any>any)| ?(?:host (?P<dst_host>(?:host )?' + IPV4_ADDRESS + '(?:\/32|'
                  '\s0.0.0.0)?))| ?(?P<dst_net>' + IPV4_ADDRESS + ' ' + IPV4_ADDRESS + '))? ?(?:(?:eq (?P<dport_eq>\d'
                  '{1,5})|range (?P<dport_start>\d{1,5}) (?P<dport_end>\d{1,5})| ?(?P<icmp_type>\d{1,2}(?:(?P<icmp_co'
                  'de>\d{1,2}))?)))?(?: ?(?P<estab>established))?(?: (?P<log>log))?')
IPV6_ACL_REGEX = (r'^ ?(?P<action>permit|deny) (?P<protocol>ipv6|\d{1,3})\ (?:(?P<src_any>any)|(?:host (?P<src_host>'
                  + IPV6_ADDRESS_OR_ADDRZ + '))|(?P<src_net>' + IPV6_ADDRESS_OR_ADDRZ + '\/\d{1,3}))(?:\s*(?:eq (?P<sp'
                  'ort_eq>\d{1,5})|range (?P<sport_start>\d{1,5}) (?P<sport_end>\d{1,5})))?(?: (?P<dst_any>any)| ?(?:h'
                  'ost (?P<dst_host>' + IPV6_ADDRESS_OR_ADDRZ + '))| ?(?P<dst_net>' + IPV6_ADDRESS_OR_ADDRZ + '\/\d{1,'
                  '3}))? ?(?:(?:eq (?P<dport_eq>\d{1,5})|range (?P<dport_start>\d{1,5}) (?P<dport_end>\d{1,5})| ?(?P<i'
                  'cmp_type>\d{1,2}(?:(?P<icmp_code>\d{1,2}))?)))?(?: ?(?P<estab>established))?(?: (?P<log>log))?')

# Compiling our regexes here, and including some simple regexes so we make
# certain that we're capturing all of the lines in the ACL file, and not just
# skipping any because we couldn't match or parse them
IPV4_ACL = re.compile(IPV4_ACL_REGEX)
IPV6_ACL = re.compile(IPV6_ACL_REGEX)
BLANK_LINE = re.compile(r'^$')
REMARK_LINE = re.compile(r'^ ?(remark.*|!.*|#.*)$')
CFG_LINE = re.compile(r'^ *((no )?ip(v6)? access-list.*|statistics per-entry|configure session.*|(commit|end|exit))$')

# Set up our mapping from field type to policy.VarType function
_VARTYPE_DICT = {'action': policy.VarType.ACTION,
                 'protocol': policy.VarType.PROTOCOL,
                 'src': policy.VarType.SADDRESS,
                 'dst': policy.VarType.DADDRESS,
                 'sport': policy.VarType.SPORT,
                 'dport': policy.VarType.DPORT,
                 'options': policy.VarType.OPTION,
                 'icmp_type': policy.VarType.ICMP_TYPE,
                 'icmp_code': policy.VarType.ICMP_CODE,
                 'logging': policy.VarType.LOGGING,
                 'name': policy.VarType.COMMENT}


def mask_from_slash(slash):
    """
    Generates an integer bitwise netmask from a prefix length argument
    """
    mask = 0x00000000
    for bit in range(0, slash):
        mask = (mask >> 1) | 0x80000000
    return mask


def int32_to_dotted_quad(num):
    """Turns 32 bit integer into dotted decimal notation.

    Args:
        num: 32 bit integer.

    Returns:
        Integer as a string in dotted decimal notation.

    """
    try:
        xrange
    except NameError:
        xrange = range
    octets = []
    for _ in xrange(4):
        octet = num & 0xFF
        octets.insert(0, str(octet))
        num >>= 8
    return '.'.join(octets)


# construct our subnet & wildcard mask tables, to make short work
# of doing lookups, without having to manually build a dict here
_SUBNET_MASK_TABLE = {int32_to_dotted_quad(mask_from_slash(x)): x for x in range(0, 33)}
_WILDCARD_MASK_TABLE = {int32_to_dotted_quad(mask_from_slash(x) ^ 0xFFFFFFFF): x for x in range(0, 33)}


def ip2long(ip, version):
    """
    Convert an IP string to long
    """
    if version == 6:
        packedIP = socket.inet_pton(socket.AF_INET6, ip)
        hi, lo = struct.unpack("!QQ", packedIP)
        return (hi << 64) | lo
    else:
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]


def is_bit_on(number, bit, masklen):
    """
    Returns true if the nth position bit (prefix length style) is on
    in number
    """
    return (number & (1 << (masklen - bit))) != 0


def contiguous_bits(mask, masklen):
    """
    Return an array of range tuples (start, end) of groups of on bits in
    the discontiguous mask
    """
    ranges = []
    start, end = (None, None)
    for bit in range(1, masklen + 1):
        if is_bit_on(mask, bit, masklen):
            if start:
                end = bit
            else:
                start = bit
                end = bit
        elif end:
            ranges.append((start, end))
            start, end = (None, None)
    if end:
        ranges.append((start, end))
    return ranges


def unroller(ranges, prefixes, af):
    """
    Takes an array of prefixes and array of ranges, operates on the
    first range and recurses until returning the full array of unrolled
    prefixes
    """
    if af == 6:
        masklen = 128
    else:
        masklen = 32
    if not ranges:
        return prefixes
    unrolled = []
    rng = ranges.pop(0)
    start, end = rng
    bits = end - start + 1
    for prefix in prefixes:
        for field in range(0, 2**bits):
            mask = mask_from_slash(start - 1) | (mask_from_slash(masklen) >> end)
            unrolled.append((prefix & mask) | (field << (masklen - end)))
    return unroller(ranges, unrolled, af)


def unroll(addr, mask, af, ip_obj=False):
    """
    Unrolls a discontiguous network & netmask into an array of either
    ipaddr objects with prefix and normal netmasks, or ipaddr strings
    with prefix and normal netmask
    """
    if af == 6:
        masklen = 128
        addr_as_long = ip2long(addr, 6)
        mask_as_long = 2**int(mask)
        nIP = nacaddr.IP
    else:
        masklen = 32
        addr_as_long = ip2long(addr, 4)
        mask_as_long = ip2long(mask, 4)
        nIP = nacaddr.IP
    # If the final bitstring ends in 32, we will return subnets instead
    # of addresses, so set it aside for later
    rng = None
    ranges = contiguous_bits(mask_as_long, masklen)
    if ranges[-1][1] == masklen:
        rng = ranges.pop()
    unrolled = unroller(ranges, [addr_as_long], af)

    processed = []
    for address in unrolled:
        if rng:
            start, end = rng
            network = address & mask_from_slash(start - 1)
            if ip_obj:
                processed.append(nIP((network, start - 1)))
            else:
                processed.append(str(nIP((network, start - 1))))
        else:
            if ip_obj:
                processed.append(nIP(address))
            else:
                processed.append(str(nIP(address)))

    return processed


class Term(policy.Term):
    """A single ACL Term."""

    def __init__(self, term, af=4):
        super(self.__class__, self).__init__(term)
        self.term = term
        # Our caller should have already verified the address family.
        assert af in (4, 6)
        self.af = af
        if af == 6:
            self.text_af = 'inet6'
        else:
            self.text_af = 'inet'


def update_term(vartype, val, t):
    if isinstance(val, (list, tuple)):
        for item in val:
            try:
                update_term(vartype, item, t)
            except policy.TermObjectTypeError:
                t.AddObject(policy.VarType(vartype, item))
    else:
        try:
            t.AddObject([policy.VarType(vartype, val)])
        except policy.TermObjectTypeError:
            t.AddObject(policy.VarType(vartype, val))
    return t


def create_single_term(action, af, protocol, src, dst, sport, dport,
                       icmp_type, icmp_code, options, logging, name=None):
    """
    returns: list of policy.Term() objects
    """
    args = locals()
    term = Term(policy.VarType(policy.VarType.ACTION, action), af)
    for k, v in args.iteritems():
        if v is not None and k not in ['action', 'af']:
            term = update_term(_VARTYPE_DICT[k], v, term)
    term.SanityCheck()
    return term


def create_multi_term(action, af, protocol, src, dst, sport, dport,
                      icmp_type, icmp_code, options, logging, name=None):
    """
    Provide a set of arguments detailing a particular set of access, and
    recurse to return a broken-down list of terms matching that access.
    This is done to handle several cases where we need to check for
    completely unoptimized access, such as discontiguous subnet masks
    that have been broken down into lists of contiguous networks/masks,
    and src/dst ports that are adjacent to one another. Also see:

    http://www.cisco.com/warp/public/cc/pd/si/casi/ca6000/tech/65acl_wp.pdf
    """
    term_multi_list = []
    if isinstance(src, (list, tuple)) or isinstance(dst, (list, tuple)):
        for src_net, dst_net in [(src_net, dst_net) for src_net in src for dst_net in dst]:
            sd_term = create_multi_term(action, af, protocol, src_net, dst_net, sport, dport,
                                        icmp_type, icmp_code, options, logging, name)
            term_multi_list.extend(sd_term)
    # If we find a port tuple that's adjacent, split it into two different
    # terms. This handles some aggressive `range` optimizations that we would
    # otherwise miss.
    elif is_tuple_adjacent(sport) or is_tuple_adjacent(dport):
        for s, d in [(s, d) for s in set(sport) for d in set(dport)]:
            term_multi_list.extend(create_multi_term(action, af, protocol, src, dst, (s, s), (d, d),
                                                     icmp_type, icmp_code, options, logging, name))
    else:
        sd_term = create_single_term(action, af, protocol, [src], [dst], sport, dport,
                                     icmp_type, icmp_code, options, logging, name)
        term_multi_list.append(sd_term)
    return term_multi_list


def is_tuple_adjacent(pair):
    if isinstance(pair, tuple) and max(pair) - min(pair) == 1:
        return True
    else:
        return False


def load_rules(filePath):
    with open(filePath, 'r') as aclFile:
        acl = aclFile.read().splitlines()
    return acl


def compare_terms(a, b, strict_action=True):
    if strict_action:
        if [y for x in a if isinstance(x, Term)
                for y in b if isinstance(y, Term) and
                (x in y or x == y) and
                x.action == y.action and
                x.text_af == y.text_af]:
            return True
        else:
            return False
    else:
        if [y for x in a if isinstance(x, Term)
                for y in b if isinstance(y, Term) and
                (x in y or x == y) and
                x.text_af == y.text_af]:
            return True
        else:
            return False


def get_line_terms_dict(acl_set):
    unparsed_list = []
    term_dict = {}
    line_dict = {i: j for i, j in enumerate(acl_set)}
    for idx, line in line_dict.iteritems():
        (_term_list, _unparsed) = create_terms_from_line(line)
        if (_term_list and len(_term_list) > 0):
            term_dict[idx] = _term_list
        if (_unparsed and len(_unparsed) > 0):
            unparsed_list.append(_unparsed)
    return line_dict, term_dict, unparsed_list


def compare_acls(a, b):
    unmatched = {}
    line_dict_a, term_dict_a, unparsed_a = get_line_terms_dict(load_rules(a))
    _, term_dict_b, _ = get_line_terms_dict(load_rules(b))
    for a_index, a_terms in term_dict_a.iteritems():
        matched = False
        for b_index, b_terms in term_dict_b.iteritems():
            if compare_terms(a_terms, b_terms):
                matched = True
                break
        if not matched:
            unmatched[a_index] = line_dict_a[a_index].strip()
    return unmatched, len(term_dict_a), unparsed_a


def check_access(search_term, acl_file):
    acl = load_rules(acl_file)
    match_dict = {}
    for idx, line in enumerate(acl):
        line_terms = []
        if 'established' not in line:
            x, y = create_terms_from_line(line)
            if x:
                line_terms.extend(x)
        else:
            continue
        # match dot com
        if [j for i in line_terms for j in search_term if compare_terms([j], [i], False)]:
            match_dict[int(idx + 1)] = line.strip()
    return match_dict


def _parse_nets(anynet, net, host, af):
    addr = None
    if anynet and af is 6:
        addr = ['0::/0']
    elif anynet and af is 4:
        addr = ['0.0.0.0/0']
    elif net and af == 6:
        addr = [net]
    elif net and af == 4:
        network, netmask = re.split(r'[ \/]', net)
        addr = unroll(network, netmask, af)
    elif host:
        addr = [host]
    return addr


def _parse_ports(peq, pstart, pend):
    port = None
    if peq:
        port = int(peq), int(peq)
    elif pstart and pend:
        port = int(pstart), int(pend)
    return port


def _parse_icmp_opts(itype, icode):
    if itype in policy.Term.ICMP_TYPE[4].keys():
        icmp_type = [itype]
    elif int(itype) in policy.Term.ICMP_TYPE[4].values():
        for k, v in policy.Term.ICMP_TYPE[4].items():
            if v == int(itype):
                icmp_type = [k]
    else:
        # return None, since this is clearly a malformed ICMP term
        return None
    if icode:
        try:
            icmp_code = [policy.Term.ICMP_CODE[icode]]
        except KeyError:
            icmp_code = [int(icode)]
    else:
        icmp_code = None
    return icmp_type, icmp_code


def _parse_proto(proto, af):
    if af == 6 and proto == 'ipv6':
        protocol = None
    elif proto in aclgenerator.Term.PROTO_MAP.keys():
        protocol = proto
    elif (proto.isdigit() and int(proto) in aclgenerator.Term.PROTO_MAP.values()):
        for k, v in aclgenerator.Term.PROTO_MAP.items():
            if v == int(proto):
                protocol = k
    else:
        return None
    return protocol


def _parse_line(line_data, af):
    m = line_data.groupdict()
    action = src = dst = protocol = sport = dport = None
    icmp_type = icmp_code = options = logging = None
    if m['action'] in _ACTION_TABLE.keys():
        action = _ACTION_TABLE[m['action']]

    protocol = _parse_proto(m['protocol'], af)

    if m['icmp_type']:
        icmp_type, icmp_code = _parse_icmp_opts(m['icmp_type'], m['icmp_code'])

    src = _parse_nets(m['src_any'], m['src_net'], m['src_host'], af)
    dst = _parse_nets(m['dst_any'], m['dst_net'], m['dst_host'], af)

    sport = _parse_ports(m['sport_eq'], m['sport_start'], m['sport_end'])
    dport = _parse_ports(m['dport_eq'], m['dport_start'], m['dport_end'])

    if m['estab'] == 'established':
        options = ['tcp-established']

    if m['log'] == 'log':
        logging = True

    return action, af, protocol, src, dst, sport, dport, icmp_type, icmp_code, options, logging


def create_terms_from_line(line):
    term_list, unparsed_list = [], []
    match = None
    if re.match(IPV4_ACL_REGEX, line):
        match = re.search(IPV4_ACL_REGEX, line)
        af = 4
    elif re.match(IPV6_ACL_REGEX, line):
        match = re.search(IPV6_ACL_REGEX, line)
        af = 6
    if match:
        action, af, protocol, src, dst, sport, dport, icmp_type, icmp_code, options, logging = _parse_line(match, af)
        term_list.extend(create_multi_term(action, af, protocol, src, dst, sport, dport, icmp_type,
                                           icmp_code, options, logging, name=line))
    elif (not re.match(BLANK_LINE, line) and
          not re.match(REMARK_LINE, line) and
          not re.match(CFG_LINE, line)):
        unparsed_list.append(line)
    return term_list, unparsed_list


def find_duplicates(args):
    match_list = []
    line_dict, term_dict, unparsed_list = get_line_terms_dict(load_rules(args.find_duplicates[0]))
    for index, terms in term_dict.items():
        for p_idx in [i for i in sorted(term_dict.keys(), reverse=True) if i < index]:
            matched = False
            for term in terms:
                if compare_terms([term], term_dict[p_idx], strict_action=False):
                    match_list.append({'shaded': line_dict[index].strip(),
                                       'shaded_line_num': index,
                                       'cover': line_dict[p_idx].strip(),
                                       'cover_line_num': p_idx})
                    matched = True
                    break
                if matched:
                    break
    if args.print_terms and len(match_list) > 0:
        print(json.dumps(match_list, indent=4, sort_keys=True))
    print('{0} access control entries/terms in {1}\n'
          '{2} duplicate entries/terms.'
          .format(len(term_dict.keys()),
                  args.find_duplicates[0],
                  len(match_list)))


def compare(args):
    unmatched_a, termlen_a, unparsed_a = compare_acls(args.compare[0], args.compare[1])
    unmatched_b, termlen_b, unparsed_b = compare_acls(args.compare[1], args.compare[0])
    if args.print_terms and (len(unmatched_a) > 0 or
                             len(unmatched_b) > 0 or
                             len(unparsed_a) > 0 or
                             len(unparsed_b) > 0):
        print(json.dumps({args.compare[0]: {'num_terms': termlen_a,
                                            'unique': unmatched_a,
                                            'unparsed': unparsed_a},
                          args.compare[1]: {'num_terms': termlen_b,
                                            'unique': unmatched_b,
                                            'unparsed': unparsed_b}}, indent=4, sort_keys=True))
    if (len(unmatched_a) > 0 or len(unmatched_b) > 0):
        print('{0} entries/terms from {1} did not match.\n'
              '{2} entries/terms from {3} did not match.'
              .format(len(unmatched_a), args.compare[0],
                      len(unmatched_b), args.compare[1]))


def _convert_addr_any(a, b):
    if a == 'any' and isinstance(nacaddr.IP(b), nacaddr.IPv6):
        a = '0::/0'
    elif a == 'any':
        a = '0.0.0.0/0'
    else:
        a = nacaddr.IP(a)
    return a


def _check_addr_fam(a, b, af=4):
    a = _convert_addr_any(a, b)
    b = _convert_addr_any(b, a)

    if (isinstance(a, nacaddr.IPv6) or isinstance(b, nacaddr.IPv6)):
        a_af, b_af = 6, 6
    elif af:
        a_af, b_af = af, af
    return a, b, a_af, b_af


def _get_addr_obj_af(source, destination):
    src, dst, src_af, dst_af = _check_addr_fam(source, destination)

    try:
        assert(src_af == dst_af)
    except AssertionError:
        print(src_af, dst_af, source, destination)
        print('Something went wrong - address families did not match!')
    af = dst_af if dst_af else src_af
    return src, dst, af


def find_term(args):
    acl_file = args.find_term[0]

    src = dst = protocol = sport = dport = None
    icmp_type = icmp_code = options = logging = line = None

    src, dst, af = _get_addr_obj_af(args.find_term[1], args.find_term[2])

    if args.find_term[3] == 'ipv6' and af != 6:
        print('Something went wrong - address families did not match specified protocol!')
        sys.exit(1)
    if args.find_term[3] in aclgenerator.Term.PROTO_MAP.keys():
        protocol = args.find_term[3]
    if protocol == 1:
        sport = dport = None
        if args.find_term[4]:
            icmp_type = int(args.find_term[4])
        if len(args.find_term) == 6:
            icmp_code = int(args.find_term[5])
    elif len(args.find_term) > 4:
        if args.find_term[4] == 'any':
            dport = None
        else:
            dport = int(args.find_term[4]), int(args.find_term[4])

    search_term = create_multi_term('accept', af, [protocol], [str(src)], [str(dst)], sport, dport,
                                    icmp_type, icmp_code, options, logging, line)
    matches = check_access(search_term, acl_file)
    if len(matches) > 0:
        for k, v in sorted(matches.items()):
            sys.stdout.write('Found match: {0}, line {1}: {2}\n'
                             .format(acl_file, k, v))
    sys.exit('{0} matches found.'.format(str(len(matches))))


def main(args):
    if args.find_term:
        find_term(args)
    elif args.find_duplicates:
        find_duplicates(args)
    elif args.compare:
        compare(args)
    else:
        _parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    # main screen turn on
    import argparse

    class SplitArgsList(argparse.Action):
        def __init__(self, option_strings, dest, nargs=None, **kwargs):
            super(SplitArgsList, self).__init__(option_strings, dest, **kwargs)

        def __call__(self, parser, namespace, values, option_string=None):
            setattr(namespace, self.dest, values.split(' '))

    _parser = argparse.ArgumentParser(description='Cisco IOS/NXOS ACL checker/differ.')

    _parser.add_argument('--quiet', help='Suppress printing to stdout, only return exit code.',
                         dest='quiet', action='store_true')

    _parser.add_argument('--find-access', help='Check an ACL file for a specific set of access.',
                         dest='find_term', nargs=5,
                         metavar=('<acl_file>', '<src_ip>', '<dst_ip>', '<protocol>', '<dport>'))

    _parser.add_argument('--find-duplicates', help='Find duplicated terms within an ACL file.',
                         dest='find_duplicates', nargs=1, metavar='<acl_file>')

    _parser.add_argument('--compare', help='Compare access control entries between two Cisco IOS/NXOS ACLs.',
                         dest='compare', nargs=2, metavar=('<acl_file1>', '<acl_file2>'))

    _parser.add_argument('--print-terms', help=('Used with --compare/--find-duplicates; print a list of either '
                         'unmatched or duplicate terms.'), dest='print_terms', action='store_true')

    args = _parser.parse_args()

    main(args)
