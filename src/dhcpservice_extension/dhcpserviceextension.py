##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################

from netaddr import IPAddress, AddrFormatError

from litp.core.model_type import ItemType, Property, PropertyType,\
Collection
from litp.core.validators import IsNotDigitValidator
from litp.core.extension import ModelExtension
from litp.core.validators import ItemValidator, PropertyValidator, \
ValidationError
import re


class DhcpserviceExtension(ModelExtension):
    '''
    DHCP Service Model Extension allows for
    the configuration of DHCP IPv4 and IPv6
    services on the peer nodes.
    '''

    @staticmethod
    def ntp_regex():
        _alias_regex = r"([a-zA-Z0-9_]([a-zA-Z0-9\-_]*[a-zA-Z0-9_])*)"
        _hostname_regex = r"([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])*)"
        _fqdnaddr_regex = r"({alias}((\.{host})+(\.?))?)".format(
                    alias=_alias_regex, host=_hostname_regex)

        return r"^{0}(,{0})*$".format(_fqdnaddr_regex)

    def define_property_types(self):

        property_types = []

        property_types.append(PropertyType("nameservers",
            regex=r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\."
                  r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
                  r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
                  r"(25[0-5]|2[0-4]\d|[01]?\d\d?)[,]?)+$",
            regex_error_desc=('"nameservers" must be a IPv4 address or a '
                              'comma-separated list of valid IPv4 addresses.'),
            validators=[NameserversValidator()])
        )

        property_types.append(PropertyType("domainsearch",
            regex=r"^(([a-zA-Z\d]+(-[a-zA-Z\d]+)*\.)+"
                  r"[a-zA-Z]{2,})(,([a-zA-Z\d]+"
                  r"(-[a-zA-Z\d]+)*\.)+[a-zA-Z]{2,}){0,}$",
            regex_error_desc=('"domainsearch" must be a domain name or a '
                              'comma-separated list of valid domain names.'),
            validators=[IsNotDigitValidator(),
                        DomainsearchValidator()])
        )

        property_types.append(PropertyType("ntpservers",
            regex=self.ntp_regex(),
            regex_error_desc=('"ntpserver" must be a FQDN or a '
                              'comma-separated list of valid FQDNs.'),
            validators=[TimeserversValidator()])
        )

        return property_types

    def define_item_types(self):

        desc_all = 'Update and remove reconfiguration actions ' + \
                   'are currently supported for this item type.'

        desc_update = 'Update reconfiguration ' + \
                      'actions are currently supported for this item type.'

        svc_name_prop = Property('basic_string',
                             prop_description='The name of the DHCP service.',
                             required=True)
        primary_prop = Property('basic_boolean',
                           prop_description='This property signals which ' + \
                                            'is the primary or the ' + \
                                            'secondary server where there ' + \
                                            'is a pair of dhcp peer servers.',
                           required=True,
                           updatable_plugin=True,
                           default='true')

        it1 = ItemType('dhcp-service',
                       item_description='A DHCP service. ' + desc_all,
                       extend_item='service-base',
                       service_name=svc_name_prop,
                       primary=primary_prop,
                       subnets=Collection('dhcp-subnet', min_count=1),
                       ntpservers=Property('ntpservers',
                                    site_specific=True,
                                    prop_description=('A comma-separated list'
                                                      ' of NTP servers.'),
                                    required=False),
                       nameservers=Property('nameservers',
                                    site_specific=True,
                                    prop_description=('A comma-separated list'
                                                      ' of name servers.'),
                                    required=False),
                       domainsearch=Property('domainsearch',
                                    site_specific=True,
                                    prop_description=('A comma-separated list'
                                                      ' of domain names.'),
                                    required=False),
                       validators=[DhcpServiceValidator()]
        )
        it2 = ItemType('dhcp-subnet',
                       item_description='This item type represents'
                             ' a DHCP subnet. ' + desc_update,
                       network_name=Property('basic_string',
                        prop_description='The name of the network'
                                         ' referenced by the subnet.',
                        required=True),
                       ranges=Collection('dhcp-range',
                                         min_count=1)
        )
        it3 = ItemType('dhcp-range',
                       item_description='This item type represents'
                             ' a DHCP subnet range. ' + desc_update,
                       start=Property('ipv4_address',
                                      site_specific=True,
                                      prop_description='The start of'
                                                       ' the range.',
                                      required=True),
                       end=Property('ipv4_address',
                                    site_specific=True,
                                    prop_description='The end of'
                                                     ' the range.',
                                    required=True),
                       validators=[IPRangeOrderValidator()]
        )
        it4 = ItemType('dhcp6-service',
                       item_description='A DHCPv6 service. ' + desc_all,
                       extend_item='service-base',
                       service_name=svc_name_prop,
                       primary=primary_prop,
                       subnets=Collection('dhcp6-subnet',
                                          min_count=1)
        )
        it5 = ItemType('dhcp6-subnet',
                       item_description='This item type represents'
                             ' an IPv6 DHCP subnet. ' + desc_update,
                       network_name=Property('basic_string',
                        prop_description='The name of the network'
                                         ' referenced by the subnet.',
                        required=True),
                       ranges=Collection('dhcp6-range',
                                         min_count=1)
        )
        it6 = ItemType('dhcp6-range',
                       item_description='This item type represents'
                             ' an IPv6 DHCP subnet range. ' + desc_update,
                       start=Property('ipv6_address',
                                      site_specific=True,
                                      prop_description='The start of'
                                                       ' the range.',
                                      required=True),
                       end=Property('ipv6_address',
                                    site_specific=True,
                                    prop_description='The end of'
                                                     ' the range.',
                                    required=True),
                       validators=[IPRangeOrderValidator()]
        )
        return [it1, it2, it3, it4, it5, it6]


class IPRangeOrderValidator(ItemValidator):
    '''
    Validates that the ``start`` property is numerically
    before or equal to the ``end`` property. Any errors are reported
    on the ``end`` property.
    '''

    def validate(self, properties):
        msgs = []

        start_ip_str = properties.get('start')
        end_ip_str = properties.get('end')

        if '/' in end_ip_str or '/' in start_ip_str:
            msgs.append('Invalid IP range: "start" and "end" '
                        'IP address must not contain a prefix. ')
        else:
            if IPAddress(start_ip_str) > IPAddress(end_ip_str):
                msgs.append('Invalid IP range: "end" IP address must be '
                      'greater than or equal to "start" IP address. ')

        emsgs = ' '.join([m for m in msgs if m])

        if emsgs:
            return ValidationError(
                property_name="end",
                error_message=emsgs)


class DhcpServiceValidator(ItemValidator):
    '''
    Validates that if the ``domainsearch`` property is present
    then the ``nameservers`` property should be present too.
    '''

    def validate(self, properties):
        domainsearch = properties.get('domainsearch')
        nameservers = properties.get('nameservers')

        if domainsearch:
            if not nameservers:
                msg = ('The property "nameservers" must be specified'
                      ' if a "domainsearch" value is provided. ')
                return ValidationError(property_name='nameservers',
                                       error_message=msg)


class NameserversValidator(PropertyValidator):

    """
    Validates that the "nameservers" property value
    is a comma-separated list of unique and valid IPv4 addresses
    or a single valid IPv4 address.
    """

    def validate(self, property_value):

        msgs = []

        if property_value:

            stripped_ips = [x.strip() for x in property_value.split(',')]

            duplicates = DhcpHelper.get_duplicates(stripped_ips)

            if duplicates:
                msgs.append(DhcpHelper.get_error_msg_for_duplicated_ips
                                                                (duplicates))

            validator = MaxCountValidator(0, 3, ',', 'nameservers')

            exceeds_max_count = validator.validate(property_value)

            if exceeds_max_count:
                msgs.append(validator.get_error_msg_for_maxcount_exceeded())

        emsgs = ' '.join([m for m in msgs if m])

        if emsgs:
            return ValidationError(
                property_name="nameservers",
                error_message=emsgs)


class DomainsearchValidator(PropertyValidator):

    """
    Validates that the "domainsearch" property value
    is a comma-separated list of unique and valid domain names
    or a single valid domain name.
    """

    def validate(self, property_value):

        msgs = []

        if property_value:

            stripped_domains = [x.strip() for x in property_value.split(',')]

            duplicates = DhcpHelper.get_duplicates(stripped_domains)

            if duplicates:
                msgs.append(DhcpHelper.\
                         get_error_msg_for_duplicated_domainsearch(duplicates))

            validator = MaxCountValidator(0, 6, ',', 'domainsearch')

            exceeds_max_count = validator.validate(property_value)

            if exceeds_max_count:
                msgs.append(validator.get_error_msg_for_maxcount_exceeded())

            validator = MaxLengthValidator(256, 'domainsearch')

            exceeds_max_length = validator.validate(property_value)

            if exceeds_max_length:
                msgs.append(validator.get_error_msg_for_maxlength_exceeded())

        emsgs = ' '.join([m for m in msgs if m])

        if emsgs:
            return ValidationError(
                property_name="domainsearch",
                error_message=emsgs)


class TimeserversValidator(PropertyValidator):

    """
    Validates that the "ntpservers" property value
    is a comma-separated list of unique and valid IPv4 addresses
    or FQDNs or a single unique and valid IPv4 address or FQDN.
    """

    def validate(self, property_value):

        msgs = []

        if property_value:
            stripped_ips = [x.strip() for x in property_value.split(',')
                                                   if x and not x.isspace()]
            for ip_str in stripped_ips:
                nibbles = ip_str.split('.')

                if len(nibbles) > 1 and '_' in nibbles[0]:
                    msgs.append('Hostname in "{host}" cannot contain'\
                    ' underscores. '.format(host=ip_str))

                # Number-only hostnames disallowed
                if len(nibbles) == 1 and nibbles[0].isdigit():
                    msgs.append(DhcpHelper.get_error_msg_for_bad_ntp(ip_str))

                # If first two domain labels are numbers, DHCPD assumes
                # the whole lot is a dotted IP address.
                if len(nibbles) >= 2 \
                    and nibbles[0].isdigit() and nibbles[1].isdigit():
                    try:
                        # LITP does not allow abbreviated IPv4 addresses
                        # (e.g 12.24 which expands to 12.0.0.24)
                        if len(nibbles) != 4 or \
                            255 in [int(octet) for octet in nibbles]:
                            raise AddrFormatError()
                        IPAddress(ip_str)
                    except AddrFormatError:
                        msgs.append(DhcpHelper.get_error_msg_for_bad_ntp
                                                                   (ip_str))

            duplicates = DhcpHelper.get_duplicates(stripped_ips)

            if duplicates:
                msgs.append(DhcpHelper.get_error_msg_for_duplicated_ntp(
                                                                 duplicates))

        emsgs = ' '.join([m for m in msgs if m])

        if emsgs:
            return ValidationError(
                property_name="ntpservers",
                error_message=emsgs)


class DhcpHelper(object):
    """
    Defines generic methods for Dhcpservice extension
    """

    @staticmethod
    def value_matches_pattern(value_to_test, pattern):

        regexp = re.compile(pattern)

        pattern_match = re.match(regexp, value_to_test)

        if not pattern_match:
            return False
        return True

    @staticmethod
    def get_duplicates(values_to_test):
        """
        check if there are duplicated values in a list
        @values_to_test: list, values to test
        @return: set, values that are duplicated
        """
        return set([item for item in values_to_test if
                           values_to_test.count(item) > 1])

    @staticmethod
    def get_error_msg_for_duplicated_ips(duplicates):
        return 'Duplicate IP address(es) detected: %s' % ', '.join([
            '"' + ip + '"' for ip in duplicates])

    @staticmethod
    def get_error_msg_for_duplicated_domainsearch(duplicates):
        return 'Duplicate domainsearch values detected: %s' % ', '.join([
            '"' + ds + '"' for ds in duplicates])

    @staticmethod
    def get_error_msg_for_ntpservers_format():
        return (
            'The value should be a Hostname, Alias, FQDN, a IPv4 address,'
            ' or a comma separated list of these with no spaces.'
            )

    @staticmethod
    def get_error_msg_for_duplicated_ntp(duplicates):
        return 'Duplicate NTP server address(es) detected %s. ' % ', '.join([
            '"' + ip + '"' for ip in duplicates])

    @staticmethod
    def get_error_msg_for_bad_ntp(ip_str):
        return 'NTP address "{0}" is not valid.'.format(ip_str)


class MaxLengthValidator(object):
    """
    Validates that the property value's character count does
    not exceed the max_length value specified.
    """

    def __init__(self, max_length, prop_name):
        """
        MaxLengthValidator with property names.

        We assume that the property names correspond to Property objects that
        are required.

        :param  max_length: max length
        :type   max_length: int

        :param  prop_name: property name
        :type   prop_name: string
        """

        self.max_length = max_length
        self.prop_name = prop_name

    def validate(self, property_value, ):
        return len(property_value) > self.max_length

    def get_error_msg_for_maxlength_exceeded(self):
        return ('The value of the "%s" property'
                ' cannot exceed %s characters. '
                % (self.prop_name, self.max_length))


class MaxCountValidator(object):
    """
    Validates that a property has not less than
    the min element count and not greater than
    the max element count split by the delimiter.
    """

    def __init__(self, min_count, max_count, delimiter, prop_name):
        """
        MaxCountValidator with property names.

        :param  min_count: min count
        :type   min_count: int

        :param  max_count: max count
        :type   max_count: int

        :param  delimiter: element delimiter
        :type   delimiter: string

        :param  delimiter: property name
        :type   delimiter: string
        """

        self.max_count = max_count
        self.min_count = min_count

        self.delimiter = delimiter
        self.property = prop_name

    def validate(self, property_value):

        if property_value:
            values_to_test = property_value.split(self.delimiter)

            return (len(values_to_test) < self.min_count
                      or len(values_to_test) > self.max_count)

    def get_error_msg_for_maxcount_exceeded(self):
        return ('A maximum of %s values for the "%s"'
                ' property can be specified. '
                % (self.max_count, self.property))
