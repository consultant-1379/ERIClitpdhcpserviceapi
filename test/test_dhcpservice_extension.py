##############################################################################
# COPYRIGHT Ericsson AB 2014
#
# The copyright to the computer program(s) herein is the property of
# Ericsson AB. The programs may be used and/or copied only with written
# permission from Ericsson AB. or in accordance with the terms and
# conditions stipulated in the agreement/contract under which the
# program(s) have been supplied.
##############################################################################


import unittest
import re
from litp.core.validators import ValidationError, ItemValidator
from dhcpservice_extension.dhcpserviceextension \
                            import DhcpserviceExtension, IPRangeOrderValidator, \
                            NameserversValidator, TimeserversValidator, MaxLengthValidator,\
                            MaxCountValidator, DhcpServiceValidator, DomainsearchValidator


class TestDhcpserviceExtension(unittest.TestCase):

    def setUp(self):
        self.ext = DhcpserviceExtension()
        self.validator = IPRangeOrderValidator()
        self.nsvalidator = NameserversValidator()
        self.dsvalidator = DomainsearchValidator()

        self.ntpvalidator = TimeserversValidator()
        self.ntp_regex = re.compile(DhcpserviceExtension.ntp_regex())

    def test_item_types_registered(self):
        item_types_expected = ['dhcp-service', 'dhcp-subnet', 'dhcp-range',
                               'dhcp6-service', 'dhcp6-subnet', 'dhcp6-range']
        item_types = [it.item_type_id for it in
                      self.ext.define_item_types()]
        self.assertEquals(item_types_expected, item_types)

    def test_ip_range_order_validator(self):
        properties = {'start': '10.0.0.5',
                      'end': '10.0.0.4'}

        msg = 'Invalid IP range: "end" IP address ' + \
              'must be greater than or equal to "start" IP address. '

        expected_error = ValidationError(property_name='end',
                                         error_message=msg)

        error = self.validator.validate(properties)
        self.assertEquals(expected_error, error)

        # --- a range of one is allowed (LITPCDS-8770)

        properties['end'] = properties['start']
        error = self.validator.validate(properties)
        self.assertEquals(None, error)

        # ---

        properties['end'] = '10.0.0.6'
        error = self.validator.validate(properties)
        self.assertEquals(None, error)

        # ---

        properties = {'start': '::192.168.0.10',
                      'end': '::192.168.0.5'}

        error = self.validator.validate(properties)
        self.assertEquals(expected_error, error)

        # --- a range of one is allowed IPv6

        properties['end'] = properties['start']
        error = self.validator.validate(properties)
        self.assertEquals(None, error)

        # ---

        properties['end'] = '::192.168.0.11'
        error = self.validator.validate(properties)
        self.assertEquals(None, error)

        # ---
        properties = {'start': 'fc01::10/64',
                      'end': 'fc01::20'}

        msg = ('Invalid IP range: "start" and "end" IP address '
               'must not contain a prefix. ')
        expected_error = ValidationError(property_name='end',
                                         error_message=msg)

        error = self.validator.validate(properties)
        self.assertEquals(expected_error, error)

        # ---
        properties = {'start': 'fc01::10',
                      'end': 'fc01::20/64'}

        expected_error = ValidationError(property_name='end',
                                         error_message=msg)

        error = self.validator.validate(properties)
        self.assertEquals(expected_error, error)

    def test_regex(self):
        regex = re.compile(r"^([0-9.]+[,]?)+$")
        find = re.match(regex, ',10.11.11.13')
        self.assertEquals(find, None)

        find = re.match(regex, '10.11.11.13, 10.11.32.14')
        self.assertEquals(find, None)

    def test_nameservers_validation(self):
        ip = "10.10.10.10"
        nameservers = '%s,%s' % (ip, ip)

        msg = 'Duplicate IP address(es) detected: "%s"' % ip

        expected_error = ValidationError(property_name='nameservers',
                                         error_message=msg)

        error = self.nsvalidator.validate(nameservers)

        self.assertEquals(expected_error, error)


    def test_domainsearch_validation(self):

        url = 'foo.com'
        domainseach = '%s,%s' % (url, url)

        msg = 'Duplicate domainsearch values detected: "%s"' % url

        expected_error = ValidationError(property_name='domainsearch',
                                         error_message=msg)

        error = self.dsvalidator.validate(domainseach)

        self.assertEquals(expected_error, error)

        domainseach = '%s,bar.com' % url

        expected_error = None

        error = self.dsvalidator.validate(domainseach)

        self.assertEquals(expected_error, None)

    def test_ntpservers_regex_validIPv4(self):
        for ntp_string in ['192.168.0.1,192.168.0.2', '10.0.0.1']:
            self.assertNotEquals(None,
                                 re.match(self.ntp_regex, ntp_string))

    def test_ntpservers_regex_validFQDN(self):
        for ntp_string in ['ntp-1.xxx.com', 'ntp-1.xxx.com,ntp-2.xxx.com']:
            self.assertNotEquals(None,
                                 re.match(self.ntp_regex, ntp_string))

    def test_ntpservers_regex_validStrictFQDN(self):
        for ntp_string in ['ntp-1.xxx.com.', 'ntp-1.xxx.com.,ntp-2.xxx.com.']:
            self.assertNotEquals(None,
                                 re.match(self.ntp_regex, ntp_string))

    def test_ntpservers_regex_validHost(self):
        for ntp_string in ['ntp-1', 'ntp-1,ntp-2']:
            self.assertNotEquals(None,
                                 re.match(self.ntp_regex, ntp_string))

    def test_ntpservers_regex_underscores(self):
        ntp_string = 'ntp-1.a_m_m_.com'
        self.assertEquals(None,
                          re.match(self.ntp_regex, ntp_string))

        ntp_string = 'ntp_1'
        self.assertNotEquals(None,
                             re.match(self.ntp_regex, ntp_string))

    def test_ntpservers_regex_trailingcomma(self):
        for ntp_string in ['ntp-1,', 'ntp-1.xxx.com,']:
            self.assertEquals(None,
                              re.match(self.ntp_regex, ntp_string))

    def test_ntpservers_regex_trailingdot(self):
        # Hostname on its own is not a FQDN..

        ntp_string = 'ntp-1.'
        self.assertEquals(None,
                          re.match(self.ntp_regex, ntp_string))

        ntp_string = 'ntp-1.xxx.com.'
        self.assertNotEquals(None,
                             re.match(self.ntp_regex, ntp_string))

    def _ntp_validator_error(self, ntp_string, error_msg):
        self.assertEquals(ValidationError(property_name='ntpservers',
                                          error_message=error_msg),
                          self.ntpvalidator.validate(ntp_string))

    def _ntp_validator_no_error(self, ntp_string):
        self.assertEquals(None,
                          self.ntpvalidator.validate(ntp_string))

    def test_ntpservers_validation_duplicates(self):
        ntp_string = 'ntp-1,ntp-1'
        error_message = 'Duplicate NTP server address(es) detected "ntp-1". '
        self._ntp_validator_error(ntp_string, error_message)

    def test_ntpservers_validation_underscores(self):
        ntp_string = 'ntp_1.amm.com'
        error_message = 'Hostname in "ntp_1.amm.com" cannot contain underscores. '
        self._ntp_validator_error(ntp_string, error_message)

        ntp_string = 'ntp_1'
        self._ntp_validator_no_error(ntp_string)

    def test_ntpservers_validation_fqdn_with_numeric_octets(self):
        ntp_string = '1.ntp.net'
        self._ntp_validator_no_error(ntp_string)

        # This particular case is ISC DHCPD choking on a valid FQDN. It
        # assumes that if the first two nibbles are all-numeric, it is
        # dealing with a dotted IP address.
        ntp_string = '1.888.com'
        error_message = 'NTP address "{0}" is not valid.'.format(ntp_string)
        self._ntp_validator_error(ntp_string, error_message)

    def test_ntpservers_validation_no_numeric_hostnames_on_own(self):
        ntp_string = '32'
        error_message = 'NTP address "{0}" is not valid.'.format(ntp_string)
        self._ntp_validator_error(ntp_string, error_message)

    def test_ntpservers_validation_ips_with_255(self):
        for ntp_string in ['255.255.255.255', '0.0.255.0']:
            error_message = 'NTP address "{0}" is not valid.'.format(ntp_string)
            self._ntp_validator_error(ntp_string, error_message)

    def test_ntpservers_validation_numbered_ips(self):
        for ntp_string in ['10.10.10.1', '1.1.1.1']:
            self.assertEqual(None,
                             self.ntpvalidator.validate(ntp_string))

        ntp_string = '1.1.1'
        self.assertEqual(ValidationError(property_name='ntpservers',
                                         error_message='NTP address "{0}" is not valid.'.format(ntp_string)),
                         self.ntpvalidator.validate(ntp_string))

    def test_max_length_items(self):
        validator = DomainsearchValidator()
        error = validator.validate("property_value_string_more_than_12 " * 9)
        ref_errors = ValidationError(property_name='domainsearch',
                                     error_message = ('The value of the "domainsearch"'
                                                      ' property cannot exceed 256 characters. '))

        self.assertEquals(error,ref_errors)

        correct = validator.validate("less_than_12")
        self.assertEquals(correct, None)

    def test_max_count_items(self):
        validator = DomainsearchValidator()
        error_max = validator.validate("test1.com,test2.com,test3.com,test4.com,test5.com,test6.com,test7.com")
        ref_errors_max = ValidationError(property_name='domainsearch',
                                         error_message = ('A maximum of 6 values for the "domainsearch"'
                                                          ' property can be specified. '))
        self.assertEquals(error_max,ref_errors_max)

        correct = validator.validate("test1.com,test2.com,test3.com")

        self.assertEquals(correct,None)


        validator = NameserversValidator()
        error_max = validator.validate("10.10.11.12,10.10.11.13,10.10.11.14,10.10.11.15")
        ref_errors_max = ValidationError(property_name='nameservers',
                                         error_message = ('A maximum of 3 values for the "nameservers"'
                                                          ' property can be specified. '))
        self.assertEquals(error_max,ref_errors_max)

        correct = validator.validate("10.10.11.13")

        self.assertEquals(correct,None)

    def test_domainsearch_regex(self):
        regex = re.compile(r"^(([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+"
                           r"[a-zA-Z]{2,})(,([a-zA-Z0-9]+"
                           r"(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}){0,}$")

        valid_values = ['a.co', 'a-a-a.com', 'Foo.com', 'foo.com',
                        'foo.bar.com', 'foo-dig.bar.com',
                        'foo.com,bar.com,zoo.com',
                        'www.google.com,www.boogle.com,www.foogle.com',
                        'ekar.mur-info.com,ekar.m-urinfo.com,ekar.murinf-o.com'
                        ]
        invalid_values = ['murphy.k.', '.123', '.com', '-mur.com', 'mur-.com',
                         'sub.-mur.com', 'sub.mur-.com']

        for v in valid_values:
            find = re.match(regex, v)
            self.assertTrue(find is not None)

        for v in invalid_values:
            find = re.match(regex, v)
            self.assertTrue(find is None)

    def test_ipv4_regex(self):
        regex=re.compile(r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\."
                         r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
                         r"(25[0-5]|2[0-4]\d|[01]?\d\d?)\."
                         r"(25[0-5]|2[0-4]\d|[01]?\d\d?)[,]?)+$")

        valid_values = ['0.0.0.0', '255.255.255.255', '1.1.1.1,']

        for v in valid_values:
            find = re.match(regex, v)
            self.assertTrue(find is not None)

        invalid_values = ['256.255.255.255', ',1.1.1.1',' 1.1.1.1',]

        for v in invalid_values:
            find = re.match(regex, v)
            self.assertTrue(find is None)

    def test_dhcp_service_validator(self):
        d = DhcpServiceValidator()
        error = d.validate({'ntpservers': '1.1.1.1',
                            'nameservers': '10.10.10.10',
                            'domainsearch': 'foo.com'})
        self.assertEquals(error, None)

        error = d.validate({'domainsearch': 'foo.com',
                            'ntpservers': '10.10.10.10'})
        msg = ('The property "nameservers" must be specified if'
               ' a "domainsearch" value is provided. ')

        missing_prop_error = ValidationError(property_name='nameservers',
                                             error_message = msg)
        self.assertEquals(error, missing_prop_error)


if __name__ == '__main__':
    unittest.main()
