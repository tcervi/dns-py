import unittest
from dnslib import CLASS, QTYPE, A, AAAA, CNAME, TXT
from server import validate_domain_class, validate_domain_type, \
    validate_domain_data, validate_new_domain, get_data_by_type


class DomainClassTestCase(unittest.TestCase):

    def test_class_in(self):
        result = validate_domain_class(CLASS[1])
        self.assertEqual(result, CLASS[1])

    def test_class_cs(self):
        result = validate_domain_class(CLASS[2])
        self.assertEqual(result, CLASS[2])

    def test_class_ch(self):
        result = validate_domain_class(CLASS[3])
        self.assertEqual(result, CLASS[3])

    def test_class_hesiod(self):
        result = validate_domain_class(CLASS[4])
        self.assertEqual(result, CLASS[4])

    def test_class_none(self):
        result = validate_domain_class(CLASS[254])
        self.assertEqual(result, CLASS[254])

    def test_class_asterisk(self):
        result = validate_domain_class(CLASS[255])
        self.assertEqual(result, CLASS[255])

    def test_class_null(self):
        result = validate_domain_class(None)
        self.assertIsNone(result)

    def test_class_string(self):
        result = validate_domain_class("abcDEFgh")
        self.assertIsNone(result)

    def test_class_integer(self):
        result = validate_domain_class(1345)
        self.assertIsNone(result)


class DomainTypeTestCase(unittest.TestCase):

    def test_type_a(self):
        result = validate_domain_type(QTYPE[1])
        self.assertEqual(result, QTYPE[1])

    def test_type_cname(self):
        result = validate_domain_type(QTYPE[5])
        self.assertEqual(result, QTYPE[5])

    def test_type_txt(self):
        result = validate_domain_type(QTYPE[16])
        self.assertEqual(result, QTYPE[16])

    def test_type_aaaa(self):
        result = validate_domain_type(QTYPE[28])
        self.assertEqual(result, QTYPE[28])

    def test_type_valid_others(self):
        not_handled_types = [2, 6, 12, 13, 15, 17, 18, 24, 25, 29, 33, 35, 36, 37, 38, 39, 41, 42, 43, 44,
                             45, 46, 47, 48, 49, 50, 51, 52, 55, 59, 60, 61, 99, 249, 250, 251, 252, 255,
                             256, 257, 32768, 32769]

        for qtype in not_handled_types:
            result = validate_domain_type(qtype)
            self.assertIsNone(result)

    def test_type_null(self):
        result = validate_domain_type(None)
        self.assertIsNone(result)

    def test_type_string(self):
        result = validate_domain_type("abcDEFgh")
        self.assertIsNone(result)

    def test_type_integer(self):
        result = validate_domain_type(1345)
        self.assertIsNone(result)


class DomainDataTestCase(unittest.TestCase):

    def test_valid_a(self):
        list_ipv4_valid = ["127.0.0.1", "192.168.1.1", "192.168.1.255", "255.255.255.255", "0.0.0.0", "1.1.1.1"]
        for data in list_ipv4_valid:
            result = validate_domain_data(QTYPE[1], data)
            self.assertEqual(result, data)

    def test_invalid_a(self):
        list_ipv4_invalid = ["30.168.1.255.1", "127.1",
                             "192.168.1.256", "-1.2.3.4", "3...3", "http://30.168.1.255.1:80"]
        for data in list_ipv4_invalid:
            result = validate_domain_data(QTYPE[1], data)
            self.assertIsNone(result)

    def test_a_null(self):
        result = validate_domain_data(QTYPE[1], None)
        self.assertIsNone(result)

    def test_a_string(self):
        result = validate_domain_data(QTYPE[1], "abcDE%^$#!Fgh")
        self.assertIsNone(result)

    def test_a_integer(self):
        result = validate_domain_data(QTYPE[1], 1345)
        self.assertIsNone(result)

    def test_valid_aaaa(self):
        list_ipv6_valid = ["1200:0000:AB00:1234:0000:2552:7777:1313", "21DA:D3:0:2F3B:2AA:FF:FE28:9C5A",
                           "FE80:0000:0000:0000:0202:B3FF:FE1E:8329", "21DA:D3:0::9C5A"]
        for data in list_ipv6_valid:
            result = validate_domain_data(QTYPE[28], data)
            self.assertEqual(result, data)

    def test_invalid_aaaa(self):
        list_ipv6_invalid = ["1200:0000:AB00:1234:O000:2552:7777:1313 ", "[2001:db8:0:1]:80 ", "30.168.1.255.1",
                             "FE80:0000:0000:0^&0:0202:B3FF:FE1E:8329", "http://[2001:db8:0:1]:80",
                             "192.168.1.256", "-1.2.3.4", "3...3"]
        for data in list_ipv6_invalid:
            result = validate_domain_data(QTYPE[28], data)
            self.assertIsNone(result)

    def test_aaaa_null(self):
        result = validate_domain_data(QTYPE[28], None)
        self.assertIsNone(result)

    def test_aaaa_string(self):
        result = validate_domain_data(QTYPE[28], "abcDE%^$#!Fgh")
        self.assertIsNone(result)

    def test_aaaa_integer(self):
        result = validate_domain_data(QTYPE[28], 1345)
        self.assertIsNone(result)

    def test_valid_cname(self):
        list_cname_valid = ["www.google.com", "abc-test.net", "test123abc.com", "asasasas12334.sdadg.as12434-asas.net"]
        for data in list_cname_valid:
            result = validate_domain_data(QTYPE[5], data)
            self.assertEqual(result, data)

    def test_invalid_cname(self):
        list_cname_invalid = ["", "123test.com.br", "abc.com.b4", "abd@#$%^.com", "abc.com.n$"]
        for data in list_cname_invalid:
            result = validate_domain_data(QTYPE[5], data)
            self.assertIsNone(result)

    def test_cname_null(self):
        result = validate_domain_data(QTYPE[5], None)
        self.assertIsNone(result)

    def test_cname_string(self):
        result = validate_domain_data(QTYPE[5], "abcDE%^$#!Fgh")
        self.assertIsNone(result)

    def test_cname_integer(self):
        result = validate_domain_data(QTYPE[5], 1345)
        self.assertIsNone(result)

    def test_valid_txt(self):
        list_txt_valid = ["test=name.abcd", "name=als1243@#$%as.com", "abc=def"]
        for data in list_txt_valid:
            result = validate_domain_data(QTYPE[16], data)
            self.assertEqual(result, data)

    def test_invalid_txt(self):
        list_txt_invalid = ["", "list_txt_valid", "testname.abcd", "nameals1243@#$%as.com"]
        for data in list_txt_invalid:
            result = validate_domain_data(QTYPE[16], data)
            self.assertIsNone(result)

    def test_txt_null(self):
        result = validate_domain_data(QTYPE[16], None)
        self.assertIsNone(result)

    def test_txt_string(self):
        result = validate_domain_data(QTYPE[16], "abcDE%^$#!Fgh")
        self.assertIsNone(result)

    def test_cname_integer(self):
        result = validate_domain_data(QTYPE[16], 1345)
        self.assertIsNone(result)


class NewDomainTestCase(unittest.TestCase):

    def test_valid_domain(self):
        domain_dic = {'domain_name': "www.google.com", 'class': "IN",
                      'qtype': "A", 'data': "1.2.3.4", 'ttl': 3600}
        result = validate_new_domain(domain_dic['domain_name'] + " " + domain_dic['class'] + " " +
                                     domain_dic['qtype'] + " " + domain_dic['data'])
        self.assertEqual(result, domain_dic)

    def test_invalid_domain(self):
        domain_dic = {'domain_name': "www.google.com", 'class': "IN",
                      'qtype': "A", 'data': "1.2.3.4", 'ttl': 3600}

        result = validate_new_domain(" " + domain_dic['class'] + " " + domain_dic['qtype'] + " " + domain_dic['data'])
        self.assertIsNone(result)

        result = validate_new_domain(domain_dic['domain_name'] + " " + domain_dic['qtype'] + " " + domain_dic['data'])
        self.assertIsNone(result)

        result = validate_new_domain(domain_dic['domain_name'] + " " + domain_dic['class'] + " " + domain_dic['data'])
        self.assertIsNone(result)

        result = validate_new_domain(domain_dic['domain_name'] + " " + domain_dic['class'] + " " + domain_dic['qtype'])
        self.assertIsNone(result)

        result = validate_new_domain("Domain: " + domain_dic['domain_name'] + " " + domain_dic['class'] + " " +
                                     domain_dic['qtype'] + " " + domain_dic['data'])
        self.assertIsNone(result)

    def test_domain_null(self):
        result = validate_new_domain(None)
        self.assertIsNone(result)

    def test_domain_string(self):
        result = validate_new_domain("abcDE%^$#!Fgh")
        self.assertIsNone(result)

    def test_domain_integer(self):
        result = validate_new_domain(1345)
        self.assertIsNone(result)


class DataByTypeTestCase(unittest.TestCase):

    def test_valid_a_data(self):
        (result_type, result_data) = get_data_by_type(QTYPE[1], "1.2.3.4")
        self.assertEqual(result_type, 1)
        self.assertIsInstance(result_data, A)

    def test_invalid_a_data(self):
        result = get_data_by_type(QTYPE[1], "30.168.1.255.1")
        self.assertIsNone(result)

    def test_valid_cname_data(self):
        (result_type, result_data) = get_data_by_type(QTYPE[5], "www.google.com")
        self.assertEqual(result_type, 5)
        self.assertIsInstance(result_data, CNAME)

    def test_invalid_cname_data(self):
        result = get_data_by_type(QTYPE[5], "123test.com.br")
        self.assertIsNone(result)

    def test_valid_txt_data(self):
        (result_type, result_data) = get_data_by_type(QTYPE[16], "txtvers=1")
        self.assertEqual(result_type, 16)
        self.assertIsInstance(result_data, TXT)

    def test_invalid_txt_data(self):
        result = get_data_by_type(QTYPE[16], "txtvers^1")
        self.assertIsNone(result)

    def test_valid_aaaa_data(self):
        (result_type, result_data) = get_data_by_type(QTYPE[28], "21DA:D3:0::9C5A")
        self.assertEqual(result_type, 28)
        self.assertIsInstance(result_data, AAAA)

    def test_invalid_aaaa_data(self):
        result = get_data_by_type(QTYPE[28], "FE80:0000:0000:0^&0:0202:B3FF:FE1E:8329")
        self.assertIsNone(result)

    def test_a_with_cname_data(self):
        result = get_data_by_type(QTYPE[1], "www.google.com")
        self.assertIsNone(result)

    def test_a_with_txt_data(self):
        result = get_data_by_type(QTYPE[1], "txtvers=1")
        self.assertIsNone(result)

    def test_a_with_aaaa_data(self):
        result = get_data_by_type(QTYPE[1], "21DA:D3:0::9C5A")
        self.assertIsNone(result)

    def test_cname_with_a_data(self):
        result = get_data_by_type(QTYPE[5], "1.2.3.4")
        self.assertIsNone(result)

    def test_cname_with_txt_data(self):
        result = get_data_by_type(QTYPE[5], "txtvers=1")
        self.assertIsNone(result)

    def test_cname_with_aaaa_data(self):
        result = get_data_by_type(QTYPE[5], "21DA:D3:0::9C5A")
        self.assertIsNone(result)

    def test_txt_with_a_data(self):
        result = get_data_by_type(QTYPE[16], "1.2.3.4")
        self.assertIsNone(result)

    def test_txt_with_cname_data(self):
        result = get_data_by_type(QTYPE[16], "www.google.com")
        self.assertIsNone(result)

    def test_txt_with_aaaa_data(self):
        result = get_data_by_type(QTYPE[16], "21DA:D3:0::9C5A")
        self.assertIsNone(result)

    def test_aaaa_with_a_data(self):
        result = get_data_by_type(QTYPE[28], "1.2.3.4")
        self.assertIsNone(result)

    def test_aaaa_with_cname_data(self):
        result = get_data_by_type(QTYPE[28], "www.google.com")
        self.assertIsNone(result)

    def test_aaaa_with_txt_data(self):
        result = get_data_by_type(QTYPE[28], "txtvers=1")
        self.assertIsNone(result)