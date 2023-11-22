#!/usr/bin/env python3

# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Andy Fingerhut, andy.fingerhut@gmail.com

import os
import logging

import ptf
import ptf.testutils as tu
from ptf.base_tests import BaseTest
import p4runtime_sh.shell as sh
import p4runtime_shell_utils as p4rtutil

from scapy.all import *
import time

# Links to many Python methods useful when writing automated tests:

# The package `ptf.testutils` contains many useful Python methods for
# writing automated tests, some of which are demonstrated below with
# calls prefixed by the local alias `tu.`.  You can see the
# definitions for all Python code in this package, including some
# documentation for these methods, here:

# https://github.com/p4lang/ptf/blob/master/src/ptf/testutils.py


######################################################################
# Configure logging
######################################################################

# Note: I am not an expert at configuring the Python logging library.
# Recommendations welcome on improvements here.

# The effect achieved by the code below seems to be that many DEBUG
# and higher priority logging messages go to the console, and also to
# a file named 'ptf.log'.  Some of the messages written to the
# 'ptf.log' file do not go to the console, and appear to be created
# from within the ptf library.

logger = logging.getLogger(None)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

# Examples of some kinds of calls that can be made to generate
# logging messages.
#logger.debug("10 logger.debug message")
#logger.info("20 logger.info message")
#logger.warn("30 logger.warn message")
#logger.error("40 logger.error message")
#logging.debug("10 logging.debug message")
#logging.info("20 logging.info message")
#logging.warn("30 logging.warn message")
#logging.error("40 logging.error message")

class HiddenSketchTest(BaseTest):
    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        logging.debug("SketchTest.setUp()")
        grpc_addr = tu.test_param_get("grpcaddr")
        if grpc_addr is None:
            grpc_addr = 'localhost:9559'
        p4info_txt_fname = tu.test_param_get("p4info")
        p4prog_binary_fname = tu.test_param_get("config")
        sh.setup(device_id=0,
                 grpc_addr=grpc_addr,
                 election_id=(0, 1), # (high_32bits, lo_32bits)
                 config=sh.FwdPipeConfig(p4info_txt_fname, p4prog_binary_fname),
                 verbose=False)
        
        # Setup mirroring
        os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/mirror_cmd > /dev/null")

        # Insert table entry
        te = sh.TableEntry('ipv4_forward')(action='ipv4_forward_action')
        te.match['hdr.ipv4.dstAddr'] = "10.0.0.1"
        te.action['port'] = "1"
        te.insert()
        te = sh.TableEntry('ipv4_forward')(action='ipv4_forward_action')
        te.match['hdr.ipv4.dstAddr'] = "10.0.0.2"
        te.action['port'] = "2"
        te.insert()
        te = sh.TableEntry('ipv4_forward')(action='ipv4_forward_action')
        te.match['hdr.ipv4.dstAddr'] = "10.0.0.7"
        te.action['port'] = "7"
        te.insert()

    def tearDown(self):
        logging.debug("SecretTest.tearDown()")
        sh.teardown()

class FwdTest2(HiddenSketchTest):
    def runTest(self):
        HH_THRESHOLD = 10
        DROP_THRESHOLD = 20

        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '10.0.0.7'

        ig_port = 2
        eg_port = 7

        te = sh.TableEntry('get_thresholds')(action='get_thresholds_action')
        te.action['hh_threshold_param'] = str(HH_THRESHOLD)
        te.action['drop_threshold_param'] = str(DROP_THRESHOLD)
        te.insert()
        # os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/dump_table_cmd")


        # IP connectivity between h1 and h2.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, pkt, [eg_port])

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_dst_addr, ip_dst=ip_src_addr)
        tu.send_packet(self, eg_port, pkt)
        tu.verify_packets(self, pkt, [ig_port])

class ReportHhOnceTest2(HiddenSketchTest):
    def runTest(self):
        HH_THRESHOLD = 10
        DROP_THRESHOLD = 20

        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '10.0.0.2'
        ip_dst_addr = '10.0.0.7'

        ig_port = 2
        eg_port = 7
        mirr_port = 3

        te = sh.TableEntry('get_thresholds')(action='get_thresholds_action')
        te.action['hh_threshold_param'] = str(HH_THRESHOLD)
        te.action['drop_threshold_param'] = str(DROP_THRESHOLD)
        te.insert()
        # os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/dump_table_cmd")

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr,
                                   tcp_sport=53, tcp_dport=6789)
        for i in range(1, DROP_THRESHOLD+1):
            # print(i)
            tu.send_packet(self, ig_port, pkt)
            if i == HH_THRESHOLD + 1:
                # print('exceed threshold')
                tu.verify_packet(self, pkt, mirr_port)
            else:
                tu.verify_no_packet(self, pkt, mirr_port)

class DnsAttackDropTest2(HiddenSketchTest):
    def runTest(self):
        HH_THRESHOLD = 10
        DROP_THRESHOLD = 20

        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '1.1.1.1'
        ip_dst_addr = '10.0.0.7'

        ig_port = 1
        eg_port = 7
        mirr_port = 3

        te = sh.TableEntry('get_thresholds')(action='get_thresholds_action')
        te.action['hh_threshold_param'] = str(HH_THRESHOLD)
        te.action['drop_threshold_param'] = str(DROP_THRESHOLD)
        te.insert()
        # os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/dump_table_cmd")

        pkt = tu.simple_udp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr,
                                   udp_sport=53, udp_dport=6789)
        for i in range(1, DROP_THRESHOLD+3):
            tu.send_packet(self, ig_port, pkt)
            if i <= DROP_THRESHOLD:
                tu.verify_packet(self, pkt, eg_port)
            else:
                tu.verify_no_packet(self, pkt, eg_port)

class DnsDropOnlyTest(HiddenSketchTest):
    def runTest(self):
        HH_THRESHOLD = 10
        DROP_THRESHOLD = 20

        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '10.0.0.7'
        ip_dst_addr = '10.0.0.2'

        ig_port = 7
        eg_port = 2
        mirr_port = 3

        te = sh.TableEntry('get_thresholds')(action='get_thresholds_action')
        te.action['hh_threshold_param'] = str(HH_THRESHOLD)
        te.action['drop_threshold_param'] = str(DROP_THRESHOLD)
        te.insert()
        # os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/dump_table_cmd")

        pkt = tu.simple_udp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr,
                                   udp_sport=53, udp_dport=6789)
        for i in range(1, DROP_THRESHOLD+3):
            tu.send_packet(self, ig_port, pkt)
            if i <= DROP_THRESHOLD:
                tu.verify_packet(self, pkt, eg_port)
            else:
                tu.verify_no_packet(self, pkt, eg_port)

        ig_port = 7
        eg_port = 2

        # IP connectivity between h7 and h2.
        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_src_addr, ip_dst=ip_dst_addr)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, pkt, [eg_port])

        pkt = tu.simple_tcp_packet(eth_src=in_smac, eth_dst=in_dmac,
                                   ip_src=ip_dst_addr, ip_dst=ip_src_addr)
        tu.send_packet(self, eg_port, pkt)
        tu.verify_packets(self, pkt, [ig_port])


verify_count = 0
expected_hh = []
rcvd_hh = []
def check_pkt(pkt):
    global verify_count
    global rcvd_hh
    global expected_hh
    # print(pkt.show())
    if ICMP in pkt:
        rcvd = ','.join([pkt[IP].src, pkt[IP].dst,str(0), str(0), pkt[IP].proto])
    elif TCP in pkt:
        rcvd = ','.join([pkt[IP].src, pkt[IP].dst, str(pkt[TCP].sport), str(pkt[TCP].dport), str(pkt[IP].proto)])
    else:
        rcvd = ','.join([pkt[IP].src, pkt[IP].dst, str(pkt[UDP].sport), str(pkt[UDP].dport), str(pkt[IP].proto)])
    assert not rcvd in rcvd_hh
    assert rcvd in expected_hh
    rcvd_hh.append(rcvd)
    verify_count = verify_count + 1


class DnsTraceTest(HiddenSketchTest):
    def runTest(self):
        HH_THRESHOLD = 150
        DROP_THRESHOLD = 180
        TOP_K_HH = 1

        ig_port = 1
        eg_port = 7

        global verify_count
        global rcvd_hh
        global expected_hh
        verify_count = 0
        expected_hh = []
        rcvd_hh = []

        te = sh.TableEntry('get_thresholds')(action='get_thresholds_action')
        te.action['hh_threshold_param'] = str(HH_THRESHOLD)
        te.action['drop_threshold_param'] = str(DROP_THRESHOLD)
        te.insert()
        # os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/dump_table_cmd")

        gt = []
        with open('./ptf2/dns-trace-gt.csv') as f:
            gt = f.read()
        gt = gt.split('\n')
        
        for i in range(len(gt)):
            entry = gt[i].split(' ')[0]
            count = int(gt[i].split(' ')[1])
            entry = entry.split(',')
            entry[2] = str(int(float(entry[2])))
            entry[3] = str(int(float(entry[3])))
            entry[4] = str(int(float(entry[4])))
            if count > HH_THRESHOLD:
                expected_hh.append(','.join(entry))
            else:
                break
        assert len(expected_hh) == TOP_K_HH

        pkts = []
        with open('./ptf2/dns-trace.csv') as f:
            pkts = f.read()
        pkts = pkts.split('\n')

        t = AsyncSniffer(iface="veth7", prn=check_pkt, count=TOP_K_HH+1, timeout=10)
        t.start()

        # ctr = 0
        for pkt in pkts:
            pkt = pkt.split(',')
            src_ip = pkt[0]
            dst_ip = pkt[1]
            src_port = int(float(pkt[2]))
            dst_port = int(float(pkt[3]))
            proto = int(float(pkt[4]))
            pkt =  Ether(src="ee:30:ca:9d:1e:00", dst="08:00:00:00:02:22")
            if proto == 1:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / ICMP()
            elif proto == 6:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
            else:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
            tu.send_packet(self, ig_port, pkt)
            time.sleep(0.005)
            # ctr += 1
            # if ctr % 100 == 0:
            #     print(ctr)
        t.join()
        assert verify_count == TOP_K_HH

class LongTraceTest(HiddenSketchTest):
    def runTest(self):
        HH_THRESHOLD = 50
        DROP_THRESHOLD = 200
        TOP_K_HH = 9

        ig_port = 1
        eg_port = 7

        global verify_count
        global rcvd_hh
        global expected_hh
        verify_count = 0
        expected_hh = []
        rcvd_hh = []

        te = sh.TableEntry('get_thresholds')(action='get_thresholds_action')
        te.action['hh_threshold_param'] = str(HH_THRESHOLD)
        te.action['drop_threshold_param'] = str(DROP_THRESHOLD)
        te.insert()
        # os.system("simple_switch_CLI --thrift-port 9090 < ./ptf/dump_table_cmd")

        gt = []
        with open('./ptf2/long-trace-gt.csv') as f:
            gt = f.read()
        gt = gt.split('\n')
        
        for i in range(len(gt)):
            entry = gt[i].split(' ')[0]
            count = int(gt[i].split(' ')[1])
            entry = entry.split(',')
            entry[2] = str(int(float(entry[2])))
            entry[3] = str(int(float(entry[3])))
            entry[4] = str(int(float(entry[4])))
            if count > HH_THRESHOLD:
                expected_hh.append(','.join(entry))
            else:
                break
        assert len(expected_hh) == TOP_K_HH

        pkts = []
        with open('./ptf2/long-trace.csv') as f:
            pkts = f.read()
        pkts = pkts.split('\n')

        t = AsyncSniffer(iface="veth7", prn=check_pkt, count=TOP_K_HH, timeout=120)
        t.start()

        # ctr = 0
        for pkt in pkts:
            pkt = pkt.split(',')
            src_ip = pkt[0]
            dst_ip = pkt[1]
            src_port = int(float(pkt[2]))
            dst_port = int(float(pkt[3]))
            proto = int(float(pkt[4]))
            pkt =  Ether(src="ee:30:ca:9d:1e:00", dst="08:00:00:00:02:22")
            if proto == 1:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / ICMP()
            elif proto == 6:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / TCP(dport=dst_port, sport=src_port)
            else:
                pkt = pkt / IP(src=src_ip, dst=dst_ip) / UDP(dport=dst_port, sport=src_port)
            tu.send_packet(self, ig_port, pkt)
            time.sleep(0.005)
            # ctr += 1
            # if ctr % 100 == 0:
            #     print(ctr)
        t.join()
        assert verify_count == TOP_K_HH