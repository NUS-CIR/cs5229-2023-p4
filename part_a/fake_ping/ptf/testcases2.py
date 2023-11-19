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

import logging

import ptf
import ptf.testutils as tu
from ptf.base_tests import BaseTest
import p4runtime_sh.shell as sh
import p4runtime_shell_utils as p4rtutil

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

class HiddenFakePingTest(BaseTest):
    def setUp(self):
        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        logging.debug("FakePingTest.setUp()")
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

        # Insert table entry
        te = sh.TableEntry('icmp_filter_table')(action='NoAction')
        te.match['hdr.ipv4.dstAddr'] = "44.44.44.44"
        te.insert()

    def tearDown(self):
        logging.debug("FakePingTest.tearDown()")
        sh.teardown()

class HiddenPingDropTest(HiddenFakePingTest):
    def runTest(self):
        in_dmac = 'ee:30:ca:9d:1e:00'
        in_smac = 'ee:cd:00:7e:70:00'

        ip_src_addr = '10.0.0.1'
        ip_dst_addr = '44.44.44.44'

        ig_port = 3
        eg_port = 3

        pkt = tu.simple_icmp_packet(eth_src=in_smac, eth_dst=in_dmac,
                ip_src = ip_src_addr, ip_dst = ip_dst_addr)
        exp_pkt = tu.simple_icmp_packet(eth_src=in_dmac, eth_dst=in_smac,
            ip_src = ip_dst_addr, ip_dst = ip_src_addr,
            icmp_type = 0, icmp_code = 0)
        tu.send_packet(self, ig_port, pkt)
        tu.verify_packets(self, exp_pkt, [eg_port])