#! /bin/bash

sudo ./../../utils/veth_setup.sh

T="`realpath ../../testlib`"
if [ x"${PYTHONPATH}" == "x" ]
then
    P="${T}"
else
    P="${T}:${PYTHONPATH}"
fi

mkdir -p ./out

set -x
p4c --target bmv2 \
    --arch v1model \
    --output ./out \
    --p4runtime-files ./out/sketch.p4info.txt \
    sketch.p4

sudo simple_switch_grpc \
     --log-file ./out/ss-log \
     --log-flush \
     --dump-packet-data 10000 \
     -i 0@veth0 \
     -i 1@veth2 \
     -i 2@veth4 \
     -i 3@veth6 \
     -i 4@veth8 \
     -i 5@veth10 \
     -i 6@veth12 \
     -i 7@veth14 \
     --no-p4 &
echo ""
echo "Started simple_switch_grpc.  Waiting 2 seconds before starting PTF test ..."
sleep 2

# Note that the mapping between switch port number and Linux interface
# names is best to make it correspond with those given when starting
# the simple_switch_grpc process.  The `ptf` process has no other way
# of getting this mapping other than by telling it on its command
# line.

sudo `which ptf` \
    --pypath "$P" \
    -i 0@veth1 \
    -i 1@veth3 \
    -i 2@veth5 \
    -i 3@veth7 \
    -i 4@veth9 \
    -i 5@veth11 \
    -i 6@veth13 \
    -i 7@veth15 \
    --test-params="grpcaddr='localhost:9559';p4info='./out/sketch.p4info.txt';config='./out/sketch.json'" \
    --test-dir ptf

echo ""
echo "PTF test finished.  Waiting 2 seconds before killing simple_switch_grpc ..."
sleep 2
sudo pkill --signal 9 --list-name simple_switch
echo ""
echo "Verifying that there are no simple_switch_grpc processes running any longer in 4 seconds ..."
sleep 4
ps axguwww | grep simple_switch

sudo simple_switch_grpc \
     --log-file ./out/ss-log \
     --log-flush \
     --dump-packet-data 10000 \
     -i 0@veth0 \
     -i 1@veth2 \
     -i 2@veth4 \
     -i 3@veth6 \
     -i 4@veth8 \
     -i 5@veth10 \
     -i 6@veth12 \
     -i 7@veth14 \
     --no-p4 &
echo ""
echo "Started simple_switch_grpc.  Waiting 2 seconds before starting PTF test ..."
sleep 2

sudo `which ptf` \
    --pypath "$P" \
    -i 0@veth1 \
    -i 1@veth3 \
    -i 2@veth5 \
    -i 3@veth7 \
    -i 4@veth9 \
    -i 5@veth11 \
    -i 6@veth13 \
    -i 7@veth15 \
    --test-params="grpcaddr='localhost:9559';p4info='./out/sketch.p4info.txt';config='./out/sketch.json'" \
    --test-dir ptf2

echo ""
echo "PTF test finished.  Waiting 2 seconds before killing simple_switch_grpc ..."
sleep 2
sudo pkill --signal 9 --list-name simple_switch
echo ""
echo "Verifying that there are no simple_switch_grpc processes running any longer in 4 seconds ..."
sleep 4
ps axguwww | grep simple_switch

/bin/rm -rf ./out
/bin/rm -rf ./ptf.log ./ptf.pcap

sudo ./../../utils/veth_teardown.sh