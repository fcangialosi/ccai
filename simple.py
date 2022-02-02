#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import Node
from mininet.link import Link, TCLink
from mininet.log import  setLogLevel, info

from time import sleep
import sys
import subprocess
import itertools

EXP_LEN = 30
NHOSTS = 3
BLAST_ENABLED = False
ALGS = ['reno', 'cubic', 'vegas', 'bbr'] # , 'blast']
if BLAST_ENABLED:
    ALGS += ['blast']
RATE = 10000000 
QUEUE_SIZE = 150000
TOPO = "topo1"

btl_rate_mbps = RATE * 8 / 1000000

# topo 1
# h0: 42.0.0.0/16
# s1: 42.1.0.0/16
#   |- h3: 42.1.3.0/24
#   |- h4: 42.1.4.0/24
# h2: 42.2.0.0/16
#
#                      h0    (42.0.0.1)        (42.2.0.1)
#            (42.0.0.2)->\         \/           \/
#           h4            ----------- (hwfq) s1 ------- h2
# (42.1.4.2)->\ (..4.1)  /         ^                  ^
#              -- s1 ----^   (42.1.0.1)            (42.2.0.2)
# (42.1.3.2)->/ (..3.1)  |
#           h3          (42.1.0.2)
#

setLogLevel( 'info' )

def clean_slate(nodes={}, pcaps=[]):
    info("delete intfs\n")
    for n in nodes.values():
        n.deleteIntfs()
    info("kill tcpdump\n")
    for p in pcaps:
        p.terminate()
    info("mn -c")
    subprocess.call("mn -c", shell=True)
    info("kill hwfq\n")
    subprocess.call("pkill -9 hwfq", shell=True)
    info("kill iperf\n")
    subprocess.call("pkill -9 iperf", shell=True)
    sleep(1)

def set_fq(node, iface):
    node.cmdPrint(f'tc qdisc replace dev {iface} root fq')
    node.cmdPrint('tc qdisc show')

def run_exp(traffic, qtype, out):
    Mininet.init()

    info( "*** Creating nodes\n" )
    switch0 = Node('s0')

    h0 = Node('h0')
    s1 = Node('s1')
    h2 = Node('h2')
    h3 = Node('h3')
    h4 = Node('h4')

    nodes = {
        'h0' : h0,
        's0' : switch0,
        's1' : s1,
        'h2' : h2,
        'h3' : h3,
        'h4' : h4,
    }

    info( "*** Creating links\n" )
    TCLink(h0, switch0)
    TCLink(s1, switch0)
    TCLink(h2, switch0, delay='50ms', bw=btl_rate_mbps)

    switch0.cmd('sysctl net.ipv4.ip_forward=1')
    switch0.intfs[0].setIP('42.0.0.1/16')
    switch0.intfs[1].setIP('42.1.0.1/16')
    switch0.intfs[2].setIP('42.2.0.1/16')
    switch0.cmd('ip route add 42.0.0.0/16 via 42.0.0.2 dev s0-eth0 scope global')
    switch0.cmd('ip route add 42.1.0.0/16 via 42.1.0.2 dev s0-eth1 scope global')
    switch0.cmd('ip route add 42.1.3.0/24 via 42.1.0.2 dev s0-eth1 scope global')
    switch0.cmd('ip route add 42.1.4.0/24 via 42.1.0.2 dev s0-eth1 scope global')
    switch0.cmd('ip route add 42.2.0.0/16 via 42.2.0.2 dev s0-eth2 scope global')

    TCLink(h3, s1, delay='10ms')
    TCLink(h4, s1, delay='10ms')
    s1.intfs[0].setIP('42.1.0.2/24')
    s1.intfs[1].setIP('42.1.3.1/24')
    s1.intfs[2].setIP('42.1.4.1/24')
    s1.cmd('sysctl net.ipv4.ip_forward=1')
    s1.cmd('ip route add 42.2.0.0/16 via 42.1.0.1 src 42.1.0.2 dev s1-eth0 scope global')
    s1.cmd('ip route add 42.1.0.0/16 dev s1-eth0 scope global')
    s1.cmd('ip route add 42.1.3.0/24 dev s1-eth1 scope global')
    s1.cmd('ip route add 42.1.4.0/24 dev s1-eth2 scope global')

    info( "*** Configuring hosts\n" )
    h0.setIP( '42.0.0.2/16' )
    h0.cmd('ip route add 42.2.0.0/16 via 42.0.0.1')

    h2.setIP( '42.2.0.2/16' )
    h2.cmd('ip route add 42.0.0.0/16 via 42.2.0.1')
    h2.cmd('ip route add 42.1.0.0/16 via 42.2.0.1')

    h3.setIP( '42.1.3.2/24' )
    h3.cmd('ip route add default via 42.1.3.1')
    h3.cmd('ip route add 42.1.0.0/16 via 42.1.3.1')
    h3.cmd('ip route add 42.2.0.0/16 via 42.1.0.1')
    h4.setIP( '42.1.4.2/24' )
    h4.cmd('ip route add default via 42.1.4.1')
    h4.cmd('ip route add 42.1.0.0/16 via 42.1.4.1')
    h4.cmd('ip route add 42.2.0.0/16 via 42.1.0.1')


    # START HWFQ AND REROUTE
    if qtype != "fifo":
        if qtype == "hwfq":
            hwfq_proc = switch0.popen(
                f"sudo env RUST_LOG=debug /home/ubuntu/hwfq/target/release/hwfq -i s0-eth2 -r {RATE} --scheduler hwfq --weights-cfg weights.yaml -q {QUEUE_SIZE} > hwfq.out 2> hwfq.err",
                shell=True)
        elif qtype == "drr":
            hwfq_proc = switch0.popen(
                f"sudo env RUST_LOG=debug /home/ubuntu/hwfq/target/release/hwfq -i s0-eth2 -r {RATE} --scheduler drr -q {QUEUE_SIZE} > hwfq.out 2> hwfq.err",
                shell=True)
        sleep(2)
        switch0.cmdPrint('ip route del 42.2.0.0/16 dev s0-eth2')
        switch0.cmdPrint('ip route add 42.2.0.0/16 dev hwfq-0')
        sleep(1)

    # from ptpython.repl import embed
    # embed(globals(), locals())

    set_fq(h0, "h0-eth0")
    set_fq(h3, "h3-eth0")
    set_fq(h4, "h4-eth0")

    #s1_from_h3_pcap = s1.popen('tcpdump -w s1-from-h3.pcap -i s1-eth1')
    #s1_to_s0_pcap = s1.popen('tcpdump -w s1-to-s0.pcap -i s1-eth0')
    #s1_h4_pcap = s1.popen('tcpdump -w s1-from-h4.pcap -i s1-eth2')
    #s0_from_h0_pcap = switch0.popen('tcpdump -w s0-from-h0.pcap -i s0-eth0')
    #s0_from_s1_pcap = switch0.popen('tcpdump -w s0-from-s1.pcap -i s0-eth1')
    #s0_from_h2_pcap = switch0.popen('tcpdump -w s0-from-h2.pcap -i s0-eth2')
    #h3_pcap = h3.popen('tcpdump -w h3.pcap -i h3-eth0')
    #pcaps = [s1_from_h3_pcap, s1_to_s0_pcap, s0_from_s1_pcap, h3_pcap]
    pcaps = []

        #subprocess.call("pkill -9 hwfq", shell=True)
        #subprocess.call("pkill -9 iperf", shell=True)

    ping = h0.cmd(f'ping -c 3 {h2.IP()}')
    if '3 packets transmitted, 3 received' not in ping:
        info("*** Ping h0 -> h2 failed, stopping\n")
        print(ping)
        stop_all()
        sys.exit(1)
    else:
        info("*** ping h0 -> h2 ok\n")

    ping = s1.cmd(f'ping -c 3 {h2.IP()}')
    if '3 packets transmitted, 3 received' not in ping:
        info("*** Ping s1 -> h2 failed, stopping\n")
        print(ping)
        stop_all()
        sys.exit(1)
    else:
        info("*** ping s1 -> h2 ok\n")

    ping = h3.cmd(f'ping -c 3 42.1.3.1')
    if '3 packets transmitted, 3 received' not in ping:
        info("*** Ping h3 -> s1 failed, stopping\n")
        print(ping)
        stop_all()
        sys.exit(1)
    else:
        info("*** ping h3 -> s1 ok\n")

    #ping = h3.cmd(f'ping -c 3 42.1.0.1')
    #if '3 packets transmitted, 3 received' not in ping:
    #    info("*** Ping h3 -> s0 failed, stopping\n")
    #    print(ping)
    #    stop_all()
    #    sys.exit(1)
    #else:
    #    info("*** ping h3 -> s0 ok\n")

    ping = h3.cmd(f'ping -c 3 {h2.IP()}')
    if '3 packets transmitted, 3 received' not in ping:
        info("*** Ping h3 -> h2 failed, stopping\n")
        print(ping)
        stop_all()
        sys.exit(1)
    else:
        info("*** ping h3 -> h2 ok\n")

    ping = h4.cmd(f'ping -c 3 {h2.IP()}')
    if '3 packets transmitted, 3 received' not in ping:
        info("*** Ping failed, stopping\n")
        print(ping)
        stop_all()
        sys.exit(1)
    info("*** ping h4 -> h2 ok\n")

    h2_iperf = h2.popen('iperf -s -p 4242', shell=True)
    if BLAST_ENABLED:
        h2_iperf_u = h2.popen('iperf -s -p 4243 -u', shell=True)
    sleep(1)

    iperfs = []
    for (src, alg) in traffic.items():
        h = nodes[src]
        if alg == 'blast':
            iperf = h.popen(f'iperf -c {h2.IP()} -p 4243 -t {EXP_LEN} -i 1 -u -b 200M > {src}.out', shell=True)
        else:
            iperf = h.popen(f'iperf -c {h2.IP()} -p 4242 -t {EXP_LEN} -i 1 -Z {alg} > {src}.out', shell=True)
        iperfs.append(iperf)
        sleep(1)

    info("senders started\n")
    for iperf in iperfs:
        iperf.wait()
    info("all senders returned\n")

    col = [qtype, str(EXP_LEN), TOPO]
    col += traffic.values()
    for (src,alg) in traffic.items():
        lines = subprocess.check_output(f"tail -n2 {src}.out", shell=True)
        lines = lines.decode("utf-8").strip().split("\n")
        if 'out-of-order' in lines[1]:
            line = lines[0]
        else:
            line = lines[1]
        tpt = "".join(line.split()[6:7+1])
        col += [f"{tpt}"]

    out.write(" ".join(col) + "\n")

    # h1_iperf = s1.cmd(f'iperf -c {h2.IP()} -p 4242 -t 10 -i 1 -Z vegas > vegas.out', shell=True)
    # h3_iperf = h3.popen(f'iperf -c {h2.IP()} -p 4242 -t 20 -i 1 -Z vegas > h3.out', shell=True)
    # h4_iperf = h4.popen(f'iperf -c {h2.IP()} -p 4242 -t 20 -i 1 -Z vegas > h4.out', shell=True)
    # info("senders started")
    # h3_iperf.wait()
    # h4_iperf.wait()
    # h0_iperf.wait()
    # info("h0 done\n")
    # print(h0_iperf.stdout.read().decode('utf-8'))
    # print(h1_iperf)

    info("cleanup\n")
    h2_iperf.kill()
    if BLAST_ENABLED:
        h2_iperf_u.kill()
    sleep(1)
    clean_slate(nodes, pcaps)


if __name__ == '__main__':

    combinations = set([])
    for i in range(3):
        combinations.update(list(itertools.combinations_with_replacement(ALGS[i:] + ALGS[:i], NHOSTS)))

    clean_slate()

    out = open('exp.out', 'a')
    out.write("qtype duration topo alg0 alg3 alg4 tpt0 tpt3 tpt4\n")
    exp_num = 1
    for qtype in ['hwfq', 'drr']: #, 'fifo']:
        for c in list(combinations)[:1]:
            info(f">>> #{exp_num}/{len(combinations)}: {c}, {qtype} <<<\n")
            traffic = {
                'h0' : c[0],
                'h3' : c[1],
                'h4' : c[2],
            }
            run_exp(traffic, qtype, out)
            out.flush()
            exp_num += 1
    out.close()
