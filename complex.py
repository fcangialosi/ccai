#!/usr/bin/python3

from mininet.net import Mininet
from mininet.node import Node
from mininet.link import Link, TCLink
from mininet.log import  setLogLevel, info

from time import sleep
import os
import sys
import subprocess
import itertools

EXP_LEN = 30
NHOSTS = 4
BLAST_ENABLED = False
ALGS = ['reno', 'cubic', 'vegas', 'bbr'] # , 'blast']
if BLAST_ENABLED:
    ALGS += ['blast']
RATE = 10000000 
QUEUE_SIZE = 150000
TOPO = "topo1"

btl_rate_mbps = RATE * 8 / 1000000

setLogLevel( 'info' )

def clean_slate(nodes={}, pcaps=[]):
    info("kill iperf\n")
    subprocess.call("pkill -9 iperf", shell=True)
    info("kill hwfq\n")
    subprocess.call("pkill -9 hwfq", shell=True)
    info("delete intfs\n")
    for n in nodes.values():
        n.deleteIntfs()
    info("kill tcpdump\n")
    for p in pcaps:
        p.terminate()
    info("mn -c")
    sleep(1)
    subprocess.call("mn -c", shell=True)
    sleep(1)

def set_fq(node, iface):
    node.cmdPrint(f'tc qdisc replace dev {iface} root fq')
    node.cmdPrint('tc qdisc show')

def run_exp(exp_num, traffic, qtype, run_dir, out):
    Mininet.init()

    info( "*** Creating nodes\n" )

    def ping(src, dst):
        src.cmdPrint(f"ping -4 {dst.IP()} -c2")
    def iperf(nfrom, nto, dur=5, bg=False):
        server = nto.popen("iperf -s -p 4242")
        if bg:
            client = nfrom.popen(f"iperf -c {nto.IP()} -p 4242 -i 1 -t {dur}", shell=True)
            return (client,server)
        else:
            nfrom.cmdPrint(f"iperf -c {nto.IP()} -p 4242 -i 1 -t {dur}")
            server.kill()
    os.makedirs('pcaps')
    def dump_intfs(link):
        cmd = f'tcpdump -l -i {link.intf1.name} > pcaps/{link.intf1.name}'
        print(cmd)
        a = link.intf1.node.popen(cmd, shell=True)
        cmd = f'tcpdump -l -i {link.intf2.name} > pcaps/{link.intf2.name}'
        print(cmd)
        b = link.intf2.node.popen(cmd, shell=True)
        return [a,b]

    # send side is '42.*'
    send_net = '42.0.0.0'
    send1 = Node('s1')
    send2 = Node('s2')
    send3 = Node('s3')
    send4 = Node('s4')
    senders = [send1, send2, send3, send4]

    # t3u1 owns 42.1.* /16
    t3u1 = Node('t3u1') 
    t3u1.cmd('sysctl net.ipv4.ip_forward=1')

    # link senders to t3u1
    link = TCLink(send1, t3u1)
    link.intf1.setIP('42.1.1.1/24')
    link.intf2.setIP('42.1.1.2/24')
    send1.cmd(f'ip route add default via 42.1.1.2')
    dump_intfs(link)
    link = TCLink(send2, t3u1)
    link.intf1.setIP('42.1.2.1/24')
    link.intf2.setIP('42.1.2.2/24')
    send2.cmd(f'ip route add default via 42.1.2.2')

    # t3u2 owns 42.2.* /16
    t3u2 = Node('t3u2')
    t3u2.cmd('sysctl net.ipv4.ip_forward=1')

    # link senders to t3u2
    link = TCLink(send3, t3u2)
    link.intf1.setIP('42.2.3.1/24')
    link.intf2.setIP('42.2.3.2/24')
    send3.cmd(f'ip route add default via 42.2.3.2')
    link = TCLink(send4, t3u2)
    link.intf1.setIP('42.2.4.1/24')
    link.intf2.setIP('42.2.4.2/24')
    send4.cmd(f'ip route add default via 42.2.4.2')

    # t2u1 owns 42.10.* /16
    t2u1 = Node('t2u1')
    t2u1.cmd('sysctl net.ipv4.ip_forward=1')

    # attach t3s to t2
    link = TCLink(t3u1, t2u1)
    link.intf1.setIP('42.10.0.2/24')
    link.intf2.setIP('42.10.0.1/24')
    dump_intfs(link)
    t3u1.cmd(f'ip route add 43.0.0.0/8 via 42.10.0.1 src 42.10.0.2 dev {link.intf1.name} scope global')
    t2u1.cmd(f'ip route add 42.1.0.0/16 via 42.10.0.2 src 42.10.0.1 dev {link.intf2.name} scope global')
    # NOTE for some reason communicating between senders in different t3s doesn't work.. but shouldn't matter??
    link = TCLink(t3u2, t2u1)
    link.intf1.setIP('42.10.0.4/24')
    link.intf2.setIP('42.10.0.3/24')
    t3u2.cmd(f'ip route add 43.0.0.0/8 via 42.10.0.3 src 42.10.0.4 dev {link.intf1.name} scope global')
    t2u1.cmd(f'ip route add 42.2.0.0/16 via 42.10.0.4 src 42.10.0.3 dev {link.intf2.name} scope global')

    
    # receive side is in '43.* /8'
    recv_net = '43.0.0.0'

    recv1 = Node('r1')
    recv2 = Node('r2')
    recv3 = Node('r3')
    recvs = [recv1, recv2, recv3]

    # t3d1 owns 43.1.* /16
    t3d1 = Node('t3d1')
    t3d1.cmd('sysctl net.ipv4.ip_forward=1')

    link = TCLink(recv1, t3d1)
    link.intf1.setIP('43.1.1.1/24')
    link.intf2.setIP('43.1.1.2/24')
    recv1.cmd(f'ip route add default via 43.1.1.2')
    link = TCLink(recv2, t3d1)
    link.intf1.setIP('43.1.2.1/24')
    link.intf2.setIP('43.1.2.2/24')
    recv2.cmd(f'ip route add default via 43.1.2.2')

    # t3d2 owns 43.2.*/16
    t3d2 = Node('t3d2')
    t3d2.cmd('sysctl net.ipv4.ip_forward=1')
    print("linking recvs to t3d2")
    link = TCLink(recv3, t3d2)
    link.intf1.setIP('43.2.3.1/24')
    link.intf2.setIP('43.2.3.2/24')
    recv3.cmd(f'ip route add default via 43.2.3.2')

    # t2d1 owns 43.10.* /16
    t2d1 = Node('t2d1')
    t2d1.cmd('sysctl net.ipv4.ip_forward=1')
    link = TCLink(t3d1, t2d1)
    link.intf1.setIP('43.10.0.2/24')
    link.intf2.setIP('43.10.0.1/24')
    dump_intfs(link)
    t3d1.cmd(f'ip route add 42.0.0.0/8 via 43.10.0.1 src 43.10.0.2 dev {link.intf1.name} scope global')
    t2d1.cmd(f'ip route add 43.1.0.0/16 via 43.10.0.2 src 43.10.0.1 dev {link.intf2.name} scope global')

    link = TCLink(t3d2, t2d1)
    link.intf1.setIP('43.10.0.4/24')
    link.intf2.setIP('43.10.0.3/24')
    t3d2.cmd(f'ip route add 42.0.0.0/8 via 43.10.0.3 src 43.10.0.4 dev {link.intf1.name} scope global')
    t2d1.cmd(f'ip route add 43.2.0.0/16 via 43.10.0.4 src 43.10.0.3 dev {link.intf2.name} scope global')

    print("adding peer links")
    # interace between t2u1 and t2d1 is 42.100
    link = TCLink(t2u1, t2d1, bw=btl_rate_mbps, delay='20ms')
    link.intf1.setIP('42.100.0.2/24')
    link.intf2.setIP('42.100.0.1/24')
    dump_intfs(link)

    t2u1.cmd(f'ip route add 43.0.0.0/8 via 42.100.0.1 src 42.100.0.2 dev {link.intf1.name} scope global')
    # t2u1.cmd(f'ip route add 43.0.0.0/8 nexthop via 42.100.0.1')
    t2d1.cmd(f'ip route add 42.0.0.0/8 via 42.100.0.2 src 42.100.0.1 dev {link.intf2.name} scope global')


    # START HWFQ AND REROUTE
    def start_hwfq():
        if qtype != "fifo":
            hwfq_out = os.path.join(run_dir, 'hwfq.out')
            hwfq_err = os.path.join(run_dir, 'hwfq.err')
            if qtype == "hwfq":
                hwfq_proc = t2u1.popen(
                    f"sudo env RUST_LOG=trace /home/ubuntu/hwfq/target/release/hwfq -i {link.intf1.name} -r {RATE} --scheduler hwfq --weights-cfg complex.yaml -q {QUEUE_SIZE} > {hwfq_out} 2> {hwfq_err}",
                    shell=True)
            elif qtype == "drr":
                hwfq_proc = t2u1.popen(
                    f"sudo env RUST_LOG=trace /home/ubuntu/hwfq/target/release/hwfq -i {link.intf1.name} -r {RATE} --scheduler drr -q {QUEUE_SIZE} > {hwfq_out} 2> {hwfq_err}",
                    shell=True)
            sleep(2)
            t2u1.cmdPrint(f'ip route del 43.0.0.0/8 dev {link.intf1.name}')
            t2u1.cmdPrint('ip route add 43.0.0.0/8 via 100.64.0.254 src 42.100.0.2 dev hwfq-0 scope global')
            sleep(1)

    from ptpython.repl import embed
    embed(globals(), locals())
    
    nodes = {
        'send1' : send1,
        'send2' : send2,
        'send3' : send3,
        'send4' : send4,
        't2d1' : t2d1
    }

    iperf_s_out = os.path.join(run_dir, "4242.out")
    h2_iperf = t2d1.popen('iperf -s -p 4242 > {iperf_s_out} 2>&1', shell=True)
    sleep(1)

    iperfs = []
    for (src, alg) in traffic.items():
        h = nodes[src]
        src_out = os.path.join(run_dir, f'{src}.out')
        src_err = os.path.join(run_dir, f'{src}.err')
        iperf = h.popen(f'iperf -c {t2d1.IP()} -p 4242 -t {EXP_LEN} -i 1 -Z {alg} > {src_out} 2> {src_err}', shell=True)
        iperfs.append(iperf)
        # sleep(1)

    info("senders started\n")
    for iperf in iperfs:
        iperf.wait()
    info("all senders returned\n")

    col = [str(exp_num), qtype, str(EXP_LEN), TOPO]
    col += traffic.values()
    for (src,alg) in traffic.items():
        src_out = os.path.join(run_dir, f'{src}.out')
        try:
            lines = subprocess.check_output(f"tail -n2 {src_out}", shell=True)
            lines = lines.decode("utf-8").strip().split("\n")
            if 'out-of-order' in lines[1]:
                line = lines[0]
            else:
                line = lines[1]
            tpt = "".join(line.split()[6:7+1])
            col += [f"{tpt}"]
        except:
            print(">>> failed to parse output! skipping...")

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
    # h2_iperf.kill()
    # if BLAST_ENABLED:
    #     h2_iperf_u.kill()
    sleep(1)
    clean_slate(nodes)


if __name__ == '__main__':

    combinations = set([])
    for i in range(3):
        combinations.update(list(itertools.combinations_with_replacement(ALGS[i:] + ALGS[:i], NHOSTS)))

    clean_slate()

    exp_dir = sys.argv[1]
    # if os.path.isdir(exp_dir):
    #     sys.exit("experiment already exists!")
    os.makedirs(exp_dir)
    out = open(os.path.join(exp_dir,'results.out'), 'a')
    out.write("run qtype duration topo alg0 alg3 alg4 tpt0 tpt3 tpt4\n")
    exp_num = 1
    for qtype in ['hwfq']: #, 'fifo']:
        for c in list(combinations)[:3]:
            info(f">>> #{exp_num}/{len(combinations)}: {c}, {qtype} <<<\n")
            traffic = {
                'send1' : c[0],
                'send2' : c[1],
                'send3' : c[2],
                'send4' : c[3],
            }
            run_dir = os.path.join(exp_dir, str(exp_num))
            os.makedirs(run_dir)
            with open(os.path.join(run_dir, 'details'), 'w') as f:
                f.write(f"{exp_num}, {c}, {qtype}\n")
            run_exp(exp_num, traffic, qtype, run_dir, out)
            out.flush()
            exp_num += 1
    out.close()
