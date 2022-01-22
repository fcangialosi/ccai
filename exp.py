import sys
import datetime
import json

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel
from mininet.cli import CLI

# A link between two nodes
class Link(object):
    def __init__(self, link_from, link_from_port, link_to, link_to_port, etype, capacity, latency, weight=None, relation=None, queue=None):
        self.from_name = link_from.name
        self.to_name = link_to.name
        self.props = {
            'capacity' : capacity,
            'latency' : latency,
            'ports' : {}
        }
        self.props['ports'][link_from.name] = link_from_port
        self.props['ports'][link_to.name] = link_to_port
        if weight:
            self.props['weight'] = weight
        if relation:
            self.props['relation'] = relation
        # Queue size of a FIFO queue, in packets, applied at the switch at BOTH ends of the link
        if queue:
            self.props['buffer'] = queue
        else: # size 0 means unbounded
            self.props['buffer'] = 0
        if etype == 'interdomain':
            self.props['entity_type'] = 'WFQChannel'

# A host OR ingress/egress
class Node(object):
    def __init__(self, name):
        self.name = name
        self.props = {
            'ports' : {}
        }
        self.port_counter = 0
        self.is_host = False
        self.links = []
        # TODO add ip and mac?

    def add_link(self, node, etype, capacity, latency, weight, relation, queue):
        my_port = self.port_counter 
        self.port_counter += 1
        their_port = node.port_counter
        node.port_counter += 1
        self.props['ports'][my_port] = (node.name, their_port)
        self.links.append(node.name)
        node.props['ports'][their_port] = (self.name, my_port)
        node.links.append(self.name)
        return Link(self, my_port, node, their_port, etype, capacity, latency, weight, relation, queue)

class Host(Node):
    def __init__(self, name):
        super(Host, self).__init__(name)
        self.props['entity_type'] = 'Host'
        self.is_host = True


class Ingress(Node):
    def __init__(self, name, parent):
        super(Ingress, self).__init__(name)
        self.props['entity_type'] = 'Router'
        self.props['direction'] = 'ingress'
        self.parent = parent

class Egress(Node):
    def __init__(self, name, parent):
        super(Egress, self).__init__(name)
        self.props['entity_type'] = 'Router'
        self.props['direction'] = 'egress'
        self.parent = parent

# A collection of ingress and egress nodes
# All ingresses and egresses are connected in a mesh
class Domain:
    def __init__(self, name):
        self.name = name
        self.ins = set()
        self.outs = set()
        self.in_counter = 1
        self.out_counter = 1
        self.is_host = False

    def add_ingress(self, node):
        name = "{}_{}_{}".format(self.name, 'in', self.in_counter)
        self.in_counter += 1
        ingress = Ingress(name, self)
        self.ins.add(ingress)
        return ingress

    def add_egress(self, node):
        name = "{}_{}_{}".format(self.name, 'out', self.out_counter)
        self.out_counter += 1
        egress = Egress(name, self)
        self.outs.add(egress)
        return egress


# No congestion on intradomain links
INTRADOMAIN_CAPACITY = '1000Mbps'
INTRADOMAIN_LATENCY = '0ms'

class Topology:
    HOST_PREFIX = 'h'
    DOMAIN_PREFIX = 'd'
    CUSTOMER = 'customer'
    PROVIDER = 'provider'
    PEER = 'peer'
    INTERDOMAIN = 'interdomain'
    INTRADOMAIN = 'intradomain'

    def __init__(self, settings):
        self.nodes = {}
        self.domains = {}
        self.links = set()
        self.settings = settings

        # Capacities
        dist, args = self.settings['capacity'].replace(")", "").split("(")
        args = args.split(",")
        if dist == 'static':
            static_capacity = args[0]
            self.default_capacity = (lambda etype : static_capacity if etype == Topology.INTERDOMAIN else INTRADOMAIN_CAPACITY)
        elif dist == 'uniform':
            clow = int(args[0].split("M")[0])
            chigh = int(args[1].split("M")[0])
            self.default_capacity = lambda etype : str(int(random.uniform(clow, chigh)))+'Mbps' if etype == Topology.INTERDOMAIN else INTRADOMAIN_CAPACITY

        # Latencies
        dist, args = self.settings['latency'].replace(")","").split("(")
        args = args.split(",")
        if dist == 'static':
            static_latency = args[0]
            self.default_latency = lambda etype : static_latency if etype == Topology.INTERDOMAIN else INTRADOMAIN_LATENCY
        elif dist == 'uniform':
            llow = int(args[0].split("M")[0])
            lhigh = int(args[1].split("M")[0])
            self.default_latency = lambda etype : str(int(random.uniform(llow, lhigh)))+'ms' if etype == Topology.INTERDOMAIN else INTRADOMAIN_LATENCY


    def _is_host(self, name):
        return name[0] == Topology.HOST_PREFIX
    def _is_domain(self, name):
        return name[0] == Topology.DOMAIN_PREFIX

    def ensure_node_exists(self, name):
        # If name starts with h its a host
        # If name starts with d its a domain
        if self._is_host(name):
            if not name in self.nodes:
                self.nodes[name] = Host(name)
            return self.nodes[name]
        elif self._is_domain(name):
            if not name in self.domains:
                self.domains[name] = Domain(name)
            return self.domains[name]
        else:
            raise Exception("unknown node prefix {}, options are {} or {}".format(
                name, Topology.HOST_PREFIX, Topology.DOMAIN_PREFIX))

    def add_edge(self, edge_from, edge_to, overrides):
        if 'capacity' in overrides:
            capacity = overrides['capacity']
        else:
            capacity = self.default_capacity(Topology.INTERDOMAIN)
        if 'latency' in overrides:
            latency = overrides['latency']
        else:
            latency = self.default_latency(Topology.INTERDOMAIN)
        weight = None
        if 'weight' in overrides:
            weight = overrides['weight']
        relation = None
        if 'relation' in overrides:
            relation = overrides['relation']
        queue = None
        if 'queue' in overrides:
            queue = overrides['queue']

        if edge_from.is_host: 
            if edge_to.is_host: # host -> host
                link = edge_to.add_link(edge_from, Topology.INTERDOMAIN, capacity, latency, weight=None, relation=None)
            else: # host -> domain
                ingress = edge_to.add_ingress(edge_from)
                assert not (ingress.name in self.nodes)
                self.nodes[ingress.name] = ingress
                link = ingress.add_link(edge_from, Topology.INTERDOMAIN, capacity, latency, weight=weight, relation=Topology.CUSTOMER, queue=None)
        elif edge_to.is_host: # domain -> host
            egress = edge_from.add_egress(edge_to)
            assert not (egress.name in self.nodes)
            self.nodes[egress.name] = egress
            link = egress.add_link(edge_to, Topology.INTERDOMAIN, capacity, latency, weight=weight, relation=Topology.PROVIDER, queue=None)
        else: # domain -> domain
            egress = edge_from.add_egress(edge_to)
            assert not (egress.name in self.nodes)
            self.nodes[egress.name] = egress
            ingress = edge_to.add_ingress(edge_from)
            assert not (ingress.name in self.nodes)
            self.nodes[ingress.name] = ingress
            link = egress.add_link(ingress, Topology.INTERDOMAIN, capacity, latency, weight=weight, relation=relation, queue=queue)
        self.links.add(link)

    def build_topology(self, edges):
        for (edge_from_name, edge_to_name, overrides) in edges:
            edge_from = self.ensure_node_exists(edge_from_name)
            edge_to = self.ensure_node_exists(edge_to_name)
            self.add_edge(edge_from, edge_to, overrides)
        for domain in list(self.domains.values()):
            for egress in domain.outs:
                for ingress in domain.ins:
                    link = ingress.add_link(
                            egress,
                            Topology.INTRADOMAIN,
                            capacity=self.default_capacity(Topology.INTRADOMAIN),
                            latency=self.default_latency(Topology.INTRADOMAIN), 
                            weight=None,
                            relation=None,
                            queue=None
                    )
                    self.links.add(link)

    def generate_paths(self, aggs):
        def find_next_hop(curr_node, next_hop_name, expect=False):
            match = [x for x in curr_node.links if next_hop_name in x]
            if expect:
                assert len(match) == 1
            return match[0] if match else None

        for agg in aggs:
            agg.router_path = []
            path = agg.router_path
            entry = find_next_hop(self.nodes[agg.src], agg.domain_path[0], expect=True)
            path.append(entry)

            domain_path = agg.domain_path + [agg.dst]
            for currd, nextd in zip(domain_path[:-1], domain_path[1:]):
                for egress in self.domains[currd].outs:
                    next_ingress = find_next_hop(egress, nextd)
                    if next_ingress:
                        path += [egress.name, next_ingress]



    def dump(self, fname=None):
        # Write to stdout if filename not specified
        if fname:
            f = open(fname, 'w')
        else:
            f = sys.stdout

        # Preamble
        f.write("""
# gutil graph
# Type:     Graph
# Nodes:    {num_nodes}
# Edges:    {num_edges}
# Written:  {now}
g 'Graph'
""".format(
            num_nodes = len(self.nodes), #+ sum([len(d.ins)+len(d.outs) for d in self.domains.values()]),
            num_edges = len(self.links),
            now = datetime.datetime.now()
        ))

        # Helpers
        def write_node(f, name, props):
            f.write("n '{name}', {props}\n".format(name=name, props=json.dumps(props)))
        def write_edge(f, a, b, props):
            f.write("e '{a}', '{b}', {props}\n".format(a=a, b=b, props=json.dumps(props)))

        # Write nodes
        for node in list(self.nodes.values()):
            write_node(f, node.name, node.props)
#        for host in self.hosts.values():
#            write_node(f, host.name, host.props)
#        for domain in self.domains.values():
#            for ingress in domain.ins:
#                write_node(f, ingress.name, ingress.props)
#            for egress in domain.outs:
#                write_node(f, egress.name, egress.props)
        # Write edges
        for link in self.links:
            write_edge(f, link.from_name, link.to_name, link.props)
        f.close()

class Aggregate(object):
    def __init__(self, id, src, dst, algs, domain_path):
        self.id = id
        self.src = src
        self.dst = dst
        self.algs = algs
        self.domain_path = domain_path

def read_topo(fname=None):
    if fname:
        f = open(fname, 'r')
    else:
        f = sys.stdin

    settings = {}
    edges = []
    aggregates = []
    agg_id = 1
    for l in f:
        l = l.strip()
        if not l or l[0] == "#":
            continue
        if l[0] == "[":
            heading = l[1:l.find("]")]
            continue

        if heading == 'settings':
            key, val = l.strip().split(" = ")
            settings[key] = val
        elif heading == 'topology':
            sp = l.strip().split()
            sp.remove("->")
            a, b = sp[0], sp[1]
            overrides = {}
            if len(sp) > 2:
                for extra in sp[2:]:
                    if extra[0] == "#":
                        break
                    try:
                        key, val = extra.strip().split("=")
                    except:
                        raise Exception("failed to parse overrides for line \"{}\". expected format is \"k1=v1 k2=v2 ...\"".format(l))

                    overrides[key] = val
                #raise Exception("unexpected field for edge: {}".format(" ".join(sp[4:])))
            edges.append((a,b,overrides))
        elif heading == 'aggregates':
            l = l.strip()
            domain_path = None
            if l.find("[") > 0:
                l, path_str = l.split("[")
                path_str = path_str.replace("]","")
                domain_path = [x.strip() for x in path_str.strip(" ").split(",")]
            sp = l.split()
            sp.remove("->")
            src, dst = sp[0], sp[1]
            algs = [x.split("=") for x in sp[2:]]
            flow_hosts = ['{}_{}_{}_{}'.format(src,dst,alg,i) for (alg,nflows) in algs for i in range(1,int(nflows)+1)]
            # Add fake "hosts" for each flow for a host
            #edges.extend((flow,src,{}) for flow in flow_hosts)
            aggregates.append(Aggregate(agg_id, src, dst, algs, domain_path))
            agg_id += 1

        else:
            raise Exception("unknown heading: {}".format(heading))

    t = Topology(settings)
    t.build_topology(edges)

    # t.generate_paths(aggregates)
    # f.close()

    return settings, t, aggregates

def get_all_paths(aggregates):
    paths = { agg.id : agg.router_path for agg in aggregates }
    reverse = { agg.id+1 : agg.router_path[::-1][1:] + [agg.src] for agg in aggregates }

    paths.update(reverse)
    return paths

class RCSTopo(Topo):
    def __init__(self, t):

        Topo.__init__(self)

        nodes = {}
        for (name,node) in t.nodes.items():
            if node.props['entity_type'] == 'Host':
                nodes[name] = self.addHost(name)
            elif node.props['entity_type'] == 'Router':
                nodes[name] = self.addSwitch(name)


        for link in t.links:
            self.addLink(nodes[link.from_name], nodes[link.to_name])
            # link.props



if __name__ == '__main__':
    setLogLevel('info')

    settings, t, aggs = read_topo(fname='test_1.topo')
    topo = RCSTopo(t)

    net = Mininet(topo=topo)
    net.start()
    # CLI(net)

    from ptpython.repl import embed
    embed(globals(), locals())
    net.stop()

