#!/usr/bin/env python
# The MIT License (MIT)
#
# Copyright (c) 2014 Daniel Lawrence <dannyla@linux.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import json
import sys
import argparse
# from pprint import pprint
from collections import defaultdict
from contextlib import contextmanager

verbose = False
bypass_cache = False

aws_flags = ['--no-verify-ssl']
database_keys = ['database', 'db', 'rds']


def echo(message, stderr=True):
    global verbose
    if not verbose:
        return

    if stderr:
        stream = sys.stderr
    else:
        stream = sys.stdout
    stream.write(message)


# check if a string is valid json, if so return the object, else return null
def parse_json(jsonstring):
    try:
        json_object = json.loads(jsonstring)
    except ValueError:
        return None

    return json_object


def get_cached_command(cmd):
    if not bypass_cache:
        if os.path.exists(cmd):
            echo(" HIT\n")

            with open(cmd, 'r') as jsonfile:
                raw_json = json.load(jsonfile)
                return raw_json

        echo(" MISS\n")

    return False


def aws_command(cmd):
    os.popen('mkdir -p /tmp/aws-cache').read()

    flags = " ".join(aws_flags)
    aws_cmd = "aws %s %s" % (flags, cmd)
    echo("%s" % aws_cmd)

    safe_cmd = "/tmp/aws-cache/%s" % aws_cmd.replace(' ', '_')

    cached_cmd = get_cached_command(safe_cmd)

    if cached_cmd:
        return cached_cmd

    raw = os.popen(aws_cmd).read()
    raw_json = json.loads(raw)

    with open(safe_cmd, 'w') as outfile:
        json.dump(raw_json, outfile)

    return raw_json


def get_rds(lookup_filter=''):
    lookup_cmd = "rds describe-db-instances %s" % lookup_filter
    rds = aws_command(lookup_cmd)
    return rds['DBInstances']


def get_subnets(lookup_filter=''):
    lookup_cmd = "ec2 describe-subnets %s" % lookup_filter
    subnets = aws_command(lookup_cmd)
    return subnets['Subnets']


def get_load_balancers(lookup_filter=''):
    lookup_cmd = "elb describe-load-balancers %s" % lookup_filter
    load_balancers = aws_command(lookup_cmd)
    return load_balancers['LoadBalancerDescriptions']


def get_load_balancers_by_name(elb_names=None):
    if not elb_names:
        return None

    if isinstance(elb_names, list):
        elb_names = ' '.join(elb_names)

    return get_load_balancers('--load-balancer-names %s' % elb_names)


def get_ec2_instances(lookup_filter=''):
    lookup_cmd = "ec2 describe-instances %s" % lookup_filter
    reservations = aws_command(lookup_cmd)
    return [ec2 for reservation in reservations['Reservations']
            for ec2 in reservation['Instances']
            if not isEc2Terminated(ec2)]


def get_resource_tags(lookup_filter=''):
    lookup_cmd = "ec2 describe-tags --filters 'Name=resource-id,Values=%s'" % lookup_filter
    tags = aws_command(lookup_cmd)
    return tags


def get_ec2_instances_by_id(instance_ids=None):
    if not instance_ids:
        return None

    if isinstance(instance_ids, list):
        instance_ids = ' '.join(instance_ids)

    return get_ec2_instances('--instance-ids %s' % instance_ids)


def get_rds_instances(lookup_filter=''):
    lookup_cmd = "rds describe-db-instances %s" % lookup_filter
    db_instances = aws_command(lookup_cmd)
    return db_instances['DBInstances']


def get_rds_instances_by_id(instance_ids=None):
    if not instance_ids:
        return None

    if isinstance(instance_ids, list):
        instance_ids = ' '.join(instance_ids)

    return get_rds_instances('--db-instance-identifier %s' % instance_ids)


def get_security_groups(lookup_filter=''):
    if isinstance(lookup_filter, list):
        r = []
        for l in lookup_filter:
            s = get_security_groups("--group-ids %s" % l)
            r += s
        return r

    lookup_cmd = "ec2 describe-security-groups %s" % lookup_filter
    security_groups = aws_command(lookup_cmd)
    return security_groups['SecurityGroups']


def get_routetables(lookup_filter=''):
    lookup_cmd = "ec2 describe-route-tables %s" % lookup_filter
    rtb = aws_command(lookup_cmd)
    return rtb['RouteTables']


def get_routetables_by_id(routetable_ids=None):
    if not routetable_ids:
        return None

    if isinstance(routetable_ids, list):
        routetable_ids = ' '.join(routetable_ids)

    return get_routetables("--route-table-ids %s" % routetable_ids)


def get_routetables_by_subnet_id(subnet_ids=None):
    if not subnet_ids:
        return None

    if isinstance(subnet_ids, list):
        subnet_ids = ','.join(subnet_ids)

    return get_routetables("--filters Name=association.subnet-id,Values=%s" % subnet_ids)


def get_network_acl(lookup_filter=''):
    if isinstance(lookup_filter, list):
        r = []
        for l in lookup_filter:
            s = get_network_acl("--network-acl-ids %s" % l)
            r += s
        return r
    lookup_cmd = "ec2 describe-network-acls %s" % lookup_filter
    nacl = aws_command(lookup_cmd)
    return nacl['NetworkAcls']


def get_network_acl_by_subnet_id(subnet_ids=None):
    if not subnet_ids:
        return None

    if isinstance(subnet_ids, list):
        subnet_ids = ','.join(subnet_ids)

    return get_network_acl("--filters Name=association.subnet-id,Values=%s" % subnet_ids)


def get_elb_rules(_id, fh):
    elb = get_load_balancers_by_name(_id)[0]
    elb_node = """
    "%s_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
    <!--
    <tr>
    <td bgcolor="black" align="center" colspan="2"><font color="white">%s_rules</font></td>
    </tr>
    -->
    <tr>
    <td bgcolor="black" align="center"><font color="white">Target</font></td>
    <td bgcolor="black" align="center">
      <font color="white">Destination</font>
    </td>
    </tr>
    """ % (_id, _id)
    for l in elb['ListenerDescriptions']:
        _in = l['Listener']['LoadBalancerPort']
        _out = l['Listener']['InstancePort']
        rule_html = """
        <tr>
        <td align="right">%s/TCP</td>
        <td align="right">%s/TCP</td>
        </tr>
        """ % (_in, _out)
        elb_node += rule_html

    elb_node += "</table>>];"
    fh.write(elb_node)


def get_rtb_rules(_id, fh):
    _id = _id[0]
    rtb = get_routetables_by_id(_id)[0]
    rtb_node = """
"%s_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
    <!--
    <tr>
       <td bgcolor="black" align="center" colspan="2"><font color="white">%s_rules</font></td>
    </tr>
    -->
  <tr>
    <td bgcolor="black" align="center"><font color="white">source</font></td>
    <td bgcolor="black" align="center">
      <font color="white">desitination</font>
    </td>
  </tr>
    """ % (_id, _id)

    for route in rtb['Routes']:
        rule_html = """
        <tr>
        <td align="right">%s</td>
        <td align="right">%s</td>
        </tr>
        """ % (route.get('GatewayId', 'N/A'), route["DestinationCidrBlock"])
        rtb_node += rule_html

    rtb_node += "</table>>];"
    fh.write(rtb_node)


def get_sg_rules(_id, fh, direction=None, combine=True):
    mutiple_sg = False
    sg_field_tr = ''
    if len(_id) > 1:
        sg_field_tr = '<td bgcolor="black" align="center"><font color="white">SG</font></td>'
        mutiple_sg = True

    _id = ' '.join(_id)
    sg_list = get_security_groups("--group-ids %s" % _id)
    _id = _id.replace(' ', '_')

    ingress_node = """
    "%s_in_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
        <tr>
          <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
          <td bgcolor="black" align="center"><font color="white">Ports</font></td>
          %s
        </tr>
    """ % (_id, sg_field_tr)

    egress_node = """
        "%s_out_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
        <tr>
          <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
          <td bgcolor="black" align="center"><font color="white">Ports</font></td>
          %s
        </tr>
    """ % (_id, sg_field_tr)

    for sg in sg_list:
        for i in sg['IpPermissions']:
            portrange = "TCP/UDP/ICMP"
            if 'FromPort' in i:
                portrange = "%s-%s/%s" % (
                    i['FromPort'], i['ToPort'], i['IpProtocol'].upper()
                )
            ips = [x['CidrIp'] for x in i['IpRanges']]
            # fh.write(" //\n", i)
            if not ips:
                ips = [x['GroupId'] for x in i['UserIdGroupPairs']]
            ips = "<Br />".join(ips)

            sg_id = ''
            if mutiple_sg:
                sg_id = '<td>%s</td>' % sg['GroupId']

            rule_html = """
            <tr>
            <td bgcolor="green" align="left">%s</td>
            <td align="right">%s</td>
            %s
            </tr>
            """ % (ips, portrange, sg_id)
            ingress_node += rule_html

        for i in sg['IpPermissionsEgress']:
            portrange = "TCP/UDP/ICMP"
            if 'FromPort' in i:
                portrange = "%s-%s/%s" % (
                    i['FromPort'], i['ToPort'], i['IpProtocol'].upper()
                )
            ips = [x['CidrIp'] for x in i['IpRanges']]
            if not ips:
                ips = [x['GroupId'] for x in i['UserIdGroupPairs']]
            ips = "<Br />".join(ips)
            sg_id = ''
            if mutiple_sg:
                sg_id = '<td>%s</td>' % sg['GroupId']
            rule_html = """
            <tr>
            <td bgcolor="green" align="left">%s</td>
            <td align="right">%s</td>
            %s
            </tr>
            """ % (ips, portrange, sg_id)
            egress_node += rule_html

    ingress_node += "</table>>];"
    egress_node += "</table>>];"

    if direction == "ingress":
        fh.write(ingress_node)
    elif direction == "egress":
        fh.write(egress_node)
    else:
        fh.write(ingress_node)
        fh.write(egress_node)


def get_nacl_rules(_id, fh, direction=None):
    if isinstance(_id, list):
        acl_list = get_network_acl(_id)
    else:
        acl_list = get_network_acl("--network-acl-ids %s" % _id)

    # _id = _id.replace(' ', '_')

    ingress = []
    egress = []

    for acl in acl_list:
        ingress_node = """
"%s_in_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<<table border="1" cellborder="0" cellpadding="3" bgcolor="white">
  <tr>
      <td bgcolor="black" align="center" colspan="3"><font color="white">%s_in_rules</font></td>
  </tr>
  <tr>
      <td bgcolor="black" align="center"><font color="white">Rule #</font></td>
      <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
      <td bgcolor="black" align="center"><font color="white">Ports</font></td>
  </tr>
    """ % ("_".join(_id), "_".join(_id))

        egress_node = """

"%s_out_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<<table border="1" cellborder="0" cellpadding="3" bgcolor="white">
  <tr>
      <td bgcolor="black" align="center" colspan="3"><font color="white">%s_out_rules</font></td>
  </tr>
  <tr>
      <td bgcolor="black" align="center"><font color="white">Rule #</font></td>
      <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
      <td bgcolor="black" align="center"><font color="white">Ports</font></td>
  </tr>
    """ % ("_".join(_id), "_".join(_id))

        P_MAP = {
            '6': 'TCP',
            '17': 'UDP'
        }
        for e in acl['Entries']:
            portrange = "TCP/UDP/ICMP"
            if "PortRange" in e:
                protocol = P_MAP[e['Protocol']]
                portrange = "%d-%d/%s" % (
                    e['PortRange']['From'], e['PortRange']['To'], protocol
                )
            rule = "%s %s %s %s" % (
                e['RuleNumber'], e['RuleAction'], e['CidrBlock'], portrange
            )
            rule_color = "red"
            if e['RuleAction'] == "allow":
                rule_color = "green"
            rule_html = """
            <tr>
            <td bgcolor="%s" align="left">%s</td>
            <td align="right">%s</td>
            <td align="right">%s</td>
            </tr>
            """ % (rule_color, e['RuleNumber'], e['CidrBlock'], portrange)

            if e['Egress']:
                egress.append(rule)
                egress_node += rule_html
            else:
                ingress.append(rule)
                ingress_node += rule_html

        egress_node += "</table>>];"
        ingress_node += "</table>>];"

        if direction == "ingress":
            fh.write(ingress_node)
        elif direction == "egress":
            fh.write(egress_node)
        else:
            fh.write(ingress_node)
            fh.write(egress_node)

    return ingress_node, egress_node


@contextmanager
def generateSubgraph(fh, **kwargs):
    generateSubgraph.counter += 1
    label = kwargs.get('label', "Subnet #%d" % generateSubgraph.counter)
    fh.write("subgraph cluster_%d {\n" % generateSubgraph.counter)
    fh.write('label = "%s"\n' % label)
    yield
    fh.write("}\n")

generateSubgraph.counter = 0


def generateSubnet(layer, fh, **kwargs):
    endpoint = kwargs.get('endpoint', None)
    label = kwargs.get('label', '')
    label += "\\n".join(layer["subnets"])

    with generateSubgraph(fh, label=label):
        fh.write('"l%(count)d_%(source)s_in" -> "l%(count)d_%(target)s_in";\n' % {
            'count': generateSubgraph.counter,
            'source': "_".join(layer["nacl"]),
            'target': "_".join(layer["securitygroups"])
        })

        fh.write('"l%(count)d_%(nodename)s_in" [label="Network ACL (inbound)\\n%(nodelabel)s"];\n' % {
            'count': generateSubgraph.counter,
            'nodename': "_".join(layer["nacl"]),
            'nodelabel': " ".join(layer["nacl"])
        })
        fh.write('"l%(count)d_%(nodename)s_out" [label="Network ACL (outbound)\\n%(nodelabel)s"];\n' % {
            'count': generateSubgraph.counter,
            'nodename': "_".join(layer["nacl"]),
            'nodelabel': " ".join(layer["nacl"])
        })
        fh.write('"l%(count)d_%(nodename)s_in" [label="Security Group (inbound)\\n%(nodelabel)s"];\n' % {
            'count': generateSubgraph.counter,
            'nodename': "_".join(layer["securitygroups"]),
            'nodelabel': "\\n".join(layer["securitygroups"]),
        })
        fh.write('"l%(count)d_%(nodename)s_out" [label="Security Group (outbound)\\n%(nodelabel)s"];\n' % {
            'count': generateSubgraph.counter,
            'nodename': "_".join(layer["securitygroups"]),
            'nodelabel': "\\n".join(layer["securitygroups"]),
        })

        fh.write('"l%(count)d_%(source)s_in" -> "l%(count)d_%(target)s";\n' % {
            'count': generateSubgraph.counter,
            'source': "_".join(layer["securitygroups"]),
            'target': endpoint
        })
        fh.write('"l%(count)d_%(source)s" -> "l%(count)d_%(target)s_out";\n' % {
            'count': generateSubgraph.counter,
            'source': endpoint,
            'target': "_".join(layer["securitygroups"])
        })

        fh.write('"l%(count)d_%(source)s_out" -> "l%(count)d_%(target)s_out";\n' % {
            'count': generateSubgraph.counter,
            'source': "_".join(layer["securitygroups"]),
            'target': "_".join(layer["nacl"])
        })

        fh.write('"l%(count)d_%(nodename)s" [label="%(nodename)s"];\n' % {
            'count': generateSubgraph.counter,
            'nodename': endpoint
        })

        rule_map = [
            "%s_in" % "_".join(layer["nacl"]),
            "%s_in" % "_".join(layer["securitygroups"]),
            endpoint,
            "%s_out" % "_".join(layer["securitygroups"]),
            "%s_out" % "_".join(layer["nacl"]),
        ]

        for rule in rule_map:
            fh.write('"l%(count)d_%(rule)s" -> "%(rule)s_rules";\n' % {
                'count': generateSubgraph.counter,
                'rule': rule
            })
            fh.write('{rank=same; "l%(count)d_%(rule)s" "%(rule)s_rules"};\n' % {
                'count': generateSubgraph.counter,
                'rule': rule
            })

    get_sg_rules(layer["securitygroups"], fh=fh)
    get_nacl_rules(layer["nacl"], fh=fh)


###############################################################################
def generateRouters(routetable, fh, **kwargs):
    source = kwargs.get('source', None)
    target = kwargs.get('target', None)

    if not source:
        return

    with generateSubgraph(fh, label="Routers"):
        rt = "_".join(routetable['routetable'])

        fh.write('"l%(count)d_%(source)s_out" -> "%(target)s";\n' % {
            'count': generateSubgraph.counter - 1,
            'source': "_".join(source["nacl"]),
            'target': rt,
        })

        fh.write('"%s" -> "%s_rules";\n' % (rt, rt))
        fh.write('{rank=same; "%s" "%s_rules"};\n' % (rt, rt))
        fh.write('"%s" [label="Route Tables\\n%s"];\n' % (
            rt,
            "\\n".join(routetable['routetable']),
        ))

    if target:
        fh.write('"%(source)s" -> "l%(count)d_%(target)s_in";\n' % {
            'count': generateSubgraph.counter + 1,
            'source': "_".join(routetable['routetable']),
            'target': "_".join(target["nacl"]),
        })

    get_rtb_rules(routetable['routetable'], fh=fh)


###############################################################################
def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--profile',
                        default=None,
                        help="AWS CLI profile to be used")
    parser.add_argument('--elb',
                        default=None,
                        help="Which ELB to examine")
    parser.add_argument('--ec2',
                        default=None,
                        help="Which EC2 to examine")
    parser.add_argument('--rds',
                        default=None,
                        help="Which RDS to attach")
    parser.add_argument('-b', '--bypass-cache',
                        default=False,
                        action="store_true",
                        help="Invalidate cache and re-pull the data.")
    parser.add_argument('-o', '--output',
                        default=sys.stdout,
                        type=argparse.FileType('w'),
                        help="Which file to output to [stdout]")
    parser.add_argument('-v', '--verbose',
                        default=False,
                        action='store_true',
                        help="Print some details")
    args = parser.parse_args()
    return args


###############################################################################
def collectElbData(elb):
    data = defaultdict(list)
    mappings = []
    for l in elb['ListenerDescriptions']:
        m = "%s:%s" % (l['Listener']['LoadBalancerPort'],
                       l['Listener']['InstancePort'])
        mappings.append(m)

    data['subnets'] = elb['Subnets']
    data['securitygroups'] = elb['SecurityGroups']
    data['mappings'] = mappings
    data['endpoint'] = elb['LoadBalancerName']

    # Network ACL
    nacl = get_network_acl_by_subnet_id(data['subnets'])
    data['nacl_raw'] = nacl
    data['nacl'] = [x['NetworkAclId'] for x in nacl]

    return data


def collectRoutetableData(subnets):
    data = defaultdict(list)

    # Route table
    routetables = get_routetables_by_subnet_id(subnets)
    data['routetable_raw'] = routetables
    data['routetable'] = [x['RouteTableId'] for x in routetables]

    return data


def collectEc2Data(instances):
    data = defaultdict(list)
    data['instances'] = instances

    instances = get_ec2_instances_by_id(instances)
    data['instances_raw'] = instances

    for i in instances:
        securitygroups = [x['GroupId'] for x in i['SecurityGroups']]
        subnets = [i['SubnetId']]

        data['subnets'] += subnets
        data['securitygroups'] += securitygroups
        data['instances'].append(i['InstanceId'])

        # Network ACL
        nacl = get_network_acl_by_subnet_id(subnets)
        data['nacl_raw'] += nacl
        data['nacl'] += [x['NetworkAclId'] for x in nacl]

    data['instances'] = list(set(data['instances']))
    data['subnets'] = list(set(data['subnets']))
    data['securitygroups'] = list(set(data['securitygroups']))

    return data


def collectRdsData(instances):
    data = defaultdict(list)
    data['instances'] = instances

    instances = get_rds_instances_by_id(instances)

    for instance in instances:
        securitygroups = [sg['VpcSecurityGroupId']
                          for sg in instance['VpcSecurityGroups']]
        subnets = [subnet['SubnetIdentifier']
                   for subnet in instance['DBSubnetGroup']['Subnets']]

        data['subnets'] += subnets
        data['securitygroups'] += securitygroups

        nacl = get_network_acl_by_subnet_id(subnets)
        data['nacl_raw'] += nacl
        data['nacl'] += [x['NetworkAclId'] for x in nacl]

    data['instances'] = list(set(data['instances']))
    data['subnets'] = list(set(data['subnets']))
    data['securitygroups'] = list(set(data['securitygroups']))

    return data


###############################################################################
def generateGroups(layer1, layer2, fh):
    # Not currently used
    groups_html = """
    "all_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
    <tr>
       <td bgcolor="black" align="center">
         <font color="white">section</font>
       </td>
       <td bgcolor="black" align="center"><font color="white">items</font></td>
    </tr>
  <tr>
      <td>Public Network ACL</td>
      <td>%s</td>
  </tr>
  <tr>
      <td>Public Security Groups</td>
      <td>%s</td>
  </tr>
  <tr>
      <td>Public ELB</td>
      <td>%s</td>
  </tr>
  <tr>
      <td>Public to Private Routes</td>
      <td>%s</td>
  </tr>
  <tr>
      <td>Private Network ACL</td>
      <td>%s</td>
  </tr>
  <tr>
      <td>Private Security Groups</td>
      <td>%s</td>
  </tr>
  <tr>
      <td>Private Instances</td>
      <td>%s</td>
  </tr>
  </table>
    >];
    """ % (
        " ".join(layer1["nacl"]),
        " ".join(layer1["securitygroups"]),
        layer1["endpoint"],
        " ".join(layer1['routetable']),
        " ".join(layer2["nacl"]),
        " ".join(layer2["securitygroups"]),
        layer2["instances"]
    )
    return groups_html


###############################################################################
@contextmanager
def generateGraph(fh):
    fh.write("digraph g {\n")
    fh.write('node [margin=0 width=0.5 shape="plaintext"]\n')
    yield
    fh.write("}\n")


###############################################################################
def displayElbList(fh):
    fh.write("ELB List:\n")

    for elb in get_load_balancers():
        elbname = elb['LoadBalancerName']
        fh.write("- %s\n" % elbname)


def displayEc2List(fh):
    fh.write("EC2 List:\n")

    for ec2instance in get_ec2_instances():
        fh.write("- %s %s\n" % (ec2instance['InstanceId'], getEc2Name(ec2instance)))


def displayRdsList(fh):
    fh.write("RDS List:\n")

    for rds_instance in get_rds_instances():
        fh.write("- %s\n" % rds_instance['DBInstanceIdentifier'])


def getEc2Name(ec2instance):
    for tag in ec2instance['Tags']:
        if tag['Key'] == 'Name':
            return tag['Value']


def getEc2RdsId(ec2instances):
    for instance in ec2instances:
        for tag in instance['Tags']:
            if tag['Key'] in database_keys:
                return tag['Value']

            jsondata = parse_json(tag['Value'])

            if jsondata:
                for k, v in jsondata.iteritems():
                    if k in database_keys:
                        return v


def isEc2Terminated(ec2instance):
    return ec2instance['State']['Code'] == 48


###############################################################################
def main():
    args = parseArgs()
    global verbose, bypass_cache

    verbose = args.verbose
    bypass_cache = args.bypass_cache
    fh = args.output

    if args.profile:
        aws_flags.extend(['--profile', args.profile])

    if args.elb is None and args.ec2 is None:
        displayElbList(fh)
        displayEc2List(fh)
        displayRdsList(fh)
        sys.exit(0)

    with generateGraph(fh):
        routetable_data = None
        ec2_instances = [args.ec2]

        if args.elb:
            elb = get_load_balancers_by_name(args.elb)[0]
            elb_data = collectElbData(elb)
            ec2_instances = [ec2instance['InstanceId']
                             for ec2instance in elb['Instances']]

            get_elb_rules(elb_data["endpoint"], fh=fh)

            generateSubnet(elb_data,
                           fh,
                           label="Public Subnet\n",
                           endpoint=elb_data["endpoint"])

            routetable_data = collectRoutetableData(elb_data['subnets'])

        ec2_data = collectEc2Data(ec2_instances)

        if routetable_data:
            generateRouters(routetable_data,
                            fh,
                            source=elb_data,
                            target=ec2_data)

        generateSubnet(ec2_data,
                       fh,
                       label="Private Subnet\n",
                       endpoint=ec2_data["instances"])

        rds = args.rds if args.rds else getEc2RdsId(ec2_data['instances_raw'])

        if rds:
            # only show RDS flow if we match with an RDS in AWS
            match = False
            for rds_instance in get_rds_instances():
                if rds_instance['DBInstanceIdentifier'] == rds:
                    match = True
                    rds_data = collectRdsData([rds])
                    routetable_data = collectRoutetableData(ec2_data['subnets'])

                    generateRouters(routetable_data,
                                    fh,
                                    source=ec2_data,
                                    target=rds_data)

                    generateSubnet(rds_data,
                                   fh,
                                   label="Database Subnet\n",
                                   endpoint=rds_data["instances"])

            if not match:
                echo("Sorry, '%s' does not appear to be an RDS." % (rds))


###############################################################################
if __name__ == '__main__':
    main()

# EOF
