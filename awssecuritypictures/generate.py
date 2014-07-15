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
#from pprint import pprint
from collections import defaultdict

aws_flags = ['--no-verify-ssl']

def echo(message, stderr=True):
    if not verbose: return

    stream = sys.stderr if stderr else sys.stdout;
    stream.write(message)


def aws_command(cmd):
    os.popen('mkdir -p /tmp/aws-cache').read()
    safe_cmd = "/tmp/aws-cache/%s" % cmd.replace(' ', '_')

    echo("%s" % cmd)

    if os.path.exists(safe_cmd):
        echo(" HIT\n")

        with open(safe_cmd, 'r') as jsonfile:
            raw_json = json.load(jsonfile)
            return raw_json

    echo(" MISS\n")

    aws_cmd = "aws %s %s" % (" ".join(aws_flags), cmd)
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


def get_ec2_instances(lookup_filter=''):
    lookup_cmd = "ec2 describe-instances %s" % lookup_filter
    ec2_instances = aws_command(lookup_cmd)
    return ec2_instances['Reservations']


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


def get_elb_rules(_id, fh):
    elb = get_load_balancers("--load-balancer-names %s" % _id)[0]
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
    <td bgcolor="black" align="center"><font color="white">Destination</font></td>
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
    rtb = get_routetables("--route-table-ids %s" % _id[0])[0]

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
      <td bgcolor="black" align="center"><font color="white">desitination</font></td>
  </tr>
    """ % (_id[0], _id[0])

    for route in rtb['Routes']:
        rule_html = """
        <tr>
        <td align="right">%s</td>
        <td align="right">%s</td>
        </tr>
        """ % (route["GatewayId"], route["DestinationCidrBlock"])
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
            #fh.write(" //\n", i)
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

    #_id = _id.replace(' ', '_')

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


###############################################################################
def generatePrivateSubnet(subgraph, layer1, layer2, fh):
    fh.write("subgraph cluster_3 {\n")

    fh.write('"%s" -> "l2_%s_in";\n' % (
        "_".join(layer1["routetable"]),
        "_".join(layer2["nacl"]),
    ))

    rule_map = [
        '%s_in' % '_'.join(layer2['nacl']),
        '%s_in' % '_'.join(layer2['securitygroups']),
        #'%s' % layer2['instances'],
        '%s_out' % '_'.join(layer2['securitygroups']),
        '%s_out' % '_'.join(layer2['nacl']),
    ]

    fh.write('"l2_%s_in" -> "l2_%s_in";\n' % (
        '_'.join(layer2['nacl']),
        '_'.join(layer2['securitygroups'])
    ))
    fh.write('"l2_%s_in" -> "l2_%s";\n' % (
        '_'.join(layer2['securitygroups']),
        " ".join(layer2['instances'])
    ))
    fh.write('"l2_%s" [label="Instances\\n%s"];\n' % (
        " ".join(layer2['instances']),
        "\\n".join(layer2['instances'])
    ))

    fh.write('"l2_%s" -> "l2_%s_out";\n' % (
        " ".join(layer2['instances']),
        '_'.join(layer2['securitygroups']),
    ))
    fh.write('"l2_%s_out" -> "l2_%s_out";\n' % (
        '_'.join(layer2['securitygroups']),
        '_'.join(layer2['nacl']),
    ))

    for item in rule_map:
        fh.write('"l2_%s" -> "%s_rules";\n' % (item, item))
        fh.write('{rank=same; "l2_%s" "%s_rules"};\n' % (item, item))

    fh.write('label = "Private Subnet\\n%s"\n' % "\\n".join(layer2["subnets"]))

    fh.write('"l2_%s_in" [label="Network ACL (inbound)\\n%s"];\n' % (
        "_".join(layer2["nacl"]),
        " ".join(layer2["nacl"])
    ))
    fh.write('"l2_%s_out" [label="Network ACL (outbound)\\n%s"];\n' % (
        "_".join(layer2["nacl"]),
        " ".join(layer2["nacl"])
    ))
    fh.write('"l2_%s_in" [label="Security Group (inbound)\\n%s"];\n' % (
        "_".join(layer2["securitygroups"]),
        "\\n".join(layer2["securitygroups"]),
    ))
    fh.write('"l2_%s_out" [label="Security Group (outbound)\\n%s"];\n' % (
        "_".join(layer2["securitygroups"]),
        "\\n".join(layer2["securitygroups"]),
    ))

    fh.write("}\n")


###############################################################################
def generatePublicSubnet(subgraph, layer1, layer2, fh):
    rule_map = [
        "%s_in" % "_".join(layer1["nacl"]),
        "%s_in" % "_".join(layer1["securitygroups"]),
        "%s" % layer1["endpoint"],
        "%s_out" % "_".join(layer1["securitygroups"]),
        "%s_out" % "_".join(layer1["nacl"]),
    ]
    fh.write("subgraph cluster_%s {\n" % subgraph)
    fh.write('"l1_%s_in" -> "l1_%s_in";\n' % ("_".join(layer1["nacl"]),
                                     "_".join(layer1["securitygroups"])))

    fh.write('"l1_%s_in" [label="Network ACL (inbound)\\n%s"];\n' % (
        "_".join(layer1["nacl"]),
        " ".join(layer1["nacl"])
    ))
    fh.write('"l1_%s_out" [label="Network ACL (outbound)\\n%s"];\n' % (
        "_".join(layer1["nacl"]),
        " ".join(layer1["nacl"])
    ))
    fh.write('"l1_%s_in" [label="Security Group (inbound)\\n%s"];\n' % (
        "_".join(layer1["securitygroups"]),
        "\\n".join(layer1["securitygroups"]),
    ))
    fh.write('"l1_%s_out" [label="Security Group (outbound)\\n%s"];\n' % (
        "_".join(layer1["securitygroups"]),
        "\\n".join(layer1["securitygroups"]),
    ))

    fh.write('"l1_%s_in" -> "l1_%s";\n' % (
        "_".join(layer1["securitygroups"]),
        layer1["endpoint"]
    ))
    fh.write('"l1_%s" -> "l1_%s_out";\n' % (
        layer1["endpoint"],
        "_".join(layer1["securitygroups"])
    ))

    fh.write('"l1_%s_out" -> "l1_%s_out";\n' % (
        "_".join(layer1["securitygroups"]),
        "_".join(layer1["nacl"])
    ))

    get_sg_rules(layer1["securitygroups"], fh=fh)

    fh.write('"l1_%s" [label="%s"];\n' % (
        layer1["endpoint"],
        layer1["endpoint"]
    ))

    for item in rule_map:
        fh.write('"l1_%s" -> "%s_rules";\n' % (item, item))
        fh.write('{rank=same; "l1_%s" "%s_rules"};\n' % (item, item))

    fh.write('label = "Public Subnet\\n%s"\n' % "\\n".join(layer1["subnets"]))
    fh.write("}\n")


###############################################################################
def generateRouters(subgraph, layer1, layer2, fh):
    rt = "_".join(layer1["routetable"])

    fh.write("subgraph cluster_%s {\n" % subgraph)
    fh.write('"l1_%s_out" -> "%s";\n' % (
        "_".join(layer1["nacl"]),
        rt,
    ))
    fh.write('"%s" -> "%s_rules";\n' % (rt, rt))
    fh.write('{rank=same; "%s" "%s_rules"};\n' % (rt, rt))
    fh.write('label = "Routers"\n')
    fh.write('"%s" [label="Route Tables\\n%s"];\n' % (
        rt,
        "\\n".join(layer1["routetable"]),
    ))
    fh.write("}\n")


###############################################################################
def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('--elb', default=None, help="Which ELB to examine [all]")
    parser.add_argument('--output', default=sys.stdout, type=argparse.FileType('w'), help="Which file to output to [stdout]")
    parser.add_argument('-v', '--verbose', default=False, action='store_true', help="Print some details")
    args = parser.parse_args()
    return args


###############################################################################
def collectLayer1(elb):
    data = defaultdict(list)
    mappings = []
    for l in elb['ListenerDescriptions']:
        m = "%s:%s" % (l['Listener']['LoadBalancerPort'], l['Listener']['InstancePort'])
        mappings.append(m)

    data['subnets'] = elb['Subnets']
    data['securitygroups'] = elb['SecurityGroups']
    data['mappings'] = mappings
    data['endpoint'] = elb['LoadBalancerName']

    subnets_csv = ",".join(data['subnets'])

    # Route table
    routetables = get_routetables("--filters Name=association.subnet-id,Values=%s" % subnets_csv)
    data['routetable_raw'] = routetables
    data['routetable'] = [x['RouteTableId'] for x in routetables]

    # Network ACL
    nacl = get_network_acl("--filters Name=association.subnet-id,Values=%s" % subnets_csv)
    data['nacl_raw'] = nacl
    data['nacl'] = [x['NetworkAclId'] for x in nacl]

    return data


###############################################################################
def collectLayer2(elb):
    data = defaultdict(list)
    # Instances
    instances = [x['InstanceId'] for x in elb['Instances']]
    data['instances'] = instances

    instance_filter = "--instance-ids %s" % " ".join(instances)
    instances = get_ec2_instances(instance_filter)
    data['instances_raw'] = instances

    for i in instances:
        i = i['Instances'][0]
        securitygroups = [x['GroupId'] for x in i['SecurityGroups']]
        subnets = [i['SubnetId']]

        data['subnets'] += subnets
        data['securitygroups'] += securitygroups
        data['instances'].append(i['InstanceId'])

        # Network ACL
        subnets_csv = ",".join(subnets)
        nacl = get_network_acl("--filters Name=association.subnet-id,Values=%s" % subnets_csv)
        data['nacl_raw'] += nacl
        data['nacl'] += [x['NetworkAclId'] for x in nacl]

    data['securitygroups'] = list(set(data['securitygroups']))
    data['instances'] = list(set(data['instances']))

    return data


###############################################################################
def generateGroups(layer1, layer2, fh):
    # Not currently used
    groups_html = """
    "all_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
    <tr>
       <td bgcolor="black" align="center"><font color="white">section</font></td>
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


###############################################################################
def generateHeader(fh):
    fh.write("digraph g {\n")
    fh.write('node [margin=0 width=0.5 shape="plaintext"]\n')


###############################################################################
def generateFooter(fh):
    fh.write("}\n")


###############################################################################
def displayElbList(fh):
    for elb in get_load_balancers():
        elbname = elb['LoadBalancerName']
        fh.write("%s\n" % elbname)


###############################################################################
def main():
    args = parseArgs()
    global verbose
    verbose = args.verbose
    fh = args.output

    if args.elb is None:
        displayElbList(fh)
        return

    for elb in get_load_balancers():
        elbname = elb['LoadBalancerName']
        if args.elb != elbname:
            continue
        if not elb['Scheme'] == 'internet-facing':
            continue
        layer_1 = collectLayer1(elb)
        layer_2 = collectLayer2(elb)

    generateHeader(fh)
    generatePublicSubnet('1', layer_1, layer_2, fh=fh)
    generateRouters('2', layer_1, layer_2, fh=fh)
    generatePrivateSubnet('3', layer_1, layer_2, fh=fh)

    get_sg_rules(layer_2["securitygroups"], fh=fh)
    get_rtb_rules(layer_1["routetable"], fh=fh)
    get_nacl_rules(layer_1["nacl"], fh=fh)
    get_nacl_rules(layer_2["nacl"], fh=fh)
    get_elb_rules(layer_1["endpoint"], fh=fh)
    generateFooter(fh)


###############################################################################
if __name__ == '__main__':
    main()

#EOF
