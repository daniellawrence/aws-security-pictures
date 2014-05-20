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
#from pprint import pprint
from collections import defaultdict


def get_load_balancers(lookup_filter=''):
    lookup_cmd = "aws elb describe-load-balancers %s" % lookup_filter
    raw_load_balancers = os.popen(lookup_cmd).read()
    load_balancers = json.loads(raw_load_balancers)
    return load_balancers['LoadBalancerDescriptions']


def get_ec2_instances(lookup_filter=''):
    lookup_cmd = "aws ec2 describe-instances %s" % lookup_filter
    raw_ec2_instances = os.popen(lookup_cmd).read()
    ec2_instances = json.loads(raw_ec2_instances)
    return ec2_instances['Reservations']


def get_security_groups(lookup_filter=''):
    if isinstance(lookup_filter, list):
        r = []
        for l in lookup_filter:
            s = get_security_groups("--group-ids %s" % l)
            r += s
        return r

    lookup_cmd = "aws ec2 describe-security-groups %s" % lookup_filter
    raw_security_groups = os.popen(lookup_cmd).read()
    security_groups = json.loads(raw_security_groups)
    return security_groups['SecurityGroups']


def get_routetables(lookup_filter=''):
    lookup_cmd = "aws ec2 describe-route-tables %s" % lookup_filter
    raw_security_groups = os.popen(lookup_cmd).read()
    security_groups = json.loads(raw_security_groups)
    return security_groups['RouteTables']


def get_network_acl(lookup_filter=''):
    if isinstance(lookup_filter, list):
        r = []
        for l in lookup_filter:
            s = get_network_acl("--network-acl-ids %s" % l)
            r += s
        return r
    lookup_cmd = "aws ec2 describe-network-acls %s" % lookup_filter
    raw_security_groups = os.popen(lookup_cmd).read()
    security_groups = json.loads(raw_security_groups)
    return security_groups['NetworkAcls']


def get_elb_rules(_id):
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
    print elb_node


def get_rtb_rules(_id):
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
    print rtb_node


def get_sg_rules(_id, direction=None, combine=True):

    _id = ' '.join(_id)

    sg_list = get_security_groups("--group-ids %s" % _id)
    _id = _id.replace(' ', '_')

    ingress_node = """
    "%s_in_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
    <!--
        <tr>
          <td bgcolor="black" align="center" colspan="2"><font color="white">%s_in_rules</font></td> 
       </tr>
    -->
        <tr>
          <td bgcolor="black" align="center"><font color="white">CIDR</font></td> 
          <td bgcolor="black" align="center"><font color="white">Ports</font></td>
        </tr>
    """ % (_id, _id)

    egress_node = """
        "%s_out_rules" [ style = "filled" penwidth = 0 fillcolor = "white" fontname = "Courier New" shape = "Mrecord" label =<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
    <!--
        <tr>
          <td bgcolor="black" align="center" colspan="2"><font color="white">%s_out_rules</font></td> 
       </tr>
    -->
        <tr>
          <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
          <td bgcolor="black" align="center"><font color="white">Ports</font></td>
        </tr>
    """ % (_id, _id)

    for sg in sg_list:

        for i in sg['IpPermissions']:
            portrange = "TCP/UDP/ICMP"
            if 'FromPort' in i:
                portrange = "%s-%s/%s" % (
                    i['FromPort'], i['ToPort'], i['IpProtocol'].upper()
                )
            ips = [x['CidrIp'] for x in i['IpRanges']]
            #print " //", i
            if not ips:
                ips = [x['GroupId'] for x in i['UserIdGroupPairs']]
            ips = "<Br />".join(ips)

            rule_html = """
            <tr>
            <td bgcolor="green" align="left">%s</td>
            <td align="right">%s</td>
            </tr>
            """ % (ips, portrange)
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
            rule_html = """
            <tr>
            <td bgcolor="green" align="left">%s</td>
            <td align="right">%s</td>
            </tr>
            """ % (ips, portrange)
            egress_node += rule_html
    ingress_node += "</table>>];"
    egress_node += "</table>>];"

    if direction == "ingress":
        print ingress_node
    elif direction == "egress":
        print egress_node
    else:
        print ingress_node
        print egress_node


def get_nacl_rules(_id, direction=None):
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
                portrange = "%d-%d/%s" %(
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
            print ingress_node
        elif direction == "egress":
            print egress_node
        else:
            print ingress_node
            print egress_node

    return ingress_node, egress_node


def main():
    load_balancers = get_load_balancers()

    layer_1 = defaultdict(list)
    layer_2 = defaultdict(list)

    ONLY_SHOW_ELBS = False

    if len(sys.argv) == 1:
        ONLY_SHOW_ELBS = True
    else:
        ONLY_SHOW_THIS_ELB = sys.argv[1]

    for elb in load_balancers:
        elbname = elb['LoadBalancerName']
        if ONLY_SHOW_ELBS:
            print elbname
            continue

        if ONLY_SHOW_THIS_ELB and ONLY_SHOW_THIS_ELB != elbname:
            continue

        if not elb['Scheme'] == 'internet-facing':
            continue
        subnets = elb['Subnets']
        instances = [x['InstanceId'] for x in elb['Instances']]
        securitygroups = elb['SecurityGroups']
        mappings = []
        for l in elb['ListenerDescriptions']:
            m = "%s:%s" % (l['Listener']['LoadBalancerPort'], l['Listener']['InstancePort'])
            mappings.append(m)

        elbname = elb['LoadBalancerName']

        layer_1['subnets'] = subnets
        layer_1['securitygroups'] = securitygroups
        layer_1['mappings'] = mappings
        layer_1['endpoint'] = elbname
        subnets_csv = ",".join(subnets)

        # Route table
        routetables = get_routetables("--filters Name=association.subnet-id,Values=%s" % subnets_csv)
        layer_1['routetable_raw'] = routetables
        layer_1['routetable'] = [x['RouteTableId'] for x in routetables]

        # Network ACL
        nacl = get_network_acl("--filters Name=association.subnet-id,Values=%s" % subnets_csv)
        layer_1['nacl_raw'] = nacl
        layer_1['nacl'] = [x['NetworkAclId'] for x in nacl]
        # Instances
        layer_2['instances'] = instances

    if ONLY_SHOW_ELBS:
        sys.exit(0)

    instance_filter = "--instance-ids %s" % " ".join(layer_2['instances'])
    instances = get_ec2_instances(instance_filter)

    for i in instances:
        i = i['Instances'][0]
        securitygroups = [x['GroupId'] for x in i['SecurityGroups']]
        subnets = [i['SubnetId']]

        layer_2['subnets'] += subnets
        layer_2['securitygroups'] += securitygroups
        layer_2['instances'].append(i['InstanceId'])
        layer_2['instances_raw'] += instances

        # Network ACL
        subnets_csv = ",".join(subnets)
        nacl = get_network_acl("--filters Name=association.subnet-id,Values=%s" % subnets_csv)
        layer_2['nacl_raw'] += nacl
        layer_2['nacl'] += [x['NetworkAclId'] for x in nacl]

    layer_2['securitygroups'] = list(set(layer_2['securitygroups']))
    layer_2['instances'] = list(set(layer_2['instances']))

    rule_map = [
        "%s_in" % "_".join(layer_1["nacl"]),
        "%s_in" % "_".join(layer_1["securitygroups"]),
        "%s" % layer_1["endpoint"],
        "%s_out" % "_".join(layer_1["securitygroups"]),
        "%s_out" % "_".join(layer_1["nacl"]),
    ]

    print "digraph g {"
    print 'node [margin=0 width=0.5 shape="plaintext"]'

    print "subgraph cluster_1 {"
    print '"l1_%s_in" -> "l1_%s_in";' % ("_".join(layer_1["nacl"]),
                                     "_".join(layer_1["securitygroups"]))

    print '"l1_%s_in" [label="Network ACL (inbound)\\n%s"];' % (
        "_".join(layer_1["nacl"]),
        " ".join(layer_1["nacl"])
    )
    print '"l1_%s_out" [label="Network ACL (outbound)\\n%s"];' % (
        "_".join(layer_1["nacl"]),
        " ".join(layer_1["nacl"])
    )
    print '"l1_%s_in" [label="Security Group (inbound)\\n%s"];' % (
        "_".join(layer_1["securitygroups"]),
        "\\n".join(layer_1["securitygroups"]),
    )
    print '"l1_%s_out" [label="Security Group (outbound)\\n%s"];' % (
        "_".join(layer_1["securitygroups"]),
        "\\n".join(layer_1["securitygroups"]),
    )

    print '"l1_%s_in" -> "l1_%s";' % (
        "_".join(layer_1["securitygroups"]),
        layer_1["endpoint"]
    )
    print '"l1_%s" -> "l1_%s_out";' % (
        layer_1["endpoint"],
        "_".join(layer_1["securitygroups"])
    )

    print '"l1_%s_out" -> "l1_%s_out";' % (
        "_".join(layer_1["securitygroups"]),
        "_".join(layer_1["nacl"])
    )

    get_sg_rules(layer_1["securitygroups"])

    print '"l1_%s" [label="%s"];' % (
        layer_1["endpoint"],
        layer_1["endpoint"]
    )

    for item in rule_map:
        print '"l1_%s" -> "%s_rules";' % (item, item)
        print '{rank=same; "l1_%s" "%s_rules"};' % (item, item)

    print 'label = "Public Subnet\\n%s"' % "\\n".join(layer_1["subnets"])
    print "}"

    print "subgraph cluster_2 {"
    print '"l1_%s_out" -> "%s";' % (
        "_".join(layer_1["nacl"]),
        "_".join(layer_1["routetable"]),
    )
    print '"%s" -> "%s_rules";' % (
        "_".join(layer_1["routetable"]),
        "_".join(layer_1["routetable"])
    )
    print '{rank=same; "%s" "%s_rules"};' % (
        "_".join(layer_1["routetable"]),
        "_".join(layer_1["routetable"])
    )

    print 'label = "Routers"'

    print '"%s" [label="Route Tables\\n%s"];' % (
        "_".join(layer_1["routetable"]),
        "\\n".join(layer_1["routetable"]),
    )

    print "}"

    print "subgraph cluster_3 {"

    print '"%s" -> "l2_%s_in";' % (
        "_".join(layer_1["routetable"]),
        "_".join(layer_2["nacl"]),
    )


    rule_map = [
        '%s_in' % '_'.join(layer_2['nacl']),
        '%s_in' % '_'.join(layer_2['securitygroups']),
        #'%s' % layer_2['instances'],
        '%s_out' % '_'.join(layer_2['securitygroups']),
        '%s_out' % '_'.join(layer_2['nacl']),
    ]

    print '"l2_%s_in" -> "l2_%s_in";' % (
        '_'.join(layer_2['nacl']),
        '_'.join(layer_2['securitygroups'])
    )
    print '"l2_%s_in" -> "l2_%s";' % (
        '_'.join(layer_2['securitygroups']),
        " ".join(layer_2['instances'])
    )
    print '"l2_%s" [label="Instances\\n%s"];' % (
        " ".join(layer_2['instances']),
        "\\n".join(layer_2['instances'])
    )

    print '"l2_%s" -> "l2_%s_out";' % (
        " ".join(layer_2['instances']),
        '_'.join(layer_2['securitygroups']),
    )
    print '"l2_%s_out" -> "l2_%s_out";' % (
        '_'.join(layer_2['securitygroups']),
        '_'.join(layer_2['nacl']),
    )

    for item in rule_map:
        print '"l2_%s" -> "%s_rules";' % (item, item)
        print '{rank=same; "l2_%s" "%s_rules"};' % (item, item)

    print 'label = "Private Subnet\\n%s"' % "\\n".join(layer_2["subnets"])

    print '"l2_%s_in" [label="Network ACL (inbound)\\n%s"];' % (
        "_".join(layer_2["nacl"]),
        " ".join(layer_2["nacl"])
    )
    print '"l2_%s_out" [label="Network ACL (outbound)\\n%s"];' % (
        "_".join(layer_2["nacl"]),
        " ".join(layer_2["nacl"])
    )
    print '"l2_%s_in" [label="Security Group (inbound)\\n%s"];' % (
        "_".join(layer_2["securitygroups"]),
        "\\n".join(layer_2["securitygroups"]),
    )
    print '"l2_%s_out" [label="Security Group (outbound)\\n%s"];' % (
        "_".join(layer_2["securitygroups"]),
        "\\n".join(layer_2["securitygroups"]),
    )

    print "}"

    get_sg_rules(layer_2["securitygroups"])

    get_rtb_rules(layer_1["routetable"])
    get_nacl_rules(layer_1["nacl"])
    get_nacl_rules(layer_2["nacl"])

    get_elb_rules(layer_1["endpoint"])


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
        " ".join(layer_1["nacl"]),
        " ".join(layer_1["securitygroups"]),
        layer_1["endpoint"],
        " ".join(layer_1['routetable']),
        " ".join(layer_2["nacl"]),
        " ".join(layer_2["securitygroups"]),
        layer_2["instances"]
    )

    print "}"

if __name__ == '__main__':
    main()
