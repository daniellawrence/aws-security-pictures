#!/usr/bin/env python
from gather import gather_data, link
import json


def acl_rules(acl):
    rules = """
  <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
  <tr>
      <td bgcolor="black" align="center"><font color="white">Direction</font></td>
      <td bgcolor="black" align="center"><font color="white">Rule </font></td>
      <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
      <td bgcolor="black" align="center"><font color="white">Ports</font></td>
  </tr>
    """
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

        direction = "inbound"
        if e['Egress']:
            direction = "outbound"

        rules += """
        <tr>
        <td bgcolor="%s" align="left">%s</td>
        <td align="left">%s</td>
        <td align="right">%s</td>
        <td align="right">%s</td>
        </tr>
        """ % (rule_color, direction,
               e['RuleNumber'], e['CidrBlock'], portrange
        )

    return rules + "</table>"


def sg_rules(sg):
    sg_id = sg['GroupName']
    rules = """
  <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
  <tr>
      <td bgcolor="black" align="center" colspan="4"><font color="white">%s</font></td>
  </tr>
  <tr>
      <td bgcolor="black" align="center"><font color="white">Direction</font></td>
      <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
      <td bgcolor="black" align="center"><font color="white">Ports</font></td>
  </tr>
    """ % sg_id
    for i in sg['IpPermissions']:
        portrange = "TCP/UDP/ICMP"
        if 'FromPort' in i:
            portrange = "%s-%s/%s" % (
                i['FromPort'], i['ToPort'], i['IpProtocol'].upper()
            )
        ips = [x['CidrIp'] for x in i['IpRanges']]
        if not ips:
            ips = [x['GroupId'] for x in i['UserIdGroupPairs']]
        ips = "<Br />".join(ips)

        rules += """
        <tr>
        <td bgcolor="green" >Inbound</td>
        <td>%s</td>
        <td>%s</td>
        </tr>
        """ % (ips, portrange)
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

        rules += """
        <tr>
        <td bgcolor="green" >Outbound</td>
        <td>%s</td>
        <td>%s</td>
        </tr>
        """ % (ips, portrange)

    return rules + "</table>"


def main():
    gather_data()
    with open('data.json', 'r') as jsonfile:
        aws = json.load(jsonfile)

    print "digraph G {"
    #print "overlap = false;"
    #print "splines = true;"
    print 'node [shape="plaintext"]'
    print """
    splines=true;
    sep="+25,25";
    overlap=scalexy;
    nodesep=0.6;
    node [fontsize=11];
    """
    already_printed = set([])
    sgs = []

    for sn_id, sn in aws['subnets'].items():
        print "//", sn_id
        sn_cluster = "cluster_%s" % sn_id
        print 'subgraph "%s" {' % sn_cluster
        print 'label = "%s"' % sn_id

        for instance_id, instance in sn['instances'].items():
            if instance_id in already_printed:
                continue
            print '"%s" [label="%s"]' % (instance_id, instance['tag_Name'])
            already_printed.add(instance_id)

        for elb_id, elb in sn['elb'].items():
            if elb_id in already_printed:
                continue
            print '"%s"' % elb_id
            already_printed.add(elb_id)

        for rds_id, rds in sn['rds'].items():
            if rds_id in already_printed:
                continue
            print '"%s"' % rds_id
            already_printed.add(rds_id)

        print "}"

        for acl_id, acl in sn['nacl'].items():
            print '"%s" [label=<%s>];' % (acl_id, acl_rules(acl))
            link(sn_cluster, acl_id)

        for instance_id, instance in sn['instances'].items():
            for sg_id, sg in instance['SecurityGroups'].items():
                link(instance_id, sg_id)
                sgs.append(sg)

        for elb_id, elb in sn['elb'].items():
            for sg_id in elb['SecurityGroups'].keys():
                link(elb_id, sg_id)
            for instance_id, instance in elb['Instances'].items():
                link(elb_id, instance_id)

        for rds_id, rds in sn['rds'].items():
            for sg_id in rds['SecurityGroups'].keys():
                link(rds_id, sg_id)

        for sg in sgs:
            sg_id = sg['GroupId']
            print '"%s" [label=<%s>];' % (sg_id, sg_rules(sg))
    print "}"


if __name__ == '__main__':
    main()
