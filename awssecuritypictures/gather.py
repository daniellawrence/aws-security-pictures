#!/usr/bin/env python
import json

from main import get_load_balancers, get_ec2_instances, get_security_groups, \
    get_network_acl, get_subnets, get_routetables, get_rds


def memorize(function):
    memo = {}

    def wrapper(*args):
        if isinstance(args, list):
            k = "".join(args)
        else:
            k = str(args)
        if k in memo:
            return memo[k]
        else:
            rv = function(*args)
            memo[k] = rv
            return rv
    return wrapper


@memorize
def expand_tags(item):
    tags = {}

    if 'Tags' not in item:
        return item

    for kv in item['Tags']:
        k = "tag_%s" % kv['Key']
        v = kv['Value']
        tags[k] = v

    item.update(tags)
    return item


@memorize
def get_all_subnet():
    all_subnets = {}
    for subnet in get_subnets():
        subnet_id = subnet['SubnetId']
        if subnet['VpcId'] != 'vpc-fa878c98':
            continue
        all_subnets[subnet_id] = subnet
    return all_subnets


@memorize
def get_all_instances():
    all_ec2 = {}
    for r in get_ec2_instances():
        instance = r['Instances'][0]
        instance_id = instance['InstanceId']
        instance_securitygroups = grab_from(
            get_instance_securitygroup_ids(instance),
            get_all_securitygroups()
        )
        instance["SecurityGroups"] = instance_securitygroups
        instance = expand_tags(instance)
        all_ec2[instance_id] = instance

    return all_ec2


@memorize
def get_instances_in(subnet_id):
    instance_filter = "--filters Name=subnet-id,Values=%s" % subnet_id
    all_ec2 = {}
    for r in get_ec2_instances(instance_filter):
        instance = r['Instances'][0]
        instance_id = instance['InstanceId']
        instance_securitygroups = grab_from(
            get_instance_securitygroup_ids(instance),
            get_all_securitygroups()
        )
        instance["SecurityGroups"] = instance_securitygroups
        instance = expand_tags(instance)
        all_ec2[instance_id] = instance

    return all_ec2


@memorize
def get_instance_securitygroup_ids(instance):
    sg_id_list = []
    for sg_meta in instance['SecurityGroups']:
        sg_id_list.append(sg_meta['GroupId'])
    return sg_id_list


@memorize
def get_all_elb(subnet_id=None):
    all_elb = {}
    for elb in get_load_balancers():
        elb_name = elb['LoadBalancerName']
        elb_subnets = elb['Subnets']
        if subnet_id and subnet_id not in elb_subnets:
            continue
        elb_securitygroups = grab_from(
            elb["SecurityGroups"],
            get_all_securitygroups()
        )
        elb["SecurityGroups"] = elb_securitygroups

        elb_instances = grab_from(
            [i['InstanceId'] for i in elb["Instances"]],
            get_all_instances()
        )
        elb["Instances"] = elb_instances
        elb = expand_tags(elb)
        all_elb[elb_name] = elb
    return all_elb


@memorize
def get_elb_in(subnet_id):
    return get_all_elb(subnet_id)


@memorize
def get_subnet_acl(subnet_id):
    all_nacl = {}
    acl_filter = "--filters Name=association.subnet-id,Values=%s" % subnet_id
    for nacl in get_network_acl(acl_filter):
        nacl_id = nacl['NetworkAclId']
        nacl = expand_tags(nacl)
        all_nacl[nacl_id] = nacl
    return all_nacl


@memorize
def get_rds_in(subnet_id):
    all_rds = {}
    rds_filter = ""
    for rds in get_rds(rds_filter):
        rds_sn_ids = [s['SubnetIdentifier'] for s in rds['DBSubnetGroup']['Subnets']]
        rds_id = rds['DBInstanceIdentifier']
        if subnet_id not in rds_sn_ids:
            continue
        rds_sg_ids = [s['VpcSecurityGroupId'] for s in rds['VpcSecurityGroups']]
        rds_securitygroups = grab_from(
            rds_sg_ids,
            get_all_securitygroups()
        )
        rds['SecurityGroups'] = rds_securitygroups
        rds = expand_tags(rds)
        all_rds[rds_id] = rds
    return all_rds


@memorize
def get_subnet_routetables(subnet_id):
    all_rtb = {}
    rtb_filter = "--filters Name=association.subnet-id,Values=%s" % subnet_id
    for rtb in get_routetables(rtb_filter):
        rtb_id = rtb['RouteTableId']
        all_rtb[rtb_id] = rtb
    return all_rtb


@memorize
def get_all_securitygroups():
    all_sg = {}
    for sg in get_security_groups():
        sg_id = sg['GroupId']
        all_sg[sg_id] = sg
    return all_sg


@memorize
def grab_from(ids, from_dict):
    print "// Find: %s" % ids
    results = {}
    for item_id, item in from_dict.items():
        if item_id in ids:
            results[item_id] = item
    return results


def gather_data():
    aws = {}
    aws['subnets'] = get_all_subnet()
    aws['securitygroups'] = get_all_securitygroups()

    for subnet_id in aws['subnets']:
        subnet_instances = get_instances_in(subnet_id)
        subnet_elb = get_elb_in(subnet_id)
        subnet_nacl = get_subnet_acl(subnet_id)
        subnet_rtb = get_subnet_routetables(subnet_id)
        subnet_rds = get_rds_in(subnet_id)

        aws['subnets'][subnet_id]['instances'] = subnet_instances
        aws['subnets'][subnet_id]['elb'] = subnet_elb
        aws['subnets'][subnet_id]['nacl'] = subnet_nacl
        aws['subnets'][subnet_id]['rtb'] = subnet_rtb
        aws['subnets'][subnet_id]['rds'] = subnet_rds

    with open('data.json', 'w') as outfile:
        json.dump(aws, outfile)


def link(t1, t2):
    print '"%s" -> "%s";' % (t1, t2)


def sg_rule_as_row(rule):
    portrange = "TCP/UDP/ICMP"
    if 'FromPort' in rule:
        portrange = "%s-%s/%s" % (
            rule['FromPort'], rule['ToPort'], rule['IpProtocol'].upper()
        )
    ips = [x['CidrIp'] for x in rule['IpRanges']]
    if not ips:
        ips = [x['GroupId'] for x in rule['UserIdGroupPairs']]
    ips = "<Br />".join(ips)
    rule_html = """
    <tr>
      <td bgcolor="green" align="left">%s</td>
      <td align="right">%s</td>
    </tr>
    """ % (ips, portrange)
    return rule_html


def sg_rules_as_table(sg):
    inbound_rules = """label=<
    <table border="1" cellborder="0" cellpadding="3" bgcolor="white">
        <tr>
          <td bgcolor="black" align="center"><font color="white">CIDR</font></td>
          <td bgcolor="black" align="center"><font color="white">Ports</font></td>
        </tr>
    """
    outbound_rules = inbound_rules

    for rule in sg['IpPermissions']:
        inbound_rules += sg_rule_as_row(rule)
    inbound_rules += "</table>>"

    for rule in sg['IpPermissionsEgress']:
        outbound_rules += sg_rule_as_row(rule)
    outbound_rules += "</table>>"

    return inbound_rules, outbound_rules


def main():
    gather_data()


if __name__ == '__main__':
    main()

# EOF
