#!/usr/bin/env python
from gather import gather_data, link
import json


def test_layout_sg(i_id, i, sn):
    sn_id = sn['SubnetId']
    if 'SecurityGroups' in i:
        sg_ids = i['SecurityGroups'].keys()
    else:
        sg_ids = [s['VpcSecurityGroupId'] for s in i['VpcSecurityGroups']]
    sg_group = "_".join(sg_ids)

    link("%s__%s__in" % (sn_id, sg_group), i_id)
    link(i_id, "%s__%s__out" % (sn_id, sg_group))

    if 'nacl' in sn:
        for nacl_id, nacl in sn['nacl'].items():
            link(
                "%s__%s__in" % (sn_id, nacl_id),
                "%s__%s__in" % (sn_id, sg_group)
            )
            link(
                "%s__%s__out" % (sn_id, sg_group),
                "%s__%s__out" % (sn_id, nacl_id)
            )

    sn_az = sn['AvailabilityZone']

    print 'subgraph "cluster_%s__%s" {' % (sn_id, sg_group)
    print '"%s"' % i_id
    print 'label = "%s"' % sg_group

    if 'LoadBalancerName' in i:
        i_id = i_id.split('_')[-1]
        link("%s_%s" % (sn_az, i_id), "%s_rules" % i_id)

    print "}"


def test_layout(aws):
    print "digraph G {"
    print "overlap = false;"
    print "splines = true;"
    for sn_id, sn in aws['subnets'].items():

        sn_az = sn['AvailabilityZone']

        print 'subgraph "cluster_%s" {' % sn_id
        print 'label = "%s"' % sn_id

        if 'instances' in sn:
            for instance_id, instance in sn['instances'].items():
                print "// %s -> %s" % (sn_id, instance_id)
                print '"%s"' % instance_id
                for t in instance['Tags']:
                    continue
                    if t['Key'] == 'Name':
                        print '"%s" [label="%s"]' % (instance_id, t['Value'])
                test_layout_sg(instance_id, instance, sn)

        if 'rds' in sn:
            for rds_id, rds in sn['rds'].items():
                print "// %s -> %s" % (sn_id, rds_id)
                test_layout_sg("%s_%s" % (sn_az, rds_id), rds, sn)

        if 'elb' in sn:
            for elb_id, elb in sn['elb'].items():
                print "// %s -> %s" % (sn_id, elb_id)
                test_layout_sg("%s_%s" % (sn_az, elb_id), elb, sn)

        print "}"

    print "}"


def main():
    gather_data()
    with open('data.json', 'r') as jsonfile:
        aws = json.load(jsonfile)

    test_layout(aws)

if __name__ == '__main__':
    main()
