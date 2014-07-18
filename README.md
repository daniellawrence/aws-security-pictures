[![Build Status](https://travis-ci.org/daniellawrence/aws-security-pictures.svg?branch=master)](https://travis-ci.org/daniellawrence/aws-security-pictures)


AWS Security Pictures
---------------------

Generate detailed images of aws deployments for security reviews.


How to Install
--------------

    $ sudo apt-get install graphviz python-pip python-virtualenv
	$ git clone https://github.com/daniellawrence/aws-security-pictures
	$ cd aws-security-pictures
    $ virtualenv venv
	$ source venv/bin/activate
	$ pip install -r requirements.txt


How to Contribute
-----------------

	$ pip install -r requirements-dev.txt

Please make sure the following command exits successfully before pushing your
code.

	$ flake8 awssecuritypictures --ignore=E501
	$ python ./setup.py install


How to run
----------

Generate a picture of an ELB,

	$ ./awssecuritypictures/generate.py --elb ELBNAME -o output.dot

Generate a picture of an EC2,

	$ ./awssecuritypictures/generate.py --ec2 EC2NAME -o output.dot

The above generate the dot files required. In order to see the output image,

	$ dot -T png output.dot -o output.png

Generate a list of all ELBs and EC2s,

	$ ./awssecuritypictures/generate.py

Make use of AWS CLI profiles,

	$ ./awssecuritypictures/generate.py --profile PROFILENAME

	or

	$ ./awssecuritypictures/generate.py -p PROFILENAME

More handy arugments can be found here,

	$ ./awssecuritypictures/generate.py -h


Experiments
-----------

Generate all rules within a subnet for review,

	$ ./experiments/firewall_review.py > x.dot; fdp -Tpng x.dot >x.png; eog x.png

Generate the relationships of all the items with a account,

	$ ./experiments/relationships.py > x.dot; fdp -Tpng x.dot >x.png; eog x.png


Examples
--------

ELB pointing to a single instances.

![](https://raw.githubusercontent.com/daniellawrence/aws-security-pictures/master/examples/simple_example.png)
