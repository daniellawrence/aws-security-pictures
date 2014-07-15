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
	$ pip install awscli

How to run
----------

Generate a picture of an elb.

	$ ./main.py <elbname>

Generate a list of all elbs

	$ ./main.py

Generate all rules within a subnet for review

	$ ./firewall_review.py > x.dot; fdp -Tpng x.dot >x.png; eog x.png

Generate the relationships of all the items with a account

	$ ./relationships.py > x.dot; fdp -Tpng x.dot >x.png; eog x.png
	
	

Examples
--------

ELB pointing to a single instances.

![](https://raw.githubusercontent.com/daniellawrence/aws-security-pictures/master/examples/simple_example.png)
