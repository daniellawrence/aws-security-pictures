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
	

Examples
--------

ELB pointing to a single instances.

![](https://raw.githubusercontent.com/daniellawrence/aws-security-pictures/master/examples/simple_example.png)
