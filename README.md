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

	$ ./main.py <elbname>
	

Example
-------

![](https://raw.githubusercontent.com/daniellawrence/aws-security-pictures/master/examples/simple_example.png)
