from setuptools import setup

setup(
    name='awssecuritypictures',
    version='0.0.1',
    description="AWS Security Pictures",
    long_description='AWS Security Pictures',
    classifiers=["Programming Language :: Python"],
    keywords='AWS securitygroups firewall nacl',
    author='Daniel Lawrence',
    author_email='dannyla@linux.com',
    url='http://github.com/daniellawrence/aws-security-pictures',
    license='',
    packages=['awssecuritypictures'],
    package_dir={'awssecuritypictures': 'awssecuritypictures'},
    include_package_data=True,
    zip_safe=False,
)
