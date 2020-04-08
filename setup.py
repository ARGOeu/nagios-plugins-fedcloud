from __future__ import print_function

from distutils.core import setup
import glob
import sys

NAME = "nagios-plugins-fedcloud"
DESTDIR = "/usr/libexec/argo-monitoring/probes/fedcloud"


def get_ver():
    try:
        for line in open(NAME + ".spec"):
            if "Version:" in line:
                return line.split()[1]
    except IOError:
        print("Make sure that %s is in directory" % (NAME + ".spec"))
        sys.exit(1)


setup(
    name=NAME,
    version=get_ver(),
    license="ASL 2.0",
    author="SRCE",
    author_email="dvrcic@srce.hr, eimamagi@srce.hr",
    description="Package include probes for EGI FedCloud services",
    platforms="noarch",
    long_description="""
      This package includes probes for EGI FedCloud services.
      Currently it supports the following tests:
        - AppDB workflow
        - Openstack Nova
        - OpenStack Swift
        - FedCloud Accounting Freshness
        - OCCI compute create
        - Perun
      """,
    url="https://github.com/ARGOeu/nagios-plugins-fedcloud",
    data_files=[(DESTDIR, glob.glob("src/*"))],
    packages=["nagios_plugins_fedcloud"],
    package_dir={"nagios_plugins_fedcloud": "pymodule/"},
)
