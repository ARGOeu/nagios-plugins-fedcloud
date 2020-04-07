# Plugin for EGI FedCloud services

This package includes probes for EGI FedCloud services. Currently it supports the following tests:

- [AppDB Workflow](#appdb-workflow-appdb-cloud-probepl)
- [OpenStack Nova](#openstack-nova-novaprobepy)
- [OpenStack Swift](#openstack-swift-swiftprobepy)
- [FedCloud Accounting Freshness](#fedcloud-accounting-freshness-check_fedcloud_accnt)
- [OCCI Compute Create](#occi-compute-create-check_occi_compute_create)
- [Perun](#perun-check_perun)

## AppDB Workflow (`appdb-cloud-probe.pl`)

Nagios probe for AppDB workflow.

## OpenStack Nova (`novaprobe.py`)

Probe uses two Nagios tests: 
- `eu.egi.cloud.OpenStack-VM`
- `eu.egi.cloud.OpenStack-VM-OIDC`

### `eu.egi.cloud.OpenStack-VM`

Probe uses OpenStack native APIs to:
- Discover the image identifier of the EGI monitoring image
- Discover the smallest flavour that fits the image
- Discover available networks
- Create a VM with the discovered image, flavour and network
- Wait for the VM to become active
- Destroy the VM

In order for the probe to work properly sites need to provide Keystone URL in the GOCDB URL. Command executed is: 
```
/usr/libexec/argo-monitoring/probes/fedcloud/novaprobe.py --endpoint $KEYSTONE_ENDPOINT --appdb-image 1017
```

### `eu.egi.cloud.OpenStack-VM-OIDC`

Probe runs the same test as `eu.egi.cloud.OpenStack-VM` with OIDC token. 

## OpenStack Swift (`swiftprobe.py`)

`eu.egi.cloud.OpenStack-Swift` Nagios test uses `swiftprobe.py` probe to:
- Establish a connection with the OpenStack Swift Object Storage
- Create a new Open Stack Swift Container
- Create a new object file
- Fetch the object file
- Delete the object file
- Delete the OpenStack Swift Container
- Close connection with the OpenStack Swift Object Storage

In order for the probe to work properly sites need to provide Keystone URL in the GOCDB URL. Probe uses OIDC token. 
```
/usr/libexec/argo-monitoring/probes/fedcloud/swiftprobe.py --endpoint $KEYSTONE_ENDPOINT --access-token $OIDC_ACCESS_TOKEN
```

## FedCloud Accounting Freshness (`check_fedcloud_accnt`)

Check looks at the http://goc-accounting.grid-support.ac.uk/cloudtest/cloudsites2.html and checks if the site is there. It also checks `lastupdate` field and raise:

- `WARNING`: if `lastupdate` is older than 7 days
- `CRITICAL`: if `lastupdate` is older than 30 days 

When searching the web site probe uses name provided in the URL in GOCDB entry.

## OCCI Compute Create (`check_occi_compute_create`)
Probe uses OCCI interface to create VM, waits for the VM to become active and then destroys it. In order for the probe to work properly sites need to provide information in the GOCDB URL.

## Perun (`check_perun`)
Probe inspects Perun DB version with the help of Perun RPC calls.
