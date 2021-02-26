# prometheus-xtremio-exporter

This exporter collects performance and usage stats from a Dell EMC XtremIO cluster running XMS version 6.1.0 and above. This exporter utilizes the v3 API, which is not supported by previous versions of XMS, but support for v2 could be added with some effort. Because this application utilizes the API, it's performance is at the mercy of the API. It isn't recommended to run this exporter on the Dell EMC cluster itself, but rather to run it on a separate machine (preferably in close proximity for low latency). It's also recommended that you only collect metrics that truly matter in order to reduce the time a scrape takes to complete.

## Usage & Configuration
### Configuration
To run the exporter, you must make a configuration file called `config.json` located in the same directory as [xtremio.py](xtremio.py). An example of a configuration file can be found below or in [example_config](example_config.json).

````json
{
    "domain": "https://10.0.1.255",
    "username": "exporter",
    "password": "password12345",
    "port": 9891,
    "metrics": [
        "alert_definitions",
        "bbus",
        "bricks",
        "clusters",    
        "ssds",
        "volumes",
        "xenvs",
        "xms"
    ]
}
````

| Variable  | Description
|-----------|----------------------------------------------------------------------------------------------
| domain    | The base URL of the XtremIO management inferface 
| username  | The username of a user that will be used to access the API. Read only access is recommended
| password  | The password to the user that will be used to access the API
| port      | An integer indicating the port you want the metrics to be exposed on
| metrics   | An array of metric groupings to be collected. See below for possible metric group values.

### Metric Groupings
The API provides a lot of different endpoints that can be called to collect various information. A lot of this information doesn't pertain directly to monitoring, so only the endpoints that provide the most monitoring value have been fully implemented. The implemented metric groupings are listed below:
````
alert_definitions
bbus
bricks
clusters
ssds
volumes
xenvs
xms
````

The remaining metric groupings will return one metric indicating how many results were returned in the API call. Without being implemented, including these values in your config file will just cause the exporter to run slower without providing any valuable metrics. These values are listed below:
````
advisory_notices
alerts
consistency_groups
dae_controllers
dae_psus
dae_row_controllers
daes
data_protection_groups
debug_info
email_notifier
events
infiniband_switches
initiator_groups
initiators
ip_links
iscsi_portals
iscsi_routes
ldap_configs
local_disks
local_protections
lun_maps
nvrams
protection_domains
qos_policies
remote_protections
retention_policies
schedulers
slots
snapshot_groups
snapshot_sets
snmp_notifier
storage_controller_psus
storage_controllers
syr_notifier
syslog_notifier
tags
target_groups
targets
user_accounts
volume_pairs
````
### Dependencies
The exporter requires Python 3 and the `requests` and `prometheus_client` modules to be installed.
### Running the Exporter
Once you have a config file made in the same directory as the exporter, you can start the exporter by running the following command:
`python3 xtremio.py`

To verify that your exporter is running, open a browser and go to the port that you're running the exporter on (i.e. 9891) http://localhost:9891.

A Docker image will be available in the future
