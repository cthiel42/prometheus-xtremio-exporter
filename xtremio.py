import json
import time
import os
import requests
from prometheus_client import start_http_server, REGISTRY, Metric
from concurrent.futures import ThreadPoolExecutor, as_completed

class Collector(object):
    def __init__(self, config):
        self.config = config
        self.unimplemented_collectors = (['advisory_notices','alerts','consistency_groups','dae_row_controllers','daes','data_protection_groups','debug_info','email_notifier','events',
        'infiniband_switches','initiator_groups','initiators','ip_links','iscsi_portals','iscsi_routes','ldap_configs','local_disks','local_protections','lun_maps','nvrams',
        'protection_domains','qos_policies','remote_protections','retention_policies','schedulers','slots','snapshot_groups','snapshot_sets','snmp_notifier',
        'storage_controller_psus','storage_controllers','syr_notifier','syslog_notifier','tags','target_groups','targets','user_accounts','volume_pairs'])

    def collect(self):
        start = time.time()
        print("Running Collection")
        self.config["authCookie"] = requests.get("{}/api/json/v3/commands/login?password={}&user={}".format(self.config["domain"],self.config["password"],self.config["username"]),verify=False).cookies
        
        processes = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for path in self.config["metrics"]:
                if path in self.unimplemented_collectors:
                    processes.append(executor.submit(self.unimplemented,path))
                elif hasattr(self, path):
                    method = getattr(self, path)
                    processes.append(executor.submit(method))
        
        for task in as_completed(processes):
            metrics = task.result()
            if metrics==None:
                continue
            for metric in metrics:
                yield metric

        print("Logging out")
        requests.get("{}/api/json/v3/commands/logout".format(self.config["domain"]),verify=False)
        self.config["authCookie"] = ""
        print("Collection complete in: "+str(time.time()-start)+" seconds")

    def gather_endpoint(self, path):
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        return json.loads(requests.get("{}/api/json/v3/types/{}".format(self.config["domain"],path),cookies=self.config["authCookie"],headers=headers,verify=False).content)

    def alert_definitions(self):
        start = time.time()
        print("alert_definitions: Starting")
        resp = self.gather_endpoint("alert-definitions")

        metric1 = Metric('xio_alert_definitions_count','Number of alert definitions',"gauge")
        metric1.add_sample('xio_alert_definitions_count',value=len(resp["alert-definitions"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric('xio_alert_definitions_definition_exists','Alert name and guid included as labels for each existing alert definition',"gauge")
        for alert in resp["alert-definitions"]:
            metric2.add_sample("xio_alert_definitions_definition_exists",
                    value=1,
                    labels={
                        "alert_name":alert["name"],
                        "guid":alert["href"].split("/")[-1]
                    })

        print("alert_definitions: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]
    
    def bbus(self):
        start = time.time()
        print("BBU's: Starting")
        resp = self.gather_endpoint("bbus")

        metric1 = Metric('xio_bbus_count','Number of bbus',"gauge")
        metric1.add_sample('xio_bbus_count',value=len(resp["bbus"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric('xio_bbus_exists',"System name and BBU name included as labels for each existing BBU", "gauge")
        metric3 = Metric('xio_bbus_power',"Power usage of BBU", "gauge")
        metric4 = Metric("xio_bbus_enabled","Is BBU enabled","gauge")
        metric5 = Metric("xio_bbus_average_daily_temp","Average Daily Temperature of BBU","gauge")
        metric6 = Metric("xio_bbus_ups_need_battery_replacement","Does the BBU UPS need a battery replacement","gauge")
        metric7 = Metric("xio_bbus_ups_low_battery_no_input","Is 1 if the UPS has low battery and is recieving no input","gauge")
        for bbus in resp["bbus"]:
            metric2.add_sample('xio_bbus_exists',value=1,labels={"href":bbus["href"],"bbus_name":bbus["name"],"sys_name":bbus["sys-name"]})
            bbus_resp = self.gather_endpoint("bbus/"+bbus["href"].split("/")[-1])
            labels = {"serial_number":bbus_resp["content"]["serial-number"],"guid":bbus_resp["content"]["guid"],"power_feed":bbus_resp["content"]["power-feed"],"name":bbus_resp["content"]["name"],"model_name":bbus_resp["content"]["model-name"]}
            metric3.add_sample("xio_bbus_power",value=bbus_resp["content"]["power"],labels=labels)
            
            if bbus_resp["content"]["enabled-state"]=="enabled":
                enabled = 1
            else:
                enabled = 0
            metric4.add_sample("xio_bbus_enabled",value=enabled,labels=labels)

            metric5.add_sample("xio_bbus_average_daily_temp",value=bbus_resp["content"]["avg-daily-temp"],labels=labels)

            if bbus_resp["content"]["ups-need-battery-replacement"]=="false":
                battery_replacement = 0
            else:
                battery_replacement = 1
            metric6.add_sample("xio_bbus_ups_need_battery_replacement",value=battery_replacement,labels=labels)

            if bbus_resp["content"]["is-low-battery-no-input"]=="false":
                low_battery = 0
            else:
                low_battery = 1
            metric7.add_sample("xio_bbus_ups_low_battery_no_input",value=low_battery,labels=labels)

        print("BBU's: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2,metric3,metric4,metric5,metric6,metric7]

    def bricks(self):
        start = time.time()
        print("Bricks: Starting")
        resp = self.gather_endpoint("bricks")

        metric1 = Metric('xio_bricks_count','Number of bricks',"gauge")
        metric1.add_sample('xio_bricks_count',value=len(resp["bricks"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_bricks_exist","Brick name and system name in labels for all bricks that exist","gauge")
        metric3 = Metric("xio_bricks_ssd_count","Number of SSD's for brick","gauge")
        for brick in resp["bricks"]:
            metric2.add_sample('xio_bricks_exist',value=1,labels={"name":brick["name"],"sys_name":brick["sys-name"],"href":brick["href"]})
            brick_resp = self.gather_endpoint("bricks/"+brick["href"].split("/")[-1])
            metric3.add_sample("xio_bricks_ssd_count",value=brick_resp["content"]["num-of-ssds"],labels={"guid":brick_resp["content"]["guid"],"sys_name":brick_resp["content"]["sys-name"],"name":brick_resp["content"]["name"]})

        print("Bricks: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2,metric3]
    
    def clusters(self):
        start = time.time()
        print("Clusters: Starting")
        resp = self.gather_endpoint("clusters")

        metric1 = Metric('xio_clusters_count','Number of clusters',"gauge")
        metric1.add_sample('xio_clusters_count',value=len(resp["clusters"]), labels={"href":resp["links"][0]["href"]})
        metric2 = Metric("xio_clusters_exist","Label with the name of cluster that exists","gauge")
        metric3 = Metric("xio_clusters_compression_factor","Cluster factor over 1","gauge")
        metric4 = Metric("xio_clusters_percent_memory_in_use","Percent of cluster memory in use","gauge")
        metric5 = Metric("xio_clusters_read_iops","Cluster read IOPS","gauge")
        metric6 = Metric("xio_clusters_write_iops","Cluster write IOPS","gauge")
        metric7 = Metric("xio_clusters_number_of_volumes","Cluster number of volumes","gauge")
        metric8 = Metric("xio_clusters_free_ssd_space_in_percent","Cluster percent of free SSD space","gauge")
        metric9 = Metric("xio_clusters_ssd_num","Cluster read IOPS","gauge")
        metric10 = Metric("xio_clusters_data_reduction_ratio","Cluster data reduction ratio","gauge")
        for cluster in resp["clusters"]:
            metric2.add_sample("xio_clusters_exist",value=1,labels={"href":cluster["href"],"name":cluster["name"]})
            cluster_resp = self.gather_endpoint("clusters/"+cluster["href"].split("/")[-1])
            labels = {"hardware_platform":cluster_resp["content"]["hardware-platform"],"name":cluster_resp["content"]["name"],"license_id":cluster_resp["content"]["license-id"],"guid":cluster_resp["content"]["guid"],"sys_psnt_serial_number":cluster_resp["content"]["sys-psnt-serial-number"]}
            metric3.add_sample("xio_clusters_compression_factor",value=cluster_resp["content"]["compression-factor"],labels=labels)
            metric4.add_sample("xio_clusters_percent_memory_in_use",value=cluster_resp["content"]["total-memory-in-use-in-percent"],labels=labels)
            metric5.add_sample("xio_clusters_read_iops",value=cluster_resp["content"]["rd-iops"],labels=labels)
            metric6.add_sample("xio_clusters_write_iops",value=cluster_resp["content"]["wr-iops"],labels=labels)
            metric7.add_sample("xio_clusters_number_of_volumes",value=cluster_resp["content"]["num-of-vols"],labels=labels)
            metric8.add_sample("xio_clusters_free_ssd_space_in_percent",value=cluster_resp["content"]["free-ud-ssd-space-in-percent"],labels=labels)
            metric9.add_sample("xio_clusters_clusters_ssd_num",value=cluster_resp["content"]["num-of-ssds"],labels=labels)
            metric10.add_sample("xio_clusters_data_reduction_ratio",value=cluster_resp["content"]["data-reduction-ratio"],labels=labels)

        print("Clusters: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2,metric3,metric4,metric5,metric6,metric7,metric8,metric9,metric10]

    def dae_controllers(self):
        start = time.time()
        print("DAE Controllers: Starting")
        resp = self.gather_endpoint("dae-controllers")

        metric1 = Metric('xio_dae_controllers_count','Number of dae controllers',"gauge")
        metric1.add_sample('xio_dae_controllers_count',value=len(resp["dae-controllers"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_dae_controllers_exist","DAE Controller name and system name in labels for all DAE Controllers that exist","gauge")
        for dae in resp["dae-controllers"]:
            metric2.add_sample('xio_dae_controller_exist',value=1,labels={"name":dae["name"],"sys_name":dae["sys-name"],"href":dae["href"]})
            
        print("DAE Controllers: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]
        
    def dae_psus(self):
        start = time.time()
        print("DAE PSU's: Starting")
        resp = self.gather_endpoint("dae-psus")

        metric1 = Metric('xio_dae_psus_count',"Number of DAE PSU's","gauge")
        metric1.add_sample('xio_dae_psus_count',value=len(resp["dae-psus"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_dae_psus_exist","DAE PSU name and system name in labels for all DAE PSU's that exist","gauge")
        for dae in resp["dae-psus"]:
            metric2.add_sample('xio_dae_psus_exist',value=1,labels={"name":dae["name"],"sys_name":dae["sys-name"],"href":dae["href"]})
            
        print("DAE PSU's: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]

    def ssds(self): 
        start = time.time()
        print("SSD's: Starting")
        resp = self.gather_endpoint("ssds")

        metric1 = Metric('xio_ssds_count',"Number of SSD's","gauge")
        metric1.add_sample('xio_ssds_count',value=len(resp["ssds"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_ssds_exist","SSD name and system name in labels for all SSD's that exist","gauge")
        metric3 = Metric("xio_ssds_ssd_size","SSD size in kilobytes","gauge")
        metric4 = Metric("xio_ssds_ssd_space_in_use","SSD space in use in kilobytes","gauge")
        metric5 = Metric("xio_ssds_write_iops","SSD Write IOPS","gauge")
        metric6 = Metric("xio_ssds_read_iops","SSD Read IOPS","gauge")
        metric7 = Metric("xio_ssds_write_bandwidth","SSD Write Bandwidth","gauge")
        metric8 = Metric("xio_ssds_read_bandwidth","SSD Read Bandwidth","gauge")
        metric9 = Metric("xio_ssds_num_bad_sectors","Number of sectors on SSD that are bad","gauge")
        
        ssd_processes = []
        with ThreadPoolExecutor(max_workers=30) as ssd_executor:
            for ssd in resp["ssds"]:
                ssd_processes.append(ssd_executor.submit(self.ssds_helper,ssd))
        
        for task in as_completed(ssd_processes):
            ssd,ssd_resp = task.result()
            labels = {"guid":ssd_resp["content"]["guid"],"serial_number":ssd_resp["content"]["serial-number"],"ssd_uid":ssd_resp["content"]["ssd-uid"],"sys_name":ssd_resp["content"]["sys-name"],"model_name":ssd_resp["content"]["model-name"],"firmware_version":ssd_resp["content"]["fw-version"]}
            metric2.add_sample('xio_ssds_exist',value=1,labels={"name":ssd["name"],"sys_name":ssd["sys-name"],"href":ssd["href"]})
            metric3.add_sample('xio_ssds_ssd_size',value=ssd_resp["content"]["ssd-size"],labels=labels)
            metric4.add_sample('xio_ssds_ssd_space_in_use',value=ssd_resp["content"]["ssd-space-in-use"],labels=labels)
            metric5.add_sample('xio_ssds_write_iops',value=ssd_resp["content"]["wr-iops"],labels=labels)
            metric6.add_sample('xio_ssds_read_iops',value=ssd_resp["content"]["rd-iops"],labels=labels)
            metric7.add_sample('xio_ssds_write_bandwidth',value=ssd_resp["content"]["wr-bw"],labels=labels)
            metric8.add_sample('xio_ssds_read_bandwidth',value=ssd_resp["content"]["rd-bw"],labels=labels)
            metric9.add_sample('xio_ssds_num_bad_sectors',value=ssd_resp["content"]["num-bad-sectors"],labels=labels)
            
        print("SSD's: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2,metric3,metric4,metric5,metric6,metric7,metric8,metric9]

    def ssds_helper(self,ssd):
        return (ssd,self.gather_endpoint("ssds/"+ssd["href"].split("/")[-1]))

    def volumes(self):
        start = time.time()
        print("Volumes: Starting")
        resp = self.gather_endpoint("volumes")

        metric1 = Metric('xio_volumes_count',"Number of Volumes","gauge")
        metric1.add_sample('xio_volumes_count',value=len(resp["volumes"]), labels={"href":resp["links"][0]["href"]})

        volume_processes = []
        metric2 = Metric("xio_volumes_exist","Volume name and system name in labels for all Volumes that exist","gauge")
        metric3 = Metric("xio_volumes_read_iops","Volume Read IOPS","gauge")
        metric4 = Metric("xio_volumes_write_iops","Volume Write IOPS","gauge")
        metric5 = Metric("xio_volumes_read_latency","Volume Read Latency","gauge")
        metric6 = Metric("xio_volumes_write_latency","Volume Write Latency","gauge")
        metric7 = Metric("xio_volumes_data_reduction_ratio","Volume Data Reduction Ratio","gauge")
        metric8 = Metric("xio_volumes_provisioned_space","Volume Provisioned Space","gauge")
        metric9 = Metric("xio_volumes_used_space","Volume Used Space","gauge")
        with ThreadPoolExecutor(max_workers=10) as volume_executor:
            for volume in resp["volumes"]:
                volume_processes.append(volume_executor.submit(self.gather_endpoint,"volumes/"+volume["href"].split("/")[-1]))
        
        for task in as_completed(volume_processes):
            volume_resp = task.result()
            labels = {"guid":volume_resp["content"]["guid"],"name":volume_resp["content"]["name"],"sys_name":volume_resp["content"]["sys-name"],"href":volume_resp["links"][0]["href"]}
            metric2.add_sample('xio_volumes_exist',value=1,labels=labels)
            metric3.add_sample("xio_volumes_read_iops",value=volume_resp["content"]["rd-iops"],labels=labels)
            metric4.add_sample("xio_volumes_write_iops",value=volume_resp["content"]["wr-iops"],labels=labels)
            metric5.add_sample("xio_volumes_read_latency",value=volume_resp["content"]["rd-latency"],labels=labels)
            metric6.add_sample("xio_volumes_write_latency",value=volume_resp["content"]["wr-latency"],labels=labels)
            metric7.add_sample("xio_volumes_data_reduction_ratio",value=volume_resp["content"]["data-reduction-ratio"],labels=labels)
            metric8.add_sample("xio_volumes_provisioned_space",value=volume_resp["content"]["vol-size"],labels=labels)
            metric9.add_sample("xio_volumes_used_space",value=volume_resp["content"]["logical-space-in-use"],labels=labels)
  
        print("Volumes: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2,metric3,metric4,metric5,metric6,metric7,metric8,metric9]

    def xenvs(self):
        start = time.time()
        print("xEnvs: Starting")
        resp = self.gather_endpoint("xenvs")

        metric1 = Metric('xio_xenvs_count',"Number of xEnvs","gauge")
        metric1.add_sample('xio_xenvs_count',value=len(resp["xenvs"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_xenvs_exist","xEnv name and system name in labels for all xEnvs that exist","gauge")
        for xenv in resp["xenvs"]:
            metric2.add_sample('xio_xenvs_exist',value=1,labels={"name":xenv["name"],"sys_name":xenv["sys-name"],"href":xenv["href"]})
            
        print("xEnvs: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]
    
    def xms(self):
        start = time.time()
        print("XMS: Starting")
        resp = self.gather_endpoint("xms")

        metric1 = Metric('xio_xms_count',"Number of XMS","gauge")
        metric1.add_sample('xio_xms_count',value=len(resp["xmss"]), labels={"href":resp["links"][0]["href"]})
        metric2 = Metric("xio_xms_exist","XMS name and system name in labels for all XMS that exist","gauge")
        metric3 = Metric("xio_xms_write_iops","XMS write iops","gauge")
        metric4 = Metric("xio_xms_read_iops","XMS read iops","gauge")
        metric5 = Metric("xio_xms_overall_efficiency_ratio","XMS overall efficiency ratio","gauge")
        metric6 = Metric("xio_xms_ssd_space_in_use","XMS SSD space in use","gauge")
        metric7 = Metric("xio_xms_ram_in_use","XMS RAM in use","gauge")
        metric8 = Metric("xio_xms_ram_total","XMS RAM total","gauge")
        metric9 = Metric("xio_xms_cpu_usage_total","XMS CPU usage total","gauge")
        metric10 = Metric("xio_xms_write_latency","XMS write latency","gauge")
        metric11 = Metric("xio_xms_read_latency","XMS read latency","gauge")
        metric12 = Metric("xio_xms_user_accounts_count","XMS read latency","gauge")
        for xms in resp["xmss"]:
            metric2.add_sample('xio_xms_exist',value=1,labels={"name":xms["name"],"href":xms["href"]})
            xms_resp = self.gather_endpoint("xms/"+xms["href"].split("/")[-1])
            labels = {"xms_ip":xms_resp["content"]["xms-ip"],"version":xms_resp["content"]["version"],"name":xms_resp["content"]["name"],"guid":xms_resp["content"]["guid"]}
            metric3.add_sample("xio_xms_write_iops",value=xms_resp["content"]["wr-iops"],labels=labels)
            metric4.add_sample("xio_xms_read_iops",value=xms_resp["content"]["rd-iops"],labels=labels)
            metric5.add_sample("xio_xms_overall_efficiency_ratio",value=xms_resp["content"]["overall-efficiency-ratio"],labels=labels)
            metric6.add_sample("xio_xms_ssd_space_in_use",value=xms_resp["content"]["ssd-space-in-use"],labels=labels)
            metric7.add_sample("xio_xms_ram_in_use",value=xms_resp["content"]["ram-usage"],labels=labels)
            metric8.add_sample("xio_xms_ram_total",value=xms_resp["content"]["ram-total"],labels=labels)
            metric9.add_sample("xio_xms_cpu_usage_total",value=xms_resp["content"]["cpu"],labels=labels)
            metric10.add_sample("xio_xms_write_latency",value=xms_resp["content"]["wr-latency"],labels=labels)
            metric11.add_sample("xio_xms_read_latency",value=xms_resp["content"]["rd-latency"],labels=labels)
            metric12.add_sample("xio_xms_user_accounts_count",value=xms_resp["content"]["num-of-user-accounts"],labels=labels)

        print("XMS: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2,metric3,metric4,metric5,metric6,metric7,metric8,metric9,metric10,metric11,metric12]

    def unimplemented(self,underscored_name):
        start = time.time()
        print(underscored_name+": Starting")
        resp = self.gather_endpoint(underscored_name.replace("_","-"))

        metric1 = Metric('xio_'+underscored_name+'_count',"Number of "+underscored_name,"gauge")
        metric1.add_sample('xio_'+underscored_name+'_count',value=len(resp[underscored_name.replace("_","-")]), labels={"href":resp["links"][0]["href"]})

        print(underscored_name+": Done in "+str(time.time()-start)+" seconds")
        return [metric1]

def load_config():
    try:
        configFile = open("config.json","r")
        config = json.loads(configFile.read())
        configFile.close()
    except Exception as e:
        raise Exception("Configuration file was unabled to be loaded: "+str(e))
    
    if "domain" not in config:
        raise Exception("No domain specified in configuration file")
    if "port" not in config:
        config["port"] = 9891
    if not isinstance(config["port"],int) or config["port"] < 0 or config["port"] > 65535:
        raise Exception("Port must be an integer between 0 and 65535")
    if "username" not in config:
        raise Exception("Username is missing from configuration file")
    if "password" not in config:
        if "XTREMIO_PASSWORD" in os.environ:
            config["password"] = os.environ.get("XTREMIO_PASSWORD")
        else:
            raise Exception("Password is missing from configuration file and environment variables")
    if "metrics" not in config:
        config["metrics"] = ["alert_definitions","bbus","bricks","clusters","ssds","volumes","xenvs","xms"]
    if not isinstance(config["metrics"],list):
        raise Exception("Metrics field in configuration must be an array")

    return config
    
def main():
    config = load_config()

    start_http_server(config["port"])

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    REGISTRY.register(Collector(config))

    print("Exporter Running")
    while 1:
        time.sleep(5)

main()
