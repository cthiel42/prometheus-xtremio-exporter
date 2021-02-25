import json
import time
import requests
from prometheus_client import start_http_server, REGISTRY, Metric
from concurrent.futures import ThreadPoolExecutor, as_completed

class Collector(object):
    def __init__(self, config):
        self.config = config

    def collect(self):
        start = time.time()
        print("Running Collection")
        self.config["authCookie"] = requests.get("{}/api/json/v3/commands/login?password={}&user={}".format(self.config["domain"],self.config["password"],self.config["username"]),verify=False).cookies
        
        processes = []
        with ThreadPoolExecutor(max_workers=10) as executor:
            for path in self.config["metrics"]:
                if hasattr(self, path):
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
    
    def advisory_notices(self):
        return self.unimplemented("Advisory Notices","advisory_notices")

    def alert_definitions(self):
        start = time.time()
        print("alert_definitions: Starting")
        resp = self.gather_endpoint("alert-definitions")

        metric1 = Metric('xio_alert_definitions_count','Number of alert definitions',"summary")
        metric1.add_sample('xio_alert_definitions_count',value=len(resp["alert-definitions"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric('xio_alert_definitions_definition_exists','Alert name and guid included as labels for each existing alert definition',"summary")
        for alert in resp["alert-definitions"]:
            metric2.add_sample("xio_alert_definitions_definition_exists",
                    value=1,
                    labels={
                        "alert_name":alert["name"],
                        "guid":alert["href"].split("/")[-1]
                    })

        print("alert_definitions: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]
    
    def alerts(self):
        return self.unimplemented("Alerts","alerts")
    
    def bbus(self):
        start = time.time()
        print("BBU's: Starting")
        resp = self.gather_endpoint("bbus")

        metric1 = Metric('xio_bbus_count','Number of bbus',"summary")
        metric1.add_sample('xio_bbus_count',value=len(resp["bbus"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric('xio_bbus_exists',"System name and BBU name included as labels for each existing BBU", "summary")
        metric3 = Metric('xio_bbus_power',"Power usage of BBU", "summary")
        metric4 = Metric("xio_bbus_enabled","Is BBU enabled","summary")
        metric5 = Metric("xio_bbus_average_daily_temp","Average Daily Temperature of BBU","summary")
        metric6 = Metric("xio_bbus_ups_need_battery_replacement","Does the BBU UPS need a battery replacement","summary")
        metric7 = Metric("xio_bbus_ups_low_battery_no_input","Is 1 if the UPS has low battery and is recieving no input","summary")
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

        metric1 = Metric('xio_bricks_count','Number of bricks',"summary")
        metric1.add_sample('xio_bricks_count',value=len(resp["bricks"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_bricks_exist","Brick name and system name in labels for all bricks that exist","summary")
        metric3 = Metric("xio_bricks_ssd_count","Number of SSD's for brick","summary")
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

        metric1 = Metric('xio_clusters_count','Number of clusters',"summary")
        metric1.add_sample('xio_clusters_count',value=len(resp["clusters"]), labels={"href":resp["links"][0]["href"]})
        metric2 = Metric("xio_clusters_exist","Label with the name of cluster that exists","summary")
        metric3 = Metric("xio_clusters_compression_factor","Cluster factor over 1","summary")
        metric4 = Metric("xio_clusters_percent_memory_in_use","Percent of cluster memory in use","summary")
        metric5 = Metric("xio_clusters_read_iops","Cluster read IOPS","summary")
        metric6 = Metric("xio_clusters_write_iops","Cluster write IOPS","summary")
        metric7 = Metric("xio_clusters_number_of_volumes","Cluster number of volumes","summary")
        metric8 = Metric("xio_clusters_free_ssd_space_in_percent","Cluster percent of free SSD space","summary")
        metric9 = Metric("xio_clusters_ssd_num","Cluster read IOPS","summary")
        metric10 = Metric("xio_clusters_data_reduction_ratio","Cluster data reduction ratio","summary")
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

    def consistency_groups(self):
        return self.unimplemented("Consistency Groups","consistency_groups")

    def dae_controllers(self):
        start = time.time()
        print("DAE Controllers: Starting")
        resp = self.gather_endpoint("dae-controllers")

        metric1 = Metric('xio_dae_controllers_count','Number of dae controllers',"summary")
        metric1.add_sample('xio_dae_controllers_count',value=len(resp["dae-controllers"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_dae_controllers_exist","DAE Controller name and system name in labels for all DAE Controllers that exist","summary")
        for dae in resp["dae-controllers"]:
            metric2.add_sample('xio_dae_controller_exist',value=1,labels={"name":dae["name"],"sys_name":dae["sys-name"],"href":dae["href"]})
            
        print("DAE Controllers: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]
        
    def dae_psus(self):
        start = time.time()
        print("DAE PSU's: Starting")
        resp = self.gather_endpoint("dae-psus")

        metric1 = Metric('xio_dae_psus_count',"Number of DAE PSU's","summary")
        metric1.add_sample('xio_dae_psus_count',value=len(resp["dae-psus"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_dae_psus_exist","DAE PSU name and system name in labels for all DAE PSU's that exist","summary")
        for dae in resp["dae-psus"]:
            metric2.add_sample('xio_dae_psus_exist',value=1,labels={"name":dae["name"],"sys_name":dae["sys-name"],"href":dae["href"]})
            
        print("DAE PSU's: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]

    def dae_row_controllers(self):
        return self.unimplemented("DAE Row Controllers","dae_row_controllers")
    
    def daes(self):
        return self.unimplemented("DAE's","daes")
    
    def data_protection_groups(self):
        return self.unimplemented("Data Protection Groups","data_protection_groups")

    def debug_info(self):
        return self.unimplemented("Debug Info","debug_info")
    
    def email_notifier(self):
        return self.unimplemented("Email Notifier","email_notifier")    
    
    def events(self):
        return self.unimplemented("Events","events") 

    def infiniband_switches(self):
        return self.unimplemented("Infiniband Switches","infiniband_switches") 
    
    def initiator_groups(self):
        return self.unimplemented("Initiator Groups","initiator_groups")
    
    def initiators(self):
        return self.unimplemented("Initiators","initiators")

    def ip_links(self):
        return self.unimplemented("IP Links","ip_links")

    def iscsi_portals(self):
        return self.unimplemented("iSCSI Portals","iscsi_portals")
    
    def iscsi_routes(self):
        return self.unimplemented("iSCSI Routes","iscsi_routes")
    
    def ldap_configs(self):
        return self.unimplemented("LDAP Configs","ldap_configs")
    
    def local_disks(self):
        return self.unimplemented("Local Disks","local_disks")

    def local_protections(self):
        return self.unimplemented("Local Protections","local_protections")
        
    def lun_maps(self):
        return self.unimplemented("LUN Maps","lun_maps")

    def nvrams(self):
        return self.unimplemented("NVRAM's","nvrams")

    def protection_domains(self):
        return self.unimplemented("Protection Domains","protection_domains")

    def qos_policies(self):
        return self.unimplemented("QOS Policies","qos_policies")

    def remote_protections(self):
        return self.unimplemented("Remote Protections","remote_protections")

    def retention_policies(self):
        return self.unimplemented("Retention Policies","retention_policies")

    def schedulers(self):
        return self.unimplemented("Schedulers","schedulers")

    def slots(self):
        return self.unimplemented("Slots","slots")

    def snapshot_groups(self):
        return self.unimplemented("Snapshot Groups","snapshot_groups")

    def snapshot_sets(self):
        return self.unimplemented("Snapshot Sets","snapshot_sets")

    def snmp_notifier(self):
        return self.unimplemented("SNMP Notifier","snmp_notifier")

    def ssds(self): 
        start = time.time()
        print("SSD's: Starting")
        resp = self.gather_endpoint("ssds")

        metric1 = Metric('xio_ssds_count',"Number of SSD's","summary")
        metric1.add_sample('xio_ssds_count',value=len(resp["ssds"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_ssds_exist","SSD name and system name in labels for all SSD's that exist","summary")
        metric3 = Metric("xio_ssds_ssd_size","SSD size in kilobytes","summary")
        metric4 = Metric("xio_ssds_ssd_space_in_use","SSD space in use in kilobytes","summary")
        metric5 = Metric("xio_ssds_write_iops","SSD Write IOPS","summary")
        metric6 = Metric("xio_ssds_read_iops","SSD Read IOPS","summary")
        metric7 = Metric("xio_ssds_write_bandwidth","SSD Write Bandwidth","summary")
        metric8 = Metric("xio_ssds_read_bandwidth","SSD Read Bandwidth","summary")
        metric9 = Metric("xio_ssds_num_bad_sectors","Number of sectors on SSD that are bad","summary")
        
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

    def storage_controller_psus(self):
        return self.unimplemented("Storage Controller PSU's","storage_controller_psus")

    def storage_controllers(self):
        return self.unimplemented("Storage Controllers","storage_controllers")

    def syr_notifier(self):
        return self.unimplemented("SYR Notifier","syr_notifier")

    def syslog_notifier(self):
        return self.unimplemented("SysLog Notifier","syslog_notifier")

    def tags(self):
        return self.unimplemented("Tags","tags")

    def target_groups(self):
        return self.unimplemented("Target Groups","target_groups")

    def targets(self):
        return self.unimplemented("Targets","targets")

    def user_accounts(self):
        return self.unimplemented("User Accounts","user_accounts")

    def volume_pairs(self):
        return self.unimplemented("Volume Pairs","volume_pairs")

    def volumes(self):
        start = time.time()
        print("Volumes: Starting")
        resp = self.gather_endpoint("volumes")

        metric1 = Metric('xio_volumes_count',"Number of Volumes","summary")
        metric1.add_sample('xio_volumes_count',value=len(resp["volumes"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_volumes_exist","Volume name and system name in labels for all Volumes that exist","summary")
        for volume in resp["volumes"]:
            metric2.add_sample('xio_volumes_exist',value=1,labels={"name":volume["name"],"sys_name":volume["sys-name"],"href":volume["href"]})
            
        print("Volumes: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]

    def xenvs(self):
        start = time.time()
        print("xEnvs: Starting")
        resp = self.gather_endpoint("xenvs")

        metric1 = Metric('xio_xenvs_count',"Number of xEnvs","summary")
        metric1.add_sample('xio_xenvs_count',value=len(resp["xenvs"]), labels={"href":resp["links"][0]["href"]})

        metric2 = Metric("xio_xenvs_exist","xEnv name and system name in labels for all xEnvs that exist","summary")
        for xenv in resp["xenvs"]:
            metric2.add_sample('xio_xenvs_exist',value=1,labels={"name":xenv["name"],"sys_name":xenv["sys-name"],"href":xenv["href"]})
            
        print("xEnvs: Done in "+str(time.time()-start)+" seconds")
        return [metric1,metric2]
    
    def xms(self):
        start = time.time()
        print("XMS: Starting")
        resp = self.gather_endpoint("xms")

        metric1 = Metric('xio_xms_count',"Number of XMS","summary")
        metric1.add_sample('xio_xms_count',value=len(resp["xmss"]), labels={"href":resp["links"][0]["href"]})
        metric2 = Metric("xio_xms_exist","XMS name and system name in labels for all XMS that exist","summary")
        metric3 = Metric("xio_xms_write_iops","XMS write iops","summary")
        metric4 = Metric("xio_xms_read_iops","XMS read iops","summary")
        metric5 = Metric("xio_xms_overall_efficiency_ratio","XMS overall efficiency ratio","summary")
        metric6 = Metric("xio_xms_ssd_space_in_use","XMS SSD space in use","summary")
        metric7 = Metric("xio_xms_ram_in_use","XMS RAM in use","summary")
        metric8 = Metric("xio_xms_ram_total","XMS RAM total","summary")
        metric9 = Metric("xio_xms_cpu_usage_total","XMS CPU usage total","summary")
        metric10 = Metric("xio_xms_write_latency","XMS write latency","summary")
        metric11 = Metric("xio_xms_read_latency","XMS read latency","summary")
        metric12 = Metric("xio_xms_user_accounts_count","XMS read latency","summary")
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

    def unimplemented(self,name,underscored_name):
        start = time.time()
        print(name+": Starting")
        resp = self.gather_endpoint(underscored_name.replace("_","-"))

        metric1 = Metric('xio_'+underscored_name+'_count',"Number of "+name,"summary")
        metric1.add_sample('xio_'+underscored_name+'_count',value=len(resp[underscored_name.replace("_","-")]), labels={"href":resp["links"][0]["href"]})

        print(name+": Done in "+str(time.time()-start)+" seconds")
        return [metric1]

def main():
    configFile = open("config.json","r")
    config = json.loads(configFile.read())
    configFile.close()

    start_http_server(config["port"])

    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    REGISTRY.register(Collector(config))

    print("Exporter Running")

main()