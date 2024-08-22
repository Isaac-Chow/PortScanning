import nmap

class NmapScan:
    def __init__(self, target):
        self.nm = nmap.PortScanner()

        self.target = target

    def perform_nmap_scan(self):
        self.nm.scan(self.target, ports="1-1000", arguments="sT")
        print("\n--------------------------------------------------------------")
        print(f"Nmap port scan TCP on:\n{self.target}")

        for host in self.nm.all_hosts():
            print(f"\nHost: {host}")
            print(f"State: {self.nm[host].state()}")

            for proto in self.nm[host].all_protocols():
                print(f"Protocol:{proto}")

                ports = self.nm[host][proto].keys()
                for port in ports:
                    print(f"Port: {port} - State: {self.nm[host][proto][port]['state']}")
        
        print("\n--------------------------------------------------------------")
        print("Nmap Scan CSV Output:")
        print(self.nm.csv())

        nmap_scan_object = NmapScan("scanme.nmap.org")
        nmap_scan_object.perform_nmap_scan()