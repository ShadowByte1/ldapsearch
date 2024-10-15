import subprocess
import re

# Function to run an Nmap scan and extract domain information
def run_nmap(ip):
    # Run nmap with version detection (-sV) and OS detection (-A)
    print(f"[*] Running Nmap scan on {ip} to detect services...")
    nmap_command = ["nmap", "-sV", "-A", "-T5", ip]
    result = subprocess.run(nmap_command, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"[+] Nmap scan completed successfully for {ip}")
        return result.stdout
    else:
        print(f"[-] Nmap scan failed for {ip}. Error: {result.stderr}")
        return None

# Function to extract domain, FQDN, and related information from Nmap results
def extract_domain_info(nmap_result):
    domain = None
    fqdn = None
    os_info = None
    
    # Extract domain, FQDN, and OS info using regex patterns from Nmap output
    print("[*] Extracting domain, FQDN, and OS information from Nmap scan results...")
    for line in nmap_result.splitlines():
        # Example patterns for extracting domain, FQDN, and OS
        domain_match = re.search(r'Domain:\s+([^\s]+)', line)
        fqdn_match = re.search(r'FQDN:\s+([^\s]+)', line)
        os_match = re.search(r'OS:\s+([^\s]+)', line)
        
        if domain_match:
            domain = domain_match.group(1)
            print(f"[+] Domain found: {domain}")
        if fqdn_match:
            fqdn = fqdn_match.group(1)
            print(f"[+] FQDN found: {fqdn}")
        if os_match:
            os_info = os_match.group(1)
            print(f"[+] OS found: {os_info}")
    
    if not domain:
        print("[-] Domain not found in Nmap results.")
    if not fqdn:
        print("[-] FQDN not found in Nmap results.")
    if not os_info:
        print("[-] OS info not found in Nmap results.")
    
    return domain, fqdn, os_info

# Function to perform LDAP query and save results to queries.txt
def ldap_query(ip, base_dn):
    ldap_info_file = "queries.txt"
    
    # LDAP command to collect sAMAccountName information
    ldap_command = f"ldapsearch -x -H ldap://{ip} -b '{base_dn}' '(objectclass=*)' sAMAccountName"
    print(f"[*] Running LDAP Query: {ldap_command}")
    
    try:
        # Run the LDAP command
        result = subprocess.run(ldap_command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Write LDAP output to the queries.txt file
            with open(ldap_info_file, "w") as file:
                file.write(result.stdout)
            print(f"[+] LDAP query completed. Results saved to {ldap_info_file}.")
        else:
            print(f"[-] LDAP query failed: {result.stderr}")
    except Exception as e:
        print(f"[-] Error running LDAP query: {e}")

# Function to extract sAMAccountName from the queries.txt file
def extract_samaccountname():
    ldap_info_file = "queries.txt"
    try:
        print("[*] Extracting sAMAccountName from queries.txt...")
        subprocess.run(f"cat {ldap_info_file} | grep sAMAccountName", shell=True)
    except Exception as e:
        print(f"[-] Error extracting sAMAccountName: {e}")

# Main function
def main():
    # Prompt the user for the target IP
    target_ip = input("Enter the target IP: ")

    # Run the Nmap scan to gather domain and FQDN information
    nmap_result = run_nmap(target_ip)

    if nmap_result:
        # Extract domain and FQDN from the Nmap scan result
        domain, fqdn, os_info = extract_domain_info(nmap_result)
        
        # Format the domain as the base DN for LDAP queries
        if domain:
            base_dn = f"DC={domain.replace('.', ',DC=')}"
            print(f"[+] Using Base DN for LDAP queries: {base_dn}")
            
            # Run the LDAP query to collect sAMAccountName values
            ldap_query(target_ip, base_dn)
            
            # Extract and display sAMAccountName from queries.txt
            extract_samaccountname()
        else:
            print("[-] No domain information found. Cannot perform LDAP queries.")
    else:
        print("[-] Nmap scan did not return valid results.")

if __name__ == "__main__":
    main()
