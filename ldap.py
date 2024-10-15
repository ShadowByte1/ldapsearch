import subprocess
import re

# ANSI escape codes for colors
RESET = "\033[0m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"

# Function to run an Nmap scan and extract domain information
def run_nmap(ip):
    print(f"{CYAN}[*] Running Nmap scan on {ip} to detect services...{RESET}")
    nmap_command = ["nmap", "-sV", "-A", "-T5", ip]
    result = subprocess.run(nmap_command, capture_output=True, text=True)
    
    if result.returncode == 0:
        print(f"{GREEN}[+] Nmap scan completed successfully for {ip}{RESET}")
        return result.stdout
    else:
        print(f"{RED}[-] Nmap scan failed for {ip}. Error: {result.stderr}{RESET}")
        return None

# Function to extract domain, FQDN, and related information from Nmap results
def extract_domain_info(nmap_result):
    domain = None
    fqdn = None
    os_info = None
    
    print(f"{CYAN}[*] Extracting domain, FQDN, and OS information from Nmap scan results...{RESET}")
    for line in nmap_result.splitlines():
        domain_match = re.search(r'Domain:\s+([^\s]+)', line)
        fqdn_match = re.search(r'FQDN:\s+([^\s]+)', line)
        os_match = re.search(r'OS:\s+([^\s]+)', line)
        
        if domain_match:
            domain = domain_match.group(1)
            print(f"{GREEN}[+] Domain found: {domain}{RESET}")
        if fqdn_match:
            fqdn = fqdn_match.group(1)
            print(f"{GREEN}[+] FQDN found: {fqdn}{RESET}")
        if os_match:
            os_info = os_match.group(1)
            print(f"{GREEN}[+] OS found: {os_info}{RESET}")
    
    if not domain:
        print(f"{YELLOW}[-] Domain not found in Nmap results.{RESET}")
    if not fqdn:
        print(f"{YELLOW}[-] FQDN not found in Nmap results.{RESET}")
    if not os_info:
        print(f"{YELLOW}[-] OS info not found in Nmap results.{RESET}")
    
    return domain, fqdn, os_info

# Function to perform LDAP query and save results to queries.txt
def ldap_query(ip, base_dn):
    ldap_info_file = "queries.txt"
    
    # Correct LDAP command with double quotes
    ldap_command = f'ldapsearch -H "ldap://{ip}" -b "{base_dn}" "(objectclass=*)" -x sAMAccountName'
    print(f"{CYAN}[*] Running LDAP Query: {ldap_command}{RESET}")
    
    try:
        # Run the LDAP command
        result = subprocess.run(ldap_command, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Write LDAP output to the queries.txt file
            with open(ldap_info_file, "w") as file:
                file.write(result.stdout)
            print(f"{GREEN}[+] LDAP query completed. Results saved to {ldap_info_file}.{RESET}")
        else:
            print(f"{RED}[-] LDAP query failed with error: {result.stderr}{RESET}")
    except Exception as e:
        print(f"{RED}[-] Error running LDAP query: {e}{RESET}")

# Function to extract sAMAccountName from the queries.txt file
def extract_samaccountname():
    ldap_info_file = "queries.txt"
    try:
        print(f"{CYAN}[*] Extracting sAMAccountName from {ldap_info_file}...{RESET}")
        subprocess.run(f"cat {ldap_info_file} | grep sAMAccountName", shell=True)
    except Exception as e:
        print(f"{RED}[-] Error extracting sAMAccountName: {e}{RESET}")

# Main function
def main():
    # Prompt the user for the target IP
    target_ip = input(f"{CYAN}Enter the target IP: {RESET}")

    # Run the Nmap scan to gather domain and FQDN information
    nmap_result = run_nmap(target_ip)

    if nmap_result:
        # Extract domain and FQDN from the Nmap scan result
        domain, fqdn, os_info = extract_domain_info(nmap_result)
        
        # Format the domain as the base DN for LDAP queries
        if domain:
            base_dn = f"DC={domain.replace('.', ',DC=')}"
            print(f"{CYAN}[+] Using Base DN for LDAP queries: {base_dn}{RESET}")
            
            # Run the LDAP query to collect sAMAccountName values
            ldap_query(target_ip, base_dn)
            
            # Extract and display sAMAccountName from queries.txt
            extract_samaccountname()
        else:
            print(f"{RED}[-] No domain information found. Cannot perform LDAP queries.{RESET}")
    else:
        print(f"{RED}[-] Nmap scan did not return valid results.{RESET}")

if __name__ == "__main__":
    main()
