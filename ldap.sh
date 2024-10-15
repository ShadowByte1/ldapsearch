#!/bin/bash

# Prompt the user for the IP address
read -p "Enter the target IP for the LDAP server: " TARGET_IP

# Run an nmap service version detection scan (-sV) on the user-provided IP
echo "Running nmap scan to detect services..."
NMAP_OUTPUT=$(nmap -sV "$TARGET_IP")

# Display nmap output
echo "$NMAP_OUTPUT"

# Attempt to extract the base DN from the nmap output (customize this based on expected format)
# Here we assume nmap output contains relevant LDAP information, adjust the grep accordingly
BASE_DN=$(echo "$NMAP_OUTPUT" | grep -i "Domain:" | awk '{print $2}')

# If we couldn't extract the base DN, prompt the user for it
if [ -z "$BASE_DN" ]; then
  echo "Could not detect the Base DN from the nmap scan."
  read -p "Please manually enter the Base DN (e.g., DC=secura,DC=yzX): " BASE_DN
else
  echo "Detected Base DN: $BASE_DN"
fi

# Use the extracted or manually provided Base DN and the target IP to perform the ldapsearch
echo "Performing LDAP search using Base DN: $BASE_DN"

# Perform ldapsearch to retrieve users based on sAMAccountName
ldapsearch -x -H "ldap://$TARGET_IP" -b "$BASE_DN" "(objectClass=user)" sAMAccountName | grep "sAMAccountName" | awk '{print $2}'

echo "LDAP search completed."
