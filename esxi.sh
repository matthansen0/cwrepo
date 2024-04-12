#!/bin/sh
# Set default firewall action to false
esxcli network firewall set --default-action false

# Disable all firewall rules
for RULESET in $(esxcli network firewall ruleset list | grep true | awk '{print $1}')
do
    # Print what rule is being disabled
    echo "Disabling rule: $RULESET"
    esxcli network firewall ruleset set --enabled false --ruleset-id "$RULESET"
done

# create a list of rules to enable
rules="ntp httpClient webAccess vSphereClient dns dhcp"

# Enable the rules
for RULE in $rules
do
    # Print what rule is being enabled
    echo "Enabling rule: $RULE"
    esxcli network firewall ruleset set --enabled true --ruleset-id "$RULE"
done

# Apply the firewall rules
echo "Applying firewall rules"
esxcli network firewall refresh
