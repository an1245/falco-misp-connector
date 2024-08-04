#!/bin/bash

DEBUGTRUE=$(cat ../config.py | grep debugtest | awk -F'= ' '{ print $2 }' | sed "s/'//g")
if [ "$DEBUGTRUE" != "True" ]; then
      echo "debugtest is not equal to True - existing"
      exit
fi
 

if ! [ -f ./ip46-outbound.test ]; then
  echo "ip46-outbound.test file doesn't exist - please run falco-misp-connector.py first!"
  exit
fi

if ! [ -f ./ip46-inbound.test ]; then
  echo "ip46-inbound.test file doesn't exist - please run falco-misp-connector.py first!"
  exit
fi


MISP_API_KEY=$(cat ../config.py | grep misp_auth_key | awk -F'= ' '{ print $2 }' | sed "s/'//g")
MISP_URL=$(cat ../config.py | grep misp_server_url | awk -F'= ' '{ print $2 }' | sed "s/'//g")


# outbound
echo "Getting ip-dst using curl"
curl -s --insecure -XPOST --header "Authorization: $MISP_API_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -d '{"returnFormat":"json","to_ids":true, "deleted":false, "excludeDecayed":true, "type":"ip-dst"}'  https://$MISP_URL/attributes/restSearch | jq .response.Attribute[].value | sed 's/\"//g' |sort | uniq > ./curl-ip46-outbound.out
cat ip46-outbound.test | sort |uniq > ip46-outbound.test.sorted
echo "Performing diff on outbound IP addresses"
diff curl-ip46-outbound.out ip46-outbound.test.sorted

# inbound
echo "Getting ip-src using curl"
curl -s --insecure -XPOST --header "Authorization: $MISP_API_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -d '{"returnFormat":"json","to_ids":true, "deleted":false, "excludeDecayed":true, "type":"ip-src"}'  https://$MISP_URL/attributes/restSearch | jq .response.Attribute[].value | sed 's/\"//g' |sort | uniq > ./curl-ip46-inbound.out
cat ip46-inbound.test | sort |uniq > ip46-inbound.test.sorted
echo "Performing diff on inbound IP addresses"
diff curl-ip46-inbound.out ip46-inbound.test.sorted

echo "Validating Falco outbound rules files"
timeout --preserve-status 5s falco -c /etc/falco/falco.yaml -r /etc/falco/falco_rules.yaml -r /etc/falco/falco-sandbox_rules.yaml -r ./ipv4-outbound-rules.yaml -r ./ipv6-outbound-rules.yaml -r ./cidr-outbound-rules.yaml -r ./ipv4-inbound-rules.yaml -r ./ipv6-inbound-rules.yaml -r ./cidr-inbound-rules.yaml
status=$?
if [ $status -eq 0 ]; then
      echo "Validation Successful"
else
      echo "Validation Failed!"
      exit 1
fi