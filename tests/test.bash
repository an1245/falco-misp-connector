#!/bin/bash

DEBUGTRUE=$(cat ../config.py | grep debugtest | awk -F'= ' '{ print $2 }' | sed "s/'//g")
if [ "$DEBUGTRUE" != "True" ]; then
      echo "debugtest is not equal to True - existing"
      exit
fi
 

if ! [ -f ./ip46.test ]; then
  echo "ip46.test file doesn't exist - please run falco-misp-connector.py first!"
  exit
fi


MISP_API_KEY=$(cat ../config.py | grep misp_auth_key | awk -F'= ' '{ print $2 }' | sed "s/'//g")
MISP_URL=$(cat ../config.py | grep misp_server_url | awk -F'= ' '{ print $2 }' | sed "s/'//g")

echo "Getting ip-dst using curl"
curl -s --insecure -XPOST --header "Authorization: $MISP_API_KEY" --header "Accept: application/json" --header "Content-Type: application/json" -d '{"returnFormat":"json","to_ids":true, "deleted":false, "excludeDecayed":true, "type":"ip-dst"}'  https://$MISP_URL/attributes/restSearch | jq .response.Attribute[].value | sed 's/\"//g' |sort | uniq > ./curl-ip46.out
cat ip46.test | sort |uniq > ip46.test.sorted
echo "Performing diff on IP address outputs"
diff curl-ip46.out ip46.test.sorted

echo "Validating Falco rules files"
timeout --preserve-status 5s falco -c /etc/falco/falco.yaml -r /etc/falco/falco_rules.yaml -r ./ipv4-rules.yaml -r ./ipv6-rules.yaml -r ./cidr-rules.yaml
status=$?
if [ $status -eq 0 ]; then
      echo "Validation Successful"
else
      echo "Validation Failed!"
      exit 1
fi
