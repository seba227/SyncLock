# SyncLock

PowerShell script to run the SyncLock attack: disabling users (cloud-only or synced) using a sync identity bearer token and the Sync API.

For detailed information regarding the attack, read [this post](https://mnemonic.io).

##  Disable_cloud_user.ps1

Main script that carries out the attack.

Usage:

```
.\Disable_cloud_user.ps1 -BearerToken "eyJ0..." -CloudAnchor "User_<ObjectID>"
```

Parameters:
- `BearerToken`: JWT of the Sync Principal towards the Sync API (aud: 6bf85cfa-ac8a-4be5-b5de-425a0d0dc016). Can be fetched using `Get-SyncAccessToken.ps1`.
- `CloudAnchor`: Used to identify the user to be disabled. Follows the format `User_<UUID4>`, where the UUID4 is the ObjectID of the user.

## Get-SyncAccessToken.ps1

Helper script I included that can be used to fetch a JWT for the Sync Service Principal. Needs to be run on the Entra Connect Sync server as local admin.

Usage:

```
.\Get-SyncAccessToken.ps1 -TenantId 'contoso.onmicrosoft.com' -ClientId '<sync-sp-appid>'
```

Parameters:
- `TenantId`: TenantId of the target tenant. Can be either the UUID4 or the primary domain.
- `ClientId`: Application ID of the Sync Service Principal. Look for the SP whose name starts with `ConnectSyncProvisioning_*`.