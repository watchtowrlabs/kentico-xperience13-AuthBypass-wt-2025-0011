# WT-2025-0011 (CVE not assigned yet)
Kentico Xperience 13 CMS - Staging Service Authentication Bypass Check
 

# Detection in Action

```
python3 .\watchTowr-vs-kentico-xperience13-AuthBypass-wt-2025-0011.py -H http://labcms -u admin
                         __         ___  ___________
         __  _  ______ _/  |__ ____ |  |_\__    ____\____  _  ________
         \ \/ \/ \__  \    ___/ ___\|  |  \|    | /  _ \ \/ \/ \_  __ \
          \     / / __ \|  | \  \___|   Y  |    |(  <_> \     / |  | \/
           \/\_/ (____  |__|  \___  |___|__|__  | \__  / \/\_/  |__|
                                  \/          \/     \/

        watchTowr-vs-kentico-xperience13-AuthBypass-wt-2025-0011.py
        (*) WT-2025-0011: Kentico Xperience 13 CMS - Staging Service Authentication Bypass Check

          - Piotr Bazydlo (@chudyPB) of watchTowr

        CVEs: TBD

[+] Verifying Authentication Bypass in Staging API
[+] VULNERABLE: Authentication Bypassed!
```

# Description

This script attempts to bypass authentication on Kentico Xperience 13 CMS Staging Service. It sends a single POST request and analyzes the API response.

It accepts an optional `-u` argument, which defines the Staging Service username (default: `admin`).

Before Kentico Xperience 13 Hotfix 173, this vulnerability can be exploited with any username provided.
For Hotfix >= 173 and < 178, this vulnerability can be exploited only if you provide a valid Staging Service username (default: `admin`).
Hotfix 178 delivers a patch and is not vulnerable.

# Affected Versions

* Kentico Xperience 13 before Hotfix 178
* Configuration: Staging Service needs to be enabled with the username/password authentication

Different Kentico Xperience versions were not tested (like Kentico Xperience 12).

# Note

Exploitation process is slightly different depending on the Kentico Hotfix level. See `Description` section for details.

# Follow [watchTowr](https://watchTowr.com) Labs

For the latest security research follow the [watchTowr](https://watchTowr.com) Labs Team 

- https://labs.watchtowr.com/
- https://x.com/watchtowrcyber