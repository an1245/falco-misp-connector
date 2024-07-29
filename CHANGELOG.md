## v0.4

Release on 

### Additions
* Added exception list to sample-falco-ipv4-rule.yaml, sample-falco-ipv6-rule.yaml and sample-falco-cidr-rule.yaml

### Changes
* Changed ExpandedPyMISP to PyMISP because ExpandedPyMISP is deprecated

### Upgrades
* Upgraded pymisp==2.4.195

## v0.3

Released on 2024-07-22

### Additions
* Added support for CIDR blocks in MISP Feeds
* the sample-file-[ipv4|cidr]-rule file will now be appended to the output rule file so that it is easier to pass Falco validation
* updated tests so that it will perform Falco rule validation as well
* output the IPv6 indicators to file!  finally!

### Tidy up
* removed some old code which was redundant

### Upgrades
* Upgraded pymisp==2.4.194

### Breaking Changes :warning:
* the sample-file-[ipv4|cidr]-rule file will now be appended to the output rule file so that it is easier to pass Falco validation.  this might appear as a duplicate if you have it elsewhere already.

## v0.2

Released on 2024-06-28

### Additions
* Added basic DecayedScore support
* Added end-to-end testing for IPv4/IPv6 and Domains against curl (debugtest = True in config.py)

### Upgrades
* Upgraded pymisp==2.4.193 and requests==2.32.3 and urllib3==2.2.2

### Breaking Changes :warning:
* Removed the ability to read the existing misp files and process them.  It will just overwrite them now
* Removed the delete capability which was tied to the above read of the existing file - it was taking too long and producing inconsistent results
* Remove misp_remove_deleted configuration option because no longer needed
* Removed "filename", "sha256", "size-in-bytes", "domain", "hostname", "url" until they are supported
