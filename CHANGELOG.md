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