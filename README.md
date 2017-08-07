# Azure Files FUSE Driver
## Enables using SAS Tokens for mounting Azure Files shares

### Motivation
I wanted to be able to use Shared Access Signature (SAS) Tokens for connecting to file shares. Microsoft Azure Files provides CIFS/SMB mounting but, unfortunately, only mounting via Account Key is supported.

### But why would I care about mounting via SAS instead of Account Primary/Secondary key?
Azure Storage primary and secondary keys grant full read/write/delete access to that storage account. This means that the machine with the SMB/CIFS mount, if somehow was compromised, the secret present would gain broader access to Azure than the CIFS/SMB mount ever had leveraged. This violates the principle of least privilege. For this reason, I created this project. 


## Using Azure Files FUSE Driver

- sudo apt-get -y install python3 python3-pip fuse
- sudo pip3 install -r requirements.txt
- /bin/mkdir <mount_point>
- sudo python3 azfilesfuse.py <azure_storage_account> <azure_file_share_name> <sas_token> <mount_point>


### Example
sudo -H -u username python3 azfilesfuse.py 'crwilcoxteststorage' 'testshare' 'se=2017-07-16T20%3A42%3A33Z&sp=rwdl&sv=2016-05-31&sr=s&sig=C/N0tRE%AlLYaKeyD' 'testmount'


## Additional Notes
I am currently using this on Ubuntu 16.04 LTS but it should work on many other Linux platforms.