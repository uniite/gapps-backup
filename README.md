## Overview
Includes a script for backing up your GMail account over IMAP to S3 (or local fs, with some tweaks).
It will automatically encrypt each message with GPG, compress it with GZip, and place it in a predictable place
on your storage provider of choice.

In the future, this may support backing up additional parts of your acount (such as Contacts, and Calendar).

## How to Use
1. Install the script's dependencies:
`pip install -r requirements.txt`
1. Create config.py (see config.py.example for help). You need at least one storage provider.
*Note: You should use an application-specific password for your account.
I can not be held responsible for any password or security-related issues.*
1. Run the script, and be patient (the first backup, as with any backup tool, takes a while).
1. Run it again to make sure it backed up properly (it should say little to nothing additional needs to be backed up).
1. Set it up as a cron job, and enjoy.
