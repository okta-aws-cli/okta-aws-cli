# okta-aws-cli

Tool to access AWS CLI via Okta SSO, using either account-level MFA or app-level MFA, with chained roles through a managing account.

This tool works with Python 2.7 and 3.6 on Windows and Linux/Mac, install the necessary libraries per requirements.txt (sudo pip install -r requirements.txt).

Make sure the provided 'oktacli' config file exists as ~/.aws/oktacli. You'll have to create profiles for each of your accounts, following the sample format present in the file. Add as many accounts as needed. Also make sure to verify the two URLs in the config file (API and SAML). Grab the SAML URL from your Okta setup by doing a debug session on the browser.

Current supported MFA modes are:
- OKTA / TOTP
- OKTA / Push
- GOOGLE / TOTP

Run the script with "./okta-aws-cli.py $Profile" where $Profile is the name of the account profile under ~/.aws/oktacli. When running the script for the first time you will be prompted for a password and then an MFA push. 

Enable the newly generated credential with the 'export' command at the end of the script output. If you need to change the MFA option, simply delete the mfa_factor line from the oktacli config file. 

The script will save the credentials file, so the only addition you will need is for your .bashrc or .profile.
