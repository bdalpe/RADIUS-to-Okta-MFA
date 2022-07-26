# OKTA Radius to MFA Gateway

I ran into an issue with Okta and the Remote Desktop Gateway/Network Policy Server not working correctly. This program overcomes the issues and allows for you to enforce multi-factor authentication on connections made through the RD Gateway.

Some assumptions were made when designing this program. This program only supports the Okta Push verification method. A user must already be setup/enrolled with a push factor. Second, no group enforcement is currently done on the Okta side. You must control access to your Remote Desktop services through the NPS. 

### Requirements 

You will need the following information:
1. Your Okta tenant url (e.g. planet-express.okta.com)
2. An API key from your tenant
3. The shared RADIUS secret the calling station

### Setup and Run
#### Standalone
To run the program standalone:

Ensure Python >3.7 is installed. Edit the environment variables in the `run.sh` script.

```commandline
pip3 install -r requirements.txt
/bin/sh run.sh
```

#### Docker Container
To run the program using Docker:

Edit the environment variables in the `docker-compose.yml` file. Then run:

```commandline
docker-compose up -d
```

#### API Permissions

To follow security best practices, I recommend using the least privileged account permissions possible. To make this program work with Okta, a **Help Desk Administrator** level account is required. It is not recommended that you use an API key tied to a superadmin or org admin.

#### Using `samAccountName` to Find a User

By default, the server will use the Okta username to locate the user record, however some systems use `samAccountName` as the username identifier. To locate user records in Okta by the `samAccountName` attribute, add the following to your `run.sh`:

```shell
export OKTA_USE_SAMACCOUNTNAME=true
```

#### Poll Timeout

To reduce the likelihood that a user is prompted multiple times for a single authentication request, requests to the Okta verify endpoint are threaded. Internally, state is kept for each `user_id` that is authenticating. If multiple requests are received before the user has responded to the push challenge and the `OKTA_POLL_TIMEOUT` window has not expired yet, the subsequent requests will wait for the first request to complete and return the same result.

To customize the timeout period for the verification request, set the `OKTA_POLL_TIMEOUT` environment variable. Default setting is 60 seconds. 

```shell
export OKTA_POLL_TIMEOUT=60
```