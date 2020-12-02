#!/bin/sh

export OKTA_TENANT=yourtenant.okta.com
export OKTA_API_KEY=XXXXXX
export RADIUS_SECRET=******

p=$(which python3)
$p server.py