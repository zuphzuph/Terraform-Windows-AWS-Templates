# Terraform Windows AWS Templates
This repo includes terraform templates for various uses.
Templated tested on v0.11.11.

Current Templates:
Server 2019 w/ IIS (webserver)
Server 2019 w/ MSSQL 2017 (dbserver)

Requirements:
AWS - IAM Permissions and Access/Secret key for EC2 Administraton | SSH Key Pair | VPC | Security Groups (Should be reachable by machine deployed from.)
Terraform - fully installed and configured.

Steps:
Pull sub directory, plug in information and execute files from local dir using: terraform init (create req files) | terraform plan (preview of creation) | terraform deploy (push to AWS) | terraform destroy (teardown)
