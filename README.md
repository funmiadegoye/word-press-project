# WordPress Infrastructure on AWS (Terraform)

This project provisions a scalable, secure, and highly available WordPress environment on AWS using Terraform. It includes VPC, subnets, EC2, RDS, S3, CloudFront, IAM, CloudWatch, Route53, and more.

## Features

- **VPC & Subnets:** Custom VPC with public/private subnets across multiple AZs.
- **EC2 Instance:** WordPress server with user data for automated setup.
- **RDS MySQL:** Managed database in private subnets.
- **S3 Buckets:** For media, code, and logs, with appropriate policies.
- **CloudFront:** CDN for media content.
- **Load Balancer & Auto Scaling:** Application Load Balancer, target groups, launch template, and auto scaling group.
- **IAM Roles & Policies:** Least-privilege roles for EC2 and S3 access.
- **CloudWatch:** Monitoring, alarms, and dashboard.
- **Route53:** DNS records for domain and certificate validation.
- **ACM:** SSL certificate for HTTPS.
- **SNS:** Email alerts for monitoring.
- **Checkov Integration:** Security scanning with Slack notifications.

## File Structure

- `main.tf` – Main Terraform configuration (resources, networking, compute, storage, IAM, monitoring, etc.)
- `provider.tf` – AWS provider configuration.
- `variable.tf` – Input variables.
- `output.tf` – Outputs (e.g., public IP, DB endpoint).
- `wordpress_user_data.tf` – EC2 user data script for WordPress setup.
- `set25-key.txt` – RSA private key (should be kept secure, not committed).
- `checkov_scan.sh` – Script to run Checkov security scans and send Slack alerts.
- `.gitignore` – Ignores WordPress core, uploads, and sensitive files.
- `gitignore.txt` – Ignores Terraform state, logs, and sensitive files.
- `README.md` – Project documentation.

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html) v1.0+
- AWS CLI configured with sufficient permissions
- Domain name (e.g., `selfdevops.space`) managed in Route53
- [Checkov](https://www.checkov.io/) and [jq](https://stedolan.github.io/jq/) for security scanning (optional)
- Slack webhook URL for notifications (optional)

## Usage

1. **Clone the repository:**
   ```sh
   git clone <repo-url>
   cd word-press-project
   ```

2. **Initialize Terraform:**
   ```sh
   terraform init
   ```

3. **Set variables:**
   - Edit `variable.tf` or use a `terraform.tfvars` file for values like AMI, instance type, DB credentials, and alert email.

4. **Run Checkov scan (optional but recommended):**
   ```sh
   bash checkov_scan.sh
   ```

5. **Apply the Terraform configuration:**
   ```sh
   terraform apply
   ```

6. **Access WordPress:**
   - Use the output public IP or domain name to access your WordPress site.

## Security

- Sensitive files like `set25-key.txt` and Terraform state files are ignored via `.gitignore` and `gitignore.txt`.
- Secrets are managed using AWS Secrets Manager.
- S3 buckets have policies and public access blocks as appropriate.
- IAM roles follow least-privilege principles.

## Clean Up

To destroy all resources:
```sh
terraform destroy
```

## Notes

- Ensure your AWS account has the necessary quotas and permissions.
- The EC2 user data script installs WordPress, configures Apache, PHP, and syncs content to S3.
- CloudFront is used for serving media files via CDN.
- Route53 and ACM are used for DNS and SSL.
- Checkov scan results are sent to Slack if configured.

## Authors

-Hannah Adegoye

## License

MIT Licence

