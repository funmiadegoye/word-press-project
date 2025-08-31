variable "redhat_ami" {}
variable "instance_type" {}
variable "db_username" {}
variable "db_password" {}
# variable "alert_email" {}
variable "db_name" {}
variable "db_host" {}
# variable "cloudfront_domain" {}
variable "dbcred1" {
  type = map(string)
  default = {
    username = "admin"
    password = "admin123"
  }
}
variable "alert_email" {}