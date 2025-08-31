locals {
  db_cred = jsondecode(aws_secretsmanager_secret_version.db_cred_version.secret_string)

}

#checkov
# resource "null_resource" "checkov_scan" {
#   provisioner "local-exec" {
#     command = "./checkov_scan.sh"
#     interpreter = [ "bash", "-c"]
#   }
# provisioner "local-exec" {
# when = destroy
# command = "rm -f checkov_output.json" 
# }
#   triggers = {
#     always_run = timestamp()
#   }
# }
# output "checkov_scan_status" {
# value = "checkov scan completed check the output.json file for details"
# }

#Create a VPC
resource "aws_vpc" "vpc" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "Set25-vpc"
  }
}

# This assumes the VPC already exists and is defined in the same workspace
resource "aws_subnet" "public_subnet_1" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "eu-west-3a"
  map_public_ip_on_launch = true
  tags = {
    Name = "set25-public-subnet-1"
  }
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "eu-west-3b"
  map_public_ip_on_launch = true
  tags = {
    Name = "set25-public-subnet-2"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "eu-west-3a"
  map_public_ip_on_launch = true
  tags = {
    Name = "set25-private-subnet-1"
  }
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id                  = aws_vpc.vpc.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "eu-west-3b"
  map_public_ip_on_launch = true
  tags = {
    Name = "set25-private-subnet-2"
  }
}
# Create an Internet Gateway
resource "aws_internet_gateway" "igw-set25" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "igw-set25"
  }
}

# Route table for private subnet
resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.set25-nat-gw.id
  }

  tags = {
    Name = "set25-pri-rt-1"
  }
}

# Route table for public subnets
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw-set25.id
  }

  tags = {
    Name = "set25-public-rt-1"
  }
}

# Route table association for public subnet 1
resource "aws_route_table_association" "pri_assoc-1" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

resource "aws_route_table_association" "pri_assoc-2" {
  subnet_id      = aws_subnet.private_subnet_2.id
  route_table_id = aws_route_table.private_rt.id
}

# Route table association for public subnet 1 and 2
resource "aws_route_table_association" "pub_assoc-1" {
  subnet_id      = aws_subnet.public_subnet_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "pub_assoc-2" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.public_rt.id
}

# Elastic IP
resource "aws_eip" "set25-eip" {
  domain = "vpc"
  tags = {
    Name = "set25-eip"
  }
}

# Create Nat Gateway
resource "aws_nat_gateway" "set25-nat-gw" {
  allocation_id = aws_eip.set25-eip.id
  subnet_id     = aws_subnet.public_subnet_1.id
  tags = {
    Name = "set25-NAT"
  }
  depends_on = [aws_internet_gateway.igw-set25]
}

#creating securitygroup
resource "aws_security_group" "set25-ec2_sg" {
  name   = "set25-ec2-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    description = "Allow ssh inbound traffic"
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow https inbound traffic"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow http inbound traffic"
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "set25-ec2-sg"
  }
}

resource "aws_security_group" "set25-rds" {
  name   = "set25-rds-sg"
  vpc_id = aws_vpc.vpc.id

  ingress {
    description = "Allow https inbound traffic"
    protocol    = "tcp"
    from_port   = 3306
    to_port     = 3306
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "set25-rds-sg"
  }
}

resource "tls_private_key" "key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "key" {
  content         = tls_private_key.key.private_key_pem
  filename        = "set25-key"
  file_permission = "600"
}
resource "aws_key_pair" "key" {
  key_name   = "set25-pub-key"
  public_key = tls_private_key.key.public_key_openssh
}

# IAM Role for EC2 instances
resource "aws_iam_role" "wordpress_ec2_role" {
  name = "Ste24_WordPressEC2ServiceRole"

  description = "IAM role assumed by EC2 instances in the WordPress image-sharing app for secure resource access."

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Project = "WordPressImageSharing"
    Purpose = "EC2InstanceRole"
  }
}



# WordPress EC2 Instance
resource "aws_instance" "wordpress_server" {
  ami                         = var.redhat_ami
  instance_type               = var.instance_type
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.public_subnet_1.id
  #depends_on = [ null_resource.checkov_scan ]
  vpc_security_group_ids = [
    aws_security_group.set25-ec2_sg.id,
    aws_security_group.set25-rds.id
  ]

  iam_instance_profile = aws_iam_instance_profile.wordpress_instance_profile.name
  key_name             = aws_key_pair.key.id
  user_data            = local.wordpress_script


  # depends_on = [null_resource.pre_scan]

  tags = {
    Name    = "set25-wordpress-server"
    Project = "WordPressImageSharing"
  }
}

# Amazon machine image (AMI) for the backend instance
resource "aws_ami_from_instance" "set-custom_ami" {
  name                    = "set25-custom-ami"
  source_instance_id      = aws_instance.wordpress_server.id
  snapshot_without_reboot = true
  depends_on              = [aws_instance.wordpress_server, time_sleep.ami-sleep]
}

resource "time_sleep" "ami-sleep" {
  depends_on      = [aws_instance.wordpress_server]
  create_duration = "300s"
}

# Custom Policy with Least Privilege permissions for the role
resource "aws_iam_policy" "wordpress_ec2_policy" {
  name        = "Ste24_WordPressEC2LimitedPolicy1"
  description = "Policy granting EC2 instances access to essential AWS services for WordPress image sharing."

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "secretsmanager:GetSecretValue"
        ],
        Resource = "*"
      }
    ]
  })
}

# Attach the Policy to the Role
resource "aws_iam_role_policy_attachment" "wordpress_role_policy_attach" {
  role       = aws_iam_role.wordpress_ec2_role.name
  policy_arn = aws_iam_policy.wordpress_ec2_policy.arn

}

# IAM Instance Profile to associate the Role with EC2 instances
resource "aws_iam_instance_profile" "wordpress_instance_profile" {
  name = "Ste24_WordPressInstanceProfile"
  role = aws_iam_role.wordpress_ec2_role.name
}



# #insert secret manager here
resource "aws_secretsmanager_secret" "db_cred1" {
  name        = "db_cred8"
  description = "Database credentials for the WordPress image-sharing application"
}

resource "aws_secretsmanager_secret_version" "db_cred_version" {
  secret_id     = aws_secretsmanager_secret.db_cred1.id
  secret_string = jsonencode(var.dbcred1)
}
#database
# First create a DB Subnet Group
resource "aws_db_subnet_group" "wordpress_db_subnet" {
  name       = "wordpress-db-subnet5"
  subnet_ids = [aws_subnet.private_subnet_1.id, aws_subnet.private_subnet_2.id]

  tags = {
    Name = "wordpress-db-subnet"
  }
}

#Create RDS MySQL Instance
resource "aws_db_instance" "wordpress_db" {
  identifier             = "wordpress-db"
  allocated_storage      = 20
  max_allocated_storage  = 100 #define storage auto scaling
  storage_type           = "gp2"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t3.micro"
  username               = local.db_cred.username          # DB user
  password               = local.db_cred.password        # DB password
  parameter_group_name   = "default.mysql8.0"
  db_subnet_group_name   = aws_db_subnet_group.wordpress_db_subnet.name
  vpc_security_group_ids = [aws_security_group.set25-rds.id]
  skip_final_snapshot    = true #Whether to skip the final snapshot before deletion
  deletion_protection = false #Prevent accidental deletion
  publicly_accessible      = false
  backup_retention_period  = 3 #days to keep automated RDS backups
  backup_window            = "03:00-04:00" #backups will happen between...
  db_name = var.db_name

  tags = {
    Name = "wordpress-db"
  }
}

#application load balancer
resource "aws_lb" "wordpress_alb" {
  name               = "wordpress-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.set25-ec2_sg.id]
  subnets            = [aws_subnet.public_subnet_1.id, aws_subnet.public_subnet_2.id]

  enable_deletion_protection = false

  tags = {
    Name = "wordpress-alb"
  }
}

#application target group
resource "aws_lb_target_group" "wordpress_tg" {
  name     = "wordpress-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id

  health_check {
    path                = "/indextest.html"
    interval            = 60
    timeout             = 30
    healthy_threshold   = 3
    unhealthy_threshold = 5
    port                = 80
  }

  tags = {
    Name = "wordpress-target-group"
  }
}

# HTTTPS Target Group
resource "aws_lb_target_group" "wordpress-https_tg" {
  name     = "wordpress-https-tg"
  port     = 443
  protocol = "HTTPS"
  vpc_id   = aws_vpc.vpc.id

  health_check {
    path                = "/indextest.html"
    interval            = 60
    timeout             = 30
    healthy_threshold   = 3
    unhealthy_threshold = 5
    port                = 433
  }

  tags = {
    Name = "wordpress-https-target-group"
  }
}

# Load balancer attachement
resource "aws_lb_target_group_attachment" "lb_attachment_http" {
  target_group_arn = aws_lb_target_group.wordpress_tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "lb_attachment_https" {
  target_group_arn = aws_lb_target_group.wordpress-https_tg.arn
  target_id        = aws_instance.wordpress_server.id
  port             = 443
}

# launch template
resource "aws_launch_template" "set25-launch-template" {
  name_prefix   = "set25-lt"
  image_id      = aws_ami_from_instance.set-custom_ami.id
  instance_type = "t2.medium"
  key_name = aws_key_pair.key.id
  iam_instance_profile {
    name = aws_iam_instance_profile.wordpress_instance_profile.id
  }
  network_interfaces {
    associate_public_ip_address = true
    security_groups = [aws_security_group.set25-ec2_sg.id]
  }
  user_data = base64encode(local.wordpress_script)
}

#auto scaling policy
resource "aws_autoscaling_policy" "scale_out" {
  name                   = "scale-out-policy"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  
  autoscaling_group_name = aws_autoscaling_group.set25-auto-scaling-group.name
}

# Autoscaling group
resource "aws_autoscaling_group" "set25-auto-scaling-group" {
  name                      = "set25-auto-scaling-group"
  desired_capacity          = 2
  max_size                  = 5
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  force_delete              = true


  launch_template {
    id      = aws_launch_template.set25-launch-template.id
    version = "$Latest"
  }

  vpc_zone_identifier = [
    aws_subnet.public_subnet_1.id,
    aws_subnet.public_subnet_2.id
  ]

  target_group_arns = [aws_lb_target_group.wordpress_tg.arn, aws_lb_target_group.wordpress-https_tg.arn]
}

#insert two target groups. one for http and another for https here

#load balancer listener
resource "aws_lb_listener" "wordpress_listener" {
  load_balancer_arn = aws_lb.wordpress_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_tg.arn
  }
}
#creating acm certificate for ssl
resource "aws_acm_certificate" "acm_cert" {
  domain_name               = "selfdevops.space"
  validation_method         = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

# Create a listener for HTTPS
resource "aws_lb_listener" "wordpress-https_listener" {
  load_balancer_arn = aws_lb.wordpress_alb.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn = aws_acm_certificate.acm_cert.arn
  ssl_policy = "ELBSecurityPolicy-2016-08"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress-https_tg.arn
  }
}
#creat another target group listener for https 

resource "aws_route53_record" "validate-record" {
  for_each = {
    for dvo in aws_acm_certificate.acm_cert.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
 
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.set-25_zone.zone_id
}
resource "aws_acm_certificate_validation" "cert-validation" {
  certificate_arn         = aws_acm_certificate.acm_cert.arn
  validation_record_fqdns = [for record in aws_route53_record.validate-record : record.fqdn]
}
 
locals {
  s3_origin_id = aws_s3_bucket.media-bucket.id
}
#creat load balancer

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-utilization"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 70

  alarm_description   = "Triggers when CPU exceeds 70% utilization"
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.set25-auto-scaling-group.name
  }

  alarm_actions = [
    aws_autoscaling_policy.scale_out.arn,
    aws_sns_topic.server_alert.arn
  ]
}




#create s3 policy for log bucket. Ensure only users/roles from the AWS account can access this bucket.
# resource "aws_s3_bucket_policy" "log-policy" {
#   bucket = aws_s3_bucket.log-bucket.id
#   alarm_description   = "This alarm triggers when CPU exceeds 70%"
#   dimensions = {
#     AutoScalingGroupName = aws_autoscaling_group.set25-auto-scaling-group.name
#   }

#   alarm_actions = [aws_autoscaling_policy.scale_out.arn]
# }


# create media bucktet
resource "aws_s3_bucket" "media-bucket" {
  bucket        = "set25-media-bucket"
  force_destroy = true
  #depends_on    = [null_resource.pre_scan]
  tags = {
    Name = "set25-media-bucket"
  }
 
}
 
resource "aws_s3_bucket_public_access_block" "set25_media_pub" {
  bucket                  = aws_s3_bucket.media-bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
 
}
 
resource "aws_s3_bucket_ownership_controls" "set25_media_ctrl" {
  bucket = aws_s3_bucket.media-bucket.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
  depends_on = [aws_s3_bucket_public_access_block.set25_media_pub]
 
}
 
# Media Bucket policy
resource "aws_s3_bucket_policy" "set25_media_policy" {
  bucket = aws_s3_bucket.media-bucket.id
  policy = data.aws_iam_policy_document.set25_media_policy.json
}
 
data "aws_iam_policy_document" "set25_media_policy" {
 
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetObjectVersion"
    ]
    resources = [
      aws_s3_bucket.media-bucket.arn,
      "${aws_s3_bucket.media-bucket.arn}/*"
    ]
  }
}
 
# S3 code Bucket
resource "aws_s3_bucket" "code-bucket" {
  bucket        = "set25-code-bucket1"
  #depends_on    = [null_resource.pre_scan]
  force_destroy = true
 
  tags = {
    Name = "set25-code-bucket"
  }
}
 
# creating IAM role
resource "aws_iam_role" "iam_role1" {
  name = "set25-iam-role1"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "iam_role"
  }
}
 
# creating media bucket iam policy
resource "aws_iam_policy" "media-iam-policy" {
  name = "set25-media-iam-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:*"]
        Resource = "*"
        Effect   = "Allow"
      },
    ]
  })
}
resource "aws_iam_role_policy_attachment" "iam_s3_attachment" {
  role       = aws_iam_role.iam_role1.name
  policy_arn = aws_iam_policy.media-iam-policy.arn
}
 
#creating iam instance profile
resource "aws_iam_instance_profile" "iam-instance-profile1" {
  name = "instance-profile1"
  role = aws_iam_role.iam_role1.name
}
 
# Creating log bucket
resource "aws_s3_bucket" "log-bucket" {
  bucket        = "set25-log-bucket120"
  force_destroy = true
  #depends_on    = [null_resource.pre_scan]
 
  tags = {
    Name = "set25-log-bucket"
  }
}
 
# Setting bucket ownership controls
resource "aws_s3_bucket_ownership_controls" "log_bucket_owner" {
  bucket = aws_s3_bucket.log-bucket.id
 
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}
 
# Setting bucket ACL (private)
resource "aws_s3_bucket_acl" "log_bucket_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.log_bucket_owner]
  bucket     = aws_s3_bucket.log-bucket.id
  acl        = "log-delivery-write" # Allows CloudFront to write logs
}
 
# Creating log bucket policy
data "aws_iam_policy_document" "log_bucket_policy" {
 
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = ["s3:GetObject",
               "s3:GetBucketAcl",
               "s3:PutBucketAcl",
               "s3:PutObject"
    ]
    resources = [aws_s3_bucket.log-bucket.arn,        # Bucket-level permissions
                "${aws_s3_bucket.log-bucket.arn}/*" # Object-level permissions
                ]
  }
   
}
 
 
# Applying the bucket policy
resource "aws_s3_bucket_policy" "set25_log_bucket_policy" {
  bucket = aws_s3_bucket.log-bucket.id
  policy = data.aws_iam_policy_document.log_bucket_policy.json
}
 
# Blocking public access (Best Practice)
resource "aws_s3_bucket_public_access_block" "log_bucket_access_block" {
  bucket = aws_s3_bucket.log-bucket.id
 
  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}
 


# Cloudwatch dashboard
resource "aws_cloudwatch_dashboard" "set25_dashboard" {
  dashboard_name = "Set25-Infra-Dashboard"
  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric",
        x    = 0,
        y    = 0,
        width = 6,
        height = 6,
        properties = {
          metrics = [
            [ "AWS/EC2", "CPUUtilization", "InstanceId", "${aws_instance.wordpress_server.id}", { "label" : "Average CPU Utilization" }]
          ]
          period  = 300
          region  = "eu-west-3"
          stacked = false
          stat    = "Average"
          title   = "EC2 Average CPUUtilization"
          view    = "timeSeries"
          yAxis = {
            left = {
              label     = "Percentage"
              showUnits = true
            }
          }
        }
      }
    ]
  })
}


// Creating cloudwatch metric alarm ec2 instance
resource "aws_cloudwatch_metric_alarm" "CMA_EC2_Instance" {
  alarm_name          = "CMA-Instance"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_sns_topic.server_alert.arn]
  dimensions = {
    InstanceId : aws_instance.wordpress_server.id
  }
}
// Creating cloudwatch metric alarm auto-scalling group
resource "aws_cloudwatch_metric_alarm" "CMA_Autoscaling_Group" {
  alarm_name          = "CMA-asg"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 50
  alarm_description   = "This metric monitors asg cpu utilization"
  alarm_actions       = [aws_autoscaling_policy.scale_out.arn, aws_sns_topic.server_alert.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.set25-auto-scaling-group.name
  }
}
#creating sns topic
resource "aws_sns_topic" "server_alert" {
  name            = "server-alert"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
}
#creating sns topic subscription
resource "aws_sns_topic_subscription" "acp_updates_sqs_target" {
  topic_arn = aws_sns_topic.server_alert.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Hosted Zone for Route 53
data "aws_route53_zone" "set-25_zone" {
  name = "selfdevops.space"
  private_zone = false

}

resource "aws_route53_record" "set25_zone_record" {
  zone_id = data.aws_route53_zone.set-25_zone.zone_id
  name    = "selfdevops.space"
  type    = "A"

  alias {
    name                   = aws_lb.wordpress_alb.dns_name
    zone_id                = aws_lb.wordpress_alb.zone_id
    evaluate_target_health = true
  }
}

#creating aws_cloudfront_distribution
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name = aws_s3_bucket.media-bucket.bucket_regional_domain_name
    origin_id   = local.s3_origin_id
  }
 
  enabled = true
 
  # Optional logging configuration for CloudFront access logs
  logging_config {
    include_cookies = false
    bucket          = "log-bucket.s3.amazonaws.com"
    prefix          = "cloudfront-log"
  }
 
  # Default cache behavior configuration for serving images
  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id
 
    forwarded_values {
      query_string = false  # Disable query string forwarding as images don't need them
      cookies {
        forward = "none"   # No need to forward cookies for serving static images
      }
    }
 
    viewer_protocol_policy = "redirect-to-https"  # Allow requests to HTTPS and HTTP
    min_ttl                = 3600                 # Minimum TTL (1 hour) for caching
    default_ttl            = 86400                # Default TTL (1 day) for caching
    max_ttl                = 31536000             # Maximum TTL (1 year) for caching
  }
 
  # Using the most cost-effective CloudFront price class
  price_class = "PriceClass_100"
 
  # Restrictions (no geo restrictions applied)
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
 
  # Dependency to ensure scanning is completed before distribution
  #depends_on = [null_resource.pre_scan]
 
  # Tagging for identification
  tags = {
    Name = "set25-cloudfront"
  }
 
  # Default CloudFront SSL certificate (you can configure a custom certificate if needed)
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
 
# Data block to retrieve the CloudFront distribution information
data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.s3_distribution.id
}
 
# Route53 Hosted Zone
data "aws_route53_zone" "acp_zone" {
  name         = "selfdevops.space"
  private_zone = false
}
 