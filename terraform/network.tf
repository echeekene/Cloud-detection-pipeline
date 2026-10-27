# Lab VPC. Splunk runs here, and Flow Logs give network level
# visibility to pair with CloudTrail's API level visibility.

resource "aws_vpc" "lab" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.project_name}-vpc" }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1) # 10.20.1.0/24
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false # public IPs are assigned deliberately, never by default

  tags = { Name = "${var.project_name}-public" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }

  tags = { Name = "${var.project_name}-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Lock down the default security group so nothing accidentally uses it.
resource "aws_default_security_group" "lab" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_flow_log" "lab" {
  vpc_id               = aws_vpc.lab.id
  traffic_type         = "ALL" # accepted and rejected, rejects are often the interesting part
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.logs.arn

  # 1 minute aggregation instead of the 10 minute default, for faster detections.
  max_aggregation_interval = 60

  depends_on = [aws_s3_bucket_policy.logs]
}
